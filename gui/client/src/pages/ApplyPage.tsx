import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router';
import {
  type AllowlistedCmdlet,
  type CmdletParameters,
  type CommandStatus,
} from '../../../shared/types/commands';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { TerminalOutput, AnsiConvert } from '@/components/commands/TerminalOutput';
import { PlayCircle, CheckCircle2, AlertCircle, XCircle, OctagonX, FlaskConical } from 'lucide-react';
import { toast } from 'sonner';

// ---------------------------------------------------------------------------
// Implementation actions — fixed 4-cmdlet set for the Apply workflow
// ---------------------------------------------------------------------------
const IMPLEMENTATION_ACTIONS = [
  {
    cmdlet: 'Update-EntraOpsPrivilegedAdministrativeUnit' as AllowlistedCmdlet,
    label: 'Administrative Units',
    description: 'Assign users to Administrative Units based on their computed tier classification.',
  },
  {
    cmdlet: 'Update-EntraOpsPrivilegedConditionalAccessGroup' as AllowlistedCmdlet,
    label: 'Conditional Access Groups',
    description: 'Sync Conditional Access group membership with the current tier structure.',
  },
  {
    cmdlet: 'Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit' as AllowlistedCmdlet,
    label: 'Unprotected Administrative Units',
    description: 'Flag Administrative Units that lack Restricted Management protection.',
  },
  {
    cmdlet: 'Update-EntraOpsClassificationControlPlaneScope' as AllowlistedCmdlet,
    label: 'ControlPlane Scope',
    description: 'Update ControlPlane scope boundaries based on current classification data.',
  },
] as const;

type PageState = 'idle' | 'confirming' | 'running' | 'done';
type CmdletResult = 'pending' | 'pass' | 'fail' | 'skipped';

// ---------------------------------------------------------------------------
// Helper: derive overall CommandStatus from per-cmdlet results
// ---------------------------------------------------------------------------
function deriveOverallStatus(results: Map<string, CmdletResult>): CommandStatus {
  const values = Array.from(results.values());
  if (values.every((v) => v === 'skipped' || v === 'pending')) return 'stopped';
  if (values.some((v) => v === 'fail')) return 'failed';
  if (values.every((v) => v === 'pass')) return 'completed';
  return 'stopped'; // mixed skipped
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export function ApplyPage() {
  const navigate = useNavigate();

  // Page state machine
  const [pageState, setPageState] = useState<PageState>('idle');

  // Action selection — all 4 selected by default
  const [selected, setSelected] = useState<Set<string>>(
    new Set(IMPLEMENTATION_ACTIONS.map((a) => a.cmdlet))
  );

  // Per-cmdlet run results
  const [results, setResults] = useState<Map<string, CmdletResult>>(new Map());
  const [runningIndex, setRunningIndex] = useState(0);

  // Terminal / SSE state
  const [htmlContent, setHtmlContent] = useState('');
  const [status, setStatus] = useState<CommandStatus>('idle');

  // Config fetched on mount
  const [tenantName, setTenantName] = useState('');
  const [subscriptionId, setSubscriptionId] = useState('');

  // Dry-run mode — preserved across Apply Again resets (D-01, D-03)
  const [isDryRun, setIsDryRun] = useState(false);

  // Refs
  const abortRef = useRef<AbortController | null>(null);
  const converterRef = useRef(new AnsiConvert({ stream: true }));
  const stoppedRef = useRef(false);

  // ------------------------------------------------------------------
  // On mount: pre-populate tenant info from config
  // ------------------------------------------------------------------
  useEffect(() => {
    fetch('/api/config')
      .then((r) => r.json())
      .then((cfg: Record<string, unknown>) => {
        if (typeof cfg.TenantName === 'string') setTenantName(cfg.TenantName);
        if (typeof cfg.SubscriptionId === 'string') setSubscriptionId(cfg.SubscriptionId);
      })
      .catch(() => { /* config missing — leave fields blank */ });
  }, []);

  // ------------------------------------------------------------------
  // Toggle a single action checkbox
  // ------------------------------------------------------------------
  function toggleAction(cmdlet: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(cmdlet)) {
        next.delete(cmdlet);
      } else {
        next.add(cmdlet);
      }
      return next;
    });
  }

  // ------------------------------------------------------------------
  // Run a single cmdlet via SSE — returns exit code (or -1 on error/abort)
  // ------------------------------------------------------------------
  const runSingleCmdlet = useCallback(
    async (
      cmdlet: AllowlistedCmdlet,
      parameters: CmdletParameters,
      signal: AbortSignal
    ): Promise<number> => {
      try {
        const response = await fetch('/api/commands/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ cmdlet, parameters }),
          signal,
        });

        if (response.status === 409) {
          setHtmlContent((prev) => prev + '<span class="text-amber-400">[Error] A command is already running.</span>\n');
          return -1;
        }

        if (!response.ok) {
          const errData = await response.json().catch(() => ({ error: response.statusText })) as { error?: string };
          setHtmlContent((prev) => prev + `<span class="text-red-400">[Error] ${errData.error ?? response.statusText}</span>\n`);
          return -1;
        }

        const reader = response.body!.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let exitCode = -1;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          // Parse SSE frames: split on '\n\n' boundaries
          const frames = buffer.split('\n\n');
          buffer = frames.pop() ?? '';

          for (const frame of frames) {
            const line = frame.replace(/^data: /, '').trim();
            if (!line) continue;
            try {
              const event = JSON.parse(line) as { type: string; data: string };
              if (event.type === 'stdout' || event.type === 'stderr') {
                const html = converterRef.current.toHtml(event.data.replace(/\r/g, ''));
                setHtmlContent((prev) => prev + html);
              } else if (event.type === 'exit') {
                exitCode = parseInt(event.data, 10);
              } else if (event.type === 'error') {
                setHtmlContent((prev) => prev + `<span class="text-red-400">[Error] ${event.data}</span>\n`);
                exitCode = -1;
              }
            } catch { /* ignore malformed frames */ }
          }
        }

        return exitCode;
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') {
          return -1;
        }
        const msg = err instanceof Error ? err.message : String(err);
        setHtmlContent((prev) => prev + `<span class="text-red-400">[Error] ${msg}</span>\n`);
        toast.error(`Command failed: ${msg}`);
        return -1;
      }
    },
    []
  );

  // ------------------------------------------------------------------
  // Handle Run — sequential multi-cmdlet execution
  // ------------------------------------------------------------------
  async function handleRun() {
    stoppedRef.current = false;
    setPageState('running');
    setStatus('running');
    setHtmlContent('');

    const selectedActions = IMPLEMENTATION_ACTIONS.filter((a) => selected.has(a.cmdlet));
    const newResults = new Map<string, CmdletResult>(
      selectedActions.map((a) => [a.cmdlet, 'pending'])
    );
    setResults(new Map(newResults));

    const abort = new AbortController();
    abortRef.current = abort;

    for (let i = 0; i < selectedActions.length; i++) {
      if (stoppedRef.current) {
        // Mark remaining as skipped
        for (let j = i; j < selectedActions.length; j++) {
          newResults.set(selectedActions[j].cmdlet, 'skipped');
        }
        setResults(new Map(newResults));
        break;
      }

      setRunningIndex(i);
      const action = selectedActions[i];

      // Inject run separator — includes [DRY RUN] prefix when in dry-run mode (per UI-SPEC Screen 3)
      const timestamp = new Date().toLocaleString([], {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
      });
      const dryRunPrefix = isDryRun ? '<span class="text-sky-500 font-semibold">[DRY RUN]</span> ' : '';
      const sep = `\n<span class="text-zinc-500">─── ${dryRunPrefix}${action.label} · ${timestamp} ───</span>\n`;
      setHtmlContent((prev) => prev + sep);

      // Build parameters
      const parameters: CmdletParameters = {};
      if (tenantName.trim()) parameters.TenantName = tenantName.trim();
      if (subscriptionId.trim()) parameters.SubscriptionId = subscriptionId.trim();
      if (isDryRun) parameters.SampleMode = true;

      const exitCode = await runSingleCmdlet(action.cmdlet, parameters, abort.signal);

      newResults.set(action.cmdlet, exitCode === 0 ? 'pass' : 'fail');
      setResults(new Map(newResults));
    }

    setPageState('done');
    setStatus(deriveOverallStatus(newResults));
  }

  // ------------------------------------------------------------------
  // Handle Stop
  // ------------------------------------------------------------------
  async function handleStop() {
    stoppedRef.current = true;
    abortRef.current?.abort();
    try {
      const res = await fetch('/api/commands/stop', { method: 'POST' });
      const data = await res.json() as { stopped: boolean; message?: string };
      if (data.stopped && data.message) {
        setHtmlContent((prev) => prev + `<span class="text-zinc-400">${data.message}</span>\n`);
      }
    } catch { /* ignore */ }
    setStatus('stopped');
  }

  // ------------------------------------------------------------------
  // Reset to idle (preserving selection and isDryRun per D-03)
  // ------------------------------------------------------------------
  function handleApplyAgain() {
    setPageState('idle');
    setHtmlContent('');
    setResults(new Map());
    setStatus('idle');
  }

  // ------------------------------------------------------------------
  // Derived values for the outcome screen
  // ------------------------------------------------------------------
  const selectedActions = IMPLEMENTATION_ACTIONS.filter((a) => selected.has(a.cmdlet));

  function OutcomeHeader() {
    const values = Array.from(results.values());
    const hasFail = values.some((v) => v === 'fail');
    const allPass = values.every((v) => v === 'pass');
    const isStopped = status === 'stopped';

    if (isStopped) {
      if (isDryRun) {
        return (
          <div className="flex items-center gap-3">
            <OctagonX size={20} className="text-zinc-500" />
            <h2 className="text-xl font-semibold">Dry-run Stopped</h2>
            <Badge className="bg-sky-500/10 text-sky-500 border border-sky-500/30">◈ Simulated</Badge>
          </div>
        );
      }
      return (
        <div className="flex items-center gap-3">
          <OctagonX size={20} className="text-zinc-400" />
          <h2 className="text-xl font-semibold">Implementation Stopped</h2>
          <Badge className="bg-zinc-500/20 text-zinc-400 border border-zinc-500/30">Stopped</Badge>
        </div>
      );
    }
    if (allPass) {
      if (isDryRun) {
        return (
          <div className="flex items-center gap-3">
            <CheckCircle2 size={20} className="text-sky-500" />
            <h2 className="text-xl font-semibold">Dry-run Complete — No changes made</h2>
            <Badge className="bg-sky-500/10 text-sky-500 border border-sky-500/30">◈ Simulated</Badge>
          </div>
        );
      }
      return (
        <div className="flex items-center gap-3">
          <CheckCircle2 size={20} className="text-green-400" />
          <h2 className="text-xl font-semibold">Implementation Complete</h2>
          <Badge className="bg-green-500/20 text-green-400 border border-green-500/30">Complete</Badge>
        </div>
      );
    }
    if (hasFail) {
      const allFail = values.filter((v) => v !== 'skipped').every((v) => v === 'fail');
      if (allFail) {
        if (isDryRun) {
          return (
            <div className="flex items-center gap-3">
              <XCircle size={20} className="text-red-500" />
              <h2 className="text-xl font-semibold">Dry-run — Simulation Errors</h2>
              <Badge className="bg-sky-500/10 text-sky-500 border border-sky-500/30">◈ Simulated</Badge>
            </div>
          );
        }
        return (
          <div className="flex items-center gap-3">
            <XCircle size={20} className="text-red-400" />
            <h2 className="text-xl font-semibold">Implementation Failed</h2>
            <Badge className="bg-red-500/20 text-red-400 border border-red-500/30">Failed</Badge>
          </div>
        );
      }
      if (isDryRun) {
        return (
          <div className="flex items-center gap-3">
            <AlertCircle size={20} className="text-amber-500" />
            <h2 className="text-xl font-semibold">Dry-run Finished — Review Simulation Results</h2>
            <Badge className="bg-sky-500/10 text-sky-500 border border-sky-500/30">◈ Simulated</Badge>
          </div>
        );
      }
      return (
        <div className="flex items-center gap-3">
          <AlertCircle size={20} className="text-amber-400" />
          <h2 className="text-xl font-semibold">Implementation Finished — Review Results</h2>
          <Badge className="bg-amber-500/20 text-amber-400 border border-amber-500/30">Partial</Badge>
        </div>
      );
    }
    return null;
  }

  // ------------------------------------------------------------------
  // Screen 1 — idle: Action Selection
  // ------------------------------------------------------------------
  if (pageState === 'idle') {
    return (
      <div className="p-6 max-w-2xl mx-auto">
        <h1 className="text-2xl font-semibold">Apply to Entra</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Apply your EntraOps tier structure to the tenant. Select actions to continue.
        </p>

        <Separator className="my-6" />

        <p className="text-sm font-semibold mb-3">Actions</p>

        <div className="flex flex-col gap-2">
          {IMPLEMENTATION_ACTIONS.map((action) => {
            const checked = selected.has(action.cmdlet);
            return (
              <label key={action.cmdlet} className="cursor-pointer">
                <div
                  className={`border border-border rounded-md p-4 bg-card ${
                    checked ? 'ring-1 ring-inset ring-foreground/10' : ''
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <Checkbox
                      checked={checked}
                      onCheckedChange={() => toggleAction(action.cmdlet)}
                      className="mt-0.5"
                    />
                    <div>
                      <p className="text-sm font-medium">{action.label}</p>
                      <p className="text-xs text-muted-foreground mt-1">{action.description}</p>
                    </div>
                  </div>
                </div>
              </label>
            );
          })}
        </div>

        <Separator className="my-4" />

        <div className="flex items-start justify-between gap-4 py-4">
          <Label htmlFor="dry-run-toggle" className="flex flex-col gap-0.5 cursor-pointer">
            <span className="text-sm font-medium text-foreground">Dry-run mode</span>
            <span className="text-xs text-muted-foreground mt-0.5 max-w-sm">
              Simulate changes without writing to Entra. Cmdlets run with -SampleMode.
            </span>
          </Label>
          <div className="flex items-center gap-3 shrink-0">
            {isDryRun && (
              <Badge className="bg-sky-500/10 text-sky-500 border border-sky-500/30 text-xs">
                ◈ Simulation active
              </Badge>
            )}
            <Switch
              id="dry-run-toggle"
              checked={isDryRun}
              onCheckedChange={setIsDryRun}
            />
          </div>
        </div>

        <Separator className="my-4" />

        <p className="text-xs text-muted-foreground mt-4">
          {selected.size === 0
            ? 'Select at least one action to continue.'
            : `${selected.size} of 4 actions selected`}
        </p>

        <Button
          disabled={selected.size === 0}
          onClick={() => setPageState('confirming')}
          className="w-full max-w-xs mt-2"
        >
          {isDryRun ? 'Review & Simulate' : 'Review & Apply'}
        </Button>
      </div>
    );
  }

  // ------------------------------------------------------------------
  // Screen 2 — confirming: Pre-run Confirmation
  // ------------------------------------------------------------------
  if (pageState === 'confirming') {
    return (
      <div className="p-6 max-w-2xl mx-auto">
        <h1 className="text-2xl font-semibold">Apply to Entra</h1>
        <Separator className="my-6" />

        <p className="text-sm font-semibold">Review before running</p>
        <p className="text-sm text-muted-foreground mt-1 mb-4">
          {isDryRun
            ? 'The following cmdlets will simulate in order. No changes will be applied to your Entra tenant.'
            : 'The following cmdlets will run in order. Changes will be applied to your Entra tenant.'}
        </p>

        {isDryRun ? (
          <Alert className="border-sky-500/30 bg-sky-500/5 mb-4">
            <FlaskConical className="text-sky-500" size={16} />
            <AlertTitle className="text-sm font-medium text-sky-700 dark:text-sky-400">
              Simulation Mode
            </AlertTitle>
            <AlertDescription className="text-sm text-sky-700 dark:text-sky-400">
              Dry-run mode — No changes will be made to your Entra tenant. All cmdlets will execute with -SampleMode.
            </AlertDescription>
          </Alert>
        ) : (
          <Alert className="border-amber-500/30 bg-amber-500/5 mb-4">
            <AlertCircle className="text-amber-500" size={16} />
            <AlertDescription className="text-amber-700 dark:text-amber-400">
              This will make changes to your live Entra tenant. Ensure your session token is valid before proceeding.
            </AlertDescription>
          </Alert>
        )}

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-8">#</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Cmdlet</TableHead>
              <TableHead>Parameters</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {IMPLEMENTATION_ACTIONS.filter((a) => selected.has(a.cmdlet)).map((action, idx) => (
              <TableRow key={action.cmdlet}>
                <TableCell className="text-sm text-muted-foreground">{idx + 1}</TableCell>
                <TableCell className="text-sm font-medium">{action.label}</TableCell>
                <TableCell className="text-xs font-mono text-muted-foreground">{action.cmdlet}</TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {isDryRun
                    ? (tenantName.trim() ? `${tenantName.trim()} -SampleMode` : '-SampleMode')
                    : (tenantName.trim() ? tenantName.trim() : 'environment defaults')}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>

        <div className="flex justify-between items-center mt-6">
          <Button variant="outline" onClick={() => setPageState('idle')}>
            Back
          </Button>
          <Button onClick={() => void handleRun()}>
            {isDryRun ? 'Simulate Now' : 'Run Now'}
          </Button>
        </div>
      </div>
    );
  }

  // ------------------------------------------------------------------
  // Screen 3 — running: Live SSE Output
  // ------------------------------------------------------------------
  if (pageState === 'running') {
    const runningAction = selectedActions[runningIndex];
    return (
      <div className="p-6 max-w-2xl mx-auto">
        <div className="flex items-center gap-3 mb-1">
          <h2 className="text-lg font-semibold">
            {isDryRun ? 'Simulating — Dry-run in progress…' : 'Applying to Entra…'}
          </h2>
          {isDryRun ? (
            <Badge className="bg-sky-500/10 text-sky-500 border border-sky-500/30">◈ Simulating</Badge>
          ) : (
            <Badge className="bg-amber-500/20 text-amber-400 border border-amber-500/30">Running</Badge>
          )}
        </div>
        <p className="text-xs text-muted-foreground mt-1 mb-4">
          {isDryRun ? 'Simulating' : 'Running'} action {runningIndex + 1} of {selectedActions.length} — {runningAction?.label ?? ''}
        </p>

        {isDryRun && (
          <Alert className="border-sky-500/30 bg-sky-500/5 py-2 mb-4">
            <FlaskConical className="text-sky-500" size={14} />
            <AlertDescription className="text-xs text-sky-700 dark:text-sky-400">
              Dry-run mode active — no changes are being written to Entra.
            </AlertDescription>
          </Alert>
        )}

        <div className="h-[400px]">
          <TerminalOutput htmlContent={htmlContent} status={status} onStop={() => void handleStop()} />
        </div>
      </div>
    );
  }

  // ------------------------------------------------------------------
  // Screen 4 — done: Outcome Summary
  // ------------------------------------------------------------------
  return (
    <div className="p-6 max-w-2xl mx-auto">
      <OutcomeHeader />

      {isDryRun && (
        <Alert className="border-sky-500/30 bg-sky-500/5 mb-4 mt-4">
          <FlaskConical className="text-sky-500" size={16} />
          <AlertTitle className="text-sm font-medium text-sky-700 dark:text-sky-400">
            Dry-run complete — no changes were made
          </AlertTitle>
          <AlertDescription className="text-sm text-sky-700/80 dark:text-sky-400/80">
            This was a simulation run. Your Entra tenant was not modified.
            To apply real changes, return to the Apply screen and disable dry-run mode.
          </AlertDescription>
        </Alert>
      )}

      <div className="mt-4 border border-border rounded-md overflow-hidden">
        {selectedActions.map((action) => {
          const result = results.get(action.cmdlet) ?? 'pending';
          return (
            <div
              key={action.cmdlet}
              className="flex items-center justify-between px-4 py-3 border-b border-border last:border-b-0"
            >
              <span className="text-sm font-medium">{action.label}</span>
              {result === 'pass' && (
                isDryRun ? (
                  <Badge className="bg-sky-500/10 text-sky-500 border border-sky-500/30">◈ Sim. Pass</Badge>
                ) : (
                  <Badge className="bg-green-500/20 text-green-400 border border-green-500/30">✓ Pass</Badge>
                )
              )}
              {result === 'fail' && (
                isDryRun ? (
                  <Badge className="bg-red-500/20 text-red-400 border border-red-500/30">◈ Sim. Fail</Badge>
                ) : (
                  <Badge className="bg-red-500/20 text-red-400 border border-red-500/30">✕ Fail</Badge>
                )
              )}
              {result === 'skipped' && (
                <Badge className="bg-zinc-500/20 text-zinc-400 border border-zinc-500/30">◼ Skipped</Badge>
              )}
              {result === 'pending' && (
                <Badge className="bg-zinc-500/20 text-zinc-400 border border-zinc-500/30">Pending</Badge>
              )}
            </div>
          );
        })}
      </div>

      <Separator className="my-4" />

      <div className="h-48">
        <TerminalOutput htmlContent={htmlContent} status={status} onStop={() => {}} />
      </div>

      <div className="flex justify-between items-center mt-6">
        <Button variant="outline" onClick={handleApplyAgain}>
          Apply Again
        </Button>
        <Button onClick={() => navigate('/')}>
          Back to Dashboard
        </Button>
      </div>
    </div>
  );
}
