import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ALLOWLISTED_CMDLETS,
  RBAC_SYSTEMS,
  type AllowlistedCmdlet,
  type CmdletParameters,
  type CommandStatus,
  type RunHistoryRecord,
  type RbacSystemValue,
} from '../../../shared/types/commands';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { Separator } from '@/components/ui/separator';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command';
import { TerminalOutput, AnsiConvert } from '@/components/commands/TerminalOutput';
import { CommandHistory } from '@/components/commands/CommandHistory';
import { ChevronDown, Check } from 'lucide-react';
import { cn } from '@/lib/utils';

// Cmdlets that take no parameters — show confirmation dialog instead of param form
const NO_PARAM_CMDLETS = new Set<AllowlistedCmdlet>(['Update-EntraOps']);

export function RunCommandsPage() {
  const [selectedCmdlet, setSelectedCmdlet] = useState<AllowlistedCmdlet | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);

  // Parameter form state
  const [rbacSystems, setRbacSystems] = useState<RbacSystemValue[]>([]);
  const [sampleMode, setSampleMode] = useState(false);
  const [tenantName, setTenantName] = useState('');
  const [subscriptionId, setSubscriptionId] = useState('');

  // Terminal state
  const [htmlContent, setHtmlContent] = useState('');
  const [status, setStatus] = useState<CommandStatus>('idle');

  // History
  const [history, setHistory] = useState<RunHistoryRecord[]>([]);

  // Refs
  const abortRef = useRef<AbortController | null>(null);
  const converterRef = useRef(new AnsiConvert({ stream: true }));

  const fetchHistory = useCallback(() => {
    fetch('/api/commands/history')
      .then((r) => r.json())
      .then((data: { records: RunHistoryRecord[] }) => {
        setHistory(data.records);
      })
      .catch(() => { /* history unavailable — not critical */ });
  }, []);

  // Load config and history on mount
  useEffect(() => {
    fetch('/api/config')
      .then((r) => r.json())
      .then((cfg: Record<string, unknown>) => {
        if (typeof cfg.TenantName === 'string') setTenantName(cfg.TenantName);
        if (typeof cfg.SubscriptionId === 'string') setSubscriptionId(cfg.SubscriptionId);
      })
      .catch(() => { /* config missing — leave fields blank */ });
    fetchHistory();
  }, [fetchHistory]);

  function buildParameters(): CmdletParameters {
    const params: CmdletParameters = {};
    if (rbacSystems.length > 0) params.RbacSystems = rbacSystems;
    if (sampleMode) params.SampleMode = true;
    if (tenantName.trim()) params.TenantName = tenantName.trim();
    if (subscriptionId.trim()) params.SubscriptionId = subscriptionId.trim();
    return params;
  }

  async function handleRun() {
    if (!selectedCmdlet) return;

    const abort = new AbortController();
    abortRef.current = abort;
    setStatus('running');

    // Inject run separator into accumulated output
    const timestamp = new Date().toLocaleString([], {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
    const sep = `\n<span class="text-zinc-500">─── ${selectedCmdlet} · ${timestamp} ───</span>\n`;
    setHtmlContent((prev) => prev + sep);

    try {
      const response = await fetch('/api/commands/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cmdlet: selectedCmdlet, parameters: buildParameters() }),
        signal: abort.signal,
      });

      if (response.status === 409) {
        setHtmlContent((prev) => prev + '<span class="text-amber-400">[Error] A command is already running.</span>\n');
        setStatus('idle');
        return;
      }

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ error: response.statusText })) as { error?: string };
        setHtmlContent((prev) => prev + `<span class="text-red-400">[Error] ${errData.error ?? response.statusText}</span>\n`);
        setStatus('failed');
        return;
      }

      const reader = response.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

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
              const code = parseInt(event.data, 10);
              setStatus(code === 0 ? 'completed' : 'failed');
              fetchHistory();
            } else if (event.type === 'error') {
              setHtmlContent((prev) => prev + `<span class="text-red-400">[Error] ${event.data}</span>\n`);
              setStatus('failed');
            }
          } catch { /* ignore malformed frames */ }
        }
      }
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        // Stopped by user — handleStop already updated status
        return;
      }
      setHtmlContent((prev) => prev + `<span class="text-red-400">[Error] ${String(err)}</span>\n`);
      setStatus('failed');
    }
  }

  async function handleStop() {
    abortRef.current?.abort();
    try {
      const res = await fetch('/api/commands/stop', { method: 'POST' });
      const data = await res.json() as { stopped: boolean; message?: string };
      if (data.stopped && data.message) {
        setHtmlContent((prev) => prev + `<span class="text-zinc-400">${data.message}</span>\n`);
      }
    } catch { /* ignore */ }
    setStatus('stopped');
    fetchHistory();
  }

  function handleRunOrConfirm() {
    if (!selectedCmdlet) return;
    if (NO_PARAM_CMDLETS.has(selectedCmdlet)) {
      setConfirmDialogOpen(true);
    } else {
      void handleRun();
    }
  }

  function handleHistorySelect(record: RunHistoryRecord) {
    setSelectedCmdlet(record.cmdlet);
    setRbacSystems(record.parameters.RbacSystems ?? []);
    setSampleMode(record.parameters.SampleMode ?? false);
    setTenantName(record.parameters.TenantName ?? '');
    setSubscriptionId(record.parameters.SubscriptionId ?? '');
  }

  function toggleRbacSystem(system: RbacSystemValue) {
    setRbacSystems((prev) =>
      prev.includes(system) ? prev.filter((s) => s !== system) : [...prev, system]
    );
  }

  const isNoParam = selectedCmdlet !== null && NO_PARAM_CMDLETS.has(selectedCmdlet);

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Run Commands</h1>

      {/* Command palette selector */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-foreground mb-2">
          Command
        </label>
        <Popover open={paletteOpen} onOpenChange={setPaletteOpen}>
          <PopoverTrigger asChild>
            <Button
              variant="outline"
              role="combobox"
              aria-expanded={paletteOpen}
              className="w-full max-w-lg justify-between font-mono text-sm"
            >
              {selectedCmdlet ?? 'Select a cmdlet…'}
              <ChevronDown size={16} className="ml-2 shrink-0 text-muted-foreground" />
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-[480px] p-0" align="start">
            <Command>
              <CommandInput placeholder="Search cmdlets…" />
              <CommandList>
                <CommandEmpty>No cmdlets found.</CommandEmpty>
                <CommandGroup>
                  {ALLOWLISTED_CMDLETS.map((cmdlet) => (
                    <CommandItem
                      key={cmdlet}
                      value={cmdlet}
                      onSelect={() => {
                        setSelectedCmdlet(cmdlet);
                        setPaletteOpen(false);
                      }}
                      className="font-mono text-xs"
                    >
                      <Check
                        size={14}
                        className={cn('mr-2 shrink-0', selectedCmdlet === cmdlet ? 'opacity-100' : 'opacity-0')}
                      />
                      {cmdlet}
                    </CommandItem>
                  ))}
                </CommandGroup>
              </CommandList>
            </Command>
          </PopoverContent>
        </Popover>
      </div>

      {/* Two-column layout: parameters (left) + terminal (right) */}
      <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-6">

        {/* Parameters panel */}
        <div className="flex flex-col gap-4">
          <div className="rounded-md border border-border p-4 bg-card">
            <h2 className="text-sm font-semibold mb-4 text-foreground">Parameters</h2>

            {!selectedCmdlet && (
              <p className="text-xs text-muted-foreground">Select a cmdlet to configure parameters.</p>
            )}

            {selectedCmdlet && isNoParam && (
              <p className="text-xs text-muted-foreground">
                <span className="font-mono text-foreground">{selectedCmdlet}</span> takes no parameters.
                Clicking Run will prompt for confirmation.
              </p>
            )}

            {selectedCmdlet && !isNoParam && (
              <div className="flex flex-col gap-5">
                {/* RBAC Systems */}
                <div>
                  <p className="text-xs font-medium text-foreground mb-2">
                    RBAC Systems
                    <span className="ml-1 text-muted-foreground font-normal">(optional)</span>
                  </p>
                  <div className="flex flex-col gap-2">
                    {RBAC_SYSTEMS.map((system) => (
                      <label key={system} className="flex items-center gap-2 cursor-pointer">
                        <Checkbox
                          id={`rbac-${system}`}
                          checked={rbacSystems.includes(system)}
                          onCheckedChange={() => toggleRbacSystem(system)}
                        />
                        <span className="text-xs font-mono text-foreground">{system}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <Separator />

                {/* SampleMode */}
                <div>
                  <p className="text-xs font-medium text-foreground mb-2">Options</p>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <Checkbox
                      id="sample-mode"
                      checked={sampleMode}
                      onCheckedChange={(checked) => setSampleMode(checked === true)}
                    />
                    <span className="text-xs text-foreground">SampleMode</span>
                    <span className="text-xs text-muted-foreground">(optional)</span>
                  </label>
                </div>

                <Separator />

                {/* Connection parameters */}
                <div>
                  <p className="text-xs font-medium text-foreground mb-2">Connection</p>
                  <div className="flex flex-col gap-3">
                    <div>
                      <label className="text-xs text-muted-foreground mb-1 block" htmlFor="tenant-name">
                        TenantName
                        <span className="ml-1">(optional)</span>
                      </label>
                      <Input
                        id="tenant-name"
                        value={tenantName}
                        onChange={(e) => setTenantName(e.target.value)}
                        placeholder="your-tenant.onmicrosoft.com"
                        className="h-8 text-xs font-mono"
                      />
                    </div>
                    <div>
                      <label className="text-xs text-muted-foreground mb-1 block" htmlFor="subscription-id">
                        SubscriptionId
                        <span className="ml-1">(optional)</span>
                      </label>
                      <Input
                        id="subscription-id"
                        value={subscriptionId}
                        onChange={(e) => setSubscriptionId(e.target.value)}
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        className="h-8 text-xs font-mono"
                      />
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Action buttons */}
          <div className="flex gap-2">
            <Button
              onClick={handleRunOrConfirm}
              disabled={!selectedCmdlet || status === 'running'}
              className="flex-1"
            >
              Run
            </Button>
            <Button
              variant="outline"
              onClick={() => setHtmlContent('')}
              disabled={htmlContent === ''}
            >
              Clear
            </Button>
          </div>
        </div>

        {/* Terminal output */}
        <div className="flex flex-col gap-4">
          <TerminalOutput
            htmlContent={htmlContent}
            status={status}
            onStop={() => void handleStop()}
          />
        </div>
      </div>

      {/* Command History */}
      <div className="mt-8">
        <h2 className="text-sm font-semibold mb-3 text-foreground">Command History</h2>
        <CommandHistory records={history} onSelect={handleHistorySelect} />
      </div>

      {/* Update-EntraOps confirmation dialog */}
      <Dialog open={confirmDialogOpen} onOpenChange={setConfirmDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Run Update-EntraOps?</DialogTitle>
            <DialogDescription>
              This will update the EntraOps module files on disk. The operation may take a few minutes
              while PowerShell downloads and installs the latest module version.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                setConfirmDialogOpen(false);
                void handleRun();
              }}
            >
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
