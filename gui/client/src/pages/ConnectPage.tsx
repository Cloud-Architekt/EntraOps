import { useCallback, useEffect, useRef, useState, Fragment } from 'react';
import { useNavigate } from 'react-router';
import { toast } from 'sonner';
import { Check, Clipboard } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { TerminalOutput, AnsiConvert } from '@/components/commands/TerminalOutput';
import type { CommandRunEvent, CommandStatus, RbacSystemValue } from '../../../shared/types/commands';
import type { AuthType } from '../../../shared/types/connect';

const RBAC_SYSTEM_META: { key: string; label: string; description: string }[] = [
  { key: 'EntraID',            label: 'EntraID',            description: 'Entra ID roles and Administrative Units' },
  { key: 'ResourceApps',       label: 'ResourceApps',       description: 'Azure resource app role assignments' },
  { key: 'IdentityGovernance', label: 'IdentityGovernance', description: 'Identity Governance roles and entitlements' },
  { key: 'DeviceManagement',   label: 'DeviceManagement',   description: 'Intune / Device Management roles' },
  { key: 'Defender',           label: 'Defender',           description: 'Microsoft Defender for Identity roles' },
];

const STEP_LABELS = ['Tenant', 'Authenticate', 'Review & Classify', 'Classifying'];

type StepState = 'completed' | 'active' | 'upcoming';

function StepNode({ index, state, label }: { index: number; state: StepState; label: string }) {
  return (
    <div className="flex flex-col items-center">
      <div className={cn(
        'w-8 h-8 rounded-full flex items-center justify-center',
        state === 'completed' && 'bg-fluent-accent',
        state === 'active' && 'border-2 border-fluent-accent bg-background',
        state === 'upcoming' && 'border-2 border-border bg-muted',
      )}>
        {state === 'completed'
          ? <Check size={16} className="text-white" />
          : <span className={cn(
              'text-sm',
              state === 'active' ? 'text-fluent-accent font-semibold' : 'text-muted-foreground',
            )}>{index + 1}</span>
        }
      </div>
      <span className={cn(
        'text-xs mt-1 text-center',
        state === 'active' ? 'font-semibold text-foreground' : 'text-muted-foreground',
      )}>{label}</span>
    </div>
  );
}

function ConnectorLine({ completed }: { completed: boolean }) {
  return <div className={cn('flex-1 h-0.5 mx-2 mt-[-10px]', completed ? 'bg-fluent-accent' : 'bg-border')} />;
}

function StepIndicator({ current }: { current: number }) {
  return (
    <div className="flex items-start justify-between mb-8">
      {STEP_LABELS.map((label, i) => (
        <Fragment key={label}>
          <StepNode
            index={i}
            label={label}
            state={i < current ? 'completed' : i === current ? 'active' : 'upcoming'}
          />
          {i < STEP_LABELS.length - 1 && <ConnectorLine completed={i < current} />}
        </Fragment>
      ))}
    </div>
  );
}

function cancelLabel(step: number, classifyRunning: boolean): string {
  if (step === 3 && classifyRunning) return 'Stop & Start Over';
  if (step === 3) return '';
  return 'Exit Setup';
}

function stepHeading(step: number, authSt: CommandStatus, classifySt: CommandStatus): string {
  if (step === 0) return 'Connect to your Entra tenant';
  if (step === 1) {
    if (authSt === 'completed') return 'Authentication complete';
    if (authSt === 'failed') return 'Authentication failed';
    return 'Authenticating…';
  }
  if (step === 2) return 'Select systems to classify';
  if (classifySt === 'completed') return 'Classification complete';
  if (classifySt === 'failed') return 'Classification failed';
  return 'Classifying your tenant…';
}

function stepDescription(step: number, classifySt: CommandStatus): string {
  if (step === 0) return 'Enter your tenant details to begin the connection process.';
  if (step === 1) return 'Complete the sign-in prompt in your browser to continue.';
  if (step === 2) return 'All systems are selected by default. Deselect any to skip in this run.';
  if (classifySt === 'completed') return 'Your dashboard data has been updated.';
  if (classifySt === 'failed') return 'Review the output below for error details.';
  return 'Your tenant is being classified. This may take a few minutes.';
}

export function ConnectPage() {
  const [currentStep, setCurrentStep] = useState(0);
  const [tenantName, setTenantName] = useState('');
  const [tenantError, setTenantError] = useState(false);
  const [authType, setAuthType] = useState<AuthType>('DeviceAuthentication');
  const [selectedSystems, setSelectedSystems] = useState<Record<string, boolean>>(
    Object.fromEntries(RBAC_SYSTEM_META.map(s => [s.key, true]))
  );
  const [authHtml, setAuthHtml] = useState('');
  const [authStatus, setAuthStatus] = useState<CommandStatus>('idle');
  const [rawAuthOutput, setRawAuthOutput] = useState('');
  const [deviceLoginUrl, setDeviceLoginUrl] = useState<string | null>(null);
  const [deviceCode, setDeviceCode] = useState<string | null>(null);
  const [classifyHtml, setClassifyHtml] = useState('');
  const [classifyStatus, setClassifyStatus] = useState<CommandStatus>('idle');
  const authAbortRef = useRef<AbortController | null>(null);
  const classifyAbortRef = useRef<AbortController | null>(null);
  const authConverterRef = useRef(new AnsiConvert({ stream: true }));
  const classifyConverterRef = useRef(new AnsiConvert({ stream: true }));
  const navigate = useNavigate();

  // Pre-populate from config on mount
  useEffect(() => {
    fetch('/api/config')
      .then(r => r.json())
      .then((cfg: Record<string, unknown>) => {
        if (typeof cfg.TenantName === 'string' && cfg.TenantName) setTenantName(cfg.TenantName);
        if (Array.isArray(cfg.RbacSystems) && cfg.RbacSystems.length > 0) {
          setSelectedSystems(Object.fromEntries(
            RBAC_SYSTEM_META.map(s => [s.key, (cfg.RbacSystems as string[]).includes(s.key)])
          ));
        }
      })
      .catch(() => { /* config missing — leave defaults */ });
  }, []);

  // Device code extraction from raw auth output
  useEffect(() => {
    if (!deviceLoginUrl && rawAuthOutput.includes('microsoft.com/devicelogin')) {
      const urlMatch = rawAuthOutput.match(/https:\/\/microsoft\.com\/devicelogin/);
      const codeMatch = rawAuthOutput.match(/enter the code ([A-Z0-9]+)/i);
      if (urlMatch) setDeviceLoginUrl('https://microsoft.com/devicelogin');
      if (codeMatch?.[1]) setDeviceCode(codeMatch[1]);
    }
  }, [rawAuthOutput, deviceLoginUrl]);

  // Auto-advance from step 1 to step 2 on auth completion
  useEffect(() => {
    if (authStatus === 'completed' && currentStep === 1) {
      setCurrentStep(2);
    }
  }, [authStatus, currentStep]);

  // Toast + status event on classify completion/failure
  useEffect(() => {
    if (classifyStatus === 'completed') {
      toast.success('Classification complete', {
        description: 'Your dashboard data has been updated.',
        duration: 8000,
        action: { label: 'Go to Dashboard', onClick: () => navigate('/') },
      });
      window.dispatchEvent(new Event('entraops:connect-status'));
    } else if (classifyStatus === 'failed') {
      toast.error('Classification failed', {
        description: 'Classification completed with errors — check the output above.',
        duration: 8000,
      });
    }
  }, [classifyStatus, navigate]);

  async function handleConnect() {
    if (!tenantName.trim()) { setTenantError(true); return; }
    setTenantError(false);
    const abort = new AbortController();
    authAbortRef.current = abort;
    setAuthStatus('running');
    setCurrentStep(1);
    try {
      const response = await fetch('/api/connect/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenantName: tenantName.trim(), authType }),
        signal: abort.signal,
      });
      if (!response.ok || !response.body) {
        setAuthStatus('failed');
        return;
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const frames = buffer.split('\n\n');
        buffer = frames.pop() ?? '';
        for (const frame of frames) {
          const line = frame.replace(/^data: /, '').trim();
          if (!line) continue;
          try {
            const event = JSON.parse(line) as CommandRunEvent;
            if (event.type === 'exit') {
              const code = parseInt(event.data, 10);
              setAuthStatus(code === 0 ? 'completed' : 'failed');
            } else if (event.type === 'error') {
              setAuthStatus('failed');
            } else {
              const cleaned = event.data.replace(/\r/g, '');
              if (cleaned.trim()) {
                const html = authConverterRef.current.toHtml(cleaned);
                setAuthHtml(prev => prev + html);
              }
              setRawAuthOutput(prev => prev + event.data);
            }
          } catch { /* malformed frame — skip */ }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== 'AbortError') {
        setAuthStatus('failed');
      }
    }
  }

  async function handleStartClassify() {
    const selectedRbac = RBAC_SYSTEM_META
      .filter(s => selectedSystems[s.key])
      .map(s => s.key) as RbacSystemValue[];
    const abort = new AbortController();
    classifyAbortRef.current = abort;
    setClassifyStatus('running');
    setCurrentStep(3);
    try {
      const response = await fetch('/api/commands/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cmdlet: 'Save-EntraOpsPrivilegedEAMJson',
          parameters: { RbacSystems: selectedRbac },
        }),
        signal: abort.signal,
      });
      if (!response.ok || !response.body) {
        setClassifyStatus('failed');
        return;
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const frames = buffer.split('\n\n');
        buffer = frames.pop() ?? '';
        for (const frame of frames) {
          const line = frame.replace(/^data: /, '').trim();
          if (!line) continue;
          try {
            const event = JSON.parse(line) as CommandRunEvent;
            if (event.type === 'exit') {
              const code = parseInt(event.data, 10);
              setClassifyStatus(code === 0 ? 'completed' : 'failed');
            } else if (event.type === 'error') {
              setClassifyStatus('failed');
            } else {
              const cleaned = event.data.replace(/\r/g, '');
              if (cleaned.trim()) {
                const html = classifyConverterRef.current.toHtml(cleaned);
                setClassifyHtml(prev => prev + html);
              }
            }
          } catch { /* malformed frame — skip */ }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== 'AbortError') {
        setClassifyStatus('failed');
      }
    }
  }

  const handleCancel = useCallback(async () => {
    if (authAbortRef.current) { authAbortRef.current.abort(); authAbortRef.current = null; }
    if (classifyAbortRef.current) { classifyAbortRef.current.abort(); classifyAbortRef.current = null; }
    if (currentStep === 1 || currentStep === 2) {
      await fetch('/api/connect/disconnect', { method: 'POST' }).catch(() => {});
      window.dispatchEvent(new Event('entraops:connect-status'));
    }
    setCurrentStep(0);
    setAuthHtml('');
    setAuthStatus('idle');
    setRawAuthOutput('');
    setDeviceLoginUrl(null);
    setDeviceCode(null);
    setClassifyHtml('');
    setClassifyStatus('idle');
  }, [currentStep]);

  const noneSelected = Object.values(selectedSystems).every(v => !v);
  const isClassifyRunning = classifyStatus === 'running';
  const cancelBtnLabel = cancelLabel(currentStep, isClassifyRunning);
  const showCancelBtn = !(currentStep === 3 && classifyStatus !== 'running');

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="max-w-2xl mx-auto px-4 py-8">
        <StepIndicator current={currentStep} />

        <Card className="shadow-sm">
          <CardHeader className="flex flex-row items-start justify-between pb-4">
            <div>
              <CardTitle className="text-lg font-semibold">
                {stepHeading(currentStep, authStatus, classifyStatus)}
              </CardTitle>
              <CardDescription className="text-sm text-muted-foreground mt-1">
                {stepDescription(currentStep, classifyStatus)}
              </CardDescription>
            </div>
            {showCancelBtn && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => { void handleCancel(); }}
                className="text-muted-foreground hover:text-destructive shrink-0"
              >
                {cancelBtnLabel}
              </Button>
            )}
          </CardHeader>
          <CardContent>
            {/* Step 0: Tenant form */}
            {currentStep === 0 && (
              <form
                onSubmit={(e) => { e.preventDefault(); void handleConnect(); }}
                className="flex flex-col gap-4"
              >
                <div>
                  <Label htmlFor="tenantName">Tenant name</Label>
                  <Input
                    id="tenantName"
                    value={tenantName}
                    onChange={e => { setTenantName(e.target.value); setTenantError(false); }}
                    placeholder="contoso.onmicrosoft.com"
                    className="mt-1"
                  />
                  <p className="text-xs text-muted-foreground mt-1">
                    Your tenant's .onmicrosoft.com domain or custom verified domain
                  </p>
                  {tenantError && (
                    <p className="text-xs text-destructive mt-1">Tenant name is required</p>
                  )}
                </div>
                <div>
                  <Label className="mb-2 block">Authentication type</Label>
                  <RadioGroup
                    value={authType}
                    onValueChange={v => setAuthType(v as AuthType)}
                    className="flex flex-col gap-2"
                  >
                    {[
                      {
                        value: 'DeviceAuthentication',
                        label: 'Device Code',
                        desc: 'Sign in using a one-time code — works from any machine',
                      },
                      {
                        value: 'UserInteractive',
                        label: 'User Interactive',
                        desc: 'Opens a login popup (requires desktop session)',
                      },
                    ].map(opt => (
                      <label
                        key={opt.value}
                        className={cn(
                          'flex items-start gap-3 p-3 rounded-md border border-border cursor-pointer',
                          authType === opt.value && 'border-fluent-accent bg-fluent-accent/5',
                        )}
                      >
                        <RadioGroupItem value={opt.value} id={opt.value} className="mt-0.5" />
                        <div>
                          <p className="text-sm font-semibold">{opt.label}</p>
                          <p className="text-xs text-muted-foreground">{opt.desc}</p>
                        </div>
                      </label>
                    ))}
                  </RadioGroup>
                </div>
                <Button type="submit" className="w-full" disabled={!tenantName.trim()}>
                  Connect to Tenant
                </Button>
              </form>
            )}

            {/* Step 1: Authenticate */}
            {currentStep === 1 && (
              <div>
                {deviceLoginUrl && deviceCode && (
                  <div className="mb-4 rounded-md border border-fluent-accent/30 bg-fluent-accent/8 p-4">
                    <p className="text-xs text-muted-foreground mb-1">Visit this URL and enter the code:</p>
                    <p className="text-xs font-semibold text-fluent-accent mb-2 break-all">{deviceLoginUrl}</p>
                    <div className="flex items-center justify-between">
                      <code className="text-2xl font-semibold font-mono tracking-[0.3em] text-foreground">
                        {deviceCode}
                      </code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => navigator.clipboard.writeText(deviceCode ?? '')}
                      >
                        <Clipboard size={14} className="mr-1" /> Copy Code
                      </Button>
                    </div>
                  </div>
                )}
                <TerminalOutput
                  htmlContent={authHtml}
                  status={authStatus}
                  onStop={() => { void handleCancel(); }}
                />
              </div>
            )}

            {/* Step 2: Review & Classify (RBAC selection) */}
            {currentStep === 2 && (
              <div>
                <div className="flex flex-col gap-2">
                  {RBAC_SYSTEM_META.map(sys => (
                    <label
                      key={sys.key}
                      htmlFor={sys.key}
                      className="flex items-start gap-3 rounded-md border border-border p-3 cursor-pointer hover:bg-muted/60 transition-colors"
                    >
                      <Checkbox
                        id={sys.key}
                        checked={selectedSystems[sys.key]}
                        onCheckedChange={checked =>
                          setSelectedSystems(prev => ({ ...prev, [sys.key]: !!checked }))
                        }
                        className="mt-0.5"
                      />
                      <div>
                        <p className="text-sm font-semibold text-foreground">{sys.label}</p>
                        <p className="text-xs text-muted-foreground">{sys.description}</p>
                      </div>
                    </label>
                  ))}
                </div>
                {noneSelected && (
                  <p className="text-xs text-destructive mt-2">
                    Select at least one RBAC system to continue
                  </p>
                )}
                <Button
                  className="w-full mt-4"
                  disabled={noneSelected}
                  onClick={() => { void handleStartClassify(); }}
                >
                  Start Classification
                </Button>
              </div>
            )}

            {/* Step 3: Classifying */}
            {currentStep === 3 && (
              <div>
                <div className="[&_pre]:h-96">
                  <TerminalOutput
                    htmlContent={classifyHtml}
                    status={classifyStatus}
                    onStop={() => {
                      if (classifyAbortRef.current) {
                        classifyAbortRef.current.abort();
                        classifyAbortRef.current = null;
                      }
                      setClassifyStatus('stopped');
                    }}
                  />
                </div>
                {classifyStatus !== 'idle' && classifyStatus !== 'running' && (
                  <div className="mt-4">
                    {classifyStatus === 'completed' && (
                      <Button variant="default" className="w-full" onClick={() => navigate('/')}>
                        Go to Dashboard
                      </Button>
                    )}
                    {(classifyStatus === 'failed' || classifyStatus === 'stopped') && (
                      <Button
                        variant="outline"
                        className="w-full"
                        onClick={() => { void handleCancel(); }}
                      >
                        Start Over
                      </Button>
                    )}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
