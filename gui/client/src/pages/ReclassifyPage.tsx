import { useState } from 'react';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useObjects } from '@/hooks/useObjects';
import { useOverrides } from '@/hooks/useOverrides';
import { useExclusions } from '@/hooks/useExclusions';
import { computedTierName } from '../../../shared/utils/tier.js';
import type { Override } from '../../../shared/types/api.js';
import { ShieldMinus, Loader2, PlayCircle } from 'lucide-react';
import { useNavigate } from 'react-router';
import { toast } from 'sonner';

const TIER_BADGE_CLASS: Record<string, string> = {
  ControlPlane: 'border-tier-control text-tier-control',
  ManagementPlane: 'border-tier-management text-tier-management',
  UserAccess: 'border-tier-user text-tier-user',
  Unclassified: 'border-tier-unclassified text-tier-unclassified',
};

const NO_OVERRIDE = '__none__';

function getEffectiveOverride(
  objectId: string,
  persisted: Override[],
  pending: Map<string, string | null>,
): string {
  if (pending.has(objectId)) return pending.get(objectId) ?? NO_OVERRIDE;
  return persisted.find((o) => o.ObjectId === objectId)?.OverrideTierLevelName ?? NO_OVERRIDE;
}

function isDirty(
  objectId: string,
  persisted: Override[],
  pending: Map<string, string | null>,
): boolean {
  if (!pending.has(objectId)) return false;
  const pendingVal = pending.get(objectId) ?? null;
  const persistedVal = persisted.find((o) => o.ObjectId === objectId)?.OverrideTierLevelName ?? null;
  return pendingVal !== persistedVal;
}

function getPendingCount(
  persisted: Override[],
  pending: Map<string, string | null>,
): number {
  return [...pending.entries()].filter(([id, val]) => {
    const persistedVal = persisted.find((o) => o.ObjectId === id)?.OverrideTierLevelName ?? null;
    return val !== persistedVal;
  }).length;
}

function buildSavePayload(
  persisted: Override[],
  pending: Map<string, string | null>,
): Override[] {
  const merged = new Map<string, string>(persisted.map((o) => [o.ObjectId, o.OverrideTierLevelName]));
  for (const [id, val] of pending) {
    if (val === null || val === '') merged.delete(id);
    else merged.set(id, val);
  }
  return [...merged.entries()].map(([ObjectId, OverrideTierLevelName]) => ({
    ObjectId,
    OverrideTierLevelName: OverrideTierLevelName as Override['OverrideTierLevelName'],
  }));
}

export function ReclassifyPage() {
  const [pending, setPending] = useState<Map<string, string | null>>(new Map());
  const [isSaving, setIsSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const { data: objectsData, isLoading: objectsLoading } = useObjects({ pageSize: 10000 });
  const { data: persistedOverrides, isLoading: overridesLoading, invalidate } = useOverrides();
  const { exclusions, isLoading: exclusionsLoading, addExclusion } = useExclusions();

  const objects = objectsData?.objects ?? [];
  const isLoading = objectsLoading || overridesLoading || exclusionsLoading;

  const pendingCount = getPendingCount(persistedOverrides, pending);
  const navigate = useNavigate();
  const [excludingIds, setExcludingIds] = useState<Set<string>>(new Set());

  function handleOverrideChange(objectId: string, value: string) {
    setPending((prev) => {
      const next = new Map(prev);
      next.set(objectId, value === NO_OVERRIDE ? null : value);
      return next;
    });
  }

  async function handleSave() {
    setIsSaving(true);
    setSaveError(null);
    try {
      const payload = buildSavePayload(persistedOverrides, pending);
      const res = await fetch('/api/overrides', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ overrides: payload }),
      });
      if (!res.ok) {
        const err = await res.json() as { error: unknown };
        setSaveError(`Save failed: ${JSON.stringify(err.error)}`);
        return;
      }
      setPending(new Map());
      invalidate();
    } catch (err) {
      setSaveError(String(err));
    } finally {
      setIsSaving(false);
    }
  }

  function handleDiscard() {
    setPending(new Map());
  }

  async function handleExclude(objectId: string, displayName?: string, objectType?: string) {
    // D-14: Remove pending override synchronously before the async POST
    // so getPendingCount reflects the correct count immediately (D-15)
    const previousPendingValue = pending.get(objectId);
    const hadPendingEntry = pending.has(objectId);

    if (hadPendingEntry) {
      setPending((prev) => {
        const next = new Map(prev);
        next.delete(objectId);
        return next;
      });
    }

    // D-12: mark in-flight
    setExcludingIds((prev) => new Set([...prev, objectId]));

    try {
      await addExclusion(objectId, displayName, objectType);
      // D-11: individual toast per action; D-16: user stays on Reclassify screen
      toast.success('Object excluded', {
        action: {
          label: 'View Exclusions →',
          onClick: () => navigate('/exclusions'),
        },
      });
    } catch {
      // Restore pending entry on failure (preserve user's unsaved override work)
      if (hadPendingEntry) {
        setPending((prev) => {
          const next = new Map(prev);
          next.set(objectId, previousPendingValue ?? null);
          return next;
        });
      }
      toast.error('Failed to exclude object — please try again');
    } finally {
      setExcludingIds((prev) => {
        const next = new Set(prev);
        next.delete(objectId);
        return next;
      });
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground text-sm">
        Loading...
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Page header */}
      <div className="px-6 py-4 border-b border-border">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-xl font-semibold">Reclassify Objects</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Override the tier assignment for individual objects. Changes are display-layer only.
            </p>
          </div>
          <Button variant="secondary" onClick={() => navigate('/apply')}>
            <PlayCircle size={16} className="mr-2" />
            Apply to Entra
          </Button>
        </div>
      </div>

      {/* Sticky action bar — only visible when there are pending changes */}
      {pendingCount > 0 && (
        <div className="sticky top-0 z-10 flex items-center gap-3 bg-background border-b border-border px-6 py-3">
          <Button onClick={handleSave} disabled={isSaving}>
            {isSaving ? 'Saving...' : `Save All (${pendingCount})`}
          </Button>
          <Button variant="ghost" onClick={handleDiscard} disabled={isSaving}>
            Discard
          </Button>
          {saveError && (
            <p className="text-destructive text-sm">{saveError}</p>
          )}
        </div>
      )}

      {/* Reclassification table */}
      <div className="flex-1 overflow-auto px-6 py-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Object</TableHead>
              <TableHead>Applied Tier</TableHead>
              <TableHead>Computed Tier</TableHead>
              <TableHead>Override</TableHead>
              <TableHead className="text-right w-[100px]">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {objects.map((obj) => {
              const computedTier = computedTierName(obj.Classification);
              const dirty = isDirty(obj.ObjectId, persistedOverrides, pending);
              const effectiveOverride = getEffectiveOverride(obj.ObjectId, persistedOverrides, pending);
              const isExcluded = exclusions.has(obj.ObjectId);

              return (
                <TableRow
                  key={obj.ObjectId}
                  className={cn(dirty && 'bg-amber-500/10', isExcluded && 'opacity-60')}
                >
                  {/* Object name */}
                  <TableCell className="font-medium">
                    <div className="flex items-center gap-2">
                      {obj.ObjectDisplayName}
                      {isExcluded && (
                        <Badge
                          variant="outline"
                          className="text-xs font-medium text-muted-foreground border-muted-foreground/40"
                          title="This object is in the Global Exclusions list and will be skipped by the classification engine"
                        >
                          Excluded
                        </Badge>
                      )}
                    </div>
                  </TableCell>

                  {/* Applied Tier — solid badge */}
                  <TableCell>
                    {obj.ObjectAdminTierLevelName ? (
                      <Badge
                        variant="outline"
                        className={cn(
                          'text-xs font-medium',
                          TIER_BADGE_CLASS[obj.ObjectAdminTierLevelName] ?? '',
                        )}
                      >
                        {obj.ObjectAdminTierLevelName}
                      </Badge>
                    ) : (
                      <span className="text-muted-foreground text-xs">—</span>
                    )}
                  </TableCell>

                  {/* Computed Tier — dashed badge */}
                  <TableCell>
                    {computedTier ? (
                      <Badge
                        variant="outline"
                        className={cn(
                          'text-xs font-medium border-dashed',
                          TIER_BADGE_CLASS[computedTier] ?? '',
                        )}
                      >
                        {computedTier}
                      </Badge>
                    ) : (
                      <span className="text-muted-foreground text-xs">—</span>
                    )}
                  </TableCell>

                  {/* Override Select */}
                  <TableCell>
                    <Select
                      value={effectiveOverride}
                      onValueChange={(val) => handleOverrideChange(obj.ObjectId, val)}
                      disabled={isExcluded}
                    >
                      <SelectTrigger className="h-7 text-xs w-[160px]">
                        <SelectValue placeholder="— No override" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value={NO_OVERRIDE}>— No override</SelectItem>
                        <SelectItem value="ControlPlane">Control Plane</SelectItem>
                        <SelectItem value="ManagementPlane">Management Plane</SelectItem>
                        <SelectItem value="UserAccess">User Access</SelectItem>
                      </SelectContent>
                    </Select>
                  </TableCell>

                  {/* Actions — per UI-SPEC: null cell for already-excluded rows (badge already in Object cell) */}
                  <TableCell className="text-right">
                    {!isExcluded && (
                      excludingIds.has(obj.ObjectId) ? (
                        <Button variant="ghost" size="sm" className="h-7 gap-1" disabled>
                          <Loader2 size={14} className="animate-spin" />
                          Exclude
                        </Button>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 gap-1"
                          aria-label={`Exclude ${obj.ObjectDisplayName} from classification`}
                          onClick={() => handleExclude(obj.ObjectId, obj.ObjectDisplayName, obj.ObjectType)}
                        >
                          <ShieldMinus size={14} />
                          Exclude
                        </Button>
                      )
                    )}
                  </TableCell>
                </TableRow>
              );
            })}

            {objects.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="text-center text-muted-foreground py-12">
                  No objects found. Run Save-EntraOpsPrivilegedEAMJson to load data.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
