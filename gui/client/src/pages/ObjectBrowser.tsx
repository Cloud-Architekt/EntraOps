import { useState, useCallback } from 'react';
import { parseAsString, parseAsArrayOf, parseAsInteger, useQueryStates } from 'nuqs';
import { useObjects } from '@/hooks/useObjects';
import { ObjectFilters } from '@/components/objects/ObjectFilters';
import { ObjectTable } from '@/components/objects/ObjectTable';
import { ObjectDetailPanel } from '@/components/objects/ObjectDetailPanel';
import type { PrivilegedObject } from '../../../shared/types/eam';
import { useNavigate } from 'react-router';
import { toast } from 'sonner';
import { useExclusions } from '@/hooks/useExclusions';
import { Button } from '@/components/ui/button';
import { PlayCircle } from 'lucide-react';

// nuqs URL param schema — RESEARCH.md Pattern 5 (react-router/v7 adapter)
// sort stores an actual PrivilegedObject field name (used as sortBy on server)
const OBJECT_PARAMS = {
  q:      parseAsString.withDefault(''),
  tier:   parseAsArrayOf(parseAsString).withDefault([]),
  rbac:   parseAsArrayOf(parseAsString).withDefault([]),
  type:   parseAsArrayOf(parseAsString).withDefault([]),
  pim:    parseAsArrayOf(parseAsString).withDefault([]),
  onprem: parseAsString.withDefault(''),
  sort:   parseAsString.withDefault('ObjectAdminTierLevel'),
  order:  parseAsString.withDefault('asc'),
  page:   parseAsInteger.withDefault(1),
};

const PAGE_SIZE = 50;

export function ObjectBrowser() {
  const [selectedObject, setSelectedObject] = useState<PrivilegedObject | null>(null);
  const [params, setParams] = useQueryStates(OBJECT_PARAMS);

  const { data, isLoading, error } = useObjects({
    q:        params.q || undefined,
    tier:     params.tier.length ? params.tier : undefined,
    rbac:     params.rbac.length ? params.rbac : undefined,
    type:     params.type.length ? params.type : undefined,
    pim:      params.pim.length ? params.pim : undefined,
    onprem:   params.onprem || undefined,
    sort:     params.sort,
    order:    params.order as 'asc' | 'desc',
    page:     params.page,
    pageSize: PAGE_SIZE,
  });

  // Derive available object types from the current result set for the dynamic type filter
  const availableTypes = data
    ? Array.from(new Set(data.objects.map(o => o.ObjectType))).sort()
    : [];

  function handleSortChange(column: string) {
    if (params.sort === column) {
      // Toggle direction on same column; reset to page 1
      setParams({ order: params.order === 'asc' ? 'desc' : 'asc', page: 1 });
    } else {
      setParams({ sort: column, order: 'asc', page: 1 });
    }
  }

  function handleRowClick(object: PrivilegedObject) {
    setSelectedObject(object);
  }

  const navigate = useNavigate();
  const { exclusions, addExclusion } = useExclusions();
  const [pendingExcludes, setPendingExcludes] = useState<Set<string>>(new Set());

  const handleExclude = useCallback(async (object: PrivilegedObject) => {
    const guid = object.ObjectId;
    setPendingExcludes((prev) => new Set([...prev, guid]));
    try {
      await addExclusion(guid, object.ObjectDisplayName, object.ObjectType);
      toast.success('Object excluded', {
        action: {
          label: 'View Exclusions →',
          onClick: () => navigate('/exclusions'),
        },
      });
    } catch {
      toast.error('Failed to exclude object — please try again');
    } finally {
      setPendingExcludes((prev) => {
        const next = new Set(prev);
        next.delete(guid);
        return next;
      });
    }
  }, [addExclusion, navigate]);

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[22px] font-semibold">Object Browser</h1>
          <p className="text-sm text-muted-foreground">
            Browse and filter privileged identity objects across all RBAC systems
          </p>
        </div>
        <Button variant="secondary" onClick={() => navigate('/apply')}>
          <PlayCircle size={16} className="mr-2" />
          Apply to Entra
        </Button>
      </div>

      <ObjectFilters
        q={params.q}
        tier={params.tier}
        rbac={params.rbac}
        type={params.type}
        pim={params.pim}
        onprem={params.onprem}
        availableTypes={availableTypes}
        onQChange={q => setParams({ q, page: 1 })}
        onTierChange={tier => setParams({ tier, page: 1 })}
        onRbacChange={rbac => setParams({ rbac, page: 1 })}
        onTypeChange={type => setParams({ type, page: 1 })}
        onPimChange={pim => setParams({ pim, page: 1 })}
        onOnpremChange={onprem => setParams({ onprem, page: 1 })}
      />

      {error ? (
        <p className="text-sm text-destructive">Failed to load objects: {error}</p>
      ) : (
        <ObjectTable
          objects={data?.objects ?? []}
          total={data?.total ?? 0}
          page={params.page}
          pageSize={PAGE_SIZE}
          isLoading={isLoading}
          sort={params.sort}
          order={params.order as 'asc' | 'desc'}
          onSortChange={handleSortChange}
          onPageChange={page => setParams({ page })}
          onRowClick={handleRowClick}
          excludedIds={exclusions}
          loadingIds={pendingExcludes}
          onExclude={handleExclude}
        />
      )}

      <ObjectDetailPanel
        object={selectedObject}
        onClose={() => setSelectedObject(null)}
      />
    </div>
  );
}
