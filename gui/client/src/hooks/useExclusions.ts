import { useState, useEffect, useCallback } from 'react';
import { fetchApi } from '@/lib/api';

interface ExclusionResponse {
  guid: string;
  displayName: string | null;
  objectType: string | null;
  resolved: boolean;
}

interface UseExclusionsResult {
  exclusions: Set<string>;
  isLoading: boolean;
  invalidate: () => void;
  addExclusion: (guid: string, displayName?: string, objectType?: string) => Promise<void>;
}

export function useExclusions(): UseExclusionsResult {
  const [exclusions, setExclusions] = useState<Set<string>>(new Set());
  const [isLoading, setIsLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);

  const invalidate = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);

    fetchApi<ExclusionResponse[]>('/api/exclusions')
      .then((res) => {
        if (!cancelled) {
          setExclusions(new Set(res.map((item) => item.guid.toLowerCase())));
          setIsLoading(false);
        }
      })
      .catch(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  const addExclusion = useCallback(async (guid: string, displayName?: string, objectType?: string): Promise<void> => {
    const res = await fetch('/api/exclusions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ guid, displayName, objectType }),
    });
    if (!res.ok && res.status !== 409) {
      throw new Error(`Failed to exclude object (${res.status})`);
    }
    invalidate();
  }, [invalidate]);

  return { exclusions, isLoading, invalidate, addExclusion };
}
