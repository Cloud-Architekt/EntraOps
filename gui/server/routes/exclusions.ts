import { Router } from 'express';
import path from 'node:path';
import fs from 'node:fs/promises';
import { z } from 'zod';
import { atomicWrite } from '../utils/atomicWrite.js';

const router = Router();

const REPO_ROOT = process.env.ENTRAOPS_ROOT ?? path.resolve(import.meta.dirname, '../../..');
const GLOBAL_JSON = path.join(REPO_ROOT, 'Classification', 'Global.json');
const PRIVILEGED_EAM_BASE = path.join(REPO_ROOT, 'PrivilegedEAM');

const NAMES_CACHE_JSON = path.join(REPO_ROOT, 'Classification', 'ExclusionsNamesCache.json');

const UUIDParam = z.string().uuid();
const PostBodySchema = z.object({
  guid: z.string().uuid(),
  displayName: z.string().optional(),
  objectType: z.string().optional(),
});
const GlobalFileSchema = z.tuple([z.object({ ExcludedPrincipalId: z.array(z.string()) })]).rest(z.unknown());
const NamesCacheSchema = z.record(z.string(), z.object({ displayName: z.string(), objectType: z.string() }));
type NamesCache = z.infer<typeof NamesCacheSchema>;

interface ExclusionItem {
  guid: string;
  displayName: string | null;
  objectType: string | null;
  resolved: boolean;
}

function parseBomJson(raw: string): unknown {
  return JSON.parse(raw.replace(/^\uFEFF/, ''));
}

async function readNamesCache(): Promise<NamesCache> {
  try {
    const raw = await fs.readFile(NAMES_CACHE_JSON, 'utf-8');
    const result = NamesCacheSchema.safeParse(JSON.parse(raw));
    return result.success ? result.data : {};
  } catch {
    return {};
  }
}

async function writeNamesCache(cache: NamesCache): Promise<void> {
  await atomicWrite(NAMES_CACHE_JSON, JSON.stringify(cache, null, 2));
}

async function buildNameLookup(): Promise<Map<string, { displayName: string | null; objectType: string | null }>> {
  const map = new Map<string, { displayName: string | null; objectType: string | null }>();

  // Seed from names cache first — covers objects excluded before the last classification run
  const cache = await readNamesCache();
  for (const [guid, entry] of Object.entries(cache)) {
    map.set(guid.toLowerCase(), { displayName: entry.displayName, objectType: entry.objectType });
  }

  // Supplement with live EAM data — overrides cache with fresher data if object is present
  try {
    const entries = await fs.readdir(PRIVILEGED_EAM_BASE, { recursive: true });
    for (const entry of entries) {
      if (!String(entry).endsWith('.json')) continue;
      try {
        const raw = await fs.readFile(path.join(PRIVILEGED_EAM_BASE, String(entry)), 'utf-8');
        const parsed = parseBomJson(raw);
        const items = Array.isArray(parsed) ? parsed : [parsed];
        for (const item of items) {
          if (item && typeof item === 'object' && typeof (item as Record<string, unknown>).ObjectId === 'string') {
            const obj = item as Record<string, unknown>;
            map.set(String(obj.ObjectId).toLowerCase(), {
              displayName: typeof obj.ObjectDisplayName === 'string' ? obj.ObjectDisplayName : null,
              objectType: typeof obj.ObjectType === 'string' ? obj.ObjectType : null,
            });
          }
        }
      } catch {
        // Skip unreadable files
      }
    }
  } catch {
    // Missing directory — return empty map
  }
  return map;
}

router.get('/', async (_req, res, next) => {
  try {
    let guids: string[] = [];
    try {
      const raw = await fs.readFile(GLOBAL_JSON, 'utf-8');
      const parsed = GlobalFileSchema.safeParse(parseBomJson(raw));
      if (parsed.success) guids = parsed.data[0].ExcludedPrincipalId;
    } catch {
      // Missing or malformed — return empty
    }

    const lookup = await buildNameLookup();
    const items: ExclusionItem[] = guids.map(guid => {
      const entry = lookup.get(guid.toLowerCase());
      return {
        guid,
        displayName: entry?.displayName ?? null,
        objectType: entry?.objectType ?? null,
        resolved: entry !== undefined,
      };
    });
    res.json(items);
  } catch (err) {
    next(err);
  }
});

router.delete('/:guid', async (req, res, next) => {
  try {
    const paramResult = UUIDParam.safeParse(req.params.guid);
    if (!paramResult.success) {
      res.status(400).json({ error: 'Invalid GUID' });
      return;
    }
    const guid = paramResult.data;

    let raw: string;
    try {
      raw = await fs.readFile(GLOBAL_JSON, 'utf-8');
    } catch {
      res.status(404).json({ error: 'Global.json not found' });
      return;
    }

    const parseResult = GlobalFileSchema.safeParse(parseBomJson(raw));
    if (!parseResult.success) {
      res.status(500).json({ error: 'Failed to parse Global.json' });
      return;
    }

    const data = parseResult.data;
    const exists = data[0].ExcludedPrincipalId.some(g => g.toLowerCase() === guid.toLowerCase());
    if (!exists) {
      res.status(404).json({ error: 'GUID not found in exclusions' });
      return;
    }

    data[0].ExcludedPrincipalId = data[0].ExcludedPrincipalId.filter(g => g.toLowerCase() !== guid.toLowerCase());
    await atomicWrite(GLOBAL_JSON, JSON.stringify(data, null, 2));

    // Remove from names cache so stale entries don't accumulate
    const cache = await readNamesCache();
    delete cache[guid.toLowerCase()];
    await writeNamesCache(cache);

    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

router.post('/', async (req, res, next) => {
  try {
    const bodyResult = PostBodySchema.safeParse(req.body);
    if (!bodyResult.success) {
      res.status(400).json({ error: 'Invalid GUID' });
      return;
    }
    const guid = bodyResult.data.guid;

    let raw: string;
    try {
      raw = await fs.readFile(GLOBAL_JSON, 'utf-8');
    } catch {
      res.status(404).json({ error: 'Global.json not found' });
      return;
    }

    const parseResult = GlobalFileSchema.safeParse(parseBomJson(raw));
    if (!parseResult.success) {
      res.status(500).json({ error: 'Failed to parse Global.json' });
      return;
    }

    const data = parseResult.data;
    const alreadyExists = data[0].ExcludedPrincipalId.some(
      (g) => g.toLowerCase() === guid.toLowerCase(),
    );
    if (alreadyExists) {
      res.status(409).json({ error: 'Already excluded' });
      return;
    }

    data[0].ExcludedPrincipalId.push(guid);
    await atomicWrite(GLOBAL_JSON, JSON.stringify(data, null, 2));

    // Cache display name so Exclusions page can resolve it even after a classification run
    const { displayName, objectType } = bodyResult.data;
    if (displayName) {
      const cache = await readNamesCache();
      cache[guid.toLowerCase()] = { displayName, objectType: objectType ?? '' };
      await writeNamesCache(cache);
    }

    res.status(201).end();
  } catch (err) {
    next(err);
  }
});

export { router as exclusionsRouter };
