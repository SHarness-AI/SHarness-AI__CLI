// Refreshes the vendored vectors from the standard's published copy on sharness.ai.
import { mkdirSync, writeFileSync } from 'node:fs';
const BASE = 'https://sharness.ai/code/standards/policy-v0/';
const dir = new URL(process.cwd() + '/', 'file://');
const manifest = await (await fetch(BASE + 'vectors.json')).json();
mkdirSync(new URL('vectors/', dir), { recursive: true });
writeFileSync(new URL('vectors.json', dir), JSON.stringify(manifest, null, 1) + '\n');
for (const c of manifest.cases) writeFileSync(new URL(c.file, dir), await (await fetch(BASE + c.file)).text());
console.log(`fetched ${manifest.cases.length} vectors (oracle ${manifest.oracle.commit}, generated ${manifest.generated})`);
