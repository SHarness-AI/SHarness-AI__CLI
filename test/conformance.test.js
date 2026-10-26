// The standard's test vectors: every accept case hashes to the hash the standard gives, every
// refuse case is refused. conformance/vectors.json is a vendored copy; `npm run conformance:fetch`
// refreshes it from sharness.ai, and CI runs this file against the live copy too.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { check, parse, policyHash, PolicyError } from '../src/policy.js';

const dir = new URL(process.env.SHARNESS_AI_VECTORS ? process.env.SHARNESS_AI_VECTORS + '/' : '../conformance/', import.meta.url);
const manifest = JSON.parse(readFileSync(new URL('vectors.json', dir), 'utf8'));

for (const c of manifest.cases) {
  const text = readFileSync(new URL(c.file, dir), 'utf8');
  if (c.kind === 'accept') {
    test(`accept ${c.name}`, async () => {
      const policy = parse(text, c.name);
      assert.deepEqual(check(policy), []);
      assert.equal(await policyHash(policy), c.hash);
    });
  } else {
    test(`refuse ${c.name} (${c.reason})`, () => {
      let refused = false;
      try { refused = check(parse(text, c.name)).length > 0; } catch (e) { if (!(e instanceof PolicyError)) throw e; refused = true; }
      assert.ok(refused, `${c.name} must be refused`);
    });
  }
}

test('the vendored manifest is the standard at v0', () => {
  assert.equal(manifest.standard, 'policy');
  assert.equal(manifest.version, 'v0');
  assert.equal(manifest.cases.length, manifest.counts.accept + manifest.counts.refuse);
});
