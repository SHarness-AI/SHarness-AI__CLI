#!/usr/bin/env node
// sharness-ai, the JavaScript reference implementation: policy hash FILE | policy check FILE.
// The same words and exit codes as the Python CLI for these two commands; nothing else exists yet.
import { readFileSync } from 'node:fs';
import { canonical, check, parse, policyHash, PolicyError, summary } from '../src/policy.js';

const USAGE = `sharness-ai (JavaScript) experiments stage: no SHarness component is built
  policy hash FILE     the one value the person supplies: canonical JSON -> sha256:...
  policy check FILE    the shape of a v0 policy
The standard and its test vectors: https://sharness.ai/code/standards/policy-v0/`;

export async function main(argv) {
  const [group, cmd, file] = argv;
  if (group !== 'policy' || !['hash', 'check'].includes(cmd) || !file) { console.log(USAGE); return argv.length ? 2 : 0; }
  let policy;
  try {
    policy = parse(readFileSync(file, 'utf8'), file);
    if (cmd === 'hash') { canonical(policy); console.log(await policyHash(policy)); return 0; }
  } catch (e) {
    if (!(e instanceof PolicyError)) throw e;
    console.error(`sharness-ai policy: ${e.message}`);
    return 1;
  }
  const problems = check(policy);
  if (problems.length) {
    console.log(`${file}: ${problems.length} problem(s)`);
    for (const x of problems) console.log(`  x ${x}`);
    return 1;
  }
  console.log(`${file}: well-formed v0 policy, id ${policy.id}: ${summary(policy)}; ${await policyHash(policy)}`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exit(await main(process.argv.slice(2)));
