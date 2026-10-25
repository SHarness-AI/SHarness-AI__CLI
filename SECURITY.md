# Security

SHarness is a security product at the experiments stage. The security pages of the site are
the full picture: the threat model, the register of known risks and accepted risks, the
findings of every review and what was done about them, and the hardening guidance.

- Threat model: https://sharness.ai/security/threat-model/index.md
- Known risks and accepted risks: https://sharness.ai/security/risks/index.md
- Reviews and findings (with fixes and dates): https://sharness.ai/security/reviews/index.md
- Hardening: how to run it, and how the repositories are locked down: https://sharness.ai/security/hardening/index.md
- Supply chain: what runs in CI, what is pinned, how a release is built and attested: https://sharness.ai/security/supply-chain/index.md

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository:
https://github.com/SHarness-AI/SHarness-AI__CLI/security/advisories/new

Please include the version (`sharness-ai --version`), the kernel (`sharness-ai probe`), the policy
file, and the command. A report that reproduces is answered with a fix or a written acceptance,
and the finding is added to the register on the site whichever it is: the aim is that nobody
reviewing this project finds something it does not already say about itself.

Do not open a public issue for a vulnerability until it is published on the register. There is no
bug bounty.

## Scope

In scope: everything in this repository that runs on a reader's machine (`sharness_ai/`, the
example policies, `experiments/browser/`, the workflows) and the release on PyPI.

Out of scope by the threat model (https://sharness.ai/design/why/index.md#threat-model): the
kernel, the hardware, the platform running the VM, and anything with root on the machine. A policy
a process applies to its own children is a Boundary for them and a Setting for itself; a report
that the applying process can skip the policy is the design's own statement, not a finding.

## Supported versions

Only the latest release on PyPI and the head of `dev`. Nothing is backported at this stage.
