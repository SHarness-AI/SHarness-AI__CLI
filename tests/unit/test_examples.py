"""The example policies in experiments/policies are well-formed v0 policies with stable hashes."""
import json
from pathlib import Path

from sharness_ai import policy

POLICIES = Path(__file__).resolve().parents[2] / "experiments" / "policies"
FILES = sorted(POLICIES.glob("*.json"))
SYSTEM_EXEC = {"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"}


class Test_examples:
    def test_there_are_examples(self):
        assert len(FILES) >= 8

    def test_every_example_is_well_formed(self):
        for f in FILES:
            p = policy.load(f)
            assert policy.check(p) == [], f.name
            assert p["id"] == f.stem, f"{f.name}: id must be the file name"

    def test_hashes_are_distinct_and_stable(self):
        hashes = {}
        for f in FILES:
            p = policy.load(f)
            assert policy.policy_hash(p) == policy.policy_hash(json.loads(f.read_text(encoding="utf-8")))
            hashes[policy.policy_hash(p)] = f.name
        assert len(hashes) == len(FILES)

    def test_pinned_hashes(self):
        """Pinned on 25 Oct 2026; a change here is a change of policy and must be deliberate."""
        pinned = {
            "deny-all-example": "sha256:ab1d3e4e779313274f7a1d3ef3e46f6eacef038d8cfaa6198151a45cd82dcc76",
            "allow-https-example": "sha256:2944751573bbca5bbb1060c72b514de65e742ca1c2d119fcd28a744488961ef1",
            "p0-hello-world": "sha256:a6244d346ea9d7955c04defba5e67f71ae9867af618fa21d11589c7ef8449032",
            "p1-agent-session": "sha256:e619092574cc31d00d190199c1b383b586f5f5653bb5347100c3f189943dcfa8",
            "p2-tool-server": "sha256:b31ca68ae1900af5feaa2e286d5be63043110f6980055a6aa96be807d8bdba06",
            "p3-newsroom-agent": "sha256:35b17ac8592a0c13b8e75b04e0679f56248681544db71fd5a2180a2827c71aff",
            "p4-sgit": "sha256:661db5999ffbecbde5fced78fd052f8cb5ecaf9ae0d18a218579fb173c1b358e",
            "p5-web-fetch": "sha256:b897938091c29713f4478a2a6f040fbf47e6cd5164a6bfb509c3b1ffa9d41862",
        }
        for f in FILES:
            assert policy.policy_hash(policy.load(f)) == pinned[f.stem], f.name

    def test_profiles_can_start_a_dynamic_binary(self):
        """The ELF interpreter lives under /lib on musl: every profile lists it as executable."""
        for f in FILES:
            if f.stem.startswith("p"):
                assert SYSTEM_EXEC <= set(policy.load(f)["files"]["exec"]), f.name

    def test_profiles_never_make_the_workspace_executable(self):
        for f in FILES:
            p = policy.load(f)
            for w in p["files"]["write"]:
                assert not any(w == e or w.startswith(e + "/") for e in p["files"]["exec"]), f"{f.name}: {w} is writable and executable"

    def test_readme_lists_every_file(self):
        readme = (POLICIES / "README.md").read_text(encoding="utf-8")
        for f in FILES:
            assert f.name in readme, f.name
