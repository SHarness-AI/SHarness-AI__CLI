import hashlib
import json
import os
import tempfile

import pytest

from sharness_ai.policy import PolicyError, canonical, check, load, policy_hash

ROOT    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXAMPLE = os.path.join(ROOT, "experiments", "policies", "deny-all-example.json")


class Test_Canonical:

    def test_sorted_keys_no_whitespace_utf8(self):
        assert canonical({"b": 1, "a": {"d": [1, "x"], "c": None}}) == b'{"a":{"c":null,"d":[1,"x"]},"b":1}'

    def test_non_ascii_is_kept_as_utf8_not_escaped(self):
        assert canonical({"id": "café"}) == '{"id":"café"}'.encode("utf-8")

    def test_floats_are_refused(self):
        with pytest.raises(PolicyError):
            canonical({"max_runtime_s": 1.5})

    def test_key_order_does_not_change_the_hash(self):
        a = {"pbp": 1, "id": "x", "network": "none"}
        b = {"network": "none", "id": "x", "pbp": 1}
        assert policy_hash(a) == policy_hash(b)

    def test_hash_is_sha256_of_the_canonical_bytes(self):
        # the vector the browser mockup (sharness.ai/mockups/policy-hash.html) must reproduce
        obj = {"pbp": 1, "id": "vector"}
        assert canonical(obj) == b'{"id":"vector","pbp":1}'
        assert policy_hash(obj) == "sha256:" + hashlib.sha256(b'{"id":"vector","pbp":1}').hexdigest()


class Test_Example_Policies:

    def test_example_is_well_formed_and_its_hash_is_stable(self):
        policy = load(EXAMPLE)
        assert check(policy) == []
        # changing the example changes this hash; the site's mockup quotes it, so update both
        assert policy_hash(policy) == "sha256:ab1d3e4e779313274f7a1d3ef3e46f6eacef038d8cfaa6198151a45cd82dcc76"

    def test_check_reports_each_problem(self):
        problems = check({"pbp": 2, "id": "", "files": {"read": ["relative"]}, "network": {"ports": []},
                          "process": {"no_new_privs": False}, "extra": 1})
        joined = "\n".join(problems)
        for s in ("pbp must be 1", "id must be", "files.read", "connect_tcp_ports", "network.ports",
                  "no_new_privs", "extra: unknown key"):
            assert s in joined

    def test_load_rejects_non_json_and_non_objects(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("[1, 2]")
        try:
            with pytest.raises(PolicyError):
                load(f.name)
        finally:
            os.unlink(f.name)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{not json")
        try:
            with pytest.raises(PolicyError):
                load(f.name)
        finally:
            os.unlink(f.name)
