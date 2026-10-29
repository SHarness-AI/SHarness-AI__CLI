import os
import re

import pytest

from sharness_ai           import VERSION
from sharness_ai.cli       import main
from sharness_ai._version  import VERSION_FILE

ROOT    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXAMPLE = os.path.join(ROOT, "experiments", "policies", "deny-all-example.json")


class Test_Version:

    def test_version_is_read_from_the_version_file(self):
        with open(VERSION_FILE) as f:
            assert VERSION == f.read().strip()

    def test_version_is_a_release_tag(self):
        assert re.fullmatch(r'v\d+\.\d+\.\d+', VERSION)


class Test_CLI:

    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(['--version'])
        assert exc.value.code == 0
        assert capsys.readouterr().out.strip() == f'sharness-ai {VERSION}'

    def test_no_args_prints_help(self, capsys):
        assert main([]) == 0
        out = capsys.readouterr().out
        assert 'usage: sharness-ai' in out
        for cmd in ('probe', 'policy', 'run', 'hello'):
            assert cmd in out

    def test_probe_text_and_json(self, capsys):
        assert main(['probe']) == 0
        assert 'the grant' in capsys.readouterr().out
        assert main(['probe', '--json']) == 0
        assert '"landlock_abi"' in capsys.readouterr().out

    def test_policy_hash_and_check(self, capsys):
        assert main(['policy', 'hash', EXAMPLE]) == 0
        assert capsys.readouterr().out.strip() == 'sha256:ab1d3e4e779313274f7a1d3ef3e46f6eacef038d8cfaa6198151a45cd82dcc76'
        assert main(['policy', 'check', EXAMPLE]) == 0
        assert 'well-formed' in capsys.readouterr().out

    def test_policy_check_fails_on_a_bad_file(self, tmp_path, capsys):
        p = tmp_path / 'bad.json'
        p.write_text('{"pbp": 1}')
        assert main(['policy', 'check', str(p)]) == 1
        assert 'problem' in capsys.readouterr().out

    def test_run_with_a_missing_policy_file_is_refused(self, capsys):
        assert main(['run', '--policy', '/nonexistent.json', '--', 'true']) == 125
