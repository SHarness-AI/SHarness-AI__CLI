import re

import pytest

from sharness_ai           import VERSION
from sharness_ai.cli       import main
from sharness_ai._version  import VERSION_FILE


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
        assert 'usage: sharness-ai' in capsys.readouterr().out
