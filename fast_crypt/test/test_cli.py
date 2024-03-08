# test_cli.py
import pytest
from click.testing import CliRunner
from fast_crypt.cli import main



def test_cli_exit(mocker):
    mocker.patch('click.prompt', return_value=0)
    runner = CliRunner()
    result = runner.invoke(main)
    assert result.exit_code == 0
    assert 'FastCrypt Close.' in result.output
