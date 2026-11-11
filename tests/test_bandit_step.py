import os
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "bandit_step.sh"
PASSWORD = "A" * 32
NEXT = "b" * 32

# A stand-in for ssh. It asks SSH_ASKPASS for the password the same way OpenSSH does,
# then checks it against FAKE_EXPECT and prints FAKE_OUTPUT.
FAKE_SSH = """#!/bin/bash
if [ -z "$SSH_ASKPASS" ] || [ "$SSH_ASKPASS_REQUIRE" != "force" ]; then
  echo "askpass not configured" >&2
  exit 3
fi
got="$("$SSH_ASKPASS")"
if [ "$got" != "$FAKE_EXPECT" ]; then
  echo "Permission denied" >&2
  exit 255
fi
cat "$FAKE_OUTPUT"
"""


@pytest.fixture
def env(tmp_path):
    fake = tmp_path / "fake-ssh"
    fake.write_text(FAKE_SSH)
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    passes = tmp_path / "passwords"
    passes.mkdir()
    (passes / "pass12").write_text(PASSWORD + "\n")
    output = tmp_path / "output.txt"
    base = os.environ.copy()
    base.update(
        {
            "SSH_BIN": str(fake),
            "BANDIT_PASS_DIR": str(passes),
            "FAKE_EXPECT": PASSWORD,
            "FAKE_OUTPUT": str(output),
        }
    )
    return base, passes, output


def run(env, *args):
    return subprocess.run(["bash", str(SCRIPT), *args], env=env, capture_output=True, text=True)


def test_saves_next_password_and_does_not_print_it(env):
    base, passes, output = env
    output.write_text(NEXT + "\n")
    result = run(base, "12", "cat data.txt")
    assert result.returncode == 0, result.stderr
    assert (passes / "pass13").read_text() == NEXT + "\n"
    assert NEXT not in result.stdout and NEXT not in result.stderr
    assert oct((passes / "pass13").stat().st_mode & 0o777) == "0o600"


def test_ignores_blank_lines_and_carriage_returns(env):
    base, passes, output = env
    output.write_text("\n" + NEXT + "\r\n\n")
    result = run(base, "12", "cat data.txt")
    assert result.returncode == 0, result.stderr
    assert (passes / "pass13").read_text() == NEXT + "\n"


def test_refuses_output_with_several_lines(env):
    base, passes, output = env
    output.write_text("Correct!\n" + NEXT + "\n")
    result = run(base, "12", "cat data.txt")
    assert result.returncode == 1
    assert "nothing saved" in result.stderr
    assert not (passes / "pass13").exists()


def test_refuses_short_output(env):
    base, passes, output = env
    output.write_text("not a password\n")
    result = run(base, "12", "cat data.txt")
    assert result.returncode == 1
    assert not (passes / "pass13").exists()


def test_refuses_to_overwrite_an_existing_password(env):
    base, passes, output = env
    (passes / "pass13").write_text("keep me\n")
    output.write_text(NEXT + "\n")
    result = run(base, "12", "cat data.txt")
    assert result.returncode == 1
    assert (passes / "pass13").read_text() == "keep me\n"


def test_wrong_password_is_reported_and_nothing_saved(env):
    base, passes, output = env
    base["FAKE_EXPECT"] = "C" * 32
    output.write_text(NEXT + "\n")
    result = run(base, "12", "cat data.txt")
    assert result.returncode == 1
    assert "status 255" in result.stderr
    assert not (passes / "pass13").exists()


def test_show_mode_prints_output_and_saves_nothing(env):
    base, passes, output = env
    output.write_text("Correct!\n" + NEXT + "\n")
    result = run(base, "--show", "12", "cat data.txt")
    assert result.returncode == 0, result.stderr
    assert "Correct!" in result.stdout
    assert not (passes / "pass13").exists()


def test_missing_password_file_is_a_clear_error(env):
    base, passes, _output = env
    result = run(base, "7", "cat data.txt")
    assert result.returncode == 1
    assert "missing" in result.stderr


def test_usage_and_level_validation(env):
    base, _passes, _output = env
    assert run(base).returncode == 2
    assert run(base, "x", "cat").returncode == 2
