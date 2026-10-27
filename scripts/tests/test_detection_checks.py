"""The shell checks added from what the botnet self-test does.

The 28 published checks score the build that fails the self-test in the wild exactly like the fixed
one, so they cannot see that regression. These two probes are written by us, not replayed from a
payload, and are tried here against fake shells that answer like the real host, the regressed build
and an old build.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection_checks import SHELL_CHECKS, sh_case_in_substitution, sh_write_chmod_run  # noqa: E402


class Fake:
    def __init__(self, out=b"", err=b"", code=0):
        self.reply = (out, err, code)
        self.ran = []

    def run(self, cmd):
        self.ran.append(cmd)
        return self.reply


def test_case_in_substitution_passes_like_bash():
    ok, obs = sh_case_in_substitution(Fake(b"[sub]\n"))
    assert ok, obs


def test_case_in_substitution_fails_on_the_regressed_parser():
    ok, obs = sh_case_in_substitution(Fake(b"", b"bash: syntax error near unexpected token `;;'\n", 2))
    assert not ok and "syntax error" in obs, obs


def test_case_in_substitution_fails_when_case_is_unsupported():
    ok, _ = sh_case_in_substitution(Fake(b"sub\r\nbash: esac): command not found\r\n[]\r\n"))
    assert not ok


def test_write_chmod_run_passes_like_bash():
    ok, obs = sh_write_chmod_run(Fake(b"hi\n"))
    assert ok, obs


def test_write_chmod_run_fails_when_the_script_does_not_run():
    ok, _ = sh_write_chmod_run(Fake(b"", b"bash: /tmp/.dc_script: Permission denied\n", 126))
    assert not ok


def test_the_probes_do_not_leave_files_behind():
    f = Fake(b"hi\n")
    sh_write_chmod_run(f)
    assert any("rm -f" in c for c in f.ran), f.ran


def test_both_checks_are_registered_with_a_source():
    names = {title: source for title, source, _ in SHELL_CHECKS}
    assert names["case statement inside $( )"].startswith("botnet self-test")
    assert names["write, chmod +x and run a script"].startswith("botnet self-test")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok", t.__name__)
    print(f"\n{len(tests)} tests passed")
