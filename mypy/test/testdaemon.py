"""End-to-end test cases for the daemon (dmypy).

These are special because they run multiple shell commands.

This also includes some unit tests.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

from mypy.dmypy_server import filter_out_missing_top_level_packages
from mypy.fscache import FileSystemCache
from mypy.modulefinder import SearchPaths
from mypy.test.config import PREFIX, test_temp_dir
from mypy.test.data import DataDrivenTestCase, DataSuite
from mypy.test.helpers import assert_string_arrays_equal, normalize_error_messages

# Files containing test cases descriptions.
daemon_files = ["daemon.test"]


class DaemonSuite(DataSuite):
    files = daemon_files

    def run_case(self, testcase: DataDrivenTestCase) -> None:
        try:
            test_daemon(testcase)
        finally:
            # Kill the daemon if it's still running.
            run_cmd("dmypy kill")


def test_daemon(testcase: DataDrivenTestCase) -> None:
    assert testcase.old_cwd is not None, "test was not properly set up"
    for i, step in enumerate(parse_script(testcase.input)):
        cmd = step[0]
        expected_lines = step[1:]
        assert cmd.startswith("$")
        cmd = cmd[1:].strip()
        cmd = cmd.replace("{python}", sys.executable)
        if cmd.split()[1] in ("start", "restart", "run"):
            cmd = cmd.replace(
                "-- ", "-- --no-strict --no-infer-function-types --no-default-return "
            )
        sts, output = run_cmd(cmd)
        output_lines = output.splitlines()
        output_lines = normalize_error_messages(output_lines)
        if sts:
            output_lines.append("== Return code: %d" % sts)
        assert_string_arrays_equal(
            expected_lines,
            output_lines,
            "Command %d (%s) did not give expected output" % (i + 1, cmd),
        )


def parse_script(input: list[str]) -> list[list[str]]:
    """Parse testcase.input into steps.

    Each command starts with a line starting with '$'.
    The first line (less '$') is sent to the shell.
    The remaining lines are expected output.
    """
    steps = []
    step: list[str] = []
    for line in input:
        if line.startswith("$"):
            if step:
                assert step[0].startswith("$")
                steps.append(step)
                step = []
        step.append(line)
    if step:
        steps.append(step)
    return steps


def run_cmd(input: str) -> tuple[int, str]:
    if input[1:].startswith("mypy run --") and "--show-error-codes" not in input:
        input += " --hide-error-codes"
    if input.startswith("dmypy "):
        input = sys.executable + " -m mypy." + input
    if input.startswith("mypy "):
        input = sys.executable + " -m" + input
    env = os.environ.copy()
    env["PYTHONPATH"] = PREFIX
    env["__MYPY_UNDER_TEST__"] = "1"
    try:
        output = subprocess.check_output(
            input, shell=True, stderr=subprocess.STDOUT, text=True, cwd=test_temp_dir, env=env
        )
        return 0, output
    except subprocess.CalledProcessError as err:
        return err.returncode, err.output


class DaemonUtilitySuite(unittest.TestCase):
    """Unit tests for helpers"""

    def test_filter_out_missing_top_level_packages(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.make_file(td, "base/a/")
            self.make_file(td, "base/b.py")
            self.make_file(td, "base/c.pyi")
            self.make_file(td, "base/missing.txt")
            self.make_file(td, "typeshed/d.pyi")
            self.make_file(td, "typeshed/@python2/e")  # outdated
            self.make_file(td, "pkg1/f-stubs")
            self.make_file(td, "pkg2/g-python2-stubs")  # outdated
            self.make_file(td, "mpath/sub/long_name/")

            def makepath(p: str) -> str:
                return os.path.join(td, p)

            search = SearchPaths(
                python_path=(makepath("base"),),
                mypy_path=(makepath("mpath/sub"),),
                package_path=(makepath("pkg1"), makepath("pkg2")),
                typeshed_path=(makepath("typeshed"),),
            )
            fscache = FileSystemCache()
            res = filter_out_missing_top_level_packages(
                {"a", "b", "c", "d", "e", "f", "g", "long_name", "ff", "missing"}, search, fscache
            )
            assert res == {"a", "b", "c", "d", "f", "long_name"}

    def make_file(self, base: str, path: str) -> None:
        fullpath = os.path.join(base, path)
        os.makedirs(os.path.dirname(fullpath), exist_ok=True)
        if not path.endswith("/"):
            with open(fullpath, "w") as f:
                f.write("# test file")
