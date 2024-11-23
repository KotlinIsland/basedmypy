"""Utilities for processing .test files containing test case descriptions."""

from __future__ import annotations

import os
import os.path
import posixpath
import re
import shutil
import sys
import tempfile
from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Iterator, NamedTuple, NoReturn, Pattern, Union
from typing_extensions import TypeAlias as _TypeAlias

import pytest

from mypy import defaults
from mypy.test.config import PREFIX, test_data_prefix, test_temp_dir
from mypy.util import safe

root_dir = os.path.normpath(PREFIX)

# Debuggers that we support for debugging mypyc run tests
# implementation of using each of these debuggers is in test_run.py
# TODO: support more debuggers
SUPPORTED_DEBUGGERS: Final = ["gdb", "lldb"]


# File modify/create operation: copy module contents from source_path.
class UpdateFile(NamedTuple):
    module: str
    content: str
    target_path: str


# File delete operation: delete module file.
class DeleteFile(NamedTuple):
    module: str
    path: str


FileOperation: _TypeAlias = Union[UpdateFile, DeleteFile]


def _file_arg_to_module(filename: str) -> str:
    filename, _ = os.path.splitext(filename)
    parts = filename.split("/")  # not os.sep since it comes from test data
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def parse_test_case(case: DataDrivenTestCase) -> None:
    """Parse and prepare a single case from suite with test case descriptions.

    This method is part of the setup phase, just before the test case is run.
    """
    test_items = parse_test_data(case.data, case.name)
    base_path = case.suite.base_path
    if case.suite.native_sep:
        join = os.path.join
    else:
        join = posixpath.join

    out_section_missing = case.suite.required_out_section

    files: list[tuple[str, str]] = []  # path and contents
    output_files: list[tuple[str, str | Pattern[str]]] = []  # output path and contents
    output: list[str] = []  # Regular output errors
    output2: dict[int, list[str]] = {}  # Output errors for incremental, runs 2+
    deleted_paths: dict[int, set[str]] = {}  # from run number of paths
    stale_modules: dict[int, set[str]] = {}  # from run number to module names
    rechecked_modules: dict[int, set[str]] = {}  # from run number module names
    triggered: list[str] = []  # Active triggers (one line per incremental step)
    targets: dict[int, list[str]] = {}  # Fine-grained targets (per fine-grained update)
    test_modules: list[str] = []  # Modules which are deemed "test" (vs "fixture")

    def _case_fail(msg: str) -> NoReturn:
        pytest.fail(f"{case.file}:{case.line}: {msg}", pytrace=False)

    # Process the parsed items. Each item has a header of form [id args],
    # optionally followed by lines of text.
    item = first_item = test_items[0]
    test_modules.append("__main__")
    ignore = "\n# mypy: allow-untyped-defs, allow-any-explicit, allow-incomplete-defs, allow_any_generics, disable-error-code=explicit-override\n"
    for item in test_items[1:]:

        def _item_fail(msg: str) -> NoReturn:
            item_abs_line = case.line + item.line - 2
            pytest.fail(f"{case.file}:{item_abs_line}: {msg}", pytrace=False)

        if item.id in {"file", "fixture", "outfile", "outfile-re"}:
            # Record an extra file needed for the test case.
            assert item.arg is not None
            contents = expand_variables("\n".join(item.data))
            path = join(base_path, item.arg)
            if item.id != "fixture":
                test_modules.append(_file_arg_to_module(item.arg))
            if item.id in {"file", "fixture"}:
                files.append((path, contents))
            elif item.id == "outfile-re":
                output_files.append((path, re.compile(contents.rstrip(), re.S)))
            elif item.id == "outfile":
                output_files.append((path, contents))
        elif item.id == "builtins":
            # Use an alternative stub file for the builtins module.
            assert item.arg is not None
            mpath = join(os.path.dirname(case.file), item.arg)
            with open(mpath, encoding="utf8") as f:
                files.append((join(base_path, "builtins.pyi"), f.read() + ignore))
        elif item.id == "typing":
            # Use an alternative stub file for the typing module.
            assert item.arg is not None
            src_path = join(os.path.dirname(case.file), item.arg)
            with open(src_path, encoding="utf8") as f:
                files.append((join(base_path, "typing.pyi"), f.read() + ignore))
        elif item.id == "_typeshed":
            # Use an alternative stub file for the _typeshed module.
            assert item.arg is not None
            src_path = join(os.path.dirname(case.file), item.arg)
            with open(src_path, encoding="utf8") as f:
                files.append((join(base_path, "_typeshed.pyi"), f.read()))
        elif re.match(r"stale[0-9]*$", item.id):
            passnum = 1 if item.id == "stale" else int(item.id[len("stale") :])
            assert passnum > 0
            modules = set() if item.arg is None else {t.strip() for t in item.arg.split(",")}
            stale_modules[passnum] = modules
        elif re.match(r"rechecked[0-9]*$", item.id):
            passnum = 1 if item.id == "rechecked" else int(item.id[len("rechecked") :])
            assert passnum > 0
            modules = set() if item.arg is None else {t.strip() for t in item.arg.split(",")}
            rechecked_modules[passnum] = modules
        elif re.match(r"targets[0-9]*$", item.id):
            passnum = 1 if item.id == "targets" else int(item.id[len("targets") :])
            assert passnum > 0
            reprocessed = [] if item.arg is None else [t.strip() for t in item.arg.split(",")]
            targets[passnum] = reprocessed
        elif item.id == "delete":
            # File/directory to delete during a multi-step test case
            assert item.arg is not None
            m = re.match(r"(.*)\.([0-9]+)$", item.arg)
            if m is None:
                _item_fail(f"Invalid delete section {item.arg!r}")
            num = int(m.group(2))
            if num < 2:
                _item_fail(f"Can't delete during step {num}")
            full = join(base_path, m.group(1))
            deleted_paths.setdefault(num, set()).add(full)
        elif re.match(r"out[0-9]*$", item.id):
            if item.arg is None:
                args = []
            else:
                args = item.arg.split(",")

            version_check = True
            for arg in args:
                if arg.startswith("version"):
                    compare_op = arg[7:9]
                    if compare_op not in {">=", "=="}:
                        _item_fail("Only >= and == version checks are currently supported")
                    version_str = arg[9:]
                    try:
                        version = tuple(int(x) for x in version_str.split("."))
                    except ValueError:
                        _item_fail(f"{version_str!r} is not a valid python version")
                    if compare_op == ">=":
                        if version <= defaults.PYTHON3_VERSION:
                            _item_fail(
                                f"{arg} always true since minimum runtime version is {defaults.PYTHON3_VERSION}"
                            )
                        version_check = sys.version_info >= version
                    elif compare_op == "==":
                        if version < defaults.PYTHON3_VERSION:
                            _item_fail(
                                f"{arg} always false since minimum runtime version is {defaults.PYTHON3_VERSION}"
                            )
                        if not 1 < len(version) < 4:
                            _item_fail(
                                f'Only minor or patch version checks are currently supported with "==": {version_str!r}'
                            )
                        version_check = sys.version_info[: len(version)] == version
            if version_check:
                tmp_output = [expand_variables(line) for line in item.data]
                if os.path.sep == "\\" and case.normalize_output:
                    tmp_output = [fix_win_path(line) for line in tmp_output]
                if item.id == "out" or item.id == "out1":
                    output = tmp_output
                else:
                    passnum = int(item.id[len("out") :])
                    assert passnum > 1
                    output2[passnum] = tmp_output
                out_section_missing = False
        elif item.id == "triggered" and item.arg is None:
            triggered = item.data
        else:
            section_str = item.id + (f" {item.arg}" if item.arg else "")
            _item_fail(f"Invalid section header [{section_str}] in case {case.name!r}")

    if out_section_missing:
        _case_fail(f"Required output section not found in case {case.name!r}")

    for passnum in stale_modules.keys():
        if passnum not in rechecked_modules:
            # If the set of rechecked modules isn't specified, make it the same as the set
            # of modules with a stale public interface.
            rechecked_modules[passnum] = stale_modules[passnum]
        if (
            passnum in stale_modules
            and passnum in rechecked_modules
            and not stale_modules[passnum].issubset(rechecked_modules[passnum])
        ):
            _case_fail(f"Stale modules after pass {passnum} must be a subset of rechecked modules")

    output_inline_start = len(output)
    input = first_item.data
    expand_errors(input, output, "main")
    tmp_output = []
    for file_path, contents in files:
        expand_errors(contents.split("\n"), tmp_output, file_path)
    output = tmp_output + output

    seen_files = set()
    for file, _ in files:
        if file in seen_files:
            _case_fail(f"Duplicated filename {file}. Did you include it multiple times?")

        seen_files.add(file)

    case.input = input
    case.output = output
    case.output_inline_start = output_inline_start
    case.output2 = output2
    case.last_line = case.line + item.line + len(item.data) - 2
    case.files = files
    case.output_files = output_files
    case.expected_stale_modules = stale_modules
    case.expected_rechecked_modules = rechecked_modules
    case.deleted_paths = deleted_paths
    case.triggered = triggered or []
    case.expected_fine_grained_targets = targets
    case.test_modules = test_modules


class DataDrivenTestCase(pytest.Item):
    """Holds parsed data-driven test cases, and handles directory setup and teardown."""

    # Override parent member type
    parent: DataSuiteCollector

    input: list[str]
    output: list[str]  # Output for the first pass
    output_inline_start: int
    output2: dict[int, list[str]]  # Output for runs 2+, indexed by run number

    # full path of test suite
    file = ""
    line = 0

    # (file path, file content) tuples
    files: list[tuple[str, str]]
    # Modules which is to be considered "test" rather than "fixture"
    test_modules: list[str]
    expected_stale_modules: dict[int, set[str]]
    expected_rechecked_modules: dict[int, set[str]]
    expected_fine_grained_targets: dict[int, list[str]]

    # Whether or not we should normalize the output to standardize things like
    # forward vs backward slashes in file paths for Windows vs Linux.
    normalize_output: bool

    # Extra attributes used by some tests.
    last_line: int
    output_files: list[tuple[str, str | Pattern[str]]]  # Path and contents for output files
    deleted_paths: dict[int, set[str]]  # Mapping run number -> paths
    triggered: list[str]  # Active triggers (one line per incremental step)

    def __init__(
        self,
        parent: DataSuiteCollector,
        suite: DataSuite,
        *,
        file: str,
        name: str,
        writescache: bool,
        only_when: str,
        normalize_output: bool,
        platform: str | None,
        skip: bool,
        xfail: bool,
        data: str,
        line: int,
    ) -> None:
        super().__init__(name, parent)
        self.suite = suite
        self.file = file
        self.writescache = writescache
        self.only_when = only_when
        self.normalize_output = normalize_output
        if (platform == "windows" and sys.platform != "win32") or (
            platform == "posix" and sys.platform == "win32"
        ):
            skip = True
        self.skip = skip
        self.xfail = xfail
        self.data = data
        self.line = line
        self.old_cwd: str | None = None
        self.tmpdir: tempfile.TemporaryDirectory[str] | None = None
        os.environ["__MYPY_UNDER_TEST__"] = "1"

    def runtest(self) -> None:
        if self.skip:
            pytest.skip()
        # TODO: add a better error message for when someone uses skip and xfail at the same time
        elif self.xfail:
            self.add_marker(pytest.mark.xfail)
        parent = self.getparent(DataSuiteCollector)
        assert parent is not None, "Should not happen"
        suite = parent.obj()
        suite.setup()
        try:
            suite.run_case(self)
        except Exception:
            # As a debugging aid, support copying the contents of the tmp directory somewhere
            save_dir: str | None = self.config.getoption("--save-failures-to", None)
            if save_dir:
                assert self.tmpdir is not None
                target_dir = os.path.join(save_dir, os.path.basename(self.tmpdir.name))
                print(f"Copying data from test {self.name} to {target_dir}")
                if not os.path.isabs(target_dir):
                    assert self.old_cwd
                    target_dir = os.path.join(self.old_cwd, target_dir)
                shutil.copytree(self.tmpdir.name, target_dir)
            raise

    def setup(self) -> None:
        parse_test_case(case=self)
        self.old_cwd = os.getcwd()
        self.tmpdir = tempfile.TemporaryDirectory(prefix="mypy-test-")
        os.chdir(self.tmpdir.name)
        os.mkdir(test_temp_dir)

        # Precalculate steps for find_steps()
        steps: dict[int, list[FileOperation]] = {}

        for path, content in self.files:
            m = re.match(r".*\.([0-9]+)$", path)
            if m:
                # Skip writing subsequent incremental steps - rather
                # store them as operations.
                num = int(m.group(1))
                assert num >= 2
                target_path = re.sub(r"\.[0-9]+$", "", path)
                module = module_from_path(target_path)
                operation = UpdateFile(module, content, target_path)
                steps.setdefault(num, []).append(operation)
            else:
                # Write the first incremental steps
                dir = os.path.dirname(path)
                os.makedirs(dir, exist_ok=True)
                with open(path, "w", encoding="utf8") as f:
                    f.write(content)

        for num, paths in self.deleted_paths.items():
            assert num >= 2
            for path in paths:
                module = module_from_path(path)
                steps.setdefault(num, []).append(DeleteFile(module, path))
        max_step = max(steps) if steps else 2
        self.steps = [steps.get(num, []) for num in range(2, max_step + 1)]

    def teardown(self) -> None:
        if self.old_cwd is not None:
            os.chdir(self.old_cwd)
        if self.tmpdir is not None:
            try:
                self.tmpdir.cleanup()
            except OSError:
                pass
        self.old_cwd = None
        self.tmpdir = None

    def reportinfo(self) -> tuple[str, int, str]:
        return self.file, self.line, self.name

    def repr_failure(
        self, excinfo: pytest.ExceptionInfo[BaseException], style: Any | None = None
    ) -> str:
        excrepr: object
        if isinstance(excinfo.value, SystemExit):
            # We assume that before doing exit() (which raises SystemExit) we've printed
            # enough context about what happened so that a stack trace is not useful.
            # In particular, uncaught exceptions during semantic analysis or type checking
            # call exit() and they already print out a stack trace.
            excrepr = excinfo.exconly()
        elif isinstance(excinfo.value, pytest.fail.Exception) and not excinfo.value.pytrace:
            excrepr = excinfo.exconly()
        else:
            excinfo.traceback = self.parent._traceback_filter(excinfo)
            excrepr = excinfo.getrepr(style="short")

        return f"data: {Path(self.file).as_uri()}:{self.line}:\n{excrepr}"

    def find_steps(self) -> list[list[FileOperation]]:
        """Return a list of descriptions of file operations for each incremental step.

        The first list item corresponds to the first incremental step, the second for the
        second step, etc. Each operation can either be a file modification/creation (UpdateFile)
        or deletion (DeleteFile).

        Defaults to having two steps if there aern't any operations.
        """
        return self.steps


def module_from_path(path: str) -> str:
    path = re.sub(r"\.pyi?$", "", path)
    # We can have a mix of Unix-style and Windows-style separators.
    parts = re.split(r"[/\\]", path)
    del parts[0]
    module = ".".join(parts)
    module = re.sub(r"\.__init__$", "", module)
    return module


@dataclass
class TestItem:
    """Parsed test caseitem.

    An item is of the form
      [id arg]
      .. data ..
    """

    id: str
    arg: str | None
    # Processed, collapsed text data
    data: list[str]
    # Start line: 1-based, inclusive, relative to testcase
    line: int
    # End line: 1-based, exclusive, relative to testcase; not same as `line + len(test_item.data)` due to collapsing
    end_line: int

    @property
    def trimmed_newlines(self) -> int:  # compensates for strip_list
        return self.end_line - self.line - len(self.data)


def parse_test_data(raw_data: str, name: str) -> list[TestItem]:
    """Parse a list of lines that represent a sequence of test items."""

    lines = ["", "[case " + name + "]"] + raw_data.split("\n")
    ret: list[TestItem] = []
    data: list[str] = []

    id: str | None = None
    arg: str | None = None

    i = 0
    i0 = 0
    while i < len(lines):
        s = lines[i].strip()

        if lines[i].startswith("[") and s.endswith("]"):
            if id:
                data = collapse_line_continuation(data)
                data = strip_list(data)
                ret.append(TestItem(id, arg, data, i0 + 1, i))

            i0 = i
            id = s[1:-1]
            arg = None
            if " " in id:
                arg = id[id.index(" ") + 1 :]
                id = id[: id.index(" ")]
            data = []
        elif lines[i].startswith("\\["):
            data.append(lines[i][1:])
        elif not lines[i].startswith("--"):
            data.append(lines[i])
        elif lines[i].startswith("----"):
            data.append(lines[i][2:])
        i += 1

    # Process the last item.
    if id:
        data = collapse_line_continuation(data)
        data = strip_list(data)
        ret.append(TestItem(id, arg, data, i0 + 1, i - 1))

    return ret


def strip_list(l: list[str]) -> list[str]:
    """Return a stripped copy of l.

    Strip whitespace at the end of all lines, and strip all empty
    lines from the end of the array.
    """

    r: list[str] = []
    for s in l:
        # Strip spaces at end of line
        r.append(re.sub(r"\s+$", "", s))

    while r and r[-1] == "":
        r.pop()

    return r


def collapse_line_continuation(l: list[str]) -> list[str]:
    r: list[str] = []
    cont = False
    for s in l:
        ss = re.sub(r"\\$", "", s)
        if cont:
            r[-1] += re.sub("^ +", "", ss)
        else:
            r.append(ss)
        cont = s.endswith("\\")
    return r


def expand_variables(s: str) -> str:
    return s.replace("<ROOT>", root_dir)


def expand_errors(input: list[str], output: list[str], fnam: str) -> None:
    """Transform comments such as '# E: message' or
    '# E:3: message' in input.

    The result is lines like 'fnam:line: error: message'.
    """

    for i in range(len(input)):
        # The first in the split things isn't a comment
        for possible_err_comment in input[i].split(" # ")[1:]:
            m = re.search(
                r"^([ENW]):((?P<col>\d+):)? (?P<message>.*)$", possible_err_comment.strip()
            )
            if m:
                if m.group(1) == "E":
                    severity = "error"
                elif m.group(1) == "N":
                    severity = "note"
                elif m.group(1) == "W":
                    severity = "warning"
                col = m.group("col")
                message = safe(m.group("message"))
                message = message.replace("\\#", "#")  # adds back escaped # character
                if col is None:
                    output.append(f"{fnam}:{i + 1}: {severity}: {message}")
                else:
                    output.append(f"{fnam}:{i + 1}:{col}: {severity}: {message}")


def fix_win_path(line: str) -> str:
    r"""Changes Windows paths to Linux paths in error messages.

    E.g. foo\bar.py -> foo/bar.py.
    """
    line = line.replace(root_dir, root_dir.replace("\\", "/"))
    m = re.match(r"^([\S/]+):(\d+:)?(\s+.*)", line)
    if not m:
        return line
    else:
        filename, lineno, message = m.groups()
        return "{}:{}{}".format(filename.replace("\\", "/"), lineno or "", message)


def fix_cobertura_filename(line: str) -> str:
    r"""Changes filename paths to Linux paths in Cobertura output files.

    E.g. filename="pkg\subpkg\a.py" -> filename="pkg/subpkg/a.py".
    """
    m = re.search(r'<class .* filename="(?P<filename>.*?)"', line)
    if not m:
        return line
    return "{}{}{}".format(
        line[: m.start(1)], safe(m.group("filename")).replace("\\", "/"), line[m.end(1) :]
    )


##
#
# pytest setup
#
##


# This function name is special to pytest.  See
# https://docs.pytest.org/en/latest/reference.html#initialization-hooks
def pytest_addoption(parser: Any) -> None:
    group = parser.getgroup("mypy")
    group.addoption(
        "--update-data",
        action="store_true",
        default=False,
        help="Update test data to reflect actual output (supported only for certain tests)",
    )
    group.addoption(
        "--save-failures-to",
        default=None,
        help="Copy the temp directories from failing tests to a target directory",
    )
    group.addoption(
        "--mypy-verbose", action="count", help="Set the verbose flag when creating mypy Options"
    )
    group.addoption(
        "--mypyc-showc",
        action="store_true",
        default=False,
        help="Display C code on mypyc test failures",
    )
    group.addoption(
        "--mypyc-debug",
        default=None,
        dest="debugger",
        choices=SUPPORTED_DEBUGGERS,
        help="Run the first mypyc run test with the specified debugger",
    )


@pytest.hookimpl(tryfirst=True)
def pytest_cmdline_main(config: pytest.Config) -> None:
    if config.getoption("--collectonly"):
        return
    # --update-data is not compatible with parallelized tests, disable parallelization
    if config.getoption("--update-data"):
        config.option.numprocesses = 0


# This function name is special to pytest.  See
# https://doc.pytest.org/en/latest/how-to/writing_plugins.html#collection-hooks
def pytest_pycollect_makeitem(collector: Any, name: str, obj: object) -> Any | None:
    """Called by pytest on each object in modules configured in conftest.py files.

    collector is pytest.Collector, returns Optional[pytest.Class]
    """
    if isinstance(obj, type):
        # Only classes derived from DataSuite contain test cases, not the DataSuite class itself
        if issubclass(obj, DataSuite) and obj is not DataSuite:
            # Non-None result means this obj is a test case.
            # The collect method of the returned DataSuiteCollector instance will be called later,
            # with self.obj being obj.
            return DataSuiteCollector.from_parent(parent=collector, name=name)  # type: ignore[no-untyped-call, unused-ignore]
    return None


_case_name_pattern = re.compile(
    r"(?P<name>[a-zA-Z_0-9]+)"
    r"(?P<writescache>-writescache)?"
    r"(?P<only_when>-only_when_cache|-only_when_nocache)?"
    r"(?P<skip_path_normalization>-skip_path_normalization)?"
    r"(-(?P<platform>posix|windows))?"
    r"(?P<skip>-skip)?"
    r"(?P<xfail>-xfail)?"
    r"(?P<version>-3.\d+)?"
)


def split_test_cases(
    parent: DataFileCollector, suite: DataSuite, file: str
) -> Iterator[DataDrivenTestCase]:
    """Iterate over raw test cases in file, at collection time, ignoring sub items.

    The collection phase is slow, so any heavy processing should be deferred to after
    uninteresting tests are filtered (when using -k PATTERN switch).
    """
    with open(file, encoding="utf-8") as f:
        data = f.read()
    cases = re.split(r"^\[case ([^]+)]+)\][ \t]*$\n", data, flags=re.DOTALL | re.MULTILINE)
    cases_iter = iter(cases)
    line_no = next(cases_iter).count("\n") + 1
    test_names = set()
    for case_id in cases_iter:
        data = next(cases_iter)

        m = _case_name_pattern.fullmatch(case_id)
        if not m:
            raise RuntimeError(f"Invalid testcase id {case_id!r}")
        name = safe(m.group("name"))
        if name in test_names:
            raise RuntimeError(
                'Found a duplicate test name "{}" in {} on line {}'.format(
                    name, parent.name, line_no
                )
            )
        version = m.group("version")
        if version:
            if sys.version_info < (3, int(version.split(".")[1])):
                continue
            name += version
        yield DataDrivenTestCase.from_parent(  # type: ignore[unused-ignore, no-untyped-call]
            parent=parent,
            suite=suite,
            file=file,
            name=add_test_name_suffix(name, suite.test_name_suffix),
            writescache=bool(m.group("writescache")),
            only_when=m.group("only_when"),
            platform=m.group("platform"),
            skip=bool(m.group("skip")),
            xfail=bool(m.group("xfail")),
            normalize_output=not m.group("skip_path_normalization"),
            data=data,
            line=line_no,
        )
        line_no += data.count("\n") + 1

        # Record existing tests to prevent duplicates:
        test_names.update({name})


class DataSuiteCollector(pytest.Class):
    def collect(self) -> Iterator[DataFileCollector]:
        """Called by pytest on each of the object returned from pytest_pycollect_makeitem"""

        # obj is the object for which pytest_pycollect_makeitem returned self.
        suite: DataSuite = self.obj

        assert os.path.isdir(
            suite.data_prefix
        ), f"Test data prefix ({suite.data_prefix}) not set correctly"

        for data_file in suite.files:
            yield DataFileCollector.from_parent(parent=self, name=data_file)


class DataFileFix(NamedTuple):
    lineno: int  # 1-offset, inclusive
    end_lineno: int  # 1-offset, exclusive
    lines: list[str]


class DataFileCollector(pytest.Collector):
    """Represents a single `.test` data driven test file.

    More context: https://github.com/python/mypy/issues/11662
    """

    parent: DataSuiteCollector

    _fixes: list[DataFileFix]

    @classmethod  # We have to fight with pytest here:
    def from_parent(
        cls, parent: DataSuiteCollector, *, name: str  # type: ignore[override]
    ) -> DataFileCollector:
        collector = super().from_parent(parent, name=name)
        assert isinstance(collector, DataFileCollector)
        return collector

    def collect(self) -> Iterator[DataDrivenTestCase]:
        yield from split_test_cases(
            parent=self,
            suite=self.parent.obj,
            file=os.path.join(self.parent.obj.data_prefix, self.name),
        )

    def setup(self) -> None:
        super().setup()
        self._fixes = []

    def teardown(self) -> None:
        super().teardown()
        self._apply_fixes()

    def enqueue_fix(self, fix: DataFileFix) -> None:
        self._fixes.append(fix)

    def _apply_fixes(self) -> None:
        if not self._fixes:
            return
        data_path = Path(self.parent.obj.data_prefix) / self.name
        lines = data_path.read_text().split("\n")
        # start from end to prevent line offsets from shifting as we update
        for fix in sorted(self._fixes, reverse=True):
            lines[fix.lineno - 1 : fix.end_lineno - 1] = fix.lines
        data_path.write_text("\n".join(lines))


def add_test_name_suffix(name: str, suffix: str) -> str:
    # Find magic suffix of form "-foobar" (used for things like "-skip").
    m = re.search(r"-[-A-Za-z0-9]+$", name)
    if m:
        # Insert suite-specific test name suffix before the magic suffix
        # which must be the last thing in the test case name since we
        # are using endswith() checks.
        magic_suffix = m.group(0)
        return name[: -len(magic_suffix)] + suffix + magic_suffix
    else:
        return name + suffix


def is_incremental(testcase: DataDrivenTestCase) -> bool:
    return "incremental" in testcase.name.lower() or "incremental" in testcase.file


def has_stable_flags(testcase: DataDrivenTestCase) -> bool:
    if any(re.match(r"# flags[2-9]:", line) for line in testcase.input):
        return False
    for filename, contents in testcase.files:
        if os.path.basename(filename).startswith("mypy.ini."):
            return False
    return True


class DataSuite:
    # option fields - class variables
    files: list[str]

    base_path = test_temp_dir

    # Allow external users of the test code to override the data prefix
    data_prefix = test_data_prefix

    required_out_section = False

    native_sep = False

    # Name suffix automatically added to each test case in the suite (can be
    # used to distinguish test cases in suites that share data files)
    test_name_suffix = ""

    def setup(self) -> None:
        """Setup fixtures (ad-hoc)"""

    @abstractmethod
    def run_case(self, testcase: DataDrivenTestCase) -> None:
        raise NotImplementedError
