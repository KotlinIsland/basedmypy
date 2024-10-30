#!/usr/bin/env python

from __future__ import annotations

import glob
import os
import os.path
import sys
from typing import TYPE_CHECKING, Any

if sys.version_info < (3, 8, 0):  # noqa: UP036
    sys.stderr.write("ERROR: You need Python 3.8 or later to use basedmypy.\n")
    exit(1)

# we'll import stuff from the source tree, let's ensure is on the sys path
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

# This requires setuptools when building; setuptools is not needed
# when installing from a wheel file (though it is still needed for
# alternative forms of installing, as suggested by README.md).
from setuptools import Extension, find_packages, setup
from setuptools.command.build_py import build_py

from mypy.version import __based_version__, __version__, based_version_info

if TYPE_CHECKING:
    from typing_extensions import TypeGuard

description = "Based static typing for Python"
long_description = """
.. image:: https://raw.githubusercontent.com/KotlinIsland/basedmypy/master/docs/static/logo-light.png

Basedmypy is a type checker that is built on top of the work done by the
`mypy project <https://github.com/python/mypy>`_. It adds based functionality and breaks compatibility with
the cringe parts of pep 484.

Based features
==============

Baseline
--------

Basedmypy has baseline, baseline is based! It allows you to adopt new strictness or features
without the burden of fixing up every usage, just save all current errors to the baseline
file and deal with them later.

Consider the following:

.. code-block:: python

    def foo(a):
        print(a)

.. code-block:: text

    > mypy demo.py
    demo.py:1: error: missing typehints
    Failed: errors found in source file


    > mypy --write-baseline demo.py
    demo.py:1: error: missing typehints
    Baseline successfully written to .mypy/baseline.json

    > mypy demo.py
    Success: no issues found in 1 source file

Then on subsequent runs the existing errors will be filtered out:

.. code-block:: python

    def foo(a):
        print(a)

    def bar(b: str, c: int) -> bool:
        return b + c

.. code-block:: text

    > mypy demo.py
    demo.py:4:5: error: Returning Any from function declared to return "bool"  [no-any-return]
    demo.py:4:16: error: Unsupported operand types for + ("str" and "int")  [operator]
    Found 2 errors in 1 file (checked 1 source file)

Intersection Types
------------------

Using the ``&`` operator or ``basedtyping.Intersection`` you can denote intersection types:

.. code-block:: python

    class Growable(ABC, Generic[T]):
        @abstractmethod
        def add(self, item: T): ...

    class Resettable(ABC):
        @abstractmethod
        def reset(self): ...

    def f(x: Resettable & Growable[str]):
        x.reset()
        x.add("first")

Type Joins
----------

Mypy joins types to their common base type:

.. code-block:: python

    a: int
    b: str
    reveal_type(a if bool() else b)  # Revealed type is "builtins.object"

Basedmypy joins types into unions instead:

.. code-block:: python

    a: int
    b: str
    reveal_type(a if bool() else b)  # Revealed type is "int | str"

Bare Literals
-------------

``Literal`` is so cumbersome! just use a bare literal instead:

.. code-block:: python

    class Color(Enum):
        RED = auto()

    a: 1 | 2
    b: True | Color.RED


Default Return Type
-------------------

The default return type of functions is ``None`` instead of ``Any``:
(configurable with the ``default_return`` option.)

.. code-block:: python

    def f(name: str):
        print(f"Hello, {name}!")

    reveal_type(f)  # (str) -> None

Generic ``TypeVar`` Bounds
--------------------------

Allows the bounds of ``TypeVar``\\s to be generic.

So you are able to have functions with polymorphic generic parameters.

.. code-block:: python

    E = TypeVar("E")
    I = TypeVar("I", bound=Iterable[E])

    def foo(i: I, e: E) -> I:
        assert e not in i
        return i

    reveal_type(foo(["based"], "mypy"))  # N: Revealed type is "list[str]"
    reveal_type(foo({1, 2}, 3))  # N: Revealed type is "set[int]"

Overload Implementation Inference
---------------------------------

The types in overload implementations (including properties) can be inferred:

.. code-block:: python

    @overload
    def f(a: int) -> str: ...

    @overload
    def f(a: str) -> int: ...

    def f(a):
        reveal_type(a)  # int | str
        return None  # error: expected str | int

    class A:
        @property
        def foo(self) -> int: ...
        @foo.setter
        def foo(self, value): ...  # no need for annotations


Infer Function Parameters
-------------------------

Infer the type of a function parameter from it's default value:

.. code-block:: python

    def f(a=1, b=True):
        reveal_type((a, b))  # (int, bool)

Tuple Literal Types
-------------------

Basedmypy allows denotation of tuple types with tuple literals:

.. code-block:: python

    a: (int, str) = (1, "a")

Types in Messages
-----------------

Basedmypy makes significant changes to error and info messages, consider:

.. code-block:: python

    T = TypeVar("T", bound=int)

    def f(a: T, b: list[str | 1 | 2]) -> Never:
        reveal_type((a, b))

    reveal_type(f)

Mypy shows::

    Revealed type is "Tuple[T`-1, Union[builtins.str, Literal[1], Literal[2]]]"
    Revealed type is "def [T <: builtins.int] (a: T`-1, b: Union[builtins.str, Literal[1], Literal[2]]) -> <nothing>"

Basedmypy shows::

    Revealed type is "(T@f, str | 1 | 2)"
    Revealed type is "def [T: int] (a: T, b: str | 1 | 2) -> Never"
""".lstrip()


def is_list_of_setuptools_extension(items: list[Any]) -> TypeGuard[list[Extension]]:
    return all(isinstance(item, Extension) for item in items)


def find_package_data(base, globs, root="mypy"):
    """Find all interesting data files, for setup(package_data=)

    Arguments:
      root:  The directory to search in.
      globs: A list of glob patterns to accept files.
    """

    rv_dirs = [root for root, dirs, files in os.walk(base)]
    rv = []
    for rv_dir in rv_dirs:
        files = []
        for pat in globs:
            files += glob.glob(os.path.join(rv_dir, pat))
        if not files:
            continue
        rv.extend([os.path.relpath(f, root) for f in files])
    return rv


class CustomPythonBuild(build_py):
    def pin_version(self):
        path = os.path.join(self.build_lib, "mypy")
        self.mkpath(path)
        with open(os.path.join(path, "version.py"), "w") as stream:
            stream.write("from mypy.versionutil import VersionInfo\n")
            stream.write(f'__version__ = "{__version__}"\n')
            stream.write(f"based_version_info = {based_version_info!r}\n")
            stream.write(f'__based_version__ = "{__based_version__}"\n')

    def run(self):
        self.execute(self.pin_version, ())
        build_py.run(self)


cmdclass = {"build_py": CustomPythonBuild}

package_data = ["py.typed"]

package_data += find_package_data(os.path.join("mypy", "typeshed"), ["*.py", "*.pyi"])
package_data += [os.path.join("mypy", "typeshed", "stdlib", "VERSIONS")]

package_data += find_package_data(os.path.join("mypy", "xml"), ["*.xsd", "*.xslt", "*.css"])

USE_MYPYC = False
# To compile with mypyc, a mypyc checkout must be present on the PYTHONPATH
if len(sys.argv) > 1 and "--use-mypyc" in sys.argv:
    sys.argv.remove("--use-mypyc")
    USE_MYPYC = True
if os.getenv("MYPY_USE_MYPYC", None) == "1":
    USE_MYPYC = True

if USE_MYPYC:
    MYPYC_BLACKLIST = tuple(
        os.path.join("mypy", x)
        for x in (
            # Need to be runnable as scripts
            "__main__.py",
            "pyinfo.py",
            os.path.join("dmypy", "__main__.py"),
            # Uses __getattr__/__setattr__
            "split_namespace.py",
            # Lies to mypy about code reachability
            "bogus_type.py",
            # We don't populate __file__ properly at the top level or something?
            # Also I think there would be problems with how we generate version.py.
            "version.py",
            # Skip these to reduce the size of the build
            "stubtest.py",
            "stubgenc.py",
            "stubdoc.py",
        )
    ) + (
        # Don't want to grab this accidentally
        os.path.join("mypyc", "lib-rt", "setup.py"),
        # Uses __file__ at top level https://github.com/mypyc/mypyc/issues/700
        os.path.join("mypyc", "__main__.py"),
    )

    everything = [os.path.join("mypy", x) for x in find_package_data("mypy", ["*.py"])] + [
        os.path.join("mypyc", x) for x in find_package_data("mypyc", ["*.py"], root="mypyc")
    ]
    # Start with all the .py files
    all_real_pys = [
        x for x in everything if not x.startswith(os.path.join("mypy", "typeshed") + os.sep)
    ]
    # Strip out anything in our blacklist
    mypyc_targets = [x for x in all_real_pys if x not in MYPYC_BLACKLIST]
    # Strip out any test code
    mypyc_targets = [
        x
        for x in mypyc_targets
        if not x.startswith(
            (
                os.path.join("mypy", "test") + os.sep,
                os.path.join("mypyc", "test") + os.sep,
                os.path.join("mypyc", "doc") + os.sep,
                os.path.join("mypyc", "test-data") + os.sep,
            )
        )
    ]
    # ... and add back in the one test module we need
    mypyc_targets.append(os.path.join("mypy", "test", "visitors.py"))

    # The targets come out of file system apis in an unspecified
    # order. Sort them so that the mypyc output is deterministic.
    mypyc_targets.sort()

    use_other_mypyc = os.getenv("ALTERNATE_MYPYC_PATH", None)
    if use_other_mypyc:
        # This bit is super unfortunate: we want to use a different
        # mypy/mypyc version, but we've already imported parts, so we
        # remove the modules that we've imported already, which will
        # let the right versions be imported by mypyc.
        del sys.modules["mypy"]
        del sys.modules["mypy.version"]
        del sys.modules["mypy.git"]
        sys.path.insert(0, use_other_mypyc)

    from mypyc.build import mypycify

    opt_level = os.getenv("MYPYC_OPT_LEVEL", "3")
    debug_level = os.getenv("MYPYC_DEBUG_LEVEL", "1")
    force_multifile = os.getenv("MYPYC_MULTI_FILE", "") == "1"
    ext_modules = mypycify(
        mypyc_targets + ["--config-file=mypy_bootstrap.ini", "--no-strict"],
        opt_level=opt_level,
        debug_level=debug_level,
        # Use multi-file compilation mode on windows because without it
        # our Appveyor builds run out of memory sometimes.
        multi_file=sys.platform == "win32" or force_multifile,
    )
    assert is_list_of_setuptools_extension(ext_modules), "Expected mypycify to use setuptools"

else:
    ext_modules = []


classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Environment :: Console",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Software Development",
    "Typing :: Typed",
]

setup(
    name="basedmypy",
    version=__based_version__,
    description=description,
    long_description=long_description,
    author="KotlinIsland",
    license="MIT",
    py_modules=[],
    ext_modules=ext_modules,
    packages=find_packages(),
    package_data={"mypy": package_data},
    entry_points={
        "console_scripts": [
            "mypy=mypy.__main__:console_entry",
            "stubgen=mypy.stubgen:main",
            "stubtest=mypy.stubtest:main",
            "dmypy=mypy.dmypy.client:console_entry",
            "mypyc=mypyc.__main__:main",
        ]
    },
    classifiers=classifiers,
    cmdclass=cmdclass,
    # When changing this, also update mypy-requirements.txt and pyproject.toml
    install_requires=[
        "basedtyping>=0.1.4",
        "typing_extensions>=4.6.0",
        "mypy_extensions >= 1.0.0",
        "tomli>=1.1.0; python_version<'3.11'",
    ],
    # Same here.
    extras_require={
        "dmypy": "psutil >= 4.0",
        "mypyc": "setuptools >= 50",
        "reports": "lxml",
        "install-types": "pip",
        "faster-cache": "orjson",
    },
    python_requires=">=3.8",
    include_package_data=True,
    project_urls={
        "News": "https://github.com/KotlinIsland/basedmypy/releases",
        "Documentation": "https://KotlinIsland.github.io/basedmypy",
        "Repository": "https://github.com/KotlinIsland/basedmypy",
        "Changelog": "https://github.com/KotlinIsland/basedmypy/blob/master/CHANGELOG.md",
        "Discord": "https://discord.gg/7y9upqPrk2",
    },
)
