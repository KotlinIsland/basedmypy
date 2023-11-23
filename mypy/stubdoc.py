"""Parsing/inferring signatures from documentation.

This module provides several functions to generate better stubs using
docstrings and Sphinx docs (.rst files).
"""

from __future__ import annotations

import contextlib
import io
import keyword
import re
import tokenize
from typing import Any, Final, MutableMapping, MutableSequence, NamedTuple, Sequence, Tuple
from typing_extensions import TypeAlias as _TypeAlias

import mypy.util

# Type alias for signatures strings in format ('func_name', '(arg, opt_arg=False)').
Sig: _TypeAlias = Tuple[str, str]


_TYPE_RE: Final = re.compile(r"^[a-zA-Z_][\w\[\], ]*(\.[a-zA-Z_][\w\[\], ]*)*$")
_ARG_NAME_RE: Final = re.compile(r"\**[A-Za-z_][A-Za-z0-9_]*$")


def is_valid_type(s: str) -> bool:
    """Try to determine whether a string might be a valid type annotation."""
    if s in ("True", "False", "retval"):
        return False
    if "," in s and "[" not in s:
        return False
    return _TYPE_RE.match(s) is not None


class ArgSig:
    """Signature info for a single argument."""

    def __init__(self, name: str, type: str | None = None, default: bool = False):
        self.name = name
        self.type = type
        # Does this argument have a default value?
        self.default = default

    def is_star_arg(self) -> bool:
        return self.name.startswith("*") and not self.name.startswith("**")

    def is_star_kwarg(self) -> bool:
        return self.name.startswith("**")

    def __repr__(self) -> str:
        return "ArgSig(name={}, type={}, default={})".format(
            repr(self.name), repr(self.type), repr(self.default)
        )

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, ArgSig):
            return (
                self.name == other.name
                and self.type == other.type
                and self.default == other.default
            )
        return False


class FunctionSig(NamedTuple):
    name: str
    args: list[ArgSig]
    ret_type: str | None

    def is_special_method(self) -> bool:
        return bool(
            self.name.startswith("__")
            and self.name.endswith("__")
            and self.args
            and self.args[0].name in ("self", "cls")
        )

    def has_catchall_args(self) -> bool:
        """Return if this signature has catchall args: (*args, **kwargs)"""
        if self.args and self.args[0].name in ("self", "cls"):
            args = self.args[1:]
        else:
            args = self.args
        return (
            len(args) == 2
            and all(a.type in (None, "object", "Any", "typing.Any") for a in args)
            and args[0].is_star_arg()
            and args[1].is_star_kwarg()
        )

    def is_catchall_signature(self) -> bool:
        """Return if this signature is the catchall identity: (*args, **kwargs) -> Any"""
        return self.has_catchall_args() and self.ret_type in (None, "Any", "typing.Any")

    def format_sig(
        self,
        indent: str = "",
        is_async: bool = False,
        any_val: str | None = None,
        docstring: str | None = None,
    ) -> str:
        args: list[str] = []
        for arg in self.args:
            arg_def = arg.name

            if arg_def in keyword.kwlist:
                arg_def = "_" + arg_def

            if (
                arg.type is None
                and any_val is not None
                and arg.name not in ("self", "cls")
                and not arg.name.startswith("*")
            ):
                arg_type: str | None = any_val
            else:
                arg_type = arg.type
            if arg_type:
                arg_def += ": " + arg_type
                if arg.default:
                    arg_def += " = ..."

            elif arg.default:
                arg_def += "=..."

            args.append(arg_def)

        retfield = ""
        ret_type = self.ret_type or any_val
        if ret_type is not None:
            retfield = " -> " + ret_type

        prefix = "async " if is_async else ""
        sig = "{indent}{prefix}def {name}({args}){ret}:".format(
            indent=indent, prefix=prefix, name=self.name, args=", ".join(args), ret=retfield
        )
        if docstring:
            suffix = f"\n{indent}    {mypy.util.quote_docstring(docstring)}"
        else:
            suffix = " ..."
        return f"{sig}{suffix}"


# States of the docstring parser.
STATE_INIT: Final = 1
STATE_FUNCTION_NAME: Final = 2
STATE_ARGUMENT_LIST: Final = 3
STATE_ARGUMENT_TYPE: Final = 4
STATE_ARGUMENT_DEFAULT: Final = 5
STATE_RETURN_VALUE: Final = 6
STATE_OPEN_BRACKET: Final = 7  # For generic types.


class DocStringParser:
    """Parse function signatures in documentation."""

    def __init__(self, function_name: str) -> None:
        # Only search for signatures of function with this name.
        self.function_name = function_name
        self.state = [STATE_INIT]
        self.accumulator = ""
        self.arg_type: str | None = None
        self.arg_name = ""
        self.arg_default: str | None = None
        self.ret_type = "Any"
        self.found = False
        self.args: list[ArgSig] = []
        # Valid signatures found so far.
        self.signatures: list[FunctionSig] = []

    def add_token(self, token: tokenize.TokenInfo) -> None:
        """Process next token from the token stream."""
        if (
            token.type == tokenize.NAME
            and token.string == self.function_name
            and self.state[-1] == STATE_INIT
        ):
            self.state.append(STATE_FUNCTION_NAME)

        elif (
            token.type == tokenize.OP
            and token.string == "("
            and self.state[-1] == STATE_FUNCTION_NAME
        ):
            self.state.pop()
            self.accumulator = ""
            self.found = True
            self.state.append(STATE_ARGUMENT_LIST)

        elif self.state[-1] == STATE_FUNCTION_NAME:
            # Reset state, function name not followed by '('.
            self.state.pop()

        elif (
            token.type == tokenize.OP
            and token.string in ("[", "(", "{")
            and self.state[-1] != STATE_INIT
        ):
            self.accumulator += token.string
            self.state.append(STATE_OPEN_BRACKET)

        elif (
            token.type == tokenize.OP
            and token.string in ("]", ")", "}")
            and self.state[-1] == STATE_OPEN_BRACKET
        ):
            self.accumulator += token.string
            self.state.pop()

        elif (
            token.type == tokenize.OP
            and token.string == ":"
            and self.state[-1] == STATE_ARGUMENT_LIST
        ):
            self.arg_name = self.accumulator
            self.accumulator = ""
            self.state.append(STATE_ARGUMENT_TYPE)

        elif (
            token.type == tokenize.OP
            and token.string == "="
            and self.state[-1] in (STATE_ARGUMENT_LIST, STATE_ARGUMENT_TYPE)
        ):
            if self.state[-1] == STATE_ARGUMENT_TYPE:
                self.arg_type = self.accumulator
                self.state.pop()
            else:
                self.arg_name = self.accumulator
            self.accumulator = ""
            self.state.append(STATE_ARGUMENT_DEFAULT)

        elif (
            token.type == tokenize.OP
            and token.string in (",", ")")
            and self.state[-1]
            in (STATE_ARGUMENT_LIST, STATE_ARGUMENT_DEFAULT, STATE_ARGUMENT_TYPE)
        ):
            if self.state[-1] == STATE_ARGUMENT_DEFAULT:
                self.arg_default = self.accumulator
                self.state.pop()
            elif self.state[-1] == STATE_ARGUMENT_TYPE:
                self.arg_type = self.accumulator
                self.state.pop()
            elif self.state[-1] == STATE_ARGUMENT_LIST:
                self.arg_name = self.accumulator
                if not (
                    token.string == ")" and self.accumulator.strip() == ""
                ) and not _ARG_NAME_RE.match(self.arg_name):
                    # Invalid argument name.
                    self.reset()
                    return

            if token.string == ")":
                self.state.pop()

            # arg_name is empty when there are no args. e.g. func()
            if self.arg_name:
                if self.arg_type and not is_valid_type(self.arg_type):
                    # wrong type, use Any
                    self.args.append(
                        ArgSig(name=self.arg_name, type=None, default=bool(self.arg_default))
                    )
                else:
                    self.args.append(
                        ArgSig(
                            name=self.arg_name, type=self.arg_type, default=bool(self.arg_default)
                        )
                    )
            self.arg_name = ""
            self.arg_type = None
            self.arg_default = None
            self.accumulator = ""

        elif token.type == tokenize.OP and token.string == "->" and self.state[-1] == STATE_INIT:
            self.accumulator = ""
            self.state.append(STATE_RETURN_VALUE)

        # ENDMAKER is necessary for python 3.4 and 3.5.
        elif token.type in (tokenize.NEWLINE, tokenize.ENDMARKER) and self.state[-1] in (
            STATE_INIT,
            STATE_RETURN_VALUE,
        ):
            if self.state[-1] == STATE_RETURN_VALUE:
                if not is_valid_type(self.accumulator):
                    self.reset()
                    return
                self.ret_type = self.accumulator
                self.accumulator = ""
                self.state.pop()

            if self.found:
                self.signatures.append(
                    FunctionSig(name=self.function_name, args=self.args, ret_type=self.ret_type)
                )
                self.found = False
            self.args = []
            self.ret_type = "Any"
            # Leave state as INIT.
        else:
            self.accumulator += token.string

    def reset(self) -> None:
        self.state = [STATE_INIT]
        self.args = []
        self.found = False
        self.accumulator = ""

    def get_signatures(self) -> list[FunctionSig]:
        """Return sorted copy of the list of signatures found so far."""

        def has_arg(name: str, signature: FunctionSig) -> bool:
            return any(x.name == name for x in signature.args)

        def args_kwargs(signature: FunctionSig) -> bool:
            return has_arg("*args", signature) and has_arg("**kwargs", signature)

        # Move functions with (*args, **kwargs) in their signature to last place.
        return list(sorted(self.signatures, key=lambda x: 1 if args_kwargs(x) else 0))


def infer_sig_from_docstring(docstr: str | None, name: str) -> list[FunctionSig] | None:
    """Convert function signature to list of FunctionSig

    Look for function signatures of function in docstring. Signature is a string of
    the format <function_name>(<signature>) -> <return type> or perhaps without
    the return type.

    Returns empty list, when no signature is found, one signature in typical case,
    multiple signatures, if docstring specifies multiple signatures for overload functions.
    Return None if the docstring is empty.

    Arguments:
        * docstr: docstring
        * name: name of function for which signatures are to be found
    """
    if not (isinstance(docstr, str) and docstr):
        return None

    state = DocStringParser(name)
    # Return all found signatures, even if there is a parse error after some are found.
    with contextlib.suppress(tokenize.TokenError):
        try:
            tokens = tokenize.tokenize(io.BytesIO(docstr.encode("utf-8")).readline)
            for token in tokens:
                state.add_token(token)
        except IndentationError:
            return None
    sigs = state.get_signatures()

    def is_unique_args(sig: FunctionSig) -> bool:
        """return true if function argument names are unique"""
        return len(sig.args) == len({arg.name for arg in sig.args})

    # Return only signatures that have unique argument names. Mypy fails on non-unique arg names.
    return [sig for sig in sigs if is_unique_args(sig)]


def infer_arg_sig_from_anon_docstring(docstr: str) -> list[ArgSig]:
    """Convert signature in form of "(self: TestClass, arg0: str='ada')" to List[TypedArgList]."""
    ret = infer_sig_from_docstring("stub" + docstr, "stub")
    if ret:
        return ret[0].args
    return []


def infer_ret_type_sig_from_docstring(docstr: str, name: str) -> str | None:
    """Convert signature in form of "func(self: TestClass, arg0) -> int" to their return type."""
    ret = infer_sig_from_docstring(docstr, name)
    if ret:
        return ret[0].ret_type
    return None


def infer_ret_type_sig_from_anon_docstring(docstr: str) -> str | None:
    """Convert signature in form of "(self: TestClass, arg0) -> int" to their return type."""
    return infer_ret_type_sig_from_docstring("stub" + docstr.strip(), "stub")


def parse_signature(sig: str) -> tuple[str, list[str], list[str]] | None:
    """Split function signature into its name, positional an optional arguments.

    The expected format is "func_name(arg, opt_arg=False)". Return the name of function
    and lists of positional and optional argument names.
    """
    m = re.match(r"([.a-zA-Z0-9_]+)\(([^)]*)\)", sig)
    if not m:
        return None
    name = m.group(1)
    name = name.split(".")[-1]
    arg_string = m.group(2)
    if not arg_string.strip():
        # Simple case -- no arguments.
        return name, [], []

    args = [arg.strip() for arg in arg_string.split(",")]
    positional = []
    optional = []
    i = 0
    while i < len(args):
        # Accept optional arguments as in both formats: x=None and [x].
        if args[i].startswith("[") or "=" in args[i]:
            break
        positional.append(args[i].rstrip("["))
        i += 1
        if args[i - 1].endswith("["):
            break
    while i < len(args):
        arg = args[i]
        arg = arg.strip("[]")
        arg = arg.split("=")[0]
        optional.append(arg)
        i += 1
    return name, positional, optional


def build_signature(positional: Sequence[str], optional: Sequence[str]) -> str:
    """Build function signature from lists of positional and optional argument names."""
    args: MutableSequence[str] = []
    args.extend(positional)
    for arg in optional:
        if arg.startswith("*"):
            args.append(arg)
        else:
            args.append(f"{arg}=...")
    sig = f"({', '.join(args)})"
    # Ad-hoc fixes.
    sig = sig.replace("(self)", "")
    return sig


def parse_all_signatures(lines: Sequence[str]) -> tuple[list[Sig], list[Sig]]:
    """Parse all signatures in a given reST document.

    Return lists of found signatures for functions and classes.
    """
    sigs = []
    class_sigs = []
    for line in lines:
        line = line.strip()
        m = re.match(r"\.\. *(function|method|class) *:: *[a-zA-Z_]", line)
        if m:
            sig = line.split("::")[1].strip()
            parsed = parse_signature(sig)
            if parsed:
                name, fixed, optional = parsed
                if m.group(1) != "class":
                    sigs.append((name, build_signature(fixed, optional)))
                else:
                    class_sigs.append((name, build_signature(fixed, optional)))

    return sorted(sigs), sorted(class_sigs)


def find_unique_signatures(sigs: Sequence[Sig]) -> list[Sig]:
    """Remove names with duplicate found signatures."""
    sig_map: MutableMapping[str, list[str]] = {}
    for name, sig in sigs:
        sig_map.setdefault(name, []).append(sig)

    result = []
    for name, name_sigs in sig_map.items():
        if len(set(name_sigs)) == 1:
            result.append((name, name_sigs[0]))
    return sorted(result)


def infer_prop_type_from_docstring(docstr: str | None) -> str | None:
    """Check for Google/Numpy style docstring type annotation for a property.

    The docstring has the format "<type>: <descriptions>".
    In the type string, we allow the following characters:
    * dot: because sometimes classes are annotated using full path
    * brackets: to allow type hints like List[int]
    * comma/space: things like Tuple[int, int]
    """
    if not docstr:
        return None
    test_str = r"^([a-zA-Z0-9_, \.\[\]]*): "
    m = re.match(test_str, docstr)
    return m.group(1) if m else None
