"""Plugin to provide accurate types for regex patterns."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Optional, Tuple, cast

from mypy import errorcodes
from mypy.messages import MessageBuilder
from mypy.nodes import CallExpr, Context
from mypy.plugin import FunctionContext, FunctionSigContext, MethodContext, MethodSigContext
from mypy.types import (
    AnyType,
    CallableType,
    Instance,
    LiteralType,
    NoneType,
    ProperType,
    TupleType,
    Type,
    TypedDictType,
    TypeOfAny,
    UnionType,
    get_proper_type,
)

Groups = Tuple[Tuple[Optional[str], bool], ...]


def match(ctx: FunctionContext | MethodContext) -> Type:
    """re.{match,fullmatch,search,finditer}, re.Pattern.{match,fullmatch,search,finditer}"""
    default = cast("UnionType | Instance", ctx.default_return_type)
    if isinstance(ctx, FunctionContext):
        value = _get_first_str_arg(ctx.arg_types[0][0])
        if value is None:
            return default
        groups = parse_groups(value, ctx.args[0][0], ctx.api.msg)
        if groups is None:
            return AnyType(TypeOfAny.from_error)
    else:
        assert isinstance(ctx.type, Instance)
        groups = get_groups(ctx.type)
        if groups is None:
            return default
    instance = default.items[0] if isinstance(default, UnionType) else default.args[0]
    # type ignore because this implementation is closely tied to the stubs and will never see a type alias
    assert isinstance(instance, Instance)  # type: ignore[misc]
    instance.metadata["groups"] = groups
    return (
        UnionType([instance, NoneType()])
        if isinstance(default, UnionType)
        else default.copy_modified(args=[instance])
    )


def match_groups(ctx: MethodContext) -> Type:
    default = ctx.default_return_type
    if not isinstance(ctx.type, Instance):
        return default
    proper_default = get_proper_type(default)
    if isinstance(proper_default, TupleType):
        anystr_none = proper_default.items[0]
        fallback = proper_default.partial_fallback
    elif isinstance(proper_default, Instance):
        anystr_none = proper_default.args[0]
        fallback = proper_default
    else:
        return default
    if isinstance(anystr_none, UnionType):  # type: ignore[misc]
        anystr = anystr_none.items[0]
    else:
        anystr = anystr_none

    groups = get_groups(ctx.type)
    if groups is None:
        return default
    return TupleType([anystr if group[1] == 1 else anystr_none for group in groups], fallback)


def match_group(ctx: MethodContext) -> Type:
    default = ctx.default_return_type
    if not isinstance(ctx.type, Instance):
        return default
    if not ctx.args[0]:
        return default
    value = _get_first_arg(ctx.arg_types[0][0])
    groups = get_groups(ctx.type)
    if groups is None:
        return default
    return _group(value, groups, ctx)


def _group(value: object, groups: Groups, ctx: MethodContext) -> Type:
    assert isinstance(ctx.type, Instance)
    if isinstance(value, int):
        if value > len(groups):
            ctx.api.msg.fail(f"No such group: {value}", ctx.context, code=errorcodes.REGEX)
            return AnyType(TypeOfAny.from_error)
        if value == 0 or groups[value - 1][1] == 1:
            assert isinstance(ctx.type, Instance)
            return ctx.type.args[0]
    elif isinstance(value, str):
        for group in groups:
            if value == group[0]:
                if group[1] == 1:
                    return ctx.type.args[0]
                return ctx.default_return_type
        ctx.api.msg.fail(f"No such group: '{value}'", ctx.context, code=errorcodes.REGEX)

        return AnyType(TypeOfAny.from_error)
    return ctx.default_return_type


def compile(ctx: FunctionContext) -> Type:
    """re.compile, re.template"""
    default = ctx.default_return_type
    if not ctx.arg_types[0]:
        return default
    value = _get_first_str_arg(ctx.arg_types[0][0])
    if value is None:
        return default
    groups = parse_groups(value, ctx.args[0][0], ctx.api.msg)
    if groups is None:
        return AnyType(TypeOfAny.from_error)
    assert isinstance(default, Instance)  # type: ignore[misc]
    default.metadata["groups"] = groups
    return default


def split(ctx: FunctionContext | MethodContext) -> Type:
    default = cast(Instance, ctx.default_return_type)
    if isinstance(ctx, FunctionContext):
        value = _get_first_str_arg(ctx.arg_types[0][0])
        if value is None:
            return default
        groups = parse_groups(value, ctx.args[0][0], ctx.api.msg)
        if groups is None:
            return AnyType(TypeOfAny.from_error)
    else:
        if not isinstance(ctx.type, Instance):
            return default
        groups = get_groups(ctx.type)
    if groups is None:
        return default
    if all(group for _, group in groups):
        # all groups are non-optional
        arg = default.args[0]
        assert isinstance(arg, UnionType)  # type: ignore[misc]
        return default.copy_modified(args=[arg.items[0]])
    return default


def findall(ctx: FunctionContext | MethodContext) -> Type:
    default = cast(Instance, ctx.default_return_type)
    if isinstance(ctx, FunctionContext):
        value = _get_first_str_arg(ctx.arg_types[0][0])
        if value is None:
            return default
        groups = parse_groups(value, ctx.args[0][0], ctx.api.msg)
        if groups is None:
            return AnyType(TypeOfAny.from_error)
    else:
        groups = get_groups(cast(Instance, ctx.type))
        if groups is None:
            return default
    l = len(groups)
    arg = default.args[0]
    assert isinstance(arg, UnionType)  # type: ignore[misc]
    any_str = arg.items[0]
    if l <= 1:
        return ctx.api.named_generic_type("builtins.list", [any_str])
    return ctx.api.named_generic_type(
        "builtins.list",
        [TupleType([any_str] * l, ctx.api.named_generic_type("builtins.tuple", [any_str]))],
    )


def sub(ctx: FunctionSigContext | MethodSigContext) -> CallableType:
    default = ctx.default_signature
    args = default.arg_types.copy()

    if isinstance(ctx, FunctionSigContext):
        if not isinstance(ctx.context, CallExpr):
            return default
        arg_one = ctx.context.args[0]
        typ = ctx.api.get_expression_type(arg_one)
        value = _get_first_str_arg(typ)
        if value is None:
            return default
        groups = parse_groups(value, ctx.context, ctx.api.msg)
        repl_index = 1
    else:
        groups = get_groups(cast(Instance, ctx.type))
        repl_index = 0
    if groups is None:
        return default
    repl = args[repl_index]
    assert isinstance(repl, UnionType)  # type: ignore[misc]
    call = repl.items[1]
    assert isinstance(call, CallableType)  # type: ignore[misc]
    arg = call.arg_types[0]
    assert isinstance(arg, Instance)  # type: ignore[misc]
    grouped = arg.copy_modified()
    grouped.metadata["groups"] = groups
    call = call.copy_modified(arg_types=[grouped])
    items = repl.items.copy()
    items[1] = call
    repl = UnionType(items)
    args[repl_index] = repl
    return default.copy_modified(arg_types=args)


def _get_first_arg(arg: Type) -> str | int | None:
    assert isinstance(arg, ProperType)
    if isinstance(arg, LiteralType):
        result = arg.value
        if not isinstance(result, (str, int)):
            return None
        return result
    elif (
        isinstance(arg, Instance)
        and arg.last_known_value
        and isinstance(arg.last_known_value.value, (str, int))
    ):
        return arg.last_known_value.value
    return None


def _get_first_str_arg(arg: Type) -> str | None:
    result = _get_first_arg(arg)
    assert not isinstance(result, int)
    return result


def match_groupdict(ctx: MethodContext) -> Type:
    default = ctx.default_return_type
    if not isinstance(ctx.type, Instance):
        return default
    groups = get_groups(ctx.type)
    if groups is None:
        return default
    str = ctx.type.args[0]
    str_none = UnionType([str, NoneType()])
    groups_keys = {key for key, _ in groups if key}
    assert isinstance(default, Instance)  # type: ignore[misc]
    return TypedDictType(
        items={name: str if group else str_none for name, group in groups if name},
        required_keys=groups_keys,
        fallback=default,
    )


def parse_groups(value: str, context: Context, msg: MessageBuilder) -> Groups | None:
    groups = _parse_groups(value)
    if isinstance(groups, Exception):
        msg.fail(str(groups), context, code=errorcodes.REGEX)
        return None
    return groups


@lru_cache(None)
def _parse_groups(value: str) -> Groups | re.error:
    """The 'most important part' of this feature, we parse the regex pattern to discern which groups are optional."""
    try:
        p = re.compile(value)
    except re.error as e:
        return e

    groups: list[bool] = []
    working = []
    """
    1 = capturing group
    0 = optional capturing group
    -1 = non-capturing group
    -2 = optional non-capturing group
    """
    depth = 0
    escape = False
    union = -1
    character_set = 0
    """
    0 = not in a character set
    1 = `]` is literal in a character set
    2 = normal character set
    """
    comment = False
    for i in range(len(value)):
        if escape:
            escape = False
            continue
        char = value[i]
        if char == ")" and comment:
            comment = False
            continue
        if char == "\\":
            if character_set:
                character_set = 2
            escape = True
            continue
        if comment:
            continue
        if char == "^" and character_set == 1:
            continue
        if char == "]" and character_set == 2:
            character_set = 0
            continue
        if character_set:
            character_set = 2
            continue
        if char == "[":
            character_set = 1
            continue
        if char == "|" and (union > depth or union == -1):
            union = depth
            continue
        if char not in ("(", ")"):
            continue
        if char == "(":
            depth += 1
            if value[i + 1] == "?":
                if value[i + 2 : i + 4] == "P<":
                    working.append(1)
                elif value[i + 2] == "!":
                    working.append(-2)
                elif value[i + 2] in "#":
                    comment = True
                    continue
                else:
                    working.append(-1)
            else:
                working.append(1)
            continue
        if char == ")":
            depth -= 1
            if i + 1 < len(value) and value[i + 1] in "*?":
                for d in range(depth, len(working)):
                    if working[d] == 1:
                        working[d] = 0
            if depth == union - 1 or (depth < len(working) and working[depth] < -1):
                for d in range(depth + 1, len(working)):
                    if working[d] == 1:
                        working[d] = 0
                union = -1
            if depth == 0:
                groups.extend(bool(group) for group in working if group > -1)
                working.clear()
    if union == 0:
        for d in range(len(groups)):
            if groups[d] is True:
                groups[d] = False
    assert len(groups) == p.groups, "parsed groups differ from compiled groups"
    mapping = {value: key for key, value in p.groupindex.items()}
    return tuple((mapping.get(i + 1), group) for i, group in enumerate(groups))


def get_groups(typ: Instance) -> Groups | None:
    return cast("Groups | None", typ.metadata.get("groups"))
