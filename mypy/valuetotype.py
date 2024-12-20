"""Translate an Expression to a Type value."""

from __future__ import annotations

import builtins

from mypy import checker
from mypy.types import (
    FunctionLike,
    Instance,
    LiteralType,
    LiteralValue,
    NoneType,
    TupleType,
    Type,
    TypeType,
    UninhabitedType,
)


def value_to_type(value: object, chk: checker.TypeChecker):
    if isinstance(value, tuple):
        return TupleType([value_to_type(item) for item in value], fallback=chk.named_type('builtins.tuple'))
    if isinstance(value, (int, str, float, complex)):
        type_value = value.__class__
        return (
            LiteralType(
                value,
                chk.named_type(
                    f"{type_value.__module__}.{type_value.__name__}"
                ),
            )
        )
    if isinstance(value, type):
        # TODO: should this be Instance?
        return TypeType(chk.named_type(f"{value.__module__}.{value.__qualname__}"))
    if value is None:
        return NoneType()
    if value is NotImplemented:
        return UninhabitedType()
    typ = value.__class__
    return chk.named_type(f"{typ.__module__}.{typ.__qualname__}")

def type_to_value(typ: Type, chk: checker.TypeChecker) -> object:
    # TODO: type args
    if isinstance(typ, Instance):
        if typ.last_known_value:
            return typ.last_known_value.value
        elif typ.type.fullname.startswith("builtins."):
            return eval(typ.type.fullname, {"builtins": builtins})
    elif isinstance(typ, TypeType) or isinstance(typ, FunctionLike) and typ.fallback.type.fullname == "builtins.type":
        return type
    elif isinstance(typ, NoneType):
        return None
    elif isinstance(typ, LiteralType):
        return typ.value
    else:
        return object
