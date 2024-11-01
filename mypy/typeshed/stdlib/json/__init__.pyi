from _typeshed import SupportsRead, SupportsWrite
from collections.abc import Callable
from typing_extensions import Any, TypeAlias, overload, Never

from .decoder import JSONDecodeError as JSONDecodeError, JSONDecoder as JSONDecoder
from .encoder import JSONEncoder as JSONEncoder

__all__ = ["dump", "dumps", "load", "loads", "JSONDecoder", "JSONDecodeError", "JSONEncoder"]

_JsonType: TypeAlias = dict[str, _JsonType] | list[_JsonType] | float | int | bool | str | None

def dumps(
    obj: object,
    *,
    skipkeys: bool = False,
    ensure_ascii: bool = True,
    check_circular: bool = True,
    allow_nan: bool = True,
    cls: type[JSONEncoder] | None = None,
    indent: None | int | str = None,
    separators: tuple[str, str] | None = None,
    default: Callable[[Any], Any] | None = None,
    sort_keys: bool = False,
    **kwds: object,
) -> str: ...
def dump(
    obj: object,
    fp: SupportsWrite[str],
    *,
    skipkeys: bool = False,
    ensure_ascii: bool = True,
    check_circular: bool = True,
    allow_nan: bool = True,
    cls: type[JSONEncoder] | None = None,
    indent: None | int | str = None,
    separators: tuple[str, str] | None = None,
    default: Callable[[Never], object] | None = None,
    sort_keys: bool = False,
    **kwds: object,
) -> None: ...

@overload
def loads(s: str | bytes | bytearray) -> _JsonType: ...
@overload
def loads(
    s: str | bytes | bytearray,
    *,
    cls: type[JSONDecoder] | None = None,
    object_hook: Callable[[dict[Any, Any]], Any] | None = None,
    parse_float: Callable[[str], Any] | None = None,
    parse_int: Callable[[str], Any] | None = None,
    parse_constant: Callable[[str], Any] | None = None,
    object_pairs_hook: Callable[[list[tuple[Never, Never]]], object] | None = None,
    **kwds: object,
) -> object: ...

@overload
def load(fp: SupportsRead[str | bytes])-> _JsonType:...
def load(
    fp: SupportsRead[str | bytes],
    *,
    cls: type[JSONDecoder] | None = None,
    object_hook: Callable[[dict[Any, Any]], Any] | None = None,
    parse_float: Callable[[str], Any] | None = None,
    parse_int: Callable[[str], Any] | None = None,
    parse_constant: Callable[[str], Any] | None = None,
    object_pairs_hook: Callable[[list[tuple[Any, Any]]], Any] | None = None,
    **kwds: object,
) -> object: ...

def detect_encoding(b: bytes | bytearray) -> str: ...  # undocumented
