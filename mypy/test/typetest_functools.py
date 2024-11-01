from __future__ import annotations

from functools import _lru_cache_wrapper, lru_cache

# use `basedtyping` when we drop python 3.8
from types import FunctionType
from typing import TYPE_CHECKING, Callable
from typing_extensions import assert_type

from mypy_extensions import Arg

cache = lru_cache(None)


class A:
    @cache
    def m(self, a: int): ...

    @classmethod
    @cache
    def c(cls, a: int): ...

    @staticmethod
    @cache
    def s(a: int): ...


@cache
def f(a: int): ...


a = A()
assert_type(a.m.__call__, Callable[[Arg(int, "a")], None])
assert_type(a.c.__call__, Callable[[Arg(int, "a")], None])
# should be fixed when 1.14 fork is merged
assert_type(a.s.__call__, Callable[[Arg(int, "a")], None])  # type: ignore[assert-type]

if TYPE_CHECKING:
    assert_type(f, _lru_cache_wrapper[FunctionType[[Arg(int, "a")], None]])
    from functools import _HashCallable, _LruCacheWrapperBase

    assert_type(f.__get__(1), _LruCacheWrapperBase[Callable[[], None]])
    assert_type(f.__call__, FunctionType[[Arg(int, "a")], None] | _HashCallable)
