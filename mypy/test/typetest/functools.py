from __future__ import annotations

from functools import lru_cache

# use `basedtyping` when we drop python 3.8
from types import MethodType
from typing import TYPE_CHECKING, Callable
from typing_extensions import assert_type

from mypy_extensions import Arg

# use `functools.cache` when we drop python 3.8
cache = lru_cache(None)


class A:
    @cache
    def m(self, a: list[int]): ...

    @classmethod
    @cache
    def c(cls, a: list[int]): ...

    @staticmethod
    @cache
    def s(a: list[int]): ...


@cache
def f(a: list[int]): ...


if TYPE_CHECKING:
    from functools import _HashCallable, _LruCacheWrapperBase, _LruCacheWrapperMethod

    ExpectedFunction = _LruCacheWrapperBase[Callable[[Arg(list[int], "a")], None]]
    ExpectedMethod = _LruCacheWrapperMethod[Callable[[Arg(list[int], "a")], None]]
    ExpectedMethodNone = _LruCacheWrapperMethod["() -> None"]
    a = A()
    a.m([1])  # type: ignore[arg-type]
    assert_type(a.m, ExpectedMethod)
    assert_type(a.c, ExpectedMethod)
    # this is wrong, it shouldn't eat the `a` argument, but this is because of mypy `staticmethod` special casing
    assert_type(a.s, ExpectedMethodNone)
    assert_type(a.s, MethodType & (_LruCacheWrapperBase[Callable[[Arg(list[int], "a")], None]] | _HashCallable))  # type: ignore[assert-type]
    assert_type(f.__get__(1), ExpectedMethodNone)
    f([1])  # type: ignore[arg-type]
