[![Discord](https://img.shields.io/discord/948915247073349673?logo=discord)](https://discord.gg/7y9upqPrk2)
[![Stable Version](https://img.shields.io/pypi/v/basedmypy?color=blue)](https://pypi.org/project/basedmypy/)
[![Downloads](https://img.shields.io/pypi/dm/basedmypy)](https://pypistats.org/packages/basedmypy)
[![Documentation](https://img.shields.io/badge/📚%20docs-blue)](https://KotlinIsland.github.io/basedmypy)
[![Checked with basedmypy](https://img.shields.io/badge/basedmypy-checked-brightgreen?labelColor=orange)](https://github.com/KotlinIsland/basedmypy)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)

<!-- can't use a <picture> because it doesn't work in the app -->

![Amon Gus.](/docs/static/logo-dark.png#gh-dark-mode-only)
![Amon Gus.](/docs/static/logo-light.png#gh-light-mode-only)

# Based Static Typing for Python

Basedmypy is a Python type checker that is built on top of the work done by the
[mypy project](https://github.com/python/mypy). It adds based functionality and breaks compatibility with
the cringe parts of pep 484.

Based features include:

- Typesafe by default (optional and dynamic typing still supported)
- Baseline functionality
- Support for `Intersection` types
- Default return type of `None` instead of `Any`
- Generic `TypeVar` bounds
- Infer parameter type from default value
- Infer overload types
- Bare literals
- Tuple literal types

See the [features](#features) for a more information.

## Usage

### Installation

Basedmypy can be installed using pip from PyPI or from this GitHub repo:

    python -m pip install -U basedmypy

### Running

Basedmypy is installed as an alternative to, and in place of, the `mypy` installation:

    mypy test.py

    python -m mypy test.py

## Features

Have you ever tried to use Pythons type system and thought to yourself "This doesn't seem based"?

Well fret no longer as basedmypy has got you covered!

### Baseline

Basedmypy has baseline, baseline is based! It allows you to adopt new strictness or features
without the burden of refactoring and fixing every new error, just save all current errors to the baseline
file and resolve them at what ever pace you want. Only new code will report new errors.

Read more and see examples in [the docs](https://KotlinIsland.github.io/basedmypy/baseline)

### Intersection Types

Using the `&` operator or `basedtyping.Intersection` you can denote intersection types:

```py
class Growable(ABC, Generic[T]):
    @abstractmethod
    def add(self, item: T): ...


class Resettable(ABC):
    @abstractmethod
    def reset(self): ...


def f(x: Resettable & Growable[str]):
    x.reset()
    x.add("first")
```

### Type Joins

Mypy joins types to their common base type:

```py
a: int
b: str
reveal_type(a if bool() else b)  # Revealed type is "builtins.object"
``````

Basedmypy joins types into unions instead:

```py
a: int
b: str
reveal_type(a if bool() else b)  # Revealed type is "int | str"
```

### Bare Literals

`Literal` is so cumbersome! just use a bare literal instead.

```py
class Color(Enum):
    RED = auto()


a: 1 | 2
b: True | Color.RED
```

### Default Return Type

The default return type of functions is `None` instead of `Any`:
(configurable with the `default_return` option.)

```py
def f(name: str):
    print(f"Hello, {name}!")


reveal_type(f)  # (str) -> None
```

### Generic `TypeVar` Bounds

Basedmpy allows the bounds of `TypeVar`s to be generic.

So you are able to have functions with polymorphic generic parameters:

```py
E = TypeVar("E")
I = TypeVar("I", bound=Iterable[E])


def foo(i: I, e: E) -> I:
    assert e not in i
    return i


reveal_type(foo(["based"], "mypy"))  # N: Revealed type is "list[str]"
reveal_type(foo({1, 2}, 3))  # N: Revealed type is "set[int]"
```

### Overload Implementation Inference

The types in overload implementations (including properties) can be inferred:

```py
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
```

### Infer Function Parameters

Infer the type of a function parameter from its default value:

```py
def f(a=1, b=True):
    reveal_type((a, b))  # (int, bool)
```

### Tuple Literal Types

Basedmypy allows denotation of tuple types with tuple literals:

```py
a: (int, str) = (1, "a")
```

### Types in Messages

Basedmypy makes significant changes to error and info messages, consider:

```py
T = TypeVar("T", bound=int)


def f(a: T, b: list[str | 1 | 2]) -> Never:
    reveal_type((a, b))


reveal_type(f)
```

Mypy shows:

```
Revealed type is "Tuple[T`-1, Union[builtins.str, Literal[1], Literal[2]]]"
Revealed type is "def [T <: builtins.int] (a: T`-1, b: Union[builtins.str, Literal[1], Literal[2]]) -> <nothing>"
```

Basedmypy shows:

```
Revealed type is "(T@f, str | 1 | 2)"
Revealed type is "def [T: int] (a: T, b: str | 1 | 2) -> Never"
```

Got a question or found a bug?
----------------------------------

Feel free to start a discussion or raise an issue, we're happy to respond:

- [basedmypy tracker](https://github.com/KotlinIsland/basedmypy/issues)
  for basedmypy issues
- [basedtypeshed tracker](https://github.com/KotlinIsland/basedtypeshed/issues)
  for issues with specific modules
- [basedtyping tracker](https://github.com/KotlinIsland/basedtyping/issues)
  for issues with the 'basedtyping' package (runtime functionality).
