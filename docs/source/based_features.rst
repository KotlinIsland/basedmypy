.. _based_features:

Based Features
==============


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

``Literal`` is so cumbersome! Just use a bare literal instead:

.. code-block:: python

    class Color(Enum):
        RED = auto()

    a: 1 | 2
    b: True | Color.RED


Default Return Type
-------------------

The default return type of functions is ``None`` instead of ``Any``:
(configurable with the :confval:`default_return` option.)

.. code-block:: python

    def f(name: str):
        print(f"Hello, {name}!")

    reveal_type(f)  # (str) -> None

Generic ``TypeVar`` Bounds
--------------------------

Basedmpy allows the bounds of ``TypeVar``\s to be generic.

So you are able to have functions with polymorphic generic parameters:

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

Infer the type of a function parameter from its default value:

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

