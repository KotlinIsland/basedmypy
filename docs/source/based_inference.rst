.. _based_inference:

Based Inference
===============


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

Narrow On Initial Assignment
----------------------------

When a variable definition has an explicit annotation, the initialization value will be used to narrow it's type:

.. code-block:: python

    a: object = 1
    reveal_type(a)  # Revealed type is "int"


Unused Parameter Inferred
-------------------------

When a parameter is named `_`, it's type will be inferred as `object`:

.. code-block:: python

    def f(a: int, _):
        reveal_type(_)  # Revealed type is "object"

This is to help with writing functions for callbacks where you don't care about certain parameters.
