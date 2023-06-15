.. _baseline:

Baseline
========

Basedmypy supports a feature know as 'baselining' where a snapshot of a codebase is
taken and compared against on subsequent runs. This can be used to ease the gradual
adoption of new checks and strictness options. It is not intended as a utility to
replace ``type: ignore`` comments or to hide errors.

The baseline file should be committed with your project so that other people can utilize and update it.


Workflow
--------

Consider the following:


.. code-block:: python

    # demo.py
    def foo(a: list) -> None:
        if "bar" in a:
            a.append("baz")


All three lines here contain errors:

.. code-block:: text

    > mypy demo.py
    demo.py:1: error: Missing type parameters for generic type "list"  [type-arg]
    demo.py:2: error: Expression type contains "Any" (has type "List[Any]")  [no-any-expr]
    demo.py:3: error: Expression type contains "Any" (has type "List[Any]")  [no-any-expr]
    Found 3 errors in 1 file (checked 1 source file)

We can write these errors to a baseline file:

.. code-block:: text

    > mypy --write-baseline demo.py
    demo.py:1: error: Missing type parameters for generic type "list"  [type-arg]
    demo.py:2: error: Expression type contains "Any" (has type "List[Any]")  [no-any-expr]
    demo.py:3: error: Expression type contains "Any" (has type "List[Any]")  [no-any-expr]
    Found 3 errors (3 new errors) in 1 file (checked 1 source file)
    Baseline successfully written to .mypy/baseline.json

Now when we run mypy again we will not receive any errors:

.. code-block:: text

    > mypy demo.py
    Success: no issues found in 1 source file

If we modify the source code to have the correct full-form type annotation:

.. code-block:: python

    def foo(a: list[str]) -> None:
        if "bar" in a:
            a.append("baz")

And run mypy again:

.. code-block:: text

    > mypy demo.py
    No errors, baseline file removed
    Success: no issues found in 1 source file

It has detected that all the errors have now been resolved and the baseline file is no longer required.

Alternatively, if instead we introduce new code that contains errors:

.. code-block:: python

    def foo(a: list) -> None:
        if "bar" in a:
            a.append("baz")
        1 + ""

And run mypy again:

.. code-block:: text

    > mypy demo.py
    demo.py:4:9: error: Unsupported operand types for + ("int" and "str")  [operator]
    Found 1 error in 1 file (checked 1 source file)

Only errors within the new code are reported.

Additionally
************

If your project uses multiple mypy runs or configurations you can specify alternative baseline file locations for each:

.. code-block:: shell

    > mypy --baseline-file .mypy/strict.json
