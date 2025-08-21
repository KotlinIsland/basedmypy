> [!IMPORTANT]
> deprecated: basedmypy is no longer actively maintained
>
> as of July 2025, this project is deprecated. basedmypy was intended to push the ecosystem forward from mypy, and there are now great alternatives that exist
>
> - basedpyright: https://github.com/DetachHead/basedpyright
> - ty: https://github.com/astral-sh/ty
>
> we recommend migrating to one of the above projects for ongoing improvements and support. Thank you to everyone who used, contributed to, and supported basedmypy

[![Discord](https://img.shields.io/discord/948915247073349673?logo=discord)](https://discord.gg/7y9upqPrk2)
[![Playground](https://img.shields.io/badge/🛝%20playground-blue)](https://mypy-play.net/?mypy=basedmypy-latest)
[![Stable Version](https://img.shields.io/pypi/v/basedmypy?color=blue)](https://pypi.org/project/basedmypy/)
[![Downloads](https://img.shields.io/pypi/dm/basedmypy)](https://pypistats.org/packages/basedmypy)
[![Documentation](https://img.shields.io/badge/📚%20docs-blue)](https://KotlinIsland.github.io/basedmypy)
[![Checked with basedmypy](https://img.shields.io/badge/basedmypy-checked-brightgreen?labelColor=orange)](https://github.com/KotlinIsland/basedmypy)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Linting: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/charliermarsh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

<!-- can't use a <picture> because it doesn't work in the app -->

![Amon Gus.](/docs/static/logo-dark.png#gh-dark-mode-only)
![Amon Gus.](/docs/static/logo-light.png#gh-light-mode-only)

# Based Static Typing for Python

Basedmypy is a Python type checker that is built on top of the work done by the
[mypy project](https://github.com/python/mypy). It resolves fundamental issues, limitations and compromises
that exist within Mypy and Python's type system.

Based features include:

- Typesafe by default (optional and dynamic typing still supported)
- Baseline functionality
- Support for `Intersection` types
- Default return type of `None` instead of `Any`
- Generic `TypeVar` bounds
- Based type-guards
- Infer parameter type from default value
- Infer overload types
- Bare literals
- Tuple literal types

See the [the docs](https://kotlinisland.github.io/basedmypy/based_features.html) for a comprehensive list.


### BasedPyright

Also, take a look at [BasedPyright](https://github.com/DetachHead/basedpyright), a based type checker and language server based on Pyright!

## Usage

Basedmypy is installed as an alternative to, and in place of, the `mypy` installation:

    mypy test.py

    python -m mypy test.py


## Why?

basedmypy was created to attempt to resolve two issues within Python and Mypy's typing ecosystem
and to demonstrate new typing concepts:

1. Mypy is lacking numerous pieces of functionality
2. Pythons type system is full of deeply concerning compromises

You can find a comprehensive list of features in [the docs](https://kotlinisland.github.io/basedmypy/based_features.html).


## Integrations

If you are using vscode, we recommend the [mypy extension](https://marketplace.visualstudio.com/items?itemName=ms-python.mypy-type-checker)

If you are using IntelliJ IDEA/PyCharm, we recommend the [basedtyping plugin](https://plugins.jetbrains.com/plugin/23374-basedtyping)

If you are using [Pydantic](https://github.com/pydantic/pydantic), we recommend [pydantic-basedtyping](https://github.com/KotlinIsland/pydantic-basedtyping)


### Baseline

Basedmypy supports a feature called baseline. It allows you to adopt new strictness or features
without the burden of refactoring and fixing every new error, just save all current errors to the baseline
file and resolve them at what ever pace you want. Only new code will report new errors.

Read more and see examples in [the docs](https://KotlinIsland.github.io/basedmypy/baseline)
