# Stub for basedtyping. Many of the definitions have special handling in
# the type checker, so they can just be initialized to anything.
#
# DO NOT ADD TO THIS FILE UNLESS YOU HAVE A GOOD REASON! Additional definitions
# will slow down tests.

from helper import T

Untyped = 0
Intersection = 0
FunctionType = 0
Abstract = 0
def abstract(fn: T) -> T: ...
