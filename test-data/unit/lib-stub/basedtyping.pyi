# Stub for basedtyping. Many of the definitions have special handling in
# the type checker, so they can just be initialized to anything.
#
# DO NOT ADD TO THIS FILE UNLESS YOU HAVE A GOOD REASON! Additional definitions
# will slow down tests.

Untyped = 0
Intersection = 1
FunctionType = 2
def type_function(fn): ...
class TypeFunctionError(Exception): ...
