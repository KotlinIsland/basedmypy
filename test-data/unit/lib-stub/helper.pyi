from typing import TypeVar

T = TypeVar("T")
T_out = TypeVar("T_out", covariant=True)
out_T = TypeVar("out_T", covariant=True)
T_in = TypeVar("T_in", contravariant=True)
in_T = TypeVar("in_T", contravariant=True)
