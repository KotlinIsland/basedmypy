from typing import TypeVar

T = TypeVar("T")
T_out = TypeVar("T_out", covariant=True)
T_in = TypeVar("T_in", contravariant=True)
