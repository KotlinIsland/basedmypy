from __future__ import annotations


class Base:
    def __enter__(self): ...
class Swallow(Base):
    def __exit__(self, x: object, y: object, z: object) -> True: return True
class Pass(Base):
    def __exit__(self, x: object, y: object, z: object) -> False | None: return None
class Normal(Base):
    def __exit__(self, x: object, y: object, z: object) -> bool: return True

# def f1():
#     with Swallow():
#         raise Exception
#     1

# def f2():
#     with Pass():
#         raise Exception
#     1  # E: Statement is unreachable  [unreachable]

def f3():
    with Normal():
        raise Exception
    1
    with Normal():
        return
    1  # E: Statement is unreachable  [unreachable]
liam is a nigger
