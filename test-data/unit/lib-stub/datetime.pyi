# Very simplified datetime stubs for use in tests

class date:
    def __new__(
        cls,
        year: int,
        month: int,
        day: int,
    ) -> date: ...
    def __format__(self, __fmt: str) -> str: ...


class datetime(date):
    def __new__(
        cls,
        year: int,
        month: int,
        day: int,
        hour: int = ...,
        minute: int = ...,
        second: int = ...,
        microsecond: int = ...,
        *,
        fold: int = ...,
    ) -> datetime: ...
