from operator import attrgetter
from typing_extensions import assert_type


def check_attrgetter():
    assert_type(attrgetter("name"), attrgetter[object])
