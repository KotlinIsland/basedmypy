import re
from unittest import TestCase

from mypy.plugins.re import _parse_groups


class TestRe(TestCase):
    def test_parse_groups(self):
        assert _parse_groups("") == ()
        assert _parse_groups("()") == ((None, True),)
        assert _parse_groups("(?:)") == ()
        assert _parse_groups("(?m)") == ()
        assert _parse_groups("()?") == ((None, False),)
        assert _parse_groups("()*") == ((None, False),)

        error = _parse_groups("(")
        assert isinstance(error, re.error)
        assert error.msg == "missing ), unterminated subpattern"
        assert _parse_groups("([\\'])") == ((None, True),)
        assert _parse_groups("(())?") == ((None, False), (None, False))
        assert _parse_groups("(()?)") == ((None, True), (None, False))
        assert _parse_groups("((())?)") == ((None, True), (None, False), (None, False))

        assert _parse_groups("()|()") == ((None, False), (None, False))
        assert _parse_groups("(()|())") == ((None, True), (None, False), (None, False))
        assert _parse_groups("(())(()|()())") == (
            (None, True),
            (None, True),
            (None, True),
            (None, False),
            (None, False),
            (None, False),
        )

        assert _parse_groups("[()]") == ()
        assert _parse_groups("[]\\]()]") == ()
        assert _parse_groups("[^]()]") == ()

        assert _parse_groups("(?P<a>(?P<b>))(?P<c>(?P<d>)|(?P<e>)(?P<f>))") == (
            ("a", True),
            ("b", True),
            ("c", True),
            ("d", False),
            ("e", False),
            ("f", False),
        )
        assert _parse_groups("(?P<n>a)(?(n)b)") == (("n", True),)

        assert _parse_groups("(?=a(b)c)a") == ((None, True),)
        assert _parse_groups("(?!a(b)c)a") == ((None, False),)
        assert _parse_groups("(?#as(|[]]]|[((((\\)df)fdsa") == ()
        assert _parse_groups("(?#a)()") == ((None, True),)
        assert _parse_groups("(?#()()") == ((None, True),)

        assert _parse_groups("(?x)#()\n(?#()()?") == ((None, False),)
        assert _parse_groups("#()\n(?#()()?", verbose=True) == ((None, False),)
        assert _parse_groups("((?:#x))") == ((None, True),)
