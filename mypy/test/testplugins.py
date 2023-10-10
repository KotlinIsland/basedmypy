import re
from unittest import TestCase

from mypy.plugins.re import _parse_groups


class TestRe(TestCase):
    def test_parse_groups(self):
        assert _parse_groups("") == ()
        assert _parse_groups("()") == ((None, 1),)
        assert _parse_groups("(?:)") == ()
        assert _parse_groups("(?m)") == ()
        assert _parse_groups("()?") == ((None, 0),)
        assert _parse_groups("()*") == ((None, 0),)

        error = _parse_groups("(")
        assert isinstance(error, re.error)
        assert error.msg == "missing ), unterminated subpattern"
        assert _parse_groups("([\\'])") == ((None, 1),)
        assert _parse_groups("(())?") == ((None, 0), (None, 0))
        assert _parse_groups("(()?)") == ((None, 1), (None, 0))
        assert _parse_groups("((())?)") == ((None, 1), (None, 0), (None, 0))

        assert _parse_groups("()|()") == ((None, 0), (None, 0))
        assert _parse_groups("(()|())") == ((None, 1), (None, 0), (None, 0))
        assert _parse_groups("(())(()|()())") == (
            (None, 1),
            (None, 1),
            (None, 1),
            (None, 0),
            (None, 0),
            (None, 0),
        )

        assert _parse_groups("[()]") == ()
        assert _parse_groups("[]\\]()]") == ()
        assert _parse_groups("[^]()]") == ()

        assert _parse_groups("(?P<a>(?P<b>))(?P<c>(?P<d>)|(?P<e>)(?P<f>))") == (
            ("a", 1),
            ("b", 1),
            ("c", 1),
            ("d", 0),
            ("e", 0),
            ("f", 0),
        )

        assert _parse_groups("(?=a(b)c)a") == ((None, 1),)
        assert _parse_groups("(?!a(b)c)a") == ((None, 0),)
        assert _parse_groups("(?#as(|[]]]|[((((\\)df)fdsa") == ()
