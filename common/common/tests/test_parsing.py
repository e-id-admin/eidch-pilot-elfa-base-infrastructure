# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import common.parsing as parsing


def test_interpret_as_bool():
    assert parsing.interpret_as_bool("True")
    assert parsing.interpret_as_bool("true")
    assert parsing.interpret_as_bool("TrUe")
    assert parsing.interpret_as_bool("yes")
    assert parsing.interpret_as_bool("y")
    assert parsing.interpret_as_bool("1")
    assert parsing.interpret_as_bool(1)
    assert parsing.interpret_as_bool(True)
    assert not parsing.interpret_as_bool("False")
    assert not parsing.interpret_as_bool("Falee")
    assert not parsing.interpret_as_bool("Truee")
    assert not parsing.interpret_as_bool("no")
    assert not parsing.interpret_as_bool("n")
    assert not parsing.interpret_as_bool("0")
    assert not parsing.interpret_as_bool(0)
    assert not parsing.interpret_as_bool(False)
