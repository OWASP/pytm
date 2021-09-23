#!/usr/bin/env python3
"""
Test if an import has more than one element and the test onyl uses one of them that the result is the same as test1.py
"""
import norandom

from pytm import (
    TM,
    Dataflow,
    Process,
)
import many_import as tm


t = TM(
    "Test",
)

test = Process(
        'Test',
        port=1
        )

Dataflow(
    test,
    tm.entity,
    'flow',
    port=1,
)

if __name__ == "__main__":
    t.process()
