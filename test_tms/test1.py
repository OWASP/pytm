#!/usr/bin/env python3
"""
Simple import of one element
"""
import norandom

from pytm import (
    TM,
    Dataflow,
    Process,
)
import tm_import1 as tm


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
