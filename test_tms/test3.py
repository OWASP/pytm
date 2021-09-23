#!/usr/bin/env python3
"""
Test if an import below the creation of the TM object
affects the result
"""
import norandom


from pytm import (
    TM,
    Dataflow,
    Process,
)


t = TM(
    "test1",
)
import tm_import1 as tm

test = Process(
        'Test',
        port=1
        )

Dataflow(
    test,
    test,
    'flow',
    port=1,
)

if __name__ == "__main__":
    t.process()
