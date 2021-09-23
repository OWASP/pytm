#!/usr/bin/env python3
import norandom

"""
Test if an import below the creation of the TM object
affects the result
"""

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
    tm.entity,
    'flow',
    port=1,
)

if __name__ == "__main__":
    t.process()
