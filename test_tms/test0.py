#!/usr/bin/env python3
"""
Just a test to amke sure a normal TM gives the desired result
"""
import norandom

from pytm import (
    TM,
    Dataflow,
    Process,
    ExternalEntity,
)



t = TM(
    "Test",
)

test = Process(
        'Test',
        port=1
        )
entity = ExternalEntity('ImportedEntity')

Dataflow(
    test,
    entity,
    'flow',
)

if __name__ == "__main__":
    t.process()
