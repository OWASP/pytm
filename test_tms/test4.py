#!/usr/bin/env python3
"""
Test if the creation of an elment via an import function changes the result
"""
import norandom

from pytm import (
    TM,
    Dataflow,
    Process,
    ExternalEntity,
)

import fn_import


t = TM(
    "Test",
)

test = fn_import.process('Test')
entity = ExternalEntity('ImportedEntity')

Dataflow(
    test,
    entity,
    'flow',
)

if __name__ == "__main__":
    t.process()
