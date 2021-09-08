#!/usr/bin/env python3

from pytm import (
    TM,
    Dataflow,
    ExternalEntity,
)


t = TM(
    "my test tm",
    ignoreUnused=True,
)

test = ExternalEntity('Test')

print("import")
import tm as example

Dataflow(
    test,
    example.user,
    'flow',
)


if __name__ == "__main__":
    t.process()
