#!/usr/bin/env python3

from pytm import (
    TM,
    Dataflow,
    ExternalEntity,
)


t = TM(
    "my test tm",
)

test = ExternalEntity('Test')
test2 = ExternalEntity('Test2')

import tm

Dataflow(
    test,
    tm.user,
    'flow',
    data=tm.comment_to_show,
)

Dataflow(
    test,
    tm.secretDb,
    'flow2',
    data=tm.comment_to_show,
)

if __name__ == "__main__":
    t.process()
