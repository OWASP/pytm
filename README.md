# pytm

A Pythonistic framework for threat modeling

For the security practitioner: add threats to the Threat object:

```python
Threats = {
    "DF1": {
        "description": "Dataflow not authenticated",
        "cvss": 8.6,
        "target": Dataflow,
        "condition": "target.authenticatedWith is False"
    },
    "SR1": {
        "description": "Server not hardened",
        "cvss": 9.0,
        "target": Server,
        "condition": "target.isHardened is False"
    }
}
```

The logic lives in the "condition", where members of "target" can be logically evaluated.
Returning a true means the rule generates a finding, otherwise, it is not a finding.


For the developer: define your system in code as a collection of objects and annotate them with properties, then call out TM.resolve() to identify threats and TM.report() to write out the report.

Report comes out in Markdown with diagrams using Dataflow (https://github.com/sonyxperiadev/dataflow). Source files are output, Dataflow is not expected to be installed or ran in lieu of the user.

```python
from pytm.pytm import TM, Server, Database, Dataflow

tm = TM("my test tm")
tm.description = "another test tm"


web = Server("web server")
web.OS = "CloudOS"
web.isHardened = True

db = Database("database server")
web.OS = "CentOS"
web.isHardened = False

web_and_db = Dataflow(web, db, "web and db")
web_and_db.protocol = "HTTP"

''' generates findings '''
tm.resolve()
''' prints out the finding report '''
tm.report()
''' prints out the input for Dataflow '''
tm.dfd()
```

