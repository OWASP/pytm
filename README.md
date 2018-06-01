# pytm

A Pythonic framework for threat modeling

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

For the developer: define your system in code as a collection of objects and annotate them with properties, then call out TM.process() to identify threats and TM.report() to write out the report. Partial operations can be chosen on the command line:

```text

```

Report comes out in Markdown with diagrams using ![Dataflow](https://github.com/sonyxperiadev/dataflow). Source files are output, Dataflow is not expected to be installed or ran in lieu of the user.

```python

tm = TM("my test tm")
tm.description = "another test tm"

Web_side = Boundary("Web Side")
DB_side = Boundary("DB side")

web = Server("web server")
web.OS = "CloudOS"
web.isHardened = True
web.inBoundary = "Web Side"

db = Database("database server")
db.OS = "CentOS"
db.isHardened = False
db.inBoundary = "DB side"

web_and_db = Dataflow(web, db, "web and db")
web_and_db.protocol = "HTTP"

''' resolves and outputs, according to command line arguments '''
tm.process()
```

This input generates a .tm file:

```text
/* threats =
Finding: Dataflow not authenticated on web and db with score 8.6
*/
diagram {
boundary Web_Side {
    title = "Web Side"
    function web_server {
        title = "web server"
    }
}
boundary DB_side {
    title = "DB side"
    database database_server {
        title = "database server"
    }
}
    web_server -> database_server {
         operation = "web and db"
         data = "HTTP"
    }
}
```

Which, once fed to dataflow and dot:

```bash
dataflow dfd sample.tm | dot -Tpng -o sample.png
```

Generates this diagram:

![sample.png](docs/sample.png)
