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

**CAVEAT: the threat.py file contains strings that run through eval\(\) -&gt; make sure the file has correct permissions or risk having an attacker change the strings and cause you to run code on their behalf**

The logic lives in the "condition", where members of "target" can be logically evaluated. Returning a true means the rule generates a finding, otherwise, it is not a finding.

For the developer: define your system in code as a collection of objects and annotate them with properties, then call out TM.process\(\) to identify threats and TM.report\(\) to write out the report. Partial operations can be chosen on the command line:

```text
usage: tm.py [-h] [--debug] [--resolve] [--dfd] [--report] [--all]
             [--exclude EXCLUDE] [--seq]

optional arguments:
  -h, --help         show this help message and exit
  --debug            print debug messages
  --resolve          identify threats
  --dfd              output DFD (default)
  --report           output report
  --all              output everything
  --exclude EXCLUDE  specify threat IDs to be ignored
  --seq              output sequential diagram
```

Report comes out in Markdown with diagrams using ![Dot](https://graphviz.gitlab.io/) and ![PlantUML](https://plantuml.com/). Source files are output to stdout, Dataflow and PlantUML are not expected to be installed and do not run in lieu of the user.

```python
#!/usr/bin/env python3

from pytm.pytm import TM, Server, Datastore, Dataflow, Boundary, Actor


tm = TM("my test tm")
tm.description = "another test tm"

User_Web = Boundary("User/Web")
Web_DB = Boundary("Web/DB")

user = Actor("User")
user.inBoundary = User_Web

web = Server("Web Server")
web.OS = "CloudOS"
web.isHardened = True

db = Datastore("SQL Database (*)")
db.OS = "CentOS"
db.isHardened = False
db.inBoundary = Web_DB
db.isSql = True
db.inScope = False

user_to_web = Dataflow(user, web, "User enters comments (*)")
user_to_web.protocol = "HTTP"
user_to_web.dstPort = 80
user_to_web.data = 'Comments in HTML or Markdown'
user_to_web.order = 1

web_to_user = Dataflow(web, user, "Comments saved (*)")
web_to_user.protocol = "HTTP"
web_to_user.data = 'Ack of saving or error message, in JSON'
web_to_user.order = 2

web_to_db = Dataflow(web, db, "Insert query with comments")
web_to_db.protocol = "MySQL"
web_to_db.dstPort = 3306
web_to_db.data = 'MySQL insert statement, all literals'
web_to_db.order = 3

db_to_web = Dataflow(db, web, "Comments contents")
db_to_web.protocol = "MySQL"
db_to_web.data = 'Results of insert op'
db_to_web.order = 4

tm.process()

```

This input generates output to stdout, which is fed to Graphviz's dot:

```bash
tm.py --dfd | dot -Tpng -o sample.png
```

Generates this diagram:

![dfd.png](.gitbook/assets/dfd.png)

Dataflows can be ordered and sequence diagrams can be generated:

```python
user_to_web = Dataflow(user, web, "User enters comments (*)")
user_to_web.protocol = "HTTP"
user_to_web.dstPort = 80
user_to_web.data = 'Comments in HTML or Markdown'
user_to_web.order = 1
```

```bash
tm.py --seq | java -Djava.awt.headless=true -jar ~/bin/plantuml.jar -tpng > seq.png
```

Generates this diagram:

![seq.png](.gitbook/assets/seq.png)
