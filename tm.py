#!/usr/bin/env python3

from pytm.pytm import TM, Server, Database, Dataflow


tm = TM("my test tm")
tm.description = "another test tm"


web = Server("web server")
web.OS = "CloudOS"
web.hardened = True

db = Database("database server")
db.OS = "CentOS"
db.hardened = False
db.print()

web_and_db = Dataflow(web, db, "web and db")
web_and_db.protocol = "HTTP"

tm.resolve()  
tm.dataflow()