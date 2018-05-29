#!/usr/bin/env python3

from pytm.pytm import TM, Server, Database, Dataflow, Boundary


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

tm.resolve() 
tm.report()
tm.dfd()

