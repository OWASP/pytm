#!/usr/bin/env python3

from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Lambda

tm = TM("my test tm")
tm.description = "This is a sample threat model of a very simple system - a web-based comment system. The user enters comments and these are added to a database and displayed back to the user. The thought is that it is, though simple, a complete enough example to express meaningful threats."

internet = Boundary("Internet")
server_db = Boundary("Server/DB")
vpc = Boundary("AWS VPC")

user = Actor("User")
user.inBoundary = internet

web = Server("Web Server")
web.OS = "Ubuntu"
web.isHardened = True
web.sanitizesInput = False
web.encodesOutput = True
web.authorizesSource = False

db = Datastore("SQL Database")
db.OS = "CentOS"
db.isHardened = False
db.inBoundary = server_db
db.isSQL = True
db.inScope = True

my_lambda = Lambda("AWS Lambda")
my_lambda.hasAccessControl = True
my_lambda.inBoundary = vpc

user_to_web = Dataflow(user, web, "User enters comments (*)")
user_to_web.protocol = "HTTP"
user_to_web.dstPort = 80
user_to_web.data = 'Comments in HTML or Markdown'
user_to_web.order = 1
user_to_web.note = "This is a simple web app\nthat stores and retrieves user comments."

web_to_db = Dataflow(web, db, "Insert query with comments")
web_to_db.protocol = "MySQL"
web_to_db.dstPort = 3306
web_to_db.data = 'MySQL insert statement, all literals'
web_to_db.order = 2
web_to_db.note = "Web server inserts user comments\ninto it's SQL query and stores them in the DB."

db_to_web = Dataflow(db, web, "Retrieve comments")
db_to_web.protocol = "MySQL"
db_to_web.dstPort = 80
db_to_web.data = 'Web server retrieves comments from DB'
db_to_web.order = 3

web_to_user = Dataflow(web, user, "Show comments (*)")
web_to_user.protocol = "HTTP"
web_to_user.data = 'Web server shows comments to the end user'
web_to_user.order = 4

my_lambda_to_db = Dataflow(my_lambda, db, "Lambda periodically cleans DB")
my_lambda_to_db.protocol = "MySQL"
my_lambda_to_db.dstPort = 3306
my_lambda_to_db.data = "Lamda clears DB every 6 hours"
my_lambda_to_db.order = 5

tm.process()
