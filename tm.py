#!/usr/bin/env python3

from pytm import (
    TM,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    Lambda,
    Server,
)

tm = TM("my test tm")
tm.description = "This is a sample threat model of a very simple system - a web-based comment system. The user enters comments and these are added to a database and displayed back to the user. The thought is that it is, though simple, a complete enough example to express meaningful threats."
tm.isOrdered = True
tm.mergeResponses = True

internet = Boundary("Internet")
server_db = Boundary("Server/DB")
server_db.levels = [2]
vpc = Boundary("AWS VPC")

user = Actor("User")
user.inBoundary = internet
user.levels = [2]

web = Server("Web Server")
web.OS = "Ubuntu"
web.isHardened = True
web.sanitizesInput = False
web.encodesOutput = True
web.authorizesSource = False
web.sourceFiles = ["pytm/json.py", "docs/template.md"]

db = Datastore("SQL Database")
db.OS = "CentOS"
db.isHardened = False
db.inBoundary = server_db
db.isSQL = True
db.inScope = True
db.maxClassification = Classification.RESTRICTED
db.levels = [2]

secretDb = Datastore("Real Identity Database")
secretDb.OS = "CentOS"
secretDb.sourceFiles = ["pytm/pytm.py"]
secretDb.isHardened = True
secretDb.inBoundary = server_db
secretDb.isSQL = True
secretDb.inScope = True
secretDb.storesPII = True
secretDb.maxClassification = Classification.TOP_SECRET

my_lambda = Lambda("AWS Lambda")
my_lambda.hasAccessControl = True
my_lambda.inBoundary = vpc
my_lambda.levels = [1, 2]

token_user_identity = Data("Token verifying user identity", classification=Classification.SECRET)
db_to_secretDb = Dataflow(db, secretDb, "Database verify real user identity")
db_to_secretDb.protocol = "RDA-TCP"
db_to_secretDb.dstPort = 40234
db_to_secretDb.data = token_user_identity
db_to_secretDb.note = "Verifying that the user is who they say they are."
db_to_secretDb.maxClassification = Classification.SECRET

comments_in_text = Data("Comments in HTML or Markdown", classification=Classification.PUBLIC)
user_to_web = Dataflow(user, web, "User enters comments (*)")
user_to_web.protocol = "HTTP"
user_to_web.dstPort = 80
user_to_web.data = comments_in_text
user_to_web.note = "This is a simple web app\nthat stores and retrieves user comments."

web_to_db = Dataflow(web, db, "Insert query with comments")
web_to_db.protocol = "MySQL"
web_to_db.dstPort = 3306
# this is a BAD way of defining a data object, here for a demo on how it
# will appear on the sample report. Use Data objects.
web_to_db.data = "MySQL insert statement, all literals"
web_to_db.note = (
    "Web server inserts user comments\ninto it's SQL query and stores them in the DB."
)

comment_retrieved = Data("Web server retrieves comments from DB", classification=Classification.PUBLIC)
db_to_web = Dataflow(db, web, "Retrieve comments")
db_to_web.protocol = "MySQL"
db_to_web.dstPort = 80
db_to_web.data = comment_retrieved
db_to_web.responseTo = web_to_db

comment_to_show = Data("Web server shows comments to the end user", classifcation=Classification.PUBLIC)
web_to_user = Dataflow(web, user, "Show comments (*)")
web_to_user.protocol = "HTTP"
web_to_user.data = comment_to_show
web_to_user.responseTo = user_to_web

clear_op = Data("Serverless function clears DB", classification=Classification.PUBLIC)
my_lambda_to_db = Dataflow(my_lambda, db, "Serverless function periodically cleans DB")
my_lambda_to_db.protocol = "MySQL"
my_lambda_to_db.dstPort = 3306
my_lambda_to_db.data = clear_op

userIdToken = Data(
    name="User ID Token",
    description="Some unique token that represents the user real data in the secret database",
    classification=Classification.TOP_SECRET,
    traverses=[user_to_web, db_to_secretDb],
    processedBy=[db, secretDb],
)


if __name__ == "__main__":
    tm.process()
