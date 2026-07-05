#!/usr/bin/env python3

from pytm import (
    TM,
    Actor,
    Agent,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    Lambda,
    LLM,
    Server,
    DatastoreType,
    Assumption,
)

tm = TM("my test tm")
tm.description = """This is a sample threat model of a very simple system - a web-based comment system. 
The user enters comments and these are added to a database and displayed back to the user. 
The thought is that it is, though simple, a complete enough example to express meaningful threats."""
tm.isOrdered = True
tm.mergeResponses = True
tm.assumptions = [
    "Here you can document a list of assumptions about the system",
]

internet = Boundary("Internet")

server_db = Boundary("Server/DB")
server_db.levels = [2]

vpc = Boundary("AWS VPC")

user = Actor("User")
user.inBoundary = internet
user.levels = [2]

web = Server("Web Server")
web.inBoundary = vpc
web.OS = "Ubuntu"
web.controls.isHardened = True
web.controls.sanitizesInput = False
web.controls.encodesOutput = True
web.controls.authorizesSource = False
web.sourceFiles = ["pytm/json.py", "docs/template.md"]
web.assumptions = [
    Assumption(
        "This webserver does not use PHP",
        exclude=["INP16"],
    ),
]

db = Datastore("SQL Database")
db.OS = "CentOS"
db.controls.isHardened = False
db.inBoundary = server_db
db.type = DatastoreType.SQL
db.inScope = True
db.maxClassification = Classification.RESTRICTED
db.levels = [2]

secretDb = Datastore("Real Identity Database")
secretDb.OS = "CentOS"
secretDb.sourceFiles = ["pytm/pytm.py"]
secretDb.controls.isHardened = True
secretDb.inBoundary = server_db
secretDb.type = DatastoreType.SQL
secretDb.inScope = True
secretDb.storesPII = True
secretDb.maxClassification = Classification.TOP_SECRET

my_lambda = Lambda("AWS Lambda")
my_lambda.controls.hasAccessControl = True
my_lambda.inBoundary = vpc
my_lambda.levels = [1, 2]

comment_moderator = LLM("Comment Moderation LLM")
comment_moderator.inBoundary = vpc
comment_moderator.isSelfHosted = True
comment_moderator.processesUntrustedInput = True
comment_moderator.hasContentFiltering = True
comment_moderator.hasSystemPrompt = True

ai_assistant = LLM("AI Writing Assistant")
ai_assistant.inBoundary = vpc
ai_assistant.isThirdParty = True
ai_assistant.processesUntrustedInput = True
ai_assistant.processesPersonalData = True
ai_assistant.hasContentFiltering = False
ai_assistant.hasSystemPrompt = True

moderation_agent = Agent("Moderation Agent")
moderation_agent.inBoundary = server_db
moderation_agent.usesExternalTools = True
moderation_agent.validatesToolLaunchConfig = False

token_user_identity = Data(
    "Token verifying user identity", classification=Classification.SECRET
)
db_to_secretDb = Dataflow(db, secretDb, "Database verify real user identity")
db_to_secretDb.protocol = "RDA-TCP"
db_to_secretDb.dstPort = 40234
db_to_secretDb.data = token_user_identity
db_to_secretDb.note = "Verifying that the user is who they say they are."
db_to_secretDb.maxClassification = Classification.SECRET

comments_in_text = Data(
    "Comments in HTML or Markdown", classification=Classification.PUBLIC
)
user_to_web = Dataflow(user, web, "User enters comments (*)")
user_to_web.protocol = "HTTP"
user_to_web.dstPort = 80
user_to_web.data = comments_in_text
user_to_web.note = "This is a simple web app\nthat stores and retrieves user comments."

query_insert = Data("Insert query with comments", classification=Classification.PUBLIC)
web_to_db = Dataflow(web, db, "Insert query with comments")
web_to_db.protocol = "MySQL"
web_to_db.dstPort = 3306
web_to_db.data = query_insert
web_to_db.note = (
    "Web server inserts user comments\ninto it's SQL query and stores them in the DB."
)

comment_retrieved = Data(
    "Web server retrieves comments from DB", classification=Classification.PUBLIC
)
db_to_web = Dataflow(db, web, "Retrieve comments")
db_to_web.protocol = "MySQL"
db_to_web.dstPort = 80
db_to_web.data = comment_retrieved
db_to_web.responseTo = web_to_db

comment_to_show = Data(
    "Web server shows comments to the end user", classification=Classification.PUBLIC
)
web_to_user = Dataflow(web, user, "Show comments (*)")
web_to_user.protocol = "HTTP"
web_to_user.data = comment_to_show
web_to_user.responseTo = user_to_web

clear_op = Data("Serverless function clears DB", classification=Classification.PUBLIC)
my_lambda_to_db = Dataflow(my_lambda, db, "Serverless function periodically cleans DB")
my_lambda_to_db.protocol = "MySQL"
my_lambda_to_db.dstPort = 3306
my_lambda_to_db.data = clear_op

moderation_request = Data(
    "Comment submitted for moderation", classification=Classification.PUBLIC
)
web_to_moderator = Dataflow(web, comment_moderator, "Send comment for moderation")
web_to_moderator.protocol = "HTTPS"
web_to_moderator.dstPort = 443
web_to_moderator.data = moderation_request

moderation_result = Data("Moderation verdict", classification=Classification.PUBLIC)
moderator_to_web = Dataflow(comment_moderator, web, "Moderation verdict")
moderator_to_web.protocol = "HTTPS"
moderator_to_web.data = moderation_result
moderator_to_web.responseTo = web_to_moderator

draft_request = Data(
    "User draft text for AI assistance", classification=Classification.PUBLIC
)
web_to_assistant = Dataflow(web, ai_assistant, "Request AI comment assistance")
web_to_assistant.protocol = "HTTPS"
web_to_assistant.dstPort = 443
web_to_assistant.data = draft_request

draft_suggestion = Data(
    "AI-generated comment suggestion", classification=Classification.PUBLIC
)
assistant_to_web = Dataflow(ai_assistant, web, "Return AI suggestion")
assistant_to_web.protocol = "HTTPS"
assistant_to_web.data = draft_suggestion
assistant_to_web.responseTo = web_to_assistant

agent_to_db = Dataflow(moderation_agent, db, "Agent queries user comment history")
agent_to_db.protocol = "MySQL"
agent_to_db.dstPort = 3306

userIdToken = Data(
    name="User ID Token",
    description="Some unique token that represents the user real data in the secret database",
    classification=Classification.TOP_SECRET,
    traverses=[user_to_web, db_to_secretDb],
    processedBy=[db, secretDb],
)

if __name__ == "__main__":
    tm.process()
