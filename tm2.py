#!/usr/bin/env python3

from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Lambda, Process, ExternalEntity


tm = TM("my test tm")
tm.description = "This is a sample threat model of a very simple system - a web-based comment system. The user enters comments and these are added to a database and displayed back to the user. The thought is that it is, though simple, a complete enough example to express meaningful threats."

internet = Boundary("Internet")
server_db = Boundary("Server/DB")
vpc = Boundary("AWS VPC")

user = Actor("User")
user.inBoundary = internet

my_lambda = Lambda("AWS Lambda")
my_lambda.hasAccessControl = True
my_lambda.inBoundary = vpc

lambda1 = Lambda("Lambda1")
lambda1.usesEnvironmentVariables = True
lambda1.sanitizesInput = False 
lambda1.checksInputBounds = False
lambda1.onAWS = True
lambda1.authenticatesSource = False
lambda1.hasAccessControl = False
lambda1.encodesOutput = False
lambda1.handlesResourceConsumption = False
lambda1.authenticationScheme = 'OAuth2.0'
lambda1.validatesInput = False
lambda1.environment = 'Production'
lambda1.implementsAPI = False

process1 = Process("Process1")
process1.sanitizesInput = False
process1.checksInputBounds = False
process1.codeType = 'Unmanaged'
process1.implementsCommunicationProtocol = False
process1.providesConfidentiality = False
process1.providesIntegrity = False
process1.authenticatesSource = False
process1.authenticatesDestination = False
process1.data = 'XML'
process1.name = 'Web Application'
process1.implementsAuthenticationScheme = False
process1.implementsNonce = False
process1.definesConnectionTimeout = False
process1.isResilient = False
process1.handlesCrashes = False
process1.hasAccessControl = False
process1.tracksExecutionFlow = False
process1.implementsCSRFToken = False
process1.handlesResourceConsumption = False
process1.handlesInterruptions = False
process1.authorizesSource = False
process1.authenticationScheme = 'OAuth2.0'
process1.validatesInput = False
process1.implementsAPI = False
process1.usesSecureFunctions = False
process1.environment = 'Production'

web = Server("Web Server")
web.OS = "Ubuntu"
web.isHardened = True
web.sanitizesInput = True
web.encodesOutput = True
web.authenticatesSource = True
web.providesConfidentiality = False
web.providesIntegrity = False
web.authenticatesDestination = False
web.implementsAuthenticationScheme = False
web.hasAccessControl = False
web.implementsCSRFToken = False
web.handlesResourceConsumption = False
web.authenticationScheme = 'OAuth2.0'
web.validatesInput = False
web.validatesHeaders = False
web.usesSessionTokens = False
web.implementsNonce = False
web.usesEncryptionAlgorithm = 'AES'
web.usesCache = False
web.protocol = 'HTTP'
web.usesVPN = False
web.isResilient = False

adversary = ExternalEntity("Adversary")
adversary.implementsAuthenticationScheme = False
adversary.implementsNonce = False
adversary.handlesResources = False
adversary.definesConnectionTimeout = False
adversary.hasPhysicalAccess = False

db = Datastore("SQL Database")
db.OS = "CentOS"
db.isHardened = False
db.inBoundary = server_db
db.isSQL = True
db.inScope = True
db.onRDS = False
db.storesLogData = False
db.storesPII = False
db.storesSensitiveData = False
db.isEncrypted = False
db.providesConfidentiality = False
db.providesIntegrity = False
db.authenticatesSource = False
db.authenticatesDestination = False
db.isShared = False
db.hasWriteAccess = False
db.handlesResourceConsumption = False
db.definesConnectionTimeout = False
db.isResilient = False
db.handlesInterruptions = False
db.authorizesSource = False
db.hasAccessControl = False
db.authenticationScheme = 'OAuth2.0'
db.usesEncryptionAlgorithm = 'AES'
db.validatesInput = False

user_to_web = Dataflow(user, web, "User enters comments (*)")
user_to_web.protocol = "HTTP"
user_to_web.dstPort = 80
user_to_web.data = 'Comments in HTML or Markdown'
user_to_web.order = 1
user_to_web.note = "This is a simple web app\nthat stores and retrieves user comments."
user_to_web.authenticatedWith = False
user_to_web.implementsCommunicationProtocol = False
user_to_web.implementsNonce = False
user_to_web.isEncrypted = False
user_to_web.usesVPN = False
user_to_web.authorizesSource = False
user_to_web.usesSessionTokens = False

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
