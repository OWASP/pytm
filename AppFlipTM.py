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
	ExternalEntity,
	Process,
	SetOfProcesses,
	Element,
)

tm = TM("Google App Flip integration")
tm.description = "Threat Model for the integration of Google AppFlip with Arlo phone app."
tm.isOrdered = True
tm.mergeResponses = True

phone = Boundary("Mobile Device")

backend = Boundary("Arlo Back-End")

google_home = Boundary("Google Home")
gcloud = ExternalEntity("Google Cloud")
gcloud.inScope = False
gcloud.inBoundary = google_home

google_app = Process("Google Home App")
google_app.inScope = False

arlo_app = Process("Arlo App")
arlo_app.implementsAPI = True
arlo_app.sanitizesInput = True
arlo_app.encodesOutput = True
#arlo_app.authorizesSource = True
arlo_app.inBoundary = phone
arlo_app.allowsClientSideScripting = False
arlo_app.encryptsSessionData = True
arlo_app.usesMFA = True
arlo_app.usesStrongSessionIdentifiers = True
arlo_app.verifySessionIdentifiers = True



xcoauth = Server("XC OAuth")
xcoauth.inBoundary = backend
xcoauth.providesIntegrity = True
xcoauth.usesSessionTokens = True
#xcoauth.encodesOutput = True
xcoauth.authorizesSource = True

beservice = Process("Arlo Partner Backend Microservice")
beservice.inBoundary = backend
beservice.providesIntegrity = True
beservice.inScope = False

ghome_to_arloapp = Dataflow(google_app, arlo_app, "AppFlip to Arlo app via deep/universal link")
ghome_to_arloapp.protocol = "HTTPS"
ghome_to_arloapp.data = "Google Home App invokes deep link to Arlo app to start OAuth"
ghome_to_arloapp.maxClassification = Classification.RESTRICTED

arloapp_to_xcoauth = Dataflow(arlo_app, xcoauth, "authenticate with existing session")
arloapp_to_xcoauth.protocol = "HTTPS"
arloapp_to_xcoauth.data = "uses existing session to authenticate with XC OAuth"
arloapp_to_xcoauth.maxClassification = Classification.RESTRICTED

xcoauth_to_gcloud = Dataflow(xcoauth, gcloud, "auth code to Google redirect_uri")
xcoauth_to_gcloud.protocol = "HTTPS"
xcoauth_to_gcloud.data = "Auth code sent to partner via redirect URI"
xcoauth_to_gcloud.maxClassification = Classification.SECRET

gcloud_to_xcoauth = Dataflow(gcloud, xcoauth, "call oauth/token")
gcloud_to_xcoauth.protocol = "HTTPS"
gcloud_to_xcoauth.data = "Auth code used to generate refresh & access tokens for user"
gcloud_to_xcoauth.inScope = False
gcloud_to_xcoauth.maxClassification = Classification.SECRET

xcoauth_to_gcloud2 = Dataflow(xcoauth, gcloud, "Return access/refresh tokens for that user")
xcoauth_to_gcloud2.protocol = "HTTPS"
xcoauth_to_gcloud2.responseTo = gcloud_to_xcoauth
xcoauth_to_gcloud2.inScope = False
xcoauth_to_gcloud2.data = "Access and Refresh tokens generated for user and returned"
xcoauth_to_gcloud2.maxClassification = Classification.SECRET

ghome_to_gcloud = Dataflow(google_app, gcloud, "fetch device list, support live streaming")
ghome_to_gcloud.protocol = "HTTPS"
ghome_to_gcloud.inScope = False

gcloud_to_beservice = Dataflow(gcloud, beservice, "API call to suppport action/directive")
gcloud_to_beservice.protocol = "HTTPS"
gcloud_to_beservice.inScope = False

oauth_tokens = Data(
    name = "Refresh & Access tokens",
    description = "Session Refresh & Access tokens",
    classification = Classification.TOP_SECRET,
    traverses = [xcoauth_to_gcloud2, gcloud_to_beservice],
    processedBy = [beservice],
)

if __name__ == "__main__":
    tm.process()
