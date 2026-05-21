#!/usr/bin/env python3
"""Sample threat model demonstrating LLM element usage."""

from pytm import TM, LLM, Server, Datastore, Boundary, Dataflow, Actor

tm = TM("Sample LLM Threat Model")
tm.description = "A web app using an LLM API for chat and a self-hosted model for classification"

# Boundaries
internet = Boundary("Internet")
cloud = Boundary("Cloud")
internal = Boundary("Internal Network")

# Elements
user = Actor("User", inBoundary=internet)

web_server = Server(
    "Web Server",
    inBoundary=cloud,
)

llm_api = LLM(
    "GPT-4 API",
    inBoundary=cloud,
    isThirdParty=True,
    processesUntrustedInput=True,
    processesPersonalData=True,
    hasContentFiltering=False,
    hasSystemPrompt=True,
    hasRAG=True,
)

llm_agent = LLM(
    "Support Agent",
    inBoundary=cloud,
    isThirdParty=True,
    processesUntrustedInput=True,
    hasAgentCapabilities=True,
    hasAccessToSensitiveSystems=True,
    executesCode=False,
    hasContentFiltering=True,
)

local_model = LLM(
    "Local Classifier",
    inBoundary=internal,
    isThirdParty=False,
    isSelfHosted=True,
    processesUntrustedInput=False,
    hasFineTuning=True,
    hasContentFiltering=False,
)

db = Datastore("User DB", inBoundary=internal)

# Dataflows
Dataflow(user, web_server, "User prompt")
Dataflow(web_server, llm_api, "Chat request")
Dataflow(llm_api, web_server, "Chat response")
Dataflow(web_server, llm_agent, "Support query")
Dataflow(llm_agent, db, "DB lookup")
Dataflow(web_server, local_model, "Classify request")
Dataflow(local_model, web_server, "Classification result")

tm.process()
