#!/usr/bin/env python3

import sys
sys.path.insert(0, '..')

from pytm.pytm import TM, Element,SetOfProcesses, Process, Server, Datastore, Dataflow, Boundary, Actor

tm = TM("CHANGE ME")
tm.description = "CHANGE ME"

user = Actor("user")
server = Server("server")
database = Datastore("database")
configs = Datastore("configs")
logs = Datastore("logs")
user_to_server = Dataflow(user, server, 'CHANGE ME')
server_to_database = Dataflow(server, database, 'CHANGE ME')
database_to_server = Dataflow(database, server, 'CHANGE ME')
configs_to_server = Dataflow(configs, server, 'CHANGE ME')
server_to_logs = Dataflow(server, logs, 'CHANGE ME')

tm.process()

