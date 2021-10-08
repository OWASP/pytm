from pytm import (
    Datastore,
    Boundary,
    Server,
)

internet = Boundary("Internet")
server_db = Boundary("Server/DB")
db = Datastore("SQL Database", inBoundary=server_db)
web = Server("Web Server")
