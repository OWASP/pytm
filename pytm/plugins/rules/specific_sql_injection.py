from pytm.plugins.base.rule_plugin import RulePlugin, RuleResult
from pytm import DatastoreType


class StrictSQLInjectionRulePlugin(RulePlugin):
    # Boilerplate
    name = "strict_sql_injection"
    description = "A strict SQL injection rule"

    SID = "EXP01"
    details = "A SQL datastore is connected to a web server which does not sanitize inputs. This web server can be accessed by an actor"
    LikelihoodOfAttack = "High"
    severity = "High"
    condition = "A SQL datastore is connected to a web server which does not sanitize inputs. This web server can be accessed by an actor"
    prerequisites = ""
    mitigations = "Sanitize input to protect the SQL server. Use PreparedStatements"
    example = ""
    reference_list = []
    target = []

    cwes = ["89", "1286"]
    capecs = ["66"]
    ttps = ["T1190"]

    def __init__(self):
        super().__init__()
        self.plugin_path = __file__

    def connected_elements(self, element):
            """ Lists all elements connected by Dataflows to this element """
            res = []

            for a_dataflow in self.get_elements():
                if self.get_type(a_dataflow) == "Dataflow":
                    if a_dataflow.source == element:
                          res.append(a_dataflow.sink)
                    if a_dataflow.sink == element:
                         res.append(a_dataflow.source)
            return res

    def threat_match(self):
        """ Specific SQL injection test. Extra specific to test the power of plugin rules.

            A SQL datastore is connected to a web server which does not sanitize inputs. This web server can be accessed by an actor .
        """
        for a_database in self.get_elements():
            if self.get_type(a_database) == "Datastore" and a_database.type == DatastoreType.SQL:
                servers_connected_to_database = self.connected_elements(a_database)
                for a_webserver in servers_connected_to_database:
                     # Is connected to a web server which does not sanitize input
                     if self.get_type(a_webserver) == "Server" and a_webserver.controls.sanitizesInput == False:
                        users_connected_to_server = self.connected_elements(a_webserver)
                        # Check all connections of this web server, is a user connected (="Actor")
                        for a_user in users_connected_to_server:
                             if self.get_type(a_user) == "Actor":
                                  self.add_threat(a_database, comment = f"The user '{a_user.name}' could run SQL injection attacks on '{a_database.name}' via '{a_webserver.name}'")





