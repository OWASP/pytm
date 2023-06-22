from pytm.plugins.base.rule_plugin import RulePlugin, RuleResult


class ExampleRulePlugin(RulePlugin):
    # Boilerplate
    name = "example_rule_no_internet"
    description = "An example rule: We do not allow internet"

    SID = "EXP01"
    details = "This example attack is just detecting stuff on the internet (boundary)"
    LikelihoodOfAttack = "High"
    severity = "High"
    condition = ""
    prerequisites = "The application has an internet boundary. Everyone knows there are cat pics on the internet. "
    mitigations = "Do not expose yourself or the application to cat pics. Remove any internet boundary."
    example = "Can i haz Cheesburger ?"
    reference_list = ["https://www.youtube.com/watch?v=dQw4w9WgXcQ"]
    target = ["Boundary"]

    def __init__(self):
        super().__init__()
        self.plugin_path = __file__

    def threat_match(self):
        for e in self.get_elements():
            if self.get_type(e) == "Boundary" and e.name == "Internet":
                self.add_threat(e, "A comment on internet boundaries")