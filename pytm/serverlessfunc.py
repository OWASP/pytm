class ServerlessFunc(Asset):
    """A serverless function running in a Function-as-a-Service (FaaS) environment"""

    onAWS = varBool(True)
    environment = varString("")
    implementsAPI = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def _dfd_template(self):
        return """{uniq_name} [
    shape = {shape};

    color = {color};
    fontcolor = {color};
    label = <
        <table border="0" cellborder="0" cellpadding="2">
            <tr><td><b>{label}</b></td></tr>
        </table>
    >;
]
"""

    def dfd(self, **kwargs):
        self._is_drawn = True

        levels = kwargs.get("levels", None)
        if levels and not levels & self.levels:
            return ""

        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=self._color(),
            shape=self._shape(),
        )

    def _shape(self):
        return "rectangle; style=rounded"
