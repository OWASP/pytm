""" Base class for all plugin types """


class BasePlugin():
    """ Base class for plugins """

    def __init__(self):
        raise NotImplementedError("Plugin needs an __init__ function")

    def get_name(self):
        return self.name