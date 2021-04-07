# shamelessly lifted from https://makina-corpus.com/blog/metier/2016/the-worlds-simplest-python-template-engine

import string


class SuperFormatter(string.Formatter):
    """World's simplest Template engine."""

    def format_field(self, value, spec):
        if spec.startswith("repeat"):
            template = spec.partition(":")[-1]
            if type(value) is dict:
                value = value.items()
            return "".join([self.format(template, item=item) for item in value])
        elif spec.startswith("call"):
            result = value()
            if type(result) is list:
                template = spec.partition(":")[-1]
                return "".join([self.format(template, item=item) for item in result])

            return result
        elif spec.startswith("utils"):

            spec_parts = spec.split(":")

            method_name = spec_parts[1]
            template = spec_parts[-1]

            module_name = "pytm.report_util"
            klass_name = "ReportUtils"
            module = __import__(module_name, fromlist=['ReportUtils'])
            klass = getattr(module, klass_name)

            method = getattr(klass, method_name)
            result = method(value)

            if type(result) is list:
                return "".join([self.format(template, item=item) for item in result])
            
            return result

        elif spec.startswith("if"):
            return (value and spec.partition(":")[-1]) or ""
        else:
            return super(SuperFormatter, self).format_field(value, spec)
