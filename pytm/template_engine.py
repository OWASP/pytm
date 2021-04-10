# shamelessly lifted from https://makina-corpus.com/blog/metier/2016/the-worlds-simplest-python-template-engine
# but modified to include support to call methods which return lists, to call external utility methods, use
# if operator with methods and added a not operator.

import string


class SuperFormatter(string.Formatter):
    """World's simplest Template engine."""

    def format_field(self, value, spec):
        spec_parts = spec.split(":")
        if spec.startswith("repeat"):
           # Example usage, format, count of spec_parts, exampple format
           # object:repeat:template           2          {item.findings:repeat:{{item.id}}, }

            template = spec.partition(":")[-1]
            if type(value) is dict:
                value = value.items()
            return "".join([self.format(template, item=item) for item in value])

        elif spec.startswith("call"):
           # Example usage, format, count of spec_parts, exampple format
           # methood:call                     1          {item:call:getParentName}
           # methood:call:template            2          {item.parents:call:{{item.name}}, }
           # object:call:method_name          2          {item:call:getFindingCount}
           # object:call:method_name:template 3          {item:call:getNamesOfParents:
           #                                             **{{item}}**
           #                                             }

            if (hasattr(value, "__call__")):

                result = value()
                if type(result) is list:
                    template = spec.partition(":")[-1]
                    return "".join([self.format(template, item=item) for item in result])

                return result

            else:

                method_name = spec_parts[1]
                template = spec_parts[-1]

                result = self.call_util_method(method_name, value)

                if type(result) is list:
                    return "".join([self.format(template, item=item) for item in result])

                return result

            return "ERROR using call operator"

        elif (spec.startswith("if") or spec.startswith("not")):
           # Example usage, format, count of spec_parts, exampple format
           # object.boolean:if:template       2       {item.isResponse:if:True}
           # method:if:method_name:template   3       {item.parents:if:Has a parent}
           # object:if:method_name:template   3       {item:if:getNamesOfParents:
           #                                          **{{item}}**
           #                                          }
           # object.boolean:not:template       2       {item.isResponse:not:False}
           # method:not:method_name:template   3       {item.parents:not:Does not have a parents}
           # object:not:method_name:template   3       {item:not:getNamesOfParents:
           #                                          **{{item}}**
           #                                          }

            if (hasattr(value, "__call__")):
                result = value()
            elif(len(spec_parts) == 3):
                method_name = spec_parts[1]
                result = self.call_util_method(method_name, value)
            else:
                result = value

            if (spec.startswith("if")):
                return (result and spec_parts[-1]) or ""
            else: 
                return (not result and spec_parts[-1]) or ""

        else:
            return super(SuperFormatter, self).format_field(value, spec)

    def call_util_method(self, method_name, object):
        module_name = "pytm.report_util"
        klass_name = "ReportUtils"
        module = __import__(module_name, fromlist=['ReportUtils'])
        klass = getattr(module, klass_name)
        method = getattr(klass, method_name)

        result = method(object)
        return result
