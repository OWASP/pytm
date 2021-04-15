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

        elif spec.startswith("call:") and hasattr(value, "__call__"):
           # Example usage, format, exampple format
           # methood:call                                {item:call:getParentName}
           # methood:call:template                       {item.parents:call:{{item.name}}, }
            result = value()

            if type(result) is list:
                template = spec.partition(":")[-1]
                return "".join([self.format(template, item=item) for item in result])

            return result

        elif spec.startswith("call:"):
           # Example usage, format, exampple format
           # object:call:method_name                     {item:call:getFindingCount}
           # object:call:method_name:template            {item:call:getNamesOfParents:
           #                                             **{{item}}**
           #                                             }

            method_name = spec_parts[1]
            template = spec.partition(":")[-1]

            result = self.call_util_method(method_name, value)

            if type(result) is list:
                return "".join([self.format(template, item=item) for item in result])

            return result

        elif (spec.startswith("if") or spec.startswith("not")):
           # Example usage, format, exampple format
           # object.bool:if:template                     {item.inScope:if:<p>Is in scope.</p>}
           # object:if:template                          {item.findings:if:<p>Has Findings</p>}
           # object.method:if:template                   {item.parents:if:<p>Has Parents</p>}
           #
           # object.bool:not:template                     {item.inScope:not:<p>Is not in scope.</p>}
           # object:not:template                          {item.findings:not:<p>Has No Findings</p>}
           # object.method:not:template                   {item.parents:not:<p>Has No Parents</p>}
 
            template = spec.partition(":")[-1]
            if (hasattr(value, "__call__")):
                result = value()
            else:
                result = value

            if (spec.startswith("if")):
                return (result and template or "")
            else: 
                return (not result and template or "")

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
