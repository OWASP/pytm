"""Print docs/threats.md, the list of built-in threats, to stdout."""

from pytm.threatlib import BUILTIN_THREATS

TEMPLATE = """## {id} {description}

{details}

<dl>
  <dt>Severity</dt>
  <dd>{severity}</dd>

  <dt>Prerequisites</dt>
  <dd>{prerequisites}</dd>

  <dt>Example</dt>
  <dd>{example}</dd>

  <dt>Mitigations</dt>
  <dd>{mitigations}</dd>

  <dt>References</dt>
  <dd>{references}</dd>

  <dt>Condition</dt>
  <dd>{condition}</dd>
</dl>



"""

print("# Threat database")
for cls in BUILTIN_THREATS:
    threat = cls()
    print(TEMPLATE.format(**threat.model_dump()), end="")
