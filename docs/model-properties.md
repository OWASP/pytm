# Model properties and threat conditions

Threat conditions inspect properties of a model element (`target`) and its
security controls (`target.controls`). Set these properties to describe the
system you are modeling. A condition that evaluates to `True` creates a
finding; the property name alone does not prove that a control is present or
absent in a real system.

The [threats database section](../README.md#threats-database) explains the
condition syntax. `python tm.py --describe Server` lists the available Server
properties and their defaults. Use `python tm.py --describe Controls` for
control properties, their descriptions, and their defaults. These descriptions
are maintained on the fields in [`Controls`](../pytm/base.py).

`element.sourceFiles` lists paths to source files represented by the element,
relative to the model script's directory. The `--stale` check uses these paths
to compare source file and model timestamps; they are not input to the bundled
threat conditions.

For example, a server that validates input but does not enforce input length
limits can be modeled as:

```python
from pytm import Server

api = Server("API")
api.controls.validatesInput = True
api.controls.checksInputBounds = False
api.sourceFiles = ["src/api.py"]
```

In that model, a condition such as
`target.controls.checksInputBounds is False` still matches the server.
Validation of allowed values and checking length bounds are represented by
different controls. Only set a flag to `True` when the corresponding control
applies to the element being modeled; the built-in control flags default to
`False`.
