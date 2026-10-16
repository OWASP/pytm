# Model properties and threat conditions

Threat conditions inspect properties of a model element (`target`) and its
security controls (`target.controls`). Set these properties to describe the
system you are modeling. A condition that evaluates to `True` creates a
finding; the property name alone does not prove that a control is present or
absent in a real system.

The [threats database section](../README.md#threats-database) explains the
condition syntax. `python tm.py --describe Server` lists the available Server
properties and their defaults. The control properties live in
[`Controls`](../pytm/base.py), which is not a standalone `--describe` class.

| Property | What to record |
| --- | --- |
| `element.controls.checksInputBounds` | Set to `True` when the element enforces size or range limits on the input it processes. The bundled buffer overflow rules check this flag; it is more specific than general input validation. |
| `element.controls.validatesInput` | Set to `True` when the element checks input against its expected format or allowed values. Several injection rules inspect this flag. |
| `element.controls.sanitizesInput` | Set to `True` when the element cleans or rejects unsafe content in input. This is a separate flag from `validatesInput` in the bundled rules. |
| `element.controls.usesStrongSessionIdentifiers` | Set to `True` when session identifiers are hard to predict or guess. The bundled session ID threat checks this flag alongside source authentication and integrity. |
| `element.controls.authenticatesSource` | Set to `True` when the element verifies the identity of the source of an interaction. For a `Dataflow`, this describes the flow's source authentication control; it does not by itself assert that the source is authorized. |
| `element.controls.authorizesSource` | Set to `True` when the element checks whether the source is allowed to perform the interaction. The bundled access control rules distinguish this from authentication. |
| `element.sourceFiles` | Paths to source files represented by this element, relative to the model script's directory. The `--stale` check uses these paths to compare source file and model timestamps; they are not input to the bundled threat conditions. |

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
