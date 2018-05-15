# pytm

A Pythonistic framework for threat modeling

For the security practitioner: add threats to the threat object

For the developer: define your system in code as a collection of objects and annotate them with properties, then call out TM.resolve() to identify threats and TM.report() to write out the report.

Report comes out in Markdown with diagrams using Dataflow (https://github.com/sonyxperiadev/dataflow). Source files are output, Dataflow is not expected to be installed or ran in lieu of the user.

