## System Description

{tm.description}

## Dataflows

|:----:|:----:|:---:|:----:|:--------:|:----:|
{dataflows:repeat:|{{item.name}}|{{item.source.name}}|{{item.sink.name}}|{{item.data}}|{{item.protocol}}|{{item.dstPort}}|
}

## Data Dictionary

|:----:|:--------:|:----:|
{data:repeat:|{{item.name}}|{{item.description}}|{{item.classification.name}}|
}

## Potential Threats

{findings:repeat:

  * **{{item.id}}**  {{item.description}}
    * Target: {{item.target}}
    * Severity: {{item.severity}}
    * Example Instances: {{item.example}}
    * Mitigations: {{item.mitigations}}
    * References: {{item.references}}
}
