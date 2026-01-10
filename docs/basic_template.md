<link href="docs/Stylesheet.css" rel="stylesheet"></link>

## System Description
&nbsp;

{tm.description}

&nbsp;

{tm.assumptions:if:

|Assumptions|
|-----------|
{tm.assumptions:repeat:|{{item}}| 
}

&nbsp;
&nbsp;
&nbsp;
}


## Dataflow Diagram - Level 0 DFD

![](sample.png)

&nbsp;

## Dataflows
&nbsp;

Name|From|To |Data|Protocol|Port
|:----:|:----:|:---:|:----:|:--------:|:----:|
{dataflows:repeat:|{{item.name}}|{{item.source.name}}|{{item.sink.name}}|{{item.data}}|{{item.protocol}}|{{item.dstPort}}|
}

## Data Dictionary
&nbsp;

Name|Description|Classification
|:----:|:--------:|:----:|
{data:repeat:|{{item.name}}|{{item.description}}|{{item.classification.name}}|
}

&nbsp;

## Potential Threats
&nbsp;
&nbsp;

{findings:repeat:
<details>
  <summary>
    {{item:call:getThreatId}} — {{item:call:getFindingDescription}}
  </summary>

  <h6>Targeted Element</h6>
  <p>{{item:call:getFindingTarget}}</p>

  <h6>Severity</h6>
  <p>{{item:call:getFindingSeverity}}</p>

  <h6>Example Instances</h6>
  <p>{{item:call:getFindingExample}}</p>

  <h6>Mitigations</h6>
  <p>{{item:call:getFindingMitigations}}</p>

  <h6>References</h6>
  <p>{{item:call:getFindingReferences}}</p>

  &nbsp;
</details>
}

