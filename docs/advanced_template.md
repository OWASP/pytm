<link href="docs/Stylesheet.css" rel="stylesheet"></link>

## System Description

{tm.description}

## Dataflow Diagram - Level 0 DFD

![](sample.png)

&nbsp;

## Dataflows

Name|From|To |Data|Protocol|Port
|:----:|:----:|:---:|:----:|:--------:|:----:|
{dataflows:repeat:|{{item.display_name:call:}}|{{item.source.name}}|{{item.sink.name}}|{{item.data}}|{{item.protocol}}|{{item.dstPort}}|
}

## Data Dictionary

Name|Description|Classification|Carried|Processed
|:----:|:--------:|:----:|:----|:----|
{data:repeat:|{{item.name}}|{{item.description}}|{{item.classification.name}}|{{item.carriedBy:repeat:{{{{item.name}}}}<br>}}|{{item.processedBy:repeat:{{{{item.name}}}}<br>}}|
}

## Actors

{actors:repeat:
Name|{{item.name}}
|:----|:----|
Description|{{item.description}}|
Is Admin|{{item.isAdmin}}|
Finding Count|{{item:call:getFindingCount}}|

{{item:call:getInScopeFindings:
**Threats**

<details>
  <summary>
   {{item:call:getThreatId}} — {{item:call:getFindingDescription}}
  </summary>

  <h6> Targeted Element </h6>
  <p>{{item:call:getFindingTarget}}</p>
  <h6> Severity </h6>
  <p>{{item:call:getFindingSeverity}}</p>
  <h6>Example Instances</h6>
  <p>{{item:call:getFindingExample}}</p>
  <h6>Mitigations</h6>
  <p>{{item:call:getFindingMitigations}}</p>
  <h6>References</h6>
  <p>{{item:call:getFindingReferences}}</p>
  &emsp;
</details>
}}
}

## Boundaries

{boundaries:repeat:
Name|{{item.name}}
|:----|:----|
Description|{{item.description}}|
In Scope|{{item.inScope}}|
Immediate Parent|{{item.parents:if:{{item:call:getParentName}}}}{{item.parents:not:N/A, primary boundary}}|
All Parents|{{item.parents:call:{{{{item.display_name:call:}}}}, }}|
Classification|{{item.maxClassification}}|
Finding Count|{{item:call:getFindingCount}}|

{{item:call:getInScopeFindings:
**Threats**

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
</details>
}}
}


## Assets

{assets:repeat:
Name|{{item.name}}|
|:----|:----|
Description|{{item.description}}|
In Scope|{{item.inScope}}|
Type|{{item:call:getElementType}}|
Finding Count|{{item:call:getFindingCount}}|

{{item:call:getInScopeFindings:
**Threats**

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
</details>
}}
}


## Data Flows

{dataflows:repeat:
Name|{{item.name}}
|:----|:----|
Description|{{item.description}}|
Sink|{{item.sink}}|
Source|{{item.source}}|
Is Response|{{item.isResponse}}|
In Scope|{{item.inScope}}|
Finding Count|{{item:call:getFindingCount}}|

{{item:call:getInScopeFindings:
**Threats**

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
</details>
}}
}


{tm.excluded_findings:if:
# Excluded Threats
}

{tm.excluded_findings:repeat:
<details>
  <summary>
    {{item:call:getThreatId}} — {{item:call:getFindingDescription}}
  </summary>
  <p>
    <b>{{item:call:getThreatId}}</b> was excluded for
    <b>{{item:call:getFindingTarget}}</b>
    because of the assumption "{{item.assumption.name}}"
  </p>
  {{item.assumption.description:if:
  <h6>Assumption description</h6>
  <p>{{item.assumption.description}}</p>
  }}
  <h6>Severity</h6>
  <p>{{item:call:getFindingSeverity}}</p>
  <h6>Example Instances</h6>
  <p>{{item:call:getFindingExample}}</p>
  <h6>References</h6>
  <p>{{item:call:getFindingReferences}}</p>
</details>
}
