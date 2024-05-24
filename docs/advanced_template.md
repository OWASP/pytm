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
Is Admin|{{item.isAdmin}}
Finding Count|{{item:call:getFindingCount}}|

{{item.findings:if:

**Threats**

{{item.findings:repeat:
<details>
  <summary>   {{{{item.id}}}}  --  {{{{item.threat_id}}}}   --   {{{{item.description}}}}</summary>
  <h6> Targeted Element </h6>
  <p> {{{{item.target}}}} </p>
  <h6> Severity </h6>
  <p>{{{{item.severity}}}}</p>
  <h6>Example Instances</h6>
  <p>{{{{item.example}}}}</p>
  <h6>Mitigations</h6>
  <p>{{{{item.mitigations}}}}</p>
  <h6>References</h6>
  <p>{{{{item.references}}}}</p>
  &emsp;
</details>
}}
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

{{item.findings:if:

**Threats**

{{item.findings:repeat:
<details>
  <summary>   {{{{item.id}}}}  --  {{{{item.threat_id}}}}   --   {{{{item.description}}}}</summary>
  <h6> Targeted Element </h6>
  <p> {{{{item.target}}}} </p>
  <h6> Severity </h6>
  <p>{{{{item.severity}}}}</p>
  <h6>Example Instances</h6>
  <p>{{{{item.example}}}}</p>
  <h6>Mitigations</h6>
  <p>{{{{item.mitigations}}}}</p>
  <h6>References</h6>
  <p>{{{{item.references}}}}</p>
  &emsp;
</details>
}}
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

{{item.findings:if:

**Threats**

{{item.findings:repeat:
<details>
  <summary>   {{{{item.id}}}}  --  {{{{item.threat_id}}}}   --   {{{{item.description}}}}</summary>
  <h6> Targeted Element </h6>
  <p> {{{{item.target}}}} </p>
  <h6> Severity </h6>
  <p>{{{{item.severity}}}}</p>
  <h6>Example Instances</h6>
  <p>{{{{item.example}}}}</p>
  <h6>Mitigations</h6>
  <p>{{{{item.mitigations}}}}</p>
  <h6>References</h6>
  <p>{{{{item.references}}}}</p>
  &nbsp;
</details>
}}
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

{{item.findings:if:

**Threats**

{{item.findings:repeat:
<details>
  <summary>   {{{{item.id}}}}  --  {{{{item.threat_id}}}}   --   {{{{item.description}}}}</summary>
  <h6> Targeted Element </h6>
  <p> {{{{item.target}}}} </p>
  <h6> Severity </h6>
  <p>{{{{item.severity}}}}</p>
  <h6>Example Instances</h6>
  <p>{{{{item.example}}}}</p>
  <h6>Mitigations</h6>
  <p>{{{{item.mitigations}}}}</p>
  <h6>References</h6>
  <p>{{{{item.references}}}}</p>
  &emsp;
</details>
}}
}}
}

{tm.excluded_findings:if:
# Excluded Threats
}

{tm.excluded_findings:repeat:
<details>
  <summary>  {{item.id}}  --  {{item.threat_id}}   --   {{item.description}}</summary>
  <p>**{{item.threat_id}}** was excluded for **{{item.target}}** because of the assumption: "{{item.assumption.name}}
"</p>
  {{item.assumption.description:if:
    <h6> Assumption description </h6>
    <p> {{item.assumption.description}} </p>  
  }}

  <h6> Targeted Element </h6>
  <p> {{item.target}} </p>
  <h6> Severity </h6>
  <p>{{item.severity}}</p>
  <h6>Example Instances</h6>
  <p>{{item.example}}</p>
  <h6>References</h6>
  <p>{{item.references}}</p>
</details>
}
