<link href="docs/Stylesheet.css" rel="stylesheet"></link>

## System Description
&nbsp;

{tm.description}

&nbsp;

## Dataflow Diagram - Level 0 DFD

![](sample.png)

&nbsp;

## Dataflows
&nbsp;

Name|From|To |Data|Protocol|Port
|:----:|:----:|:---:|:----:|:--------:|:----:|
{dataflows:repeat:|{{item.name}}|{{item.source.name}}|{{item.sink.name}}|{{item.data}}|{{item.protocol}}|{{item.dstPort}}|
}

<br>
<br>

## Data Dictionary
&nbsp;

Name|Description|Classification|Carried|Processed
|:----:|:--------:|:----:|:----|:----|
{data:repeat:|{{item.name}}|{{item.description}}|{{item.classification.name}}|{{item.carriedBy:repeat:{{{{item.name}}}}<br>}}|{{item.processedBy:repeat:{{{{item.name}}}}<br>}}|
}

&nbsp;

## Actors
&nbsp;

Name|Description|isAdmin
|:----:|:--------:|:----:|
{actors:repeat:|{{item.name}}|{{item.description}}|{{item.isAdmin}}|
}

<br>
<br>

## Boundaries 

{boundaries:repeat:
Element|{{item.name}}
|:----|:----|
Description|{{item.description}}|
InScope|{{item.inScope}}|
Parent|{{item:utils:getParentName}}|
Parents|{{item.parents:call:{{{{item.name}}}}, }}|
Classification|{{item.maxClassification}}|

<br>
<br>

}

## Assets 

{assets:repeat:

<br>
<hr>

Element|{{item.name}}
|:----|:----|
Description|{{item.description}}|
InScope|{{item.inScope}}|
Type|{{item.__class__.__name__}}|
Finding Count|{{item:utils:countFindings}}|

###### Threats 

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
  &nbsp;
  &emsp;
</details>
}}
}

<br>
<br>

## Data Flows 

{dataflows:repeat(e):

<br>
<hr>

Dataflow|{{item.name}}
|:----|:----|
Description|{{item.description}}|
InScope|{{item.inScope}}|
Finding Count|{{item:utils:countFindings}}|

###### Threats 

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
  &nbsp;
  &emsp;
</details>
}}

}

&nbsp;
