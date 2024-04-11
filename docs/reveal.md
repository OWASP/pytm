# {tm.name}

---

## System Description 

{tm.description}

---

## Dataflow Diagram 

![](sample.png)

---

## Dataflows

----

{dataflows:repeat:

- **name**     : {{item.display_name:call:}}
- **from**     : {{item.source.name}}
- **to**       : {{item.sink.name}}:{{item.dstPort}}
- **data**     : {{item.data}}
- **protocol** : {{item.protocol}}

----
}

---

## Data Dictionary

----

{data:repeat:

- **name** : {{item.name}}
- **description** : {{item.description}}
- **classification** : {{item.classification.name}}
- **carried by** : {{item.carriedBy:repeat:{{{{item.name}}}}<br>}}
- **processed by** : {{item.processedBy:repeat:{{{{item.name}}}}<br>}}

----
}


---

## Actors

----

{actors:repeat:
- **name** : {{item.name}}
- **description** : {{item.description}}
- **is Admin** : {{item.isAdmin}}
- **# of findings** : {{item:call:getFindingCount}}

{{item.findings:not:
---
}}

{{item.findings:if:
----
**Findings**

----

{{item.findings:repeat:
  <summary>{{{{item.id}}}}  --   {{{{item.description}}}}</summary>

  - **Targeted Element** : {{{{item.target}}}}    
  - **Severity** : {{{{item.severity}}}}    
  - **References** : {{{{item.references}}}}   

----

}}
}}
}

## Trust Boundaries 

----

{boundaries:repeat:
- **name** : {{item.name}}
- **description** : {{item.description}}
- **in scope** : {{item.inScope}}
- **immediate parent** : {{item.parents:if:{{item:call:getParentName}}}}{{item.parents:not:N/A, primary boundary}}
- **all parents** : {{item.parents:call:{{{{item.display_name:call:}}}}, }}
- **classification** : {{item.maxClassification}}
- **finding count** : {{item:call:getFindingCount}}

{{item.findings:not:
---
}}

{{item.findings:if:
----
**Findings**

----

{{item.findings:repeat:
  <summary>{{{{item.id}}}} - {{{{item.description}}}}</summary>

  - **Targeted Element** : {{{{item.target}}}}    
  - **Severity** : {{{{item.severity}}}}    
  - **References** : {{{{item.references}}}}   
----

}}
}}
}

## Assets 

{assets:repeat:

- **name** : {{item.name}}
- **description** : {{item.description}}
- **in scope** : {{item.inScope}}
- **type** : {{item:call:getElementType}}
- **# of findings** : {{item:call:getFindingCount}}

{{item.findings:not:
---
}}

{{item.findings:if:
----
**Findings**

----

{{item.findings:repeat:
  <summary>{{{{item.id}}}} - {{{{item.description}}}}</summary>

  - **Targeted Element** : {{{{item.target}}}}    
  - **Severity** : {{{{item.severity}}}}    
  - **References** : {{{{item.references}}}}   
----

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

{{item.findings:not:
---
}}

{{item.findings:if:
----
**Findings**

----

{{item.findings:repeat:
  <summary>{{{{item.id}}}} - {{{{item.description}}}}</summary>

  - **Targeted Element** : {{{{item.target}}}}    
  - **Severity** : {{{{item.severity}}}}    
  - **References** : {{{{item.references}}}}   
----

}}
}}
}

