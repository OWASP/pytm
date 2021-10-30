<link href="docs/Stylesheet.css" rel="stylesheet"></link>

## System Description
&nbsp;

aaa

&nbsp;




## Dataflow Diagram - Level 0 DFD

![](sample.png)

&nbsp;

## Dataflows
&nbsp;

Name|From|To |Data|Protocol|Port
|:----:|:----:|:---:|:----:|:--------:|:----:|
|User enters comments (*)|User|Web Server|auth cookie||-1|
|Insert query with comments|Web Server|SQL Database|[]||-1|
|Call func|Web Server|Lambda func|[]||-1|
|Retrieve comments|SQL Database|Web Server|[]||-1|
|Show comments (*)|Web Server|User|[]||-1|
|Query for tasks|Task queue worker|SQL Database|[]||-1|


## Data Dictionary
&nbsp;

Name|Description|Classification
|:----:|:--------:|:----:|
|auth cookie|auth cookie description|PUBLIC|


&nbsp;

## Potential Threats

&nbsp;
&nbsp;

||
