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


<br>
<br>

## Data Dictionary
&nbsp;

Name|Description|Classification|Carried|Processed
|:----:|:--------:|:----:|:----|:----|
|auth cookie||PUBLIC|User enters comments (*)<br>|User<br>Web Server<br>|


&nbsp;

## Actors
&nbsp;

Name|Description|isAdmin
|:----:|:--------:|:----:|
|User||False|


<br>
<br>

## Boundaries 


Element|Internet
|:----|:----|
Description||
InScope|True|
Parent||
Parents||
Classification|Classification.UNKNOWN|

<br>
<br>


Element|Server/DB
|:----|:----|
Description||
InScope|True|
Parent||
Parents||
Classification|Classification.UNKNOWN|

<br>
<br>



## Assets 



<br>
<hr>

Element|Web Server
|:----|:----|
Description||
InScope|True|
Type|Server|
Finding Count|0|

###### Threats 




<br>
<hr>

Element|Lambda func
|:----|:----|
Description||
InScope|True|
Type|Lambda|
Finding Count|0|

###### Threats 




<br>
<hr>

Element|Task queue worker
|:----|:----|
Description||
InScope|True|
Type|Process|
Finding Count|0|

###### Threats 




<br>
<hr>

Element|SQL Database
|:----|:----|
Description||
InScope|True|
Type|Datastore|
Finding Count|0|

###### Threats 




<br>
<br>

## Data Flows 



<br>
<hr>

Dataflow|User enters comments (*)
|:----|:----|
Description||
InScope|True|
Finding Count|0|

###### Threats 





<br>
<hr>

Dataflow|Insert query with comments
|:----|:----|
Description||
InScope|True|
Finding Count|0|

###### Threats 





<br>
<hr>

Dataflow|Call func
|:----|:----|
Description||
InScope|True|
Finding Count|0|

###### Threats 





<br>
<hr>

Dataflow|Retrieve comments
|:----|:----|
Description||
InScope|True|
Finding Count|0|

###### Threats 





<br>
<hr>

Dataflow|Show comments (*)
|:----|:----|
Description||
InScope|True|
Finding Count|0|

###### Threats 





<br>
<hr>

Dataflow|Query for tasks
|:----|:----|
Description||
InScope|True|
Finding Count|0|

###### Threats 





&nbsp;
