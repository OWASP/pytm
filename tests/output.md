<link href="docs/Stylesheet.css" rel="stylesheet"></link>

## System Description

aaa

## Dataflow Diagram - Level 0 DFD

![](sample.png)

&nbsp;

## Dataflows

Name|From|To |Data|Protocol|Port
|:----:|:----:|:---:|:----:|:--------:|:----:|
|User enters comments (*)|User|Web Server|auth cookie||-1|
|Insert query with comments|Web Server|SQL Database|[]||-1|
|Call func|Web Server|Lambda func|[]||-1|
|Retrieve comments|SQL Database|Web Server|[]||-1|
|Show comments (*)|Web Server|User|[]||-1|
|Query for tasks|Task queue worker|SQL Database|[]||-1|


## Data Dictionary

Name|Description|Classification|Carried|Processed
|:----:|:--------:|:----:|:----|:----|
|auth cookie||PUBLIC|User enters comments (*)<br>|User<br>Web Server<br>|


## Actors


Name|User
|:----|:----|
Description||
Is Admin|False
Finding Count|0|




## Boundaries 


Name|Internet
|:----|:----|
Description||
In Scope|True|
Immediate Parent|Primary Boundary|
All Parents||
Classification|Classification.UNKNOWN|
Finding Count|0|



Name|Server/DB
|:----|:----|
Description||
In Scope|True|
Immediate Parent|Primary Boundary|
All Parents||
Classification|Classification.UNKNOWN|
Finding Count|0|




## Assets 


|Name|Web Server|
|:----|:----|
Description||
In Scope|True|
Type|Server|
Finding Count|0|



|Name|Lambda func|
|:----|:----|
Description||
In Scope|True|
Type|Lambda|
Finding Count|0|



|Name|Task queue worker|
|:----|:----|
Description||
In Scope|True|
Type|Process|
Finding Count|0|



|Name|SQL Database|
|:----|:----|
Description||
In Scope|True|
Type|Datastore|
Finding Count|0|




## Data Flows 


Name|User enters comments (*)
|:----|:----|
Description||
Sink|Server(Web Server)|
Source|Actor(User)|
|Is Response|False
In Scope|True|
Finding Count|0|



Name|Insert query with comments
|:----|:----|
Description||
Sink|Datastore(SQL Database)|
Source|Server(Web Server)|
|Is Response|False
In Scope|True|
Finding Count|0|



Name|Call func
|:----|:----|
Description||
Sink|Lambda(Lambda func)|
Source|Server(Web Server)|
|Is Response|False
In Scope|True|
Finding Count|0|



Name|Retrieve comments
|:----|:----|
Description||
Sink|Server(Web Server)|
Source|Datastore(SQL Database)|
|Is Response|False
In Scope|True|
Finding Count|0|



Name|Show comments (*)
|:----|:----|
Description||
Sink|Actor(User)|
Source|Server(Web Server)|
|Is Response|False
In Scope|True|
Finding Count|0|



Name|Query for tasks
|:----|:----|
Description||
Sink|Datastore(SQL Database)|
Source|Process(Task queue worker)|
|Is Response|False
In Scope|True|
Finding Count|0|



