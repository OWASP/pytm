UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    SED = sed
endif
ifeq ($(UNAME_S),Darwin)
    SED = gsed
endif

PREV:=$(shell grep version= setup.py | $(SED) -E -e "s/\s*version='([0-9]*.[0-9]*)',/\1/")
NEXT:=$(shell echo $(PREV)+0.1 | /usr/bin/bc | $(SED) -E -e "s/^\./0\./")
#DEPLOYURL=--repository-url https://test.pypi.org/legacy/
DEPLOYURL=

MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CWD := $(patsubst %/,%,$(dir $(MKFILE_PATH)))
DOCKER_IMG := pytm

ifeq ($(USE_DOCKER),true)
	SHELL=docker
	.SHELLFLAGS=run -u $$(id -u) -v $(CWD):/usr/src/app --rm $(DOCKER_IMG):latest -c
endif
ifndef PLANTUML_PATH
	export PLANTUML_PATH = ./plantuml.jar
endif

models := tm.py
libs := $(wildcard pytm/*.py) $(wildcard pytm/threatlib/*.json) $(wildcard pytm/images/*)
all: clean build
all: $(models:.py=/report.html) $(models:.py=/dfd.png) $(models:.py=/seq.png)

clean:
	rm -rf dist/* build/* $(models:.py=/*)

tm:
	mkdir -p tm

%/dfd.png: %.py tm $(libs)
	./$< --dfd | dot -Tpng -o $@

%/seq.png: %.py tm $(libs)
	./$< --seq | java -Djava.awt.headless=true -jar $$PLANTUML_PATH -tpng -pipe > $@

%/report.html: %.py tm $(libs) docs/template.md docs/Stylesheet.css
	./$< --report docs/template.md | pandoc -f markdown -t html > $@

dfd: $(models:.py=/dfd.png)

seq: $(models:.py=/seq.png)

report: $(models:.py=/report.html) seq dfd

build: setup.py
	#cat setup.py | sed -e "s/'$(PREV)'/'$(NEXT)'/" > newver.py
	#mv newver.py setup.py
	rm -rf dist build
	python3 setup.py sdist bdist_wheel
	twine upload $(DEPLOYURL) dist/*

.PHONY: describe
describe:
	for i in TM Element Server ExternalEntity Datastore Actor Process SetOfProcesses Dataflow Boundary Lambda Finding; do ./tm.py --describe $$i; done

.PHONY: image
image:
	docker build -t $(DOCKER_IMG) .
