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
all: clean
all: $(models:.py=/report.html) $(models:.py=/dfd.png) $(models:.py=/seq.png) docs/pytm/index.html

docs/pytm/index.html: $(wildcard pytm/*.py)
	PYTHONPATH=. pdoc --html --force --output-dir docs pytm

docs/threats.md: $(wildcard pytm/threatlib/*.json)
	printf "# Threat database\n" > $@
	jq -r ".[] | \"$$(cat docs/threats.jq)\"" $< >> $@

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

.PHONY: test
test:
	@python3 -m unittest

.PHONY: describe
describe:
	./tm.py --describe "TM Element Boundary ExternalEntity Actor Lambda Server Process SetOfProcesses Datastore Dataflow"

.PHONY: image
image:
	docker build -t $(DOCKER_IMG) .

.PHONY: docs
docs: docs/pytm/index.html docs/threats.md

.PHONY: fmt
fmt:
	black  $(wildcard pytm/*.py) $(wildcard tests/*.py) $(wildcard *.py)
