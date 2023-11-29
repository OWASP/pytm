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

MODEL?=tm

libs := $(wildcard pytm/*.py) $(wildcard pytm/threatlib/*.json) $(wildcard pytm/images/*)

all: clean docs/pytm/index.html $(MODEL)

safe_filename:
ifeq ($(suffix $(MODEL)), .py)
	@echo "I think you mean MODEL=$(patsubst .py,,$(MODEL))"
	exit 1
endif


docs/pytm/index.html: $(wildcard pytm/*.py)
	PYTHONPATH=. pdoc --html --force --output-dir docs pytm

docs/threats.md: $(wildcard pytm/threatlib/*.json)
	printf "# Threat database\n" > $@
	jq -r ".[] | \"$$(cat docs/threats.jq)\"" $< >> $@

clean: safe_filename
	rm -rf dist/* build/* $(MODEL)

$(MODEL): safe_filename
	mkdir -p $(MODEL)
	$(MAKE) MODEL=$(MODEL) report

$(MODEL)/dfd.png: $(MODEL).py $(libs)
	./$< --dfd | dot -Tpng -o $@

$(MODEL)/seq.png: $(MODEL).py $(libs)
	./$< --seq | java -Djava.awt.headless=true -jar $$PLANTUML_PATH -tpng -pipe > $@

$(MODEL)/report.html: $(MODEL).py $(libs) docs/basic_template.md docs/Stylesheet.css
	./$< --report docs/basic_template.md | pandoc -f markdown -t html > $@

dfd: $(MODEL)/dfd.png

seq: $(MODEL)/seq.png

report: $(MODEL)/report.html seq dfd

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
