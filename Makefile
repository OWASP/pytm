UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        SED = /usr/bin/sed
    endif
    ifeq ($(UNAME_S),Darwin)
        SED = /usr/local/bin/gsed
    endif

PREV:=$(shell grep version= setup.py | $(SED) -E -e "s/\s*version='([0-9]*.[0-9]*)',/\1/")
NEXT:=$(shell echo $(PREV)+0.1 | /usr/bin/bc | $(SED) -E -e "s/^\./0\./")
#DEPLOYURL=--repository-url https://test.pypi.org/legacy/
DEPLOYURL=

all: clean build tm report

clean:
	rm -rf dist/* build/*

tm:
	mkdir -p tm

dfd:
	./tm.py --dfd | dot -Tpng -o tm/dfd.png

seq:
	./tm.py --seq | java -Djava.awt.headless=true -jar ./plantuml.jar -tpng -pipe > tm/seq.png

report: tm dfd seq
	./tm.py --report docs/template.md | pandoc -f markdown -t html > tm/report.html

build: setup.py
	#cat setup.py | sed -e "s/'$(PREV)'/'$(NEXT)'/" > newver.py
	#mv newver.py setup.py
	rm -rf dist build
	python3 setup.py sdist bdist_wheel
	twine upload $(DEPLOYURL) dist/*

.PHONY: tm
