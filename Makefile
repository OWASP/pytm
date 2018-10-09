PREV:=$(shell grep version= setup.py | gsed -E -e "s/\s*version='([0-9]*.[0-9]*)',/\1/")
NEXT:=$(shell echo $(PREV)+0.1 | /usr/bin/bc | gsed -E -e "s/^\./0\./")
DEPLOYURL=https://test.pypi.org/legacy/

all: build tm report
	echo foo
tm:
	mkdir -p tm

dfd:
	./tm.py --dfd | dot -Tpng -o dfd.png

seq:
	./tm.py --seq | java -Djava.awt.headless=true -jar ./plantuml.jar -tpng -pipe > seq.png

report: tm dfd seq
	./tm.py --report docs/template_test.md > tm/report.md

build: pytm/pytm.py
	cat setup.py | sed -e "s/'$(PREV)'/'$(NEXT)'/" > newver.py
	mv newver.py setup.py
	rm -rf dist/*
	python3 setup.py sdist bdist_wheel
	twine upload --repository-url $(DEPLOYURL) dist/*

.PHONY: tm
