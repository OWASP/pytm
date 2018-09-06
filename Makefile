all: tm report

tm:
	mkdir -p tm

dfd:
	./tm.py --dfd | dot -Tpng -o dfd.png

seq:
	./tm.py --seq | java -Djava.awt.headless=true -jar ./plantuml.jar -tpng -pipe > seq.png

report: tm dfd seq
	./tm.py --report docs/template_test.md > tm/report.md

.PHONY: tm
