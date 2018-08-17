all: tm report

tm:
	mkdir -p tm

dfd.png: tm.py
	./tm.py --dfd > tm/dfd.png

seq.png: tm.py
	./tm.py --seq > tm/seq.png

report: tm.py dfd.png seq.png
	./tm.py --report docs/template_test.md > tm/report.md

.PHONY: tm
