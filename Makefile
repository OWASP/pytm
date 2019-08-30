py = $(wildcard *.py)
png = $(py:.py=.png)
html = $(py:.py=.html)

all: clean tm report

%.png: %.py
	-docker-compose run --rm pytm /bin/sh "$< --dfd | dot -Tpng -o tm/$@"

%.html: %.py
	-docker-compose run --rm pytm /bin/sh -c "$< --report template.md | -f markdown -t html > tm/$@.html"

.PHONY: tm

clean:
	rm -rf tm/*

tm:
	mkdir -p tm

dfd:	
	-docker-compose run --rm pytm /bin/sh -c "python3 ./tm.py --dfd | dot -Tpng -o tm/dfd.png"
seq:
	-docker-compose run --rm pytm /bin/sh -c "python3 ./tm.py --seq | java -Djava.awt.headless=true -jar plantuml.jar -tpng -pipe > tm/seq.png"

report: tm dfd seq
	-docker-compose run --rm pytm /bin/sh -c "python3 ./tm.py --report ./template.md | pandoc -f markdown -t html > tm/report.html"


