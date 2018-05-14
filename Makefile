init:
	pip3 install -r requirements.txt

test:
	py.test tests


.PHONY: init test
