MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CWD := $(patsubst %/,%,$(dir $(MKFILE_PATH)))

models := $(shell find . -d 1 -name "test*.py")
# Get the name of the current branch and put it into a local path
BRANCH_DIR := branch/$(shell git rev-parse --abbrev-ref HEAD)
# Keep the source tree into the objects tree
TM_DIRS := $(addprefix $(BRANCH_DIR)/,$(models:.py=/))
TM_MDS := $(addprefix $(BRANCH_DIR)/,$(models:.py=/report.md))
TM_DFDS := $(addprefix $(BRANCH_DIR)/,$(models:.py=/dfd.dot))
TM_SEQS := $(addprefix $(BRANCH_DIR)/,$(models:.py=/seq.puml))

# Oh my, python and its stupid import rules
PYTHON := PYTHONPATH=.. python3

$(info $(shell mkdir -p $(TM_DIRS)))

libs := $(wildcard pytm/*.py) $(wildcard pytm/threatlib/*.json) $(wildcard pytm/images/*)

all: $(TM_MDS) $(TM_DFDS) $(TM_SEQS)

clean:
	rm -rf $(TM_MSDS) $(TM_DFDS) $(TM_SEQS)

$(TM_DFDS): $(BRANCH_DIR)/%/dfd.dot: %.py $(libs)
	$(PYTHON) $< --dfd > $@

$(TM_SEQS):$(BRANCH_DIR)/%/seq.puml: %.py $(libs)
	$(PYTHON) $< --seq > $@

$(TM_MDS):$(BRANCH_DIR)/%/report.md: %.py $(libs) template.md
	$(PYTHON) $< --report template.md  > $@


dfd: $(models:.py=/dfd.png)

seq: $(models:.py=/seq.png)

report: $(models:.py=/report.html) seq dfd
