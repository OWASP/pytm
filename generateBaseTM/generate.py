#!/usr/bin/env python3

from sys import stderr
import argparse
import csv

fileHeader = '''#!/usr/bin/env python3

import sys
sys.path.insert(0, '..')

from pytm.pytm import TM, Element,SetOfProcesses, Process, Server, Datastore, Dataflow, Boundary, Actor

tm = TM("CHANGE ME")
tm.description = "CHANGE ME"
'''

fileFooter = '''
tm.process()
'''

elementText = '{0} = Element("{0}")'
#DF_SE_Configs = Dataflow(endPointConfigs, mvsaSmartEndpoint, "Configuration Data")
dataFlowText = "{0}_to_{1} = Dataflow({0}, {1}, 'CHANGE ME')"



def _debug(msg):
    if _args.debug is True:
        stderr.write("DEBUG: {}\n".format(msg))

def process(self):
    self.check()
    if _args.all is True:
        _args.report = True
        _args.dfd = True
        _args.resolve = True
    if _args.seq is True:
        self.seq()
    if _args.dfd is True:
        self.dfd()
    if _args.resolve is True:
        self.resolve()
    if _args.report is True:
        self.report()

_parser = argparse.ArgumentParser()
_parser.add_argument('--input', help='input csv file')
_parser.add_argument('--output', help='output py tm file')
_parser.add_argument('--debug', action='store_true', help='print debug messages')
_args = _parser.parse_args()

if _args.input is None or _args.output is None:
    print("ERROR: Input and Output files must be specified")
    exit(0)

if _args.input:
    inputFile = _args.input

if _args.output:
    outputFile = _args.output

elements = {}
flows = {}


with open(inputFile, 'r') as csvfile:
    reader = csv.DictReader(csvfile, fieldnames=("SOURCE", "SINK"))
    for row in reader:
        source = row['SOURCE'].strip()
        sink = row['SINK'].strip()
        elements[source] = elementText.format(source)
        elements[sink] = elementText.format(sink)
        flows[source+"-"+sink] = dataFlowText.format(source, sink)

tmFile = open(outputFile, 'w')
tmFile.write(fileHeader + "\n")

for e in elements:
    tmFile.write(elements[e] + "\n")

for f in flows:
    tmFile.write(flows[f] + "\n")

tmFile.write(fileFooter + "\n")

