# Used to extend the command line of the pytm.py
#
# usage: 
#   from pytm.tmconfig import configure_from_cli
#   configure_from_cli(tm)

import argparse
import sys

def get_visual_args():
  p = argparse.ArgumentParser()

  # Visual configuration for dfd
  p.add_argument("--defaultcolor", help="default color for lines etc")
  p.add_argument("--bgcolor", help="background color")
  p.add_argument("--edgefontcolor", help="font color for edge texts")
  p.add_argument("--lambdaimage", help="the filename to use for lambda images")
  p.add_argument("--datastoreimage", help="the filename to use for datastore images")
  p.add_argument("--ortho", action="store_true", help="sets spline=ortho should make straight lines for digraph")

  # Standard arguments (need to replicate these here to support older models.)
  p.add_argument("--sqldump", help="""dumps all threat model elements and findings into the named sqlite file (erased if exists)""")
  p.add_argument("--debug", action="store_true", help="print debug messages")
  p.add_argument("--dfd", action="store_true", help="output DFD")
  p.add_argument("--report", help="""output report using the named template file(sample template file is under docs/template.md)""")
  p.add_argument("--exclude", help="specify threat IDs to be ignored")
  p.add_argument("--seq", action="store_true", help="output sequential diagram")
  p.add_argument("--list", action="store_true", help="list all available threats")
  p.add_argument("--describe", help="describe the properties available for a given element")
  p.add_argument("--list-elements", action="store_true", help="list all elements which can be part of a threat model")
  p.add_argument("--json", help="output a JSON file")
  p.add_argument("--levels",type=int,nargs="+",help="Select levels to be drawn in the threat model (int separated by comma).")
  p.add_argument("--stale_days",help="""checks if the delta between the TM script and the code described by it is bigger than the specified value in days""", type=int)  
  
  return p.parse_args()

def configure_from_cli(threatmodel):
  threatmodel._externalConfig = get_visual_args()
  configure_from_setting(threatmodel._externalConfig, threatmodel._externalConfig)  

def configure_from_setting(result, threatmodel):

  if result.ortho is not None:
      threatmodel.orthoSplines = result.ortho

  if result.defaultcolor is not None:
      threatmodel._settingDefaultColor = result.defaultcolor
      threatmodel._settingEdgeFontColor = result.edgefontcolor

  if result.edgefontcolor is not None:
      threatmodel._settingEdgeFontColor = result.edgefontcolor

  if result.lambdaimage is not None:
      threatmodel._settingLambdaImage = result.lambdaimage

  if result.datastoreimage is not None:
      threatmodel._settingDatastoreImage = result.datastoreimage

  if result.bgcolor is not None:
      threatmodel._settingBgColor = result.bgcolor