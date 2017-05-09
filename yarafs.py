#!/usr/bin/env python3

import argparse
import glob
import logging
import yara
import sys
import os
from pathlib import Path
from sys import platform

yaraCfg = None #global yara Object
cfgFile = 'config.txt'
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

class yaraConfig(object):
  """ Basic object containing needed yara arguments """
  def __init__(self,filePath,filePaths,source, sources):
    self.filePath = filePath
    self.filePaths = filePaths
    self.src = source
    self.srcs = sources

def beginScan(rules):
  """ Requires a list of rules to match against while it traverses the file system,yara's matches method requires a string input
  therefore for each file found in filesFound check each and every single file, and print the matches"""
  
  if platform == 'linux':
    homeDir = os.path.expanduser('~')

  filesFound = [] #emptyList as the initial state
  os.chdir(homeDir)
  filesFound = glob.iglob('**/*',recursive=True)
  matchesFound = {}

  for file in filesFound:
    if os.path.isfile(file):
      try:
        matches = rules.match(file)

        if matches:
          """If the malware already was detected and there was another file flagged for same malware, append that file to that specific malware"""
          matchesFound.setdefault(matches[0],[]).append(file)

      except Exception as e:
        print("==ERROR==\nMaybe bad file?\n")
        print(e)
        print("===")
        pass

  """ If there are no malicious files found"""
  if not matchesFound:
    print("No malicious files found")
  else:
    print("Malware types found in Text files:\n---Malware \tFile---") #debug because idk wtf im doing here
    for keys,values in matchesFound.items():
      print(keys,"\t",values)

def initYara():
  """Creates the actual yara object"""
  try:
    return yara.compile(yaraCfg.filePath)
  except Exception as e:
    print("==ERROR loading Yara!")
    #print("== "+e)
    print(e)
    sys.exit(1)

def grabLocalPaths():
  """Setups the global Yara configuration object. It will also check what operating system the script is running on,
     and then access the user's home directory with the path dependant on OS
  """
  if platform == 'linux':
    curDir = os.getcwd()

  global yaraCfg
  rulesFolder = curDir+'/myrules/master_rules.yar'
  rulesFolderPaths = curDir
  srcFolder = curDir
  srcsFolder = curDir

  yaraCfg = yaraConfig(rulesFolder,rulesFolderPaths,srcFolder,srcsFolder)
  

def bootUp():
  grabLocalPaths()
  #  exit(0)

def main():
  parser = argparse.ArgumentParser(description='Uses yara to scan a given path for any known malware/viruses.')
  parser.add_argument('-v',action='version',version="%(prog)s 1.0",help='prints out version')
  parser.add_argument('-s',dest='inputPath',help='Scan the specified path')
  args = parser.parse_args()

  bootUp()
  rules = initYara() #create the yara object
  print("Yara successfully Loaded! Let's hunt some Malware!")
  print("This will take a while...")
  beginScan(rules)

if __name__ == '__main__':
  main()

