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
    print("Linux")
    homeDir = os.path.expanduser('~')
  filesFound = [] #emptyList as the initial state
  os.chdir(homeDir)
  print(homeDir)
  filesFound = glob.glob('*.txt')
  #filesFound = glob.glob(homeDir+'/*.*',recursive=True)
  matchesFound = {}
  for file in filesFound:
    print("DEBUG: File"+file)
    matches = rules.match(file)
    if matches:
      print(matches[0])
      matchesFound.update({matches[0]:file})

  print("Malware types found:\n---Malware \tFile---") #debug because idk wtf im doing here
  for keys,values in matchesFound.items():
    print(keys,"\t",values)

def initYara():
  try:
    return yara.compile(yaraCfg.filePath)
  except Exception as e:
    print("==ERROR loading Yara!")
    print("== "+e)

def loadConfig(file):
  """ Configuration setup, using the Yara object we will pass all needed arguments so that yara python module can be properly used"""
  global yaraCfg
  yaraVals = {}
  fPath = None
  fPaths = None
  src = None
  srcs = None

  cfgFile = open(file, 'r')
  for line in cfgFile.readlines():
    string = line.split('=')
    key = string[0].strip()
    value = string[1].strip('\n')
    value = value.replace('"','').strip()
    yaraVals.update({key:value})


  for keys,values in yaraVals.items():
    print (keys,values)
  yaraCfg = yaraConfig(yaraVals['Yara folderPath'],yaraVals['Yara folderPaths'],yaraVals['Yara source'],yaraVals['Yara sources'])

  try:
    if yaraCfg.filePath and yaraCfg.filePaths and yaraCfg.src and yaraCfg.srcs is not None:
      logging.info(yaraCfg.filePath)
      logging.info(yaraCfg.filePaths)
      logging.info(yaraCfg.src)
      logging.info(yaraCfg.srcs)
  except Exception as e:
    print ("Missing an attribute!")
    print(e)

def bootUp():
  if Path(cfgFile).exists():
    loadConfig(cfgFile)
  else:
    print("Configuration file was not found! Please redownload from repo")
    exit(0)

def main():
  parser = argparse.ArgumentParser(description='Uses yara to scan a given path for any known malware/viruses.')
  parser.add_argument('-v',action='version',version="%(prog)s 1.0",help='prints out version')
  parser.add_argument('-s',dest='inputPath',help='Scan the specified path')
  args = parser.parse_args()

  bootUp()
  rules = initYara() #create the yara object
  print("Yara successfully Loaded! Let's hunt some Malware!")
  beginScan(rules)

if __name__ == '__main__':
  main()

