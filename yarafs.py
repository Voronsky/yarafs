import argparse
import glob
import logging
import yara
import sys
import os

yaraCfg = None #global yara Object

class yaraConfig(object):

  def __init__(self,filePath,source,
               filePaths, sources):
    self.filePath = filePath
    self.filePaths = filePaths
    self.source = source
    self.sources = sources

def getPath(path):
  pass

def checkForPath():
  pass

def loadConfig(file):
  global yaraCfg
  fPath = None
  fPaths = None
  src = None
  srcs = None

  cfgFile = open(file, 'r')
  for line in cfgFile.readlines():
    if 'Yara folderPath' in line:
      string = line.split('=')
      fPath = string[1].strip() #White space needs to be a goner

    elif 'Yara folderPaths' in line:
      string = line.split('=')
      fPaths = string[1].strip()

    elif 'Yara source' in line:
      string = line.split('=')
      src = string[1].strip()

    elif 'Yara sources' in line:
      string  = line.split('=')
      srcs = string[1].strip()

  yaraCfg = yaraConfig(fPath,fPaths,src,srcs)

  try:
    getattr(yaraCfg, yaraCfg.filePath)
    getattr(yaraCfg, yaraCfg.filePaths)
    getattr(yaraCfg, yaraCfg.source)
    getattr(yaraCfg, yaraCfg.sources)
  except Exception as e:
    print ("Missing an attribute!")
    print (e)

def bootUp():
  for file in glob.glob("config.txt"):
    if file is not None:
      loadConfig(file)
    else:
      print("Configuration file was not found! Please redownload from repo")
      exit(0)

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Uses yara to scan a given path for any known malware/viruses.')
  parser.add_argument('-v',version="%(prog)s 1.0",help='prints out version')
  parser.add_argument('-s',dest='inputPath',help='Scan the specified path')
  args = parser.parse_args()
  bootup()

