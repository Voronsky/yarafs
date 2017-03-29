import argparse
import logging
import yara
import sys
import os


class yara(object):
  pass

def getPath(path):
  pass

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Uses yara to scan a given path for any known malware/viruses.')
  parser.add_argument('-v',version="%(prog)s 1.0",help='prints out version')
  parser.add_argument('-s',dest='inputPath',help='Scan the specified path')
  args = parser.parse_args()
  getPath(args.inputPath)
