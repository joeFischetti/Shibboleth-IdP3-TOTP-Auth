#!/bin/env python3

import sys, re, yaml, os

#Ldif files include blank lines, commented lines, and WRAPPED lines.
#  Wrapped lines are lines that start with whitespace.  We'll need
#  to fix the ldif file we're reading in so that it no longer has wrapped
#  lines.  This new variable will hold that fixed file
fixedLinesLdif = ""

#File that will have the ldif information for adding and removing
#  the new and old encrypted seed values.  Two separate files since
#  the values with the new key will need to be added, shib will need to
#  be switch to use the new key, and then the old values will need to be
#  removed
addKeys = open('/tmp/addKeys.ldif', 'w')
deleteKeys = open('/tmp/deleteKeys.ldif', 'w')

#Read the properties file as yaml
with open('./keys.properties') as propFile:
  properties = yaml.safe_load(propFile)
  

if len(sys.argv) is 1:
  print("No arguments provided, need the path to the ldif input file")
  sys.exit()

#open the ldif file that we'll use as input 
with open(sys.argv[1],'r') as userKeys:
  for line in userKeys:
    if re.match('^#', line):
      #it's a comment line, ignore it
      continue
    if re.match('^ ', line):
      #it's a line that starts with a space, unwrap it to the previous line
      fixedLinesLdif = fixedLinesLdif.rstrip("\n") + line.strip(" ")
      continue
    else:
      fixedLinesLdif += line

multipleKeys = 0

#process the ldif line by line
for line in fixedLinesLdif.split("\n"):
  if re.match('^dn: .*', line):
    if multipleKeys is 1:
      addKeys.write("\n")
      deleteKeys.write("\n")
    multipleKeys = 0
    #it's a dn line... write it to each new ldif file
    addKeys.write(line + "\n")
    deleteKeys.write(line + "\n")
    #add the write modify lines to each one
    addKeys.write("changetype: modify\nadd: description\n")
    deleteKeys.write("changetype: modify\ndelete: description\n")
    continue
  if re.match('^description: totpseed=(.*)', line):
    encryptedSeed = line[line.index("(")+1:-1]
    newSeed = os.popen('java -cp ./libs/commons-lang3-3.9.jar:./bin helper.BasicEncryption --quiet --encryptedSEED ' + encryptedSeed  + ' --newkey ' + properties['newKey'] + ' --oldkey ' + properties['oldKey']).read()

    print(newSeed)
    if not newSeed:
      continue

    if multipleKeys is 1:
      addKeys.write(":\n")
      deleteKeys.write(":\n")
    #its a key line.
    #extract the encrypted key
    addKeys.write("description: totpseed=(" + newSeed.strip() + ")\n")
    deleteKeys.write(line + "\n")
    multipleKeys = 1


addKeys.close()
deleteKeys.close()
