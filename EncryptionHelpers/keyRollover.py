#!/bin/env python3

import sys, re, yaml, os

oldEncrypted = ""
fixedLinesLdif = ""
addKeys = open('/tmp/addKeys.ldif', 'w')
deleteKeys = open('/tmp/deleteKeys.ldif', 'w')
oldKey = ""
newKey = ""

with open('./keys.properties') as propFile:
  properties = yaml.safe_load(propFile)
   
with open('/tmp/users.ldif','r') as userKeys:
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

#process the ldif line by line
for line in fixedLinesLdif.split("\n"):
  if re.match('^dn: .*', line):
    #it's a dn line... write it to each new ldif file
    addKeys.write(line + "\n")
    deleteKeys.write(line + "\n")
    #add the write modify lines to each one
    addKeys.write("changetype: modify\nadd: description\n")
    deleteKeys.write("changetype: modify\ndelete: description\n")
    continue
  if re.match('^description: totpseed=(.*)', line):
    #its a key line.
    #extract the encrypted key
    encryptedSeed = line[line.index("(")+1:-1]
    newSeed = os.popen('java -cp ./libs/commons-lang3-3.9.jar:./bin helper.BasicEncryption --quiet --encryptedSEED ' + encryptedSeed  + ' --newkey ' + properties['newKey'] + ' --oldkey ' + properties['oldKey']).read()
    addKeys.write("descrition: totpseed=(" + newSeed.strip() + ")\n\n")
    deleteKeys.write(line + "\n\n")


addKeys.close()
deleteKeys.close()
