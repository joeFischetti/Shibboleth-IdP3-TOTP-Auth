#!/bin/env python3

import sys, re

oldEncrypted = ""
fixedLinesLdif = ""
addKeys = open('/tmp/addKeys.ldif', 'w')
deleteKeys = open('/tmp/deleteKeys.ldif', 'w')


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
    encryptedKey = line[line.index("(")+1:-1]
    print(encryptedKey)

    deleteKeys.write(line + "\n\n")


addKeys.close()
deleteKeys.close()
