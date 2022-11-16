import os,sys
import requests
from publicsuffixlist import PublicSuffixList

psl = PublicSuffixList()

domains = requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_domains.txt").text.split("\n")
tlds = {}

for domain in domains:
  try:
    tld = psl.publicsuffix(domain)
    if tld not in tlds:
      tlds[tld] = 0
    tlds[tld] += 1
  except:
    pass
outlist = open("output.md",'w')
for tld in tlds:
  outlist.write("{}: {}\n".format(tld,tlds[tld]))
outlist.close()
