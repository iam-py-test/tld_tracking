import os,sys
import requests
from publicsuffixlist import PublicSuffixList

psl = PublicSuffixList()

lists = {"The malicious website blocklist":"https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_domains.txt","iam-py-test's anti-PUP list":"https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antipup_domains.txt"}
lists_data = {}
tldsg = {}


tlds = {}
for l in lists:
  domains = requests.get(lists[l]).text.split("\n")
  for domain in domains:
    try:
      tld = psl.publicsuffix(domain)
      if tld == None:
        print(domain)
        continue
      if tld not in tlds:
        tlds[tld] = 0
      tlds[tld] += 1
      if tld not in tldsg:
        tldsg[tld] = 0
      tldsg[tld] += 1
    except:
      pass
  lists_data[l] = tlds
outlist = open("output.md",'w')
outlist.write("## All lists\n")
for tld in tldsg:
  outlist.write("{}: {}<br>\n".format(tld,tldsg[tld]))

for ldata in lists_data:
  outlist.write("## {}\n".format(ldata))
  ltlds = lists_data[ldata]
  for tld in ltlds:
    outlist.write("{}: {}<br>\n".format(tld,ltlds[tld]))
outlist.close()
