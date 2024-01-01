import os,sys,json
import requests
from publicsuffixlist import PublicSuffixList
from tranco import Tranco

psl = PublicSuffixList()

lists = {
  "The malicious website blocklist":"https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_domains.txt",
  "iam-py-test's anti-PUP list":"https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antipup_domains.txt",
  "URLHaus": "https://urlhaus.abuse.ch/downloads/hostfile/"
}
lists_data = {}
tldsg = {}

tld_stats = {}
try:
  tld_stats = json.loads(open("stats.json", encoding="UTF-8").read())
except:
  pass

tranco = Tranco(cache=False)
trancolist = tranco.list()
topdomains = trancolist.top()

lists_data["tranco"] = {}

for domain in topdomains:
  tld = psl.publicsuffix(domain)
  if tld == None:
    continue
  if tld not in lists_data["tranco"]:
    lists_data["tranco"][tld] = 0
  lists_data["tranco"][tld] += 1

for l in lists:
  tlds = {}
  domains = requests.get(lists[l]).text.replace("\r", "").split("\n")
  for domain in domains:
    if domain.startswith("#"):
      continue
    if domain.startswith("127.0.0.1\t"):
      domain = domain.replace("127.0.0.1\t", "")
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
  if tld not in tld_stats:
    tld_stats[tld] = []
  tld_stats[tld].append(tldsg[tld])
  outlist.write("{}: {}<br>\n".format(tld,tldsg[tld]))

for ldata in lists_data:
  outlist.write("## {}\n".format(ldata))
  ltlds = lists_data[ldata]
  for tld in ltlds:
    outlist.write("{}: {}<br>\n".format(tld,ltlds[tld]))
outlist.close()

try:
  statsf = open("stats.json", 'w')
  statsf.write(json.dumps(tld_stats))
  statsf.close()
except:
  pass
