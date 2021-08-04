# © Copyright 2021 HP Development Company, L.P.
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute, MISPObject
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests, logging
import matplotlib.pyplot as plt

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.getLogger("pymisp").setLevel(logging.CRITICAL)

misp = ExpandedPyMISP("MISP_URL_GOES_HERE", "MISP_API_KEY_GOES_HERE", False)

hashes = [
    "06e1bc999bb5df10b2472be1822312e7fe229394cdaf652b41bcebd171d63f2f",
    "f61151f81c42799bd857298ecb606d19f91b955bdb9ee3aef13bbff40c02ff44",
    "b8a9e3b4a0ebdaf111c4499c8e465b30ad2077bc4a62448eeaee5f77cf3a2a66",
    "3938bbfdc2befe11089d2a2c3e6fb1b9070b70917f2adb803248398a07e44c73",
    "4b812428a3112be107627ca7db82c89f7e7a3f5cbe7b663c2af2f6e20599c67b",
    "eff23a6b3184b9032dcd3599c3a636a827399ccad79e7bfc9e22ff70cd5b67cb",
    "825ae6835c175c1eed83c2ee4aa2f4065ca87b93d97b2854af55c863b0decddc",
    "ca3b5a666dc87c49b31e49193b844fb8f0070f0588f7b9c5572b88f0156d6e40"
]

events = list()
for h in hashes:
    events += misp.search_index(pythonify=True, attribute=h) 
	
webservers = dict()

for e in events:
    web_added = False
    event = misp.search(eventid=e.id, pythonify=True)
    if len(event) > 0:
        event = event[0]
        
    for attribute in event.attributes:
        if attribute.comment == "Webserver" and not web_added:
            web_added = True
            if attribute.value in webservers:
                webservers[attribute.value] += 1
            else:
                webservers[attribute.value] = 1

				
webserver_name = list()
webserver_count = list()

for w in dict(sorted(webservers.items(), key=lambda item: item[1], reverse=True)):
    webserver_name.append(w)
    webserver_count.append(webservers[w])

fig = plt.figure()
ax = fig.add_axes([0,0,1,1])
ax.bar(webserver_name,webserver_count)
plt.xticks(rotation='vertical')
plt.savefig('webserver.png', bbox_inches='tight')
plt.show()
