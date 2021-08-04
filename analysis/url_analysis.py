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

urls = list()
for e in events:
    event = misp.search(eventid=e.id, pythonify=True)
    if len(event) > 0:
        event = event[0]
        
    for obj in event.objects:
        url = ""
        hash = ""
        date = event.date
        add = False
        for attribute in obj.attributes:
            if attribute.object_relation == "url":
                url = attribute.value 
            if attribute.value in hashes:
                hash = attribute.value
                add = True
        if add:
            urls.append((date, url, hash))
				
				
# Finding common webshell names
file_set = dict()
max_length = 0
for u in urls:
    file_name = str(u[1]).split("/")[-1]
    if file_name == "":
        continue
    if len(file_name) > max_length:
            max_length = len(file_name)
    if file_name in file_set:
        file_set[file_name] += 1
    else:
        file_set[file_name] = 1
	
print("******** Common Webshell names *********")
sorted_webshells = dict(sorted(file_set.items(), key=lambda item: item[1],reverse=True))

print(("{:<"+str(max_length+5)+"} {:<10}").format('Name:','Num:'))
for webshell in sorted_webshells:
    print(("{:<"+str(max_length+5)+"} {:<10}").format(webshell, str(sorted_webshells[webshell])))
    
# Finding common wordpress plugin names
plugins = dict()
max_length = 0
for u in urls:		
    if "plugins" in u[1] and "wp-" in u[1]:
        index = u[1].find("plugins")
        index2 = u[1].find("/", index+8)
        plugin = u[1][index+8:index2]
        if len(plugin) > max_length:
            max_length = len(plugin)
        if plugin not in plugins:
            plugins[plugin] = 1
        else:
            plugins[plugin] += 1

print("\n******** Common Wordpress Plugins *********")
sorted_plugins = dict(sorted(plugins.items(), key=lambda item: item[1],reverse=True))

print(("{:<"+str(max_length+5)+"} {:<10}").format('Plugin:','Num:'))
for plugin in sorted_plugins:
    print(("{:<"+str(max_length+5)+"} {:<10}").format(plugin, str(sorted_plugins[plugin])))