# © Copyright 2021 HP Development Company, L.P.
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute, MISPObject
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import requests, logging, tlsh, subprocess

from networkx.algorithms import bipartite
from networkx.drawing.nx_agraph import write_dot
from networkx import graph as nx

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.getLogger("pymisp").setLevel(logging.CRITICAL)

network = nx.Graph()
cluster = list()

def sumRow(matrix, i):
    return np.sum(matrix[i,:])
 
def determineRow(matrix):
    maxNumOfOnes = -1
    row = -1
    for i in range(len(matrix)):
        if maxNumOfOnes < sumRow(matrix, i):
            maxNumOfOnes = sumRow(matrix, i)
            row = i
    return row
 
def addIntoGroup(matrix, ind):
    change = True
    indexes = []
    for col in range(len(matrix)):
        if matrix[ind, col] == 1:
            indexes.append(col)
    while change == True:
        change = False
        numIndexes = len(indexes)
        for i in indexes:
            for col in range(len(matrix)):
                if matrix[i, col] == 1:
                    if col not in indexes:
                        indexes.append(col)
        numIndexes2 = len(indexes)
        if numIndexes != numIndexes2:
            change = True
    return indexes
 
def deleteChosenRowsAndCols(matrix, indexes):
    for i in indexes:
        matrix[i,:] = 0
        matrix[:,i] = 0
    return matrix
    
def categorizeIntoClusters(matrix):
    groups = []
    while np.sum(matrix) > 0:
        group = []
        row = determineRow(matrix)
        indexes = addIntoGroup(matrix, row)
        groups.append(indexes)
        matrix = deleteChosenRowsAndCols(matrix, indexes)
    return groups
 
def buildSimilarityMatrix(cluster):
    numOfSamples = len(cluster)
    matrix = np.zeros(shape=(numOfSamples, numOfSamples))
    i = 0
    for u1 in cluster:
        j = 0
        for u2 in cluster:
            if u1 != u2:
                try:
                    score = tlsh.diff(u1[1], u2[1])
                    if score < 100:
                        matrix[i,j] = 1
                        
                        network.add_node(u1[0],
                            label=str(u1[2]),
                            style='filled',
                            fillcolor='white',
                            color='white',
                            fontcolor='black',
                            fontname='Arial',
                            fontsize='16',
                            bipartite=0)

                        network.add_node(u2[0],
                            label=str(u2[2]),
                            style='filled',
                            fillcolor='white',
                            color='white',
                            fontcolor='black',
                            fontname='Arial',
                            fontsize='16',
                            bipartite=1)

                        network.add_edge(u2[0],
                            u1[0],
                            penwidth=1,
                            color='#0096D6',
                            dir='none')
                    else:
                        matrix[i,j] = 0
                except:
                    matrix[i,j] = 0
            j += 1
        i += 1
                            
    return matrix
 
def main():
    misp = ExpandedPyMISP("MISP_URL_GOES_HERE", "MISP_API_KEY_GOES_HERE", False)
    
    hashes = ["06e1bc999bb5df10b2472be1822312e7fe229394cdaf652b41bcebd171d63f2f",
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
    
    # events = misp.search_index(pythonify=True, tags="opendir") # TODO: change date..
    
    for e in events:
        event_added = False
        event = misp.search(eventid=e.id, pythonify=True)
        if len(event) > 0:
            event = event[0] 
            
            if len(event.objects) > 0:
                tags = list()
                for tag in event.tags:
                    tags.append(tag.name)
                for obj in event.objects:
                    url = ""
                    hash = ""
                    add_to_cluster = False
                    for att in obj.attributes:
                        if att.object_relation == "tlsh":
                            hash = att.value
                        if att.object_relation == "url":
                            url = att.value
                        if att.object_relation == "sha256":
                            if att.value in hashes:
                                add_to_cluster = True
                    if hash != "" and add_to_cluster:
                        cluster.append((url, hash, tags))
                               
    print("done collecting data")
    
   # compare all elements from cluster by calculating the hash distance and save into matrix
    
    matrix = buildSimilarityMatrix(cluster)
    
    write_dot(network, 'cluster_output.dot')
    subprocess.Popen(['sfdp',
                            'cluster_output.dot', 
                            '-Tpng', 
                            '-o', 
                            'cluster.png', 
                            '-Goutputorder="edgesfirst"',
                            '-Gfontsize="16"',
                            '-Gfontname="Arial"'
                            ])
                            
    subprocess.Popen(['sfdp', 
                            'cluster_output.dot', 
                            '-Tsvg', 
                            '-o', 
                            'cluster_output.svg', 
                            '-Goutputorder="edgesfirst"',
                            '-Gfontsize="16"',
                            '-Gfontname="Arial"'
                            ])
    
    # print groups
    groups = categorizeIntoClusters(matrix)
    group_nr = 0
    for g in groups:
        if len(g) > 1:
            print("Group " + str(group_nr))
            group_nr += 1
            for element in g:
                print(str(cluster[element][0]) + " - " + str(cluster[element][1]))

if __name__ == '__main__':
    main()