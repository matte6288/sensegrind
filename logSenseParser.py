from __future__ import print_function
import os, sys
import fileinput
import re
import argparse

#include all substrings of all functions that output data to user
output_flags=["print"]

potential_sensitive=set()

parser = argparse.ArgumentParser()

parser.add_argument("-v", "--var_file_name", help="The name of variable file", required=True)
parser.add_argument("-l", "--log_file_name", help="The name of the log file", required=True)
args = parser.parse_args()

namedNodes = []
variableNames = []
#get named nodes from file
with open(args.var_file_name) as f:
    for line in f.readlines():
        variableNames.append(line.strip())



def sanitise_var(varname):
    # dot will complain if we have strange chars
    varname = varname.replace('[','_').replace(']','_')
    varname = varname.replace('.','_').replace('.','_')

    # E.g. <address>_unknownobj -> a<address>
    if "_unknownobj" in varname:
        varname = 'a' + varname.split("_unknownobj")[0]

    # E.g. <varname>:<address> -> a<address>
    if ":" in varname:
        for v in variableNames:
            if varname not in namedNodes and varname.split(":")[0].startswith(v):
                namedNodes.append(varname)
        varname = 'a'+varname.split(":")[1]


    # dot will complain if var name starts with a number
    if re.match('^[0-9]',varname):
        varname = 'g' + varname

    # dot will complain if var name contains a space
    if ' ' in varname:
        varname = varname.split(' ')[0]
    return varname


# Get the location/function of a line
# E.g. Input is '0x8048507: main (sign32.c:10)',
#      Output is 'main'
def get_loc(line):
    if '(' in line.split()[1]:
        return line.split()[1].split('(')[0]
    return line.split()[1] 


# g:     array to collect nodes by function
# label: node label
# loc:   function

def add_node(g, label, loc):
    if loc not in g:
        g[loc] = ""
    elif label not in g[loc]:
        g[loc] += "    %s\n" % (label)
    return g


# Extract the function name from, e.g.
# 0x4CC398D: free (malloc.c:3103)
# Expected output from above: free (malloc.c)
def getfuncname(addr):
    funcname = addr
    # Get rid of address
    if ": " in addr:
        funcname = addr.split(": ")[1]

    # Remove all digits and colons
    funcname = re.sub(r'[0-9:]', '', funcname)
    return funcname


TAINT_SINKS = ["__memcpy_sse_unaligned_erms (memmove-vec-unaligned-erms.S)",
               "memcpy@GLIBC_.. (memmove-vec-unaligned-erms.S)",
               "_int_malloc (malloc.c)",
              ]


# array to store all lines
data = []


f = []

with open(args.log_file_name) as l:
    for line in l.readlines():
        f.append(line.strip())

# Pass 1: Remove non-taintgrind output
for i in range(len(f)):
    line = f[i]

    if not line.startswith("0x"):
        continue

    # Need to remove valgrind warnings, which add a LF
    # We need to add the next line as well
    if "-- warning:" in line:
        elts = line.split("|")
        nextline = f[i+1]
        c = 2

        while "-- warning:" in nextline:
            nextline = f[i+c]
            c += 1
        
        elts[-1] = " " + nextline
        line = "|".join(elts)

    data.append(line)


# Pass 2: Construct the graph; define nodes and edges
edges = []
nodes = {}

for line in data:
    addr = ""
    insn = ""
    insnty = ""
    val = ""
    flow = ""

    a = line.rstrip().split(" | ")

    if len(a) == 5:
        (addr,insn,insnty,val,flow) = line.rstrip().split(" | ")
    elif len(a) == 4:
        (addr,insnty,val,flow) = line.rstrip().split(" | ")
    elif len(a) == 2:
        (addr,flow) = line.rstrip().split(" | ")
    else:
        print("%d" % (len(a)))
        sys.exit(0)

    funcname = getfuncname(addr)

    # If there is taint flow
    if len(flow) >= 4:
        # Get location/function of line
        loc = get_loc(line)

        if " <- " in flow:
            (sink,sources) = flow.split(" <- ")

            for source in sources.split():
                # Add an edge for each source
                if "(" not in source:
                    # Direct source
                    edges.append("%s -> %s" % (sanitise_var(source),sanitise_var(sink)))
                    if source not in nodes:
                        nodes[source] = ("%s [label=\"%s\"]" % (sanitise_var(source), source), loc)
                else:
                    # Indirect source, colour it red
                    source2 = source[1:-1]
                    edges.append("%s -> %s[color=\"red\"]" % (sanitise_var(source2),sanitise_var(sink)))
                    if source2 not in nodes:
                        nodes[source2] = ("%s [label=\"%s\"]" % (sanitise_var(source2), source2), loc)

            vname = sanitise_var(sink)

            if (funcname in TAINT_SINKS) and ("Store" in insnty):
                # If we find Stores in predefined TAINT_SINKS, e.g. malloc or memcpy, colour it red
                nodes[sink] = ("%s [label=\"%s:%s (%s)\",fillcolor=red,style=filled]" % (vname,sink,val,insnty), loc)
            elif (len(sources.split()) > 1) and ("Store" in insnty):
                # If both address and data to this Store are tainted, colour it red
                nodes[sink] = ("%s [label=\"%s:%s (%s)\",fillcolor=red,style=filled]" % (vname,sink,val,insnty), loc)
            elif val and insnty:
                #os.system(">&2 echo \"%s\" %s" % (funcname, insnty))
                nodes[sink] = ("%s [label=\"%s:%s (%s)\"]" % (vname,sink,val,insnty), loc)
            else:
                nodes[sink] = ("%s [label=\"\" shape=point]" % (vname), loc)

        elif "Jmp" in insnty:
            vname = sanitise_var(flow)
            # If jump target is tainted, colour it red
            nodes[flow] = ("%s [label=\"%s:%s (%s)\",fillcolor=red,style=filled]" % (vname,flow,val,insnty), loc)
        elif "IfGoto" in insnty and funcname in TAINT_SINKS:
            vname = sanitise_var(flow)
            # If if-goto is in a taint sink, colour it red
            nodes[flow] = ("%s [label=\"%s:%s (%s)\",fillcolor=red,style=filled]" % (vname,flow,val,insnty), loc)
        elif val and insnty:
            vname = sanitise_var(flow)
            nodes[flow] = ("%s [label=\"%s:%s (%s)\"]" % (vname,flow,val,insnty), loc)
        else:
            vname = sanitise_var(flow)
            nodes[flow] = ("%s [label=\"\" shape=point]" % (vname), loc)


#create mapping from sanitized name to node
connected= []
sanatized_name_to_node={}
nodesCopy=nodes.copy()
for node in nodes:
    if "[" in node or "." in node:
        nodesCopy[node.replace('[','_').replace(']','_')]=nodesCopy[node]
        nodesCopy[node.replace('.','_').replace('.','_')]=nodesCopy[node]
        del nodesCopy[node]

nodes = nodesCopy

for node in nodes:
    sanatized_name_to_node[sanitise_var(node)]=node

#create mapping from node to sanitized name
node_to_sanatized_name={}
for node in nodes:
    node_to_sanatized_name[node]=sanitise_var(node)

#remove root nodes
rootnodes=set()
for node in namedNodes:
    found = False
    for e in edges:
        source, dest = e.split(" -> ")
        if node_to_sanatized_name[node] == dest:
            found = True
            break
    if not found:
        namedNodes.remove(node) 
        rootnodes.add(node)  
#find nodes that belong to output functions
output_nodes = set()
for substring in output_flags:
    for node in nodes:
        if substring in nodes[node][1]:
            output_nodes.add(node)



# filter to only contains paths with named vars and that print
def connected_to_named(nodes,edges,named):

    connected_edges = set()
    connected_nodes = set()

    visited = set()
    path_nodes = set()
    path_edges = set()

    def dfs(node):
        visited.add(node)
        path_nodes.add(node)
        for p in path_nodes:
            if p in named:
                for q in path_nodes:
                    if q in output_nodes:
                        connected_nodes.update(path_nodes)
                        connected_edges.update(path_edges)
                        potential_sensitive.add(p)
        #dfs edges
        for e in edges:
            source, dest = e.split(" -> ")
            try:
                if source ==  node_to_sanatized_name[node] and sanatized_name_to_node[dest] not in visited:
                    path_edges.add(e)
                    dfs(sanatized_name_to_node[dest])
            except KeyError:
                pass
        path_nodes.remove(node)
        for e in edges:
            source, dest = e.split(" -> ")
            if node_to_sanatized_name[node] == dest:
                try:
                    path_edges.remove(e)
                except KeyError:
                    pass


    for node in nodes:
        if node not in visited:
            path_nodes=set()
            path_edges=set()
            dfs(node)

    return connected_nodes, connected_edges


# 8. For each neighbor of the current node, if it hasn't been visited, call "dfs" recursively with the neighbor as an argument.
# 10. Iterate over each node in the tree. If the node hasn't been visited, call "dfs" with the node as an argument.
# 11. Return the sets "path_nodes" and "path_edges".


connected, edges = connected_to_named(nodes.keys(),edges,namedNodes)
nodes = {key: nodes[key] for key in connected}



# Pass 3: Collect the nodes into subgraphs,
#         Grouped together by function
subgraph = {}

for line in data:
    addr = ""
    insn = ""
    insnty = ""
    val = ""
    flow = ""

    a = line.rstrip().split(" | ")

    if len(a) == 5:
        (_,_,_,_,flow) = line.rstrip().split(" | ")
    elif len(a) == 4:
        (_,_,_,flow) = line.rstrip().split(" | ")
    elif len(a) == 2:
        (_,flow) = line.rstrip().split(" | ")
    else:
        print("%d" % (len(a)))
        sys.exit(0)

    # If there is taint flow
    if len(flow) >= 4:
        # Get location/function of line
        loc = get_loc(line)

        if " <- " in flow:
            (sink,sources) = flow.split(" <- ")

            for source in sources.split():
                # Add an edge for each source
                if "(" not in source:
                    # Direct source
                    try:
                        subgraph = add_node(subgraph, nodes[source][0], nodes[source][1])
                    except KeyError:
                        pass
                else:
                    # Indirect source, colour it red
                    try:
                        source2 = source[1:-1]
                        subgraph = add_node(subgraph, nodes[source2][0], nodes[source2][1])
                    except KeyError:
                        pass
            try:
                subgraph = add_node(subgraph, nodes[sink][0], nodes[sink][1])
            except KeyError:
                pass
        else:
            try:
                subgraph = add_node(subgraph, nodes[flow][0], nodes[flow][1])
            except KeyError:
                pass



with open("possible_sense_vars.txt", "w") as file1:
# Writing data to a file
    for var in potential_sensitive:
        file1.write(var+"\n")

# Now we construct the graph
print("digraph {")

# Print subgraphs
for s in subgraph:
    sname = s.replace("???","unknown")
    sname = re.sub(r'[^a-zA-Z0-9_]', '_', sname)
    print("    subgraph cluster_%s{" % (sname))
    print("        label=\"%s\"" % (s))
    print(subgraph[s])
    print("    }")

# Print the edges
for e in edges:
    print("    " + e)

print("}")


