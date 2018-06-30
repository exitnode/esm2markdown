#!/usr/bin/env python3
'''
esm2markdown - McAfee ESM correlation rule XML export to markdown converter
Copyright (C) 2018 Michael Clemens

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
'''

import sys
import os.path
import re
from configparser import ConfigParser
from lxml import etree
from urllib.parse import unquote
from subprocess import check_call


# Set configuration defaults in case of missing ini file
key_style = "**"
value_style = ""
sort_rules = True
toc = True
imagepath = "images"

mklines = []


# Reads ini file, sets global variables
def readConfig():

    # Overwrite variables with settings from ini file
    try:
        config = ConfigParser()
        config.read('esm2markdown.ini')
        key_style = config.get('config', 'key_style')
        value_style = config.get('config', 'value_style')
        sort_rules = config.getboolean('config', 'sort_rules')
        toc = config.getboolean('config', 'toc')
        imagepath = config.get('config', 'imagepath')
    except:
        print("Configuration file not found, using default settings")


# Generates a line containing linebreaks, indented lists, styles etc.
def addLine(typ,level,key,value):

    lvl = ""
    output = ""
    valout = ""

    if value:
        value = unquote(value)

    if key:
        if typ == "list":
            if level == 1: lvl = "*   "
            elif level == 2: lvl = "    * "
            elif level == 3: lvl = "        * "
            if value == "N/A": output = lvl + key_style + key + key_style + "\n"
            elif value: output = lvl + key_style + key + key_style + " " + \
                    value_style + value + value_style + "\n"
        elif typ == "header":
            if level == 1: lvl = "# "
            elif level == 2: lvl = "## "
            elif level == 3: lvl = "### "
            elif level == 4: lvl = "#### "
            output = "\n" + lvl + key + "\n"
        elif typ == "none":
            output = key + "\n"

    output = re.sub('\$\$',"!",output)
    mklines.append(output)

def validateXML(xmlfile):

    xmlok = True
    parser = etree.XMLParser(strip_cdata=False)
    with open(xmlfile, "rb") as source:
        root = etree.parse(source, parser=parser)

    temp = root.find("rules")

    msglist = []

    for e in temp:
        msg = e.findtext("message")
        if msg in msglist:
            print("Duplicate rule: " + msg)
            xmlok = False
        msglist.append(msg)

    if xmlok == False:
        print("The XML file contains some errors. Please fix the input file and rerun this script.")

    return xmlok


# Sorts input XML alphabetically based on Rule Names
def sortXML(xmlfile):

    parser = etree.XMLParser(strip_cdata=False)
    with open(xmlfile, "rb") as source:
        root = etree.parse(source, parser=parser)

    temp = root.find("rules")

    data = []
    for e in temp:
        msg = e.findtext("message")
        data.append((msg, e))

    data.sort()

    temp[:] = [item[-1] for item in data]
    return root


# Generates Markdown Syntax for Images
def addImage(rulename):

    out = ""
    if not os.path.exists(imagepath):
        os.makedirs(imagepath)
    imagefile = imagepath + "/" + rulename + ".png"
    imagefile = imagefile.replace(" ", "_")
    out = "![](" + imagefile + ")\n\n\n"
    return out


# Generates dict object with relations between triggers and match blocks
def getRelationDict(cdata):

    rel = {}

    # Populate Tree with rule objects
    for r in cdata.getiterator('rule'):
        if not r.get('name') == "Root Rule":
            for e in r.iter():
                if str(e.tag) == 'action':
                    if e.get('type') == "TRIGGER":
                        for trigger in cdata.getiterator('trigger'):
                            if e.get('trigger') == trigger.get('name'):
                                rel[r.get('name')]=trigger.get('name')

    # Populate Tree with trigger objects
    for t in cdata.getiterator('trigger'):
        tname = t.get('name')
        tparent = t.findtext('trigger')

        if tname:
            if not tparent:
                tparent = "root"
            rel[tname]=tparent

    return rel


# Populates Graph object with trigger nodes and edges
def addTriggersToGraph(cdata,G):

    # get dictionary with all element relations
    reldict = getRelationDict(cdata)

    # Walk through dict
    tco = 99
    for key in sorted(reldict):
        trigcount = 0
        # count triggers per rule
        if key.startswith("trigger") or key.startswith("Root Trigger"):
            for trigkey in sorted(reldict):
                if reldict[trigkey] == key:
                   trigcount += 1
            # get count value from triggers element
            for tc in cdata.getiterator('trigger'):
                if tc.get('name') == key:
                    if tc.get('count'):
                        tco = int(tc.get('count'))
            # compare count value and counted triggers
            # if both are the same, all match blocks need to match
            # therefore the logical operator is AND
            # otherwise its OR
            if tco == trigcount:
                oper = "AND"
            else:
                oper = "OR"

            # add trigger nodes to graph
            G.add_node(key, label=oper, shape='plaintext')
            if key != "root" and reldict[key] != "root":
                G.add_edge(reldict[key],key,splines='ortho', nodesep=0.2)
    return G


# Generates png file visualizing match block relationships
def generateGraph(cdata,dMatchBlocks,rid):

    dependencies = True

    try:
        from networkx.drawing.nx_pydot import write_dot
        import networkx as nx
    except ImportError:
        print("Cannot find networkx. Please install pydot and networkx.")
        print("Output file will be created without images.")
        dependencies = False
        return False

    if dependencies:
        G = nx.DiGraph()

        # populate Graph object with triggers
        G = addTriggersToGraph(cdata,G)

        for x in dMatchBlocks:
            G.add_node(x, color=dMatchBlocks[x]['shapecol'],style='filled',fillcolor=dMatchBlocks[x]['shapecol'],shape='box')
            G.add_edge(dMatchBlocks[x]['parent'],x)

        # write dot file for Graphviz out to file system
        write_dot(G,'file.dot')
        # execute 'dot' as os command, generate png file from dot file
        try:
            check_call(['dot','-Tpng','-Grankdir=LR','file.dot','-o',imagepath + '/' +
                        rid +'.png'])
        except OSError as e:
            dependencies = False
            print("'dot' could not be found. Please install pydot.")

        return True


# Walks through list 'mklines' and write content to outfile
def writeMarkdownFile(outfile):

    file = open(outfile,"w")
    for l in mklines:
        file.write(l)
    file.close()


# Parses and procresses XML file
def parseXML(xmlfile):

    mklines.clear

    if sort_rules:
        root = sortXML(xmlfile)
    else:
        root = etree.parse(xmlfile)

    if toc:
        addLine("header",1,"Correlation Rule Overview","")
        for rule in root.getiterator('rule'):
            addLine("list",1,rule.findtext('message'),"N/A")

    for rule in root.getiterator('rule'):

        dMatchBlocks = {}

        # Get CDATA
        text = rule.findtext('text')
        cdata = etree.fromstring(text)

        # Print rule name as header
        addLine("header",1,rule.findtext('message'),"")
        # Print rule description
        addLine("header",2,"Description","")
        addLine("none","",rule.findtext('description'),"")
        # Print rule information (ID, Normalization, Severity, Tags, Group By)
        addLine("header",2,"General Information","")
        addLine("list",1,"Rule ID:",rule.findtext('id'))
        addLine("list",1,"Normalization ID:",rule.findtext('normid'))
        addLine("list",1,"Severity:",rule.findtext('severity'))
        for tags in rule.getiterator('tag'):
            addLine("list",1,"Tag:",tags.text)
        for rs in cdata.getiterator('ruleset'):
            addLine("list",1,"Group By:",rs.get('correlationField'))
        addLine("header",2,"Correlation Details","")
        # Insert diagram into text
        mklines.append(addImage(rule.findtext('id')))
        parameters = False
        # Print rule parameters
        for param in cdata.getiterator('param'):
            if not parameters:
                addLine("header",3,"Parameters","")
                parameters = True
            addLine("list",1,param.get('name'),"N/A")
            addLine("list",2,"Description:",param.get('description'))
            addLine("list",2,"Default Value:",param.get('defaultvalue'))

        addLine("header",3,"Rules","")

        # Parse CDATA element and print correlation rule match blocks
        for r in cdata.getiterator('rule'):
            # initialize variables
            o = ""
            v = ""
            t = ""
            override = ""
            parent = ""
            matchtype = ""

            # Walk through all rules except Root Rule
            if not r.get('name') == "Root Rule":
                addLine("header",4,r.get('name').title().replace("_", " "),"")
                override = r.get('correlationField')
                for e in r.iter():
                    if str(e.tag) == 'activate':
                        addLine("list",1,"Activate:",e.get('type'))
                        if override:
                            addLine("list",1,"Override Group By:",override)
                    if str(e.tag) == 'action':
                        if e.get('type') == "TRIGGER":
                            addLine("list",1,"Action:","Trigger")
                            # Find parent trigger of current rule
                            for trigger in cdata.getiterator('trigger'):
                                if e.get('trigger') == trigger.get('name'):
                                    parent = trigger.get('name')
                                    addLine("list",2,"Timeout:",trigger.get('timeout'))
                                    addLine("list",2,"Time Units:",trigger.get('timeUnit'))
                                    addLine("list",2,"Threshold:",trigger.get('threshold'))
                                    addLine("list",2,"Sequence:",trigger.get('ordered'))
                        else:
                            addLine("list",1,"Action","N/A")
                            addLine("list",2,"NOT IMPLEMENTED","N/A")
                    if str(e.tag) == 'match':
                        matchtype = e.get('matchType')
                        addLine("list",1,"Match Type:",matchtype)
                        addLine("list",2,"Count:",e.get('count'))
                    if str(e.tag) == 'matchFilter':
                        addLine("list",1,"Match Filter","N/A")
                    if str(e.tag) == 'singleFilterComponent':
                        t = e.get('type')
                    if str(e.tag) == 'filterData':
                        if (e.get('name') == "operator"):
                            o = e.get('value')
                        if (e.get('name') == "value"):
                            v = e.get('value')
                    if o and v and t:
                        addLine("list",2,"Filter Component","N/A")
                        addLine("list",3,"Condition:","'" + t + "' " + o + " '" \
                                + v + "'")
                        # Set nice label, add rule as graphviz node,
                        # add edge between trigger and node
                        label = t + r"\n" + o + r"\n" + v
                        v = ""
                        o = ""
                    if matchtype == "REFERENCE":
                        shapecol="blue"
                    else:
                        shapecol="orange"
                    if parent and r.get('name'):
                        nicename = r.get('name').title().replace("_", " ")
                        dMatchBlocks[nicename] = {'parent': parent, 'shapecol': shapecol}

        mklines.append("\n\\newpage\n")

        generateGraph(cdata,dMatchBlocks,rule.findtext('id'))


# Main function
if __name__=="__main__":

    if len(sys.argv) != 3:
        print('Invalid Numbers of Arguments. Script will be terminated.')
        print('Usage: python esm2markdown <rule xml file> <output file>')
        print('Example: python esm2markdown RuleExport.xml documentation.mk')
    else:
        readConfig()
        if validateXML(sys.argv[1]) == True:
            parseXML(sys.argv[1])
            writeMarkdownFile(sys.argv[2])
