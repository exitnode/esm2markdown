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


# Read configuration from ini file
config = ConfigParser()
config.read('esm2markdown.ini')

key_style = config.get('config', 'key_style')
value_style = config.get('config', 'value_style')
sort_rules = config.getboolean('config', 'sort_rules')
toc = config.getboolean('config', 'toc')
images = config.getboolean('config', 'images')
imagepath = config.get('config', 'imagepath')


# Generates a line containing linebreaks, indented lists, styles etc.
def line(level,key,value):

    lvl = ""	
    output = ""
    valout = ""

    if level == 1: lvl = "*   "
    elif level == 2: lvl = "    * "
    elif level == 3: lvl = "        * "
    else: lvl = ""

    if key:
        if value == "N/A": output = lvl + key_style + key + key_style + "\n"
        elif value: output = lvl + key_style + key + key_style + " " + \
                value_style + value + value_style + "\n"
        else: output = ""

    output = re.sub('\$\$$',"]",output)
    output = re.sub('\$\$',"PARAMETER:[",output)
    return output


# Sorts input XML alphabetically based on Rule Names
def sortxml(xmlfile):

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

# Generate Markdown Syntax for Images
def addimage(rulename):
    
    out = ""
    imagefile = imagepath + "/" + rulename + ".png"
    imagefile = imagefile.replace(" ", "_")
    if (os.path.isfile(imagefile)):
        out = "![](" + imagefile + ")\n\n\n"
    return out

# Main Function
def main(xmlfile,outfile):

    file = open(outfile,"w")

    if sort_rules:
        root = sortxml(xmlfile)
    else:
        root = etree.parse(xmlfile)

    if toc:
        file.write("\n# Correlation Rule Overview\n\n")
        for rule in root.getiterator('rule'):
            file.write(line(1,rule.findtext('message'),"N/A"))

    for rule in root.getiterator('rule'):
        # Get CDATA
        text = rule.findtext('text')
        cdata = etree.fromstring(text)
        # Print rule name as header
        rulename = rule.findtext('message')
        file.write("\n# " + rulename + "\n")
        # Print rule description
        description = rule.findtext('description')
        file.write("\n## Description\n")
        file.write(description +"\n")
        # Print rule information (ID, Normalization, Severity, Tags, Group By)
        file.write("\n## General Information\n")
        file.write(line(1,"Rule ID:",rule.findtext('id')))
        file.write(line(1,"Normalization ID:",rule.findtext('normid')))
        file.write(line(1,"Severity:",rule.findtext('severity')))
        for tags in rule.getiterator('tag'):
            file.write(line(1,"Tag:",tags.text))
        for rs in cdata.getiterator('ruleset'):
            file.write(line(1,"Group By:",rs.get('correlationField')))
        file.write("\n## Correlation Details\n")
        if images:
            file.write(addimage(rulename))
        parameters = False
        # Print rule parameters
        for param in cdata.getiterator('param'):
            if not parameters:
                file.write("\n### Parameters\n")
                parameters = True
            file.write(line(1,param.get('name'),"N/A"))
            file.write(line(2,"Description:",param.get('description')))
            file.write(line(2,"Default Value:",param.get('defaultvalue')))
        file.write("\n### Rules\n")
        # Parse CDATA element and print correlation rule match blocks
        for r in cdata.getiterator('rule'):
            o = ""
            v = ""
            t = ""
            if not r.get('name') == "Root Rule":
                file.write("\n#### " + r.get('name') + "\n")
                for e in r.iter():
                    if str(e.tag) == 'activate':
                        file.write(line(1,"Activate:",e.get('type')))
                    if str(e.tag) == 'action':
                        if e.get('type') == "TRIGGER":
                            file.write(line(1,"Action:","Trigger"))
                            for trigger in cdata.getiterator('trigger'):
                                if e.get('trigger') == trigger.get('name'):
                                    file.write(line(2,"Timeout:",trigger.get('timeout')))
                                    file.write(line(2,"Time Units:",trigger.get('timeUnit')))
                                    file.write(line(2,"Threshold:",trigger.get('threshold')))
                                    file.write(line(2,"Sequence:",trigger.get('ordered')))
                        else:
                            file.write(line(1,"Action","N/A"))
                            file.write(line(2,"NOT IMPLEMENTED","N/A"))
                    if str(e.tag) == 'match':
                        file.write(line(1,"Match Type:",e.get('matchType')))
                        file.write(line(2,"Count:",e.get('count')))
                        #file.write(line(2,"Match Type:",e.get('matchType')))
                    if str(e.tag) == 'matchFilter':
                        file.write(line(1,"Match Filter:",e.get('type').upper()))
                        #file.write(line(2,"Logical Element Type:",e.get('type').upper()))
                    if str(e.tag) == 'singleFilterComponent':
                        t = e.get('type')
                    if str(e.tag) == 'filterData':
                        if (e.get('name') == "operator"):
                            o = e.get('value')
                        if (e.get('name') == "value"):
                            v = e.get('value')
                    if o and v and t:
                        file.write(line(2,"Filter Component","N/A"))
                        file.write(line(3,"Condition:","'" + t + "' " + o + " '" \
                                + v + "'"))
                        v = ""
                        o = ""
        file.write("\n\\newpage\n")
    file.close()

if __name__=="__main__":
    if len(sys.argv) != 3:
        print('Invalid Numbers of Arguments. Script will be terminated.')
        print('Usage: python esm2markdown <rule xml file> <output file>')
        print('Example: python esm2markdown RuleExport.xml documentation.mk')
    else:
        main(sys.argv[1],sys.argv[2]);
