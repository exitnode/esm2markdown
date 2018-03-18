#!/usr/bin/env python
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
from lxml import etree

# Configure here the style of keys and values e.g. to bold or italic.
# Default: Keys are displayed in bold, values have no specific style
key_style = "**"
value_style = ""

# Configure here how your lists will look like in Markdown
level1 = "*   "
level2 = "    * "
level3 = "        * "
    
# Configure here if Rules should be alphabetically sorted or not
sort_rules = True

# Configure TOC generation
toc = True

# Generates a line containing linebreaks, indented lists, styles etc.
def line(level,key,value):

    lvl = ""	
    output = ""
    valout = ""

    if level == 1: lvl = level1	
    elif level == 2: lvl = level2	
    elif level == 3: lvl = level3	
    else: lvl = ""

    if key:
        if value == "N/A": output = lvl + key_style + key + key_style + "\n"
        elif value: output = lvl + key_style + key + key_style + " " + \
                value_style + value + value_style + "\n"
        else: output = ""

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
        message = "\n# " + rule.findtext('message')
        file.write(message + "\n")
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
        parameters = False
        # Print rule parameters
        for param in cdata.getiterator('param'):
            if not parameters:
                file.write("\n### Parameters\n")
                parameters = True
            file.write(line(1,param.get('name'),"N/A"))
            file.write(line(2,"Description:",param.get('description')))
            file.write(line(2,"Default Value:",param.get('defaultvalue')))
        # Print trigger information (Sequence, Timeout, Time Unit, Threshold)
        triggers = False 
        for trigger in cdata.getiterator('trigger'):
            if not triggers:
                file.write("\n### Triggers\n")
                triggers = True
            file.write(line(1,trigger.get('name'),"N/A"))
            file.write(line(2,"Timeout:",trigger.get('timeout')))
            file.write(line(2,"Time Units:",trigger.get('timeUnit')))
            file.write(line(2,"Threshold:",trigger.get('threshold')))
            file.write(line(2,"Sequence:",trigger.get('ordered')))
        file.write("\n### Rules\n")
        # Parse CDATA element and print correlation rule match blocks
        for r in cdata.getiterator('rule'):
            o = ""
            v = ""
            t = ""
            file.write("\n#### " + r.get('name') + "\n")
            for e in r.iter():
                if str(e.tag) == 'activate':
                    file.write(line(1,"Activate:",e.get('type')))
                if str(e.tag) == 'action':
                    file.write(line(1,"Action","N/A"))
                    file.write(line(2,"Type:",e.get('type')))
                    file.write(line(2,"Trigger:",e.get('trigger')))
                if str(e.tag) == 'match':
                    file.write(line(1,"Match","N/A"))
                    file.write(line(2,"Count:",e.get('count')))
                    file.write(line(2,"Match Type:",e.get('matchType')))
                if str(e.tag) == 'matchFilter':
                    file.write(line(1,"Match Filter","N/A"))
                    file.write(line(2,"Logical Element Type:",e.get('type')))
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
