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

style="**"

def main(xmlfile,outfile):

	file = open(outfile,"w")
	root = etree.parse(xmlfile)

	for rule in root.getiterator('rule'):
		# Get CDATA
		text = rule.findtext('text')
		cdata = etree.fromstring(text)
		# Print rule name as header
		message = "# " + rule.findtext('message')
		file.write(message + "\n")
		# Print rule description
		description = rule.findtext('description')
		file.write("## Description\n")
		file.write(description +"\n")
		# Print general rule information (ID, Normalization, Severity, all Tags, Group By)
		file.write("## General Information\n")
		ruleid = "* " + style + "Rule ID:" + style + " " + rule.findtext('id')
		file.write(ruleid +"\n")
		normalization = "* " + style + "Normalization ID:" + style + " " + rule.findtext('normid')
		file.write(normalization + "\n")
		severity = "* " + style + "Severity:" + style + " " + rule.findtext('severity')
		file.write(severity + "\n")
		for tags in rule.getiterator('tag'):
			file.write("* " + style + "Tag:" + style + " " + tags.text + "\n")
		for rs in cdata.getiterator('ruleset'):
			correlationField = "* " + style + "Group By:" + style + " " + rs.get('correlationField')
			file.write(correlationField + "\n")
		file.write("## Correlation Details\n")
		# Print rule parameters
		file.write("### Parameters\n")
		for param in cdata.getiterator('param'):
			if (param.get('name')):
				file.write("* " + style + param.get('name') + style + "\n")
				file.write("  - " + style + "Description:" + style + " " + param.get('description') + "\n")
				file.write("  - " + style + "Default Value:" + style + " " + param.get('defaultvalue') + "\n")
		# Print trigger information (Sequence, Timeout, Time Unit, Threshold)
		file.write("### Trigger\n")
		for trigger in cdata.getiterator('trigger'):
			if (trigger.get('name')):
				file.write("* " + style + trigger.get('name') + style + "\n")
				file.write("  - " + style + "Timeout:" + style + " " + trigger.get('timeout') + " " + trigger.get('timeUnit') + "\n")
				file.write("  - " + style + "Threshold:" + style + " " + trigger.get('threshold') + "\n")
				if (trigger.get('ordered')):
					file.write("  - " + style + "Sequence:" + style + " " + trigger.get('ordered') + "\n")
		file.write("### Rules\n")
		# Parse CDATA element and print correlation rule match blocks
		for r in cdata.getiterator('rule'):
			o = ""
			v = ""
			t = ""
			file.write("#### " + r.get('name') + "\n")
			for e in r.iter():
				if str(e.tag) == 'activate':
					file.write("* " + style + "Activate:" + style + " ")
					if (e.get('type')):
						file.write(e.get('type') + "\n")
				if str(e.tag) == 'action':
					file.write("* " + style + "Action:" + style + " \n")
					if (e.get('type')):
						file.write("  - " + style + "Type:" + style + " " + e.get('type') + "\n")
					if (e.get('trigger')):
						file.write("  - " + style + "Trigger:" + style + " " + e.get('trigger') + "\n")
				if str(e.tag) == 'match':
					file.write("* " + style + "Match:" + style + " \n")
					if (e.get('count')):
						file.write("  - " + style + "Count:" + style + " " + e.get('count') + "\n")
					if (e.get('matchType')):
						file.write("  - " + style + "Match Type:" + style + " " + e.get('matchType') + "\n")
				if str(e.tag) == 'matchFilter':
					file.write("* " + style + "Match Filter:" + style + " \n")
					if (e.get('type')):
						file.write("  - " + style + "Logical Element Type:" + style + " " + e.get('type') + "\n")
				if str(e.tag) == 'singleFilterComponent':
					if (e.get('type')):
						t = e.get('type')
				if str(e.tag) == 'filterData':
					if (e.get('name') == "operator"):
						o = e.get('value')
					if (e.get('name') == "value"):
						v = e.get('value')
				if o and v and t:
					file.write("  - " + style + "Filter Component" + style + " \n")
					file.write("    - " + style + "Condition:" + style + " '" + t + "' " + o + " '" + v + "' \n")
		file.write("******\n")
	file.close()

if __name__=="__main__":
	if len(sys.argv) != 3:
		print('Invalid Numbers of Arguments. Script will be terminated.')
		print('Usage: python esm2markdown <rule xml file> <markdown output file>')
		print('Example: python esm2markdown RuleExport_2018_03_01_12_36_37.xml documentation.mk')
	else:
		main(sys.argv[1],sys.argv[2]);
