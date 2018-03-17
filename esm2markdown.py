#!/usr/bin/env python
import sys
from lxml import etree


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
		ruleid = "* Rule ID: " + rule.findtext('id')
		file.write(ruleid +"\n")
		normalization = "* Normalization ID: " + rule.findtext('normid')
		file.write(normalization + "\n")
		severity = "* Severity: " + rule.findtext('severity')
		file.write(severity + "\n")
		for tags in rule.getiterator('tag'):
			file.write("* Tag: " + tags.text + "\n")
		for rs in cdata.getiterator('ruleset'):
			correlationField = "* Group By: " + rs.get('correlationField')
			file.write(correlationField + "\n")
		file.write("## Correlation Details\n")
		# Print rule parameters
		file.write("### Parameters\n")
		for param in cdata.getiterator('param'):
			file.write("* Name: " + param.get('name') + "\n")
			file.write("  - Description: " + param.get('description') + "\n")
			file.write("  - Default Value: " + param.get('defaultvalue') + "\n")
		# Print trigger information (Sequence, Timeout, Time Unit, Threshold)
		file.write("### Trigger\n")
		for trigger in cdata.getiterator('trigger'):
			if (trigger.get('name')):
				file.write("* Name: " + trigger.get('name') + "\n")
				file.write("  - Timeout: " + trigger.get('timeout') + "\n")
				file.write("  - Time Unit: " + trigger.get('timeUnit') + "\n")
				file.write("  - Threshold: " + trigger.get('threshold') + "\n")
				if (trigger.get('ordered')):
					file.write("  - Sequence: " + trigger.get('ordered') + "\n")
		file.write("### Rules\n")
		# Parse CDATA element and print correlation rule match blocks
		for r in cdata.getiterator('rule'):
			file.write("#### " + r.get('name') + "\n")
			for e in r.iter():
				if str(e.tag) == 'activate':
					file.write("* Activate: ")
					if (e.get('type')):
						file.write(e.get('type') + "\n")
				if str(e.tag) == 'action':
					file.write("* Action: \n")
					if (e.get('type')):
						file.write("  - Type: " + e.get('type') + "\n")
					if (e.get('trigger')):
						file.write("  - Trigger: " + e.get('trigger') + "\n")
				if str(e.tag) == 'match':
					file.write("* Match: \n")
					if (e.get('count')):
						file.write("  - Count: " + e.get('count') + "\n")
					if (e.get('matchType')):
						file.write("  - Match Type: " + e.get('matchType') + "\n")
				if str(e.tag) == 'matchFilter':
					file.write("* Match Filter: \n")
					if (e.get('type')):
						file.write("  - Logical Element Type: " + e.get('type') + "\n")
				if str(e.tag) == 'singleFilterComponent':
					if (e.get('type')):
						file.write("  - Filter Component \n    - Type: " + e.get('type') + "\n")
				if str(e.tag) == 'filterData':
					if (e.get('name') == "operator"):
						file.write("    - Operator: " + e.get('value') + "\n")
					if (e.get('name') == "value"):
						file.write("    - Value: " + e.get('value') + "\n")
		file.write("******\n")
	file.close()

if __name__=="__main__":
	if len(sys.argv) != 3:
		print('Invalid Numbers of Arguments. Script will be terminated.')
		print('Usage: python esm2markdown <rule xml file> <markdown output file>')
		print('Example: python esm2markdown RuleExport_2018_03_01_12_36_37.xml documentation.mk')
	else:
		main(sys.argv[1],sys.argv[2]);
