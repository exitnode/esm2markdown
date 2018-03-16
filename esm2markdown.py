#!/usr/bin/env python
import sys
from lxml import etree


def main(xmlfile,outfile):

	file = open(outfile,"w")
	root = etree.parse(xmlfile)

	for rule in root.getiterator('rule'):
		text = rule.findtext('text')
		cdata = etree.fromstring(text)
		message = "# " + rule.findtext('message')
		file.write(message + "\n")
		description = rule.findtext('description')
		file.write("## Description\n")
		file.write(description +"\n")
		file.write("## General Information\n")
		ruleid = "* Rule ID: " + rule.findtext('id')
		file.write(ruleid +"\n")
		normalization = "* Normalization ID: " + rule.findtext('normid')
		file.write(normalization + "\n")
		severity = "* Severity: " + rule.findtext('severity')
		file.write(severity + "\n")
		if (rule.findtext('tag')):
			tag = "* Tag: " + rule.findtext('tag')
			file.write(tag + "\n")
		for x in cdata.getiterator('ruleset'):
			correlationField = "* Group By: " + x.get('correlationField')
		file.write(correlationField + "\n")
		file.write("## Correlation Details\n")
		file.write("### Parameters\n")
		for p in cdata.getiterator('param'):
			file.write("* Name: " + p.get('name') + "\n")
			file.write("  - Description: " + p.get('description') + "\n")
			file.write("  - Default Value: " + p.get('defaultvalue') + "\n")
		file.write("### Trigger\n")
		for t in cdata.getiterator('trigger'):
			if (t.get('ordered')):
				trigger_ordered = "* Ordered: " + str(t.get('ordered'))
				file.write(trigger_ordered + "\n")
			if (t.get('timeout')):
				trigger_timeout = "* Timeout: " + str(t.get('timeout'))
				file.write(trigger_timeout + "\n")
			if (t.get('timeUnit')):
				trigger_timeunit = "* Timeunit: " + str(t.get('timeUnit'))
				file.write(trigger_timeunit + "\n")
			if (t.get('threshold')):
				trigger_threshold = "* Threshold: " + str(t.get('threshold'))
				file.write(trigger_threshold + "\n")
		file.write("### Rules\n")
		# Parse CDATA element
		for r in cdata.getiterator('rule'):
			file.write("#### Name: " + r.get('name') + "\n")
			for e in r.iter():
				op = ""
				type = ""
				value = ""
				if str(e.tag) == 'match':
					file.write("* Match: \n")
					if (e.get('count')):
						file.write("  - Count: " + e.get('count') + "\n")
					if (e.get('matchType')):
						file.write("  - Match Type: " + e.get('matchType') + "\n")
				if str(e.tag) == 'matchFilter':
					file.write("* Match Filter: \n")
					if (e.get('type')):
						file.write("  - Type: " + e.get('type') + "\n")
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
