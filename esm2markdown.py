#!/usr/bin/env python
import sys
from lxml import etree


def main(xmlfile,outfile):

	file = open(outfile,"w")
	root = etree.parse(xmlfile)

	for rule in root.getiterator('rule'):

		message = "# " + rule.findtext('message')
		description = rule.findtext('description')
		normalization = "* Normalization ID: " + rule.findtext('normid')
		ruleid = "* Rule ID: " + rule.findtext('id')
		severity = "* Severity: " + rule.findtext('severity')
		tag = "* Tag: " + rule.findtext('tag')
		text = rule.findtext('text')
		cdata = etree.fromstring(text)
		for x in cdata.getiterator('ruleset'):
			correlationField = "* Group By: " + x.get('correlationField')
		for t in cdata.getiterator('trigger'):
			if (t.get('ordered')):
				trigger_ordered = "* Ordered: " + str(t.get('ordered'))
			if (t.get('timeout')):
				trigger_timeout = "* Timeout: " + str(t.get('timeout'))
			if (t.get('timeUnit')):
				trigger_timeunit = "* Timeunit: " + str(t.get('timeUnit'))
			if (t.get('threshold')):
				trigger_threshold = "* Threshold: " + str(t.get('threshold'))
			
		file.write(message + "\n")
		file.write("## Description\n")
		file.write(description +"\n")
		file.write("## General Information\n")
		file.write(ruleid +"\n")
		file.write(normalization + "\n")
		file.write(severity + "\n")
		file.write(tag + "\n")
		file.write(correlationField + "\n")
		file.write("## Correlation Details\n")
		file.write("### Parameters\n")
		for p in cdata.getiterator('param'):
			file.write("* Name: " + p.get('name') + "\n")
			file.write("  - Description: " + p.get('description') + "\n")
			file.write("  - Default Value: " + p.get('defaultvalue') + "\n")
		file.write("### Trigger\n")
		file.write(trigger_timeout + "\n")
		file.write(trigger_timeunit + "\n")
		file.write(trigger_threshold + "\n")
		file.write("### Rules\n")
		for r in cdata.getiterator('rule'):
			file.write("#### Name: " + r.get('name') + "\n")
			for e in r.iter():
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
						file.write("  - Filter Component - Type: " + e.get('type') + "\n")
				if str(e.tag) == 'filterData':
					if (e.get('name') == "value"):
						file.write("    - Value: " + e.get('value') + "\n")
					if (e.get('name') == "operator"):
						file.write("    - Operator: " + e.get('value') + "\n")
		file.write("******\n")
	file.close()

if __name__=="__main__":
	if len(sys.argv) != 3:
		print('Invalid Numbers of Arguments. Script will be terminated.')
		print('Usage: python esm2markdown <rule xml file> <markdown output file>')
		print('Example: python esm2markdown RuleExport_2018_03_01_12_36_37.xml documentation.mk')
	else:
		main(sys.argv[1],sys.argv[2]);
