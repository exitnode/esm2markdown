# esm2markdown

This python script is intended to be used to automatically generate use case / correlation rule documentation in Markdown format for the McAfee Enterprise Sceurity Manager (ESM). It accepts a XML file that has been exported from the correlation rule editor of the ESM, converts its contents to Markdown format and writes it into a new file. If you need any other format, you might want to use pandoc to convert to e.g. pdf, docx or HTML.

## Requirements

This tool requires lxml (https://github.com/lxml/lxml).
On Debian you can install it with "sudo apt-get install python3-lxml"

## Usage

```
python esm2markdown <rule xml file> <markdown output file>
```

## Example

```
python esm2markdown RuleExport_2018_03_01_12_36_37.xml documentation.mk
```
