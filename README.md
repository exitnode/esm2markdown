# esm2markdown

This python script is intended to be used to automatically generate use case / correlation rule documentation in Markdown format for the McAfee Enterprise Sceurity Manager (ESM). It accepts a XML file that has been exported from the correlation rule editor of the ESM, converts its contents to Markdown format and writes it into a new file. If you need any other format, you might want to use pandoc to convert to e.g. pdf, docx or HTML.

## Requirements

This tool requires the following:
* Python 3
* lxml (XML parser that understands CDATA)
* networkx (needed for creating graphs)
* pydot (needed for creating graphs)
* pandoc (for converting to other formats than Markdown)


On Debian you can install the dependencies with "sudo apt-get install python3-lxml python3-networkxi python3-pydot"

## Usage

Please configure esm2markdown.ini to your liking and execute esm2markdown.py like this:

```
# python esm2markdown.py <rule xml file> <markdown output file>
```

## Example

### Convert xml to Markdown

```
# python esm2markdown demo.xml demo.mk
```

### Convert to Markdown to DOCX

```
# pandoc -s demo.mk -o demo.docx
```

In the end, the result should look like this shortened output:


![screenshot](demo/demo.png "")
[...]
