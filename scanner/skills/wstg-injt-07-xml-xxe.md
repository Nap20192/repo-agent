---
name: wstg-injt-07-xml-xxe
description: Use for CWE-91/CWE-611 (XML Injection): the static evidence that confirms it and the controls that reject it (WSTG WSTG-INJT-07)
cwes: [CWE-91, CWE-611]
wstg: WSTG-INJT-07
top10: A05:2025
---
# WSTG-INJT-07 — XML Injection (static verification)

Objective: find XML built from request data or parsed with external entities enabled.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: request body XML, uploaded XML/SVG/DOCX, SOAP payloads, or request values interpolated into XML text.
2. **Sink**: an XML parser configured to resolve external entities/DTDs, or XML text assembled with untrusted fragments: `lxml.etree.fromstring(data)` with resolve_entities, `libxmljs.parseXml(x, {noent: true})`, `xml.NewDecoder` with custom entity map, `Sprintf("<user>%s</user>", v)`.
3. **Missing control**: no `resolve_entities=False`/`no_network`, no DTD disabling, no XML-escaping of interpolated fragments.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- `defusedxml` is used, or the parser is built with entities/DTD disabled (`resolve_entities=False`, `noent: false`, `no_network=True`).
- Go `encoding/xml` (does not resolve external entities) and no custom entity handling.
- fragments are escaped with `xml.EscapeText` / `saxutils.escape` / a serializer builds the document.

## Not enough to confirm
- Go's standard decoder is safe by default: an XXE claim on `encoding/xml` needs a third-party parser or entity map to stand.
- parsing trusted config XML from disk is not a finding.

## Sinks by language
- Go: third-party parsers with entity expansion, `Sprintf` into XML.
- Python: `lxml.etree.XMLParser(resolve_entities=True)`, `xml.dom.minidom`/`sax` on untrusted input, `xml.etree` with DTD.
- Node/TS: `libxmljs` `noent: true`, `xmldom` with entity handling, `fast-xml-parser` with `processEntities`.

## False-positive traps
- a `DOCTYPE` in a test fixture is not evidence; cite the parser configuration at the sink.

Cite `owasp:WSTG-INJT-07` in evidence. Reference: OWASP WSTG WSTG-INJT-07; prevention: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
