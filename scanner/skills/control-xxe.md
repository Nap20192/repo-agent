---
name: control-xxe
description: What a real control for CWE-611/CWE-91 looks like (XML parser hardening) and when it dominates the sink — for the Critic
cwes: [CWE-611, CWE-91]
role: critic
---
# Control: XML parser hardening

## Control
External entities and DTDs are disabled on the parser that handles untrusted XML, or a hardened wrapper (`defusedxml`) is used; interpolated fragments are XML-escaped.

## Grep
- Go: `encoding/xml` (safe by default), `xml\.EscapeText`
- Python: `defusedxml`, `XMLParser\(resolve_entities=False`, `no_network=True`
- Node/TS: `libxmljs` `noent: false`, `fast-xml-parser` without `processEntities`, `xmldom` without entity handling

## Dominates when
1. the hardened parser is the one used at the sink.
2. the configuration is not overridden later for the same parser.

## Not a control
- input size limits.
- a schema validation after parsing.
- catching parser exceptions.

## Cite as
Call `check_dominance(file, sink_line, control_line)` first; only if it returns `dominates: true`, call `disprove_finding(finding_id, counter_evidence=[the control line(s) exactly as read], reason="<control> dominates the sink")`. Otherwise keep the finding and note why the control does not cover the path.

## Remediation
Disable DTD and external entity resolution; use defusedxml or equivalent. https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
