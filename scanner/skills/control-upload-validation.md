---
name: control-upload-validation
description: What a real control for CWE-434 looks like (file upload validation) and when it dominates the sink — for the Critic
cwes: [CWE-434]
role: critic
---
# Control: file upload validation

## Control
Extension allow-list (double-extension safe), content-type AND magic-byte check, generated filename, size limit, storage outside the web root or on a separate origin, no execute permissions.

## Grep
- Go: `filepath\.Ext\(` + `switch ext`, `http\.DetectContentType`, `MaxBytesReader|io\.LimitReader`, `uuid\.New` in the name
- Python: `secure_filename`, `imghdr|magic\.from_buffer`, `MAX_CONTENT_LENGTH`, `FileExtensionValidator`
- Node/TS: `multer\(\{.*limits`, `fileFilter`, `file-type` magic check, generated `filename`

## Dominates when
1. every control applies to the same upload path.
2. the stored path is generated, not user-supplied.
3. the storage directory is not served with execution.

## Not a control
- client-side `accept=` attribute.
- content-type header trust alone.
- extension check without magic bytes.

## Cite as
Call `check_dominance(file, sink_line, control_line)` first; only if it returns `dominates: true`, call `disprove_finding(finding_id, counter_evidence=[the control line(s) exactly as read], reason="<control> dominates the sink")`. Otherwise keep the finding and note why the control does not cover the path.

## Remediation
Validate extension and content, rename, limit size, store outside the web root. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
