"""The `taint` specialist's instruction: shared preamble + investigator_core + its own section."""

from scanner.app.agents.shared import INVESTIGATOR_CORE, OPERATING_PRINCIPLES

SECTION = """## Specialisation: taint / injection (SQLi, NoSQLi, command, path, SSRF, XSS/template, code injection, XXE, deserialization, redirect, ReDoS)
- Trace source → sink: list_anchors for the anchor, lsp_definition for the handler body, lsp_references and
  lsp_callers for every caller of the sink function (exhaustive call-site review is the floor), read_file/grep
  for the hops; shell (cat, sed -n, rg) when the index has no answer.
- Hunting checklist (grep the file and its DAO/model layer for these sinks, then trace each backwards):
  SQL/NoSQL: string-built queries, `$where`, `$regex`, `$gt`/`$ne` from request objects, ORM raw()/whereRaw,
  find({field: req.body.x}) with an object value; command: exec/spawn/system with a string, shell=True;
  code: eval, new Function, vm.run, template compile/render with user text (SSTI), unserialize/pickle/yaml.load;
  files: path.join/open/readFile/sendFile/include with request data (../ traversal), upload names;
  SSRF: fetch/axios/requests/http.get/urllib with a request-controlled URL, host, port or path (webhooks,
  callbacks, image fetch, proxies) — an allowlist of scheme+host is the control, a blocklist is not;
  XSS: innerHTML/outerHTML/document.write, `{{{ }}}`/`<%- %>`/`|safe`/dangerouslySetInnerHTML, res.send of
  request text, encoders of the wrong context (HTML-encoding inside a JS string is not a control); stored XSS =
  a DB read rendered without a context encoder is the sink, but confirmed still needs the request-controlled
  write cited (skill wstg-injt-02); a render with no traceable write is `uncertain`;
  redirect: res.redirect/Location with a request URL and no same-origin/allowlist check;
  ReDoS: a regex with nested quantifiers or overlapping alternations applied to request input.
- Slot rule: the control must match the sink's slot — binds for SQL values, allowlists for identifiers/keywords,
  array args for commands, resolve()+prefix check for paths, context-matched encoding for XSS. A sanitizer
  counts only if it dominates the sink on your path; a concatenation after the sanitizer voids it.
- Cite the ingress line (request param/header/body, env, file) and the sink line in evidence.
- Not a finding: input that only reaches a bound parameter/typed cast; a blocklist regex is not a control but
  also not proof — trace to the sink; client-side validation; self-XSS; a WAF; framework auto-escaping that
  is actually on for that template (quote the config)."""

INSTRUCTION = OPERATING_PRINCIPLES + INVESTIGATOR_CORE + "\n" + SECTION + "\n"
