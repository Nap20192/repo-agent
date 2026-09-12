---
name: wstg-injt-12-command-injection
description: Use for CWE-78/CWE-77/CWE-88 (Command Injection): the static evidence that confirms it and the controls that reject it (WSTG WSTG-INJT-12)
cwes: [CWE-78, CWE-77, CWE-88]
wstg: WSTG-INJT-12
top10: A05:2025
---
# WSTG-INJT-12 — Command Injection (static verification)

Objective: find OS commands built from request data and how arguments are passed.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: request value, filename, header, environment-derived value that a request can influence.
2. **Sink**: a shell is invoked with the value inside the command string: `exec.Command("sh", "-c", cmd)`, `os.system(cmd)`, `subprocess.*(cmd, shell=True)`, `child_process.exec(cmd)`, `execSync(`; or the value lands in argv of a program that interprets it (`--output=`, `-e`) — argument injection.
3. **Missing control**: the command is not a literal with the value as a separate argv element; no allow-list of the value; no `--` before positional args.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- `exec.Command(literal, arg1, arg2)`, `subprocess.run([literal, v])` without `shell=True`, `execFile`/`spawn` without `shell: true` — and the value is not an option-shaped string.
- the value passed an allow-list pattern (`^[A-Za-z0-9._-]{1,64}$`) before the call, or a library call replaces the shell (`os.MkdirAll` instead of `mkdir`).
- the command and all its arguments are constants.

## Not enough to confirm
- `shlex.quote` alone: neutralises shell metacharacters but not option injection (`-rf`).
- a command built from config values that no request reaches is hygiene.

## Sinks by language
- Go: `exec.Command`, `syscall.Exec`, `os/exec` with `sh -c`.
- Python: `os.system`, `os.popen`, `subprocess.*` with `shell=True`, `commands.getoutput`.
- Node/TS: `child_process.exec`, `execSync`, `spawn(..., {shell: true})`.

## False-positive traps
- `spawn('sh', ['-c', cmd])` is a shell even without `shell: true`.

Cite `owasp:WSTG-INJT-12` in evidence. Reference: OWASP WSTG WSTG-INJT-12; prevention: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
