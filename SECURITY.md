# Security policy

## Reporting a vulnerability

Report security problems privately through GitHub's
[private vulnerability reporting](https://github.com/JohanLindvall/enrich/security/advisories/new)
(the **Security** tab → **Report a vulnerability**), not in a public issue or
pull request. A private report reaches only the maintainer, so the fix and its
advisory can be prepared before anything is disclosed.

Include the input that triggers the problem (the log line, or the bytes passed
to `ParseBytes`), the version or commit you tested, and what you observed.
Scrub anything sensitive out of a real log line first.

## Scope

Parsing untrusted input is this package's job: a log line says whatever its
producer, or whoever controls that producer's input, made it say. So these are
vulnerabilities, not ordinary bugs:

- an input that makes `Parse`, `ParseInto` or `ParseBytes` panic;
- an input that makes a call take time or memory super-linear in the length of
  the line;
- any memory-safety problem. The package aliases the input through `unsafe`
  instead of copying it, so a result field that reads memory outside the input
  is in scope.

A wrong result — a misread timestamp, a level the producer did not mean, a
missed trace ID — is a bug; open an ordinary issue for it.

The JSON decoder and the logfmt scanner come from
[lightning](https://github.com/JohanLindvall/lightning) and
[logfmt](https://github.com/JohanLindvall/logfmt), by the same author. A problem
whose cause turns out to be in one of them can still be reported here.

## Supported versions

The module is pre-1.0, and CI tags a new patch version on every green build of
`main`. Fixes land on `main` and ship in the next tag; only the latest version
is supported.
