# Security Policy

## Scope and intended use

Frida-ShieldBreaker is a dynamic analysis and instrumentation framework.
Like Frida itself, its hooking and bypass capabilities are dual-use: the
same code that lets a researcher verify their own app's root-detection
logic can be pointed at a system the operator has no right to test.

This project is intended **only** for:

- Security research on applications you own or maintain.
- Engagements where you hold explicit, written authorization to test the
  target (e.g. a penetration test statement of work, a bug bounty program's
  published scope, or a CTF competition's rules).
- Educational and defensive-security use — understanding detection and
  protection techniques in order to build better ones.

Using this project against systems without authorization may violate
computer-crime law in your jurisdiction and the target's terms of service.
The maintainers do not condone, and take no responsibility for, unauthorized
use.

## Reporting a vulnerability in this project

If you find a security issue in Frida-ShieldBreaker itself — for example, a
flaw that could let an instrumented process execute unintended code on the
analyst's host, corrupt IPC in a way that's exploitable rather than merely
buggy, or a supply-chain concern in a pinned dependency — please report it
privately rather than opening a public issue:

1. Prefer **GitHub's private vulnerability reporting** (the "Report a
   vulnerability" button under this repository's Security tab), which opens
   a private advisory visible only to the maintainers until a fix is ready.
2. If that isn't available to you, open an issue asking a maintainer to
   provide a private contact channel — please do not include exploit
   details in the public issue itself.

Please include:

- A clear description of the issue and its potential impact.
- Steps to reproduce, or a minimal proof of concept.
- The affected version/commit and your environment (OS, Frida version,
  target platform if relevant).

## What to expect

- We aim to acknowledge new reports within a few days.
- We'll work with you to understand and reproduce the issue, and to agree
  on a reasonable disclosure timeline before any public write-up.
- Credit is given in the changelog/release notes unless you'd prefer to
  remain anonymous.

## Out of scope

Detection bypasses succeeding against a *specific third-party application*
are not, by themselves, a vulnerability in this project — that's the
framework doing its intended job against a target you're authorized to
test. Please don't file reports naming specific third-party apps, package
identifiers, or organizations; discuss techniques generically instead.
