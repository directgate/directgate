# Security Policy

This document explains how to report a vulnerability and what is in scope for this repository.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Instead, use one of the following private channels:

- **GitHub Security Advisories** (preferred) - go to the
  [Security tab](https://github.com/directgate/directgate/security/advisories/new)
  of this repository and click *Report a vulnerability*.
- **Email** - [security@directgate.io](mailto:security@directgate.io).

To help us triage quickly, please include as much of the following as you can:

- A description of the issue and its potential impact
- The affected version, release, or commit hash
- Step-by-step instructions to reproduce
- Any proof-of-concept code, logs, or configuration
- Suggested remediation, if you have one

We will acknowledge your report as soon as we can, typically within a few
business days and keep you informed as we investigate and work on a fix. If you
report a valid vulnerability, we are happy to credit you in the advisory unless
you prefer to remain anonymous.

Please give us a reasonable amount of time to release a fix before any public
disclosure.

## Scope

This repository contains the **DirectGate agent** - the open-source component that
runs on your own machines. Reports about the agent's code, cryptography, protocol
handling, and packaging belong here.

The DirectGate cloud infrastructure (API, relay/signaling service, account
management, and the web client) is operated separately by directgate.io and is
**not** part of this repository. Vulnerabilities in those services can also be
reported to [security@directgate.io](mailto:security@directgate.io); please note in
your report that the issue concerns the hosted service rather than the agent.

## Supported versions

Security fixes are issued for the latest released version of the agent. Install
from the official package repositories (or build the source from the latest tag)
so you receive updates through your normal system update process.

See the [README](../main/README.md#installation) for setup.

## Further reading

- [Security model](../main/docs/security.md) - cryptography, authentication, and trust assumptions
- [directgate.io/security](https://directgate.io/security) - threat model, trust assumptions, and FAQ
