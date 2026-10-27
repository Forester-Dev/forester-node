# Security

forester-node holds other people's data, so security reports are taken seriously and handled first.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Instead, report it privately:

- through GitHub: the **Security** tab of this repository, then **Report a vulnerability**, or
- by email to **security@forester.dev**

Include what you found, how to reproduce it, and what an attacker could do with it. You will get an acknowledgement within a few days. Please give us a reasonable time to ship a fix before disclosing publicly; we will credit you in the release notes unless you prefer otherwise.

## What is in scope

- The node binary and its installer in this repository
- The node's wire protocol ([PROTOCOL.md](PROTOCOL.md)): capabilities, the control link, storage proofs, direct transfers and signed updates

Especially interesting: anything that lets someone read data a node holds, make a node act on an instruction the control plane did not sign, install an update not signed by the release key, or reach the machine running a node.

The share.forester.dev website and API are run separately; report problems with them to the same address.
