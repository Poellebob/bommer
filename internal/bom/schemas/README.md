# Embedded CycloneDX schemas

Original, unmodified schema artifacts from CycloneDX/specification, release tag
`1.7`, commit `4b3f59453366e27c8073fd24e98bf21ef8892c8e`:

https://github.com/CycloneDX/specification/tree/4b3f59453366e27c8073fd24e98bf21ef8892c8e

Both BOM schema versions and their transitive JSON schema dependencies are
vendored here. `LICENSE` is the upstream license. `SHA256SUMS` records the exact
downloaded bytes. No schema is downloaded at runtime.

Each artifact was downloaded from
`https://raw.githubusercontent.com/CycloneDX/specification/4b3f59453366e27c8073fd24e98bf21ef8892c8e/schema/<filename>`;
`LICENSE` comes from the repository root at the same revision.

Reference closure:

- `bom-1.6.schema.json`: `spdx.schema.json`, `jsf-0.82.schema.json`.
- `bom-1.7.schema.json`: the above plus `cryptography-defs.schema.json`.
- These three dependencies have no further external schema references.
- Draft-07 metaschemas are embedded in the pinned `jsonschema/v6` dependency.

The Apache-2.0 license and original in-schema attribution comments are retained,
including the JSON Signature Format/OpenKeyStore attribution to Anders Rundgren
and the model-card attribution to TensorFlow Model Card Toolkit and VerifyML.
The SPDX file is the upstream license identifier enumeration, not license texts.

To check artifact integrity from this directory: `sha256sum -c SHA256SUMS`.
