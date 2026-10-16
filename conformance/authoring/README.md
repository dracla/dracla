These are source-test authoring inputs, including the independent goldens from
M1-1 through M1-11. They are not installed package data. Every key, nonce, clock
and identity here is a fixed test input. Never use these values in production.

`build.py` invokes the current authoring modules to rebuild calculated fields.
The original text supplies formatting and independent expected values. If the
rebuilt value equals the original, its original formatting is retained. A
changed result is emitted with ordinary JSON formatting and fails `--check`.
The original tests continue to compare the independent goldens with behavior.
Neither generation nor checking reads expected results from the destination.

`relocation-v1.json` records the original eleven file digests at the M1-11 base.
The shared manifest records current output digests, versions, owners and case
identities. Transition cases use complete canonical replay and full reference
materializers at both ends. No incremental updater is an oracle here.
