---
artifact: swe-design-review-attestation
schema_version: 2
scope_key: 4db2ef9e8f4e757bdb28ee17e24742ec883bcf15304114f92b480b6e39de5b67
scope: {"kind": "path", "primary_target": "design/requirements.md", "repository": "/home/omry/dev/dracla", "selector": "design/requirements.md"}
review_content_identity_sha256: 9aa1967a174319ea9a723cfa1c629952eb08f2c27a4b80d190c1d6dac9cf51e7
target_content_identity_sha256: bbd9147031f632d4914c64d588f33d8e8a452b32b93ff817cf26234e9b5c89fa
baseline_content_identity_sha256: 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945
target_documents: [{"path": "design/requirements.md", "repository": "/home/omry/dev/dracla", "sha256": "1137ea5f33cd275203eba6cc2693604b524ff922e98cb8b39d0c9a2903ee9ba7"}]
baseline_documents: []
document_repository: "/home/omry/dev/dracla"
document_path: "design/requirements.md"
document_revision_provenance: "d8fab8098a68d68a208d37095415b1d6b02240e0"
document_sha256: 1137ea5f33cd275203eba6cc2693604b524ff922e98cb8b39d0c9a2903ee9ba7
verdict: clean
attested_at: 2026-08-22T09:36:18Z
---
<!-- swe-design-review-attestation:v2 -->

# SWE design-review attestation

Review freshness is determined by the target and baseline document bytes
listed in the version-2 header. Revisions are provenance only.

## Durable review state

## Standing decisions

### R9-1 — rejected — An in-flight old GitHub event can still publish a stale final pass

- Reason: Accepted risk: a merge-group check already in flight may finish against the routing snapshot from when it started during a rare administrator-driven repository rename or transfer. Do not add a mandatory final GitHub read to every merge. GitHub lifecycle events and reconciliation correct later checks; administrators requiring a clean cutover must stop merges before moving the repository.
- Actor: Omry
- Decided: 2026-08-22T09:30:09Z
