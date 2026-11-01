---
artifact: swe-design-review-attestation
schema_version: 6
scope_key: 202f0bb5683e170f68f1ef7a879d35208c809c529b0d397d2dcbc26cd6e54d01
scope: {"kind": "path", "primary_target": "design/lld/m3-control-reconciler.md", "repository": ".", "selector": "design/lld/m3-control-reconciler.md"}
review_content_identity_sha256: 7f64138fb5194d44228b70f83fab9de3fe8dca26196a45331dd90db3ddf8953f
target_content_identity_sha256: 0b9f7db6d2bef672ceadf3b2684123d285d5dcf47c7c0f62bcc9795b1b2342df
baseline_content_identity_sha256: 7711f34330fefd8ab5d215c3c1feb43c37afafedf044585b12bcbf43d8221152
target_documents: [{"executable": false, "path": "design/lld/m3-control-reconciler.md", "repository": ".", "sha256": "3d4bb7e0b9b91763b1a60688528eecd406041a80ec8e091c3f2f2fcbf0f71fa4"}]
baseline_documents: [{"executable": false, "path": "design/high-level-design.md", "repository": ".", "sha256": "fd76a3345e9fbafed9909e2bc64bccd947b32d171972f3ca90e32039a9d4110e"}, {"executable": false, "path": "design/lld/m1-conformance-kernel.md", "repository": ".", "sha256": "f29e26200dca12869aee89609d7136138992f34454697be95f1cbd70ed949e6a"}, {"executable": false, "path": "design/requirements.md", "repository": ".", "sha256": "eb04181fabcade4a8bc807795b1fba70a012eb935dca2a6d84eca952b3c067df"}]
design_dependency_documents: [{"executable": false, "path": "design/high-level-design.md", "repository": ".", "sha256": "fd76a3345e9fbafed9909e2bc64bccd947b32d171972f3ca90e32039a9d4110e"}, {"executable": false, "path": "design/lld/m1-conformance-kernel.md", "repository": ".", "sha256": "f29e26200dca12869aee89609d7136138992f34454697be95f1cbd70ed949e6a"}, {"executable": false, "path": "design/requirements.md", "repository": ".", "sha256": "eb04181fabcade4a8bc807795b1fba70a012eb935dca2a6d84eca952b3c067df"}]
plan_binding: {"base_revision": "95fbea79ccd119ce6bce3f4a42123d12860f39dc", "documents": [{"executable": false, "path": "design/lld/m3-control-reconciler.md", "plan_key": "m3", "sha256": "3d4bb7e0b9b91763b1a60688528eecd406041a80ec8e091c3f2f2fcbf0f71fa4", "slice_convention": "hierarchical-v1"}], "predecessors": [{"executable": false, "path": "design/lld/m3-control-reconciler.md", "sha256": "eb25804e898db10a624b19998ef105ab2b8e8226be920b76933f996bd8a64f69"}]}
security_review: {"actual": "dbb", "binding_identity_sha256": "25025e32a4472ff4516ba4bb72d74c4897c838f5c6a081a73a01c0e7a2a1b07d", "requested": "dbb", "reviewer": "/root/pr62_narrative_design_dbb", "schema_version": 1}
document_repository: "."
document_path: "design/lld/m3-control-reconciler.md"
document_revision_provenance: "95fbea79ccd119ce6bce3f4a42123d12860f39dc"
document_sha256: 3d4bb7e0b9b91763b1a60688528eecd406041a80ec8e091c3f2f2fcbf0f71fa4
verdict: clean
attested_at: 2026-11-02T01:09:55Z
---
<!-- swe-design-review-attestation:v6 -->

# SWE design-review attestation

Review freshness binds target and baseline document bytes and executable state
listed in the version-6 header. Revisions are provenance only.

## Durable review state

No standing rejected or deferred decisions.
