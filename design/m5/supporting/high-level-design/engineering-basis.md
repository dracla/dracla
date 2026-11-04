# M5 engineering basis

This supports the [current architecture](../../high-level-design.md) and later
engineering plan. It records source and feasibility evidence, not another
normative design or an implementation-progress ledger. Source inspection used
Sapling head `ec45c63ad01c197330702bbaefb2c5935333e688` and the exact current
reviewed M4/M5 requirements. Source-line counts include comments and blanks;
they are anchors, not estimated incremental delivered LOC.

## Current primitives and missing production work

| Source | Physical source lines | Reuse and gap |
|---|---:|---|
| `api/src/conformance/actionForms.ts` | 213 | Closed form types, JCS/HMAC, session/actor/digest/time binding and immutable terminal-no-op verification exist. Issuance, current authority, browser forms and runtime reads do not. |
| `api/src/conformance/derived.ts` | 323 | Selected private-class reads and full 32-shard reader-source validation exist. `resolveReadStatus` still requires a full coverage projection. M5 must reuse its semantics through an owned validated partial-coverage status adapter, alongside runtime acquisition, current generations and private-read proofs; do not fetch all 37 coverage members for every private page or add a second evaluator. |
| `api/src/conformance/events.ts` | 1,578 | Shared closed canonical event/artifact identities and operation mappings exist; use them rather than new public form event types. |
| `core/dracla/records/exports.py` | 580 | Actual current/historical rendering, encrypted request-scoped pairs, CSV safety and final reader checks exist. `export_hosted` requires a real `authenticate_request`/`is_team_member` provider; a saved principal or transport credential is rejected. |
| `core/dracla/records/history.py` | 425 | Authenticated bootstrap/history/key/source and reader semantics exist. It is not a browser-session or Worker replay implementation. |
| `core/dracla/administration.py` | 302 | Typed account/repository/authority observations and exact three-role scope exist. Local provisioning credentials are not credentials for the hosted portal. |
| `core/dracla/provisioning.py` | 255 | Provisioning descriptions and disclosures exist. They do not establish an installed live wrapping/Connect producer. |

The API package currently has TypeScript and Node conformance tests. There is
no production static portal, OAuth/session service or private-read/export
authority adapter. The approved parent layout uses `dashboard/` for the static
shell; M5's portal assets and M7's dashboard/badges extend that one asset tree.
No existing frontend framework needs to be retained or duplicated.

M4 owns the new real Worker/SQLite harness, bounded GitHub/credential clients,
crypto transport, route/gate coordinator, exact callback and shared durable
canonical writer. Those are reviewed future prerequisites, not shipped code.
M5 counts only its action-specific extensions and integrations. M3 supplies
full replay/recovery and actual export rendering, never a second edge replay.

## Existing numerical constraints

The checked-in M1 `core/dracla/conformance/release-profile-v1.json` fixes 32
shards, 49 subrequests, 3 mutation attempts, 512 members per reader source, 10
continuous reader rules and 32 continuous exemption rules. It also binds class
ciphertext/state/prepared-cell limits and bulk fanout. M5 must validate the
actual profile rather than copying looser constants into browser code.

The existing hosted exporter fixes 383,000 plaintext bytes per output, 512,000
encrypted bytes per output, 1,024,000 bytes per pair and 10,000 records. These
are existing ceilings, not evidence of hosted runtime or Actions acceptance.
M5 adds the authenticated job/delivery adapter and concrete time/message bounds;
M6 installs compatible protected code and M7 binds release evidence.

## Primary platform checks

Checked 3 November 2026:

- [GitHub App user-token flow](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)
  documents S256 PKCE, the exact callback/verifier exchange, returned expiry and
  the intersection of user and App access. Configure expiring tokens and use
  their actual expiry; do not treat the records App's user token as access to
  every repository the user administers. M5 retains the no-refresh policy.
- [Worker asset routing](https://developers.cloudflare.com/workers/static-assets/routing/worker-script/)
  supports selected Worker-first routes. OAuth callbacks and every API/internal
  operation must reach the Worker instead of an SPA navigation fallback.
  Ordinary public shell assets can remain static.
- [Asset bindings](https://developers.cloudflare.com/workers/static-assets/binding/)
  permit the approved single-origin shell/API deployment without another Worker.
  The separate agreement origin uses a strictly public host branch, never the
  portal API router or session cookies. Static delivery does not prove its
  security headers or browser isolation; executable browser checks are required.

These checks were public documentation reads, not authenticated account, OAuth,
credential or hosted probes. M4's existing basis owns common runtime/crypto/
resource references; M5 does not repeat that platform investigation.

## Direction and alternatives

Use the approved static shell and same-origin API. A new server-rendering path
or frontend framework adds no required capability. Agreement markup stays in
the already-required sandboxed cookieless origin, with allowlist sanitization
and CSP; a sanitizer alone cannot replace that boundary.

Use existing form/read codecs, purpose-separated key families, authenticated
service bindings and protected-control OIDC. Bootstrap and export need exact
transient request context, not a new durable approval/job store. No context
token substitutes for current session, authority, source or membership checks.
The installer never sends its general provisioning credential to the service.
Private PR views need minimal typed result/observation extensions; an unscoped
repository proxy or a second records/enforcer credential path is unnecessary.

Use the parent's two private-read result classes. Project-index authorization
does not become arbitrary subject-status authority. Named PR details use the
exact subject-scoped proof/page flow and bounded pages; do not invent a bulk
authority cache to reduce request counts. Include the actual cost in estimates
and measurements. A changed protocol/grant is a material choice if required;
it must not be hidden in an estimate's high bound.

## Finite engineering and acceptance work

The detailed plan must close the context envelopes and current-authority
providers, minimum PR observation/result union, capability-specific wrapping
and protected-control challenge transport, authenticated hosted-export provider,
partial derived reads/writes and complete browser/API input/work limits.
Reuse existing wire formats and cryptography wherever they already exist.

Actual installed-grant visibility, SSO/policy behavior, live callback/PKCE,
bootstrap/control readiness, dispatch/expiry behavior and cold private-read/
mutation/export resource limits require separately authorized acceptance.
If those tests cannot establish a required permission result or boundary within
existing grants, return the concrete contract/trust choice; do not ship a
permanently blocked path as completion. No such production result is claimed here.
