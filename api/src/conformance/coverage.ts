/** Pure coverage over authenticated immutable observations (HLD 5.3/5.4).
 * The caller authenticates repository contents, committed-event ancestry and
 * historical event preconditions. This module performs no I/O or replay.
 */
import { canonicalJson, parseCanonicalJson, freezeJson, type JsonObject, type ReadonlyJsonObject } from './canonical.js';
import { resolveArtifactIdentity, overrideKey } from './artifacts.js';
import { base64urlDecode } from './encoding.js';
import { decodeProjection, CoverageError } from './projections.js';
import { validateEvent } from './events.js';
export { CoverageError } from './projections.js';
const SOURCE = 'source.enc.json', ACTIVE = 'agreements/active.enc.json', EXEMPT = 'exemptions.enc.json';
const MARKER = 'inflight.enc.json', FENCE = 'decision-fence.enc.json';
const SHARDS = Array.from({ length: 32 }, (_, i) => `users/${String(i).padStart(2, '0')}.enc.json`);
const FILES = [SOURCE, ACTIVE, EXEMPT, MARKER, FENCE, ...SHARDS];
type Row = Record<string, unknown>;
const snapshots = new WeakMap<object, ReadonlyJsonObject>();
export interface CoverageProjection {
    readonly projectId: string;
    toDict(): JsonObject;
    plaintextFiles(): Readonly<Record<string, Uint8Array<ArrayBuffer>>>;
}
function require(value: unknown, message: string): asserts value {
    if (!value) throw new CoverageError(message);
}
function object(value: unknown, keys?: readonly string[]): Row {
    require(value !== null && typeof value === 'object' && !Array.isArray(value), 'coverage object required');
    const row = value as Row;
    if (keys) require(Object.keys(row).length === keys.length && keys.every(key => Object.hasOwn(row, key)), 'missing or unknown coverage fields');
    return row;
}
function text(value: unknown): string { require(typeof value === 'string' && value.length > 0, 'nonempty string required'); return value; }
function oid(value: unknown): string {
    const result = text(value);
    require(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$(?![\s\S])/.test(result), 'Git OID required');
    return result;
}
function token(value: unknown): string { const result = text(value); base64urlDecode(result, 32); return result; }
function clone(value: unknown): Row { return object(parseCanonicalJson(canonicalJson(value))); }
function same(a: unknown, b: unknown): boolean {
    const x = canonicalJson(a), y = canonicalJson(b);
    return x.length === y.length && x.every((byte, i) => byte === y[i]);
}
function ordered(values: readonly string[]): string[] {
    const encoded = (s: string) => Array.from(canonicalJson(s), b => String.fromCharCode(b)).join('');
    return [...new Set(values)].sort((a, b) => encoded(a) < encoded(b) ? -1 : encoded(a) > encoded(b) ? 1 : 0);
}
function files(projection: CoverageProjection): Row {
    const value = snapshots.get(projection);
    require(value !== undefined, 'validated coverage projection required');
    return clone(value);
}
export function coverageShard(subject: number, shardCount: number): number {
    require(Number.isSafeInteger(subject) && subject > 0, 'positive safe subject ID required');
    require(shardCount === 32, 'projection format 1 requires 32 shards');
    return subject % shardCount;
}
function subjectKey(key: string): void {
    require(/^[1-9][0-9]{0,15}$(?![\s\S])/.test(key) && String(Number(key)) === key, 'canonical subject ID required');
    coverageShard(Number(key), 32);
}
function operationPair(marker: Row, fence: Row): void {
    const entries = Object.entries(object(marker.ops));
    if (entries.length) {
        const [id, value] = entries[0]!, entry = object(value);
        require(fence.state === 'mutation' && fence.operation_id === id &&
            ['operation_sha256', 'subjects', 'project_wide'].every(key => same(entry[key], fence[key])), 'marker and mutation fence do not match');
    }
}
/** Own and validate every plaintext, including shards untouched by an update. */
export async function coverageProjection(projectId: string, input: unknown, expectedCanonicalOid?: string): Promise<CoverageProjection> {
    try {
        const project = text(projectId), value = clone(input), expected = expectedCanonicalOid;
        canonicalJson(project);
        object(value, FILES);
        const encoded = FILES.map(path => canonicalJson(value[path]));
        if (expected !== undefined) require(object(value[SOURCE]).canonical_sha === oid(expected), 'coverage source mismatch');
        require(object(value[SOURCE]).successor_project_id !== project, 'project cannot succeed itself');
        await Promise.all(FILES.map((path, i) => decodeProjection(resolveArtifactIdentity('coverage', 'coverage', path), encoded[i]!)));
        operationPair(object(value[MARKER]), object(value[FENCE]));
        const owned = freezeJson(value as JsonObject);
        const result: CoverageProjection = Object.freeze({ projectId: project,
            toDict: () => clone(owned) as JsonObject,
            plaintextFiles: () => Object.freeze(Object.fromEntries(FILES.map(path => [path, canonicalJson(owned[path])]))) });
        snapshots.set(result, owned);
        return result;
    } catch (cause) { throw new CoverageError('invalid coverage projection', { cause }); }
}
export function validateCoverageProjection(projection: CoverageProjection, expectedProjectId: string, expectedCanonicalOid?: string): void {
    const value = files(projection);
    require(projection.projectId === text(expectedProjectId), 'coverage project mismatch');
    if (expectedCanonicalOid !== undefined) require(object(value[SOURCE]).canonical_sha === oid(expectedCanonicalOid), 'coverage source mismatch');
}
export interface CoverageDecision {
    readonly decision: 'covered' | 'uncovered';
    readonly reason_code: string | null;
    readonly overridden: boolean;
    readonly successor_project_id: string | null;
}
export async function evaluateSubject(projection: CoverageProjection, subject: number, agreementId: string, overrideContext: unknown = null): Promise<CoverageDecision> {
    const value = files(projection), user = coverageShard(subject, 32), agreement = text(agreementId);
    const context = overrideContext === null ? null : clone(overrideContext);
    let override: string | null = null;
    if (context !== null) {
        object(context, ['repository_id', 'pull_request_number', 'tree_oid']);
        override = await overrideKey({ repository_id: context.repository_id as number, pull_request_number: context.pull_request_number as number, tree_oid: context.tree_oid as string, subject_user_id: subject });
    }
    const decision = (covered: boolean, reason: string | null, overridden = false, successor: string | null = null): CoverageDecision =>
        Object.freeze({ decision: covered ? 'covered' : 'uncovered', reason_code: reason, overridden, successor_project_id: successor });
    const source = object(value[SOURCE]), fence = object(value[FENCE]), active = object(value[ACTIVE]);
    if (source.project_state === 'succeeded') return decision(false, null, false, source.successor_project_id as string);
    if (fence.state === 'mutation' && (fence.project_wide || (fence.subjects as number[]).includes(subject))) return decision(false, 'indeterminate');
    require(active.agreement_id === null || active.agreement_id === agreement, 'requested agreement differs from active agreement');
    const rowValue = object(value[SHARDS[user]!])[String(subject)], row = rowValue === undefined ? null : object(rowValue);
    const agreements = row === null ? {} : object(row.agreements);
    const basis = Object.hasOwn(agreements, agreement) ? object(agreements[agreement]) : null;
    if (basis?.reason_code === 'indeterminate') return decision(false, 'indeterminate');
    if (basis?.decision === 'covered' && (active.accepted_versions as string[]).includes(basis.version as string)) return decision(true, 'signed');
    if (Object.hasOwn(object(value[EXEMPT]), String(subject))) return decision(true, 'exempt');
    if (row !== null && override !== null && Object.hasOwn(object(row.overrides), override)) return decision(true, null, true);
    return decision(false, basis?.decision === 'covered' ? 'version_not_active' : basis?.reason_code as string ?? 'not_signed');
}
export function coverageDelta(before: CoverageProjection, after: CoverageProjection): { readonly files: readonly string[]; readonly shards: readonly number[] } {
    validateCoverageProjection(after, before.projectId);
    const old = files(before), current = files(after), changed = FILES.filter(path => !same(old[path], current[path])).sort();
    return Object.freeze({ files: Object.freeze(changed), shards: Object.freeze(SHARDS.flatMap((path, i) => changed.includes(path) ? [i] : [])) });
}
/** Caller-authenticated source facts, never inferred from coverage booleans.
 * Include every affected subject, even with an empty union. Rule withdrawal
 * includes every currently exempt subject so removal cannot skip a shard.
 */
export interface ExemptionUnionObservation {
    readonly project_id: string;
    readonly canonical_oid: string;
    readonly sources: Readonly<Record<string, readonly string[]>>;
}
export interface ActivationObservation {
    readonly project_id: string;
    readonly canonical_oid: string;
    readonly event: unknown;
}
export interface CoverageUpdateOptions {
    readonly expectedHead: string;
    readonly builtAt: string;
    readonly draclaVersion: string;
    readonly operationState: readonly [unknown, unknown];
    readonly priorExemptionUnion?: ExemptionUnionObservation;
    readonly restoredActivation?: ActivationObservation;
}
/** Operational windows change explicit guards at the same canonical head. */
export async function updateCoverageOperations(before: CoverageProjection, operationState: readonly [unknown, unknown]): Promise<CoverageProjection> {
    const value = files(before), pair = parseCanonicalJson(canonicalJson(operationState));
    require(Array.isArray(pair) && pair.length === 2, 'explicit marker/fence pair required');
    value[MARKER] = pair[0]; value[FENCE] = pair[1];
    return coverageProjection(before.projectId, value);
}
function exemptionUpdate(value: Row, event: Row, observation: unknown, project: string, head: string): void {
    const target = object(event.target), payload = object(event.payload), type = event.type;
    const supplied = object(observation, ['project_id', 'canonical_oid', 'sources']);
    require(supplied.project_id === project && supplied.canonical_oid === head, 'stale or wrong exemption union');
    const unions = object(supplied.sources), exemptions = object(value[EXEMPT]);
    for (const [key, sources] of Object.entries(unions)) {
        subjectKey(key);
        require(Array.isArray(sources), 'source union must be an array');
        sources.forEach(token);
        require(new Set(sources).size === sources.length, 'duplicate exemption source');
        require((sources.length > 0) === Object.hasOwn(exemptions, key), 'source union disagrees with coverage');
    }
    const subject = (s: unknown): string => String(object(s).github_user_id);
    const affected = type === 'exemption_snapshot' ? (target.subjects as unknown[]).map(subject) :
        type === 'exemption_rule_withdrawn' ? Object.keys(exemptions) : [subject(target.subject)];
    for (const key of affected) {
        require(Object.hasOwn(unions, key), 'affected subject source union missing');
        const prior = new Set(unions[key] as string[]);
        if (type === 'exemption' || type === 'exemption_snapshot') prior.add(event.event_id as string);
        else if (type === 'exemption_source_withdrawn') prior.delete(target.source_event_id as string);
        else if (type === 'exemption_rule_withdrawn') prior.delete(target.rule_event_id as string);
        else {
            const id = target.rule_event_id as string;
            require(prior.has(id) !== (payload.result === 'add'), 'materialization source presence mismatch');
            if (payload.result === 'add') prior.add(id); else prior.delete(id);
        }
        if (prior.size) exemptions[key] = { active: true }; else delete exemptions[key];
    }
}
/** A committed append, authenticated at parent_oid. Closed event validation here
 * does not replace the historical precondition checks required before append.
 */
export async function updateCoverage(before: CoverageProjection, inputRecord: unknown, options: CoverageUpdateOptions): Promise<CoverageProjection> {
    try {
        const value = files(before), record = clone(inputRecord), opts = clone(options), project = before.projectId;
        object(record, ['event', 'commit_oid', 'parent_oid']);
        object(opts, ['expectedHead', 'builtAt', 'draclaVersion', 'operationState',
            ...(Object.hasOwn(opts, 'priorExemptionUnion') ? ['priorExemptionUnion'] : []), ...(Object.hasOwn(opts, 'restoredActivation') ? ['restoredActivation'] : [])]);
        const head = oid(opts.expectedHead), commit = oid(record.commit_oid);
        validateCoverageProjection(before, project, head);
        require(record.parent_oid === head && commit !== head, 'append parent or commit mismatch');
        require(Array.isArray(opts.operationState) && opts.operationState.length === 2, 'explicit marker/fence pair required');
        const validated = await validateEvent(record.event, { expectedProjectId: project }), event = clone(validated);
        const target = object(event.target), payload = object(event.payload), active = object(value[ACTIVE]), source = object(value[SOURCE]);
        const type = validated.type;
        require(type !== 'project_connected', 'coverage initialization requires an explicit connected snapshot');
        source.canonical_sha = commit; source.built_at = opts.builtAt; source.dracla_version = opts.draclaVersion;
        value[MARKER] = opts.operationState[0]; value[FENCE] = opts.operationState[1];
        const row = (subject: number): Row => {
            const shard = object(value[SHARDS[coverageShard(subject, 32)]!]), key = String(subject);
            if (!Object.hasOwn(shard, key)) shard[key] = { agreements: {}, overrides: {} };
            return object(shard[key]);
        };
        if (type === 'acceptance' || type === 'revocation') {
            const tuple = object(target.coverage_tuple), agreements = object(row(tuple.github_user_id as number).agreements);
            require(active.agreement_id === tuple.agreement_id, 'signature agreement mismatch');
            if (type === 'acceptance') require(active.active_version === target.version, 'acceptance version is not active');
            const basis = type === 'acceptance' ?
                { decision: 'covered', reason_code: 'signed', version: target.version, digest: target.digest } :
                { decision: 'uncovered', reason_code: 'revoked', version: null, digest: null };
            Object.defineProperty(agreements, tuple.agreement_id as string, { value: basis, enumerable: true, configurable: true, writable: true });
        } else if (type === 'agreement_activated' || type === 'agreement_activation_restored') {
            require(active.agreement_id === null || active.agreement_id === target.agreement_id, 'currency agreement mismatch');
            const accepted = payload.accepted_versions as string[], prior = active.accepted_versions as string[];
            let version = target.version as string, retired = active.retired_versions as string[];
            if (type === 'agreement_activated') {
                require(!retired.includes(version), 'ordinary activation cannot revive retired version');
                require(same(accepted, payload.supersedes_coverage ? [version] : ordered([...prior, version])), 'activation currency mismatch');
                if (payload.supersedes_coverage) retired = ordered([...retired, ...prior]).filter(item => item !== version);
            } else {
                const observed = object(opts.restoredActivation, ['project_id', 'canonical_oid', 'event']);
                require(observed.project_id === project && observed.canonical_oid === head, 'stale or wrong activation observation');
                const original = await validateEvent(observed.event, { expectedProjectId: project });
                require(original.type === 'agreement_activated' && original.event_id === target.activation_event_id &&
                    original.target.agreement_id === target.agreement_id && same(original.payload.accepted_versions, accepted), 'restore activation mismatch');
                version = original.target.version as string;
                retired = ordered([...retired, ...prior]).filter(item => !accepted.includes(item));
            }
            Object.assign(active, { agreement_id: target.agreement_id, active_version: version, accepted_versions: accepted, retired_versions: retired, activation_event_id: event.event_id });
        } else if (['exemption', 'exemption_snapshot', 'exemption_source_withdrawn', 'exemption_materialized', 'exemption_rule_withdrawn'].includes(type)) {
            exemptionUpdate(value, event, opts.priorExemptionUnion, project, head);
        } else if (type === 'override') {
            for (const subject of payload.subjects as Row[]) {
                const id = subject.github_user_id as number, overrides = object(row(id).overrides);
                const identity = { repository_id: target.repository_id as number, pull_request_number: target.pull_request_number as number, subject_user_id: id, tree_oid: target.tree_oid as string };
                const key = await overrideKey(identity);
                require(!Object.hasOwn(overrides, key), 'overlapping active override');
                overrides[key] = { ...identity, grant_event_id: event.event_id, active: true };
            }
        } else if (type === 'override_withdrawn') {
            let found = false;
            for (const path of SHARDS) for (const [userId, user] of Object.entries(object(value[path]))) {
                const overrides = object(object(user).overrides);
                let removed = false;
                for (const [key, entry] of Object.entries(overrides)) if (object(entry).grant_event_id === target.override_event_id) {
                    delete overrides[key]; found = true; removed = true;
                }
                if (removed && !Object.keys(object(object(user).agreements)).length && !Object.keys(overrides).length) delete object(value[path])[userId];
            }
            require(found, 'withdrawal does not name an active override');
        } else if (type === 'project_succeeded') {
            source.project_state = 'succeeded'; source.successor_project_id = target.successor_project_id;
        }
        // Reader and other non-coverage transitions still advance source without
        // accepting or consulting private derived state.
        return await coverageProjection(project, value, commit);
    } catch (cause) { throw new CoverageError('invalid incremental coverage update', { cause }); }
}
