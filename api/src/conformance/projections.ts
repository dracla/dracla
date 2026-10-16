/** Closed read-only projection plaintexts. No update or decision logic. */
import { canonicalJson, parseCanonicalJson, freezeJson, type JsonObject, type ReadonlyJsonObject } from './canonical.js';
import { overrideKey, resolveArtifactIdentity, sha256, type ArtifactIdentity } from './artifacts.js';
import { base64urlDecode, copyBytes } from './encoding.js';
import { DERIVED_CLASSES, ReleaseProfile, type DerivedClass } from './releaseProfile.js';
export class ProjectionError extends Error {
    constructor(message: string, options?: ErrorOptions) { super(message, options); this.name = new.target.name; }
}
export class CoverageError extends ProjectionError {
}
export class DerivedError extends ProjectionError {
}
export class OperationCorruption extends ProjectionError {
}
export class DerivedClassOverflow extends DerivedError {
    constructor(readonly derived_class: DerivedClass | 'state') { super('private derived class exceeds its profile: ' + derived_class); }
}
type ObjectValue = Record<string, unknown>;
const classes: Readonly<Record<string, DerivedClass>> = { 'derived-index': 'derived_index', 'status-detail': 'status_detail', 'reader-authority': 'reader_authority' };
function require(condition: unknown, message: string): asserts condition {
    if (!condition)
        throw new ProjectionError(message);
}
function object(value: unknown, fields?: readonly string[]): ObjectValue {
    require(value !== null && typeof value === 'object' && !Array.isArray(value), 'object required');
    const result = value as ObjectValue;
    if (fields)
        require(Object.keys(result).length === fields.length && fields.every(key => Object.hasOwn(result, key)), 'missing or unknown members');
    return result;
}
function text(value: unknown): string { require(typeof value === 'string' && value.length > 0, 'nonempty string required'); return value; }
function count(value: unknown, positive = false): number {
    require(typeof value === 'number' && Number.isSafeInteger(value) && value >= (positive ? 1 : 0), 'safe integer required');
    return value;
}
function token(value: unknown): string { const result = text(value); base64urlDecode(result, 32); return result; }
function oid(value: unknown): string { const result = text(value); require(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$(?![\s\S])/.test(result), 'Git OID required'); return result; }
function digest(value: unknown): void { require(/^sha256:[0-9a-f]{64}$(?![\s\S])/.test(text(value)), 'SHA256 digest required'); }
function timestamp(value: unknown): void {
    const result = text(value);
    require(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$(?![\s\S])/.test(result) && Number(result.slice(0, 4)) > 0, 'UTC whole-second timestamp required');
    const date = new Date(result);
    require(Number.isFinite(date.valueOf()) && date.toISOString() === result.slice(0, -1) + '.000Z', 'invalid calendar timestamp');
}
function subject(key: string): number {
    require(/^[1-9][0-9]{0,15}$(?![\s\S])/.test(key), 'canonical subject key required');
    const number = count(Number(key), true);
    require(String(number) === key, 'canonical subject key required');
    return number;
}
function equal(left: unknown, right: unknown): boolean {
    const a = canonicalJson(left), b = canonicalJson(right);
    return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
function team(value: unknown): void {
    const row = object(value, ['organization_id', 'team_id', 'slug_snapshot']);
    count(row.organization_id, true);
    count(row.team_id, true);
    text(row.slug_snapshot);
}
function scope(row: ObjectValue): void {
    require(typeof row.project_wide === 'boolean' && Array.isArray(row.subjects), 'invalid scope');
    const ids = row.subjects.map(value => count(value, true));
    require(ids.every((id, i) => i === 0 || id > ids[i - 1]!) && (ids.length === 0) === row.project_wide, 'scope must be sorted unique subjects or project-wide');
}
function marker(value: unknown): void {
    const ops = object(object(value, ['ops']).ops);
    require(Object.keys(ops).length <= 1, 'at most one marker operation');
    for (const [key, value] of Object.entries(ops)) {
        token(key);
        const row = object(value, ['operation_sha256', 'started_at', 'subjects', 'project_wide']);
        digest(row.operation_sha256);
        timestamp(row.started_at);
        scope(row);
    }
}
function fence(value: unknown): void {
    const row = object(value), state = row.state;
    const fields = ['state', 'generation'];
    if (state === 'mutation')
        fields.push('operation_id', 'operation_sha256', 'subjects', 'project_wide', 'prepared_commit_oid', 'prepared_blob_sha', 'prepared_generation');
    else if (state === 'success_reserved')
        fields.push('check_identity', 'projection_commit');
    else
        require(state === 'idle', 'unknown fence state');
    object(row, fields);
    count(row.generation);
    if (state === 'mutation') {
        token(row.operation_id);
        digest(row.operation_sha256);
        scope(row);
        oid(row.prepared_commit_oid);
        oid(row.prepared_blob_sha);
        count(row.prepared_generation);
    }
    else if (state === 'success_reserved') {
        token(row.check_identity);
        oid(row.projection_commit);
    }
}
function active(value: unknown): void {
    const row = object(value, ['agreement_id', 'active_version', 'accepted_versions', 'retired_versions', 'activation_event_id', 'projection_format', 'shard_count']);
    require(row.projection_format === 1 && row.shard_count === 32, 'unsupported projection format or shard count');
    function versions(value: unknown): string[] {
        require(Array.isArray(value), 'version set must be an array');
        const result = value.map(text);
        // One code unit per UTF8 byte makes native string sort byte-lexicographic.
        const byBytes = new Map(result.map(value => [Array.from(canonicalJson(value), byte => String.fromCharCode(byte)).join(''), value]));
        const sorted = [...byBytes.keys()].sort().map(key => byBytes.get(key)!);
        require(equal(result, sorted), 'version set must be canonical-byte sorted and unique');
        return result;
    }
    const accepted = versions(row.accepted_versions), retired = versions(row.retired_versions);
    require(!accepted.some(version => retired.includes(version)), 'version sets overlap');
    if ([row.agreement_id, row.active_version, row.activation_event_id].every(value => value === null))
        require(!accepted.length && !retired.length, 'pre-activation sets must be empty');
    else {
        text(row.agreement_id);
        token(row.activation_event_id);
        require(accepted.includes(text(row.active_version)), 'active version must be accepted');
    }
}
function source(value: unknown): void {
    const row = object(value, ['canonical_sha', 'built_at', 'dracla_version', 'project_state', 'successor_project_id']);
    oid(row.canonical_sha);
    timestamp(row.built_at);
    text(row.dracla_version);
    if (row.project_state === 'active')
        require(row.successor_project_id === null, 'active project cannot name successor');
    else {
        require(row.project_state === 'succeeded', 'unknown lifecycle');
        text(row.successor_project_id);
    }
}
async function users(input: unknown, shard: number): Promise<void> {
    for (const [key, value] of Object.entries(object(input))) {
        const id = subject(key);
        require(id % 32 === shard, 'subject in wrong shard');
        const row = object(value, ['agreements', 'overrides']);
        for (const [agreement, value] of Object.entries(object(row.agreements))) {
            text(agreement);
            const decision = object(value, ['decision', 'reason_code', 'version', 'digest']);
            if (decision.reason_code === 'signed') {
                require(decision.decision === 'covered', 'signed basis must be covered');
                text(decision.version);
                digest(decision.digest);
            }
            else
                require(['revoked', 'not_signed', 'indeterminate'].includes(text(decision.reason_code)) && decision.decision === 'uncovered' && decision.version === null && decision.digest === null, 'invalid durable signature basis');
        }
        for (const [entryKey, value] of Object.entries(object(row.overrides))) {
            const entry = object(value, ['repository_id', 'pull_request_number', 'subject_user_id', 'tree_oid', 'grant_event_id', 'active']);
            const input = { repository_id: count(entry.repository_id, true), pull_request_number: count(entry.pull_request_number, true), subject_user_id: count(entry.subject_user_id, true), tree_oid: oid(entry.tree_oid) };
            token(entry.grant_event_id);
            require(entry.active === true && input.subject_user_id === id, 'invalid active override subject');
            // Canonical object keys are unique; the exact tuple hash also prevents
            // the same tuple from appearing under a different entry key.
            require(await overrideKey(input) === entryKey, 'override key or tuple mismatch');
        }
    }
}
function facts(value: unknown): void {
    const row = object(value, ['version', 'accepted_at', 'revoked_at', 'basis']), basis = object(row.basis, ['event_id', 'kind']);
    const kind = basis.kind;
    require(['acceptance', 'revocation', 'none', 'unresolved'].includes(text(kind)), 'unknown signature basis');
    if (kind === 'none')
        require([row.version, row.accepted_at, row.revoked_at, basis.event_id].every(value => value === null), 'absent basis carries facts');
    else {
        token(basis.event_id);
        if (kind === 'acceptance') {
            text(row.version);
            timestamp(row.accepted_at);
            require(row.revoked_at === null, 'acceptance retains revocation');
        }
        else if (kind === 'revocation') {
            require(row.version === null && row.accepted_at === null, 'revocation retains acceptance');
            timestamp(row.revoked_at);
        }
        else
            require([row.version, row.accepted_at, row.revoked_at].every(value => value === null), 'unresolved basis claims facts');
    }
}
function exemptionSource(value: unknown): ObjectValue {
    const row = object(value, ['source_kind', 'team', 'basis', 'instrument_ref', 'rule_event_id', 'sequence']), kind = row.source_kind;
    require(['bot', 'individual', 'snapshot', 'continuous_team'].includes(text(kind)), 'unknown exemption kind');
    count(row.sequence);
    if (kind === 'snapshot' || kind === 'continuous_team')
        team(row.team);
    else
        require(row.team === null, 'direct exemption carries team');
    for (const key of ['basis', 'instrument_ref'])
        if (kind !== 'bot' || row[key] !== null)
            text(row[key]);
    if (kind === 'continuous_team')
        token(row.rule_event_id);
    else
        require(row.rule_event_id === null, 'noncontinuous exemption carries rule');
    return row;
}
function standingRules(value: unknown, profile: ReleaseProfile): ObjectValue {
    const rules = object(value);
    profile.check('max_continuous_exemption_rules', Object.keys(rules).length);
    for (const [id, value] of Object.entries(rules)) {
        token(id);
        const row = object(value, ['team', 'basis', 'instrument_ref']);
        team(row.team);
        text(row.basis);
        text(row.instrument_ref);
    }
    return rules;
}
function privateSubjects(input: unknown, shard: number, detail: boolean, rules: ObjectValue): void {
    for (const [key, value] of Object.entries(object(input))) {
        require(subject(key) % 32 === shard, 'subject in wrong shard');
        const fields = ['login_snapshot', 'login_as_of', 'agreements', ...(detail ? ['exemption_sources', 'exemption_sequence_next', 'materialization_cursor'] : ['exempt'])];
        const row = object(value, fields);
        require((row.login_snapshot === null) === (row.login_as_of === null), 'login snapshot and observation must pair');
        if (row.login_snapshot !== null) {
            text(row.login_snapshot);
            timestamp(row.login_as_of);
        }
        for (const [agreement, value] of Object.entries(object(row.agreements))) {
            text(agreement);
            facts(value);
        }
        if (!detail) {
            require(typeof row.exempt === 'boolean', 'index exempt must be boolean');
            continue;
        }
        const next = count(row.exemption_sequence_next), sequences = new Set<number>();
        const cursor = object(row.materialization_cursor), sources = object(row.exemption_sources);
        for (const [id, value] of Object.entries(sources)) {
            token(id);
            const source = exemptionSource(value), sequence = count(source.sequence);
            require(sequence < next && !sequences.has(sequence), 'invalid exemption sequence');
            sequences.add(sequence);
            if (source.source_kind === 'continuous_team') {
                require(source.rule_event_id === id && Object.hasOwn(rules, id) && Object.hasOwn(cursor, id), 'continuous exemption rule/cursor missing');
                const rule = object(rules[id]);
                require(['team', 'basis', 'instrument_ref'].every(key => equal(source[key], rule[key])), 'standing rule provenance mismatch');
            }
        }
        for (const [rule, event] of Object.entries(cursor)) {
            token(rule);
            token(event);
            require(rule !== event && Object.hasOwn(rules, rule), 'invalid retained exemption cursor');
        }
    }
}
async function readers(input: unknown, shard: number, profile: ReleaseProfile): Promise<void> {
    let continuous = 0;
    for (const [id, value] of Object.entries(object(input))) {
        token(id);
        require(((await sha256(new TextEncoder().encode(id)))[0]! >>> 3) === shard, 'reader source in wrong shard');
        const row = object(value, ['kind', 'team', 'materialization_cursor', 'subjects']), kind = row.kind;
        require(['individual', 'snapshot', 'continuous_team'].includes(text(kind)), 'unknown reader kind');
        if (kind === 'individual')
            require(row.team === null, 'individual reader carries team');
        else
            team(row.team);
        const members = object(row.subjects), cursor = object(row.materialization_cursor), keys = Object.keys(members);
        require(kind !== 'individual' || keys.length === 1, 'individual reader must have one subject');
        require(kind !== 'snapshot' || keys.length > 0, 'empty snapshot must be removed');
        require(kind === 'continuous_team' || Object.keys(cursor).length === 0, 'noncontinuous source has cursors');
        profile.check('max_reader_source_members', keys.length);
        profile.check('max_reader_cursor_entries', Object.keys(cursor).length);
        for (const [key, value] of Object.entries(members)) {
            subject(key);
            const member = object(value, ['added_event_id']);
            token(member.added_event_id);
            if (kind !== 'continuous_team')
                require(member.added_event_id === id, 'direct reader membership source mismatch');
            else
                require(Object.hasOwn(cursor, key) && cursor[key] === member.added_event_id && member.added_event_id !== id, 'active continuous membership cursor mismatch');
        }
        for (const [key, event] of Object.entries(cursor)) {
            subject(key);
            token(event);
            require(event !== id, 'reader cursor names its rule');
        }
        if (kind === 'continuous_team')
            continuous++;
    }
    profile.check('max_continuous_reader_rules', continuous);
}
function derivedState(value: unknown, profile: ReleaseProfile): void {
    const row = object(value, ['state_version', 'generations', 'shard_digests', 'standing_rules', 'shard_count', 'profile']);
    require(row.state_version === 1 && row.shard_count === 32, 'unsupported derived state');
    for (const value of Object.values(object(row.generations, DERIVED_CLASSES)))
        token(value);
    for (const table of Object.values(object(row.shard_digests, DERIVED_CLASSES))) {
        for (const value of Object.values(object(table, Array.from({ length: 32 }, (_, i) => String(i).padStart(2, '0')))))
            digest(value);
    }
    const fields = ['max_shard_ciphertext_bytes', 'max_reader_source_members', 'max_continuous_reader_rules'];
    const installed = object(row.profile, fields), expected = profile.toDict();
    require(fields.every(key => equal(installed[key], expected[key])), 'state profile disagrees with installed profile');
    standingRules(row.standing_rules, profile);
}
export async function decodeProjection(artifact: ArtifactIdentity, data: Uint8Array, options: {
    profile?: ReleaseProfile;
    standingRules?: unknown;
} = {}): Promise<ReadonlyJsonObject> {
    const resolved = resolveArtifactIdentity(artifact.repository_role, artifact.branch, artifact.path);
    require(Object.keys(resolved).every(key => resolved[key as keyof ArtifactIdentity] === artifact[key as keyof ArtifactIdentity]), 'projection identity mismatch');
    const kind = resolved.artifact_kind;
    const ErrorType = ['inflight', 'decision-fence'].includes(kind) ? OperationCorruption : ['coverage-source', 'active-agreement', 'exemption-fold', 'coverage-shard'].includes(kind) ? CoverageError : DerivedError;
    try {
        const raw = copyBytes(data), value = object(parseCanonicalJson(raw));
        if (kind === 'coverage-source')
            source(value);
        else if (kind === 'active-agreement')
            active(value);
        else if (kind === 'exemption-fold') {
            for (const [key, entry] of Object.entries(value)) {
                subject(key);
                require(object(entry, ['active']).active === true, 'inactive exemption');
            }
        }
        else if (kind === 'coverage-shard')
            await users(value, Number(resolved.path.slice(-11, -9)));
        else if (kind === 'inflight')
            marker(value);
        else if (kind === 'decision-fence')
            fence(value);
        else {
            const profile = options.profile;
            require(profile instanceof ReleaseProfile, 'validated installed profile required');
            if (kind === 'derived-state')
                derivedState(value, profile);
            else {
                const selected = classes[kind];
                require(selected !== undefined, 'unknown projection kind');
                const shard = Number(resolved.path.slice(-11, -9));
                if (selected === 'reader_authority')
                    await readers(value, shard, profile);
                else
                    privateSubjects(value, shard, selected === 'status_detail', standingRules(options.standingRules ?? {}, profile));
            }
            const selected = classes[kind];
            if (raw.length + 16 > (kind === 'derived-state' ? profile.limit('max_state_ciphertext_bytes') : profile.limit('max_shard_ciphertext_bytes', selected)))
                throw new DerivedClassOverflow(selected ?? 'state');
        }
        return freezeJson(value as JsonObject);
    }
    catch (error) {
        if (error instanceof DerivedClassOverflow)
            throw error;
        throw new ErrorType('invalid ' + kind + ' plaintext', { cause: error });
    }
}
