/** Incremental private materialization and bounded portal reads.
 * The caller authenticates repository observations, event ancestry/preconditions,
 * canonical generations, and correspondence between decrypted and encrypted bytes.
 * This module has no history replay, repository I/O, keys or repair driver.
 */
import { canonicalJson, parseCanonicalJson, freezeJson, type JsonObject, type ReadonlyJsonObject } from './canonical.js';
import { resolveArtifactIdentity, sha256 } from './artifacts.js';
import { base64urlDecode, copyBytes } from './encoding.js';
import { decodeProjection, DerivedError, DerivedClassOverflow } from './projections.js';
import { validateEvent, validateEventOperation, validateEnforcementScope } from './events.js';
import { DERIVED_CLASSES, ReleaseProfile, type DerivedClass } from './releaseProfile.js';
import { validateCoverageProjection, coverageShard, type CoverageProjection } from './coverage.js';
export { DerivedError, DerivedClassOverflow } from './projections.js';
type Row = Record<string, unknown>;
const STATE = 'derived/state.enc.json';
const PREFIX = { derived_index: 'index', status_detail: 'status-detail', reader_authority: 'reader-authority' };
const PATHS = Object.fromEntries(DERIVED_CLASSES.map(c => [c, Array.from({ length: 32 }, (_, i) => `derived/${PREFIX[c]}/${String(i).padStart(2, '0')}.enc.json`)])) as Record<DerivedClass, string[]>;
const SHARDS = DERIVED_CLASSES.flatMap(c => PATHS[c]);
const models = new WeakMap<object, { value: Row; profile: ReleaseProfile }>();
const projections = new WeakMap<object, Row>();
const reads = new WeakMap<object, { files: Row; state: Row; profile: ReleaseProfile }>();
function require(value: unknown, message: string): asserts value { if (!value) throw new DerivedError(message); }
function object(value: unknown, keys?: readonly string[]): Row {
    require(value !== null && typeof value === 'object' && !Array.isArray(value), 'derived object required');
    const row = value as Row;
    if (keys) require(Object.keys(row).length === keys.length && keys.every(k => Object.hasOwn(row, k)), 'missing or unknown derived fields');
    return row;
}
function clone(value: unknown): Row { return object(parseCanonicalJson(canonicalJson(value))); }
function same(a: unknown, b: unknown): boolean { const x = canonicalJson(a), y = canonicalJson(b); return x.length === y.length && x.every((v, i) => v === y[i]); }
function text(value: unknown): string { require(typeof value === 'string' && value.length > 0, 'nonempty text required'); return value; }
function oid(value: unknown): string { const s = text(value); require(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$(?![\s\S])/.test(s), 'Git OID required'); return s; }
function token(value: unknown): string { const s = text(value); base64urlDecode(s, 32); return s; }
function own(row: Row, key: string): unknown { return Object.hasOwn(row, key) ? row[key] : undefined; }
function put(row: Row, key: string, value: unknown): void { Object.defineProperty(row, key, { value, enumerable: true, writable: true, configurable: true }); }
function kind(path: string): DerivedClass { const c = DERIVED_CLASSES.find(c => PATHS[c].includes(path)); require(c, 'unknown derived shard'); return c; }
function profile(value: ReleaseProfile): void { require(value instanceof ReleaseProfile, 'validated installed profile required'); }
function limit(p: ReleaseProfile, size: number, c: DerivedClass | 'state'): void {
    if (size > (c === 'state' ? p.limit('max_state_ciphertext_bytes') : p.limit('max_shard_ciphertext_bytes', c))) throw new DerivedClassOverflow(c);
}
function generations(input: unknown): Row {
    const v = clone(input); object(v, ['generations_version', ...DERIVED_CLASSES]);
    require(v.generations_version === 1, 'unsupported generations'); DERIVED_CLASSES.forEach(c => token(v[c])); return v;
}
function plain(value: DerivedPlaintext): { value: Row; profile: ReleaseProfile } {
    const m = models.get(value); require(m, 'validated private plaintext required'); return { value: clone(m.value), profile: m.profile };
}
export interface DerivedPlaintext {
    readonly projectId: string;
    readonly canonicalOid: string;
    toDict(): JsonObject;
    plaintextFiles(): Readonly<Record<string, Uint8Array<ArrayBuffer>>>;
}
export async function readerAuthorityShard(sourceId: string): Promise<number> { return (await sha256(new TextEncoder().encode(token(sourceId))))[0]! >>> 3; }
async function validateFiles(files: Row, rules: unknown, p: ReleaseProfile): Promise<void> {
    object(files, SHARDS);
    await Promise.all(SHARDS.map(path => decodeProjection(resolveArtifactIdentity('records', 'derived', path), canonicalJson(files[path]), { profile: p, standingRules: rules })));
    // Each artifact decoder checks its local count. The contract caps the union.
    const continuous = PATHS.reader_authority.reduce((n, path) => n + Object.values(object(files[path])).filter(v => object(v).kind === 'continuous_team').length, 0);
    p.check('max_continuous_reader_rules', continuous);
    for (let i = 0; i < 32; i++) {
        const index = object(files[PATHS.derived_index[i]!]), detail = object(files[PATHS.status_detail[i]!]);
        const expected = Object.fromEntries(Object.entries(detail).map(([id, v]) => [id, indexRow(object(v))]));
        require(same(index, expected), 'private index and detail facts disagree');
    }
}
function indexRow(row: Row): Row { return { login_snapshot: row.login_snapshot, login_as_of: row.login_as_of, agreements: row.agreements, exempt: Object.keys(object(row.exemption_sources)).length > 0 }; }
/** Own every shard, including rows not touched by the next event. */
export async function derivedPlaintext(projectId: string, canonicalOid: string, input: unknown, p: ReleaseProfile): Promise<DerivedPlaintext> {
    try {
        const project = text(projectId), head = oid(canonicalOid), value = clone(input); profile(p);
        object(value, ['files', 'configuration', 'standing_rules']);
        await validateEventOperation('config_updated', {}, { project_configuration: value.configuration });
        await validateFiles(object(value.files), value.standing_rules, p);
        // Validate empty standing rules too, even if every detail shard is empty.
        p.check('max_continuous_exemption_rules', Object.keys(object(value.standing_rules)).length);
        const stored = freezeJson(value as JsonObject);
        const result: DerivedPlaintext = Object.freeze({ projectId: project, canonicalOid: head,
            toDict: () => clone(stored) as JsonObject,
            plaintextFiles: () => Object.freeze(Object.fromEntries(SHARDS.map(path => [path, canonicalJson(object(stored.files)[path])]))) });
        models.set(result, { value: stored as Row, profile: p }); return result;
    } catch (cause) { if (cause instanceof DerivedClassOverflow) throw cause; throw new DerivedError('invalid private derived plaintext', { cause }); }
}
export function derivedDelta(before: DerivedPlaintext, after: DerivedPlaintext): { readonly files: readonly string[]; readonly classes: readonly DerivedClass[] } {
    const a = plain(before).value, b = plain(after).value; require(before.projectId === after.projectId, 'delta crosses projects');
    const changed = SHARDS.filter(path => !same(object(a.files)[path], object(b.files)[path]));
    const rules = !same(a.standing_rules, b.standing_rules);
    const classes = DERIVED_CLASSES.filter(c => PATHS[c].some(path => changed.includes(path)) || (c === 'status_detail' && rules));
    if (changed.length || rules) changed.push(STATE);
    return Object.freeze({ files: Object.freeze(changed.sort()), classes: Object.freeze(classes) });
}
function emptyFacts(kind = 'none', eventId: unknown = null): Row { return { version: null, accepted_at: null, revoked_at: null, basis: { kind, event_id: eventId } }; }
/** Apply one caller-authenticated committed append, without replaying history. */
export async function updateDerived(before: DerivedPlaintext, input: unknown, expectedHead: string): Promise<DerivedPlaintext> {
    try {
        const { value, profile: p } = plain(before), record = clone(input); object(record, ['event', 'commit_oid', 'parent_oid']);
        const head = oid(expectedHead), commit = oid(record.commit_oid);
        require(before.canonicalOid === head && record.parent_oid === head && commit !== head, 'incremental source/parent mismatch');
        const e = clone(await validateEvent(record.event, { expectedProjectId: before.projectId })), t = object(e.target), payload = object(e.payload), type = e.type as string;
        require(type !== 'project_connected', 'connection requires explicit initial private snapshot');
        const files = object(value.files), rules = object(value.standing_rules), old = object(plain(before).value.files);
        const row = (id: unknown): Row => {
            const key = String(id), path = PATHS.status_detail[coverageShard(id as number, 32)]!, shard = object(files[path]);
            if (!Object.hasOwn(shard, key)) put(shard, key, { login_snapshot: null, login_as_of: null, agreements: {}, exemption_sources: {}, exemption_sequence_next: 0, materialization_cursor: {} });
            return object(shard[key]);
        };
        const add = (subject: Row, sourceId: string, source: Row): void => {
            const r = row(subject.github_user_id), sources = object(r.exemption_sources);
            require(!Object.hasOwn(sources, sourceId), 'duplicate exemption source');
            put(sources, sourceId, { ...source, sequence: r.exemption_sequence_next });
            r.exemption_sequence_next = (r.exemption_sequence_next as number) + 1;
        };
        if (type === 'config_updated') value.configuration = payload.project_configuration;
        else if (type === 'acceptance' || type === 'revocation') {
            const tuple = object(t.coverage_tuple), facts = emptyFacts(type, e.event_id);
            if (type === 'acceptance') Object.assign(facts, { version: t.version, accepted_at: e.recorded_at });
            else facts.revoked_at = e.recorded_at;
            put(object(row(tuple.github_user_id).agreements), text(tuple.agreement_id), facts);
        } else if (type === 'exemption' || type === 'exemption_snapshot') {
            const subjects = type === 'exemption' ? [object(t.subject)] : t.subjects as Row[];
            for (const subject of subjects) add(subject, e.event_id as string, { source_kind: type === 'exemption' ? payload.source_kind : 'snapshot', team: type === 'exemption' ? null : payload.team, basis: payload.basis, instrument_ref: payload.instrument_ref, rule_event_id: null });
        } else if (type === 'exemption_source_withdrawn') {
            const key = String(object(t.subject).github_user_id), path = PATHS.status_detail[coverageShard(Number(key), 32)]!;
            const existing = own(object(files[path]), key);
            if (existing !== undefined) delete object(object(existing).exemption_sources)[t.source_event_id as string];
        } else if (type === 'exemption_rule_configured') {
            require(!Object.hasOwn(rules, e.event_id as string), 'duplicate standing rule');
            put(rules, e.event_id as string, { team: t.team, basis: payload.basis, instrument_ref: payload.instrument_ref });
        } else if (type === 'exemption_rule_withdrawn') {
            delete rules[t.rule_event_id as string];
            for (const path of PATHS.status_detail) for (const v of Object.values(object(files[path]))) {
                delete object(object(v).exemption_sources)[t.rule_event_id as string];
                delete object(object(v).materialization_cursor)[t.rule_event_id as string];
            }
        } else if (type === 'exemption_materialized') {
            const id = t.rule_event_id as string, rule = object(own(rules, id)), r = row(object(t.subject).github_user_id), cursor = object(r.materialization_cursor), sources = object(r.exemption_sources);
            require(same(rule.team, payload.team) && (own(cursor, id) ?? null) === payload.prior_materialization_event_id, 'exemption rule or cursor mismatch');
            require(Object.hasOwn(sources, id) !== (payload.result === 'add'), 'exemption materialization presence mismatch');
            if (payload.result === 'add') add(object(t.subject), id, { ...rule, source_kind: 'continuous_team', rule_event_id: id });
            else delete sources[id];
            put(cursor, id, e.event_id);
        } else if (type.startsWith('records_reader_')) {
            const id = (type === 'records_reader_withdrawn' ? t.source_event_id : type.includes('materialized') || type.includes('rule_withdrawn') ? t.rule_event_id : e.event_id) as string;
            const shard = object(files[PATHS.reader_authority[await readerAuthorityShard(id)]!]);
            if (type === 'records_reader_authorized' || type === 'records_reader_snapshot_authorized' || type === 'records_reader_rule_configured') {
                require(!Object.hasOwn(shard, id), 'duplicate reader source');
                const members = type === 'records_reader_authorized' ? [object(t.subject)] : type === 'records_reader_snapshot_authorized' ? t.subjects as Row[] : [];
                put(shard, id, { kind: type === 'records_reader_authorized' ? 'individual' : type === 'records_reader_snapshot_authorized' ? 'snapshot' : 'continuous_team', team: type === 'records_reader_authorized' ? null : type === 'records_reader_snapshot_authorized' ? payload.team : t.team, materialization_cursor: {}, subjects: Object.fromEntries(members.map(s => [String(s.github_user_id), { added_event_id: e.event_id }])) });
            } else if (type === 'records_reader_rule_withdrawn') delete shard[id];
            else {
                const existing = own(shard, id);
                if (type === 'records_reader_materialized') require(existing !== undefined, 'reader rule source missing');
                if (existing !== undefined) {
                    const source = object(existing), members = object(source.subjects), key = String(object(t.subject).github_user_id);
                    if (type === 'records_reader_materialized') {
                        const cursor = object(source.materialization_cursor);
                        require(source.kind === 'continuous_team' && same(source.team, payload.team) && (own(cursor, key) ?? null) === payload.prior_materialization_event_id, 'reader rule or cursor mismatch');
                        require(Object.hasOwn(members, key) !== (payload.result === 'add'), 'reader materialization presence mismatch');
                        put(cursor, key, e.event_id);
                        if (payload.result === 'add') put(members, key, { added_event_id: e.event_id }); else delete members[key];
                    } else {
                        delete members[key];
                        if (!Object.keys(members).length && source.kind !== 'continuous_team') delete shard[id];
                    }
                }
            }
        }
        // Advance login only when this event changes subject facts and writes
        // the index class. Merely appearing as an actor is not a row update.
        const observed = new Map<string, unknown>();
        for (const s of [e.actor, t.subject, ...(t.subjects as unknown[] ?? []), payload.subject, ...(payload.subjects as unknown[] ?? [])]) {
            if (s && typeof s === 'object' && Object.hasOwn(s, 'github_user_id') && Object.hasOwn(s, 'login_snapshot')) observed.set(String(object(s).github_user_id), object(s).login_snapshot);
        }
        const indexEvent = ['acceptance', 'revocation', 'exemption', 'exemption_snapshot', 'exemption_source_withdrawn', 'exemption_materialized'].includes(type);
        for (let i = 0; i < 32; i++) {
            const path = PATHS.status_detail[i]!;
            for (const [key, v] of Object.entries(object(files[path]))) {
                const r = object(v), priorValue = own(object(old[path]), key), prior = priorValue === undefined ? undefined : object(priorValue);
                const facts = (r: Row) => Object.fromEntries(Object.entries(r).filter(([k]) => !['login_snapshot', 'login_as_of'].includes(k)));
                const changed = prior === undefined || !same(facts(r), facts(prior));
                const writes = indexEvent || (type === 'exemption_rule_withdrawn' && prior !== undefined && Boolean(Object.keys(object(r.exemption_sources)).length) !== Boolean(Object.keys(object(prior.exemption_sources)).length));
                if (changed && writes && observed.has(key)) { r.login_snapshot = observed.get(key); r.login_as_of = e.recorded_at; }
            }
            files[PATHS.derived_index[i]!] = Object.fromEntries(Object.entries(object(files[path])).map(([k, r]) => [k, indexRow(object(r))]));
        }
        return await derivedPlaintext(before.projectId, commit, value, p);
    } catch (cause) { if (cause instanceof DerivedClassOverflow) throw cause; throw new DerivedError('invalid incremental private update', { cause }); }
}
export interface DerivedProjection {
    readonly plaintext: DerivedPlaintext;
    stateDict(): JsonObject;
    plaintextFiles(): Readonly<Record<string, Uint8Array<ArrayBuffer>>>;
}
async function envelopeDigest(raw: Uint8Array, project: string, path: string, p: ReleaseProfile): Promise<string> {
    const v = object(parseCanonicalJson(raw), ['envelope_version', 'algorithm', 'project_id', 'artifact_kind', 'logical_id', 'schema_version', 'kid', 'nonce', 'ciphertext']);
    const id = resolveArtifactIdentity('records', 'derived', path);
    require(v.envelope_version === 1 && v.algorithm === 'A256GCM' && v.project_id === project && v.artifact_kind === id.artifact_kind && v.logical_id === id.logical_id && v.schema_version === id.schema_version, 'derived envelope context mismatch');
    base64urlDecode(text(v.kid), 16); base64urlDecode(text(v.nonce), 12);
    const size = base64urlDecode(text(v.ciphertext)).length; require(size >= 16, 'missing authentication tag'); limit(p, size, kind(path));
    return 'sha256:' + Array.from(await sha256(raw), b => b.toString(16).padStart(2, '0')).join('');
}
function envelopes(input: Readonly<Record<string, Uint8Array>>): Record<string, Uint8Array<ArrayBuffer>> {
    object(input);
    return Object.fromEntries(Reflect.ownKeys(input).map(path => {
        const d = Object.getOwnPropertyDescriptor(input, path)!;
        require(typeof path === 'string' && d.enumerable && Object.hasOwn(d, 'value') && d.value instanceof Uint8Array, 'own envelope byte values required');
        return [path, copyBytes(d.value as Uint8Array)];
    }));
}
/** State publication is possible only with a complete 96-shard candidate. */
export async function assembleDerivedProjection(plaintext: DerivedPlaintext, canonicalGenerations: unknown, encryptedShards: Readonly<Record<string, Uint8Array>>): Promise<DerivedProjection> {
    const { value, profile: p } = plain(plaintext), g = generations(canonicalGenerations), encoded = envelopes(encryptedShards); object(encoded, SHARDS);
    const digests: Row = {};
    for (const c of DERIVED_CLASSES) digests[c] = Object.fromEntries(await Promise.all(PATHS[c].map(async (path, i) => [String(i).padStart(2, '0'), await envelopeDigest(encoded[path]!, plaintext.projectId, path, p)])));
    const installed = p.toDict(), state = { state_version: 1, generations: Object.fromEntries(DERIVED_CLASSES.map(c => [c, g[c]])), shard_digests: digests, standing_rules: value.standing_rules, shard_count: 32, profile: Object.fromEntries(['max_shard_ciphertext_bytes', 'max_reader_source_members', 'max_continuous_reader_rules'].map(k => [k, installed[k]])) };
    await decodeProjection(resolveArtifactIdentity('records', 'derived', STATE), canonicalJson(state), { profile: p });
    const frozen = freezeJson(state as JsonObject), result = Object.freeze({ plaintext,
        stateDict: () => clone(frozen) as JsonObject,
        plaintextFiles: () => Object.freeze({ ...plaintext.plaintextFiles(), [STATE]: canonicalJson(frozen) }) });
    projections.set(result, frozen as Row); return result;
}
/** Publish a completed candidate only within the installed bulk fan-out bound. */
export async function publishDerivedProjection(before: DerivedPlaintext, after: DerivedPlaintext, canonicalGenerations: unknown, encryptedShards: Readonly<Record<string, Uint8Array>>): Promise<DerivedProjection> {
    const count = derivedDelta(before, after).files.filter(path => path !== STATE).length;
    const p = plain(after).profile;
    require(same(plain(before).profile.toDict(), p.toDict()), 'publication changed installed profile');
    if (count > 2) p.check('max_bulk_shards_per_operation', count);
    return assembleDerivedProjection(after, canonicalGenerations, encryptedShards);
}
/** A stale shrink-only append must stand without completing its private class. */
export async function updateDerivedProjection(before: DerivedProjection, record: unknown, options: {
    expectedHead: string; priorGenerations: unknown; generations: unknown; encryptedShards: Readonly<Record<string, Uint8Array>>;
}): Promise<{ readonly skipped: boolean; readonly projection: DerivedProjection }> {
    const state = projections.get(before); require(state, 'validated derived projection required');
    const r = clone(record); object(r, ['event', 'commit_oid', 'parent_oid']);
    object(options, ['expectedHead', 'priorGenerations', 'generations', 'encryptedShards']);
    require(Object.values(Object.getOwnPropertyDescriptors(options)).every(d => Object.hasOwn(d, 'value')), 'own update options required');
    const expectedHead = oid(options.expectedHead), prior = generations(options.priorGenerations), next = generations(options.generations), encoded = envelopes(options.encryptedShards);
    const e = await validateEvent(r.event, { expectedProjectId: before.plaintext.projectId });
    require(r.parent_oid === expectedHead && oid(r.commit_oid) !== r.parent_oid, 'append identity mismatch');
    if (['records_reader_withdrawn', 'records_reader_rule_withdrawn'].includes(e.type) && object(state.generations).reader_authority !== prior.reader_authority) return Object.freeze({ skipped: true, projection: before });
    const after = await updateDerived(before.plaintext, r, expectedHead);
    const changed = derivedDelta(before.plaintext, after).classes;
    const published = { ...next };
    for (const c of DERIVED_CLASSES) {
        if (changed.includes(c)) require(next[c] === e.event_id, 'changed class lacks its canonical generation');
        if (next[c] !== prior[c]) { require(next[c] === e.event_id, 'new generation must name this append'); require(object(state.generations)[c] === prior[c], 'affected class was stale'); }
        else published[c] = object(state.generations)[c];
    }
    return Object.freeze({ skipped: false, projection: await publishDerivedProjection(before.plaintext, after, published, encoded) });
}
export interface DerivedReadProjection {
    readonly projectId: string; readonly canonicalOid: string; readonly selectedClass: DerivedClass;
    stateDict(): JsonObject; selectedFiles(): JsonObject; rowForSubject(subject: number): JsonObject;
}
/** A reader-authority read always validates the complete 32-shard union. */
export async function derivedReadProjection(projectId: string, canonicalOid: string, input: {
    state: unknown; selectedFiles: unknown; selectedEnvelopes: Readonly<Record<string, Uint8Array>>; generation: string; profile: ReleaseProfile;
}): Promise<DerivedReadProjection> {
    try {
        const project = text(projectId), head = oid(canonicalOid), state = clone(input.state), files = clone(input.selectedFiles), encoded = envelopes(input.selectedEnvelopes), generation = token(input.generation), p = input.profile; profile(p);
        await decodeProjection(resolveArtifactIdentity('records', 'derived', STATE), canonicalJson(state), { profile: p });
        const paths = Object.keys(files); require(paths.length > 0 && same(paths.sort(), Object.keys(encoded).sort()), 'selected plaintext/envelope paths disagree');
        const c = kind(paths[0]!); require(paths.every(path => kind(path) === c), 'read selects one private class');
        if (c === 'reader_authority') object(files, PATHS.reader_authority);
        require(object(state.generations)[c] === generation, 'selected derived generation is stale');
        await Promise.all(paths.map(async path => {
            await decodeProjection(resolveArtifactIdentity('records', 'derived', path), canonicalJson(files[path]), { profile: p, standingRules: state.standing_rules });
            const digest = await envelopeDigest(encoded[path]!, project, path, p);
            require(object(object(state.shard_digests)[c])[String(PATHS[c].indexOf(path)).padStart(2, '0')] === digest, 'selected envelope digest mismatch');
        }));
        if (c === 'reader_authority') p.check('max_continuous_reader_rules', paths.reduce((n, path) => n + Object.values(object(files[path])).filter(v => object(v).kind === 'continuous_team').length, 0));
        const stored = freezeJson(files as JsonObject), frozenState = freezeJson(state as JsonObject);
        const result: DerivedReadProjection = Object.freeze({ projectId: project, canonicalOid: head, selectedClass: c,
            stateDict: () => clone(frozenState) as JsonObject, selectedFiles: () => clone(stored) as JsonObject,
            rowForSubject: (subject: number) => { require(c !== 'reader_authority', 'reader authority has no dashboard rows'); const path = PATHS[c][coverageShard(subject, 32)]!, shard = object(own(stored as Row, path)); return clone(own(shard, String(subject))) as JsonObject; } });
        reads.set(result, { files: stored as Row, state: frozenState as Row, profile: p }); return result;
    } catch (cause) { if (cause instanceof DerivedClassOverflow) throw cause; throw new DerivedError('invalid selected private read', { cause }); }
}
export interface ReadStatusInput {
    readonly projectId: string; readonly canonicalOid: string; readonly subject: number; readonly agreementId: string;
    readonly row: unknown; readonly coverage: CoverageProjection; readonly effectiveScope: unknown;
    readonly operationState: readonly [unknown, unknown]; readonly profile: ReleaseProfile; readonly standingRules?: unknown;
}
/** Stored signature/exemption facts plus the present-tense coverage fence. */
export async function resolveReadStatus(input: ReadStatusInput): Promise<ReadonlyJsonObject> {
    const project = text(input.projectId), head = oid(input.canonicalOid), subject = input.subject, agreement = text(input.agreementId), row = clone(input.row);
    const scope = parseCanonicalJson(canonicalJson(input.effectiveScope)), pair = parseCanonicalJson(canonicalJson(input.operationState));
    validateEnforcementScope(scope); validateCoverageProjection(input.coverage, project, head);
    const covered = input.coverage.toDict(), source = object(covered['source.enc.json']), active = object(covered['agreements/active.enc.json']);
    require(source.project_state !== 'succeeded', 'project has succeeded');
    require(Array.isArray(pair) && pair.length === 2 && same(pair, [covered['inflight.enc.json'], covered['decision-fence.enc.json']]), 'operation state is not from the same coverage observation');
    require(active.agreement_id === null || active.agreement_id === agreement, 'requested agreement differs from current currency');
    const detail = Object.hasOwn(row, 'exemption_sources'), path = PATHS[detail ? 'status_detail' : 'derived_index'][coverageShard(subject, 32)]!;
    await decodeProjection(resolveArtifactIdentity('records', 'derived', path), canonicalJson({ [String(subject)]: row }), { profile: input.profile, standingRules: input.standingRules ?? {} });
    const agreements = object(row.agreements), facts = own(agreements, agreement) === undefined ? emptyFacts() : object(own(agreements, agreement)), basis = object(facts.basis), fence = object(covered['decision-fence.enc.json']);
    let event = basis.event_id, status: string, reason: string, generic: string;
    const sources = detail ? object(row.exemption_sources) : {}, exempt = detail ? Object.keys(sources).length > 0 : row.exempt;
    if (fence.state === 'mutation' && (fence.project_wide || (fence.subjects as number[]).includes(subject))) { status = 'indeterminate'; reason = 'operation_in_flight'; generic = 'indeterminate'; event = null; }
    else if (basis.kind === 'unresolved') { status = 'indeterminate'; reason = 'replay_unresolved'; generic = 'indeterminate'; }
    else if (basis.kind === 'acceptance' && (active.accepted_versions as unknown[]).includes(facts.version)) { status = 'current'; reason = 'accepted_current_version'; generic = 'signed'; }
    else if (exempt) { status = 'exempt'; reason = 'exempt_source_active'; generic = 'exempt'; event = detail ? Object.keys(sources).reduce((a, b) => (object(sources[a]).sequence as number) > (object(sources[b]).sequence as number) ? a : b) : null; }
    else if (basis.kind === 'acceptance') { const retired = (active.retired_versions as unknown[]).includes(facts.version); status = retired ? 'superseded' : 'revoked'; reason = retired ? 'superseded_by_activation' : 'version_not_accepted'; generic = 'version_not_active'; }
    else if (basis.kind === 'revocation') { status = 'revoked'; reason = 'revoked_by_contributor'; generic = 'revoked'; }
    else { status = 'revoked'; reason = 'no_acceptance_recorded'; generic = 'not_signed'; }
    return freezeJson({ status, reason_code: reason, event_id: event, version: facts.version, accepted_at: facts.accepted_at, revoked_at: facts.revoked_at, enforcement_scope: scope, coverage_decision: ['current', 'exempt'].includes(status) ? 'covered' : 'uncovered', coverage_reason_code: generic } as JsonObject);
}
export async function resolveSelectedReadStatus(read: DerivedReadProjection, subject: number, agreementId: string, coverage: CoverageProjection, effectiveScope: unknown, operationState: readonly [unknown, unknown]): Promise<ReadonlyJsonObject> {
    const value = reads.get(read); require(value, 'validated selected read required');
    return resolveReadStatus({ projectId: read.projectId, canonicalOid: read.canonicalOid, subject, agreementId, row: read.rowForSubject(subject), coverage, effectiveScope, operationState, profile: value.profile, standingRules: value.state.standing_rules });
}
/** Project the named stored source after freshness checks; M5 verifies live membership. */
export async function readerSourceForSubject(read: DerivedReadProjection, sourceId: string, subject: number): Promise<ReadonlyJsonObject> {
    const value = reads.get(read); require(value && read.selectedClass === 'reader_authority', 'validated complete reader authority required');
    coverageShard(subject, 32);
    const id = token(sourceId), path = PATHS.reader_authority[await readerAuthorityShard(id)]!;
    const shard = object(own(value.files, path)), candidate = own(shard, id);
    require(candidate, 'named reader source is not present');
    const source = object(candidate);
    require(Object.hasOwn(object(source.subjects), String(subject)), 'subject is not a member of the named reader source');
    const team = source.kind === 'continuous_team' ? object(source.team) : null;
    return freezeJson({ source_id: id, kind: source.kind, organization_id: team?.organization_id ?? null, team_id: team?.team_id ?? null } as JsonObject);
}
