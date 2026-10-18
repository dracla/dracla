/** Pure closed operation cells and coverage guards (HLD 5.4).
 * Repository authentication and projection/read-back observations belong to the caller.
 */
import { canonicalJson, parseCanonicalJson, freezeJson, type JsonObject, type JsonValue, type ReadonlyJsonObject } from './canonical.js';
import { base64urlDecode, base64urlEncode, copyBytes } from './encoding.js';
import { resolveArtifactIdentity, sha256 } from './artifacts.js';
import { decodeProjection, OperationCorruption } from './projections.js';
import { validateEvent, parseEventJcs, validateSideArtifactPackage } from './events.js';
export { OperationCorruption } from './projections.js';
export class OperationConflict extends Error {
    constructor(message: string) { super(message); this.name = new.target.name; }
}
export interface PreparedOperation {
    readonly state: string;
    readonly generation: number;
    toDict(): JsonObject;
}
export interface DecisionFence {
    readonly state: string;
    readonly generation: number;
    toDict(): JsonObject;
}
export interface InFlightMarker {
    toDict(): JsonObject;
}
export interface PreparedOperationReference {
    readonly commitOid: string;
    readonly blobSha: string;
    readonly cell: PreparedOperation;
}
type Kind = 'cell' | 'fence' | 'marker';
const states = new WeakMap<object, {
    kind: Kind;
    data: ReadonlyJsonObject;
}>();
const references = new WeakSet<object>();
const ownerFields = ['operation_id', 'operation_sha256'] as const;
const packageFields = ['prepared_events_head', 'event_jcs_b64', 'side_artifacts'] as const;
const referenceFields = ['prepared_commit_oid', 'prepared_blob_sha', 'prepared_generation'] as const;
const scopeFields = ['subjects', 'project_wide'] as const;
function require(value: unknown, message = 'invalid operation state'): asserts value {
    if (!value)
        throw new OperationCorruption(message);
}
function conflict(value: unknown, message: string): asserts value {
    if (!value)
        throw new OperationConflict(message);
}
function wire(value: unknown): Uint8Array<ArrayBuffer> {
    try {
        return canonicalJson(value);
    }
    catch {
        throw new OperationCorruption('operation state must contain valid canonical JSON values');
    }
}
function clone(value: unknown): JsonValue { return parseCanonicalJson(wire(value)); }
function object(value: unknown, fields?: readonly string[]): JsonObject {
    require(value !== null && typeof value === 'object' && !Array.isArray(value));
    if (fields)
        require(Object.keys(value).length === fields.length && fields.every(k => Object.hasOwn(value, k)), 'state has missing or extra members');
    return value as JsonObject;
}
function text(value: unknown): string { require(typeof value === 'string' && value.length > 0); return value; }
function count(value: unknown, positive = false): number {
    require(typeof value === 'number' && Number.isSafeInteger(value) && value >= (positive ? 1 : 0));
    return value;
}
function oid(value: unknown): string { const s = text(value); require(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(s)); return s; }
function digest(value: unknown): string { const s = text(value); require(/^sha256:[a-f0-9]{64}$/.test(s)); return s; }
function token(value: unknown): string {
    try {
        const s = text(value);
        base64urlDecode(s, 32);
        return s;
    }
    catch {
        throw new OperationCorruption('invalid 32-byte identity');
    }
}
function equal(a: unknown, b: unknown): boolean {
    const left = wire(a), right = wire(b);
    return left.length === right.length && left.every((v, i) => v === right[i]);
}
function make(kind: 'cell', data: JsonObject): PreparedOperation;
function make(kind: 'fence', data: JsonObject): DecisionFence;
function make(kind: 'marker', data: JsonObject): InFlightMarker;
function make(kind: Kind, data: JsonObject): PreparedOperation | DecisionFence | InFlightMarker {
    const owned = freezeJson(object(clone(data))), toDict = () => object(clone(owned));
    const result = kind === 'marker' ? { toDict } : { state: text(owned.state), generation: count(owned.generation), toDict };
    states.set(result, { kind, data: owned });
    return Object.freeze(result);
}
function value(input: unknown, kind: Kind): JsonObject {
    require(input !== null && typeof input === 'object');
    const saved = states.get(input);
    require(saved && saved.kind === kind, 'wrong operation-state value type');
    return object(clone(saved.data));
}
function owner(obj: JsonObject): readonly [
    string,
    string
] { return [token(obj.operation_id), digest(obj.operation_sha256)]; }
function requireOwner(obj: JsonObject, operationId: string, operationSha256: string): void {
    conflict(equal(owner(obj), owner({ operation_id: operationId, operation_sha256: operationSha256 })), 'operation owner does not match');
}
function bounded(data: Uint8Array, limit: number): Uint8Array<ArrayBuffer> {
    count(limit, true);
    const owned = copyBytes(data);
    require(owned.length <= limit, 'prepared operation exceeds its explicit byte limit');
    return owned;
}
async function domainHash(domain: string, obj: JsonObject): Promise<string> {
    const prefix = new TextEncoder().encode(domain + '\0'), data = wire(obj), all = new Uint8Array(prefix.length + data.length);
    all.set(prefix);
    all.set(data, prefix.length);
    return base64urlEncode(await sha256(all));
}
export async function appendClaim(operationId: string, operationSha256: string, appendHead: string): Promise<string> {
    const obj = { operation_id: operationId, operation_sha256: operationSha256, append_head: appendHead };
    owner(obj);
    oid(appendHead);
    return domainHash('dracla-append-claim-v1', obj);
}
export async function authoritativeCheckIdentity(input: {
    repository_id: number;
    merge_group_head_oid: string;
    pull_request_number: number;
    github_delivery_id: string;
}): Promise<string> {
    const obj = object(clone(input), ['repository_id', 'merge_group_head_oid', 'pull_request_number', 'github_delivery_id']);
    count(obj.repository_id, true);
    oid(obj.merge_group_head_oid);
    count(obj.pull_request_number, true);
    text(obj.github_delivery_id);
    return domainHash('dracla-authoritative-check-v1', obj);
}
export interface PreparedDecodeOptions {
    expectedProjectId: string;
    maxPreparedOperationBytes: number;
    preconditions?: unknown;
}
export async function decodePreparedOperation(data: Uint8Array, options: PreparedDecodeOptions): Promise<PreparedOperation> {
    try {
        const project = text(options.expectedProjectId), limit = count(options.maxPreparedOperationBytes, true);
        const facts = clone(options.preconditions ?? null), obj = object(parseCanonicalJson(bounded(data, limit)));
        const state = obj.state, fields: string[] = ['state', 'generation'];
        if (state === 'prepared' || state === 'appending') {
            fields.push(...ownerFields, 'event_id', ...packageFields);
            if (state === 'appending')
                fields.push('append_head', 'append_claim');
        }
        else if (state === 'terminal')
            fields.push(...ownerFields, 'event_id', 'result', 'observed_events_head', 'canonical_commit');
        else
            require(state === 'idle', 'unknown prepared state');
        object(obj, fields);
        count(obj.generation);
        if (state !== 'idle') {
            owner(obj);
            token(obj.event_id);
        }
        if (state === 'prepared' || state === 'appending') {
            require(Array.isArray(obj.side_artifacts));
            for (const artifact of obj.side_artifacts)
                object(artifact, ['kind', 'path', 'bytes_b64', 'sha256']);
            const head = oid(obj.prepared_events_head), eventBytes = base64urlDecode(text(obj.event_jcs_b64));
            const event = await parseEventJcs(eventBytes, { expectedProjectId: project });
            require(event.idempotency_key === obj.operation_id && event.operation_sha256 === obj.operation_sha256 && event.event_id === obj.event_id, 'frozen event identity disagrees with cell');
            await validateSideArtifactPackage(event, obj.side_artifacts, facts, head);
            if (state === 'appending')
                require(obj.append_claim === await appendClaim(...owner(obj), oid(obj.append_head)), 'append claim disagrees with cell');
        }
        if (state === 'terminal') {
            oid(obj.observed_events_head);
            require(['landed', 'semantic_noop', 'conflict'].includes(text(obj.result)), 'unknown terminal result');
            if (obj.result === 'landed')
                oid(obj.canonical_commit);
            else
                require(obj.canonical_commit === null, 'non-landed result cannot carry a canonical commit');
        }
        return make('cell', obj);
    }
    catch {
        throw new OperationCorruption('invalid prepared operation bytes or frozen package');
    }
}
export function encodePreparedOperation(cell: PreparedOperation, options: {
    maxPreparedOperationBytes: number;
}): Uint8Array<ArrayBuffer> {
    return bounded(wire(value(cell, 'cell')), options.maxPreparedOperationBytes);
}
export async function decodeDecisionFence(data: Uint8Array): Promise<DecisionFence> {
    try {
        const result = await decodeProjection(resolveArtifactIdentity('coverage', 'coverage', 'decision-fence.enc.json'), copyBytes(data));
        return make('fence', object(clone(result)));
    }
    catch {
        throw new OperationCorruption('invalid decision-fence bytes');
    }
}
export function encodeDecisionFence(fence: DecisionFence): Uint8Array<ArrayBuffer> { return wire(value(fence, 'fence')); }
export async function decodeInflightMarker(data: Uint8Array): Promise<InFlightMarker> {
    try {
        const result = await decodeProjection(resolveArtifactIdentity('coverage', 'coverage', 'inflight.enc.json'), copyBytes(data));
        return make('marker', object(clone(result)));
    }
    catch {
        throw new OperationCorruption('invalid in-flight marker bytes');
    }
}
export function encodeInflightMarker(marker: InFlightMarker): Uint8Array<ArrayBuffer> { return wire(value(marker, 'marker')); }
export function preparedOperationReference(commitOid: string, blobSha: string, cell: PreparedOperation): PreparedOperationReference {
    oid(commitOid);
    oid(blobSha);
    require(value(cell, 'cell').state === 'prepared', 'reference must contain the original prepared cell');
    const ref = Object.freeze({ commitOid, blobSha, cell });
    references.add(ref);
    return ref;
}
function operationScope(prepared: JsonObject): readonly [
    JsonValue[],
    boolean
] {
    const event = object(parseCanonicalJson(base64urlDecode(text(prepared.event_jcs_b64)))), target = object(event.target);
    let subjects: JsonValue[];
    if (event.type === 'acceptance' || event.type === 'revocation')
        subjects = [object(target.coverage_tuple).github_user_id!];
    else if (event.type === 'override')
        subjects = (object(event.payload).subjects as JsonValue[]).map(row => object(row).github_user_id!);
    else if (Object.hasOwn(target, 'subject'))
        subjects = [object(target.subject).github_user_id!];
    else if (Object.hasOwn(target, 'subjects'))
        subjects = (target.subjects as JsonValue[]).map(row => object(row).github_user_id!);
    else
        return [[], true];
    return [subjects.sort((a, b) => count(a, true) - count(b, true)), false];
}
function reference(fence: JsonObject, cell: JsonObject, ref: PreparedOperationReference | undefined): void {
    require(ref !== undefined && references.has(ref), 'mutation requires its authenticated prepared reference');
    const original = value(ref.cell, 'cell');
    require(equal(referenceFields.map(k => fence[k]), [ref.commitOid, ref.blobSha, ref.cell.generation]), 'prepared commit, blob or generation disagrees');
    require(cell.state !== 'idle' && equal(owner(fence), owner(cell)) && equal(owner(cell), owner(original)), 'prepared operation owner disagrees');
    require(cell.event_id === original.event_id && cell.generation === original.generation, 'prepared event or generation disagrees');
    require(equal([fence.subjects, fence.project_wide], operationScope(original)), 'mutation scope disagrees with frozen event');
    if (cell.state === 'prepared' || cell.state === 'appending')
        require(packageFields.every(k => equal(cell[k], original[k])), 'current cell changed its frozen package');
}
function markerMatches(marker: JsonObject, fence: JsonObject): boolean {
    const ops = object(marker.ops);
    if (!Object.keys(ops).length)
        return true;
    const entry = ops[text(fence.operation_id)];
    return entry !== undefined && ['operation_sha256', ...scopeFields].every(k => equal(object(entry)[k], fence[k]));
}
export function validateOperationCrossBindings(cell: PreparedOperation, fence: DecisionFence, marker: InFlightMarker, options: {
    preparedReference?: PreparedOperationReference;
} = {}): void {
    const c = value(cell, 'cell'), f = value(fence, 'fence'), m = value(marker, 'marker');
    if (f.state === 'mutation') {
        reference(f, c, options.preparedReference);
        require(markerMatches(m, f), 'marker does not match mutation fence');
    }
    else
        require(!Object.keys(object(m.ops)).length && c.state !== 'appending', 'marker or append right lacks a mutation fence');
}
function mutationBinding(cell: PreparedOperation, fence: DecisionFence, marker: InFlightMarker, ref: PreparedOperationReference): void {
    validateOperationCrossBindings(cell, fence, marker, { preparedReference: ref });
    conflict(fence.state === 'mutation', 'transition requires its matching mutation fence');
}
function wireArtifacts(input: unknown): JsonValue[] {
    require(Array.isArray(input) && Reflect.ownKeys(input).length === input.length + 1, 'side artifacts must be a plain array');
    return Array.from({ length: input.length }, (_, i) => {
        const descriptor = Object.getOwnPropertyDescriptor(input, String(i));
        require(descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable);
        const entry: unknown = descriptor.value;
        require(entry !== null && typeof entry === 'object' && !Array.isArray(entry));
        const keys = ['kind', 'path', Object.hasOwn(entry, 'bytes') ? 'bytes' : 'bytes_b64', 'sha256'];
        require(Reflect.ownKeys(entry).length === keys.length && keys.every(k => {
            const d = Object.getOwnPropertyDescriptor(entry, k);
            return d && Object.hasOwn(d, 'value') && d.enumerable;
        }), 'artifact has missing, extra or accessor fields');
        const row = entry as Record<string, unknown>, bytes = Object.hasOwn(row, 'bytes') ? copyBytes(row.bytes as Uint8Array) : base64urlDecode(text(row.bytes_b64));
        return clone({ kind: row.kind, path: row.path, bytes_b64: base64urlEncode(bytes), sha256: row.sha256 });
    });
}
export async function prepareOperation(cell: PreparedOperation, event: unknown, artifacts: unknown, options: {
    expectedProjectId: string;
    expectedEventsHead: string;
    preconditions: unknown;
    maxPreparedOperationBytes: number;
}): Promise<PreparedOperation> {
    const old = value(cell, 'cell'), head = oid(options.expectedEventsHead), project = text(options.expectedProjectId), limit = count(options.maxPreparedOperationBytes, true);
    let eventInput: JsonValue, entries: JsonValue[], facts: JsonValue;
    try {
        eventInput = clone(event);
        entries = wireArtifacts(artifacts);
        facts = clone(options.preconditions);
    }
    catch {
        throw new OperationCorruption('invalid proposed event or artifacts');
    }
    let valid: Awaited<ReturnType<typeof validateEvent>>;
    try {
        valid = await validateEvent(eventInput, { expectedProjectId: project });
    }
    catch {
        throw new OperationCorruption('invalid proposed event or artifacts');
    }
    const obj: JsonObject = { state: 'prepared', generation: cell.generation, operation_id: valid.idempotency_key,
        operation_sha256: valid.operation_sha256, event_id: valid.event_id, prepared_events_head: head,
        event_jcs_b64: base64urlEncode(wire(valid)), side_artifacts: entries };
    const candidate = await decodePreparedOperation(wire(obj), { expectedProjectId: project, maxPreparedOperationBytes: limit, preconditions: facts });
    bounded(wire({ ...obj, state: 'appending', append_head: 'f'.repeat(64), append_claim: await appendClaim(...owner(obj), 'f'.repeat(64)) }), limit);
    if (old.state === 'idle')
        return candidate;
    conflict(equal(owner(old), owner(obj)) && old.event_id === obj.event_id, 'another operation occupies the cell');
    if (old.state !== 'terminal')
        conflict(packageFields.every(k => equal(old[k], obj[k])), 'retry changed the frozen event or artifacts');
    return cell;
}
export async function claimAppend(cell: PreparedOperation, options: {
    operationId: string;
    operationSha256: string;
    fence: DecisionFence;
    marker: InFlightMarker;
    preparedReference: PreparedOperationReference;
    appendHead: string;
    maxPreparedOperationBytes: number;
    expectedAppendClaim?: string;
}): Promise<PreparedOperation> {
    const { operationId, operationSha256, fence, marker, preparedReference: ref, appendHead, maxPreparedOperationBytes: limit, expectedAppendClaim } = options;
    const obj = value(cell, 'cell');
    encodePreparedOperation(cell, { maxPreparedOperationBytes: limit });
    mutationBinding(cell, fence, marker, ref);
    conflict(Object.keys(object(value(marker, 'marker').ops)).length > 0, 'append requires the open marker');
    conflict(cell.state === 'prepared' || cell.state === 'appending', 'cell cannot acquire an append right');
    requireOwner(obj, operationId, operationSha256);
    const claim = await appendClaim(operationId, operationSha256, appendHead);
    if (cell.state === 'appending') {
        if (obj.append_head === appendHead)
            return cell;
        conflict(expectedAppendClaim === obj.append_claim, 'append claim changed');
    }
    const result = make('cell', { ...obj, state: 'appending', append_head: appendHead, append_claim: claim });
    encodePreparedOperation(result, { maxPreparedOperationBytes: limit });
    return result;
}
export function terminalOperation(cell: PreparedOperation, options: {
    operationId: string;
    operationSha256: string;
    fence: DecisionFence;
    marker: InFlightMarker;
    preparedReference: PreparedOperationReference;
    result: string;
    observedEventsHead: string;
    canonicalCommit: string | null;
    projectionVerified?: boolean;
    readbackVerified?: boolean;
}): PreparedOperation {
    const c = value(cell, 'cell'), { fence, marker, preparedReference: ref, result, observedEventsHead, canonicalCommit } = options;
    conflict(cell.state !== 'idle', 'idle cell has no terminal owner');
    mutationBinding(cell, fence, marker, ref);
    requireOwner(c, options.operationId, options.operationSha256);
    oid(observedEventsHead);
    require(['landed', 'semantic_noop', 'conflict'].includes(text(result)), 'unknown terminal result');
    if (result === 'landed')
        oid(canonicalCommit);
    else
        require(canonicalCommit === null, 'non-landed result has a canonical commit');
    const out: JsonObject = { state: 'terminal', generation: c.generation!, operation_id: c.operation_id!, operation_sha256: c.operation_sha256!,
        event_id: c.event_id!, result, observed_events_head: observedEventsHead, canonical_commit: canonicalCommit };
    if (cell.state === 'terminal') {
        conflict(equal(c, out), 'terminal outcome is immutable');
        return cell;
    }
    const open = Object.keys(object(value(marker, 'marker').ops)).length > 0;
    if (result === 'landed')
        conflict(!open && options.projectionVerified === true && options.readbackVerified === true, 'landed terminal requires projection, marker close and read-back');
    else
        conflict(open, 'semantic revalidation requires the open marker');
    conflict((result === 'landed') === (cell.state === 'appending'), 'appending must repair forward; prepared may terminate without append');
    return make('cell', out);
}
export async function acquireMutationFence(fence: DecisionFence, cell: PreparedOperation, ref: PreparedOperationReference, options: {
    subjects: readonly number[];
    projectWide: boolean;
}): Promise<DecisionFence> {
    const f = value(fence, 'fence'), c = value(cell, 'cell');
    conflict(cell.state === 'prepared' || cell.state === 'appending', 'mutation needs a prepared operation');
    require(references.has(ref), 'missing prepared reference');
    const obj: JsonObject = { state: 'mutation', generation: fence.generation, operation_id: c.operation_id!, operation_sha256: c.operation_sha256!,
        subjects: clone(options.subjects), project_wide: options.projectWide, prepared_commit_oid: ref.commitOid,
        prepared_blob_sha: ref.blobSha, prepared_generation: ref.cell.generation };
    reference(obj, c, ref);
    const candidate = await decodeDecisionFence(wire(obj));
    if (fence.state === 'mutation' && equal(f, obj))
        return fence;
    conflict(fence.state === 'idle' && cell.state === 'prepared', 'fence is occupied or append already began');
    return candidate;
}
export async function openInflightMarker(marker: InFlightMarker, fence: DecisionFence, options: {
    cell: PreparedOperation;
    preparedReference: PreparedOperationReference;
    startedAt: string;
}): Promise<InFlightMarker> {
    const m = value(marker, 'marker'), f = value(fence, 'fence'), { cell, preparedReference: ref, startedAt } = options;
    mutationBinding(cell, fence, marker, ref);
    conflict(cell.state === 'prepared' || cell.state === 'appending', 'terminal operation cannot reopen its marker');
    const candidate = await decodeInflightMarker(wire({ ops: { [text(f.operation_id)]: {
                operation_sha256: f.operation_sha256, subjects: f.subjects, project_wide: f.project_wide, started_at: startedAt
            } } }));
    return Object.keys(object(m.ops)).length ? marker : candidate;
}
export function closeInflightMarker(marker: InFlightMarker, fence: DecisionFence, options: {
    cell: PreparedOperation;
    preparedReference: PreparedOperationReference;
    projectionVerified?: boolean;
}): InFlightMarker {
    const m = value(marker, 'marker');
    mutationBinding(options.cell, fence, marker, options.preparedReference);
    conflict(options.cell.state !== 'prepared' && (options.cell.state !== 'appending' || options.projectionVerified === true), 'close requires terminal outcome or complete projection');
    return Object.keys(object(m.ops)).length ? make('marker', { ops: {} }) : marker;
}
function released(fence: DecisionFence, expected: DecisionFence): DecisionFence {
    const f = value(fence, 'fence'), e = value(expected, 'fence'), generation = count(expected.generation + 1);
    if (fence.state === 'idle' && fence.generation === generation)
        return fence;
    conflict(equal(f, e), 'fence changed before release');
    return make('fence', { state: 'idle', generation });
}
export function releaseMutationFence(fence: DecisionFence, expectedMutation: DecisionFence, cell: PreparedOperation, marker: InFlightMarker, options: {
    preparedReference: PreparedOperationReference;
    projectionVerified: boolean;
    readbackVerified: boolean;
}): DecisionFence {
    const f = value(expectedMutation, 'fence'), c = value(cell, 'cell'), m = value(marker, 'marker');
    value(fence, 'fence');
    conflict(expectedMutation.state === 'mutation' && cell.state === 'terminal', 'release needs the exact mutation and terminal cell');
    reference(f, c, options.preparedReference);
    conflict(!Object.keys(object(m.ops)).length && options.readbackVerified === true && typeof options.projectionVerified === 'boolean', 'release needs marker close and verified read-back');
    if (c.result === 'landed')
        conflict(options.projectionVerified, 'landed operation needs complete verified projection');
    return released(fence, expectedMutation);
}
export function clearPreparedOperation(cell: PreparedOperation, expectedTerminal: PreparedOperation, options: {
    mutationFence: DecisionFence;
    releasedFence: DecisionFence;
    marker: InFlightMarker;
    preparedReference: PreparedOperationReference;
}): PreparedOperation {
    const c = value(cell, 'cell'), expected = value(expectedTerminal, 'cell'), f = value(options.mutationFence, 'fence');
    value(options.releasedFence, 'fence');
    const m = value(options.marker, 'marker');
    conflict(expectedTerminal.state === 'terminal' && options.mutationFence.state === 'mutation', 'clear requires terminal owner and matching prior mutation');
    reference(f, expected, options.preparedReference);
    conflict(!Object.keys(object(m.ops)).length && options.releasedFence.state === 'idle' && options.releasedFence.generation === options.mutationFence.generation + 1, 'clear needs the exact fence release read-back');
    if (cell.state === 'idle' && cell.generation === expectedTerminal.generation)
        return cell;
    conflict(equal(c, expected), 'terminal cell changed before clear');
    return make('cell', { state: 'idle', generation: cell.generation });
}
export async function reserveSuccess(fence: DecisionFence, marker: InFlightMarker, options: {
    checkIdentity: string;
    projectionCommit: string;
}): Promise<DecisionFence> {
    const f = value(fence, 'fence');
    conflict(!Object.keys(object(value(marker, 'marker').ops)).length, 'success reservation requires an empty marker');
    const candidate = await decodeDecisionFence(wire({ state: 'success_reserved', generation: fence.generation,
        check_identity: options.checkIdentity, projection_commit: options.projectionCommit }));
    if (equal(f, value(candidate, 'fence')))
        return fence;
    conflict(fence.state === 'idle', 'success reservation requires idle fence');
    return candidate;
}
export function releaseSuccess(fence: DecisionFence, expectedReservation: DecisionFence, options: {
    completionVerified: boolean;
}): DecisionFence {
    value(fence, 'fence');
    value(expectedReservation, 'fence');
    conflict(expectedReservation.state === 'success_reserved' && options.completionVerified === true, 'reservation needs exact independently verified completion');
    return released(fence, expectedReservation);
}
