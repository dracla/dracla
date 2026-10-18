/** Closed revision-14 edge event, authorization and preparation-package contract.
 * Pure validation only: callers resolve authenticated evidence; this module never fetches or folds.
 */
import { canonicalJson, freezeJson, parseCanonicalJson, type JsonObject, type JsonValue, type ReadonlyJsonObject } from './canonical.js';
import { base64urlDecode, base64urlEncode, copyBytes } from './encoding.js';
import { segment, sha256 } from './artifacts.js';
import { resolveArtifactIdentity } from './artifacts.js';
import { decodeProjection } from './projections.js';
type ObjectValue = Record<string, unknown>;
const EVENT_FIELDS = {
    "acceptance": [["coverage_tuple", "recipient", "version", "digest"], ["fields", "confirmations", "supersedes"]],
    "revocation": [["coverage_tuple"], ["effect"]],
    "agreement_published": [["agreement_id", "version"], ["recipient", "ref", "content_commit_oid", "digest", "snapshot_content_path", "snapshot_metadata_path", "snapshot_sha256"]],
    "agreement_activated": [["agreement_id", "version"], ["published_event_id", "supersedes_coverage", "accepted_versions"]],
    "agreement_activation_restored": [["agreement_id", "activation_event_id"], ["accepted_versions", "reason"]],
    "project_connected": [[], ["recipient", "repository_owner", "project_slug", "repository_ids", "bootstrap", "project_configuration", "successor_of"]],
    "project_repository_owner_changed": [["prior_repository_owner"], ["new_repository_owner", "project_slug", "repository_ids", "registry_commit_oid", "registry_generation"]],
    "project_succeeded": [["successor_project_id"], ["successor_connected_event_id"]],
    "config_updated": [[], ["project_configuration"]],
    "keyring_activated": [[], ["generation", "keys_commit_oid", "current_kids"]],
    "enforcement_scope_requested": [["change_id"], ["prior_scope", "desired_scope", "prior_registry_generation"]],
    "enforcement_scope_activated": [["change_id"], ["request_event_id", "desired_scope", "registry_commit_oid", "registry_generation"]],
    "enforcement_scope_abandoned": [["change_id"], ["request_event_id", "reason_code"]],
    "override": [["repository_id", "pull_request_number", "tree_oid"], ["subjects", "reason", "instrument_ref"]],
    "override_withdrawn": [["override_event_id"], ["reason", "instrument_ref"]],
    "retry_requested": [["repository_id", "check_kind", "check_identity"], ["github_delivery_id"]],
    "exemption": [["subject"], ["source_kind", "basis", "instrument_ref"]],
    "exemption_snapshot": [["subjects"], ["team", "basis", "instrument_ref"]],
    "exemption_source_withdrawn": [["source_event_id", "subject"], []],
    "exemption_rule_configured": [["team"], ["basis", "instrument_ref"]],
    "exemption_rule_withdrawn": [["rule_event_id"], []],
    "exemption_materialized": [["rule_event_id", "subject"], ["result", "team", "membership_evidence", "prior_materialization_event_id"]],
    "records_reader_authorized": [["subject"], []],
    "records_reader_snapshot_authorized": [["subjects"], ["team"]],
    "records_reader_withdrawn": [["source_event_id", "subject"], []],
    "records_reader_rule_configured": [["team"], []],
    "records_reader_rule_withdrawn": [["rule_event_id"], []],
    "records_reader_materialized": [["rule_event_id", "subject"], ["result", "team", "membership_evidence", "prior_materialization_event_id"]],
} as const;
export type EventType = keyof typeof EVENT_FIELDS;
export const EVENT_TYPES: readonly EventType[] = Object.freeze(Object.keys(EVENT_FIELDS) as EventType[]);
const AUTH_ROWS = [
    ["project_connected", "project_connect_owner", "account", "repository_owner_control"],
    ["project_connected", "project_connect_records_repository", "repository", "project_repository_admin"],
    ["project_connected", "project_connect_coverage_repository", "repository", "project_repository_admin"],
    ["project_connected", "project_connect_control_repository", "repository", "project_repository_admin"],
    ["project_connected", "project_connect_records_app", "installation", "records_app_binding"],
    ["project_connected", "project_connect_enforcer_app", "installation", "enforcer_app_binding"],
    ["project_connected", "project_connect_trigger_app", "installation", "trigger_app_binding"],
    ["project_repository_owner_changed", "project_repository_owner_change_owner", "account", "repository_owner_control"],
    ["project_repository_owner_changed", "project_repository_owner_change_records_repository", "repository", "project_repository_admin"],
    ["project_repository_owner_changed", "project_repository_owner_change_coverage_repository", "repository", "project_repository_admin"],
    ["project_repository_owner_changed", "project_repository_owner_change_control_repository", "repository", "project_repository_admin"],
    ["project_repository_owner_changed", "project_repository_owner_change_records_app", "installation", "records_app_binding"],
    ["project_repository_owner_changed", "project_repository_owner_change_enforcer_app", "installation", "enforcer_app_binding"],
    ["project_repository_owner_changed", "project_repository_owner_change_trigger_app", "installation", "trigger_app_binding"],
    ["project_succeeded", "project_succeed", "repository", "records_repository_admin"],
    ["keyring_activated", "keyring_activate", "repository", "project_repository_admin"],
    ["agreement_published", "agreement_publish", "repository", "records_repository_admin"],
    ["agreement_activated", "agreement_activate", "repository", "records_repository_admin"],
    ["agreement_activation_restored", "agreement_activation_restore", "repository", "records_repository_admin"],
    ["config_updated", "project_config_update", "repository", "records_repository_admin"],
    ["enforcement_scope_requested", "enforcement_scope_repository_bind", "repository", "contributing_repository_admin"],
    ["enforcement_scope_requested", "enforcement_scope_repository_widen", "repository", "contributing_repository_admin"],
    ["enforcement_scope_requested", "enforcement_scope_repository_narrow", "repository", "contributing_repository_admin"],
    ["enforcement_scope_requested", "enforcement_scope_repository_remove", "repository", "contributing_repository_admin"],
    ["enforcement_scope_requested", "enforcement_scope_organization_bind", "organization", "organization_owner"],
    ["enforcement_scope_requested", "enforcement_scope_organization_widen", "organization", "organization_owner"],
    ["enforcement_scope_requested", "enforcement_scope_organization_narrow", "organization", "organization_owner"],
    ["enforcement_scope_requested", "enforcement_scope_organization_remove", "organization", "organization_owner"],
    ["enforcement_scope_activated", "enforcement_scope_repository_bind", "repository", "contributing_repository_admin"],
    ["enforcement_scope_activated", "enforcement_scope_repository_widen", "repository", "contributing_repository_admin"],
    ["enforcement_scope_activated", "enforcement_scope_repository_narrow", "repository", "contributing_repository_admin"],
    ["enforcement_scope_activated", "enforcement_scope_repository_remove", "repository", "contributing_repository_admin"],
    ["enforcement_scope_activated", "enforcement_scope_organization_bind", "organization", "organization_owner"],
    ["enforcement_scope_activated", "enforcement_scope_organization_widen", "organization", "organization_owner"],
    ["enforcement_scope_activated", "enforcement_scope_organization_narrow", "organization", "organization_owner"],
    ["enforcement_scope_activated", "enforcement_scope_organization_remove", "organization", "organization_owner"],
    ["enforcement_scope_abandoned", "enforcement_scope_repository_bind", "repository", "contributing_repository_admin"],
    ["enforcement_scope_abandoned", "enforcement_scope_repository_widen", "repository", "contributing_repository_admin"],
    ["enforcement_scope_abandoned", "enforcement_scope_repository_narrow", "repository", "contributing_repository_admin"],
    ["enforcement_scope_abandoned", "enforcement_scope_repository_remove", "repository", "contributing_repository_admin"],
    ["enforcement_scope_abandoned", "enforcement_scope_organization_bind", "organization", "organization_owner"],
    ["enforcement_scope_abandoned", "enforcement_scope_organization_widen", "organization", "organization_owner"],
    ["enforcement_scope_abandoned", "enforcement_scope_organization_narrow", "organization", "organization_owner"],
    ["enforcement_scope_abandoned", "enforcement_scope_organization_remove", "organization", "organization_owner"],
    ["exemption", "exemption_bot_add", "repository", "records_repository_admin"],
    ["exemption", "exemption_individual_add", "repository", "records_repository_admin"],
    ["exemption_snapshot", "exemption_snapshot_add", "repository", "records_repository_admin"],
    ["exemption_source_withdrawn", "exemption_source_withdraw", "repository", "records_repository_admin"],
    ["exemption_rule_configured", "exemption_rule_configure", "repository", "records_repository_admin"],
    ["exemption_rule_withdrawn", "exemption_rule_withdraw", "repository", "records_repository_admin"],
    ["records_reader_authorized", "records_reader_individual_add", "repository", "records_repository_admin"],
    ["records_reader_snapshot_authorized", "records_reader_snapshot_add", "repository", "records_repository_admin"],
    ["records_reader_withdrawn", "records_reader_source_withdraw", "repository", "records_repository_admin"],
    ["records_reader_rule_configured", "records_reader_rule_configure", "repository", "records_repository_admin"],
    ["records_reader_rule_withdrawn", "records_reader_rule_withdraw", "repository", "records_repository_admin"],
    ["override", "override_grant", "repository", "contributing_repository_maintain"],
    ["override_withdrawn", "override_withdraw", "repository", "contributing_repository_maintain"],
    ["retry_requested", "retry_request", "repository", "contributing_repository_write"],
] as const;
export const AUTHORIZATION_TABLE = Object.freeze(AUTH_ROWS.map(row => Object.freeze([...row])));
export class EventValidationError extends Error {
    constructor(message: string) { super(message); this.name = new.target.name; }
}
export class EventIdentityError extends EventValidationError {
}
export class AuthorizationError extends EventIdentityError {
}
export class AuthorizationValidationError extends AuthorizationError {
}
export class PreconditionValidationError extends EventValidationError {
}
export class SideArtifactValidationError extends EventValidationError {
}
function require(condition: unknown, message: string): asserts condition {
    if (!condition)
        throw new EventValidationError(message);
}
function object(value: unknown, keys?: readonly string[]): ObjectValue {
    require(value !== null && typeof value === 'object' && !Array.isArray(value), 'expected object');
    const result = value as ObjectValue;
    if (keys)
        require(Object.keys(result).length === keys.length && keys.every(key => Object.hasOwn(result, key)), 'missing or extra object fields');
    return result;
}
function array(value: unknown): unknown[] { require(Array.isArray(value), 'expected array'); return value; }
function string(value: unknown): string { require(typeof value === 'string' && value.length > 0, 'expected nonempty string'); return value; }
function integer(value: unknown, zero = false): number {
    require(typeof value === 'number' && Number.isSafeInteger(value) && value >= (zero ? 0 : 1), 'expected safe integer');
    return value;
}
function oid(value: unknown): string { const text = string(value); require(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(text), 'invalid Git object ID'); return text; }
function digest(value: unknown): string { const text = string(value); require(/^sha256:[a-f0-9]{64}$/.test(text), 'invalid SHA-256 digest'); return text; }
function encoded(value: unknown, length: number): string { const text = string(value); base64urlDecode(text, length); return text; }
function eventId(value: unknown): string { return encoded(value, 32); }
function nullableString(value: unknown): void { if (value !== null)
    string(value); }
function timestamp(value: unknown): string {
    const text = string(value);
    require(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(text), 'invalid UTC whole-second timestamp');
    const date = new Date(text);
    require(Number.isFinite(date.getTime()) && date.toISOString().slice(0, 19) + 'Z' === text && !text.startsWith('0000'), 'invalid UTC date');
    return text;
}
function equal(a: unknown, b: unknown): boolean { return compare(canonicalJson(a), canonicalJson(b)) === 0; }
function compare(a: Uint8Array, b: Uint8Array): number {
    for (let i = 0; i < Math.min(a.length, b.length); i++)
        if (a[i] !== b[i])
            return a[i]! - b[i]!;
    return a.length - b.length;
}
function ordered(values: readonly unknown[]): void {
    const bytes = values.map(canonicalJson);
    require(bytes.every((value, i) => i === 0 || compare(bytes[i - 1]!, value) <= 0), 'set is not in JCS lexical order');
}
function unique(values: readonly unknown[]): void { require(new Set(values).size === values.length, 'duplicate identity'); }
function stringSet(value: unknown, allowEmpty = false): string[] {
    const values = array(value).map(string);
    require(allowEmpty || values.length > 0, 'empty string set');
    unique(values);
    ordered(values);
    return values;
}
function freeze<T>(value: T): T {
    // All callers supply owned JSON snapshots or JSON records constructed here.
    return freezeJson(value as JsonValue) as T;
}
function snapshot(value: unknown): ObjectValue { return object(parseCanonicalJson(canonicalJson(value))); }
function hex(bytes: Uint8Array): string { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }
function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
    const result = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }
    return result;
}
async function domainHash(domain: string, value: unknown): Promise<Uint8Array<ArrayBuffer>> {
    // Own the complete preimage before the first asynchronous operation.
    return sha256(concat(new TextEncoder().encode(domain + '\0'), canonicalJson(value)));
}
const automationTypes: readonly string[] = ['exemption_materialized', 'records_reader_materialized'];
const noAuthTypes: readonly string[] = ['acceptance', 'revocation', ...automationTypes];
const scopeTypes: readonly string[] = ['enforcement_scope_requested', 'enforcement_scope_activated', 'enforcement_scope_abandoned'];
function eventType(value: unknown): EventType {
    require(typeof value === 'string' && Object.hasOwn(EVENT_FIELDS, value), 'unknown event type');
    return value as EventType;
}
function actorIdentity(actor: unknown): JsonObject {
    const value = object(actor);
    if (value.kind === 'github') {
        object(value, ['kind', 'github_user_id', 'login_snapshot']);
        string(value.login_snapshot);
        return { kind: 'github', github_user_id: integer(value.github_user_id) };
    }
    object(value, ['kind', 'principal']);
    require(value.kind === 'automation' && value.principal === 'worker-portal', 'unsupported actor');
    return { kind: 'automation', principal: 'worker-portal' };
}
export function stableActorIdentity(value: unknown): ReadonlyJsonObject {
    try {
        return freeze(actorIdentity(snapshot(value)));
    }
    catch {
        throw new EventIdentityError('invalid actor identity');
    }
}
export interface EventIdentity {
    readonly operation_nonce: string;
    readonly idempotency_key: string;
    readonly operation_sha256: string;
    readonly event_id: string;
    readonly path: string;
}
export function eventPath(value: string): string {
    try {
        eventId(value);
        return `events/${value.slice(0, 2)}/${value.slice(2, 4)}/${value}.enc.json`;
    }
    catch {
        throw new EventIdentityError('invalid event ID');
    }
}
export function newOperationNonce(): string {
    try {
        const bytes = copyBytes(crypto.getRandomValues(new Uint8Array(16)));
        require(bytes.length === 16, 'invalid platform nonce');
        return base64urlEncode(bytes);
    }
    catch {
        throw new EventIdentityError('platform CSPRNG returned an invalid nonce');
    }
}
export async function deriveEventIdentity(input: {
    project_id: string;
    operation_nonce: string;
    actor: unknown;
    type: string;
    target: unknown;
    payload: unknown;
    confirmed_canonical_oid: string | null;
}): Promise<EventIdentity> {
    try {
        const value = snapshot(input);
        object(value, ['project_id', 'operation_nonce', 'actor', 'type', 'target', 'payload', 'confirmed_canonical_oid']);
        const project = string(value.project_id), nonce = encoded(value.operation_nonce, 16), actor = actorIdentity(value.actor), type = eventType(value.type);
        const target = object(value.target), payload = object(value.payload), confirmed = value.confirmed_canonical_oid;
        if (confirmed !== null)
            oid(confirmed);
        const idempotency = await domainHash('dracla-idempotency-v1', { project_id: project, operation_nonce: nonce });
        const operation = await domainHash('dracla-operation-v1', { project_id: project, actor_identity: actor, type, target, payload, confirmed_canonical_oid: confirmed });
        const id = base64urlEncode(await sha256(concat(new TextEncoder().encode('dracla-event-v1\0'), idempotency)));
        return Object.freeze({ operation_nonce: nonce, idempotency_key: base64urlEncode(idempotency), operation_sha256: 'sha256:' + hex(operation), event_id: id, path: eventPath(id) });
    }
    catch {
        throw new EventIdentityError('invalid event identity input');
    }
}
export async function deriveAutomationNonce(ruleEventId: string, subjectUserId: number, result: string, priorMaterializationEventId: string | null): Promise<string> {
    try {
        string(ruleEventId);
        integer(subjectUserId);
        require(result === 'add' || result === 'withdraw', 'unsupported transition');
        nullableString(priorMaterializationEventId);
        return base64urlEncode((await domainHash('dracla-automation-transition-v1', { rule_event_id: ruleEventId, subject_user_id: subjectUserId, result, prior_materialization_event_id: priorMaterializationEventId })).slice(0, 16));
    }
    catch {
        throw new EventIdentityError('invalid automation nonce input');
    }
}
export async function deriveGithubRetryNonce(repositoryId: number, checkKind: string, checkIdentity: number | string, githubDeliveryId: string | null): Promise<string> {
    try {
        integer(repositoryId);
        require(checkKind === 'pull_request' || checkKind === 'merge_group', 'unsupported check kind');
        if (checkKind === 'pull_request')
            integer(checkIdentity);
        else
            oid(checkIdentity);
        nullableString(githubDeliveryId);
        return base64urlEncode((await domainHash('dracla-github-retry-v1', { repository_id: repositoryId, check_kind: checkKind, check_identity: checkIdentity, github_delivery_id: githubDeliveryId })).slice(0, 16));
    }
    catch {
        throw new EventIdentityError('invalid retry nonce input');
    }
}
export async function deriveScopeTerminalNonce(requestEventId: string, terminalType: string): Promise<string> {
    try {
        string(requestEventId);
        require(terminalType === 'enforcement_scope_activated' || terminalType === 'enforcement_scope_abandoned', 'unsupported scope terminal');
        const children = await Promise.all(['enforcement_scope_activated', 'enforcement_scope_abandoned'].map(type => domainHash('dracla-scope-terminal-v1', { request_event_id: requestEventId, terminal_type: type })));
        require(compare(children[0]!.slice(0, 16), children[1]!.slice(0, 16)) !== 0, 'scope terminal nonce collision');
        return base64urlEncode(children[terminalType === 'enforcement_scope_activated' ? 0 : 1]!.slice(0, 16));
    }
    catch {
        throw new EventIdentityError('invalid scope terminal nonce input');
    }
}
function coverage(value: unknown): ObjectValue {
    const row = object(value, ['github_user_id', 'project_id', 'agreement_id', 'recipient_id']);
    integer(row.github_user_id);
    for (const key of ['project_id', 'agreement_id', 'recipient_id'])
        string(row[key]);
    return row;
}
function recipient(value: unknown): ObjectValue { const row = object(value, ['recipient_id', 'legal_name']); string(row.recipient_id); string(row.legal_name); return row; }
function owner(value: unknown): ObjectValue { const row = object(value, ['github_account_id', 'login_snapshot']); integer(row.github_account_id); string(row.login_snapshot); return row; }
function subject(value: unknown): ObjectValue { const row = object(value, ['github_user_id', 'login_snapshot']); integer(row.github_user_id); string(row.login_snapshot); return row; }
function team(value: unknown): ObjectValue { const row = object(value, ['organization_id', 'team_id', 'slug_snapshot']); integer(row.organization_id); integer(row.team_id); string(row.slug_snapshot); return row; }
function membership(value: unknown): ObjectValue {
    const row = object(value, ['organization_id', 'team_id', 'github_user_id', 'state', 'checked_at', 'etag', 'github_request_id']);
    for (const key of ['organization_id', 'team_id', 'github_user_id'])
        integer(row[key]);
    require(row.state === 'member' || row.state === 'not_member', 'unsupported membership state');
    timestamp(row.checked_at);
    nullableString(row.etag);
    nullableString(row.github_request_id);
    return row;
}
function repositoryIds(value: unknown): ObjectValue {
    const row = object(value, ['records', 'coverage', 'control']);
    unique(Object.values(row).map(value => integer(value)));
    return row;
}
function kids(value: unknown): void { const row = object(value, ['records', 'coverage']); string(row.records); string(row.coverage); }
function bootstrap(value: unknown): ObjectValue {
    const row = object(value, ['install_generation', 'manifest_commit_oid', 'manifest_sha256', 'records_keyring_candidate_oid', 'repository_ids', 'current_kids']);
    string(row.install_generation);
    oid(row.manifest_commit_oid);
    digest(row.manifest_sha256);
    oid(row.records_keyring_candidate_oid);
    repositoryIds(row.repository_ids);
    kids(row.current_kids);
    return row;
}
function privacyPolicyUrl(value: unknown): void {
    const url = string(value), authority = /^https:\/\/([^/?#]+)/i.exec(url)?.[1];
    // Match Python M1-5 without WHATWG DNS/IPv4 normalization. Python's
    // Unicode whitespace includes U+0085 and excludes U+FEFF.
    require(authority && !authority.endsWith(':') && !/[\x00-\x20\x7f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\\]/u.test(url)
        && !/%(?![0-9a-fA-F]{2})/.test(url), 'invalid privacy policy URL');
    const unreservedAuthority = authority.replace(/[@:#?]/g, '');
    require(!/[/?#@:]/.test(unreservedAuthority.normalize('NFKC')), 'invalid privacy policy URL');
    const at = authority.lastIndexOf('@');
    require(at < 0 || authority.slice(0, at) === '' || authority.slice(0, at) === ':', 'invalid privacy policy URL');
    const hostPort = authority.slice(at + 1);
    let host: string, port: string | undefined;
    if (hostPort.includes('[') || hostPort.includes(']')) {
        const bracketed = /^\[([^\[\]]+)\](?::(.*))?$/.exec(hostPort);
        require(bracketed, 'invalid privacy policy URL');
        host = bracketed[1]!;
        port = bracketed[2];
        if (host.startsWith('v')) {
            require(/^v[0-9a-fA-F]+\..+$/u.test(host), 'invalid privacy policy URL');
        } else {
            // Native parsing is used only for the IPv6 literal, never a DNS
            // name or stored URL. Python also permits one nonempty zone ID.
            const scoped = host.split('%');
            require(scoped.length === 1 || (scoped.length === 2 && scoped[1] !== ''), 'invalid privacy policy URL');
            const address = scoped[0]!;
            require(address.includes(':'), 'invalid privacy policy URL');
            new URL('https://[' + address + ']/');
        }
    } else {
        const colon = hostPort.indexOf(':');
        host = colon < 0 ? hostPort : hostPort.slice(0, colon);
        port = colon < 0 ? undefined : hostPort.slice(colon + 1);
    }
    require(host.length > 0 && (port === undefined || (/^[0-9]+$/.test(port) && Number(port) <= 65535)), 'invalid privacy policy URL');
}
function configuration(value: unknown): ObjectValue {
    const row = object(value, ['privacy_policy_url', 'retention_statement', 'correction_procedure', 'required_fields', 'confirmation_labels']);
    privacyPolicyUrl(row.privacy_policy_url);
    string(row.retention_statement);
    string(row.correction_procedure);
    const fields = array(row.required_fields).map(value => {
        const field = object(value, ['name', 'label', 'kind', 'required']);
        require(/^[A-Za-z_][A-Za-z0-9_]*$/.test(string(field.name)), 'invalid field identifier');
        string(field.label);
        require((field.kind === 'text' || field.kind === 'email') && field.required === true, 'invalid required field');
        return field;
    });
    unique(fields.map(field => field.name));
    unique(array(row.confirmation_labels).map(string));
    return row;
}
function subjects(value: unknown): ObjectValue[] {
    const values = array(value).map(subject);
    require(values.length > 0, 'empty subject set');
    unique(values.map(row => row.github_user_id));
    ordered(values);
    return values;
}
function scope(value: unknown): ObjectValue[] {
    const values = array(value).map(value => {
        const row = object(value);
        if (row.kind === 'repository') {
            object(row, ['kind', 'repository_id', 'owner_snapshot', 'name_snapshot']);
            integer(row.repository_id);
            string(row.owner_snapshot);
            string(row.name_snapshot);
        }
        else {
            object(row, ['kind', 'organization_id', 'login_snapshot']);
            require(row.kind === 'organization', 'unsupported scope kind');
            integer(row.organization_id);
            string(row.login_snapshot);
        }
        return row;
    });
    unique(values.map(row => `${row.kind}:${row.repository_id ?? row.organization_id}`));
    ordered(values);
    return values;
}
function scopeIdentity(row: ObjectValue): string { return `${row.kind}:${row.repository_id ?? row.organization_id}`; }
function authorizationRow(value: unknown): ObjectValue {
    const row = object(value, ['operation', 'resource_kind', 'resource_id', 'required_authority', 'observed_authority', 'authorized', 'checked_at', 'github_request_id']);
    require(AUTH_ROWS.some(item => item[1] === row.operation && item[2] === row.resource_kind && item[3] === row.required_authority), 'authorization operation/authority mismatch');
    integer(row.resource_id);
    string(row.observed_authority);
    require(row.authorized === true, 'authorization denied');
    timestamp(row.checked_at);
    nullableString(row.github_request_id);
    return row;
}
function authorizationRows(value: unknown, type: EventType): ObjectValue[] {
    const rows = array(value).map(authorizationRow);
    unique(rows.map(row => `${row.operation}:${row.resource_kind}:${row.resource_id}`));
    ordered(rows);
    if (noAuthTypes.includes(type))
        require(rows.length === 0, 'unexpected authorizations');
    else
        require(rows.length > 0, 'authorization required');
    return rows;
}
function authorizations(type: EventType, target: ObjectValue, payload: ObjectValue, actor: unknown, rows: ObjectValue[], affected?: readonly number[]): void {
    require(actorIdentity(actor).kind === (automationTypes.includes(type) ? 'automation' : 'github'), 'wrong actor kind');
    require(type === 'keyring_activated' || affected === undefined, 'unexpected affected repositories');
    if (noAuthTypes.includes(type)) {
        require(rows.length === 0, 'unexpected authorizations');
        return;
    }
    const candidates = AUTH_ROWS.filter(row => row[0] === type);
    require(rows.every(row => candidates.some(candidate => candidate[1] === row.operation && candidate[2] === row.resource_kind && candidate[3] === row.required_authority)), 'wrong authorization for event');
    if (type === 'project_connected' || type === 'project_repository_owner_changed') {
        require(rows.length === 7 && new Set(rows.map(row => row.operation)).size === 7, 'incomplete connection authorization');
        const prefix = type === 'project_connected' ? 'project_connect_' : 'project_repository_owner_change_';
        const byOperation = new Map(rows.map(row => [row.operation, row]));
        require(byOperation.get(prefix + 'owner')!.resource_id === object(payload[type === 'project_connected' ? 'repository_owner' : 'new_repository_owner']).github_account_id, 'wrong owner resource');
        const ids = object(payload.repository_ids);
        for (const role of ['records', 'coverage', 'control'])
            require(byOperation.get(prefix + role + '_repository')!.resource_id === integer(ids[role]), 'wrong repository resource');
        unique(['records', 'enforcer', 'trigger'].map(role => byOperation.get(prefix + role + '_app')!.resource_id));
        return;
    }
    if (type === 'keyring_activated') {
        require(affected !== undefined && affected.length > 0, 'affected repositories required');
        affected.forEach(value => integer(value));
        unique(affected);
        require(rows.length === affected.length && rows.every(row => affected.includes(integer(row.resource_id))), 'wrong affected repository set');
        return;
    }
    require(rows.length === 1, 'one authorization required');
    const row = rows[0]!;
    if (scopeTypes.includes(type)) {
        const operation = string(row.operation), action = operation.slice(operation.lastIndexOf('_') + 1), identity = `${row.resource_kind}:${row.resource_id}`;
        if (type === 'enforcement_scope_requested') {
            const before = new Set(scope(payload.prior_scope).map(scopeIdentity)), after = new Set(scope(payload.desired_scope).map(scopeIdentity));
            const added = [...after].filter(value => !before.has(value)), removed = [...before].filter(value => !after.has(value));
            const expected = before.size === 0 && added.length === 1 ? 'bind' : added.length === 1 && removed.length === 0 ? 'widen' : after.size === 0 && removed.length === 1 ? 'remove' : removed.length === 1 && added.length === 0 ? 'narrow' : null;
            require(action === expected && (added.length ? added[0] : removed[0]) === identity, 'scope authorization transition mismatch');
        }
        else if (type === 'enforcement_scope_activated')
            require(scope(payload.desired_scope).some(value => scopeIdentity(value) === identity) === ['bind', 'widen'].includes(action), 'scope authorization membership mismatch');
    }
    else if (type === 'exemption')
        require(row.operation === (payload.source_kind === 'bot' ? 'exemption_bot_add' : payload.source_kind === 'individual' ? 'exemption_individual_add' : null), 'wrong exemption authorization');
    else if (type === 'override' || type === 'retry_requested')
        require(row.resource_id === integer(target.repository_id), 'wrong target resource');
}
export function validateAuthorizations(type: string, target: unknown, payload: unknown, actor: unknown, values: unknown, affectedRepositoryIds?: readonly number[]): readonly ReadonlyJsonObject[] {
    try {
        const input = snapshot({ type, target, payload, actor, values, affected: affectedRepositoryIds ?? null });
        const selected = eventType(input.type);
        const rows = authorizationRows(input.values, selected);
        authorizations(selected, object(input.target), object(input.payload), input.actor, rows, input.affected === null ? undefined : array(input.affected).map(value => integer(value)));
        return freeze(rows) as readonly ReadonlyJsonObject[];
    }
    catch {
        throw new AuthorizationValidationError('invalid authorization evidence');
    }
}
async function targetPayload(type: EventType, t: ObjectValue, p: ObjectValue): Promise<void> {
    object(t, EVENT_FIELDS[type][0]);
    object(p, EVENT_FIELDS[type][1]);
    switch (type) {
        case 'acceptance': {
            coverage(t.coverage_tuple);
            recipient(t.recipient);
            string(t.version);
            digest(t.digest);
            const fields = object(p.fields);
            for (const [key, value] of Object.entries(fields)) {
                string(key);
                require(typeof value === 'string', 'acceptance field must be string');
            }
            const confirmations = array(p.confirmations).map(value => { const row = object(value, ['label', 'checked']); string(row.label); require(row.checked === true, 'confirmation not affirmative'); return row; });
            unique(confirmations.map(row => row.label));
            if (p.supersedes !== null)
                eventId(p.supersedes);
            break;
        }
        case 'revocation':
            coverage(t.coverage_tuple);
            require(p.effect === 'cutoff_all_prior_versions', 'unknown revocation effect');
            break;
        case 'agreement_published': {
            const agreement = string(t.agreement_id), version = string(t.version);
            recipient(p.recipient);
            string(p.ref);
            oid(p.content_commit_oid);
            digest(p.digest);
            digest(p.snapshot_sha256);
            const path = `agreements/${await segment(agreement)}/${await segment(version)}`;
            require(p.snapshot_content_path === path + '.md' && p.snapshot_metadata_path === path + '.meta.json', 'snapshot path mismatch');
            break;
        }
        case 'agreement_activated':
            string(t.agreement_id);
            string(t.version);
            eventId(p.published_event_id);
            require(typeof p.supersedes_coverage === 'boolean', 'invalid supersedes flag');
            stringSet(p.accepted_versions);
            break;
        case 'agreement_activation_restored':
            string(t.agreement_id);
            eventId(t.activation_event_id);
            stringSet(p.accepted_versions);
            string(p.reason);
            break;
        case 'project_connected':
            recipient(p.recipient);
            owner(p.repository_owner);
            require(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(string(p.project_slug)), 'invalid project slug');
            repositoryIds(p.repository_ids);
            bootstrap(p.bootstrap);
            configuration(p.project_configuration);
            nullableString(p.successor_of);
            break;
        case 'project_repository_owner_changed':
            owner(t.prior_repository_owner);
            owner(p.new_repository_owner);
            require(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(string(p.project_slug)), 'invalid project slug');
            repositoryIds(p.repository_ids);
            oid(p.registry_commit_oid);
            integer(p.registry_generation, true);
            break;
        case 'project_succeeded':
            string(t.successor_project_id);
            eventId(p.successor_connected_event_id);
            break;
        case 'config_updated':
            configuration(p.project_configuration);
            break;
        case 'keyring_activated':
            integer(p.generation);
            oid(p.keys_commit_oid);
            kids(p.current_kids);
            break;
        case 'enforcement_scope_requested':
            string(t.change_id);
            scope(p.prior_scope);
            scope(p.desired_scope);
            integer(p.prior_registry_generation, true);
            break;
        case 'enforcement_scope_activated':
            string(t.change_id);
            eventId(p.request_event_id);
            scope(p.desired_scope);
            oid(p.registry_commit_oid);
            integer(p.registry_generation, true);
            break;
        case 'enforcement_scope_abandoned':
            string(t.change_id);
            eventId(p.request_event_id);
            string(p.reason_code);
            break;
        case 'override':
            integer(t.repository_id);
            integer(t.pull_request_number);
            oid(t.tree_oid);
            subjects(p.subjects);
            string(p.reason);
            nullableString(p.instrument_ref);
            break;
        case 'override_withdrawn':
            eventId(t.override_event_id);
            string(p.reason);
            nullableString(p.instrument_ref);
            break;
        case 'retry_requested':
            integer(t.repository_id);
            require(t.check_kind === 'pull_request' || t.check_kind === 'merge_group', 'unsupported check kind');
            if (t.check_kind === 'pull_request')
                integer(t.check_identity);
            else
                oid(t.check_identity);
            nullableString(p.github_delivery_id);
            break;
        case 'exemption':
            subject(t.subject);
            require(p.source_kind === 'bot' || p.source_kind === 'individual', 'unsupported exemption source');
            if (p.source_kind === 'bot') {
                nullableString(p.basis);
                nullableString(p.instrument_ref);
            }
            else {
                string(p.basis);
                string(p.instrument_ref);
            }
            break;
        case 'exemption_snapshot':
            subjects(t.subjects);
            team(p.team);
            string(p.basis);
            string(p.instrument_ref);
            break;
        case 'exemption_source_withdrawn':
        case 'records_reader_withdrawn':
            eventId(t.source_event_id);
            subject(t.subject);
            break;
        case 'exemption_rule_configured':
            team(t.team);
            string(p.basis);
            string(p.instrument_ref);
            break;
        case 'exemption_rule_withdrawn':
        case 'records_reader_rule_withdrawn':
            eventId(t.rule_event_id);
            break;
        case 'exemption_materialized':
        case 'records_reader_materialized': {
            eventId(t.rule_event_id);
            const s = subject(t.subject), group = team(p.team), observation = membership(p.membership_evidence);
            require(p.result === 'add' || p.result === 'withdraw', 'unknown materialization result');
            require(observation.organization_id === group.organization_id && observation.team_id === group.team_id && observation.github_user_id === s.github_user_id, 'membership target mismatch');
            require((p.result === 'add') === (observation.state === 'member'), 'membership result mismatch');
            if (p.prior_materialization_event_id !== null)
                eventId(p.prior_materialization_event_id);
            break;
        }
        case 'records_reader_authorized':
            subject(t.subject);
            break;
        case 'records_reader_snapshot_authorized':
            subjects(t.subjects);
            team(p.team);
            break;
        case 'records_reader_rule_configured':
            team(t.team);
            break;
    }
}
export interface ValidatedEvent {
    readonly schema_version: 1;
    readonly project_id: string;
    readonly event_id: string;
    readonly idempotency_key: string;
    readonly operation_nonce: string;
    readonly operation_sha256: string;
    readonly type: EventType;
    readonly recorded_at: string;
    readonly dracla_version: string;
    readonly actor: ReadonlyJsonObject;
    readonly authorizations: readonly ReadonlyJsonObject[];
    readonly confirmed_canonical_oid: string | null;
    readonly target: ReadonlyJsonObject;
    readonly payload: ReadonlyJsonObject;
}
export async function validateEvent(value: unknown, options: {
    expectedProjectId?: string;
    expectedPath?: string;
} = {}): Promise<ValidatedEvent> {
    try {
        const e = snapshot(value), expectedProject = options.expectedProjectId, expectedPath = options.expectedPath;
        object(e, ['schema_version', 'project_id', 'event_id', 'idempotency_key', 'operation_nonce', 'operation_sha256', 'type', 'recorded_at', 'dracla_version', 'actor', 'authorizations', 'confirmed_canonical_oid', 'target', 'payload']);
        require(e.schema_version === 1, 'unsupported event schema');
        const project = string(e.project_id), type = eventType(e.type);
        eventId(e.event_id);
        encoded(e.idempotency_key, 32);
        const nonce = encoded(e.operation_nonce, 16);
        digest(e.operation_sha256);
        timestamp(e.recorded_at);
        string(e.dracla_version);
        const actor = object(e.actor), rows = authorizationRows(e.authorizations, type), t = object(e.target), p = object(e.payload);
        require(actorIdentity(actor).kind === (automationTypes.includes(type) ? 'automation' : 'github'), 'wrong actor kind');
        if (type === 'acceptance' || type === 'revocation')
            oid(e.confirmed_canonical_oid);
        else
            require(e.confirmed_canonical_oid === null, 'unexpected confirmed head');
        await targetPayload(type, t, p);
        if (type === 'keyring_activated')
            require(rows.every(row => row.operation === 'keyring_activate' && row.resource_kind === 'repository' && row.required_authority === 'project_repository_admin'), 'invalid keyring authorization');
        else
            authorizations(type, t, p, actor, rows);
        const identity = await deriveEventIdentity({ project_id: project, operation_nonce: nonce, actor, type, target: t, payload: p, confirmed_canonical_oid: e.confirmed_canonical_oid as string | null });
        require(identity.event_id === e.event_id && identity.idempotency_key === e.idempotency_key && identity.operation_sha256 === e.operation_sha256, 'recomputed identity mismatch');
        if (automationTypes.includes(type))
            require(nonce === await deriveAutomationNonce(string(t.rule_event_id), integer(object(p.membership_evidence).github_user_id), string(p.result), p.prior_materialization_event_id as string | null), 'materialization nonce mismatch');
        else if (type === 'enforcement_scope_activated' || type === 'enforcement_scope_abandoned')
            require(nonce === await deriveScopeTerminalNonce(string(p.request_event_id), type), 'scope terminal nonce mismatch');
        else if (type === 'retry_requested')
            require(nonce === await deriveGithubRetryNonce(integer(t.repository_id), string(t.check_kind), t.check_identity as string | number, p.github_delivery_id as string | null), 'retry nonce mismatch');
        if (expectedProject !== undefined)
            require(project === expectedProject, 'project context mismatch');
        if (expectedPath !== undefined)
            require(identity.path === expectedPath, 'event path mismatch');
        if (type === 'acceptance' || type === 'revocation') {
            const row = coverage(t.coverage_tuple);
            require(row.project_id === project && row.github_user_id === actor.github_user_id, 'coverage project/actor mismatch');
            if (type === 'acceptance')
                require(row.recipient_id === recipient(t.recipient).recipient_id, 'coverage recipient mismatch');
        }
        else if (type === 'project_connected')
            require(equal(bootstrap(p.bootstrap).repository_ids, p.repository_ids), 'bootstrap repository set mismatch');
        else if (type === 'project_repository_owner_changed')
            require(owner(t.prior_repository_owner).github_account_id !== owner(p.new_repository_owner).github_account_id, 'owner must change');
        return freeze(e) as unknown as ValidatedEvent;
    }
    catch {
        throw new EventValidationError('event failed semantic validation');
    }
}
export async function parseEventJcs(data: Uint8Array, options: {
    expectedProjectId?: string;
    expectedPath?: string;
} = {}): Promise<ValidatedEvent> {
    try {
        return await validateEvent(parseCanonicalJson(copyBytes(data)), options);
    }
    catch {
        throw new EventValidationError('event bytes failed canonical or semantic validation');
    }
}
export type PreconditionBinding = {
    readonly mode: 'events-head';
    readonly events_head: string;
} | {
    readonly mode: 'generation';
    readonly events_head: string;
    readonly canonical_generation: string;
    readonly derived_generation: string;
} | {
    readonly mode: 'canonical-sha';
    readonly coverage_commit_oid: string;
    readonly canonical_sha: string;
} | {
    readonly mode: 'cross-project';
    readonly successor_project_id: string;
    readonly successor_events_head: string;
    readonly repository_ids: readonly number[];
} | {
    readonly mode: 'registry-generation';
    readonly registry_commit_oid: string;
    readonly registry_generation: number;
};
export interface PreconditionRequirement {
    readonly name: string;
    readonly artifact_kind: string;
    readonly repository_role: string;
    readonly branch: string;
    readonly path: string;
    readonly binding_mode: PreconditionBinding['mode'];
    readonly relation: string;
    readonly expected_head: string;
}
interface Evidence {
    name: string;
    artifact_kind: string;
    repository_role: string;
    branch: string;
    path: string;
    binding_mode: PreconditionBinding['mode'];
    binding: ObjectValue;
    value: unknown;
}
type RequirementSpec = [
    string,
    string,
    string,
    string,
    PreconditionBinding['mode'],
    string
];
const shardText = (shard: number): string => String(shard).padStart(2, '0');
async function readerPath(sourceId: string): Promise<string> {
    eventId(sourceId);
    return `derived/reader-authority/${shardText((await sha256(new TextEncoder().encode(sourceId)))[0]! >> 3)}.enc.json`;
}
async function nonceEventId(project: string, nonce: string): Promise<string> {
    const idempotency = await domainHash('dracla-idempotency-v1', { project_id: project, operation_nonce: nonce });
    return base64urlEncode(await sha256(concat(new TextEncoder().encode('dracla-event-v1\0'), idempotency)));
}
async function firstAddPath(e: ValidatedEvent): Promise<string> {
    const nonce = await deriveAutomationNonce(string(e.target.source_event_id), integer(object(e.target.subject).github_user_id), 'add', null);
    return eventPath(await nonceEventId(e.project_id, nonce));
}
function subjectShards(e: ValidatedEvent, relation: string): number[] {
    let users: number[];
    if (relation === 'coverage-state')
        users = e.type === 'revocation' ? [integer(object(e.target.coverage_tuple).github_user_id)] : array(e.payload.subjects).map(row => integer(object(row).github_user_id));
    else if (e.type === 'exemption_rule_withdrawn')
        return Array.from({ length: 32 }, (_, i) => i);
    else
        users = e.target.subject !== undefined ? [integer(object(e.target.subject).github_user_id)] : array(e.target.subjects).map(row => integer(object(row).github_user_id));
    return [...new Set(users.map(id => id % 32))].sort((a, b) => a - b);
}
async function requirements(e: ValidatedEvent, head: string): Promise<readonly PreconditionRequirement[]> {
    oid(head);
    require(e.confirmed_canonical_oid === null || e.confirmed_canonical_oid === head, 'confirmed event head mismatch');
    const sourceId = string(e.target.source_event_id ?? e.target.rule_event_id ?? e.event_id);
    const reader = await readerPath(sourceId), registry = `projects/${await segment(e.project_id)}.json`;
    const specs: Record<string, RequirementSpec> = {
        'project-lifecycle': ['coverage-source', 'coverage', 'coverage', 'source.enc.json', 'canonical-sha', 'project-lifecycle-policy'],
        'active-agreement': ['active-agreement', 'coverage', 'coverage', 'agreements/active.enc.json', 'canonical-sha', 'active-agreement-matches-target'],
        'current-configuration': ['project-config', 'records', 'events', 'config/project.enc.json', 'events-head', 'acceptance-fields-and-confirmations-match-configuration'],
        'current-project-agreement': ['canonical-project-state', 'records', 'events', '', 'events-head', 'project-agreement-and-recipient-are-current'],
        'prior-generations': ['materialization-generations', 'records', 'events', 'config/materialization-generations.enc.json', 'events-head', 'prior-generations-at-head'],
        'coverage-state': ['coverage-shard', 'coverage', 'coverage', '', 'canonical-sha', 'coverage-row-matches-target'],
        'superseded-acceptance': ['canonical-event', 'records', 'events', '', 'events-head', 'superseded-acceptance-exists-and-matches-correction'],
        'current-acceptance-basis': ['status-detail', 'records', 'derived', '', 'generation', 'current-acceptance-basis-matches-superseded-acceptance'],
        'published-agreement': ['canonical-event', 'records', 'events', '', 'events-head', 'published-event-exists-and-matches-target'],
        'target-activation': ['canonical-event', 'records', 'events', '', 'events-head', 'target-activation-exists-and-matches-restore'],
        'publication-snapshot-absence': ['agreement-snapshot', 'records', 'events', '', 'events-head', 'agreement-snapshot-is-absent'],
        'publication-metadata-absence': ['agreement-metadata', 'records', 'events', '', 'events-head', 'agreement-metadata-is-absent'],
        'current-repository-owner': ['signed-registry-entry', 'registry', 'main', registry, 'registry-generation', 'repository-owner-and-set-are-current'],
        'keyring-affected-repositories': ['canonical-project-state', 'records', 'events', '', 'events-head', 'affected-repository-ids-equal-authorization-resources'],
        'current-scope': ['signed-registry-entry', 'registry', 'main', registry, 'registry-generation', 'scope-is-current'],
        'scope-request': ['canonical-event', 'records', 'events', '', 'events-head', 'request-exists-and-matches-terminal'],
        'scope-terminal-activation-absence': ['canonical-event', 'records', 'events', '', 'events-head', 'activation-terminal-child-is-absent'],
        'scope-terminal-abandonment-absence': ['canonical-event', 'records', 'events', '', 'events-head', 'abandonment-terminal-child-is-absent'],
        'override-grant': ['canonical-event', 'records', 'events', eventPath(string(e.target.override_event_id ?? e.event_id)), 'events-head', 'override-grant-event-matches-target'],
        'current-exemption-union': ['status-detail', 'records', 'derived', '', 'generation', 'exemption-union-provenance-is-current'],
        'current-derived-state': ['derived-state', 'records', 'derived', 'derived/state.enc.json', 'generation', 'standing-rules-and-installed-profile-are-current'],
        'active-exemption-rule-state': ['derived-state', 'records', 'derived', 'derived/state.enc.json', 'generation', 'referenced-standing-rule-is-current'],
        'source-event': ['canonical-event', 'records', 'events', '', 'events-head', 'source-event-exists-and-matches-target'],
        'source-first-add': ['canonical-event', 'records', 'events', '', 'events-head', 'source-historical-subject-membership'],
        'rule-event': ['canonical-event', 'records', 'events', '', 'events-head', 'rule-event-exists-and-matches-target'],
        'materialization-cursor': ['reader-authority', 'records', 'derived', reader, 'generation', 'prior-materialization-cursor-is-current'],
        'current-reader-authority': ['reader-authority', 'records', 'derived', reader, 'generation', 'reader-source-and-rule-state-is-current'],
        'active-reader-rules': ['reader-authority', 'records', 'derived', '', 'generation', 'active-continuous-reader-rules-are-current'],
        'reader-authority-state': ['reader-authority', 'records', 'derived', reader, 'generation', 'reader-class-currentness-and-source-state'],
        'successor-project': ['canonical-event', 'records', 'events', '', 'cross-project', `successor-connected-reciprocal:${e.target.successor_project_id ?? ''}`],
        'generations-absence': ['materialization-generations', 'records', 'events', 'config/materialization-generations.enc.json', 'events-head', 'artifact-absent-at-head'],
    };
    if (e.type === 'agreement_activated')
        specs['active-agreement']![5] = 'prior-active-agreement-and-prospective-activation-match';
    else if (e.type === 'agreement_activation_restored')
        specs['active-agreement']![5] = 'prior-active-agreement-and-prospective-restore-match';
    const names = [...preconditionMatrix[e.type]!];
    if (e.type === 'acceptance' && e.payload.supersedes !== null)
        names.splice(names.indexOf('current-configuration') + 1, 0, 'superseded-acceptance', 'current-acceptance-basis');
    if (names.includes('source-event'))
        specs['source-first-add']![3] = await firstAddPath(e);
    if (e.type === 'exemption_materialized')
        specs['materialization-cursor'] = ['status-detail', 'records', 'derived', `derived/status-detail/${shardText(integer(object(e.target.subject).github_user_id) % 32)}.enc.json`, 'generation', 'prior-materialization-cursor-is-current'];
    const expanded = names.flatMap(name => name === 'coverage-state' || name === 'current-exemption-union' ? subjectShards(e, name).map(shard => `${name}-${shardText(shard)}`) : name === 'active-reader-rules' ? Array.from({ length: 32 }, (_, shard) => `${name}-${shardText(shard)}`) : [name]);
    const result: PreconditionRequirement[] = [];
    for (const name of expanded) {
        let key = name;
        if (name.startsWith('coverage-state-'))
            key = 'coverage-state';
        else if (name.startsWith('current-exemption-union-'))
            key = 'current-exemption-union';
        else if (name.startsWith('active-reader-rules-'))
            key = 'active-reader-rules';
        const spec: RequirementSpec = [...specs[key]!];
        if (key !== name) {
            const shard = name.slice(-2);
            spec[3] = key === 'coverage-state' ? `users/${shard}.enc.json` : `derived/${key === 'active-reader-rules' ? 'reader-authority' : 'status-detail'}/${shard}.enc.json`;
        }
        else if (name === 'published-agreement')
            spec[3] = eventPath(string(e.payload.published_event_id));
        else if (name === 'target-activation')
            spec[3] = eventPath(string(e.target.activation_event_id));
        else if (name === 'scope-request')
            spec[3] = eventPath(string(e.payload.request_event_id));
        else if (name === 'source-event')
            spec[3] = eventPath(string(e.target.source_event_id));
        else if (name === 'rule-event')
            spec[3] = eventPath(string(e.target.rule_event_id));
        else if (name === 'successor-project')
            spec[3] = eventPath(string(e.payload.successor_connected_event_id));
        else if (name === 'superseded-acceptance')
            spec[3] = eventPath(string(e.payload.supersedes));
        else if (name === 'current-acceptance-basis')
            spec[3] = `derived/status-detail/${shardText(integer(object(e.target.coverage_tuple).github_user_id) % 32)}.enc.json`;
        else if (name === 'publication-snapshot-absence' || name === 'publication-metadata-absence')
            spec[3] = `agreements/${await segment(string(e.target.agreement_id))}/${await segment(string(e.target.version))}${name === 'publication-snapshot-absence' ? '.md' : '.meta.json'}`;
        else if (name === 'scope-terminal-activation-absence' || name === 'scope-terminal-abandonment-absence')
            spec[3] = eventPath(await nonceEventId(e.project_id, await deriveScopeTerminalNonce(string(e.payload.request_event_id), name === 'scope-terminal-activation-absence' ? 'enforcement_scope_activated' : 'enforcement_scope_abandoned')));
        result.push({ name, artifact_kind: spec[0], repository_role: spec[1], branch: spec[2], path: spec[3], binding_mode: spec[4], relation: spec[5], expected_head: head });
    }
    return freeze(result);
}
export async function requiredPreconditions(value: unknown, expectedHead: string): Promise<readonly PreconditionRequirement[]> {
    try {
        return await requirements(await validateEvent(value), expectedHead);
    }
    catch {
        throw new PreconditionValidationError('invalid precondition request');
    }
}
function binding(value: unknown, mode: unknown): ObjectValue {
    const b = object(value);
    require(b.mode === mode, 'binding mode mismatch');
    switch (mode) {
        case 'events-head':
            object(b, ['mode', 'events_head']);
            oid(b.events_head);
            break;
        case 'generation':
            object(b, ['mode', 'events_head', 'canonical_generation', 'derived_generation']);
            oid(b.events_head);
            eventId(b.canonical_generation);
            eventId(b.derived_generation);
            break;
        case 'canonical-sha':
            object(b, ['mode', 'coverage_commit_oid', 'canonical_sha']);
            oid(b.coverage_commit_oid);
            oid(b.canonical_sha);
            break;
        case 'cross-project': {
            object(b, ['mode', 'successor_project_id', 'successor_events_head', 'repository_ids']);
            string(b.successor_project_id);
            oid(b.successor_events_head);
            const ids = array(b.repository_ids).map(value => integer(value));
            require(ids.length > 0, 'empty successor repositories');
            unique(ids);
            break;
        }
        case 'registry-generation':
            object(b, ['mode', 'registry_commit_oid', 'registry_generation']);
            oid(b.registry_commit_oid);
            integer(b.registry_generation, true);
            break;
        default: throw new PreconditionValidationError('unsupported binding mode');
    }
    return b;
}
function evidenceMap(value: unknown): Map<string, Evidence> {
    const entries = Array.isArray(value) ? value : Object.entries(object(value)).map(([name, value]) => {
        const row = object(value);
        require(row.name === undefined || row.name === name, 'evidence name/key mismatch');
        return { ...row, name };
    });
    const result = new Map<string, Evidence>();
    for (const value of entries) {
        const row = object(value, ['name', 'artifact_kind', 'repository_role', 'branch', 'path', 'binding_mode', 'binding', 'value']);
        for (const key of ['name', 'artifact_kind', 'repository_role', 'branch', 'binding_mode'])
            string(row[key]);
        require(typeof row.path === 'string' && (row.path || row.artifact_kind === 'canonical-project-state'), 'invalid evidence path');
        binding(row.binding, row.binding_mode);
        const name = string(row.name);
        require(!result.has(name), 'duplicate precondition');
        result.set(name, row as unknown as Evidence);
    }
    return result;
}
function bound(evidence: Evidence, requirement: PreconditionRequirement): void {
    for (const key of ['artifact_kind', 'repository_role', 'branch', 'path', 'binding_mode'] as const)
        require(evidence[key] === requirement[key], 'wrong evidence artifact descriptor');
    const b = evidence.binding, mode = requirement.binding_mode;
    if (mode === 'events-head' || mode === 'generation')
        require(b.events_head === requirement.expected_head, 'stale evidence head');
    if (mode === 'generation' && requirement.name !== 'reader-authority-state')
        require(b.canonical_generation === b.derived_generation, 'stale derived generation');
    if (mode === 'canonical-sha')
        require(b.canonical_sha === requirement.expected_head, 'stale coverage source');
    if (mode === 'cross-project')
        require(b.successor_project_id === requirement.relation.slice(requirement.relation.indexOf(':') + 1), 'wrong successor project');
}
function eventIds(value: unknown): string[] { const ids = array(value).map(eventId); unique(ids); return ids; }
function factProject(fact: ObjectValue, e: ValidatedEvent): void { require(fact.project_id === e.project_id, 'fact belongs to another project'); }
function absence(value: unknown, path: string): void { const fact = object(value, ['path', 'present']); require(fact.path === path && fact.present === false, 'artifact is present or observation mismatches path'); }
function versionUnion(...sets: string[][]): string[] { return [...new Set(sets.flat())].sort((a, b) => compare(canonicalJson(a), canonicalJson(b))); }
function registryEntry(value: unknown): ObjectValue {
    const input = object(value), entry = object(input.project_entry ?? input);
    require(['project_id', 'project_slug', 'repository_owner', 'repository_ids', 'registry_generation', 'enforcement_scope', 'request_event_links'].every(key => Object.hasOwn(entry, key)), 'incomplete registry entry');
    string(entry.project_id);
    require(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(string(entry.project_slug)), 'invalid registry project slug');
    owner(entry.repository_owner);
    repositoryIds(entry.repository_ids);
    integer(entry.registry_generation, true);
    scope(entry.enforcement_scope);
    for (const id of Object.values(object(entry.request_event_links)))
        eventId(id);
    return entry;
}
async function linkFact(e: ValidatedEvent, name: string, value: unknown): Promise<void> {
    const f = object(value, name === 'scope-request' ? ['event_id', 'type', 'project_id', 'target', 'payload', 'authorizations'] : ['event_id', 'type', 'project_id', 'target', 'payload']);
    eventId(f.event_id);
    factProject(f, e);
    const t = object(f.target), p = object(f.payload);
    if (name === 'active-publication' || name === 'published-agreement') {
        const agreement = name === 'active-publication' ? object(e.target.coverage_tuple).agreement_id : e.target.agreement_id;
        require(f.type === 'agreement_published' && equal(t, { agreement_id: agreement, version: e.target.version }), 'publication target mismatch');
        if (name === 'published-agreement')
            require(f.event_id === e.payload.published_event_id, 'publication identity mismatch');
        object(p, ['recipient', 'ref', 'content_commit_oid', 'digest', 'snapshot_content_path', 'snapshot_metadata_path', 'snapshot_sha256']);
        recipient(p.recipient);
        string(p.ref);
        oid(p.content_commit_oid);
        digest(p.digest);
        digest(p.snapshot_sha256);
        if (name === 'active-publication')
            require(equal(p.recipient, e.target.recipient) && p.digest === e.target.digest, 'publication recipient/digest mismatch');
    }
    else if (name === 'target-activation') {
        require(f.event_id === e.target.activation_event_id && f.type === 'agreement_activated', 'wrong target activation');
        object(t, ['agreement_id', 'version']);
        require(t.agreement_id === e.target.agreement_id, 'wrong activation agreement');
        string(t.version);
        object(p, ['published_event_id', 'supersedes_coverage', 'accepted_versions']);
        eventId(p.published_event_id);
        require(typeof p.supersedes_coverage === 'boolean', 'invalid supersedes flag');
        const versions = stringSet(p.accepted_versions);
        require(versions.includes(string(t.version)) && equal(e.payload.accepted_versions, versions), 'restore accepted versions mismatch');
    }
    else if (name === 'scope-request') {
        require(f.event_id === e.payload.request_event_id && f.type === 'enforcement_scope_requested' && equal(t, { change_id: e.target.change_id }), 'scope request mismatch');
        const rows = authorizationRows(f.authorizations, 'enforcement_scope_requested');
        const identities = (rows: readonly ObjectValue[]): unknown[] => rows.map(row => [row.operation, row.resource_kind, row.resource_id, row.required_authority]);
        require(equal(identities(rows), identities(e.authorizations as readonly ObjectValue[])), 'scope terminal authorization differs from request');
        object(p, ['prior_scope', 'desired_scope', 'prior_registry_generation']);
        scope(p.prior_scope);
        scope(p.desired_scope);
        integer(p.prior_registry_generation, true);
        if (e.payload.desired_scope !== undefined)
            require(equal(p.desired_scope, e.payload.desired_scope), 'scope terminal desired set mismatch');
    }
    else if (name === 'source-event') {
        const allowed = e.type === 'exemption_source_withdrawn' ? ['exemption', 'exemption_snapshot', 'exemption_rule_configured'] : ['records_reader_authorized', 'records_reader_snapshot_authorized', 'records_reader_rule_configured'];
        require(allowed.includes(string(f.type)) && f.event_id === e.target.source_event_id, 'source event mismatch');
        const id = subject(e.target.subject).github_user_id;
        if (f.type === 'exemption' || f.type === 'records_reader_authorized') {
            object(t, ['subject']);
            require(subject(t.subject).github_user_id === id, 'source subject mismatch');
        }
        else if (f.type === 'exemption_snapshot' || f.type === 'records_reader_snapshot_authorized') {
            object(t, ['subjects']);
            require(subjects(t.subjects).some(row => row.github_user_id === id), 'subject outside snapshot');
        }
        else {
            object(t, ['team']);
            team(t.team);
        }
    }
    else if (name === 'rule-event') {
        const expected = e.type === 'exemption_rule_withdrawn' || e.type === 'exemption_materialized' ? 'exemption_rule_configured' : 'records_reader_rule_configured';
        require(f.type === expected && f.event_id === e.target.rule_event_id, 'rule event mismatch');
        object(t, ['team']);
        if (automationTypes.includes(e.type))
            require(equal(team(t.team), team(e.payload.team)), 'materialization rule team mismatch');
    }
    else
        throw new PreconditionValidationError('unknown link relation');
}
async function sourceFirstAdd(e: ValidatedEvent, values: Map<string, Evidence>): Promise<void> {
    const evidence = values.get('source-first-add')!, f = object(evidence.value);
    require(typeof f.present === 'boolean', 'invalid first-add presence');
    object(f, f.present ? ['path', 'present', 'event'] : ['path', 'present']);
    require(f.path === evidence.path, 'first-add path mismatch');
    const origin = object(values.get('source-event')!.value);
    if (origin.type !== 'exemption_rule_configured' && origin.type !== 'records_reader_rule_configured') {
        require(f.present === false, 'unexpected first add for direct/snapshot source');
        return;
    }
    require(f.present, 'missing historical first add');
    const first = await validateEvent(f.event, { expectedProjectId: e.project_id, expectedPath: evidence.path });
    require(first.type === (e.type === 'exemption_source_withdrawn' ? 'exemption_materialized' : 'records_reader_materialized') && first.target.rule_event_id === e.target.source_event_id && object(first.target.subject).github_user_id === object(e.target.subject).github_user_id && first.payload.result === 'add' && first.payload.prior_materialization_event_id === null && equal(team(first.payload.team), team(object(origin.target).team)), 'historical first add does not prove source membership');
}
function projectAgreement(e: ValidatedEvent, value: unknown): void {
    const f = object(value, ['project_id', 'recipient', 'agreement_id', 'published_versions']);
    factProject(f, e);
    require(equal(recipient(f.recipient), recipient(e.payload.recipient)), 'wrong canonical recipient');
    if (f.agreement_id !== null)
        require(string(f.agreement_id) === e.target.agreement_id, 'wrong current agreement');
    const seen = new Set<string>();
    for (const value of array(f.published_versions)) {
        const row = object(value, ['agreement_id', 'version']), agreement = string(row.agreement_id), version = string(row.version), id = JSON.stringify([agreement, version]);
        require(f.agreement_id !== null && agreement === f.agreement_id && !seen.has(id), 'inconsistent publication catalog');
        seen.add(id);
        require(agreement !== e.target.agreement_id || version !== e.target.version, 'version already published');
    }
}
async function supersededAcceptance(e: ValidatedEvent, value: unknown): Promise<void> {
    const f = object(value, ['event_id', 'type', 'project_id', 'target', 'payload']);
    eventId(f.event_id);
    const t = object(f.target), p = object(f.payload);
    await targetPayload('acceptance', t, p);
    require(f.event_id === e.payload.supersedes && f.type === 'acceptance' && f.project_id === e.project_id, 'wrong superseded event');
    require(equal(coverage(t.coverage_tuple), coverage(e.target.coverage_tuple)) && equal(recipient(t.recipient), recipient(e.target.recipient)) && t.version === e.target.version && t.digest === e.target.digest, 'superseded acceptance target mismatch');
}
function acceptanceBasis(e: ValidatedEvent, value: unknown): void {
    const f = object(value, ['project_id', 'github_user_id', 'agreement_id', 'basis']), basis = object(f.basis, ['event_id', 'kind']);
    eventId(basis.event_id);
    integer(f.github_user_id);
    string(f.agreement_id);
    require(f.project_id === e.project_id && f.github_user_id === object(e.target.coverage_tuple).github_user_id && f.agreement_id === object(e.target.coverage_tuple).agreement_id && basis.kind === 'acceptance' && basis.event_id === e.payload.supersedes, 'acceptance basis mismatch');
}
async function activeAgreement(e: ValidatedEvent, value: unknown): Promise<void> {
    const f = object(value);
    if (e.type === 'acceptance') {
        object(f, ['project_id', 'agreement_id', 'version', 'recipient', 'digest', 'state', 'accepted_versions', 'retired_versions', 'active_version', 'activation_event_id', 'supersedes_coverage', 'publication']);
        factProject(f, e);
        require(f.state === 'active' && f.agreement_id === object(e.target.coverage_tuple).agreement_id && f.version === e.target.version && f.active_version === e.target.version, 'active agreement target mismatch');
        require(equal(f.recipient, e.target.recipient) && f.digest === e.target.digest, 'active publication mismatch');
        const accepted = stringSet(f.accepted_versions), retired = stringSet(f.retired_versions, true);
        require(!accepted.some(version => retired.includes(version)) && accepted.includes(string(f.version)) && typeof f.supersedes_coverage === 'boolean', 'active accepted/retired relation mismatch');
        eventId(f.activation_event_id);
        await linkFact(e, 'active-publication', f.publication);
        return;
    }
    // The exact same read-only closed projection decoder serves the Worker read and append boundaries.
    await decodeProjection(resolveArtifactIdentity('coverage', 'coverage', 'agreements/active.enc.json'), canonicalJson(f));
    const accepted = stringSet(f.accepted_versions, true), retired = stringSet(f.retired_versions, true);
    if (accepted.length)
        require(f.agreement_id === e.target.agreement_id, 'prior active agreement mismatch');
    if (e.type === 'agreement_activated') {
        const version = string(e.target.version);
        require(!retired.includes(version), 'ordinary activation revives retired version');
        const expected = e.payload.supersedes_coverage ? [version] : versionUnion(accepted, [version]);
        require(equal(e.payload.accepted_versions, expected), 'activation accepted-version transition mismatch');
    }
}
function registryEntries(value: unknown, keys: readonly string[]): Map<string, ObjectValue> {
    const input = object(value, keys);
    return new Map(keys.map(key => [key, registryEntry(input[key])]));
}
function routingEqual(a: ObjectValue, b: ObjectValue, includeOwner: boolean): void {
    require(a.project_slug === b.project_slug && equal(repositoryIds(a.repository_ids), repositoryIds(b.repository_ids)), 'registry routing changed');
    if (includeOwner)
        require(equal(owner(a.repository_owner), owner(b.repository_owner)), 'registry owner changed');
}
function registryOwner(e: ValidatedEvent, evidence: Evidence): void {
    const entries = registryEntries(evidence.value, ['prior_entry', 'staged_entry']), prior = entries.get('prior_entry')!, staged = entries.get('staged_entry')!;
    factProject(prior, e);
    factProject(staged, e);
    require(equal(owner(prior.repository_owner), owner(e.target.prior_repository_owner)) && equal(owner(staged.repository_owner), owner(e.payload.new_repository_owner)), 'registry owner transition mismatch');
    routingEqual(prior, staged, false);
    require(equal(scope(prior.enforcement_scope), scope(staged.enforcement_scope)) && equal(prior.request_event_links, staged.request_event_links), 'owner transition changed unrelated state');
    require(integer(prior.registry_generation, true) < integer(staged.registry_generation, true), 'registry generation did not advance');
    require(equal(staged.repository_ids, e.payload.repository_ids) && staged.project_slug === e.payload.project_slug && staged.registry_generation === e.payload.registry_generation, 'staged owner event mismatch');
    require(evidence.binding.registry_commit_oid === e.payload.registry_commit_oid && evidence.binding.registry_generation === e.payload.registry_generation, 'owner binding mismatch');
}
function registryScope(e: ValidatedEvent, evidence: Evidence, values: Map<string, Evidence>): void {
    let generation: unknown;
    if (e.type === 'enforcement_scope_requested') {
        const entries = registryEntries(evidence.value, ['prior_entry', 'current_entry']), prior = entries.get('prior_entry')!, current = entries.get('current_entry')!;
        const expected = scope(e.payload.prior_scope);
        for (const entry of [prior, current]) {
            factProject(entry, e);
            require(equal(scope(entry.enforcement_scope), expected) && entry.registry_generation === e.payload.prior_registry_generation, 'scope request differs from registry');
        }
        routingEqual(prior, current, false);
        generation = e.payload.prior_registry_generation;
    }
    else {
        const request = object(object(values.get('scope-request')!.value).payload);
        if (e.type === 'enforcement_scope_activated') {
            const entries = registryEntries(evidence.value, ['prior_entry', 'staged_entry']), prior = entries.get('prior_entry')!, staged = entries.get('staged_entry')!;
            factProject(prior, e);
            factProject(staged, e);
            require(equal(scope(prior.enforcement_scope), scope(request.prior_scope)) && prior.registry_generation === request.prior_registry_generation, 'scope activation prior mismatch');
            require(equal(scope(staged.enforcement_scope), scope(e.payload.desired_scope)) && staged.registry_generation === e.payload.registry_generation, 'scope activation staged mismatch');
            routingEqual(prior, staged, true);
            const links = object(prior.request_event_links), change = string(e.target.change_id);
            require(!Object.hasOwn(links, change), 'scope request already linked');
            require(equal(staged.request_event_links, { ...links, [change]: e.payload.request_event_id }), 'unrelated scope request link changes');
            require(integer(prior.registry_generation, true) < integer(staged.registry_generation, true), 'scope generation did not advance');
            require(evidence.binding.registry_commit_oid === e.payload.registry_commit_oid && evidence.binding.registry_generation === e.payload.registry_generation, 'scope activation binding mismatch');
            generation = e.payload.registry_generation;
        }
        else {
            const current = registryEntries(evidence.value, ['current_entry']).get('current_entry')!;
            factProject(current, e);
            require(equal(scope(current.enforcement_scope), scope(request.prior_scope)) && current.registry_generation === request.prior_registry_generation, 'scope abandonment registry mismatch');
            generation = request.prior_registry_generation;
        }
    }
    require(evidence.binding.registry_generation === generation, 'scope binding generation mismatch');
}
function lifecycle(e: ValidatedEvent, value: unknown): void {
    const f = object(value, ['project_id', 'state', 'successor_project_id']);
    factProject(f, e);
    require(f.state === 'active' || f.state === 'succeeded', 'invalid lifecycle state');
    if (f.state === 'active') {
        require(f.successor_project_id === null, 'active project names successor');
        return;
    }
    string(f.successor_project_id);
    const removableScope = ['enforcement_scope_requested', 'enforcement_scope_activated'].includes(e.type) && e.authorizations.some(row => ['enforcement_scope_repository_narrow', 'enforcement_scope_repository_remove', 'enforcement_scope_organization_narrow', 'enforcement_scope_organization_remove'].includes(string(row.operation)));
    const removableAutomation = automationTypes.includes(e.type) && e.payload.result === 'withdraw';
    require(['revocation', 'keyring_activated', 'retry_requested', 'enforcement_scope_abandoned', 'records_reader_authorized', 'records_reader_snapshot_authorized', 'records_reader_withdrawn', 'records_reader_rule_configured', 'records_reader_rule_withdrawn'].includes(e.type) || removableScope || removableAutomation, 'event forbidden after project success');
}
function readerAuthorityState(e: ValidatedEvent, evidence: Evidence): void {
    const identityKeys = e.type === 'records_reader_withdrawn' ? ['source_event_id', 'subject'] : ['rule_event_id'];
    const f = object(evidence.value, ['project_id', 'class_state', 'source_event_ids', 'cursor_event_id', ...identityKeys]);
    factProject(f, e);
    const state = evidence.binding.canonical_generation === evidence.binding.derived_generation ? 'current' : 'stale';
    require(f.class_state === state && eventId(f.cursor_event_id) === evidence.binding.derived_generation, 'reader state/generation mismatch');
    eventIds(f.source_event_ids);
    if (e.type === 'records_reader_withdrawn')
        require(eventId(f.source_event_id) === e.target.source_event_id && equal(subject(f.subject), subject(e.target.subject)), 'reader withdrawal identity mismatch');
    else
        require(eventId(f.rule_event_id) === e.target.rule_event_id, 'reader rule withdrawal identity mismatch');
}
function readerAuthority(e: ValidatedEvent, evidence: Evidence): void {
    const extra = e.type === 'records_reader_materialized' ? ['rule_event_id', 'subject', 'source_record_present'] : [];
    const f = object(evidence.value, ['project_id', 'class_state', 'sources', 'cursor_event_id', ...extra]);
    factProject(f, e);
    require(f.class_state === 'current' || f.class_state === 'stale', 'invalid reader class state');
    eventId(f.cursor_event_id);
    const sources = eventIds(f.sources);
    if (e.type === 'records_reader_materialized') {
        const source = eventId(f.rule_event_id);
        require(source === e.target.rule_event_id && equal(subject(f.subject), subject(e.target.subject)) && typeof f.source_record_present === 'boolean', 'reader materialization identity mismatch');
        const present = sources.includes(source);
        require(!present || f.source_record_present, 'reader source presence inconsistent');
        if (e.payload.result === 'add')
            require(f.source_record_present && !present, 'reader rule inactive or already materialized');
        else
            require(present && f.class_state !== 'stale', 'reader rule missing or stale for materialization withdrawal');
    }
}
function derivedRuleState(e: ValidatedEvent, evidence: Evidence): void {
    const reader = e.type === 'records_reader_rule_configured';
    const f = object(evidence.value, ['project_id', 'standing_rule_event_ids', 'max_continuous_exemption_rules', 'max_state_ciphertext_bytes', ...(reader ? ['max_continuous_reader_rules'] : [])]);
    factProject(f, e);
    const rules = eventIds(f.standing_rule_event_ids), maxRules = integer(f.max_continuous_exemption_rules);
    integer(f.max_state_ciphertext_bytes);
    if (reader)
        integer(f.max_continuous_reader_rules);
    else
        require(rules.length < maxRules, 'continuous exemption rule limit reached');
}
function exemptionUnion(e: ValidatedEvent, name: string, value: unknown): void {
    const shard = Number(name.slice(-2)), f = object(value, ['project_id', 'subjects', 'provenance']);
    factProject(f, e);
    const rows = array(f.subjects), union = rows.length ? subjects(rows) : [], provenance = object(f.provenance);
    const ids = union.map(row => String(row.github_user_id));
    require(Object.keys(provenance).length === ids.length && ids.every(id => Object.hasOwn(provenance, id)), 'provenance does not cover union');
    for (const row of union)
        require(integer(row.github_user_id) % 32 === shard, 'union subject belongs to another shard');
    for (const [id, value] of Object.entries(provenance)) {
        require(/^[0-9]+$/.test(id) && Number(id) % 32 === shard, 'wrong provenance shard');
        require(eventIds(value).length > 0, 'empty provenance');
    }
    if (e.type === 'exemption_materialized') {
        const id = String(object(e.target.subject).github_user_id), sources = Object.hasOwn(provenance, id) ? eventIds(provenance[id]) : [];
        require(sources.includes(string(e.target.rule_event_id)) === (e.payload.result === 'withdraw'), 'exemption materialization presence mismatch');
    }
}
function coverageState(e: ValidatedEvent, name: string, value: unknown): void {
    const f = object(value, ['project_id', 'state', 'resource', 'subject_ids']);
    factProject(f, e);
    object(f.resource);
    require(f.state === 'current' || f.state === 'active', 'invalid coverage state');
    require(equal(f.resource, e.target), 'coverage target mismatch');
    const ids = array(f.subject_ids).map(value => integer(value));
    unique(ids);
    require(ids.every((id, i) => !i || ids[i - 1]! < id), 'coverage subject IDs not ordered');
    const expected = e.type === 'revocation' ? [integer(object(e.target.coverage_tuple).github_user_id)] : array(e.payload.subjects).map(row => integer(object(row).github_user_id));
    const shard = Number(name.slice(-2)), selected = [...new Set(expected.filter(id => id % 32 === shard))].sort((a, b) => a - b);
    require(equal(ids, selected), 'coverage subjects mismatch');
}
async function preconditionsImpl(e: ValidatedEvent, input: unknown, head: string): Promise<Map<string, Evidence>> {
    const expected = await requirements(e, head), values = evidenceMap(input);
    require(values.size === expected.length && expected.every(row => values.has(row.name)), 'preconditions do not exactly match requirements');
    for (const requirement of expected) {
        const name = requirement.name, evidence = values.get(name)!;
        bound(evidence, requirement);
        if (name === 'source-first-add')
            continue;
        if (name === 'materialization-cursor') {
            const f = object(evidence.value, ['cursor_event_id', 'prior_materialization_event_id', 'rule_event_id', 'subject']);
            if (f.cursor_event_id !== null)
                eventId(f.cursor_event_id);
            if (f.prior_materialization_event_id !== null)
                eventId(f.prior_materialization_event_id);
            require(f.rule_event_id === e.target.rule_event_id && equal(subject(f.subject), subject(e.target.subject)) && f.cursor_event_id === e.payload.prior_materialization_event_id, 'materialization cursor mismatch');
        }
        else if (name === 'reader-authority-state')
            readerAuthorityState(e, evidence);
        else if (name === 'current-reader-authority')
            readerAuthority(e, evidence);
        else if (name === 'active-exemption-rule-state') {
            const f = object(evidence.value, ['project_id', 'standing_rule_event_ids']);
            factProject(f, e);
            require(eventIds(f.standing_rule_event_ids).includes(string(e.target.rule_event_id)), 'referenced exemption rule is inactive');
        }
        else if (name === 'current-derived-state')
            derivedRuleState(e, evidence);
        else if (name.startsWith('active-reader-rules-')) {
            const f = object(evidence.value, ['project_id', 'rule_event_ids']);
            factProject(f, e);
            for (const id of eventIds(f.rule_event_ids))
                require(await readerPath(id) === evidence.path, 'reader rule bound to wrong shard');
        }
        else if (name.startsWith('current-exemption-union-'))
            exemptionUnion(e, name, evidence.value);
        else if (name === 'override-grant') {
            const f = object(evidence.value, ['event', 'active']), grant = object(f.event, ['event_id', 'type', 'project_id', 'target', 'payload']);
            require(grant.event_id === e.target.override_event_id && grant.type === 'override' && grant.project_id === e.project_id && f.active === true, 'override grant mismatch');
            const grantTarget = object(grant.target);
            await targetPayload('override', grantTarget, object(grant.payload));
            require(e.authorizations.every(row => row.resource_id === grantTarget.repository_id), 'override withdrawal authorization repository mismatch');
        }
        else if (name.startsWith('scope-terminal-') || name === 'publication-snapshot-absence' || name === 'publication-metadata-absence')
            absence(evidence.value, evidence.path);
        else if (name === 'generations-absence')
            require(evidence.value === null || equal(evidence.value, { absent: true }), 'genesis generations already present');
        else if (name === 'prior-generations') {
            const f = object(evidence.value, ['derived_index', 'status_detail', 'reader_authority']);
            for (const id of Object.values(f))
                eventId(id);
        }
        else if (name === 'keyring-affected-repositories') {
            const f = object(evidence.value, ['project_id', 'repository_ids']);
            factProject(f, e);
            const ids = Object.values(repositoryIds(f.repository_ids));
            require(e.authorizations.length === 3 && e.authorizations.every(row => ids.includes(row.resource_id)), 'keyring affected repositories mismatch');
        }
        else if (name === 'current-project-agreement')
            projectAgreement(e, evidence.value);
        else if (name === 'superseded-acceptance')
            await supersededAcceptance(e, evidence.value);
        else if (name === 'current-acceptance-basis')
            acceptanceBasis(e, evidence.value);
        else if (name === 'current-configuration') {
            const config = configuration(evidence.value), fields = array(config.required_fields).map(row => string(object(row).name)), actual = Object.keys(object(e.payload.fields));
            require(fields.length === actual.length && fields.every(name => Object.hasOwn(object(e.payload.fields), name)), 'acceptance fields mismatch current configuration');
            require(equal(array(e.payload.confirmations).map(row => object(row).label), config.confirmation_labels), 'acceptance confirmations mismatch current configuration');
        }
        else if (['published-agreement', 'target-activation', 'scope-request', 'source-event', 'rule-event'].includes(name))
            await linkFact(e, name, evidence.value);
        else if (name === 'successor-project') {
            const f = object(evidence.value, ['event', 'active_agreement']), successor = object(f.event, ['event_id', 'type', 'project_id', 'target', 'payload']), payload = object(successor.payload);
            require(successor.event_id === e.payload.successor_connected_event_id && successor.type === 'project_connected' && successor.project_id === e.target.successor_project_id && payload.successor_of === e.project_id, 'successor is not reciprocal');
            const ids = Object.values(repositoryIds(payload.repository_ids)), boundIds = array(evidence.binding.repository_ids);
            require(boundIds.length === ids.length && boundIds.every(id => ids.includes(id)), 'successor repositories not registry-bound');
            const agreement = object(f.active_agreement, ['project_id', 'agreement_id', 'version', 'state']);
            require(agreement.project_id === successor.project_id && agreement.state === 'active', 'successor agreement not active');
        }
        else if (name === 'project-lifecycle')
            lifecycle(e, evidence.value);
        else if (name === 'active-agreement')
            await activeAgreement(e, evidence.value);
        else if (name === 'current-repository-owner')
            registryOwner(e, evidence);
        else if (name === 'current-scope')
            registryScope(e, evidence, values);
        else if (name.startsWith('coverage-state-'))
            coverageState(e, name, evidence.value);
        else
            throw new PreconditionValidationError('unknown precondition descriptor');
    }
    // A generation pair is insufficient on its own: join it to the authenticated canonical prior.
    for (const requirement of expected)
        if (requirement.binding_mode === 'generation') {
            const priorEvidence = values.get('prior-generations');
            require(priorEvidence, 'missing authenticated prior generations');
            const prior = object(priorEvidence.value, ['derived_index', 'status_detail', 'reader_authority']);
            const selected = e.type === 'records_reader_rule_configured' && requirement.name === 'current-derived-state' ? 'reader_authority' : requirement.artifact_kind === 'reader-authority' ? 'reader_authority' : requirement.artifact_kind === 'derived-state' || requirement.artifact_kind === 'status-detail' ? 'status_detail' : null;
            require(selected !== null && values.get(requirement.name)!.binding.canonical_generation === eventId(prior[selected]), 'generation does not join canonical prior');
        }
    if (e.type === 'records_reader_rule_configured') {
        const limit = integer(object(values.get('current-derived-state')!.value).max_continuous_reader_rules);
        let count = 0;
        for (const [name, evidence] of values)
            if (name.startsWith('active-reader-rules-'))
                count += array(object(evidence.value).rule_event_ids).length;
        require(count < limit, 'project-wide continuous reader rule limit reached');
    }
    if (e.type === 'exemption_source_withdrawn' || e.type === 'records_reader_withdrawn')
        await sourceFirstAdd(e, values);
    return values;
}
async function checkedPreconditions(e: ValidatedEvent, input: unknown, head: string): Promise<Map<string, Evidence>> {
    try {
        return await preconditionsImpl(e, input, head);
    }
    catch {
        throw new PreconditionValidationError('preconditions failed authentication or relation validation');
    }
}
export async function validatePreconditions(value: unknown, preconditions: unknown, expectedHead: string): Promise<readonly ReadonlyJsonObject[]> {
    try {
        const input = parseCanonicalJson(canonicalJson(preconditions)), event = await validateEvent(value);
        const values = await checkedPreconditions(event, input, expectedHead);
        return freeze([...values.values()]) as unknown as readonly ReadonlyJsonObject[];
    }
    catch {
        throw new PreconditionValidationError('preconditions failed authentication or relation validation');
    }
}
export interface SideArtifactRequirement {
    readonly kind: string;
    readonly path: string;
    readonly relation: string;
    readonly affected_classes: readonly string[];
}
function classesAffected(e: ValidatedEvent, evidence: Map<string, Evidence>): readonly string[] {
    if (e.type === 'exemption_rule_withdrawn') {
        const rule = string(e.target.rule_event_id);
        for (const [name, item] of evidence)
            if (name.startsWith('current-exemption-union-')) {
                const provenance = object(object(item.value).provenance);
                if (Object.values(provenance).some(value => { const sources = array(value); return sources.length === 1 && sources[0] === rule; }))
                    return ['derived_index', 'status_detail'];
            }
        return ['status_detail'];
    }
    if (e.type === 'records_reader_withdrawn' || e.type === 'records_reader_rule_withdrawn') {
        const observation = evidence.get('reader-authority-state')!, f = object(observation.value);
        return observation.binding.canonical_generation !== observation.binding.derived_generation || array(f.source_event_ids).includes(e.target.source_event_id ?? e.target.rule_event_id) ? ['reader_authority'] : [];
    }
    return affectedClasses[e.type] ?? [];
}
function sideRequirements(e: ValidatedEvent, evidence: Map<string, Evidence>): readonly SideArtifactRequirement[] {
    const result: SideArtifactRequirement[] = [];
    if (e.type === 'agreement_published') {
        result.push({ kind: 'agreement_snapshot', path: string(e.payload.snapshot_content_path), relation: 'recomputed-digest', affected_classes: [] });
        result.push({ kind: 'agreement_metadata', path: string(e.payload.snapshot_metadata_path), relation: 'event-determined', affected_classes: [] });
    }
    if (e.type === 'project_connected' || e.type === 'config_updated')
        result.push({ kind: 'project_config', path: 'config/project.enc.json', relation: 'event-determined', affected_classes: [] });
    const affected = classesAffected(e, evidence);
    if (affected.length)
        result.push({ kind: 'materialization_generations', path: 'config/materialization-generations.enc.json', relation: 'event-determined', affected_classes: [...affected] });
    result.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
    return freeze(result);
}
export async function requiredSideArtifacts(value: unknown, preconditions: unknown, expectedHead: string): Promise<readonly SideArtifactRequirement[]> {
    try {
        const input = parseCanonicalJson(canonicalJson(preconditions)), e = await validateEvent(value);
        return sideRequirements(e, await checkedPreconditions(e, input, expectedHead));
    }
    catch {
        throw new PreconditionValidationError('side-artifact preconditions failed validation');
    }
}
interface SideArtifact {
    kind: string;
    path: string;
    bytes: Uint8Array<ArrayBuffer>;
    sha256: string;
}
function sideArtifacts(value: unknown): SideArtifact[] {
    return array(value).map(value => {
        const row = object(value), raw = Object.hasOwn(row, 'bytes');
        object(row, ['kind', 'path', raw ? 'bytes' : 'bytes_b64', 'sha256']);
        const bytes = raw ? copyBytes(row.bytes as Uint8Array) : base64urlDecode(typeof row.bytes_b64 === 'string' ? row.bytes_b64 : (() => { throw new SideArtifactValidationError('invalid artifact encoding'); })());
        return { kind: string(row.kind), path: string(row.path), bytes, sha256: digest(row.sha256) };
    });
}
export async function validateSideArtifactPackage(value: unknown, artifacts: unknown, preconditions: unknown, expectedHead: string): Promise<void> {
    let e: ValidatedEvent, evidence: Map<string, Evidence>, actual: SideArtifact[];
    try {
        // Copy all byte and JSON inputs before any event hashing can yield to caller mutations.
        actual = sideArtifacts(artifacts);
        const input = parseCanonicalJson(canonicalJson(preconditions));
        e = await validateEvent(value);
        evidence = await checkedPreconditions(e, input, expectedHead);
    }
    catch (error) {
        if (error instanceof PreconditionValidationError)
            throw error;
        throw new SideArtifactValidationError('invalid package event, artifacts or preconditions');
    }
    try {
        const expected = sideRequirements(e, evidence);
        unique(actual.map(row => row.path));
        require(actual.every((row, i) => !i || actual[i - 1]!.path < row.path), 'package is not path ordered');
        require(actual.length === expected.length && actual.every((row, i) => row.path === expected[i]!.path && row.kind === expected[i]!.kind), 'package membership or kind mismatch');
        for (const artifact of actual) {
            const hash = 'sha256:' + hex(await sha256(artifact.bytes));
            require(hash === artifact.sha256, 'artifact digest mismatch');
            if (artifact.kind === 'agreement_snapshot') {
                new TextDecoder('utf-8', { fatal: true }).decode(artifact.bytes);
                require(hash === e.payload.snapshot_sha256 && hash === e.payload.digest, 'snapshot digest differs from publication');
            }
            else if (artifact.kind === 'agreement_metadata') {
                const expected = { metadata_version: 1, agreement_id: e.target.agreement_id, version: e.target.version, recipient: e.payload.recipient, ref: e.payload.ref, content_commit_oid: e.payload.content_commit_oid, digest: e.payload.digest, snapshot_sha256: e.payload.snapshot_sha256 };
                require(equal(parseCanonicalJson(artifact.bytes), expected), 'metadata differs from exact closed publication metadata');
            }
            else if (artifact.kind === 'project_config')
                require(compare(artifact.bytes, canonicalJson(e.payload.project_configuration)) === 0, 'configuration bytes differ from event');
            else {
                const affected = classesAffected(e, evidence), prior = e.type === 'project_connected' ? null : object(evidence.get('prior-generations')!.value);
                const expected: ObjectValue = { generations_version: 1 };
                for (const name of ['derived_index', 'status_detail', 'reader_authority'])
                    expected[name] = e.type === 'project_connected' || affected.includes(name) ? e.event_id : prior![name];
                require(equal(parseCanonicalJson(artifact.bytes), expected), 'generation bytes differ from event or authenticated prior');
            }
        }
    }
    catch {
        throw new SideArtifactValidationError('side-artifact package failed exact byte validation');
    }
}
const preconditionMatrix: Readonly<Record<string, readonly string[]>> = {
    "project_connected": ["generations-absence"],
    "acceptance": ["project-lifecycle", "active-agreement", "current-configuration", "prior-generations"],
    "revocation": ["project-lifecycle", "coverage-state", "prior-generations"],
    "agreement_published": ["project-lifecycle", "current-project-agreement", "publication-snapshot-absence", "publication-metadata-absence"],
    "agreement_activated": ["project-lifecycle", "published-agreement", "active-agreement"],
    "agreement_activation_restored": ["project-lifecycle", "target-activation", "active-agreement"],
    "project_repository_owner_changed": ["project-lifecycle", "current-repository-owner"],
    "project_succeeded": ["project-lifecycle", "successor-project"],
    "config_updated": ["project-lifecycle"],
    "keyring_activated": ["project-lifecycle", "keyring-affected-repositories"],
    "enforcement_scope_requested": ["project-lifecycle", "current-scope"],
    "enforcement_scope_activated": ["project-lifecycle", "current-scope", "scope-request", "scope-terminal-activation-absence", "scope-terminal-abandonment-absence"],
    "enforcement_scope_abandoned": ["project-lifecycle", "current-scope", "scope-request", "scope-terminal-activation-absence", "scope-terminal-abandonment-absence"],
    "override": ["project-lifecycle", "coverage-state"],
    "override_withdrawn": ["project-lifecycle", "override-grant"],
    "retry_requested": ["project-lifecycle"],
    "exemption": ["project-lifecycle", "current-exemption-union", "prior-generations"],
    "exemption_snapshot": ["project-lifecycle", "current-exemption-union", "prior-generations"],
    "exemption_source_withdrawn": ["project-lifecycle", "source-event", "source-first-add", "current-exemption-union", "prior-generations"],
    "exemption_rule_configured": ["project-lifecycle", "current-derived-state", "prior-generations"],
    "exemption_rule_withdrawn": ["project-lifecycle", "rule-event", "current-exemption-union", "prior-generations"],
    "exemption_materialized": ["project-lifecycle", "rule-event", "active-exemption-rule-state", "current-exemption-union", "materialization-cursor", "prior-generations"],
    "records_reader_authorized": ["project-lifecycle", "current-reader-authority", "prior-generations"],
    "records_reader_snapshot_authorized": ["project-lifecycle", "current-reader-authority", "prior-generations"],
    "records_reader_withdrawn": ["project-lifecycle", "source-event", "source-first-add", "reader-authority-state", "prior-generations"],
    "records_reader_rule_configured": ["project-lifecycle", "current-derived-state", "active-reader-rules", "prior-generations"],
    "records_reader_rule_withdrawn": ["project-lifecycle", "rule-event", "reader-authority-state", "prior-generations"],
    "records_reader_materialized": ["project-lifecycle", "rule-event", "current-reader-authority", "materialization-cursor", "prior-generations"],
};
const affectedClasses: Readonly<Record<string, readonly string[]>> = {
    "project_connected": ["derived_index", "status_detail", "reader_authority"],
    "acceptance": ["derived_index", "status_detail"],
    "revocation": ["derived_index", "status_detail"],
    "exemption": ["derived_index", "status_detail"],
    "exemption_snapshot": ["derived_index", "status_detail"],
    "exemption_source_withdrawn": ["derived_index", "status_detail"],
    "exemption_materialized": ["derived_index", "status_detail"],
    "exemption_rule_configured": ["status_detail"],
    "exemption_rule_withdrawn": ["status_detail"],
    "records_reader_authorized": ["reader_authority"],
    "records_reader_snapshot_authorized": ["reader_authority"],
    "records_reader_withdrawn": ["reader_authority"],
    "records_reader_rule_configured": ["reader_authority"],
    "records_reader_rule_withdrawn": ["reader_authority"],
    "records_reader_materialized": ["reader_authority"],
};
