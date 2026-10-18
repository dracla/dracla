/** Authenticated action forms and immutable terminal-effect proofs (HLD 5.4).
 * Eligible keys, live session context and the immutable terminal read are caller facts.
 */
import { canonicalJson, parseCanonicalJson, freezeJson, type JsonObject, type ReadonlyJsonObject } from './canonical.js';
import { base64urlDecode, base64urlEncode, copyBytes } from './encoding.js';
import { deriveEventIdentity, eventPath, parseEventJcs, validateEvent, validateEventOperation } from './events.js';
export class ActionFormError extends Error {
    constructor(message: string) { super(message); this.name = new.target.name; }
}
export const FORM_ACTION_TYPES = Object.freeze([
    'acceptance', 'revocation', 'project_connected', 'project_repository_owner_changed',
    'project_succeeded', 'keyring_activated', 'agreement_published', 'agreement_activated',
    'agreement_activation_restored', 'enforcement_scope_requested', 'exemption', 'exemption_snapshot',
    'exemption_rule_configured', 'exemption_rule_withdrawn', 'exemption_source_withdrawn',
    'records_reader_authorized', 'records_reader_snapshot_authorized', 'records_reader_withdrawn',
    'records_reader_rule_configured', 'records_reader_rule_withdrawn', 'override', 'override_withdrawn',
    'retry_requested', 'config_updated',
] as const);
export type FormActionType = typeof FORM_ACTION_TYPES[number];
export interface FormActionSpec {
    readonly action_type: FormActionType;
    readonly write_type: FormActionType;
    readonly terminal_types: readonly string[];
}
const registry = new Map<string, FormActionSpec>(FORM_ACTION_TYPES.map(type => [type, Object.freeze({
        action_type: type, write_type: type,
        terminal_types: Object.freeze(type === 'agreement_activation_restored' ? ['agreement_activated', 'agreement_activation_restored']
            : type === 'enforcement_scope_requested' ? ['enforcement_scope_activated'] : type === 'retry_requested' ? [] : [type]),
    })]));
export function formActionSpec(type: string): FormActionSpec {
    const spec = registry.get(type);
    if (!spec)
        throw new ActionFormError('unsupported form action');
    return spec;
}
export interface ActionForm {
    readonly v: 1;
    readonly algorithm: 'HS256';
    readonly kid: string;
    readonly session_jti: string;
    readonly github_user_id: number;
    readonly project_id: string;
    readonly type: FormActionType;
    readonly operation_nonce: string;
    readonly confirmed_canonical_oid: string;
    readonly operation_sha256: string;
    readonly terminal_noop_event_id: string | null;
    readonly issued_at: string;
    readonly expires_at: string;
}
export interface ActionFormContext {
    readonly current_time: string;
    readonly session_expires_at: string;
    readonly session_jti: string;
    readonly github_user_id: number;
    readonly project_id: string;
    readonly type: FormActionType;
    readonly operation_nonce: string;
    readonly confirmed_canonical_oid: string;
    readonly operation_sha256: string;
}
export interface VerifiedActionForm {
    readonly form: ActionForm;
    readonly isNoop: boolean;
    readonly preparable: boolean;
}
const verifiedForms = new WeakSet<object>();
const domain = new TextEncoder().encode('dracla-action-form-v1\0');
const formFields = ['v', 'algorithm', 'kid', 'session_jti', 'github_user_id', 'project_id', 'type', 'operation_nonce',
    'confirmed_canonical_oid', 'operation_sha256', 'terminal_noop_event_id', 'issued_at', 'expires_at'];
const boundFields = ['session_jti', 'github_user_id', 'project_id', 'type', 'operation_nonce', 'operation_sha256'] as const;
function require(value: unknown, message = 'invalid action form'): asserts value {
    if (!value)
        throw new ActionFormError(message);
}
function object(value: unknown, fields: readonly string[]): JsonObject {
    require(value !== null && typeof value === 'object' && !Array.isArray(value));
    require(Object.keys(value).length === fields.length && fields.every(k => Object.hasOwn(value, k)));
    return value as JsonObject;
}
function string(value: unknown): asserts value is string { require(typeof value === 'string' && value.length > 0); }
function encoded(value: unknown, length: number): void { string(value); base64urlDecode(value, length); }
function oid(value: unknown): void { string(value); require(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(value)); }
function digest(value: unknown): void { string(value); require(/^sha256:[a-f0-9]{64}$/.test(value)); }
function time(value: unknown): number {
    string(value);
    require(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && Number(value.slice(0, 4)) > 0);
    const date = new Date(value);
    require(Number.isFinite(date.getTime()) && date.toISOString() === value.slice(0, -1) + '.000Z');
    return date.getTime();
}
function bindings(value: JsonObject): void {
    string(value.session_jti);
    string(value.project_id);
    require(typeof value.github_user_id === 'number' && Number.isSafeInteger(value.github_user_id) && value.github_user_id > 0);
    string(value.type);
    formActionSpec(value.type);
    encoded(value.operation_nonce, 16);
    oid(value.confirmed_canonical_oid);
    digest(value.operation_sha256);
}
function payload(value: unknown): ActionForm {
    const obj = object(parseCanonicalJson(canonicalJson(value)), formFields);
    require(obj.v === 1 && obj.algorithm === 'HS256');
    encoded(obj.kid, 16);
    bindings(obj);
    if (obj.terminal_noop_event_id !== null) {
        encoded(obj.terminal_noop_event_id, 32);
        require(formActionSpec(obj.type as string).terminal_types.length > 0);
    }
    const lifetime = time(obj.expires_at) - time(obj.issued_at);
    require(lifetime >= 0 && lifetime <= (7 * 60 + 55) * 60 * 1000);
    return freezeJson(obj) as unknown as ActionForm;
}
function context(value: unknown): ActionFormContext {
    const obj = object(parseCanonicalJson(canonicalJson(value)), ['current_time', 'session_expires_at', 'session_jti',
        'github_user_id', 'project_id', 'type', 'operation_nonce', 'confirmed_canonical_oid', 'operation_sha256']);
    bindings(obj);
    time(obj.current_time);
    time(obj.session_expires_at);
    return freezeJson(obj) as unknown as ActionFormContext;
}
function authenticatedBytes(data: Uint8Array): Uint8Array<ArrayBuffer> {
    const result = new Uint8Array(domain.length + data.length);
    result.set(domain);
    result.set(data, domain.length);
    return result;
}
async function key(value: Uint8Array, usage: 'sign' | 'verify'): Promise<CryptoKey> {
    const owned = copyBytes(value);
    require(owned.length > 0, 'invalid form key');
    return crypto.subtle.importKey('raw', owned, { name: 'HMAC', hash: 'SHA-256' }, false, [usage]);
}
export async function encodeActionForm(value: unknown, options: {
    key: Uint8Array;
}): Promise<string> {
    try {
        const data = canonicalJson(payload(value)), secret = key(options.key, 'sign');
        const tag = new Uint8Array(await crypto.subtle.sign('HMAC', await secret, authenticatedBytes(data)));
        return base64urlEncode(data) + '.' + base64urlEncode(tag);
    }
    catch {
        throw new ActionFormError('invalid action-form payload or key');
    }
}
export async function verifyActionForm(token: string, options: {
    keys: ReadonlyMap<string, Uint8Array>;
    context: ActionFormContext;
}): Promise<VerifiedActionForm> {
    try {
        require(typeof token === 'string' && token.split('.').length === 2);
        const [part, signature] = token.split('.');
        const data = base64urlDecode(part!), tag = base64urlDecode(signature!, 32), form = payload(parseCanonicalJson(data));
        const current = context(options.context);
        require(options.keys instanceof Map && options.keys.has(form.kid), 'unknown or ineligible form key');
        const secret = key(options.keys.get(form.kid)!, 'verify');
        // Web Crypto performs the HMAC comparison; no JavaScript tag equality path.
        require(await crypto.subtle.verify('HMAC', await secret, tag, authenticatedBytes(data)), 'action-form authentication failed');
        require(boundFields.every(name => form[name] === current[name]), 'action-form context does not match');
        require(time(form.issued_at) <= time(current.current_time) && time(current.current_time) < time(form.expires_at)
            && time(form.expires_at) <= time(current.session_expires_at), 'action form is outside its absolute lifetime');
        require(form.terminal_noop_event_id !== null || form.confirmed_canonical_oid === current.confirmed_canonical_oid, 'canonical head changed; render a fresh action');
        const result = Object.freeze({ form, isNoop: form.terminal_noop_event_id !== null, preparable: form.terminal_noop_event_id === null });
        verifiedForms.add(result);
        return result;
    }
    catch {
        throw new ActionFormError('action form failed verification');
    }
}
function equal(a: unknown, b: unknown): boolean {
    const left = canonicalJson(a), right = canonicalJson(b);
    return left.length === right.length && left.every((v, i) => v === right[i]);
}
export async function validateTerminalNoop(form: VerifiedActionForm, event: unknown, operation: unknown, options: {
    expectedProjectId: string;
    expectedConfirmedOid: string;
}): Promise<void> {
    try {
        require(verifiedForms.has(form) && form.isNoop, 'a verified terminal no-op form is required');
        const value = form.form, project = options.expectedProjectId, head = options.expectedConfirmedOid;
        require(value.project_id === project && value.confirmed_canonical_oid === head, 'terminal read context mismatch');
        const op = object(parseCanonicalJson(canonicalJson(operation)), ['target', 'payload']);
        const terminalInput = event instanceof Uint8Array ? copyBytes(event) : parseCanonicalJson(canonicalJson(event));
        const checked = await validateEventOperation(value.type, op.target, op.payload), t = checked.target, p = checked.payload;
        if (value.type === 'acceptance' || value.type === 'revocation') {
            const coverage = t.coverage_tuple as ReadonlyJsonObject;
            require(coverage.project_id === value.project_id && coverage.github_user_id === value.github_user_id);
            if (value.type === 'acceptance')
                require(coverage.recipient_id === (t.recipient as ReadonlyJsonObject).recipient_id);
        }
        const identity = await deriveEventIdentity({ project_id: value.project_id, operation_nonce: value.operation_nonce,
            actor: { kind: 'github', github_user_id: value.github_user_id, login_snapshot: 'authenticated-user' },
            type: value.type, target: t, payload: p,
            confirmed_canonical_oid: value.type === 'acceptance' || value.type === 'revocation' ? value.confirmed_canonical_oid : null });
        require(identity.operation_sha256 === value.operation_sha256, 'submitted effect digest mismatch');
        const settings = { expectedProjectId: project, expectedPath: eventPath(value.terminal_noop_event_id!) };
        const terminal = terminalInput instanceof Uint8Array ? await parseEventJcs(terminalInput, settings) : await validateEvent(terminalInput, settings);
        require(formActionSpec(value.type).terminal_types.includes(terminal.type), 'terminal event type mismatch');
        if (value.type === 'enforcement_scope_requested')
            require(equal(terminal.payload.desired_scope, p.desired_scope));
        else if (value.type === 'agreement_activation_restored') {
            require(terminal.target.agreement_id === t.agreement_id
                && (terminal.type === 'agreement_activated' ? terminal.event_id : terminal.target.activation_event_id) === t.activation_event_id
                && equal(terminal.payload.accepted_versions, p.accepted_versions));
        }
        else
            require(equal(terminal.target, t) && equal(terminal.payload, p), 'terminal establishes a different desired effect');
    }
    catch {
        throw new ActionFormError('invalid terminal no-op proof');
    }
}
