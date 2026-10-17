/** Canonical wrapped project keys, matching the Python M1-3 contract. */
import { canonicalJson, parseCanonicalJson, type JsonObject } from './canonical.js';
import { base64urlDecode, base64urlEncode, copyBytes } from './encoding.js';

export class KeyringError extends Error {
    constructor(message: string) { super(message); this.name = new.target.name; }
}
export class KeyringFormatError extends KeyringError {}
export class KeyringContextError extends KeyringError {}
export class UnknownWrappingKeyError extends KeyringError {}
export class KeyringAuthenticationError extends KeyringError {}

export const WRAP_VERSION = 1;
export const KEYRING_VERSION = 1;
export const WRAPPED_KEY_ALGORITHM = 'A256GCM';
export const CAPABILITIES = Object.freeze(['records', 'coverage']);
export const WRAPPER_CAPABILITIES: Readonly<Record<string, readonly string[]>> = Object.freeze({
    'portal-records': Object.freeze(['records']),
    'portal-coverage': Object.freeze(['coverage']),
    'enforcer-coverage': Object.freeze(['coverage']),
    control: CAPABILITIES,
    recovery: CAPABILITIES,
});
const fields = ['wrap_version', 'algorithm', 'project_id', 'capability', 'data_kid',
    'wrapper_id', 'wrapper_generation', 'nonce', 'wrapped_key'];
export type WrappedKeyCopy = Readonly<{
    wrap_version: number; algorithm: string; project_id: string; capability: string;
    data_kid: string; wrapper_id: string; wrapper_generation: string;
    nonce: string; wrapped_key: string;
}>;
export type Keyring = Readonly<{ keys: readonly WrappedKeyCopy[] }>;
type WrapContext = {
    projectId: string; capability: string; dataKid: Uint8Array;
    wrapperId: string; wrapperGeneration: string; wrappingKey: Uint8Array;
};
type UnwrapContext = {
    expectedProjectId: string; expectedCapability: string;
    wrappingKeys: ReadonlyMap<string, ReadonlyMap<string, Uint8Array>>;
};
type KeyringContext = {
    expectedProjectId: string; allowedCapabilities: ReadonlySet<string>;
    allowedWrappers: ReadonlySet<string>;
    knownGenerations: ReadonlyMap<string, ReadonlySet<string>>;
};
function nonempty(value: string, label: string): string {
    if (typeof value !== 'string' || !value)
        throw new KeyringContextError(`${label} must be a nonempty string`);
    return value;
}
function capability(value: string): string {
    if (!CAPABILITIES.includes(value)) throw new KeyringContextError('unsupported capability');
    return value;
}
function wrapper(value: string): string {
    if (typeof value !== 'string' || !Object.hasOwn(WRAPPER_CAPABILITIES, value))
        throw new KeyringContextError('unsupported wrapper');
    return value;
}
function exactBytes(value: Uint8Array, length: number): Uint8Array<ArrayBuffer> {
    if (!(value instanceof Uint8Array) || value.length !== length)
        throw new KeyringFormatError('invalid key, key ID, or nonce length');
    return copyBytes(value);
}
function closedObject(value: unknown, names: readonly string[]): JsonObject {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        throw new KeyringFormatError('expected a closed object');
    try { canonicalJson(value); }
    catch { throw new KeyringFormatError('invalid JSON data model'); }
    if (Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name)))
        throw new KeyringFormatError('missing or extra fields');
    return value as JsonObject;
}
function validateCopy(input: unknown): WrappedKeyCopy {
    const value = closedObject(input, fields);
    if (value.wrap_version !== WRAP_VERSION || value.algorithm !== WRAPPED_KEY_ALGORITHM)
        throw new KeyringFormatError('unsupported wrapped-key version or algorithm');
    for (const name of fields.filter(name => name !== 'wrap_version'))
        if (typeof value[name] !== 'string') throw new KeyringFormatError('invalid wrapped-key field type');
    const copy = value as WrappedKeyCopy;
    nonempty(copy.project_id, 'project ID');
    capability(copy.capability);
    wrapper(copy.wrapper_id);
    if (!WRAPPER_CAPABILITIES[copy.wrapper_id]!.includes(copy.capability))
        throw new KeyringContextError('capability and wrapper are incompatible');
    nonempty(copy.wrapper_generation, 'wrapper generation');
    try {
        base64urlDecode(copy.data_kid, 16);
        base64urlDecode(copy.nonce, 12);
        base64urlDecode(copy.wrapped_key, 48);
    } catch { throw new KeyringFormatError('invalid wrapped-key encoding or length'); }
    return Object.freeze({ ...copy });
}
function aad(copy: WrappedKeyCopy): Uint8Array<ArrayBuffer> {
    return canonicalJson({ wrap_version: copy.wrap_version, algorithm: copy.algorithm,
        project_id: copy.project_id, capability: copy.capability, data_kid: copy.data_kid,
        wrapper_id: copy.wrapper_id, wrapper_generation: copy.wrapper_generation });
}
export function wrappedKeyAad(copy: WrappedKeyCopy): Uint8Array<ArrayBuffer> {
    return aad(validateCopy(copy));
}
export async function wrapKeyCopy(dataKey: Uint8Array, context: WrapContext): Promise<WrappedKeyCopy> {
    // Snapshot all caller-owned bytes and metadata before the first await.
    const raw = exactBytes(dataKey, 32), wrappingKey = exactBytes(context.wrappingKey, 32);
    const dataKid = exactBytes(context.dataKid, 16);
    nonempty(context.projectId, 'project ID');
    capability(context.capability);
    wrapper(context.wrapperId);
    nonempty(context.wrapperGeneration, 'wrapper generation');
    const copy = validateCopy({ wrap_version: WRAP_VERSION, algorithm: WRAPPED_KEY_ALGORITHM,
        project_id: context.projectId, capability: context.capability,
        data_kid: base64urlEncode(dataKid), wrapper_id: context.wrapperId,
        wrapper_generation: context.wrapperGeneration,
        nonce: base64urlEncode(exactBytes(crypto.getRandomValues(new Uint8Array(12)), 12)),
        wrapped_key: base64urlEncode(new Uint8Array(48)) });
    const key = await crypto.subtle.importKey('raw', wrappingKey, 'AES-GCM', false, ['encrypt']);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM',
        iv: base64urlDecode(copy.nonce, 12), additionalData: aad(copy), tagLength: 128 }, key, raw));
    return validateCopy({ ...copy, wrapped_key: base64urlEncode(encrypted) });
}
export async function unwrapKeyCopy(input: WrappedKeyCopy, context: UnwrapContext): Promise<Uint8Array<ArrayBuffer>> {
    const copy = validateCopy(input);
    const project = nonempty(context.expectedProjectId, 'project ID');
    const expectedCapability = capability(context.expectedCapability);
    if (copy.project_id !== project || copy.capability !== expectedCapability)
        throw new KeyringContextError('wrapped key does not match expected context');
    if (!(context.wrappingKeys instanceof Map)) throw new TypeError('wrappingKeys must be a map');
    if (!context.wrappingKeys.has(copy.wrapper_id)) throw new UnknownWrappingKeyError('unknown wrapping key');
    const generations = context.wrappingKeys.get(copy.wrapper_id);
    if (generations !== undefined && !(generations instanceof Map))
        throw new TypeError('wrappingKeys values must be maps');
    if (!generations?.has(copy.wrapper_generation)) throw new UnknownWrappingKeyError('unknown wrapping key');
    const rawKey = exactBytes(generations.get(copy.wrapper_generation)!, 32);
    const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
    try {
        return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM',
            iv: base64urlDecode(copy.nonce, 12), additionalData: aad(copy), tagLength: 128 },
        key, base64urlDecode(copy.wrapped_key, 48)));
    } catch { throw new KeyringAuthenticationError('wrapped-key authentication failed'); }
}
function compareBytes(left: Uint8Array, right: Uint8Array): number {
    for (let i = 0; i < Math.min(left.length, right.length); i++)
        if (left[i] !== right[i]) return left[i]! - right[i]!;
    return left.length - right.length;
}
function copies(input: Iterable<WrappedKeyCopy>): WrappedKeyCopy[] {
    if (typeof input === 'string' || input == null || typeof input[Symbol.iterator] !== 'function')
        throw new TypeError('keys must be an iterable of wrapped-key copies');
    const values = Array.from(input, validateCopy), identities = new Set<string>();
    for (const copy of values) {
        // Generation is deliberately excluded: one wrapper copy per data key.
        const id = JSON.stringify([copy.capability, copy.data_kid, copy.wrapper_id]);
        if (identities.has(id)) throw new KeyringFormatError('duplicate wrapped-key identity');
        identities.add(id);
    }
    return values;
}
export function encodeKeyring(input: Iterable<WrappedKeyCopy> | Keyring): Uint8Array<ArrayBuffer> {
    const values = copies(input !== null && typeof input === 'object' && 'keys' in input
        && typeof input.keys !== 'function' ? input.keys : input as Iterable<WrappedKeyCopy>);
    values.sort((left, right) => compareBytes(canonicalJson(left), canonicalJson(right)));
    return canonicalJson({ keyring_version: KEYRING_VERSION, keys: values });
}
function explicitSet(input: ReadonlySet<string>, vocabulary: readonly string[], label: string): void {
    if (!(input instanceof Set)) throw new TypeError(`${label} must be an explicit set`);
    for (const value of input)
        if (typeof value !== 'string' || !vocabulary.includes(value))
            throw new KeyringContextError(`${label} contains an unsupported value`);
}
export function decodeKeyring(data: Uint8Array, context: KeyringContext): Keyring {
    nonempty(context.expectedProjectId, 'project ID');
    explicitSet(context.allowedCapabilities, CAPABILITIES, 'allowed capabilities');
    explicitSet(context.allowedWrappers, Object.keys(WRAPPER_CAPABILITIES), 'allowed wrappers');
    if (!(context.knownGenerations instanceof Map)) throw new TypeError('knownGenerations must be a map');
    for (const [id, generations] of context.knownGenerations) {
        wrapper(id);
        if (!(generations instanceof Set)) throw new TypeError('known generations must be explicit sets');
        for (const generation of generations) nonempty(generation, 'wrapper generation');
    }
    if (!(data instanceof Uint8Array)) throw new TypeError('keyring input must be bytes');
    let value: JsonObject;
    try { value = closedObject(parseCanonicalJson(data), ['keyring_version', 'keys']); }
    catch { throw new KeyringFormatError('keyring must be exact canonical JSON bytes'); }
    if (value.keyring_version !== KEYRING_VERSION || !Array.isArray(value.keys))
        throw new KeyringFormatError('invalid keyring version or keys');
    const values = copies(value.keys as unknown as WrappedKeyCopy[]);
    for (let i = 0; i < values.length; i++) {
        const copy = values[i]!;
        if (copy.project_id !== context.expectedProjectId || !context.allowedCapabilities.has(copy.capability)
            || !context.allowedWrappers.has(copy.wrapper_id)
            || !context.knownGenerations.has(copy.wrapper_id)
            || !context.knownGenerations.get(copy.wrapper_id)?.has(copy.wrapper_generation))
            throw new KeyringContextError('wrapped key is outside allowed project, capability, wrapper or generation');
        if (i > 0 && compareBytes(canonicalJson(values[i - 1]!), canonicalJson(copy)) > 0)
            throw new KeyringFormatError('keyring keys are not in canonical order');
    }
    return Object.freeze({ keys: Object.freeze(values) });
}
