/** Exact RFC 8785 bytes in the shared finite safe-number JSON model. */
export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export type JsonObject = {
    [key: string]: JsonValue;
};
export type ReadonlyJsonValue = null | boolean | number | string | readonly ReadonlyJsonValue[] | ReadonlyJsonObject;
export type ReadonlyJsonObject = {
    readonly [key: string]: ReadonlyJsonValue;
};
export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
export class CanonicalJsonError extends Error {
    constructor(message: string, options?: ErrorOptions) { super(message, options); this.name = new.target.name; }
}
export class NonCanonicalJsonError extends CanonicalJsonError {
}
export function validUnicode(value: string): void {
    for (let i = 0; i < value.length; i++) {
        const unit = value.charCodeAt(i);
        if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = value.charCodeAt(++i);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                throw new CanonicalJsonError('unpaired surrogate');
        }
        else if (unit >= 0xdc00 && unit <= 0xdfff) {
            throw new CanonicalJsonError('unpaired surrogate');
        }
    }
}
export function canonicalJson(value: unknown): Uint8Array<ArrayBuffer> {
    const ancestors = new Set<object>();
    function encode(item: unknown): string {
        if (item === null || typeof item === 'boolean')
            return JSON.stringify(item);
        if (typeof item === 'number') {
            if (!Number.isFinite(item) || Math.abs(item) > MAX_SAFE_INTEGER)
                throw new CanonicalJsonError('unsafe number');
            return JSON.stringify(item);
        }
        if (typeof item === 'string') {
            validUnicode(item);
            return JSON.stringify(item);
        }
        if (typeof item !== 'object')
            throw new CanonicalJsonError('unsupported JSON value');
        if (ancestors.has(item))
            throw new CanonicalJsonError('cyclic JSON value');
        ancestors.add(item);
        try {
            if (Array.isArray(item)) {
                if (Object.keys(item).length !== item.length || Object.getOwnPropertyNames(item).length !== item.length + 1 || Object.getOwnPropertySymbols(item).length)
                    throw new CanonicalJsonError('non-JSON array');
                return '[' + Array.from({ length: item.length }, (_, i) => {
                    const descriptor = Object.getOwnPropertyDescriptor(item, String(i));
                    if (!descriptor || !('value' in descriptor))
                        throw new CanonicalJsonError('non-JSON array member');
                    return encode(descriptor.value);
                }).join(',') + ']';
            }
            if (![Object.prototype, null].includes(Object.getPrototypeOf(item)) || Object.keys(item).length !== Object.getOwnPropertyNames(item).length || Object.getOwnPropertySymbols(item).length)
                throw new CanonicalJsonError('non-JSON object');
            // Build bytes directly: inserting sorted integer-like keys into another
            // JavaScript object would let JSON.stringify reorder them numerically.
            return '{' + Object.keys(item).sort().map(key => {
                validUnicode(key);
                const descriptor = Object.getOwnPropertyDescriptor(item, key)!;
                if (!('value' in descriptor))
                    throw new CanonicalJsonError('non-JSON object member');
                return JSON.stringify(key) + ':' + encode(descriptor.value);
            }).join(',') + '}';
        }
        finally {
            ancestors.delete(item);
        }
    }
    try {
        return new TextEncoder().encode(encode(value));
    }
    catch (error) {
        if (error instanceof CanonicalJsonError)
            throw error;
        throw new CanonicalJsonError('invalid JSON data model', { cause: error });
    }
}
export function parseCanonicalJson(data: Uint8Array): JsonValue {
    if (!(data instanceof Uint8Array))
        throw new TypeError('canonical JSON input must be bytes');
    let value: unknown;
    try {
        // Preserve a BOM as a character so it cannot be silently stripped.
        value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data));
    }
    catch (error) {
        throw new CanonicalJsonError('invalid UTF-8 JSON', { cause: error });
    }
    const expected = canonicalJson(value);
    if (expected.length !== data.length || expected.some((byte, i) => byte !== data[i]))
        throw new NonCanonicalJsonError('JSON is not the RFC 8785 encoding');
    return value as JsonValue;
}
export function freezeJson(value: JsonObject): ReadonlyJsonObject;
export function freezeJson(value: JsonValue): ReadonlyJsonValue;
export function freezeJson(value: JsonValue): ReadonlyJsonValue {
    function freeze(item: JsonValue): void {
        if (item !== null && typeof item === 'object') {
            for (const child of Object.values(item))
                freeze(child);
            Object.freeze(item);
        }
    }
    freeze(value);
    return value;
}
