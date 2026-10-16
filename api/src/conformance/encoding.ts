/** Canonical unpadded RFC 4648 base64url and exact byte inputs. */
export class Base64UrlError extends Error {
    constructor(message: string, options?: ErrorOptions) { super(message, options); this.name = new.target.name; }
}
export function copyBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
    if (!(value instanceof Uint8Array))
        throw new TypeError('input must be bytes');
    return new Uint8Array(value);
}
export function base64urlEncode(value: Uint8Array): string {
    const bytes = copyBytes(value);
    // Chunking avoids argument-count limits for bounded but large ciphertexts.
    let text = '';
    for (let i = 0; i < bytes.length; i += 8192)
        text += String.fromCharCode(...bytes.subarray(i, i + 8192));
    return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
export function base64urlDecode(value: string, expectedLength?: number): Uint8Array<ArrayBuffer> {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value))
        throw new Base64UrlError('invalid base64url string');
    let bytes: Uint8Array<ArrayBuffer>;
    try {
        bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4)), character => character.charCodeAt(0));
    }
    catch (error) {
        throw new Base64UrlError('invalid base64url string', { cause: error });
    }
    if (base64urlEncode(bytes) !== value || (expectedLength !== undefined && bytes.length !== expectedLength))
        throw new Base64UrlError('noncanonical base64url or wrong length');
    return bytes;
}
