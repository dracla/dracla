/** Authenticated path-bound A256GCM artifacts, using native Web Crypto. */
import { canonicalJson, parseCanonicalJson, type JsonObject, type JsonValue } from './canonical.js';
import { resolveArtifactIdentity, type ArtifactIdentity } from './artifacts.js';
import { base64urlDecode, base64urlEncode, copyBytes } from './encoding.js';
export class ArtifactEnvelopeError extends Error {
    constructor(message: string, options?: ErrorOptions) { super(message, options); this.name = new.target.name; }
}
export class ArtifactEnvelopeFormatError extends ArtifactEnvelopeError {
}
export class ArtifactEnvelopeContextError extends ArtifactEnvelopeError {
}
export class UnknownArtifactKeyError extends ArtifactEnvelopeError {
}
export class ArtifactAuthenticationError extends ArtifactEnvelopeError {
}
export const TAG_BYTES = 16;
const fields = ['envelope_version', 'algorithm', 'project_id', 'artifact_kind', 'logical_id', 'schema_version', 'kid', 'nonce', 'ciphertext'];
const aadFields = fields.filter(name => !['nonce', 'ciphertext'].includes(name));
type EncryptionContext = {
    projectId: string;
    identity: ArtifactIdentity;
    kid: Uint8Array;
    key: Uint8Array;
};
type DecryptionContext = {
    expectedProjectId: string;
    expectedIdentity: ArtifactIdentity;
    keys: ReadonlyMap<string, Uint8Array>;
};
function identity(value: ArtifactIdentity): ArtifactIdentity {
    try {
        const resolved = resolveArtifactIdentity(value.repository_role, value.branch, value.path);
        if (Object.keys(resolved).some(name => resolved[name as keyof ArtifactIdentity] !== value[name as keyof ArtifactIdentity]))
            throw new Error('identity mismatch');
        return resolved;
    }
    catch (error) {
        throw new ArtifactEnvelopeContextError('identity disagrees with path', { cause: error });
    }
}
function projectId(value: string): string {
    if (typeof value !== 'string' || !value)
        throw new ArtifactEnvelopeContextError('project ID must be nonempty');
    return value;
}
function exactBytes(value: Uint8Array, length: number): Uint8Array<ArrayBuffer> {
    if (!(value instanceof Uint8Array) || value.length !== length)
        throw new ArtifactEnvelopeFormatError('invalid byte length');
    return copyBytes(value);
}
function metadata(project: string, artifact: ArtifactIdentity, kid: string): JsonObject {
    return { envelope_version: 1, algorithm: 'A256GCM', project_id: projectId(project), artifact_kind: artifact.artifact_kind, logical_id: artifact.logical_id, schema_version: artifact.schema_version, kid };
}
export function artifactAad(context: Omit<EncryptionContext, 'key'>): Uint8Array<ArrayBuffer> {
    return canonicalJson(metadata(context.projectId, identity(context.identity), base64urlEncode(exactBytes(context.kid, 16))));
}
function validateCsv(text: string): void {
    let mode = 'field-start', first = false;
    const formula = '=+-@\t\r\n';
    for (let i = 0; i < text.length;) {
        const character = text[i]!;
        if (mode === 'field-start') {
            if (character === '"') {
                mode = 'quoted';
                first = true;
                i++;
            }
            else if (character === ',')
                i++;
            else if ('\r\n'.includes(character))
                i += character === '\r' && text.slice(i, i + 2) === '\r\n' ? 2 : 1;
            else {
                if (formula.includes(character))
                    throw new ArtifactEnvelopeFormatError('CSV cell is not formula-neutralized');
                mode = 'unquoted';
                i++;
            }
        }
        else if (mode === 'quoted') {
            if (character === '"') {
                if (text.slice(i, i + 2) === '""') {
                    first = false;
                    i += 2;
                }
                else {
                    mode = 'after-quote';
                    i++;
                }
            }
            else {
                if (first && formula.includes(character))
                    throw new ArtifactEnvelopeFormatError('CSV cell is not formula-neutralized');
                first = false;
                i++;
            }
        }
        else if (character === ',') {
            mode = 'field-start';
            i++;
        }
        else if ('\r\n'.includes(character)) {
            mode = 'field-start';
            i += character === '\r' && text.slice(i, i + 2) === '\r\n' ? 2 : 1;
        }
        else if (mode === 'after-quote' || character === '"') {
            throw new ArtifactEnvelopeFormatError('invalid CSV structure');
        }
        else
            i++;
    }
    if (mode === 'quoted')
        throw new ArtifactEnvelopeFormatError('unterminated CSV field');
}
function plaintext(value: Uint8Array, artifact: ArtifactIdentity): void {
    try {
        if (artifact.artifact_kind === 'export-csv') {
            if (value[0] === 0xef && value[1] === 0xbb && value[2] === 0xbf)
                throw new Error('CSV BOM');
            validateCsv(new TextDecoder('utf-8', { fatal: true }).decode(value));
        }
        else
            parseCanonicalJson(value);
    }
    catch (error) {
        throw new ArtifactEnvelopeFormatError('invalid artifact plaintext', { cause: error });
    }
}
export async function encryptArtifact(value: Uint8Array, context: EncryptionContext): Promise<Uint8Array<ArrayBuffer>> {
    const artifact = identity(context.identity);
    const meta = metadata(context.projectId, artifact, base64urlEncode(exactBytes(context.kid, 16)));
    const rawKey = exactBytes(context.key, 32);
    const raw = copyBytes(value);
    plaintext(raw, artifact);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: canonicalJson(meta), tagLength: 128 }, key, raw));
    return canonicalJson({ ...meta, nonce: base64urlEncode(nonce), ciphertext: base64urlEncode(ciphertext) });
}
export async function encryptJsonArtifact(value: unknown, context: EncryptionContext): Promise<Uint8Array<ArrayBuffer>> {
    if (identity(context.identity).artifact_kind === 'export-csv')
        throw new ArtifactEnvelopeContextError('CSV requires byte plaintext');
    return encryptArtifact(canonicalJson(value), context);
}
export async function decryptArtifact(data: Uint8Array, context: DecryptionContext): Promise<Uint8Array<ArrayBuffer>> {
    const artifact = identity(context.expectedIdentity), project = projectId(context.expectedProjectId);
    let value: JsonObject;
    try {
        const parsed = parseCanonicalJson(data);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed) || Object.keys(parsed).length !== fields.length || fields.some(name => !Object.hasOwn(parsed, name)))
            throw new Error('envelope fields');
        value = parsed;
        for (const name of fields) {
            if (typeof value[name] !== (['envelope_version', 'schema_version'].includes(name) ? 'number' : 'string'))
                throw new Error('envelope types');
        }
        if (value.envelope_version !== 1 || value.algorithm !== 'A256GCM')
            throw new Error('envelope version/algorithm');
    }
    catch (error) {
        throw new ArtifactEnvelopeFormatError('invalid canonical envelope', { cause: error });
    }
    const meta = metadata(project, artifact, value.kid as string);
    if (aadFields.some(name => value[name] !== meta[name]))
        throw new ArtifactEnvelopeContextError('artifact context mismatch');
    let nonce: Uint8Array<ArrayBuffer>, ciphertext: Uint8Array<ArrayBuffer>;
    try {
        base64urlDecode(value.kid as string, 16);
        nonce = base64urlDecode(value.nonce as string, 12);
        ciphertext = base64urlDecode(value.ciphertext as string);
        if (ciphertext.length < TAG_BYTES)
            throw new Error('missing tag');
    }
    catch (error) {
        throw new ArtifactEnvelopeFormatError('invalid envelope byte fields', { cause: error });
    }
    const rawKey = context.keys.get(value.kid as string);
    if (rawKey === undefined)
        throw new UnknownArtifactKeyError('unknown artifact key');
    const key = await crypto.subtle.importKey('raw', exactBytes(rawKey, 32), 'AES-GCM', false, ['decrypt']);
    let result: Uint8Array<ArrayBuffer>;
    try {
        result = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: canonicalJson(meta), tagLength: 128 }, key, ciphertext));
    }
    catch (error) {
        throw new ArtifactAuthenticationError('artifact authentication failed', { cause: error });
    }
    plaintext(result, artifact);
    return result;
}
export async function decryptJsonArtifact(data: Uint8Array, context: DecryptionContext): Promise<JsonValue> {
    if (identity(context.expectedIdentity).artifact_kind === 'export-csv')
        throw new ArtifactEnvelopeContextError('CSV is not a JSON artifact');
    return parseCanonicalJson(await decryptArtifact(data, context));
}
