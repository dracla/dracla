/** Closed revision-14 artifact identity namespace; no repository I/O. */
import { canonicalJson, MAX_SAFE_INTEGER, validUnicode } from './canonical.js';
import { base64urlDecode, base64urlEncode, copyBytes } from './encoding.js';
export class ArtifactIdentityError extends Error {
    constructor(message: string, options?: ErrorOptions) { super(message, options); this.name = new.target.name; }
}
export interface ArtifactIdentity {
    readonly repository_role: string;
    readonly branch: string;
    readonly path: string;
    readonly artifact_kind: string;
    readonly capability: string;
    readonly schema_version: number;
    readonly logical_id: string;
}
const staticIdentities: ReadonlyArray<readonly [
    string,
    string,
    string,
    string
]> = [
    ['records', 'events', 'config/project.enc.json', 'project-config'],
    ['records', 'events', 'config/materialization-generations.enc.json', 'materialization-generations'],
    ['records', 'operations', 'prepared-operation.enc.json', 'prepared-operation'],
    ['records', 'derived', 'derived/state.enc.json', 'derived-state'],
    ['coverage', 'coverage', 'source.enc.json', 'coverage-source'],
    ['coverage', 'coverage', 'inflight.enc.json', 'inflight'],
    ['coverage', 'coverage', 'decision-fence.enc.json', 'decision-fence'],
    ['coverage', 'coverage', 'agreements/active.enc.json', 'active-agreement'],
    ['coverage', 'coverage', 'exemptions.enc.json', 'exemption-fold'],
];
export function resolveArtifactIdentity(repositoryRole: string, branch: string, path: string): ArtifactIdentity {
    if (!['records', 'coverage'].includes(repositoryRole) || typeof branch !== 'string' || !/^[\x00-\x7f]+$/.test(branch) || typeof path !== 'string' || !/^[\x00-\x7f]+$/.test(path) || /[\r\n]/.test(path) || path.split('/').some(part => ['', '.', '..'].includes(part)))
        throw new ArtifactIdentityError('invalid artifact context or path');
    let kind = staticIdentities.find(row => row[0] === repositoryRole && row[1] === branch && row[2] === path)?.[3];
    const event = /^events\/([A-Za-z0-9_-]{2})\/([A-Za-z0-9_-]{2})\/([A-Za-z0-9_-]{43})\.enc\.json$/.exec(path);
    const shard = /^(derived\/(index|status-detail|reader-authority)|users)\/([0-9]{2})\.enc\.json$/.exec(path);
    const exported = /^derived\/exports\/([A-Za-z0-9_-]{22})\.enc\.(json|csv)$/.exec(path);
    try {
        if (!kind && repositoryRole === 'records' && branch === 'events' && event) {
            base64urlDecode(event[3]!, 32);
            if (event[1] !== event[3]!.slice(0, 2) || event[2] !== event[3]!.slice(2, 4))
                throw new ArtifactIdentityError('event path shards disagree');
            kind = 'canonical-event';
        }
        if (!kind && shard) {
            const coverage = shard[1] === 'users';
            if (Number(shard[3]) > 31 || repositoryRole !== (coverage ? 'coverage' : 'records') || branch !== (coverage ? 'coverage' : 'derived'))
                throw new ArtifactIdentityError('invalid shard context');
            kind = coverage ? 'coverage-shard' : shard[2] === 'index' ? 'derived-index' : shard[2]!;
        }
        if (!kind && repositoryRole === 'records' && branch === 'derived' && exported) {
            base64urlDecode(exported[1]!, 16);
            kind = exported[2] === 'json' ? 'export-json' : 'export-csv';
        }
    }
    catch (error) {
        throw new ArtifactIdentityError('invalid artifact path token', { cause: error });
    }
    if (!kind)
        throw new ArtifactIdentityError('unknown artifact identity');
    return Object.freeze({ repository_role: repositoryRole, branch, path, artifact_kind: kind, capability: repositoryRole, schema_version: 1, logical_id: branch + ':' + path });
}
export async function sha256(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', copyBytes(bytes)));
}
export async function segment(value: string): Promise<string> {
    if (typeof value !== 'string' || !value)
        throw new ArtifactIdentityError('segment must be a nonempty string');
    try {
        validUnicode(value);
    }
    catch (error) {
        throw new ArtifactIdentityError('invalid segment Unicode', { cause: error });
    }
    return base64urlEncode(await sha256(new TextEncoder().encode(value)));
}
export async function overrideKey(value: {
    repository_id: number;
    pull_request_number: number;
    subject_user_id: number;
    tree_oid: string;
}): Promise<string> {
    for (const name of ['repository_id', 'pull_request_number', 'subject_user_id'] as const) {
        if (!Number.isSafeInteger(value[name]) || value[name] <= 0 || value[name] > MAX_SAFE_INTEGER)
            throw new ArtifactIdentityError('invalid override numeric identity');
    }
    if (typeof value.tree_oid !== 'string' || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$(?![\s\S])/.test(value.tree_oid))
        throw new ArtifactIdentityError('invalid tree OID');
    return base64urlEncode(await sha256(canonicalJson({ repository_id: value.repository_id, pull_request_number: value.pull_request_number, subject_user_id: value.subject_user_id, tree_oid: value.tree_oid })));
}
