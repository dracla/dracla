/** Explicit, closed finite private-derived limits. No coverage cap or defaults. */
import { canonicalJson, parseCanonicalJson, freezeJson, type JsonObject } from './canonical.js';
export class ReleaseProfileError extends Error {
    constructor(message: string, options?: ErrorOptions) { super(message, options); this.name = new.target.name; }
}
export const DERIVED_CLASSES = ['derived_index', 'status_detail', 'reader_authority'] as const;
export type DerivedClass = typeof DERIVED_CLASSES[number];
export const PROFILE_LIMITS = ['max_prepared_operation_bytes', 'max_reader_source_members', 'max_bulk_shards_per_operation', 'max_mutation_retries', 'max_subrequests_per_request', 'max_continuous_reader_rules', 'max_continuous_exemption_rules', 'max_reader_cursor_entries', 'max_state_ciphertext_bytes'] as const;
export type ProfileLimit = typeof PROFILE_LIMITS[number];
type ProfileValue = Readonly<Record<ProfileLimit, number> & {
    profile_version: 1;
    shard_count: 32;
    max_shard_ciphertext_bytes: Readonly<Record<DerivedClass, number>>;
}>;
export class ReleaseProfile {
    readonly #value: ProfileValue;
    constructor(value: unknown) {
        try {
            const json = parseCanonicalJson(canonicalJson(value));
            if (json === null || typeof json !== 'object' || Array.isArray(json))
                throw new Error('profile object');
            const fields = ['profile_version', 'shard_count', 'max_shard_ciphertext_bytes', ...PROFILE_LIMITS];
            if (Object.keys(json).length !== fields.length || fields.some(key => !Object.hasOwn(json, key)) || json.profile_version !== 1 || json.shard_count !== 32)
                throw new Error('profile fields/version/shards');
            const limits = json.max_shard_ciphertext_bytes;
            if (limits === null || typeof limits !== 'object' || Array.isArray(limits) || Object.keys(limits).length !== 3 || DERIVED_CLASSES.some(key => !Object.hasOwn(limits, key)))
                throw new Error('private class limits');
            for (const count of [...Object.values(limits), ...PROFILE_LIMITS.map(key => json[key])]) {
                if (typeof count !== 'number' || !Number.isSafeInteger(count) || count <= 0)
                    throw new Error('finite positive safe limit required');
            }
            if ((json.max_subrequests_per_request as number) >= 50 || json.max_continuous_reader_rules !== 10)
                throw new Error('fixed v1 limits');
            this.#value = freezeJson(json) as ProfileValue;
        }
        catch (error) {
            throw new ReleaseProfileError('invalid release profile', { cause: error });
        }
        Object.freeze(this);
    }
    toDict(): JsonObject { return parseCanonicalJson(canonicalJson(this.#value)) as JsonObject; }
    canonicalBytes(): Uint8Array<ArrayBuffer> { return canonicalJson(this.#value); }
    limit(name: ProfileLimit | 'max_shard_ciphertext_bytes', derivedClass?: DerivedClass): number {
        if (name === 'max_shard_ciphertext_bytes') {
            if (!DERIVED_CLASSES.includes(derivedClass as DerivedClass))
                throw new ReleaseProfileError('private derived class required');
            return this.#value.max_shard_ciphertext_bytes[derivedClass!];
        }
        if (!PROFILE_LIMITS.includes(name) || derivedClass !== undefined)
            throw new ReleaseProfileError('unknown or misclassified limit');
        return this.#value[name];
    }
    check(name: ProfileLimit | 'max_shard_ciphertext_bytes', actual: number, derivedClass?: DerivedClass): void {
        const maximum = this.limit(name, derivedClass);
        if (!Number.isSafeInteger(actual) || actual < 0 || actual > maximum)
            throw new ReleaseProfileError('profile limit exceeded');
    }
}
export function loadReleaseProfile(bytes: Uint8Array): ReleaseProfile {
    try {
        return new ReleaseProfile(parseCanonicalJson(bytes));
    }
    catch (error) {
        throw new ReleaseProfileError('profile must be closed canonical JSON', { cause: error });
    }
}
