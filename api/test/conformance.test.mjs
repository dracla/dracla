/** Shared checked-in corpus is the cross-runtime oracle. No Python process. */
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { createHash, createHmac } from 'node:crypto';
import test from 'node:test';
import * as canonical from '../.conformance-build/conformance/canonical.js';
import * as encoding from '../.conformance-build/conformance/encoding.js';
import * as artifacts from '../.conformance-build/conformance/artifacts.js';
import * as envelope from '../.conformance-build/conformance/envelope.js';
import * as limits from '../.conformance-build/conformance/releaseProfile.js';
import * as projections from '../.conformance-build/conformance/projections.js';
import * as keyrings from '../.conformance-build/conformance/keyrings.js';
import * as events from '../.conformance-build/conformance/events.js';
import * as actionForms from '../.conformance-build/conformance/actionForms.js';
import * as operationState from '../.conformance-build/conformance/operations.js';

const vectorDirectory = new URL('../../conformance/vectors/', import.meta.url);
const vector = async name => JSON.parse(await readFile(new URL(name, vectorDirectory), 'utf8'));
const [manifest, identities, encrypted, coverage, derived, operations, transitions] = await Promise.all([
  'manifest.json', 'artifact-identities-v1.json', 'artifact-envelope-v1.json',
  'coverage-v1.json', 'derived-v1.json', 'operation-state-v1.json', 'incremental-v1.json',
].map(vector));
const bytes = text => new TextEncoder().encode(text);
const hex = value => Buffer.from(value).toString('hex');
const unhex = value => new Uint8Array(Buffer.from(Array.isArray(value) ? value.join('') : value, 'hex'));
const wire = canonical.canonicalJson;
const parse = canonical.parseCanonicalJson;
const identity = path => artifacts.resolveArtifactIdentity(path.startsWith('derived/') ? 'records' : 'coverage', path.startsWith('derived/') ? 'derived' : 'coverage', path);
const assembled = parse(unhex(derived.wire_goldens.assembled_state.bytes_hex));
const projectionGoldenInventory = Object.freeze({
  pre_agreement_exemption: Object.freeze({
    exempted: Object.freeze(['derived/index/07.enc.json', 'derived/status-detail/07.enc.json']),
    withdrawn: Object.freeze(['derived/index/07.enc.json', 'derived/status-detail/07.enc.json']),
  }),
  canonical_signature: Object.freeze({
    accepted: Object.freeze(['derived/index/07.enc.json', 'derived/status-detail/07.enc.json']),
    revoked: Object.freeze(['derived/index/07.enc.json', 'derived/status-detail/07.enc.json']),
  }),
  canonical_recorded_exemption: Object.freeze({
    stage: Object.freeze(['derived/index/07.enc.json', 'derived/status-detail/07.enc.json']),
  }),
  canonical_readers: Object.freeze({
    files: Object.freeze(['derived/reader-authority/01.enc.json', 'derived/reader-authority/03.enc.json', 'derived/reader-authority/21.enc.json']),
  }),
});
const allWireGoldenNames = Object.freeze([
  'assembled_state', 'canonical_assembled_state', 'canonical_readers', 'canonical_recorded_exemption',
  'canonical_signature', 'exemption_source_rows', 'pre_agreement_exemption', 'reader_authority', 'status_rows',
]);
const consumedProjectionGoldenGroups = new Set();
const consumedProjectionGoldenFixtures = new Set();
// This explicit test profile uses corpus limits; it selects no release default.
const profileValue = {
  ...Object.fromEntries(limits.PROFILE_LIMITS.map(name => [name, operations.profile.max_prepared_operation_bytes])),
  ...assembled.profile, profile_version: 1, shard_count: assembled.shard_count,
  max_subrequests_per_request: 49,
};
const profile = new limits.ReleaseProfile(profileValue);
const project = encrypted.project_id;
const cryptoIdentity = artifacts.resolveArtifactIdentity(encrypted.repository_role, encrypted.branch, encrypted.path);
const kid = unhex(encrypted.kid_hex), key = unhex(encrypted.key_hex);
const encryption = { projectId: project, identity: cryptoIdentity, kid, key };
const decryption = { expectedProjectId: project, expectedIdentity: cryptoIdentity, keys: new Map([[encoding.base64urlEncode(kid), key]]) };

test('complete shared manifest and file registry match independently hashed bytes', async () => {
  assert.deepEqual((await readdir(vectorDirectory)).sort(), [...Object.keys(manifest.files), 'manifest.json'].sort());
  for (const [name, row] of Object.entries(manifest.files)) {
    assert.equal('sha256:' + createHash('sha256').update(await readFile(new URL(name, vectorDirectory))).digest('hex'), row.sha256, name);
    assert.equal(row.contract_version, 1);
    assert.ok(row.authoring_slices.length && row.cases.length);
    assert.equal(new Set(row.cases).size, row.cases.length);
  }
});

test('RFC8785 goldens, UTF16 keys, safe numbers and exact canonical rejection', () => {
  assert.equal(new TextDecoder().decode(wire(parse(bytes(encrypted.aad_utf8)))), encrypted.aad_utf8);
  assert.equal(new TextDecoder().decode(wire({ '2': 2, '10': 10, '\ue000': 1, '😀': 2, a: -0 })), '{"10":10,"2":2,"a":0,"😀":2,"\ue000":1}');
  assert.equal(new TextDecoder().decode(wire([1e-7, 1e-6, Number.MAX_SAFE_INTEGER, '\u0000\n"\\'])), '[1e-7,0.000001,9007199254740991,"\\u0000\\n\\"\\\\"]');
  for (const value of [NaN, Infinity, -Infinity, 2 ** 53, -(2 ** 53), undefined, 1n, () => {}, Symbol(), new Date(), new Map(), '\ud800', '\udc00', { '\ud800': 1 }, [,], Object.defineProperty({}, 'x', { get() { throw Error('getter must not run'); }, enumerable: true }), Object.defineProperty({}, 'hidden', { value: 1 }), Object.assign([], { extra: 1 }), Object.assign({}, { [Symbol()]: 1 })]) {
    assert.throws(() => wire(value), canonical.CanonicalJsonError);
  }
  const cyclic = {}; cyclic.self = cyclic;
  assert.throws(() => wire(cyclic), canonical.CanonicalJsonError);
  const accessorArray = Object.defineProperty([], '0', { get() { throw Error('array getter must not run'); }, enumerable: true });
  assert.throws(() => wire(accessorArray), canonical.CanonicalJsonError);
  let deep = null;
  for (let i = 0; i < 20000; i++) deep = [deep];
  assert.throws(() => wire(deep), canonical.CanonicalJsonError);
  assert.equal(hex(wire([{}, {}])), hex(bytes('[{},{}]')));
  assert.equal(hex(wire(Object.assign(Object.create(null), { x: 1 }))), hex(bytes('{"x":1}')));
  for (const text of [' {"x":1}', '{"x":1,"x":2}', '{"x":1,"x":1}', '{"x":1.0}', '-0', '1e0', '"\\u0061"', '9007199254740992', 'NaN', '\ufeff{}', '"\\ud800"']) assert.throws(() => parse(bytes(text)), canonical.CanonicalJsonError, text);
  assert.throws(() => parse(new Uint8Array([0xff])), canonical.CanonicalJsonError);
  assert.throws(() => parse('{}'), TypeError);
  assert.equal(new canonical.NonCanonicalJsonError('test').name, 'NonCanonicalJsonError');
});

test('base64url is unique, unpadded and length-bound for empty and large bytes', () => {
  for (const data of [new Uint8Array(), new Uint8Array([0xff]), new Uint8Array([0xff, 0xfe]), key, new Uint8Array(20000).fill(255)]) {
    const expected = Buffer.from(data).toString('base64url');
    assert.equal(encoding.base64urlEncode(data), expected);
    assert.equal(hex(encoding.base64urlDecode(expected, data.length)), hex(data));
  }
  for (const bad of ['=', 'A', '_x', '__9', 'AA=', 'AA\n', ' AA', '++//', 7, null]) assert.throws(() => encoding.base64urlDecode(bad), encoding.Base64UrlError);
  assert.throws(() => encoding.base64urlDecode('AA', 2), encoding.Base64UrlError);
  assert.throws(() => encoding.base64urlEncode('AA'), TypeError);
});

test('every artifact identity, segment and override golden matches the common corpus', async () => {
  for (const row of identities.identities) {
    const result = artifacts.resolveArtifactIdentity(...row.slice(0, 3));
    assert.equal(result.artifact_kind, row[3]); assert.equal(result.capability, row[4]);
    assert.equal(result.schema_version, 1); assert.equal(result.logical_id, row[1] + ':' + row[2]);
    assert.ok(Object.isFrozen(result));
    for (const bad of [row[2] + '\n', '/' + row[2], './' + row[2], row[2].replace('/', '//'), row[2] + '/', row[2].replace('.enc.', '.ENC.')].filter(value => value !== row[2])) assert.throws(() => artifacts.resolveArtifactIdentity(row[0], row[1], bad), artifacts.ArtifactIdentityError);
  }
  for (const row of identities.segments) assert.equal(await artifacts.segment(row.value), row.token);
  const eventPath = identities.identities.find(row => row[3] === 'canonical-event')[2];
  const wrongPrefix = eventPath.slice(7, 9) === 'AA' ? 'BB' : 'AA';
  assert.throws(() => artifacts.resolveArtifactIdentity('records', 'events', 'events/' + wrongPrefix + eventPath.slice(9)), artifacts.ArtifactIdentityError);
  const { key: expected, ...input } = identities.override_key;
  assert.equal(await artifacts.overrideKey(input), expected);
  for (const field of ['repository_id', 'pull_request_number', 'subject_user_id']) for (const bad of [0, -1, true, 1.5, 2 ** 53]) await assert.rejects(artifacts.overrideKey({ ...input, [field]: bad }), artifacts.ArtifactIdentityError);
  for (const tree_oid of ['a'.repeat(39), 'A'.repeat(40), 'a'.repeat(40) + '\n']) await assert.rejects(artifacts.overrideKey({ ...input, tree_oid }), artifacts.ArtifactIdentityError);
  for (const bad of ['', '\ud800', 1]) await assert.rejects(artifacts.segment(bad), artifacts.ArtifactIdentityError);
  for (const args of [['other', 'coverage', 'source.enc.json'], ['coverage', '', 'source.enc.json'], ['records', 'derived', 'derived/index/32.enc.json'], ['coverage', 'derived', 'derived/index/00.enc.json'], ['records', 'events', 'events/AA/AA/' + 'B'.repeat(43) + '.enc.json'], ['records', 'derived', 'derived/exports/' + 'B'.repeat(22) + '.enc.csv']]) assert.throws(() => artifacts.resolveArtifactIdentity(...args), artifacts.ArtifactIdentityError);
});

test('AAD and encrypted bytes match the Python golden under a test-only nonce mock', async t => {
  assert.equal(new TextDecoder().decode(envelope.artifactAad(encryption)), encrypted.aad_utf8);
  t.mock.method(crypto, 'getRandomValues', array => { array.set(unhex(encrypted.nonce_hex)); return array; });
  const actual = await envelope.encryptArtifact(bytes(encrypted.plaintext_utf8), encryption);
  assert.equal(new TextDecoder().decode(actual), encrypted.envelope_utf8);
  assert.equal(new TextDecoder().decode(await envelope.decryptArtifact(actual, decryption)), encrypted.plaintext_utf8);
  assert.deepEqual(await envelope.decryptJsonArtifact(actual, decryption), JSON.parse(encrypted.plaintext_utf8));
  assert.equal(hex(await envelope.encryptJsonArtifact(JSON.parse(encrypted.plaintext_utf8), encryption)), hex(actual));
});

test('production nonce is fresh and every envelope binding rejects its mutation', async () => {
  const first = await envelope.encryptArtifact(bytes(encrypted.plaintext_utf8), encryption);
  const second = await envelope.encryptArtifact(bytes(encrypted.plaintext_utf8), encryption);
  assert.notEqual(parse(first).nonce, parse(second).nonce);
  const original = JSON.parse(encrypted.envelope_utf8);
  for (const field of Object.keys(original)) {
    const missing = { ...original }; delete missing[field];
    await assert.rejects(envelope.decryptArtifact(wire(missing), decryption), envelope.ArtifactEnvelopeFormatError);
    await assert.rejects(envelope.decryptArtifact(wire({ ...original, [field]: [] }), decryption), envelope.ArtifactEnvelopeFormatError);
  }
  for (const mutation of [{ extra: 1 }, { algorithm: 'A128GCM' }, { envelope_version: 2 }]) await assert.rejects(envelope.decryptArtifact(wire({ ...original, ...mutation }), decryption), envelope.ArtifactEnvelopeFormatError);
  for (const mutation of [{ project_id: project + '-other' }, { logical_id: 'events:other' }, { artifact_kind: 'canonical-event' }, { schema_version: 2 }]) await assert.rejects(envelope.decryptArtifact(wire({ ...original, ...mutation }), decryption), envelope.ArtifactEnvelopeContextError);
  for (const field of ['kid', 'nonce', 'ciphertext']) await assert.rejects(envelope.decryptArtifact(wire({ ...original, [field]: original[field] + '=' }), decryption), envelope.ArtifactEnvelopeFormatError);
  await assert.rejects(envelope.decryptArtifact(wire({ ...original, ciphertext: 'AA' }), decryption), envelope.ArtifactEnvelopeFormatError);
  await assert.rejects(envelope.decryptArtifact(bytes(encrypted.envelope_utf8 + '\n'), decryption), envelope.ArtifactEnvelopeFormatError);
  await assert.rejects(envelope.decryptArtifact(bytes(encrypted.envelope_utf8), { ...decryption, keys: new Map() }), envelope.UnknownArtifactKeyError);
  await assert.rejects(envelope.decryptArtifact(bytes(encrypted.envelope_utf8), { ...decryption, keys: new Map([[original.kid, new Uint8Array(31)]]) }), envelope.ArtifactEnvelopeFormatError);
  for (const field of ['nonce', 'ciphertext']) {
    const raw = encoding.base64urlDecode(original[field]); raw[0] ^= 1;
    await assert.rejects(envelope.decryptArtifact(wire({ ...original, [field]: encoding.base64urlEncode(raw) }), decryption), envelope.ArtifactAuthenticationError);
  }
  await assert.rejects(envelope.decryptArtifact(wire({ ...original, project_id: 'other' }), { ...decryption, expectedProjectId: 'other' }), envelope.ArtifactAuthenticationError);
  await assert.rejects(envelope.encryptArtifact(bytes('{}'), { ...encryption, projectId: '' }), envelope.ArtifactEnvelopeContextError);
  await assert.rejects(envelope.encryptArtifact(bytes('{}'), { ...encryption, kid: new Uint8Array(1) }), envelope.ArtifactEnvelopeFormatError);
  await assert.rejects(envelope.encryptArtifact(bytes('{}'), { ...encryption, key: new Uint8Array(1) }), envelope.ArtifactEnvelopeFormatError);
  await assert.rejects(envelope.encryptArtifact(bytes('{} '), encryption), envelope.ArtifactEnvelopeFormatError);
  await assert.rejects(envelope.encryptArtifact(bytes('{}'), { ...encryption, identity: { ...cryptoIdentity, capability: 'coverage' } }), envelope.ArtifactEnvelopeContextError);
});

test('CSV has exact UTF8 framing and formula-neutralization without a payload schema', async () => {
  const csvIdentity = identities.identities.find(row => row[3] === 'export-csv');
  const id = artifacts.resolveArtifactIdentity(...csvIdentity.slice(0, 3));
  for (const text of ['', ',,\r\n\n\r', "'=neutralized,safe\r\n", '"quoted""cell",safe\n', '"multi\nline",end']) {
    const ciphertext = await envelope.encryptArtifact(bytes(text), { ...encryption, identity: id });
    assert.equal(hex(await envelope.decryptArtifact(ciphertext, { ...decryption, expectedIdentity: id })), hex(bytes(text)));
  }
  for (const text of ['=formula', '"+formula"', 'a"bad', '"unterminated', '"done"tail', '\ufeffhello', '"\nformula"']) await assert.rejects(envelope.encryptArtifact(bytes(text), { ...encryption, identity: id }), envelope.ArtifactEnvelopeFormatError);
  await assert.rejects(envelope.encryptArtifact(new Uint8Array([255]), { ...encryption, identity: id }), envelope.ArtifactEnvelopeFormatError);
  await assert.rejects(envelope.encryptJsonArtifact({}, { ...encryption, identity: id }), envelope.ArtifactEnvelopeContextError);
  await assert.rejects(envelope.decryptJsonArtifact(bytes('{}'), { ...decryption, expectedIdentity: id }), envelope.ArtifactEnvelopeContextError);
});

test('release profile is closed, finite, immutable, class-specific and has no coverage cap', () => {
  for (const value of [null, [], 'profile', true]) assert.throws(() => new limits.ReleaseProfile(value), limits.ReleaseProfileError);
  assert.deepEqual(limits.loadReleaseProfile(wire(profileValue)).toDict(), profileValue);
  assert.equal(hex(profile.canonicalBytes()), hex(wire(profileValue)));
  const copy = profile.toDict(); copy.max_reader_source_members = 1;
  assert.equal(profile.limit('max_reader_source_members'), profileValue.max_reader_source_members);
  for (const name of limits.PROFILE_LIMITS) {
    profile.check(name, 0); profile.check(name, profile.limit(name));
    for (const bad of [-1, true, 0.5, profile.limit(name) + 1]) assert.throws(() => profile.check(name, bad), limits.ReleaseProfileError);
  }
  for (const name of limits.DERIVED_CLASSES) profile.check('max_shard_ciphertext_bytes', profile.limit('max_shard_ciphertext_bytes', name), name);
  for (const name of Object.keys(profileValue)) {
    const missing = structuredClone(profileValue); delete missing[name];
    assert.throws(() => new limits.ReleaseProfile(missing), limits.ReleaseProfileError);
    assert.throws(() => new limits.ReleaseProfile({ ...profileValue, [name]: [] }), limits.ReleaseProfileError);
  }
  for (const mutation of [{ extra: 1 }, { profile_version: true }, { shard_count: 31 }, { max_continuous_reader_rules: 9 }, { max_subrequests_per_request: 50 }, { max_reader_source_members: 0 }, { max_reader_source_members: Infinity }, { max_reader_source_members: 2 ** 53 }, { max_shard_ciphertext_bytes: { coverage: 1 } }]) assert.throws(() => new limits.ReleaseProfile({ ...profileValue, ...mutation }), limits.ReleaseProfileError);
  assert.throws(() => profile.limit('coverage'), limits.ReleaseProfileError);
  assert.throws(() => profile.limit('max_shard_ciphertext_bytes'), limits.ReleaseProfileError);
  assert.throws(() => profile.limit('max_reader_source_members', 'derived_index'), limits.ReleaseProfileError);
  assert.throws(() => limits.loadReleaseProfile(bytes('{} ')), limits.ReleaseProfileError);
});

const samples = [];
const seen = new Set();
async function accept(path, value, standingRules = {}) {
  const raw = wire(value), id = identity(path);
  const cache = path + ':' + hex(raw) + ':' + hex(wire(standingRules));
  if (seen.has(cache)) return;
  seen.add(cache);
  const result = await projections.decodeProjection(id, raw, { profile, standingRules });
  assert.equal(hex(wire(result)), hex(raw), path);
  assert.ok(Object.isFrozen(result));
  samples.push({ path, value, standingRules });
}

let preparedSamples;
function prepareSamples() { return preparedSamples ??= (async () => {
  assert.deepEqual(Object.keys(derived.wire_goldens).sort(), allWireGoldenNames, 'wire golden group inventory changed');
  for (const [path, value] of Object.entries(coverage.empty_files)) await accept(path, value);
  await accept('agreements/active.enc.json', coverage.active);
  for (const [path, value] of Object.entries(derived.empty_shards)) await accept(path, value);
  for (const value of Object.values(operations.fences)) await accept('decision-fence.enc.json', value);
  for (const value of Object.values(operations.markers)) await accept('inflight.enc.json', value);
  for (const row of derived.wire_goldens.status_rows) {
    await accept('derived/status-detail/07.enc.json', parse(unhex(row.status_detail_bytes_hex)));
    await accept('derived/index/07.enc.json', parse(unhex(row.index_bytes_hex)));
  }
  for (const row of derived.wire_goldens.reader_authority) await accept(row.path, parse(unhex(row.bytes_hex)));
  for (const row of derived.wire_goldens.exemption_source_rows) {
    const detail = parse(unhex(row.status_detail_bytes_hex));
    const rules = {};
    for (const subject of Object.values(detail)) for (const [id, source] of Object.entries(subject.exemption_sources)) {
      if (source.source_kind === 'continuous_team') rules[id] = { team: source.team, basis: source.basis, instrument_ref: source.instrument_ref };
    }
    await accept('derived/status-detail/07.enc.json', detail, rules);
    await accept('derived/index/07.enc.json', parse(unhex(row.index_bytes_hex)));
  }
  for (const [name, stages] of Object.entries({
    pre_agreement_exemption: derived.wire_goldens.pre_agreement_exemption.stages,
    canonical_signature: derived.wire_goldens.canonical_signature.stages,
  })) {
    consumedProjectionGoldenGroups.add(name);
    assert.deepEqual(Object.keys(stages).sort(), Object.keys(projectionGoldenInventory[name]).sort(), `${name} stage inventory changed`);
    for (const [stage, files] of Object.entries(stages)) {
      assert.deepEqual(Object.keys(files).sort(), projectionGoldenInventory[name][stage], `${name}/${stage} file inventory changed`);
      for (const [path, chunks] of Object.entries(files)) {
        await accept(path, parse(unhex(chunks)));
        consumedProjectionGoldenFixtures.add(`${name}/${stage}/${path}`);
      }
    }
  }
  consumedProjectionGoldenGroups.add('canonical_recorded_exemption');
  assert.deepEqual(Object.keys(derived.wire_goldens.canonical_recorded_exemption.stage).sort(), projectionGoldenInventory.canonical_recorded_exemption.stage, 'canonical_recorded_exemption file inventory changed');
  for (const [path, chunks] of Object.entries(derived.wire_goldens.canonical_recorded_exemption.stage)) {
    await accept(path, parse(unhex(chunks)));
    consumedProjectionGoldenFixtures.add(`canonical_recorded_exemption/stage/${path}`);
  }
  consumedProjectionGoldenGroups.add('canonical_readers');
  assert.deepEqual(Object.keys(derived.wire_goldens.canonical_readers.files).sort(), projectionGoldenInventory.canonical_readers.files, 'canonical_readers file inventory changed');
  for (const [path, chunks] of Object.entries(derived.wire_goldens.canonical_readers.files)) {
    await accept(path, parse(unhex(chunks)));
    consumedProjectionGoldenFixtures.add(`canonical_readers/files/${path}`);
  }
  for (const name of ['assembled_state', 'canonical_assembled_state']) await accept('derived/state.enc.json', parse(unhex(derived.wire_goldens[name].bytes_hex)));
  for (const collection of ['cases', 'operational_cases']) for (const row of transitions[collection]) {
    for (const side of ['before', 'after']) {
      for (const [path, value] of Object.entries(row[side].coverage)) await accept(path, value);
      for (const [path, value] of Object.entries(row[side].derived.files)) await accept(path, value, row[side].derived.standing_rules);
      if (row.publication) await accept('derived/state.enc.json', parse(new Uint8Array(Buffer.from(row.publication[side].state_bytes_b64, 'base64url'))));
    }
  }
  for (const row of transitions.read_cases) {
    for (const [path, value] of Object.entries(row.coverage)) await accept(path, value);
    const path = `derived/status-detail/${String(row.subject % 32).padStart(2, '0')}.enc.json`;
    await accept(path, { [String(row.subject)]: row.row });
    for (const [path, value] of row.operation_state.map((value, i) => [i ? 'decision-fence.enc.json' : 'inflight.enc.json', value])) await accept(path, value);
  }
  for (const row of transitions.publication_cases) {
    for (const side of ['before', 'after']) for (const [path, value] of Object.entries(row[side].coverage)) await accept(path, value);
    for (const name of ['stale_private', 'repair']) if (row[name]) {
      const publication = row[name];
      await accept('derived/state.enc.json', parse(new Uint8Array(Buffer.from(publication.state_bytes_b64, 'base64url'))));
      for (const [path, value] of Object.entries(publication.plaintext.files)) await accept(path, value, publication.plaintext.standing_rules);
    }
  }
  assert.deepEqual([...consumedProjectionGoldenGroups].sort(), Object.keys(projectionGoldenInventory).sort(), 'projection golden group consumption incomplete');
  const expectedProjectionGoldenFixtures = Object.entries(projectionGoldenInventory).flatMap(([name, stages]) => Object.entries(stages).flatMap(([stage, paths]) => paths.map(path => `${name}/${stage}/${path}`))).sort();
  assert.deepEqual([...consumedProjectionGoldenFixtures].sort(), expectedProjectionGoldenFixtures, 'projection golden fixture consumption incomplete');
  assert.equal(new Set(samples.map(row => identity(row.path).artifact_kind)).size, 10);
  assert.ok(samples.length > 100);
})(); }

test('every applicable plaintext and full-reference corpus case decodes unchanged', prepareSamples);

test('every closed plaintext model rejects unknown, missing and mistyped members', async () => {
  await prepareSamples();
  assert.ok(samples.length);
  const tested = new Set();
  const discriminators = new Set(['canonical_sha', 'active_version', 'active', 'decision', 'repository_id', 'ops', 'generation', 'operation_sha256', 'accepted_at', 'login_snapshot', 'source_kind', 'kind', 'organization_id', 'added_event_id', 'state_version', 'derived_index', 'max_shard_ciphertext_bytes']);
  for (const sample of samples) {
    const pending = [{ value: sample.value, path: [] }];
    while (pending.length) {
      const node = pending.pop();
      if (node.value === null || typeof node.value !== 'object' || Array.isArray(node.value)) continue;
      for (const [key, child] of Object.entries(node.value)) pending.push({ value: child, path: [...node.path, key] });
      const keys = Object.keys(node.value);
      if (!keys.some(key => discriminators.has(key))) continue;
      const variant = keys.sort().join(',') + ':' + ['kind', 'state', 'source_kind'].map(key => node.value[key] ?? '').join(':') + ':' + keys.filter(key => node.value[key] === null).join(',');
      if (tested.has(variant)) continue;
      tested.add(variant);
      for (const [field, action] of [['unknown', 'extra'], ...keys.flatMap(key => [[key, 'delete'], [key, 'type']])]) {
        const changed = structuredClone(sample.value);
        let target = changed;
        for (const key of node.path) target = target[key];
        if (action === 'extra') target.unexpected = null;
        else if (action === 'delete') delete target[field];
        else target[field] = Array.isArray(target[field]) ? {} : [];
        await assert.rejects(projections.decodeProjection(identity(sample.path), wire(changed), { profile, standingRules: sample.standingRules }), projections.ProjectionError, `${variant}/${field}/${action}`);
      }
    }
  }
  assert.ok(tested.size >= 20, `only ${tested.size} closed model variants tested`);
});

test('currency, calendar, shard placement and durable signature invariants reject semantic mutations', async () => {
  await prepareSamples();
  const reject = async (path, value) => assert.rejects(projections.decodeProjection(identity(path), wire(value), { profile }), projections.CoverageError);
  for (const fixture of coverage.version_ordering_cases) {
    const ordered = { ...coverage.active, [fixture.set]: fixture.canonical_values, active_version: fixture.active_version };
    await projections.decodeProjection(identity('agreements/active.enc.json'), wire(ordered), { profile });
    await reject('agreements/active.enc.json', { ...ordered, [fixture.set]: fixture.reversed_values });
    await reject('agreements/active.enc.json', { ...ordered, [fixture.set]: [fixture.canonical_values[0], fixture.canonical_values[0]] });
  }
  for (const fixture of coverage.shard_cases) {
    const value = { [String(fixture.user)]: { agreements: {}, overrides: {} } };
    const path = `users/${String(fixture.expected).padStart(2, '0')}.enc.json`;
    await projections.decodeProjection(identity(path), wire(value), { profile });
    await reject(`users/${String((fixture.expected + 1) % 32).padStart(2, '0')}.enc.json`, value);
  }
  const sourceShards = new Set();
  const hashedSources = derived.source_shards.filter(fixture => Object.hasOwn(fixture, 'sha256'));
  assert.equal(hashedSources.length, 6);
  for (const fixture of derived.source_shards) {
    const digest = await artifacts.sha256(bytes(fixture.source_id));
    const shard = digest[0] >>> 3;
    sourceShards.add(shard);
    assert.equal(shard, fixture.shard, fixture.source_id);
    if (fixture.sha256) assert.equal(hex(digest), fixture.sha256, fixture.source_id);
  }
  assert.deepEqual([...sourceShards].sort((a, b) => a - b), [...Array(32).keys()]);
  for (const mutation of [{ active_version: 'missing' }, { accepted_versions: ['1', '1'] }, { accepted_versions: ['2', '1'] }, { retired_versions: ['1'] }, { projection_format: 2 }, { shard_count: 31 }, { agreement_id: null }]) await reject('agreements/active.enc.json', { ...coverage.active, ...mutation });
  const unicode = { ...coverage.active, active_version: '\ue000', accepted_versions: ['\ue000', '😀'] };
  await projections.decodeProjection(identity('agreements/active.enc.json'), wire(unicode));
  await reject('agreements/active.enc.json', { ...unicode, accepted_versions: ['😀', '\ue000'] });
  for (const date of ['2026-02-30T00:00:00Z', '1900-02-29T00:00:00Z', '0000-01-01T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:00:00.0Z', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00Z\n']) await reject('source.enc.json', { ...coverage.empty_files['source.enc.json'], built_at: date });
  await projections.decodeProjection(identity('source.enc.json'), wire({ ...coverage.empty_files['source.enc.json'], built_at: '2000-02-29T00:00:00Z' }));
  for (const mutation of [{ project_state: 'unconnected' }, { successor_project_id: 'other' }, { project_state: 'succeeded', successor_project_id: null }]) await reject('source.enc.json', { ...coverage.empty_files['source.enc.json'], ...mutation });
  const sample = samples.find(sample => sample.path.startsWith('users/') && Object.values(sample.value).some(row => Object.values(row.agreements).some(facts => facts.reason_code === 'signed')));
  const [id, row] = Object.entries(sample.value).find(([, row]) => Object.values(row.agreements).some(facts => facts.reason_code === 'signed'));
  for (const bad of ['0', '0' + id, '9007199254740992', id + '\n']) await reject(sample.path, { [bad]: row });
  await reject(`users/${String((Number(id) + 1) % 32).padStart(2, '0')}.enc.json`, { [id]: row });
  const agreement = Object.keys(row.agreements).find(key => row.agreements[key].reason_code === 'signed');
  for (const mutation of [{ decision: 'uncovered' }, { reason_code: 'version_not_active' }, { version: null }, { digest: 'a'.repeat(64) }]) {
    const changed = structuredClone(row); Object.assign(changed.agreements[agreement], mutation);
    await reject(sample.path, { [id]: changed });
  }
  const override = samples.find(sample => sample.path.startsWith('users/') && Object.values(sample.value).some(row => Object.keys(row.overrides).length));
  assert.ok(override);
  const originalOverride = Object.values(Object.values(override.value).find(row => Object.keys(row.overrides).length).overrides)[0];
  const otherTree = (originalOverride.tree_oid.startsWith('a') ? 'b' : 'a').repeat(40);
  for (const mutation of [{ active: false }, { subject_user_id: originalOverride.subject_user_id + 1 }, { tree_oid: otherTree }]) {
    const changed = structuredClone(override.value), user = Object.values(changed).find(row => Object.keys(row.overrides).length);
    Object.assign(Object.values(user.overrides)[0], mutation);
    await reject(override.path, changed);
  }
});

test('scope, private provenance, cursor retention and reader counts stay closed', async () => {
  await prepareSamples();
  const rejects = async (path, value, options = {}) => assert.rejects(projections.decodeProjection(identity(path), wire(value), { profile, ...options }), projections.ProjectionError);
  const mutationFence = operations.fences.mutation;
  for (const mutation of [{ subjects: [7, 7], project_wide: false }, { subjects: [8, 7], project_wide: false }, { subjects: [], project_wide: false }, { subjects: [7], project_wide: true }, { generation: -1 }, { operation_id: 'AA' }, { prepared_blob_sha: 'a'.repeat(40) + '\n' }]) await rejects('decision-fence.enc.json', { ...mutationFence, ...mutation });
  const marker = structuredClone(operations.markers.open), entry = Object.values(marker.ops)[0];
  marker.ops[derived.event_id] = entry;
  assert.equal(Object.keys(marker.ops).length, 2);
  await rejects('inflight.enc.json', marker);
  for (const row of derived.wire_goldens.reader_authority) {
    const value = parse(unhex(row.bytes_hex)), source = value[row.source_id];
    const empty = structuredClone(value); empty[row.source_id].subjects = {};
    if (source.kind === 'continuous_team') {
      await projections.decodeProjection(identity(row.path), wire(empty), { profile });
      const bad = structuredClone(value); bad[row.source_id].materialization_cursor = {};
      await rejects(row.path, bad);
    } else await rejects(row.path, empty);
    const bad = structuredClone(value);
    Object.values(bad[row.source_id].subjects)[0].added_event_id = source.kind === 'continuous_team' ? row.source_id : encoding.base64urlEncode(new Uint8Array(32).fill(255));
    await rejects(row.path, bad);
  }
  const continuous = derived.wire_goldens.reader_authority.find(row => row.row.kind === 'continuous_team');
  const shard = Number(continuous.path.slice(-11, -9)), crowded = {};
  for (let i = 0; Object.keys(crowded).length < 11; i++) {
    const id = createHash('sha256').update(String(i)).digest('base64url');
    if ((createHash('sha256').update(id).digest()[0] >>> 3) === shard && !Object.values(continuous.row.subjects).some(member => member.added_event_id === id)) crowded[id] = structuredClone(continuous.row);
  }
  await rejects(continuous.path, crowded);
  const detail = samples.find(sample => sample.path.startsWith('derived/status-detail/') && Object.keys(sample.standingRules).length && Object.values(sample.value).some(row => Object.values(row.exemption_sources).some(source => source.source_kind === 'continuous_team')));
  assert.ok(detail);
  await rejects(detail.path, detail.value, { standingRules: {} });
  const changed = structuredClone(detail.value), subject = Object.values(changed).find(row => Object.values(row.exemption_sources).some(source => source.source_kind === 'continuous_team'));
  subject.exemption_sequence_next = 0;
  await rejects(detail.path, changed, { standingRules: detail.standingRules });
  const mismatch = structuredClone(detail.standingRules); Object.values(mismatch)[0].basis += '-changed';
  await rejects(detail.path, detail.value, { standingRules: mismatch });
  const duplicateSample = samples.find(sample => sample.path.startsWith('derived/status-detail/') && Object.values(sample.value).some(row => Object.values(row.exemption_sources).some(source => source.source_kind === 'bot')));
  const duplicate = structuredClone(duplicateSample.value), selected = Object.values(duplicate).find(row => Object.values(row.exemption_sources).some(source => source.source_kind === 'bot'));
  const bot = Object.values(selected.exemption_sources).find(source => source.source_kind === 'bot');
  const extraId = encoding.base64urlEncode(new Uint8Array(32).fill(254));
  selected.exemption_sources[extraId] = structuredClone(bot);
  await rejects(duplicateSample.path, duplicate, { standingRules: duplicateSample.standingRules });
});

test('private byte limits, full derived state and immutable byte ownership fail closed', async () => {
  await prepareSamples();
  for (const [path, selected] of [['derived/index/00.enc.json', 'derived_index'], ['derived/status-detail/00.enc.json', 'status_detail'], ['derived/reader-authority/00.enc.json', 'reader_authority']]) {
    const tiny = new limits.ReleaseProfile({ ...profileValue, max_shard_ciphertext_bytes: { ...profileValue.max_shard_ciphertext_bytes, [selected]: 1 } });
    await assert.rejects(projections.decodeProjection(identity(path), bytes('{}'), { profile: tiny }), error => error instanceof projections.DerivedClassOverflow && error.derived_class === selected);
    await assert.rejects(projections.decodeProjection(identity(path), new Uint8Array([255]), { profile: tiny }), error => error instanceof projections.DerivedClassOverflow && error.derived_class === selected);
    const exact = new limits.ReleaseProfile({ ...profileValue, max_shard_ciphertext_bytes: { ...profileValue.max_shard_ciphertext_bytes, [selected]: 18 } });
    assert.deepEqual(await projections.decodeProjection(identity(path), bytes('{}'), { profile: exact }), {});
  }
  const stateTiny = new limits.ReleaseProfile({ ...profileValue, max_state_ciphertext_bytes: 1 });
  await assert.rejects(projections.decodeProjection(identity('derived/state.enc.json'), wire(assembled), { profile: stateTiny }), error => error instanceof projections.DerivedClassOverflow && error.derived_class === 'state');
  await assert.rejects(projections.decodeProjection(identity('derived/state.enc.json'), new Uint8Array([255]), { profile: stateTiny }), error => error instanceof projections.DerivedClassOverflow && error.derived_class === 'state');
  await projections.decodeProjection(identity('agreements/active.enc.json'), wire(coverage.active), { profile: stateTiny });
  const changed = structuredClone(assembled); delete changed.shard_digests.derived_index['00'];
  await assert.rejects(projections.decodeProjection(identity('derived/state.enc.json'), wire(changed), { profile }), projections.DerivedError);
  const mismatch = structuredClone(assembled); mismatch.profile.max_reader_source_members++;
  await assert.rejects(projections.decodeProjection(identity('derived/state.enc.json'), wire(mismatch), { profile }), projections.DerivedError);
  const limit = new limits.ReleaseProfile({ ...profileValue, max_shard_ciphertext_bytes: { ...profileValue.max_shard_ciphertext_bytes, reader_authority: 16 } });
  const input = bytes('{}'), pending = projections.decodeProjection(identity('derived/reader-authority/00.enc.json'), input, { profile: limit });
  structuredClone(input.buffer, { transfer: [input.buffer] });
  await assert.rejects(pending, projections.DerivedClassOverflow);
  const immutable = await projections.decodeProjection(identity('agreements/active.enc.json'), wire(coverage.active));
  assert.throws(() => immutable.accepted_versions.push('changed'), TypeError);
  assert.throws(() => { immutable.active_version = 'changed'; }, TypeError);
  await assert.rejects(projections.decodeProjection(identity('derived/index/00.enc.json'), bytes('{}')), projections.DerivedError);
  await assert.rejects(projections.decodeProjection(identity('source.enc.json'), bytes('{} ')), projections.CoverageError);
  await assert.rejects(projections.decodeProjection({ ...identity('source.enc.json'), schema_version: 2 }, bytes('{}')), projections.ProjectionError);
});

const wrapped = await vector('wrapped-key-v1.json');
const wrappedGolden = parse(bytes(wrapped.copy_utf8));
const wrappedDataKey = unhex(wrapped.data_key_hex), wrappingKey = unhex(wrapped.wrapping_key_hex);
const wrapContext = { projectId: wrapped.project_id, capability: wrapped.capability,
  dataKid: unhex(wrapped.data_kid_hex), wrapperId: wrapped.wrapper_id,
  wrapperGeneration: wrapped.wrapper_generation, wrappingKey };
const keyringContext = {
  expectedProjectId: wrapped.project_id, allowedCapabilities: new Set(['records', 'coverage']),
  allowedWrappers: new Set(Object.keys(keyrings.WRAPPER_CAPABILITIES)),
  knownGenerations: new Map(Object.keys(keyrings.WRAPPER_CAPABILITIES)
    .map(id => [id, new Set(['generation-1', 'generation-2'])])),
};
const unwrapContext = copy => ({ expectedProjectId: copy.project_id, expectedCapability: copy.capability,
  wrappingKeys: new Map([[copy.wrapper_id, new Map([[copy.wrapper_generation, wrappingKey]])]]) });
const decodeKeys = (data, changes = {}) => keyrings.decodeKeyring(data, { ...keyringContext, ...changes });

test('M1-14 fixed-nonce wrapped key, AAD and canonical keyring match the shared Python golden', async t => {
  t.mock.method(crypto, 'getRandomValues', array => { array.set(unhex(wrapped.nonce_hex)); return array; });
  const copy = await keyrings.wrapKeyCopy(wrappedDataKey, wrapContext);
  assert.equal(hex(keyrings.wrappedKeyAad(copy)), hex(bytes(wrapped.aad_utf8)));
  assert.equal(hex(wire(copy)), hex(bytes(wrapped.copy_utf8)));
  assert.equal(copy.wrapped_key, wrapped.wrapped_key_base64url);
  assert.equal(hex(keyrings.encodeKeyring([copy])), hex(bytes(wrapped.keyring_utf8)));
  assert.equal(hex(await keyrings.unwrapKeyCopy(copy, unwrapContext(copy))), wrapped.data_key_hex);
  const decoded = decodeKeys(bytes(wrapped.keyring_utf8));
  assert.deepEqual(decoded.keys, [copy]);
  assert.equal(hex(keyrings.encodeKeyring(decoded)), hex(bytes(wrapped.keyring_utf8)));
  for (const object of [copy, decoded, decoded.keys, decoded.keys[0]]) assert.ok(Object.isFrozen(object));
  assert.throws(() => { decoded.keys[0].project_id = 'other'; }, TypeError);
});

test('M1-14 every capability/wrapper pair, fresh nonce, rotation and UTF8 keyring ordering', async () => {
  for (const [wrapperId, capabilities] of Object.entries(keyrings.WRAPPER_CAPABILITIES)) {
    for (const capability of capabilities) {
      const first = await keyrings.wrapKeyCopy(wrappedDataKey, { ...wrapContext, capability, wrapperId });
      const second = await keyrings.wrapKeyCopy(wrappedDataKey, { ...wrapContext, capability, wrapperId,
        dataKid: new Uint8Array(16).fill(106), wrapperGeneration: 'generation-2' });
      assert.notEqual(first.nonce, second.nonce);
      for (const copy of [first, second])
        assert.equal(hex(await keyrings.unwrapKeyCopy(copy, unwrapContext(copy))), wrapped.data_key_hex);
      const encoded = keyrings.encodeKeyring([second, first]);
      assert.equal(hex(encoded), hex(keyrings.encodeKeyring([first, second])));
      assert.deepEqual(decodeKeys(encoded).keys,
        [first, second].sort((a, b) => Buffer.compare(Buffer.from(wire(a)), Buffer.from(wire(b)))));
      const reversed = parse(encoded); reversed.keys.reverse();
      assert.throws(() => decodeKeys(wire(reversed)), keyrings.KeyringFormatError);
    }
  }
  // Unicode generation ordering uses complete UTF8 object bytes, not locale order.
  const copies = ['\ue000', '😀'].map((generation, i) => ({ ...wrappedGolden,
    wrapper_id: ['control', 'recovery'][i], wrapper_generation: generation }));
  const expected = copies.sort((a, b) => Buffer.compare(Buffer.from(wire(a)), Buffer.from(wire(b))));
  assert.deepEqual(parse(keyrings.encodeKeyring(copies)).keys, expected);
  assert.equal(hex(keyrings.encodeKeyring([])), hex(bytes('{"keyring_version":1,"keys":[]}')));
  assert.deepEqual(decodeKeys(keyrings.encodeKeyring([])).keys, []);
  assert.throws(() => { keyrings.WRAPPER_CAPABILITIES.control.push('unknown'); }, TypeError);
});

test('M1-14 rejects closed-schema, canonical, scalar, context, pairing, generation and duplicate defects', async () => {
  const F = keyrings.KeyringFormatError, C = keyrings.KeyringContextError;
  const root = parse(bytes(wrapped.keyring_utf8));
  const entryCases = [
    ['wrap_version', 2, F], ['wrap_version', true, F], ['algorithm', 'AES-GCM', F],
    ['project_id', '', C], ['project_id', 'other', C], ['project_id', 7, F],
    ['capability', 'unknown', C], ['capability', 'coverage', C],
    ['wrapper_id', 'unknown', C], ['wrapper_id', 'portal-coverage', C],
    ['wrapper_generation', '', C], ['wrapper_generation', 'unknown', C],
    ['data_kid', wrappedGolden.data_kid + '=', F], ['data_kid', 7, F],
    ['nonce', 'AA', F], ['nonce', '_x', F], ['wrapped_key', 'AA', F],
  ];
  for (const [name, value, error] of entryCases)
    assert.throws(() => decodeKeys(wire({ ...root, keys: [{ ...wrappedGolden, [name]: value }] })), error, name);
  for (const name of Object.keys(wrappedGolden)) {
    const entry = { ...wrappedGolden }; delete entry[name];
    assert.throws(() => decodeKeys(wire({ ...root, keys: [entry] })), F, name);
  }
  for (const value of [null, [], 7, { ...wrappedGolden, extra: true }])
    assert.throws(() => decodeKeys(wire({ ...root, keys: [value] })), F);
  for (const value of [null, [], 'scalar', { keys: [] }, { keyring_version: 1 },
    { ...root, keyring_version: true }, { ...root, keyring_version: '1' },
    { ...root, keyring_version: 2 }, { ...root, keys: {} }, { ...root, extra: true }])
    assert.throws(() => decodeKeys(wire(value)), F);
  for (const text of [wrapped.keyring_utf8 + '\n', '{"keyring_version":1,"keys": [ ]}',
    '{"keyring_version":1,"keyring_version":1,"keys":[]}'])
    assert.throws(() => decodeKeys(bytes(text)), F);
  assert.throws(() => decodeKeys(new Uint8Array([255])), F);
  assert.throws(() => decodeKeys('text'), TypeError);
  assert.throws(() => keyrings.wrappedKeyAad(Object.defineProperty({}, 'x', { get() { throw Error('getter'); }, enumerable: true })), F);
  assert.throws(() => keyrings.wrappedKeyAad(null), F);
  for (const input of [null, 7, 'not copies']) assert.throws(() => keyrings.encodeKeyring(input), TypeError);
  assert.throws(() => keyrings.encodeKeyring([{}]), F);
  const duplicate = { ...wrappedGolden, wrapper_generation: 'generation-2' };
  assert.throws(() => keyrings.encodeKeyring([wrappedGolden, duplicate]), F);
  assert.throws(() => decodeKeys(wire({ ...root, keys: [wrappedGolden, duplicate] })), F);
  for (const changes of [
    { expectedProjectId: 'other' }, { expectedProjectId: '' },
    { allowedCapabilities: new Set(['coverage']) }, { allowedCapabilities: new Set(['unknown']) },
    { allowedWrappers: new Set(['control']) }, { allowedWrappers: new Set(['unknown']) },
    { knownGenerations: new Map() }, { knownGenerations: new Map([['unknown', new Set(['g'])]]) },
    { knownGenerations: new Map([[wrapped.wrapper_id, new Set([''])]]) },
  ]) assert.throws(() => decodeKeys(bytes(wrapped.keyring_utf8), changes), C);
  for (const changes of [{ allowedCapabilities: 'records' }, { allowedWrappers: [] },
    { knownGenerations: [] }, { knownGenerations: new Map([[wrapped.wrapper_id, 'generation-1']]) }])
    assert.throws(() => decodeKeys(bytes(wrapped.keyring_utf8), changes), TypeError);
  for (const changes of [{ projectId: '' }, { projectId: null }, { capability: 'unknown' },
    { wrapperId: 'unknown' }, { wrapperId: 'portal-coverage' }, { wrapperGeneration: '' },
    { wrapperGeneration: null }])
    await assert.rejects(keyrings.wrapKeyCopy(wrappedDataKey, { ...wrapContext, ...changes }), C);
  for (const [name, length] of [['wrappingKey', 32], ['dataKid', 16]])
    for (const value of [null, 'raw', new Uint8Array(length - 1), new Uint8Array(length + 1)])
      await assert.rejects(keyrings.wrapKeyCopy(wrappedDataKey, { ...wrapContext, [name]: value }), F);
  for (const value of [null, 'raw', new Uint8Array(31), new Uint8Array(33)])
    await assert.rejects(keyrings.wrapKeyCopy(value, wrapContext), F);
});

test('M1-14 exact wrapping-key selection, authenticated metadata, tampering and secret-safe errors', async () => {
  const baseContext = unwrapContext(wrappedGolden);
  for (const changes of [{ expectedProjectId: 'other' }, { expectedCapability: 'coverage' },
    { expectedCapability: 'unknown' }])
    await assert.rejects(keyrings.unwrapKeyCopy(wrappedGolden, { ...baseContext, ...changes }), keyrings.KeyringContextError);
  for (const keys of [new Map(), new Map([[wrapped.wrapper_id, new Map()]]),
    new Map([[wrapped.wrapper_id, new Map([['other', wrappingKey]])]])])
    await assert.rejects(keyrings.unwrapKeyCopy(wrappedGolden, { ...baseContext, wrappingKeys: keys }), keyrings.UnknownWrappingKeyError);
  const fallback = new class extends Map { get() { throw Error('unknown entry must not be read'); } }();
  await assert.rejects(keyrings.unwrapKeyCopy(wrappedGolden, { ...baseContext, wrappingKeys: fallback }), keyrings.UnknownWrappingKeyError);
  for (const wrappingKeys of [[], new Map([[wrapped.wrapper_id, []]])])
    await assert.rejects(keyrings.unwrapKeyCopy(wrappedGolden, { ...baseContext, wrappingKeys }), TypeError);
  await assert.rejects(keyrings.unwrapKeyCopy(wrappedGolden, { ...baseContext,
    wrappingKeys: new Map([[wrapped.wrapper_id, new Map([[wrapped.wrapper_generation, new Uint8Array(31)]])]]) }), keyrings.KeyringFormatError);
  const changes = [
    { nonce: encoding.base64urlEncode(new Uint8Array(12)) },
    { wrapped_key: encoding.base64urlEncode(new Uint8Array(48)) },
    { project_id: 'other' }, { data_kid: encoding.base64urlEncode(new Uint8Array(16)) },
    { wrapper_id: 'control' }, { wrapper_generation: 'generation-2' },
    { capability: 'coverage', wrapper_id: 'control' },
  ];
  const errors = [];
  for (const change of changes) {
    const copy = { ...wrappedGolden, ...change };
    await assert.rejects(keyrings.unwrapKeyCopy(copy, unwrapContext(copy)), error => {
      errors.push(String(error)); return error instanceof keyrings.KeyringAuthenticationError;
    });
  }
  await assert.rejects(keyrings.unwrapKeyCopy(wrappedGolden, { ...baseContext,
    wrappingKeys: new Map([[wrapped.wrapper_id, new Map([[wrapped.wrapper_generation, new Uint8Array(32)]])]]) }),
    error => { errors.push(String(error)); return error instanceof keyrings.KeyringAuthenticationError; });
  const output = Buffer.from(keyrings.encodeKeyring([wrappedGolden]));
  for (const secret of [wrappedDataKey, wrappingKey]) {
    for (const representation of [Buffer.from(secret), Buffer.from(hex(secret)), Buffer.from(encoding.base64urlEncode(secret))])
      assert.equal(output.includes(representation), false);
    for (const error of errors) {
      assert.equal(error.includes(hex(secret)), false);
      assert.equal(error.includes(encoding.base64urlEncode(secret)), false);
    }
  }
});

test('M1-14 snapshots caller keys and metadata before asynchronous crypto', async () => {
  const raw = wrappedDataKey.slice(), wrap = wrappingKey.slice(), context = { ...wrapContext, wrappingKey: wrap };
  const pending = keyrings.wrapKeyCopy(raw, context);
  raw.fill(255); wrap.fill(255); context.projectId = 'changed';
  const copy = await pending;
  assert.equal(copy.project_id, wrapped.project_id);
  assert.equal(hex(await keyrings.unwrapKeyCopy(copy, unwrapContext(copy))), wrapped.data_key_hex);
  const mutable = { ...copy }, callerKey = wrappingKey.slice(), unwrapping = unwrapContext(copy);
  unwrapping.wrappingKeys.get(copy.wrapper_id).set(copy.wrapper_generation, callerKey);
  const plaintext = keyrings.unwrapKeyCopy(mutable, unwrapping);
  mutable.nonce = 'changed'; callerKey.fill(255); unwrapping.expectedProjectId = 'changed';
  assert.equal(hex(await plaintext), wrapped.data_key_hex);
});

const [eventCorpus, eventIdentities, authorizationCorpus] = await Promise.all([
  'events-v1.json', 'event-identities-v1.json', 'authorization-vocabulary-v1.json',
].map(vector));
const eventRows = Object.fromEntries(eventCorpus.events.map(row => [row.type, row]));
const evtClone = value => structuredClone(value);
const evtHead = event => event.confirmed_canonical_oid ?? 'b'.repeat(40);
const evtLink = event => Object.fromEntries(['event_id', 'type', 'project_id', 'target', 'payload'].map(key => [key, evtClone(event[key])]));
const evtSort = values => values.sort((a, b) => Buffer.compare(wire(a), wire(b)));
async function evtSign(value) {
  const row = evtClone(value);
  const identity = await events.deriveEventIdentity(Object.fromEntries(['project_id', 'operation_nonce', 'actor', 'type', 'target', 'payload', 'confirmed_canonical_oid'].map(key => [key, row[key]])));
  for (const key of ['event_id', 'idempotency_key', 'operation_sha256']) row[key] = identity[key];
  return row;
}
function evtProjection(version, retired = []) {
  return { agreement_id: version === null ? null : 'agreement-1', active_version: version, activation_event_id: version === null ? null : eventRows.agreement_activated.event_id, accepted_versions: version === null ? [] : [version], retired_versions: retired, projection_format: 1, shard_count: 32 };
}
// Independent construction of the authenticated facts named by the shared event fixtures.
async function evtFacts(event, overrides = {}, head = evtHead(event)) {
  const result = [], t = event.target, p = event.payload;
  for (const requirement of await events.requiredPreconditions(event, head)) {
    const name = requirement.name, shard = Number(name.slice(-2)); let value;
    const key = Object.hasOwn(overrides, name) ? name : ['coverage-state', 'current-exemption-union'].find(prefix => name.startsWith(prefix + '-') && Object.hasOwn(overrides, prefix));
    if (key !== undefined) value = evtClone(overrides[key]);
    else if (name === 'generations-absence') value = null;
    else if (name === 'source-first-add' || name.startsWith('scope-terminal-') || name.startsWith('publication-')) value = { path: requirement.path, present: false };
    else if (name === 'prior-generations') value = Object.fromEntries(['derived_index', 'status_detail', 'reader_authority'].map(key => [key, event.event_id]));
    else if (name === 'project-lifecycle') value = { project_id: event.project_id, state: 'active', successor_project_id: null };
    else if (name === 'keyring-affected-repositories') value = { project_id: event.project_id, repository_ids: { records: 11, coverage: 12, control: 13 } };
    else if (name === 'current-configuration') value = evtClone(eventRows.project_connected.payload.project_configuration);
    else if (name === 'current-project-agreement') value = { project_id: event.project_id, recipient: evtClone(p.recipient), agreement_id: null, published_versions: [] };
    else if (name === 'superseded-acceptance') value = evtLink(eventRows.acceptance);
    else if (name === 'current-acceptance-basis') value = { project_id: event.project_id, github_user_id: t.coverage_tuple.github_user_id, agreement_id: t.coverage_tuple.agreement_id, basis: { event_id: p.supersedes, kind: 'acceptance' } };
    else if (name === 'active-agreement') {
      if (event.type === 'acceptance') value = { project_id: event.project_id, agreement_id: t.coverage_tuple.agreement_id, version: t.version, recipient: evtClone(t.recipient), digest: t.digest, state: 'active', accepted_versions: [t.version], retired_versions: [], active_version: t.version, activation_event_id: eventRows.agreement_activated.event_id, supersedes_coverage: false, publication: evtLink(eventRows.agreement_published) };
      else value = event.type === 'agreement_activation_restored' ? evtProjection('2', ['1']) : evtProjection(t.version);
    } else if (['published-agreement', 'target-activation', 'scope-request', 'source-event', 'rule-event'].includes(name)) {
      const linked = name === 'published-agreement' ? 'agreement_published' : name === 'target-activation' ? 'agreement_activated' : name === 'scope-request' ? 'enforcement_scope_requested' : name === 'source-event' ? event.type === 'exemption_source_withdrawn' ? 'exemption' : 'records_reader_authorized' : event.type.startsWith('exemption') ? 'exemption_rule_configured' : 'records_reader_rule_configured';
      const id = name === 'published-agreement' ? p.published_event_id : name === 'target-activation' ? t.activation_event_id : name === 'scope-request' ? p.request_event_id : name === 'source-event' ? t.source_event_id : t.rule_event_id;
      const target = name === 'published-agreement' ? { agreement_id: t.agreement_id, version: t.version } : name === 'target-activation' ? evtClone(eventRows.agreement_activated.target) : name === 'scope-request' ? { change_id: t.change_id } : name === 'source-event' ? { subject: evtClone(t.subject) } : { team: evtClone(eventRows.exemption_rule_configured.target.team) };
      const payload = name === 'published-agreement' ? evtClone(eventRows.agreement_published.payload) : name === 'target-activation' ? evtClone(eventRows.agreement_activated.payload) : name === 'scope-request' ? { prior_scope: [], desired_scope: evtClone(p.desired_scope ?? eventRows.enforcement_scope_requested.payload.desired_scope), prior_registry_generation: 0 } : {};
      value = { event_id: id, type: linked, project_id: event.project_id, target, payload };
      if (name === 'scope-request') value.authorizations = evtClone(event.authorizations);
    } else if (name === 'successor-project') value = { event: { event_id: p.successor_connected_event_id, type: 'project_connected', project_id: t.successor_project_id, target: {}, payload: { successor_of: event.project_id, repository_ids: { records: 11, coverage: 12, control: 13 } } }, active_agreement: { project_id: t.successor_project_id, agreement_id: 'agreement-1', version: '1', state: 'active' } };
    else if (name === 'current-repository-owner') {
      const prior = { project_id: event.project_id, project_slug: p.project_slug, repository_owner: evtClone(t.prior_repository_owner), repository_ids: evtClone(p.repository_ids), registry_generation: Math.max(0, p.registry_generation - 1), enforcement_scope: [], request_event_links: {} };
      value = { prior_entry: prior, staged_entry: { ...evtClone(prior), repository_owner: evtClone(p.new_repository_owner), registry_generation: p.registry_generation } };
    } else if (name === 'current-scope') {
      const entry = { project_id: event.project_id, project_slug: 'project-one', repository_owner: evtClone(eventRows.project_connected.payload.repository_owner), repository_ids: evtClone(eventRows.project_connected.payload.repository_ids), registry_generation: p.prior_registry_generation ?? p.registry_generation ?? 0, enforcement_scope: evtClone(p.prior_scope ?? []), request_event_links: {} };
      if (event.type === 'enforcement_scope_requested') value = { prior_entry: entry, current_entry: evtClone(entry) };
      else if (event.type === 'enforcement_scope_activated') {
        const request = overrides['scope-request']?.payload ?? eventRows.enforcement_scope_requested.payload;
        entry.enforcement_scope = evtClone(request.prior_scope); entry.registry_generation = request.prior_registry_generation;
        value = { prior_entry: entry, staged_entry: { ...evtClone(entry), enforcement_scope: evtClone(p.desired_scope), registry_generation: p.registry_generation, request_event_links: { [t.change_id]: p.request_event_id } } };
      } else value = { current_entry: entry };
    } else if (name === 'override-grant') value = { event: { ...evtLink(eventRows.override), event_id: t.override_event_id }, active: true };
    else if (name.startsWith('coverage-state-')) value = { project_id: event.project_id, state: 'current', resource: evtClone(t), subject_ids: event.type === 'revocation' ? [t.coverage_tuple.github_user_id] : p.subjects.map(row => row.github_user_id).filter(id => id % 32 === shard).sort((a, b) => a - b) };
    else if (name.startsWith('current-exemption-union-')) {
      const source = t.source_event_id ?? t.rule_event_id ?? eventRows.exemption.event_id;
      const candidates = event.type === 'exemption_materialized' && p.result === 'add' ? [] : event.type === 'exemption_rule_withdrawn' ? [eventRows.exemption.target.subject] : t.subjects ?? [t.subject ?? eventRows.exemption.target.subject];
      const subjects = evtClone(candidates.filter(row => row.github_user_id % 32 === shard));
      value = { project_id: event.project_id, subjects, provenance: Object.fromEntries(subjects.map(row => [String(row.github_user_id), [source]])) };
    } else if (name === 'current-reader-authority') {
      value = { project_id: event.project_id, class_state: 'current', sources: event.type === 'records_reader_materialized' && p.result === 'withdraw' ? [t.rule_event_id] : [], cursor_event_id: event.event_id };
      if (event.type === 'records_reader_materialized') Object.assign(value, { rule_event_id: t.rule_event_id, subject: evtClone(t.subject), source_record_present: true });
    } else if (name === 'current-derived-state') {
      value = { project_id: event.project_id, standing_rule_event_ids: [], max_continuous_exemption_rules: 10, max_state_ciphertext_bytes: 100000 };
      if (event.type === 'records_reader_rule_configured') value.max_continuous_reader_rules = 10;
    } else if (name === 'active-exemption-rule-state') value = { project_id: event.project_id, standing_rule_event_ids: [t.rule_event_id] };
    else if (name.startsWith('active-reader-rules-')) value = { project_id: event.project_id, rule_event_ids: [] };
    else if (name === 'reader-authority-state') {
      value = { project_id: event.project_id, class_state: 'current', source_event_ids: [t.source_event_id ?? t.rule_event_id], cursor_event_id: event.event_id };
      if (event.type === 'records_reader_withdrawn') Object.assign(value, { source_event_id: t.source_event_id, subject: evtClone(t.subject) }); else value.rule_event_id = t.rule_event_id;
    } else if (name === 'materialization-cursor') value = { cursor_event_id: p.prior_materialization_event_id, prior_materialization_event_id: null, rule_event_id: t.rule_event_id, subject: evtClone(t.subject) };
    else assert.fail('unhandled precondition fixture: ' + name);
    const mode = requirement.binding_mode;
    const binding = mode === 'events-head' ? { mode, events_head: head } : mode === 'generation' ? { mode, events_head: head, canonical_generation: event.event_id, derived_generation: event.event_id } : mode === 'canonical-sha' ? { mode, coverage_commit_oid: head, canonical_sha: head } : mode === 'registry-generation' ? { mode, registry_commit_oid: p.registry_commit_oid ?? 'a'.repeat(40), registry_generation: p.registry_generation ?? p.prior_registry_generation ?? 0 } : { mode, successor_project_id: t.successor_project_id, successor_events_head: head, repository_ids: [11, 12, 13] };
    result.push({ ...Object.fromEntries(['name', 'artifact_kind', 'repository_role', 'branch', 'path', 'binding_mode'].map(key => [key, requirement[key]])), binding, value });
  }
  return result;
}
const evtFact = (facts, name) => facts.find(row => row.name === name);
const evtHash = raw => 'sha256:' + createHash('sha256').update(raw).digest('hex');
const evtArtifact = (kind, path, raw) => ({ kind, path, bytes: raw, sha256: evtHash(raw) });
function evtMetadata(event) {
  return { metadata_version: 1, agreement_id: event.target.agreement_id, version: event.target.version, ...Object.fromEntries(['recipient', 'ref', 'content_commit_oid', 'digest', 'snapshot_sha256'].map(key => [key, evtClone(event.payload[key])])) };
}
async function evtPackage(event, facts) {
  const requirements = await events.requiredSideArtifacts(event, facts, evtHead(event));
  return requirements.map(row => {
    const prior = evtFact(facts, 'prior-generations')?.value;
    const value = row.kind === 'agreement_snapshot' ? null : row.kind === 'project_config' ? event.payload.project_configuration : row.kind === 'agreement_metadata' ? evtMetadata(event) : { generations_version: 1, ...Object.fromEntries(['derived_index', 'status_detail', 'reader_authority'].map(name => [name, row.affected_classes.includes(name) ? event.event_id : prior[name]])) };
    return evtArtifact(row.kind, row.path, row.kind === 'agreement_snapshot' ? bytes('agreement text') : wire(value));
  });
}

test('M1-15 every closed event and deterministic identity agrees with the shared registries', async () => {
  assert.deepEqual([...events.EVENT_TYPES].sort(), eventIdentities.event_types_v1.toSorted());
  assert.deepEqual(eventCorpus.events.map(row => row.type).sort(), [...events.EVENT_TYPES].sort());
  for (const row of eventIdentities.actors) assert.deepEqual(events.stableActorIdentity(row.actor), row.stable);
  const checkIdentity = async (input, golden) => {
    const result = await events.deriveEventIdentity(input);
    for (const key of ['idempotency_key', 'operation_sha256', 'event_id']) assert.equal(result[key], golden[key]);
    assert.equal(result.path, golden.event_path); assert.ok(Object.isFrozen(result));
  };
  for (const [type, row] of Object.entries(eventIdentities.event_identity_vectors)) await checkIdentity({ ...eventIdentities.event_identity_common_input, type, ...Object.fromEntries(['operation_nonce', 'actor', 'confirmed_canonical_oid'].map(key => [key, row[key]])) }, row);
  for (const row of [eventIdentities.event_identity, ...eventIdentities.scope_terminal_identity_variants]) await checkIdentity({ ...Object.fromEntries(['project_id', 'operation_nonce', 'actor', 'target', 'payload', 'confirmed_canonical_oid'].map(key => [key, row[key]])), type: row.event_type }, row);
  for (const row of eventIdentities.negative_examples) {
    const { name, event_type, unexpected_kwargs, ...input } = row;
    await assert.rejects(events.deriveEventIdentity({ ...input, ...unexpected_kwargs, type: event_type }), events.EventIdentityError, name);
  }
  const nonce = async row => row.domain === 'scope_terminal' ? events.deriveScopeTerminalNonce(row.request_event_id, row.terminal_type) : row.domain === 'github_retry' ? events.deriveGithubRetryNonce(row.repository_id, row.check_kind, row.check_identity, row.github_delivery_id) : events.deriveAutomationNonce(row.rule_event_id, row.subject_user_id, row.result, row.prior_materialization_event_id);
  for (const row of [{ domain: 'automation', ...eventIdentities.automation_nonce }, { domain: 'github_retry', ...eventIdentities.github_retry_nonce }, ...eventIdentities.deterministic_nonce_variants]) assert.equal(await nonce(row), row.nonce);
  for (const [field, type] of [['activation', 'enforcement_scope_activated'], ['abandonment', 'enforcement_scope_abandoned']]) assert.equal(await events.deriveScopeTerminalNonce(eventIdentities.scope_terminal_nonces.request_event_id, type), eventIdentities.scope_terminal_nonces[field]);
  assert.equal(encoding.base64urlDecode(events.newOperationNonce()).length, 16);
  for (const row of eventCorpus.events) {
    const result = await events.validateEvent(row, { expectedProjectId: row.project_id, expectedPath: events.eventPath(row.event_id) });
    assert.deepEqual(result, row); assert.ok(Object.isFrozen(result.payload)); assert.deepEqual(await events.parseEventJcs(wire(row)), row);
    assert.deepEqual((await events.requiredPreconditions(row, evtHead(row))).map(row => row.name), eventCorpus.precondition_names[row.type]);
    await events.requiredSideArtifacts(row, await evtFacts(row), evtHead(row));
  }
  for (const row of eventCorpus.negative_examples) await assert.rejects(events.validateEvent(row.input), events.EventValidationError, row.name);
  for (const row of eventCorpus.jcs_negative_cases) await assert.rejects(events.parseEventJcs(encoding.base64urlDecode(row.bytes_b64)), events.EventValidationError, row.id);
});

function evtAuthorization(operation, kind, id, authority) {
  return { operation, resource_kind: kind, resource_id: id, required_authority: authority, observed_authority: 'observed', authorized: true, checked_at: authorizationCorpus.timestamp, github_request_id: null };
}
function evtScopeAuthorization(row) {
  const action = row.operation.split('_').at(-1), before = row.prior_scope, after = row.desired_scope;
  const identity = value => [value.kind, value.repository_id ?? value.organization_id].join(':');
  const selected = ['bind', 'widen'].includes(action) ? after.find(value => !before.some(prior => identity(prior) === identity(value))) : before.find(value => !after.some(next => identity(next) === identity(value)));
  return evtAuthorization(row.operation, selected.kind, selected.repository_id ?? selected.organization_id, selected.kind === 'repository' ? 'contributing_repository_admin' : 'organization_owner');
}
test('M1-15 complete authorization vocabulary, scope transitions and negative corpus execute', () => {
  const pairs = [...new Map(events.AUTHORIZATION_TABLE.map(row => [row[1], row.slice(1)])).values()];
  assert.deepEqual(pairs, authorizationCorpus.operation_rows);
  const actor = eventRows.agreement_published.actor;
  for (const row of [...authorizationCorpus.connection_cases, ...authorizationCorpus.key_activation_cases]) {
    const values = row.rows.map(([op, kind, id, authority]) => evtAuthorization(op, kind, id, authority));
    assert.deepEqual(events.validateAuthorizations(row.event_type, {}, row.payload ?? {}, actor, values, row.affected_repository_ids), values);
  }
  for (const row of authorizationCorpus.scope_cases) {
    const authorization = evtScopeAuthorization(row), payload = { prior_scope: row.prior_scope, desired_scope: row.desired_scope, prior_registry_generation: 0 };
    events.validateAuthorizations('enforcement_scope_requested', { change_id: 'oracle' }, payload, actor, [authorization]);
    events.validateAuthorizations('enforcement_scope_activated', { change_id: 'oracle' }, { desired_scope: row.desired_scope }, actor, [authorization]);
    events.validateAuthorizations('enforcement_scope_abandoned', { change_id: 'oracle' }, {}, actor, [authorization]);
  }
  for (const [operation, kind, authority] of authorizationCorpus.pair_rejections) {
    assert.throws(() => events.validateAuthorizations('agreement_published', {}, {}, actor, [evtAuthorization(operation, kind, 5, authority)]), events.AuthorizationValidationError);
  }
  for (const row of authorizationCorpus.negative_examples) assert.throws(() => events.validateAuthorizations(row.event_type, row.target, row.payload, row.actor, row.authorizations, row.affected_repository_ids), events.AuthorizationValidationError, row.name);
  for (const row of eventCorpus.authorization_cases) {
    if (row.category === 'scope') assert.ok(authorizationCorpus.scope_cases.some(value => value.operation === row.operation));
    else assert.equal(eventRows[row.event_type].actor.kind, row.actor_kind);
    assert.equal(row.expect, 'accept');
  }
});

test('M1-15 all required evidence descriptors fail closed on missing, stale, malformed or inconsistent facts', async () => {
  const byName = new Map();
  for (const event of eventCorpus.events) for (const requirement of await events.requiredPreconditions(event, evtHead(event))) if (!byName.has(requirement.name)) byName.set(requirement.name, event);
  for (const row of eventCorpus.precondition_cases) for (const name of row.descriptor === '*' ? row.descriptors : [row.descriptor]) {
    const event = byName.get(name), head = evtHead(event), facts = await evtFacts(event), selected = evtFact(facts, name);
    if (row.status === 'satisfied') { await events.validatePreconditions(event, facts, head); continue; }
    if (row.status === 'missing') facts.splice(facts.indexOf(selected), 1);
    else if (row.status === 'wrong-binding') selected.binding_mode = selected.binding_mode === 'events-head' ? 'generation' : 'events-head';
    else if (row.status === 'inconsistent') selected.value = { inconsistent: true };
    else if (selected.binding.mode === 'canonical-sha') selected.binding.canonical_sha = 'c'.repeat(40);
    else if (selected.binding.mode === 'registry-generation') selected.binding.registry_generation += 1;
    else if (selected.binding.mode === 'cross-project') selected.binding.successor_project_id = 'other-project';
    else selected.binding.events_head = 'c'.repeat(40);
    await assert.rejects(events.validatePreconditions(event, facts, head), events.PreconditionValidationError, row.id + '/' + name);
  }
  for (const event of eventCorpus.events) {
    const head = evtHead(event), original = await evtFacts(event);
    for (const row of original) {
      for (const key of ['artifact_kind', 'repository_role', 'branch', 'path']) {
        const facts = evtClone(original); evtFact(facts, row.name)[key] += '-wrong';
        await assert.rejects(events.validatePreconditions(event, facts, head), events.PreconditionValidationError, event.type + '/' + row.name + '/' + key);
      }
      const facts = evtClone(original); evtFact(facts, row.name).binding.extra = true;
      await assert.rejects(events.validatePreconditions(event, facts, head), events.PreconditionValidationError);
    }
    await assert.rejects(events.validatePreconditions(event, [...original, original[0]], head), events.PreconditionValidationError);
    const mapping = Object.fromEntries(original.map(({ name, ...row }) => [name, row]));
    assert.equal((await events.validatePreconditions(event, mapping, head)).length, original.length);
  }
});

test('M1-15 every shared activation projection and cross-project case is enforced', async () => {
  const projections = { empty: evtProjection(null), v1: evtProjection('1'), v2_after_supersession: evtProjection('2', ['1']) };
  const malformed = {
    missing_shard_count: { ...projections.empty }, format_two: { ...projections.empty, projection_format: 2 }, shard_count_sixteen: { ...projections.empty, shard_count: 16 }, partial_active: { ...projections.empty, agreement_id: 'agreement-1' },
    duplicate_versions: { ...projections.v1, accepted_versions: ['1', '1'] }, active_version_not_member: { ...projections.v1, active_version: '2' }, bad_activation_event_id: { ...projections.v1, activation_event_id: 'bad' }, bad_accepted_versions: { ...projections.v1, accepted_versions: 'bad' }, non_string_version: { ...projections.v1, accepted_versions: [1] }, missing_agreement_id: { ...projections.v1, agreement_id: null }, missing_active_version: { ...projections.v1, active_version: '' }, extra_project_id: { ...projections.v1, project_id: 'project-1' }, wrong_agreement: { ...projections.v1, agreement_id: 'other' }, duplicate_retired: { ...projections.v2_after_supersession, retired_versions: ['1', '1'] }, overlapping_versions: { ...projections.v1, retired_versions: ['1'] }, unsorted_accepted: { ...projections.v1, accepted_versions: ['2', '1'] }, unsorted_retired: { ...projections.v2_after_supersession, retired_versions: ['3', '1'] }, bad_retired_versions: { ...projections.v1, retired_versions: 'bad' }, non_string_retired_version: { ...projections.v1, retired_versions: [1] }, empty_with_retired: { ...projections.empty, retired_versions: ['1'] },
  }; delete malformed.missing_shard_count.shard_count;
  for (const row of eventCorpus.activation_cases) {
    const projection = evtClone(projections[row.prior] ?? malformed[row.prior]); assert.ok(projection, row.id);
    const accepted = row.accepted_versions ?? (row.expect === 'accept' && !row.supersedes_coverage ? evtSort([...new Set([...projection.accepted_versions, row.event_version])]) : [row.event_version]);
    const raw = evtClone(eventRows.agreement_activated); raw.target.version = row.event_version; Object.assign(raw.payload, { supersedes_coverage: row.supersedes_coverage, accepted_versions: accepted });
    const event = await evtSign(raw), facts = await evtFacts(event, { 'active-agreement': projection });
    if (row.expect === 'accept') await events.validatePreconditions(event, facts, evtHead(event)); else await assert.rejects(events.validatePreconditions(event, facts, evtHead(event)), events.PreconditionValidationError, row.id);
  }
  for (const row of eventCorpus.cross_project_cases) {
    const event = eventRows.project_succeeded, facts = await evtFacts(event), selected = evtFact(facts, 'successor-project');
    if (row.mutation === 'wrong_backlink') selected.value.event.payload.successor_of = 'other';
    else if (row.mutation === 'missing_backlink') delete selected.value.event.payload.successor_of;
    else if (row.mutation === 'wrong_project') selected.value.event.project_id = 'other';
    else if (row.mutation === 'wrong_repository_set') selected.binding.repository_ids = [91, 92, 93];
    else if (row.mutation === 'inactive_agreement') selected.value.active_agreement.state = 'inactive';
    else assert.equal(row.mutation, 'valid');
    if (row.expect === 'accept') await events.validatePreconditions(event, facts, evtHead(event)); else await assert.rejects(events.validatePreconditions(event, facts, evtHead(event)), events.PreconditionValidationError, row.id);
  }
});

test('M1-15 override withdrawal authorization is bound to its authenticated grant repository', async () => {
  const raw = evtClone(eventRows.override_withdrawn);
  raw.target.override_event_id = eventRows.override.event_id;
  const event = await evtSign(raw), facts = await evtFacts(event);
  assert.equal(event.target.override_event_id, eventRows.override.event_id);
  assert.equal(event.authorizations[0].resource_id, 11);
  await events.validatePreconditions(event, facts, evtHead(event));
  assert.deepEqual(await events.requiredSideArtifacts(event, facts, evtHead(event)), []);
  await events.validateSideArtifactPackage(event, [], facts, evtHead(event));

  const mismatched = evtClone(event);
  mismatched.authorizations[0].resource_id = 1011;
  await events.validateEvent(mismatched);
  for (const check of [
    () => events.validatePreconditions(mismatched, facts, evtHead(mismatched)),
    () => events.requiredSideArtifacts(mismatched, facts, evtHead(mismatched)),
    () => events.validateSideArtifactPackage(mismatched, [], facts, evtHead(mismatched)),
  ]) await assert.rejects(check(), events.PreconditionValidationError);
});

test('M1-15 every exact side-artifact package vector and authenticated generation carry-forward executes', async () => {
  for (const row of eventCorpus.package_cases) {
    let event = evtClone(eventRows[row.fixture === 'publication' ? 'agreement_published' : row.fixture === 'connection' ? 'project_connected' : 'acceptance']);
    if (row.fixture === 'publication') {
      event.payload.digest = event.payload.snapshot_sha256 = evtHash(bytes('agreement text'));
      event = await evtSign(event);
    }
    const mutation = row.mutation, raw = row.bytes_b64 === undefined ? null : encoding.base64urlDecode(row.bytes_b64);
    if (mutation === 'digest_field_mismatch' || mutation === 'snapshot_sha_field_mismatch') {
      event.payload[mutation === 'digest_field_mismatch' ? 'digest' : 'snapshot_sha256'] = evtHash(bytes('different')); event = await evtSign(event);
    }
    let facts = await evtFacts(event);
    if (row.fixture === 'acceptance') Object.assign(evtFact(facts, 'prior-generations').value, Object.fromEntries(['derived_index', 'status_detail', 'reader_authority'].map(key => [key, eventRows.project_connected.event_id])));
    let packageValue = await evtPackage(event, facts);
    if (row.fixture === 'publication') {
      if (['snapshot_exact', 'snapshot_digest_mismatch', 'digest_field_mismatch', 'snapshot_sha_field_mismatch'].includes(mutation)) packageValue[0] = evtArtifact(packageValue[0].kind, packageValue[0].path, raw);
      else if (mutation === 'wrong_snapshot_path') packageValue[0].path = 'agreements/wrong.snapshot.enc.json';
      else if (mutation.startsWith('metadata_')) packageValue[1] = evtArtifact(packageValue[1].kind, packageValue[1].path, raw);
      else assert.fail('unhandled publication mutation ' + mutation);
    } else if (mutation === 'missing_required') packageValue = [];
    else if (mutation === 'extra_artifact') packageValue.push(evtArtifact('extra', 'extra.enc.json', raw));
    else if (mutation === 'duplicate_required') packageValue = [packageValue[0], packageValue[0]];
    else if (mutation === 'reverse_order') packageValue.reverse();
    else if (mutation === 'wrong_kind') packageValue[0].kind = 'wrong-kind';
    else if (mutation === 'wrong_path') packageValue[0].path = 'config/wrong.enc.json';
    else if (mutation.startsWith('configuration_')) packageValue[1] = evtArtifact(packageValue[1].kind, packageValue[1].path, raw);
    else if (mutation.startsWith('genesis_') || mutation.startsWith('generations_')) {
      packageValue[0] = evtArtifact(packageValue[0].kind, packageValue[0].path, raw);
      if (mutation === 'genesis_prior_exists') evtFact(facts, 'generations-absence').value = { absent: false };
    } else assert.fail('unhandled package mutation ' + mutation);
    if (row.expect === 'accept') {
      await assert.doesNotReject(events.validateSideArtifactPackage(event, packageValue, facts, evtHead(event)), row.id);
      await events.validateSideArtifactPackage(event, packageValue.map(({ bytes, ...item }) => ({ ...item, bytes_b64: encoding.base64urlEncode(bytes) })), facts, evtHead(event));
    } else await assert.rejects(events.validateSideArtifactPackage(event, packageValue, facts, evtHead(event)), events.EventValidationError, row.id);
  }
});

test('M1-15 project-wide continuous-reader limit authenticates all 32 shards and their generation join', async () => {
  const event = eventRows.records_reader_rule_configured, facts = await evtFacts(event);
  const distinct = new Map();
  for (let i = 0; distinct.size < 11; i++) {
    const id = createHash('sha256').update('M1-15 independent reader source ' + i).digest('base64url');
    const shard = createHash('sha256').update(id, 'ascii').digest()[0] >> 3;
    if (!distinct.has(shard)) distinct.set(shard, id);
  }
  const entries = [...distinct];
  for (const count of [9, 10, 11]) {
    const current = evtClone(facts);
    for (const [shard, id] of entries.slice(0, count)) evtFact(current, 'active-reader-rules-' + String(shard).padStart(2, '0')).value.rule_event_ids = [id];
    if (count === 9) await events.validatePreconditions(event, current, evtHead(event));
    else await assert.rejects(events.validatePreconditions(event, current, evtHead(event)), events.PreconditionValidationError, 'count ' + count);
  }
  const wrongShard = evtClone(facts), [shard, id] = entries[0];
  evtFact(wrongShard, 'active-reader-rules-' + String((shard + 1) % 32).padStart(2, '0')).value.rule_event_ids = [id];
  await assert.rejects(events.validatePreconditions(event, wrongShard, evtHead(event)), events.PreconditionValidationError);
  const missing = evtClone(facts); missing.splice(missing.findIndex(row => row.name === 'active-reader-rules-31'), 1);
  await assert.rejects(events.validatePreconditions(event, missing, evtHead(event)), events.PreconditionValidationError);
  const prior = evtFact(facts, 'prior-generations'); prior.value.status_detail = eventRows.revocation.event_id;
  await events.validatePreconditions(event, facts, evtHead(event));
  prior.value.reader_authority = eventRows.revocation.event_id;
  await assert.rejects(events.validatePreconditions(event, facts, evtHead(event)), events.PreconditionValidationError);
});

async function evtContinuous(family) {
  const rule = eventRows[family + '_rule_configured'];
  const raw = evtClone(eventRows[family === 'exemption' ? 'exemption_source_withdrawn' : 'records_reader_withdrawn']);
  raw.target.source_event_id = rule.event_id; raw.target.subject.login_snapshot = 'renamed-after-first-add';
  const withdrawal = await evtSign(raw), firstRaw = evtClone(eventRows[family + '_materialized']);
  firstRaw.target.rule_event_id = rule.event_id;
  firstRaw.operation_nonce = await events.deriveAutomationNonce(rule.event_id, firstRaw.target.subject.github_user_id, firstRaw.payload.result, firstRaw.payload.prior_materialization_event_id);
  const first = await evtSign(firstRaw), facts = await evtFacts(withdrawal);
  evtFact(facts, 'source-event').value = evtLink(rule);
  const proof = evtFact(facts, 'source-first-add'); proof.value = { path: proof.path, present: true, event: first };
  return { rule, withdrawal, first, facts };
}
test('M1-15 historical continuous-source proof survives renames, departure, retirement and repeated withdrawal', async () => {
  for (const golden of eventCorpus.source_first_add_paths) {
    const { rule, withdrawal, first, facts } = await evtContinuous(golden.family), proof = evtFact(facts, 'source-first-add');
    assert.equal(first.operation_nonce, golden.operation_nonce); assert.equal(first.event_id, golden.event_id); assert.equal(proof.path, golden.path);
    assert.equal(rule.event_id, golden.source_event_id); assert.equal(withdrawal.project_id, golden.project_id); assert.equal(first.target.subject.github_user_id, golden.github_user_id);
    assert.notEqual(first.target.subject.login_snapshot, withdrawal.target.subject.login_snapshot);
    await events.validatePreconditions(withdrawal, facts, evtHead(withdrawal));
    const empty = evtClone(facts);
    if (golden.family === 'records_reader') {
      const authority = evtFact(empty, 'reader-authority-state'); authority.value.source_event_ids = [];
      assert.deepEqual(await events.requiredSideArtifacts(withdrawal, empty, evtHead(withdrawal)), []);
      await events.validateSideArtifactPackage(withdrawal, [], empty, evtHead(withdrawal));
      authority.value.class_state = 'stale'; authority.value.cursor_event_id = first.event_id; authority.binding.derived_generation = first.event_id;
      assert.deepEqual((await events.requiredSideArtifacts(withdrawal, empty, evtHead(withdrawal))).map(row => row.affected_classes), [['reader_authority']]);
      await events.validateSideArtifactPackage(withdrawal, await evtPackage(withdrawal, empty), empty, evtHead(withdrawal));
    } else {
      const union = empty.find(row => row.name.startsWith('current-exemption-union-')); union.value.subjects = []; union.value.provenance = {};
      await events.validatePreconditions(withdrawal, empty, evtHead(withdrawal));
    }
    for (const mutate of [
      row => { row.value = { path: row.path, present: false }; },
      row => { row.value.path += '.wrong'; },
      row => { row.value.extra = true; },
      row => { row.binding.events_head = 'c'.repeat(40); },
      row => { row.value.event.project_id = 'other-project'; },
      row => { row.value.event.target.subject.github_user_id += 1; },
      row => { row.value.event.payload.prior_materialization_event_id = rule.event_id; },
      row => { row.value.event.payload.result = 'withdraw'; },
      row => { row.value.event.payload.team.team_id += 1; },
    ]) {
      const bad = evtClone(facts); mutate(evtFact(bad, 'source-first-add'));
      await assert.rejects(events.validatePreconditions(withdrawal, bad, evtHead(withdrawal)), events.PreconditionValidationError);
    }
  }
  for (const row of eventCorpus.shrink_only_cases) {
    let event = evtClone(eventRows[row.event_type]);
    if (row.mutation === 'stale_departure') {
      event.payload.result = 'withdraw'; event.payload.membership_evidence.state = 'not_member';
      event.operation_nonce = await events.deriveAutomationNonce(event.target.rule_event_id, event.target.subject.github_user_id, 'withdraw', event.payload.prior_materialization_event_id); event = await evtSign(event);
    }
    const facts = await evtFacts(event), selected = evtFact(facts, row.event_type === 'records_reader_materialized' ? 'current-reader-authority' : 'reader-authority-state');
    selected.value.class_state = row.state;
    selected.value[row.event_type === 'records_reader_materialized' ? 'sources' : 'source_event_ids'] = row.source_present ? [event.target.source_event_id ?? event.target.rule_event_id] : [];
    if (row.state === 'stale') selected.binding.derived_generation = selected.value.cursor_event_id = eventRows.revocation.event_id;
    if (row.expect === 'defer') await assert.rejects(events.requiredSideArtifacts(event, facts, evtHead(event)), events.PreconditionValidationError, row.id);
    else {
      const requirements = await events.requiredSideArtifacts(event, facts, evtHead(event)); assert.equal(requirements.length > 0, row.expect === 'affected', row.id);
      await events.validateSideArtifactPackage(event, await evtPackage(event, facts), facts, evtHead(event));
    }
  }
});

test('M1-15 lifecycle policy and confirmed heads use the same shared mutation cases', async () => {
  for (const row of eventCorpus.head_binding_cases) {
    const event = eventRows[row.event_type], facts = await evtFacts(event);
    if (row.mutation === 'earlier_head') {
      const selected = evtFact(facts, 'project-lifecycle'); selected.binding.canonical_sha = 'c'.repeat(40);
    } else if (row.mutation === 'succeeded_lifecycle') Object.assign(evtFact(facts, 'project-lifecycle').value, { state: 'succeeded', successor_project_id: 'successor-project' });
    else assert.equal(row.mutation, 'confirmed_head');
    await assert.rejects(events.requiredSideArtifacts(event, facts, row.mutation === 'confirmed_head' ? 'b'.repeat(40) : evtHead(event)), events.PreconditionValidationError, row.id);
  }
  for (const row of eventCorpus.lifecycle_cases) {
    let event = evtClone(eventRows[row.event_type]), overrides = {};
    if (row.authorization_operation) {
      // Keep the complete event valid while testing the lifecycle-specific disposition.
      const fixture = authorizationCorpus.scope_cases.find(value => value.operation === row.authorization_operation), authorization = evtScopeAuthorization(fixture);
      event.authorizations = [authorization];
      if (event.type === 'enforcement_scope_requested') Object.assign(event.payload, { prior_scope: fixture.prior_scope, desired_scope: fixture.desired_scope });
      else {
        event.payload.desired_scope = fixture.desired_scope;
        overrides['scope-request'] = { event_id: event.payload.request_event_id, type: 'enforcement_scope_requested', project_id: event.project_id, target: { change_id: event.target.change_id }, payload: { prior_scope: fixture.prior_scope, desired_scope: fixture.desired_scope, prior_registry_generation: 0 }, authorizations: [authorization] };
      }
      event = await evtSign(event);
    }
    overrides['project-lifecycle'] = { project_id: event.project_id, state: row.state, successor_project_id: row.state === 'succeeded' ? 'successor-project' : null };
    const facts = await evtFacts(event, overrides);
    if (row.expect === 'accept') await assert.doesNotReject(events.validatePreconditions(event, facts, evtHead(event)), row.id);
    else await assert.rejects(events.validatePreconditions(event, facts, evtHead(event)), events.PreconditionValidationError, row.id);
  }
});

test('M1-15 closed nested event schemas reject extra fields, unsafe values and changed byte identities', async () => {
  const paths = value => {
    const result = [];
    function visit(item, path) {
      if (!item || typeof item !== 'object') return;
      if (!Array.isArray(item)) result.push(path);
      for (const [key, child] of Object.entries(item)) visit(child, [...path, key]);
    }
    visit(value, []); return result;
  };
  for (const event of eventCorpus.events) {
    for (const path of paths(event)) {
      const raw = evtClone(event); let item = raw;
      for (const key of path) item = item[key];
      Object.defineProperty(item, 'unknown_v1_member', { value: true, enumerable: true, writable: true });
      await assert.rejects(async () => events.validateEvent(await evtSign(raw)), events.EventValidationError, event.type + '/' + path.join('/'));
    }
    for (const key of Object.keys(event)) {
      const raw = evtClone(event); delete raw[key];
      await assert.rejects(events.validateEvent(raw), events.EventValidationError, event.type + '/' + key);
    }
    await assert.rejects(events.validateEvent(event, { expectedProjectId: 'other' }), events.EventValidationError);
    await assert.rejects(events.validateEvent(event, { expectedPath: events.eventPath(eventRows.project_connected.event_id) + '.wrong' }), events.EventValidationError);
  }
  const invalidUrls = ['https:example.test', 'https:///example.test', 'https://exa mple.test/path', 'https://example.test/%ZZ', 'https://example.test/foo\\bar', 'https://example.test/\npath', 'https://', 'https://:443/path', 'https://[bad]/path', 'https://example.test:bad/path', 'https://example.test:65536/path', 'https://example.test:/path', 'http://example.test', 'https://user:secret@example.test'];
  for (const url of invalidUrls) {
    const raw = evtClone(eventRows.config_updated); raw.payload.project_configuration.privacy_policy_url = url;
    await assert.rejects(events.validateEvent(await evtSign(raw)), events.EventValidationError, url);
  }
  for (const value of [true, '1', 0, 2, 1.1]) {
    const raw = evtClone(eventRows.config_updated); raw.schema_version = value;
    await assert.rejects(events.validateEvent(raw), events.EventValidationError);
  }
  for (const value of [null, [], 'event', Object.assign({}, { secret_marker: 'M1-15-private-input' }), { get type() { throw Error('must not invoke accessor'); } }]) await assert.rejects(events.validateEvent(value), events.EventValidationError);
  for (const value of ['', 'bad', 'AA=', 'a'.repeat(43)]) assert.throws(() => events.eventPath(value), events.EventIdentityError);
  assert.throws(() => events.stableActorIdentity({ kind: 'automation', principal: 'unknown' }), events.EventIdentityError);
  for (const call of [() => events.deriveAutomationNonce('', 7, 'add', null), () => events.deriveAutomationNonce('rule', false, 'add', null), () => events.deriveAutomationNonce('rule', 7, 'other', null), () => events.deriveGithubRetryNonce(1, 'other', 1, null), () => events.deriveGithubRetryNonce(1, 'merge_group', 'bad', null), () => events.deriveScopeTerminalNonce('request', 'other')]) await assert.rejects(call(), events.EventIdentityError);
  const base = eventIdentities.event_identity, input = { ...Object.fromEntries(['project_id', 'operation_nonce', 'actor', 'target', 'payload', 'confirmed_canonical_oid'].map(key => [key, evtClone(base[key])])), type: base.event_type };
  const changed = await events.deriveEventIdentity({ ...input, payload: eventIdentities.changed_payload.changed_payload });
  assert.equal(changed.event_id, base.event_id); assert.equal(changed.idempotency_key, base.idempotency_key); assert.notEqual(changed.operation_sha256, base.operation_sha256);
});

test('M1-15 URL acceptance preserves the non-normalizing Python configuration contract', async () => {
  const accepted = [
    'https://example.test/\ufeffpath', 'https://127.0.0.999/path', 'https://%00.example/path',
    'https://[v1.foo]/path', 'https://example.test/path', 'HTTPS://example.test:000443/path',
    'https://@example.test/path', 'https://:@example.test/path', 'https://[::1]:0/path',
    'https://[::ffff:192.168.1.1]/path', 'https://[fe80::1%25zone]/path',
    'https://例え.test/path', 'https://example.test:65535/path',
  ];
  const rejected = [
    'https://example.test/\u0085path', 'https://example.test/\u001cpath',
    ...['\u00a0', '\u1680', '\u2000', '\u200a', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000'].map(c => 'https://example.test/' + c),
    'https://example.test：443/path', 'https://example.test／path',
    'https://user@example.test', 'https://:password@example.test', 'https://@@example.test',
    'https://[V1.foo]/path', 'https://[v.foo]/path', 'https://[v1.]/path',
    'https://[127.0.0.1]/path', 'https://[::ffff:192.168.001.1]/path',
    'https://[::1%25zone%25other]/path', 'https://[::1]extra/path', 'https://host[::1]/path',
    'https://[::1]]/path', 'https://[::1]:/path', 'https://[::1]:65536/path',
    'https://example.test:１２/path', 'https://example.test:1:2/path',
  ];
  for (const [urls, valid] of [[accepted, true], [rejected, false]]) {
    for (const url of urls) {
      const raw = evtClone(eventRows.config_updated);
      raw.payload.project_configuration.privacy_policy_url = url;
      const event = await evtSign(raw);
      if (valid) {
        const validated = await events.validateEvent(event);
        assert.equal(validated.payload.project_configuration.privacy_policy_url, url);
      } else await assert.rejects(events.validateEvent(event), events.EventValidationError, url);
    }
  }
});

test('M1-15 correction evidence, registry transitions and union effects remain fully bound', async () => {
  const raw = evtClone(eventRows.acceptance); raw.payload.supersedes = raw.event_id; const correction = await evtSign(raw);
  const correctionFacts = await evtFacts(correction); await events.validatePreconditions(correction, correctionFacts, evtHead(correction));
  for (const [name, path, value] of [
    ['superseded-acceptance', ['target', 'version'], 'other'], ['superseded-acceptance', ['event_id'], eventRows.revocation.event_id],
    ['current-acceptance-basis', ['basis', 'event_id'], eventRows.revocation.event_id], ['current-acceptance-basis', ['github_user_id'], 8],
    ['active-agreement', ['publication', 'payload', 'digest'], 'sha256:' + 'b'.repeat(64)], ['current-configuration', ['confirmation_labels'], []],
  ]) {
    const facts = evtClone(correctionFacts); let row = evtFact(facts, name).value;
    for (const key of path.slice(0, -1)) row = row[key]; row[path.at(-1)] = value;
    await assert.rejects(events.validatePreconditions(correction, facts, evtHead(correction)), events.PreconditionValidationError, name + '/' + path.join('/'));
  }
  const withdrawing = eventRows.exemption_rule_withdrawn, facts = await evtFacts(withdrawing);
  assert.deepEqual((await events.requiredSideArtifacts(withdrawing, facts, evtHead(withdrawing)))[0].affected_classes, ['derived_index', 'status_detail']);
  const union = facts.find(row => row.name.startsWith('current-exemption-union-') && row.value.subjects.length);
  union.value.provenance[String(union.value.subjects[0].github_user_id)].push(eventRows.exemption.event_id);
  assert.deepEqual((await events.requiredSideArtifacts(withdrawing, facts, evtHead(withdrawing)))[0].affected_classes, ['status_detail']);
  await events.validateSideArtifactPackage(withdrawing, await evtPackage(withdrawing, facts), facts, evtHead(withdrawing));
  const restored = eventRows.agreement_activation_restored, restoreFacts = await evtFacts(restored);
  await events.validateSideArtifactPackage(restored, [], restoreFacts, evtHead(restored));
  for (const event of [eventRows.project_repository_owner_changed, eventRows.enforcement_scope_requested, eventRows.enforcement_scope_activated, eventRows.enforcement_scope_abandoned]) {
    const original = await evtFacts(event), name = event.type === 'project_repository_owner_changed' ? 'current-repository-owner' : 'current-scope';
    for (const entryName of Object.keys(evtFact(original, name).value)) {
      const bad = evtClone(original); evtFact(bad, name).value[entryName].project_id = 'other';
      await assert.rejects(events.validatePreconditions(event, bad, evtHead(event)), events.PreconditionValidationError);
    }
  }
  const materialized = eventRows.records_reader_materialized, materializedFacts = await evtFacts(materialized);
  evtFact(materializedFacts, 'current-reader-authority').value.source_record_present = false;
  await assert.rejects(events.validatePreconditions(materialized, materializedFacts, evtHead(materialized)), events.PreconditionValidationError);
  const malformed = evtClone(restoreFacts); malformed[0].binding_mode = 'unknown'; malformed[0].binding.mode = 'unknown';
  await assert.rejects(events.validatePreconditions(restored, malformed, evtHead(restored)), events.PreconditionValidationError);
});

test('M1-15 async validation owns caller event, authenticated facts and artifact bytes', async () => {
  const raw = evtClone(eventRows.config_updated), expected = evtClone(raw);
  const pending = events.validateEvent(raw); raw.project_id = 'changed'; raw.payload.project_configuration.retention_statement = 'changed';
  const event = await pending; assert.deepEqual(event, expected); assert.ok(Object.isFrozen(event.payload.project_configuration.required_fields));
  const facts = await evtFacts(expected), packageValue = await evtPackage(expected, facts);
  const validation = events.validateSideArtifactPackage(expected, packageValue, facts, evtHead(expected));
  expected.payload.project_configuration.retention_statement = 'changed'; facts[0].value.project_id = 'changed'; packageValue[0].bytes.fill(0); packageValue[0].path = 'changed';
  await validation;
  const source = evtClone(eventRows.config_updated), originalFacts = await evtFacts(source), checks = events.validatePreconditions(source, originalFacts, evtHead(source));
  source.project_id = 'changed'; originalFacts[0].value.project_id = 'changed';
  const result = await checks; assert.ok(Object.isFrozen(result[0].value)); assert.equal(result[0].value.project_id, 'project-1');
  const valid = eventRows.project_connected, validFacts = await evtFacts(valid), validPackage = await evtPackage(valid, validFacts);
  for (const change of [row => { row.sha256 = 'sha256:' + '0'.repeat(64); }, row => { row.bytes = bytes('{'); row.sha256 = evtHash(row.bytes); }, row => { row.extra = true; }, row => { row.bytes_b64 = 'e30'; }, row => { row.bytes = 'not bytes'; }]) {
    const invalid = evtClone(validPackage); change(invalid[0]);
    await assert.rejects(events.validateSideArtifactPackage(valid, invalid, validFacts, evtHead(valid)), events.SideArtifactValidationError);
  }
  const invalidB64 = evtClone(validPackage).map(({ bytes, ...row }) => ({ ...row, bytes_b64: '!' }));
  await assert.rejects(events.validateSideArtifactPackage(valid, invalidB64, validFacts, evtHead(valid)), events.SideArtifactValidationError);
});

const formCorpus = await vector('action-form-v1.json');
const formKeys = () => new Map(formCorpus.keys.map(row => [row.kid, unhex(row.key_hex)]));
const formContext = (form, changes = {}) => ({ ...Object.fromEntries([
  'session_jti', 'github_user_id', 'project_id', 'type', 'operation_nonce', 'confirmed_canonical_oid', 'operation_sha256',
].map(k => [k, form[k]])), ...formCorpus.context, ...changes });
const formSignBytes = (data, key = unhex(formCorpus.keys[0].key_hex)) => encoding.base64urlEncode(data) + '.'
  + createHmac('sha256', key).update(unhex(formCorpus.domain_hex)).update(data).digest('base64url');
const uncheckedWire = value => {
  const sorted = value => Array.isArray(value) ? value.map(sorted) : value !== null && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])])) : value;
  return bytes(JSON.stringify(sorted(value)));
};
const formSign = form => formSignBytes(uncheckedWire(form));
const formVerify = (form, changes = {}) => actionForms.verifyActionForm(formSign(form), { keys: formKeys(), context: formContext(form, changes) });
async function formBind(form, operation) {
  const identity = await events.deriveEventIdentity({ project_id: form.project_id, operation_nonce: form.operation_nonce,
    actor: { kind: 'github', github_user_id: form.github_user_id, login_snapshot: 'current-login' }, type: form.type,
    target: operation.target, payload: operation.payload,
    confirmed_canonical_oid: ['acceptance', 'revocation'].includes(form.type) ? form.confirmed_canonical_oid : null });
  return { ...form, operation_sha256: identity.operation_sha256 };
}

test('M1-16 fixed form bytes, all 24 action rows and every terminal alternative', async () => {
  const golden = formCorpus.golden;
  assert.equal(hex(wire(golden.form)), hex(bytes(golden.payload_jcs)));
  assert.equal(await actionForms.encodeActionForm(golden.form, { key: unhex(formCorpus.keys[0].key_hex) }), golden.token);
  assert.equal(hex(encoding.base64urlDecode(golden.token.split('.')[1])), golden.tag_hex);
  assert.deepEqual([...actionForms.FORM_ACTION_TYPES].sort(), formCorpus.actions.map(row => row.type).sort());
  assert.equal(formCorpus.actions.length, 24); assert.equal(formCorpus.terminal_noops.length, 24);
  for (const row of formCorpus.actions) {
    assert.deepEqual(actionForms.formActionSpec(row.type), { action_type: row.type, write_type: row.write_type, terminal_types: row.terminal_types });
    const form = { ...golden.form, type: row.type }, result = await formVerify(form);
    assert.equal(result.isNoop, false); assert.equal(result.preparable, true);
    await assert.rejects(formVerify(form, { confirmed_canonical_oid: formCorpus.later_head }), actionForms.ActionFormError);
  }
  for (const type of [...events.EVENT_TYPES.filter(type => !actionForms.FORM_ACTION_TYPES.includes(type)), '', 'Acceptance', null, 7, {}])
    assert.throws(() => actionForms.formActionSpec(type), actionForms.ActionFormError);
  for (const row of formCorpus.terminal_noops) {
    const result = await actionForms.verifyActionForm(row.token, { keys: formKeys(), context: formContext(row.form, { confirmed_canonical_oid: formCorpus.later_head }) });
    assert.equal(result.isNoop, true, row.id); assert.equal(result.preparable, false, row.id);
    const terminal = eventRows[row.terminal_fixture_type], options = { expectedProjectId: row.form.project_id, expectedConfirmedOid: row.form.confirmed_canonical_oid };
    await actionForms.validateTerminalNoop(result, terminal, row.operation, options);
    await actionForms.validateTerminalNoop(result, wire(terminal), row.operation, options);
  }
});

test('M1-16 strict form encodings and authenticated closed payload rejection', async () => {
  const golden = formCorpus.golden, form = golden.form, [part, tag] = golden.token.split('.');
  for (const bad of [null, 1, '', part, part + '..' + tag, part + '.' + tag + '.', part + '=.' + tag,
    part + '.' + tag + '=', 'A.' + tag, part + '.AA', golden.token + '\n', part + '.' + encoding.base64urlEncode(new Uint8Array(32))])
    await assert.rejects(actionForms.verifyActionForm(bad, { keys: formKeys(), context: formContext(form) }), actionForms.ActionFormError);
  const malformed = [bytes(' ' + golden.payload_jcs), bytes(golden.payload_jcs.replace('"v":1', '"v":1,"v":1')),
    bytes(golden.payload_jcs.replace('"v":1', '"v":1.0')), new Uint8Array([255])];
  for (const data of malformed) await assert.rejects(actionForms.verifyActionForm(formSignBytes(data), { keys: formKeys(), context: formContext(form) }), actionForms.ActionFormError);
  const changes = [{ v: 2 }, { v: true }, { algorithm: 'HS512' }, { kid: 'bad' }, { session_jti: '' }, { github_user_id: 0 },
    { github_user_id: true }, { github_user_id: 2 ** 53 }, { project_id: '' }, { type: 'enforcement_scope_activated' },
    { operation_nonce: 'bad' }, { confirmed_canonical_oid: 'A'.repeat(40) },
    { confirmed_canonical_oid: form.confirmed_canonical_oid + '\n' }, { operation_sha256: form.operation_sha256 + '\n' }, { operation_sha256: 'sha256:BAD' },
    { terminal_noop_event_id: '' }, { terminal_noop_event_id: eventRows.config_updated.event_id, type: 'retry_requested' },
    { issued_at: '0000-01-02T12:00:00Z' }, { expires_at: '2026-02-30T12:00:00Z' }, { expires_at: '2026-01-02T19:55:01Z' },
    { expires_at: '2026-01-02T11:59:59Z' }, { unexpected: true }];
  for (const change of changes) {
    const value = { ...form, ...change };
    await assert.rejects(actionForms.encodeActionForm(value, { key: unhex(formCorpus.keys[0].key_hex) }), actionForms.ActionFormError, JSON.stringify(change));
    await assert.rejects(actionForms.verifyActionForm(formSign(value), { keys: formKeys(), context: formContext(form) }), actionForms.ActionFormError);
  }
  for (const field of Object.keys(form)) {
    const value = { ...form }; delete value[field];
    await assert.rejects(actionForms.encodeActionForm(value, { key: unhex(formCorpus.keys[0].key_hex) }), actionForms.ActionFormError, field);
  }
});

test('M1-16 eligible keys, exact context and lifetime boundaries use native HMAC verification', async () => {
  const form = formCorpus.golden.form;
  const predecessor = { ...form, kid: formCorpus.keys[1].kid }, token = formSignBytes(wire(predecessor), unhex(formCorpus.keys[1].key_hex));
  await actionForms.verifyActionForm(token, { keys: formKeys(), context: formContext(predecessor) });
  await assert.rejects(actionForms.verifyActionForm(token, { keys: new Map([[form.kid, unhex(formCorpus.keys[0].key_hex)]]), context: formContext(predecessor) }), actionForms.ActionFormError);
  for (const key of [new Uint8Array(), 'secret', null]) await assert.rejects(actionForms.encodeActionForm(form, { key }), actionForms.ActionFormError);
  for (const keys of [new Map(), {}, null]) await assert.rejects(actionForms.verifyActionForm(formCorpus.golden.token, { keys, context: formContext(form) }), actionForms.ActionFormError);
  const changes = { session_jti: 'another-session', github_user_id: form.github_user_id + 1, project_id: 'other-project', type: 'acceptance',
    operation_nonce: encoding.base64urlEncode(new Uint8Array(16)), operation_sha256: 'sha256:' + 'f'.repeat(64), confirmed_canonical_oid: formCorpus.later_head };
  for (const [field, value] of Object.entries(changes)) await assert.rejects(formVerify(form, { [field]: value }), actionForms.ActionFormError, field);
  for (const changes of [{ current_time: '2026-01-02T11:59:59Z' }, { current_time: form.expires_at },
    { session_expires_at: '2026-01-02T19:54:59Z' }, { current_time: '2026-01-02T12:00:00.000Z' }])
    await assert.rejects(formVerify(form, changes), actionForms.ActionFormError);
  await formVerify(form, { current_time: form.issued_at }); await formVerify(form, { current_time: '2026-01-02T19:54:59Z' });
  const original = crypto.subtle.verify, calls = [];
  crypto.subtle.verify = function (...args) { calls.push(args[0]); return original.apply(this, args); };
  try {
    await formVerify(form);
    await assert.rejects(actionForms.verifyActionForm(formSignBytes(wire(form), new Uint8Array(32).fill(71)), { keys: formKeys(), context: formContext(form) }), actionForms.ActionFormError);
    assert.deepEqual(calls, ['HMAC', 'HMAC']);
  } finally { crypto.subtle.verify = original; }
});

test('M1-16 terminal proofs require authenticated factory, exact immutable read and complete desired effect', async () => {
  const row = formCorpus.terminal_noops.find(row => row.action_type === 'config_updated');
  const verified = await formVerify(row.form, { confirmed_canonical_oid: formCorpus.later_head });
  const terminal = eventRows.config_updated, options = { expectedProjectId: row.form.project_id, expectedConfirmedOid: row.form.confirmed_canonical_oid };
  for (const forged of [{ ...verified }, { form: row.form, isNoop: true, preparable: false }, await formVerify(formCorpus.golden.form)])
    await assert.rejects(actionForms.validateTerminalNoop(forged, terminal, row.operation, options), actionForms.ActionFormError);
  for (const change of [{ expectedProjectId: 'another' }, { expectedConfirmedOid: formCorpus.later_head }])
    await assert.rejects(actionForms.validateTerminalNoop(verified, terminal, row.operation, { ...options, ...change }), actionForms.ActionFormError);
  for (const event of [{ event_id: terminal.event_id }, { ...terminal, extra: true }, eventRows.acceptance, bytes(' ' + new TextDecoder().decode(wire(terminal)))])
    await assert.rejects(actionForms.validateTerminalNoop(verified, event, row.operation, options), actionForms.ActionFormError);
  for (const operation of [{ ...row.operation, extra: true }, { ...row.operation, target: { extra: true } },
    { ...row.operation, payload: { ...row.operation.payload, extra: true } }])
    await assert.rejects(actionForms.validateTerminalNoop(verified, terminal, operation, options), actionForms.ActionFormError);
  const changed = evtClone(row.operation); changed.payload.project_configuration.retention_statement = 'Different valid retained effect.';
  const changedForm = await formBind(row.form, changed), changedResult = await formVerify(changedForm);
  await assert.rejects(actionForms.validateTerminalNoop(changedResult, terminal, changed, options), actionForms.ActionFormError);
  const acceptance = formCorpus.terminal_noops.find(row => row.action_type === 'acceptance');
  for (const mutate of [op => op.target.coverage_tuple.github_user_id++, op => op.target.coverage_tuple.project_id = 'other',
    op => op.target.recipient.recipient_id = 'other']) {
    const op = evtClone(acceptance.operation); mutate(op); const form = await formBind(acceptance.form, op);
    await assert.rejects(actionForms.validateTerminalNoop(await formVerify(form), eventRows.acceptance, op,
      { expectedProjectId: form.project_id, expectedConfirmedOid: form.confirmed_canonical_oid }), actionForms.ActionFormError);
  }
});

test('M1-16 forms own caller payloads, keys, contexts and terminal inputs before await', async () => {
  const input = evtClone(formCorpus.golden.form), key = unhex(formCorpus.keys[0].key_hex);
  const encoded = actionForms.encodeActionForm(input, { key }); input.project_id = 'changed'; key.fill(255);
  assert.equal(await encoded, formCorpus.golden.token);
  const context = formContext(formCorpus.golden.form), keys = formKeys(), pending = actionForms.verifyActionForm(formCorpus.golden.token, { keys, context });
  keys.get(formCorpus.golden.form.kid).fill(255); keys.clear(); context.project_id = 'changed';
  const result = await pending; assert.ok(Object.isFrozen(result) && Object.isFrozen(result.form));
  assert.throws(() => result.form.project_id = 'changed', TypeError);
  const row = formCorpus.terminal_noops.find(row => row.action_type === 'config_updated'), verified = await formVerify(row.form);
  const event = evtClone(eventRows.config_updated), op = evtClone(row.operation), options = { expectedProjectId: row.form.project_id, expectedConfirmedOid: row.form.confirmed_canonical_oid };
  const proof = actionForms.validateTerminalNoop(verified, event, op, options);
  event.payload.project_configuration = {}; op.payload.project_configuration = {}; options.expectedProjectId = 'changed'; await proof;
});

const opLimit = operations.profile.max_prepared_operation_bytes, opHead = operations.cells.prepared.prepared_events_head;
const opEvent = parse(encoding.base64urlDecode(operations.cells.prepared.event_jcs_b64)), opFacts = await evtFacts(opEvent);
const opDecodeOptions = { expectedProjectId: operations.project_id, maxPreparedOperationBytes: opLimit, preconditions: opFacts };
const opCells = Object.fromEntries(await Promise.all(Object.entries(operations.cells).map(async ([name, row]) => [name, await operationState.decodePreparedOperation(wire(row), opDecodeOptions)])));
const opFences = Object.fromEntries(await Promise.all(Object.entries(operations.fences).map(async ([name, row]) => [name, await operationState.decodeDecisionFence(wire(row))])));
const opMarkers = Object.fromEntries(await Promise.all(Object.entries(operations.markers).map(async ([name, row]) => [name, await operationState.decodeInflightMarker(wire(row))])));
const opRef = operationState.preparedOperationReference('d'.repeat(40), 'e'.repeat(40), opCells.prepared);
const opOwner = { operationId: opEvent.idempotency_key, operationSha256: opEvent.operation_sha256 };
const opBindings = { fence: opFences.mutation, marker: opMarkers.open, preparedReference: opRef };
const opPrepare = (cell, changes = {}) => operationState.prepareOperation(cell, opEvent, operations.cells.prepared.side_artifacts,
  { expectedProjectId: operations.project_id, expectedEventsHead: opHead, preconditions: opFacts, maxPreparedOperationBytes: opLimit, ...changes });
const opClaim = (cell, changes = {}) => operationState.claimAppend(cell, { ...opOwner, ...opBindings, appendHead: opHead, maxPreparedOperationBytes: opLimit, ...changes });
const opTerminal = (cell, result = 'semantic_noop', changes = {}) => operationState.terminalOperation(cell, { ...opOwner, ...opBindings,
  marker: result === 'landed' ? opMarkers.empty : opMarkers.open, result, observedEventsHead: 'c'.repeat(40), canonicalCommit: result === 'landed' ? 'c'.repeat(40) : null,
  projectionVerified: result === 'landed', readbackVerified: result === 'landed', ...changes });
const opRelease = (cell, changes = {}) => operationState.releaseMutationFence(changes.fence ?? opFences.mutation, opFences.mutation, cell, changes.marker ?? opMarkers.empty,
  { preparedReference: opRef, projectionVerified: true, readbackVerified: true, ...changes });
const opClear = (cell, changes = {}) => operationState.clearPreparedOperation(cell, opCells.landed,
  { mutationFence: opFences.mutation, releasedFence: opFences.released, marker: opMarkers.empty, preparedReference: opRef, ...changes });

test('M1-16 independent operation hash and complete state wire goldens', async () => {
  const claim = operations.append_claim, identity = operations.check_identity;
  assert.equal(await operationState.appendClaim(claim.input.operation_id, claim.input.operation_sha256, claim.input.append_head), claim.expected);
  assert.equal(await operationState.authoritativeCheckIdentity(identity.input), identity.expected);
  for (const [name, cell] of Object.entries(opCells)) assert.equal(hex(operationState.encodePreparedOperation(cell, { maxPreparedOperationBytes: opLimit })), hex(wire(operations.cells[name])), name);
  for (const [name, fence] of Object.entries(opFences)) assert.equal(hex(operationState.encodeDecisionFence(fence)), hex(wire(operations.fences[name])), name);
  for (const [name, marker] of Object.entries(opMarkers)) assert.equal(hex(operationState.encodeInflightMarker(marker)), hex(wire(operations.markers[name])), name);
  assert.deepEqual((await opPrepare(opCells.idle)).toDict(), operations.cells.prepared);
  for (const name of ['prepared', 'appending', 'landed', 'semantic_noop', 'conflict']) assert.equal(await opPrepare(opCells[name]), opCells[name], name);
  assert.deepEqual((await opClaim(opCells.prepared)).toDict(), operations.cells.appending);
  assert.equal(await opClaim(opCells.appending), opCells.appending);
  await assert.rejects(opClaim(opCells.appending, { appendHead: 'a'.repeat(40) }), operationState.OperationConflict);
  const renewed = await opClaim(opCells.appending, { appendHead: 'a'.repeat(40), expectedAppendClaim: operations.cells.appending.append_claim });
  assert.equal(renewed.toDict().append_claim, await operationState.appendClaim(opOwner.operationId, opOwner.operationSha256, 'a'.repeat(40)));
  assert.equal(renewed.toDict().event_jcs_b64, operations.cells.prepared.event_jcs_b64);
});

test('M1-16 every persisted crash tuple accepts exactly its legal transitions, without age recovery', async () => {
  for (const row of operations.crashes) {
    const cell = opCells[row.cell], fence = opFences[row.fence], marker = opMarkers[row.marker], binding = { fence, marker };
    operationState.validateOperationCrossBindings(cell, fence, marker, { preparedReference: opRef });
    const actions = {
      prepare: () => opPrepare(cell),
      acquire: () => operationState.acquireMutationFence(fence, cell, opRef, { subjects: [], projectWide: true }),
      reserve: () => operationState.reserveSuccess(fence, marker, { checkIdentity: operations.check_identity.expected, projectionCommit: opHead }),
      open: () => operationState.openInflightMarker(marker, fence, { cell, preparedReference: opRef, startedAt: '2099-01-01T00:00:00Z' }),
      claim: () => opClaim(cell, binding), noop: () => opTerminal(cell, 'semantic_noop', binding), conflict: () => opTerminal(cell, 'conflict', binding),
      landed: () => opTerminal(cell, 'landed', binding),
      close: () => operationState.closeInflightMarker(marker, fence, { cell, preparedReference: opRef }),
      close_projected: () => operationState.closeInflightMarker(marker, fence, { cell, preparedReference: opRef, projectionVerified: true }),
      release: () => opRelease(cell, binding), clear: () => opClear(cell, { releasedFence: fence, marker }),
      release_success: () => operationState.releaseSuccess(fence, opFences.success, { completionVerified: true }),
    };
    const allowed = [];
    for (const [name, action] of Object.entries(actions)) {
      try { await action(); allowed.push(name); }
      catch (error) { assert.ok(error instanceof operationState.OperationConflict || error instanceof operationState.OperationCorruption, `${row.id}/${name}: ${error}`); }
    }
    assert.deepEqual(allowed.sort(), [...row.allowed].sort(), row.id);
  }
});

test('M1-16 marker first-start time, terminal release, success reservation and exact clear retry', async () => {
  const acquired = await operationState.acquireMutationFence(opFences.idle, opCells.prepared, opRef, { subjects: [], projectWide: true });
  assert.deepEqual(acquired.toDict(), operations.fences.mutation);
  const open = await operationState.openInflightMarker(opMarkers.empty, acquired, { cell: opCells.prepared, preparedReference: opRef, startedAt: operations.markers.open.ops[opOwner.operationId].started_at });
  assert.deepEqual(open.toDict(), operations.markers.open);
  assert.equal(await operationState.openInflightMarker(open, acquired, { cell: opCells.prepared, preparedReference: opRef, startedAt: '2099-01-01T00:00:00Z' }), open);
  const noop = opTerminal(opCells.prepared), closed = operationState.closeInflightMarker(open, acquired, { cell: noop, preparedReference: opRef });
  const released = operationState.releaseMutationFence(acquired, acquired, noop, closed, { preparedReference: opRef, projectionVerified: false, readbackVerified: true });
  assert.deepEqual(released.toDict(), operations.fences.released);
  assert.equal(operationState.releaseMutationFence(released, acquired, noop, closed, { preparedReference: opRef, projectionVerified: false, readbackVerified: true }), released);
  const cleared = operationState.clearPreparedOperation(noop, noop, { mutationFence: acquired, releasedFence: released, marker: closed, preparedReference: opRef });
  assert.deepEqual(cleared.toDict(), operations.cells.idle);
  assert.equal(operationState.clearPreparedOperation(cleared, noop, { mutationFence: acquired, releasedFence: released, marker: closed, preparedReference: opRef }), cleared);
  const reserved = await operationState.reserveSuccess(opFences.idle, opMarkers.empty, { checkIdentity: operations.check_identity.expected, projectionCommit: opHead });
  assert.equal(await operationState.reserveSuccess(reserved, opMarkers.empty, { checkIdentity: operations.check_identity.expected, projectionCommit: opHead }), reserved);
  assert.throws(() => operationState.releaseSuccess(reserved, reserved, { completionVerified: false }), operationState.OperationConflict);
  assert.equal(operationState.releaseSuccess(reserved, reserved, { completionVerified: true }).generation, reserved.generation + 1);
  assert.throws(() => opTerminal(opCells.prepared, 'semantic_noop', { marker: opMarkers.empty }), operationState.OperationConflict);
  assert.throws(() => opTerminal(opCells.appending, 'semantic_noop'), operationState.OperationConflict);
  assert.throws(() => opTerminal(opCells.appending, 'landed', { projectionVerified: false }), operationState.OperationConflict);
  assert.throws(() => opRelease(opCells.landed, { readbackVerified: false }), operationState.OperationConflict);
  assert.throws(() => opClear(opCells.landed, { releasedFence: opFences.idle }), operationState.OperationConflict);
});

test('M1-16 closed operation schemas reject every missing/extra field and malformed scalar', async () => {
  const groups = [[operations.cells, row => operationState.decodePreparedOperation(wire(row), opDecodeOptions)],
    [operations.fences, row => operationState.decodeDecisionFence(wire(row))], [operations.markers, row => operationState.decodeInflightMarker(wire(row))]];
  for (const [group, decode] of groups) for (const [name, row] of Object.entries(group)) {
    for (const field of Object.keys(row)) { const value = evtClone(row); delete value[field]; await assert.rejects(decode(value), operationState.OperationCorruption, `${name}/${field}`); }
    await assert.rejects(decode({ ...row, extra: true }), operationState.OperationCorruption, name);
  }
  for (const changes of [{ state: 'old' }, { generation: true }, { generation: -1 }, { generation: 2 ** 53 },
    { operation_id: 'bad' }, { operation_sha256: 'sha256:BAD' }, { event_id: '' }, { prepared_events_head: 'G'.repeat(40) },
    { event_jcs_b64: 'A' }, { side_artifacts: {} }])
    await assert.rejects(operationState.decodePreparedOperation(uncheckedWire({ ...operations.cells.prepared, ...changes }), opDecodeOptions), operationState.OperationCorruption);
  for (const result of ['', 'LANDED', true, 7, null]) await assert.rejects(operationState.decodePreparedOperation(wire({ ...operations.cells.landed, result }), opDecodeOptions), operationState.OperationCorruption);
  for (const data of [null, {}, '{}']) {
    await assert.rejects(operationState.decodePreparedOperation(data, opDecodeOptions), operationState.OperationCorruption);
    await assert.rejects(operationState.decodeDecisionFence(data), operationState.OperationCorruption);
    await assert.rejects(operationState.decodeInflightMarker(data), operationState.OperationCorruption);
  }
  for (const data of [bytes(' {"state":"idle","generation":1}'), bytes('{"generation":1,"state":"idle","state":"idle"}')])
    await assert.rejects(operationState.decodePreparedOperation(data, opDecodeOptions), operationState.OperationCorruption);
});

test('M1-16 frozen packages, exact references, owners and derived event scopes cannot be substituted', async () => {
  for (const mutate of [row => row.event_id = encoding.base64urlEncode(new Uint8Array(32)), row => row.operation_sha256 = 'sha256:' + 'f'.repeat(64),
    row => row.side_artifacts[0].bytes_b64 = encoding.base64urlEncode(bytes('{}')), row => row.side_artifacts.pop(),
    row => row.side_artifacts[0].extra = true, row => row.prepared_events_head = 'a'.repeat(40)]) {
    const row = evtClone(operations.cells.prepared); mutate(row);
    await assert.rejects(operationState.decodePreparedOperation(wire(row), opDecodeOptions), operationState.OperationCorruption);
  }
  const wrongRef = operationState.preparedOperationReference('a'.repeat(40), 'e'.repeat(40), opCells.prepared);
  for (const preparedReference of [wrongRef, { ...opRef }, undefined])
    assert.throws(() => operationState.validateOperationCrossBindings(opCells.prepared, opFences.mutation, opMarkers.open, { preparedReference }), operationState.OperationCorruption);
  for (const change of [{ operation_id: encoding.base64urlEncode(new Uint8Array(32)) }, { prepared_blob_sha: 'a'.repeat(40) },
    { prepared_generation: opCells.prepared.generation + 1 }, { subjects: [7], project_wide: false }]) {
    const fence = await operationState.decodeDecisionFence(wire({ ...operations.fences.mutation, ...change }));
    assert.throws(() => operationState.validateOperationCrossBindings(opCells.prepared, fence, opMarkers.empty, { preparedReference: opRef }), operationState.OperationCorruption);
  }
  await assert.rejects(operationState.acquireMutationFence(opFences.idle, opCells.prepared, opRef, { subjects: [7], projectWide: false }), operationState.OperationCorruption);
  for (const type of ['acceptance', 'override', 'exemption_snapshot', 'records_reader_authorized']) {
    let event = evtClone(eventRows[type]);
    if (type === 'override') event.payload.subjects.push({ github_user_id: 9, login_snapshot: 'second' });
    if (type === 'exemption_snapshot') event.target.subjects.push({ github_user_id: 9, login_snapshot: 'second' });
    event = await evtSign(event);
    const facts = await evtFacts(event), artifacts = await evtPackage(event, facts), head = evtHead(event);
    const prepared = await operationState.prepareOperation(opCells.idle, event, artifacts, { expectedProjectId: event.project_id, expectedEventsHead: head, preconditions: facts, maxPreparedOperationBytes: opLimit });
    const reference = operationState.preparedOperationReference('d'.repeat(40), 'e'.repeat(40), prepared);
    const subjects = type === 'override' || type === 'exemption_snapshot' ? [7, 9] : [7];
    await operationState.acquireMutationFence(opFences.idle, prepared, reference, { subjects, projectWide: false });
    await assert.rejects(operationState.acquireMutationFence(opFences.idle, prepared, reference, { subjects: [], projectWide: true }), operationState.OperationCorruption);
  }
});

test('M1-16 complete byte limits include worst append head; generation and scalar overflow fail closed', async () => {
  const raw = wire(operations.cells.prepared), limit = raw.length;
  await operationState.decodePreparedOperation(raw, { ...opDecodeOptions, maxPreparedOperationBytes: limit });
  await assert.rejects(operationState.decodePreparedOperation(raw, { ...opDecodeOptions, maxPreparedOperationBytes: limit - 1 }), operationState.OperationCorruption);
  await assert.rejects(opPrepare(opCells.idle, { maxPreparedOperationBytes: limit }), operationState.OperationCorruption);
  await assert.rejects(opClaim(opCells.prepared, { maxPreparedOperationBytes: limit }), operationState.OperationCorruption);
  assert.throws(() => operationState.encodePreparedOperation(opCells.prepared, { maxPreparedOperationBytes: limit - 1 }), operationState.OperationCorruption);
  for (const maxPreparedOperationBytes of [true, 0, -1, '16384', null, 2 ** 53])
    await assert.rejects(operationState.decodePreparedOperation(raw, { ...opDecodeOptions, maxPreparedOperationBytes }), operationState.OperationCorruption);
  const largest = { ...operations.cells.appending, append_head: 'f'.repeat(64), append_claim: await operationState.appendClaim(opOwner.operationId, opOwner.operationSha256, 'f'.repeat(64)) };
  const exact = wire(largest).length;
  await opPrepare(opCells.idle, { maxPreparedOperationBytes: exact });
  await assert.rejects(opPrepare(opCells.idle, { maxPreparedOperationBytes: exact - 1 }), operationState.OperationCorruption);
  const fence = await operationState.decodeDecisionFence(wire({ ...operations.fences.success, generation: Number.MAX_SAFE_INTEGER }));
  assert.throws(() => operationState.releaseSuccess(fence, fence, { completionVerified: true }), operationState.OperationCorruption);
  await assert.rejects(operationState.authoritativeCheckIdentity({ ...operations.check_identity.input, repository_id: true }), operationState.OperationCorruption);
  await assert.rejects(operationState.appendClaim('bad', opOwner.operationSha256, opHead), operationState.OperationCorruption);
});

test('M1-16 operation values are factory-only, deeply immutable and own every pre-await input', async () => {
  const raw = wire(operations.cells.prepared), facts = evtClone(opFacts), options = { ...opDecodeOptions, preconditions: facts };
  const pending = operationState.decodePreparedOperation(raw, options); raw.fill(0); facts[0].value = {}; options.expectedProjectId = 'changed';
  const cell = await pending; assert.deepEqual(cell.toDict(), operations.cells.prepared); assert.ok(Object.isFrozen(cell));
  const copy = cell.toDict(); copy.side_artifacts[0].bytes_b64 = 'changed'; assert.deepEqual(cell.toDict(), operations.cells.prepared);
  for (const forged of [{ ...cell }, { state: 'prepared', generation: cell.generation, toDict: () => cell.toDict() }])
    assert.throws(() => operationState.encodePreparedOperation(forged, { maxPreparedOperationBytes: opLimit }), operationState.OperationCorruption);
  assert.throws(() => cell.state = 'idle', TypeError); assert.throws(() => opRef.commitOid = 'changed', TypeError);
  const event = evtClone(opEvent), artifacts = evtClone(operations.cells.prepared.side_artifacts), inputFacts = evtClone(opFacts);
  const prepared = operationState.prepareOperation(opCells.idle, event, artifacts, { expectedProjectId: operations.project_id,
    expectedEventsHead: opHead, preconditions: inputFacts, maxPreparedOperationBytes: opLimit });
  event.project_id = 'changed'; artifacts[0].bytes_b64 = ''; inputFacts[0].value = {}; assert.deepEqual((await prepared).toDict(), operations.cells.prepared);
  await assert.rejects(operationState.prepareOperation(opCells.idle, { bad: true }, [], { expectedProjectId: operations.project_id,
    expectedEventsHead: opHead, preconditions: opFacts, maxPreparedOperationBytes: opLimit }), operationState.OperationCorruption);
});

test('M1-16 scalar and accessor proposals reject with typed corruption and never execute caller getters', async () => {
  const invalidIdentities = [{ repository_id: true }, { merge_group_head_oid: opHead + '\n' }, { pull_request_number: 0 },
    { github_delivery_id: '' }, { github_delivery_id: null }, { extra: true }];
  for (const change of invalidIdentities) await assert.rejects(operationState.authoritativeCheckIdentity({ ...operations.check_identity.input, ...change }), operationState.OperationCorruption);
  for (const [id, digest, head] of [[opOwner.operationId, opOwner.operationSha256 + '\n', opHead],
    [opOwner.operationId, opOwner.operationSha256, opHead + '\n'], ['bad', opOwner.operationSha256, opHead]])
    await assert.rejects(operationState.appendClaim(id, digest, head), operationState.OperationCorruption);
  const factories = [artifacts => operationState.prepareOperation(opCells.idle, opEvent, artifacts, { expectedProjectId: operations.project_id,
    expectedEventsHead: opHead, preconditions: opFacts, maxPreparedOperationBytes: opLimit })];
  let calls = 0;
  const accessorArray = Object.defineProperty([], '0', { get() { calls++; return operations.cells.prepared.side_artifacts[0]; }, enumerable: true });
  const accessorEntry = Object.defineProperty({ ...operations.cells.prepared.side_artifacts[0] }, 'bytes_b64', { get() { calls++; return ''; }, enumerable: true });
  for (const start of factories) for (const input of [accessorArray, [accessorEntry], [undefined], Object.assign([], { extra: true })])
    await assert.rejects(start(input), operationState.OperationCorruption);
  assert.equal(calls, 0);
  const payload = Object.defineProperty({ ...formCorpus.golden.form }, 'project_id', { get() { calls++; return 'project-1'; }, enumerable: true });
  await assert.rejects(actionForms.encodeActionForm(payload, { key: unhex(formCorpus.keys[0].key_hex) }), actionForms.ActionFormError);
  assert.equal(calls, 0);
  const rawArtifacts = operations.cells.prepared.side_artifacts.map(row => ({ kind: row.kind, path: row.path, sha256: row.sha256, bytes: encoding.base64urlDecode(row.bytes_b64) }));
  const pending = operationState.prepareOperation(opCells.idle, opEvent, rawArtifacts, { expectedProjectId: operations.project_id,
    expectedEventsHead: opHead, preconditions: opFacts, maxPreparedOperationBytes: opLimit });
  for (const row of rawArtifacts) row.bytes.fill(255);
  assert.deepEqual((await pending).toDict(), operations.cells.prepared);
  for (const context of [null, [], { ...formContext(formCorpus.golden.form), extra: true }, { ...formContext(formCorpus.golden.form), github_user_id: true }])
    await assert.rejects(actionForms.verifyActionForm(formCorpus.golden.token, { keys: formKeys(), context }), actionForms.ActionFormError);
  for (const [type, target, body] of [['acceptance', { ...eventRows.acceptance.target, digest: eventRows.acceptance.target.digest + '\n' }, eventRows.acceptance.payload],
    ['unknown', {}, {}], ['acceptance', {}, {}]])
    await assert.rejects(events.validateEventOperation(type, target, body), events.EventValidationError);
});

test('M1-16 fence and marker decoding own byte views; invalid transition facts never authorize recovery', async () => {
  for (const [row, decode, encode] of [[operations.fences.mutation, operationState.decodeDecisionFence, operationState.encodeDecisionFence],
    [operations.markers.open, operationState.decodeInflightMarker, operationState.encodeInflightMarker]]) {
    const input = wire(row), pending = decode(input); input.fill(0); assert.equal(hex(encode(await pending)), hex(wire(row)));
  }
  await assert.rejects(operationState.openInflightMarker(opMarkers.open, opFences.mutation,
    { cell: opCells.prepared, preparedReference: opRef, startedAt: '2026-02-30T00:00:00Z' }), operationState.OperationCorruption);
  for (const result of ['', new String('landed'), null, true])
    assert.throws(() => opTerminal(opCells.prepared, result), operationState.OperationCorruption);
  await assert.rejects(opClaim(opCells.appending, { appendHead: 'a'.repeat(40), expectedAppendClaim: 'wrong' }), operationState.OperationConflict);
  const terminal = opTerminal(opCells.prepared);
  assert.equal(opTerminal(terminal), terminal);
  assert.throws(() => opTerminal(terminal, 'conflict'), operationState.OperationConflict);
  for (const flag of [1, null, 'true']) assert.throws(() => operationState.releaseMutationFence(opFences.mutation, opFences.mutation, terminal,
    opMarkers.empty, { preparedReference: opRef, projectionVerified: flag, readbackVerified: true }), operationState.OperationConflict);
  await assert.rejects(operationState.reserveSuccess(opFences.idle, opMarkers.open,
    { checkIdentity: operations.check_identity.expected, projectionCommit: opHead }), operationState.OperationConflict);
  assert.throws(() => operationState.releaseSuccess(opFences.idle, opFences.idle, { completionVerified: true }), operationState.OperationConflict);
});

// M1-17 consumes the checked-in reference outputs; it never runs Python/replay.
const edgeCoverage = await import('../.conformance-build/conformance/coverage.js');
function coverageFiles(basis = null, exempt = false) {
  const files = structuredClone(coverage.empty_files);
  files['agreements/active.enc.json'] = structuredClone(coverage.active);
  if (basis) files['users/07.enc.json']['7'] = { agreements: { 'agreement-1': structuredClone(coverage[basis]) }, overrides: {} };
  if (exempt) files['exemptions.enc.json']['7'] = { active: true };
  return files;
}
function coverageUpdateInput(c) {
  const input = c.input;
  const options = { expectedHead: c.before.canonical_oid, builtAt: input.built_at, draclaVersion: input.dracla_version, operationState: input.operation_state };
  if (Object.hasOwn(input, 'prior_exemption_union')) options.priorExemptionUnion = {
    project_id: transitions.project_id, canonical_oid: c.before.canonical_oid, sources: input.prior_exemption_union,
  };
  if (input.record.event.type === 'agreement_activation_restored') options.restoredActivation = {
    project_id: transitions.project_id, canonical_oid: c.before.canonical_oid,
    event: c.history.find(r => r.event.event_id === input.record.event.target.activation_event_id).event,
  };
  return structuredClone({ record: input.record, options });
}
async function applyCoverageCase(c) {
  const before = await edgeCoverage.coverageProjection(transitions.project_id, c.before.coverage, c.before.canonical_oid);
  const { record, options } = coverageUpdateInput(c);
  return { before, after: await edgeCoverage.updateCoverage(before, record, options) };
}
test('M1-17 every incremental coverage triple equals reference bytes and exact logical delta', async () => {
  const families = new Set(), shards = new Set();
  for (const c of transitions.cases) {
    const { before, after } = await applyCoverageCase(c);
    assert.deepEqual(after.toDict(), c.after.coverage, c.id);
    assert.equal(after.projectId, transitions.project_id);
    const plain = after.plaintextFiles();
    assert.equal(Object.keys(plain).length, 37);
    for (const [path, expected] of Object.entries(c.after.coverage)) assert.deepEqual(plain[path], wire(expected), c.id + ':' + path);
    assert.deepEqual(edgeCoverage.coverageDelta(before, after).files, c.changed.coverage, c.id);
    for (const shard of edgeCoverage.coverageDelta(before, after).shards) shards.add(shard);
    families.add(c.input.record.event.type);
  }
  assert.equal(families.size, 27);
  assert.deepEqual([...shards].sort((a, b) => a - b), Array.from({ length: 32 }, (_, i) => i));
});
test('M1-17 fixed subject decisions, currency restore and combined bases match reference', async () => {
  for (const c of [...coverage.evaluation_cases, ...coverage.combined_basis_cases]) {
    const files = coverageFiles(c.basis, c.exempt);
    Object.assign(files['agreements/active.enc.json'], c.active ?? {});
    const p = await edgeCoverage.coverageProjection('project-1', files);
    const d = await edgeCoverage.evaluateSubject(p, 7, 'agreement-1');
    assert.deepEqual([d.decision, d.reason_code], c.expected, c.name);
    assert.equal(d.overridden, false); assert.equal(d.successor_project_id, null);
  }
  const before = await edgeCoverage.coverageProjection('project-1', coverageFiles('signed'));
  for (const c of coverage.currency_cases) {
    const files = before.toDict();
    Object.assign(files['agreements/active.enc.json'], Object.fromEntries(Object.entries(c).filter(([k]) => k !== 'expected')));
    const p = await edgeCoverage.coverageProjection('project-1', files);
    const d = await edgeCoverage.evaluateSubject(p, 7, 'agreement-1');
    assert.deepEqual([d.decision, d.reason_code], c.expected);
    assert.deepEqual(edgeCoverage.coverageDelta(before, p).shards, []);
  }
  for (const c of coverage.shard_cases) assert.equal(edgeCoverage.coverageShard(c.user, 32), c.expected);
  assert.equal(edgeCoverage.coverageShard(Number.MAX_SAFE_INTEGER, 32), 31);
  for (const id of [0, -1, 1.1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, true, '7']) assert.throws(() => edgeCoverage.coverageShard(id, 32));
  for (const count of [0, 31, 33, '32', true]) assert.throws(() => edgeCoverage.coverageShard(7, count));
});
test('M1-17 subject and project fences fail closed with open or empty markers, succession takes precedence', async () => {
  for (const subjects of [[], [7], [8]]) for (const open of [false, true]) {
    const files = coverageFiles('signed', true), f = structuredClone(coverage.operation_states.fences.mutation);
    f.subjects = subjects; f.project_wide = !subjects.length;
    files['decision-fence.enc.json'] = f;
    if (open) {
      const marker = structuredClone(coverage.operation_states.markers.open);
      Object.assign(Object.values(marker.ops)[0], { subjects, project_wide: !subjects.length }); files['inflight.enc.json'] = marker;
    }
    const p = await edgeCoverage.coverageProjection('project-1', files);
    const d = await edgeCoverage.evaluateSubject(p, 7, 'agreement-1');
    assert.equal(d.reason_code, subjects.includes(8) ? 'signed' : 'indeterminate');
    files['source.enc.json'].project_state = 'succeeded'; files['source.enc.json'].successor_project_id = 'next';
    const s = await edgeCoverage.coverageProjection('project-1', files);
    assert.deepEqual(await edgeCoverage.evaluateSubject(s, 7, 'agreement-1'), { decision: 'uncovered', reason_code: null, overridden: false, successor_project_id: 'next' });
  }
});
test('M1-17 exact override tuple grants no generic signature and cannot hide indeterminate basis', async () => {
  const c = transitions.cases.find(c => c.input.record.event.type === 'override');
  const { after } = await applyCoverageCase(c), e = c.input.record.event;
  const id = e.payload.subjects[0].github_user_id;
  const context = { repository_id: e.target.repository_id, pull_request_number: e.target.pull_request_number, tree_oid: e.target.tree_oid };
  const d = await edgeCoverage.evaluateSubject(after, id, 'agreement-1', context);
  assert.equal(d.decision, 'covered'); assert.equal(d.overridden, true); assert.equal(d.reason_code, null);
  for (const changed of [{ ...context, repository_id: context.repository_id + 1 }, { ...context, pull_request_number: context.pull_request_number + 1 }, { ...context, tree_oid: 'f'.repeat(40) }, null]) {
    assert.equal((await edgeCoverage.evaluateSubject(after, id, 'agreement-1', changed)).overridden, false);
  }
  const files = after.toDict(); files[`users/${String(id % 32).padStart(2, '0')}.enc.json`][id].agreements['agreement-1'] = coverage.unresolved;
  const p = await edgeCoverage.coverageProjection('project-1', files);
  assert.equal((await edgeCoverage.evaluateSubject(p, id, 'agreement-1', context)).reason_code, 'indeterminate');
});
test('M1-17 coverage snapshots reject malformed whole state and every marker fence inconsistency', async () => {
  const mutations = [
    f => { delete f['users/31.enc.json']; }, f => { f.extra = {}; },
    f => { f['agreements/active.enc.json'].projection_format = 2; }, f => { f['agreements/active.enc.json'].shard_count = 31; },
    f => { f['users/31.enc.json']['7'] = { agreements: {}, overrides: {} }; },
    f => { f['users/31.enc.json']['31'] = { agreements: {}, overrides: {}, login_snapshot: 'private' }; },
    f => { f['users/07.enc.json']['7'].agreements['agreement-1'].reason_code = 'exempt'; },
    f => { f['source.enc.json'].private = true; }, f => { f['source.enc.json'].project_state = 'unknown'; },
    f => { f['source.enc.json'].canonical_sha += '\n'; }, f => { f['source.enc.json'].built_at = '2026-02-30T00:00:00Z'; },
    f => { f['source.enc.json'].project_state = 'succeeded'; f['source.enc.json'].successor_project_id = 'project-1'; },
    f => { f['exemptions.enc.json']['07'] = { active: true }; }, f => { f['exemptions.enc.json']['7'] = { active: false }; },
    f => { f['inflight.enc.json'] = structuredClone(coverage.operation_states.markers.open); },
    f => { f['inflight.enc.json'] = structuredClone(coverage.operation_states.markers.open); f['decision-fence.enc.json'] = structuredClone(coverage.operation_states.fences.success); },
  ];
  for (const mutate of mutations) {
    const f = coverageFiles('signed'); mutate(f);
    await assert.rejects(edgeCoverage.coverageProjection('project-1', f), edgeCoverage.CoverageError);
  }
  for (const field of ['operation_id', 'operation_sha256', 'subjects', 'project_wide']) {
    const f = coverageFiles('signed'); f['inflight.enc.json'] = structuredClone(coverage.operation_states.markers.open);
    f['decision-fence.enc.json'] = structuredClone(coverage.operation_states.fences.mutation);
    const fence = f['decision-fence.enc.json'];
    if (field === 'operation_id') fence[field] = encoding.base64urlEncode(new Uint8Array(32));
    if (field === 'operation_sha256') fence[field] = 'sha256:' + '0'.repeat(64);
    if (field === 'subjects' || field === 'project_wide') { fence.subjects = [7]; fence.project_wide = false; }
    await assert.rejects(edgeCoverage.coverageProjection('project-1', f), edgeCoverage.CoverageError);
  }
  const grant = transitions.cases.find(c => c.input.record.event.type === 'override').after.coverage;
  const f = structuredClone(grant), row = Object.values(f['users/07.enc.json'])[0], key = Object.keys(row.overrides)[0];
  row.overrides.bad = row.overrides[key]; delete row.overrides[key];
  await assert.rejects(edgeCoverage.coverageProjection('project-1', f), edgeCoverage.CoverageError);
  for (const c of coverage.version_ordering_cases) {
    const f = coverageFiles(); f['agreements/active.enc.json'][c.set] = c.canonical_values;
    f['agreements/active.enc.json'].active_version = c.active_version;
    await edgeCoverage.coverageProjection('project-1', f);
    f['agreements/active.enc.json'][c.set] = c.reversed_values;
    await assert.rejects(edgeCoverage.coverageProjection('project-1', f), edgeCoverage.CoverageError);
  }
});
test('M1-17 missing, stale, incomplete and inconsistent exemption unions are rejected', async () => {
  for (const type of ['exemption', 'exemption_snapshot', 'exemption_materialized', 'exemption_source_withdrawn', 'exemption_rule_withdrawn']) {
    const c = transitions.cases.find(c => c.input.record.event.type === type);
    const before = await edgeCoverage.coverageProjection(transitions.project_id, c.before.coverage);
    const { record, options } = coverageUpdateInput(c);
    const mutations = [o => { delete o.priorExemptionUnion; }, o => { o.priorExemptionUnion.canonical_oid = 'f'.repeat(40); },
      o => { o.priorExemptionUnion.project_id = 'other'; }, o => { o.priorExemptionUnion.sources = {}; },
      o => { o.priorExemptionUnion.sources['07'] = []; }, o => { o.priorExemptionUnion.sources['8'] = ['invalid']; }];
    for (const mutate of mutations) {
      const o = structuredClone(options); mutate(o);
      await assert.rejects(edgeCoverage.updateCoverage(before, record, o), edgeCoverage.CoverageError, type);
    }
  }
  const c = transitions.cases.find(c => c.input.record.event.type === 'exemption_source_withdrawn' && Object.values(c.input.prior_exemption_union).some(v => v.length > 1));
  const { before, after } = await applyCoverageCase(c);
  assert.deepEqual(after.toDict()['exemptions.enc.json'], before.toDict()['exemptions.enc.json']);
  const { record, options } = coverageUpdateInput(c); options.priorExemptionUnion.sources['7'] = [];
  await assert.rejects(edgeCoverage.updateCoverage(before, record, options), edgeCoverage.CoverageError);
});
test('M1-17 restores require the exact authenticated original activation and immutable source', async () => {
  const c = transitions.cases.find(c => c.input.record.event.type === 'agreement_activation_restored');
  const before = await edgeCoverage.coverageProjection(transitions.project_id, c.before.coverage);
  const { record, options } = coverageUpdateInput(c);
  for (const mutate of [o => { delete o.restoredActivation; }, o => { o.restoredActivation.canonical_oid = 'f'.repeat(40); },
    o => { o.restoredActivation.project_id = 'other'; }, o => { o.restoredActivation.event = c.history[0].event; },
    o => { o.restoredActivation.event.target.version = 'fake'; }]) {
    const o = structuredClone(options); mutate(o);
    await assert.rejects(edgeCoverage.updateCoverage(before, record, o), edgeCoverage.CoverageError);
  }
  for (const mutate of [r => { r.parent_oid = 'f'.repeat(40); }, r => { r.commit_oid = r.parent_oid; },
    r => { r.commit_oid += '\n'; }, r => { r.extra = {}; }, r => { r.event.operation_sha256 = 'sha256:' + '0'.repeat(64); }]) {
    const r = structuredClone(record); mutate(r); await assert.rejects(edgeCoverage.updateCoverage(before, r, options), edgeCoverage.CoverageError);
  }
  await assert.rejects(edgeCoverage.updateCoverage(before, record, { ...options, expectedHead: 'f'.repeat(40) }), edgeCoverage.CoverageError);
});
test('M1-17 reader-only appends advance canonical binding while private derivation remains unwritten', async () => {
  for (const c of transitions.cases.filter(c => c.input.record.event.type.startsWith('records_reader'))) {
    const { before, after } = await applyCoverageCase(c);
    assert.deepEqual(edgeCoverage.coverageDelta(before, after).files, ['source.enc.json'], c.id);
    edgeCoverage.validateCoverageProjection(after, transitions.project_id, c.after.canonical_oid);
    assert.throws(() => edgeCoverage.validateCoverageProjection(after, transitions.project_id, c.before.canonical_oid));
    // The updater has no derived-state parameter. This independent stale copy
    // remains unchanged while coverage already binds the appended canonical head.
    const privateBefore = structuredClone(c.before.derived);
    assert.deepEqual(privateBefore, c.before.derived);
    assert.deepEqual(after.toDict(), c.after.coverage);
  }
});
test('M1-17 snapshots, update observations and override contexts own inputs before await', async () => {
  const input = coverageFiles('signed'), promise = edgeCoverage.coverageProjection('project-1', input);
  input['users/07.enc.json']['7'].agreements['agreement-1'].reason_code = 'revoked';
  const p = await promise; assert.equal((await edgeCoverage.evaluateSubject(p, 7, 'agreement-1')).reason_code, 'signed');
  assert.ok(Object.isFrozen(p)); const copy = p.toDict(); copy['source.enc.json'].canonical_sha = 'f'.repeat(40);
  const plain = p.plaintextFiles(); plain['source.enc.json'].fill(0);
  assert.notDeepEqual(p.plaintextFiles()['source.enc.json'], plain['source.enc.json']);
  assert.deepEqual(edgeCoverage.coverageDelta(p, p), { files: [], shards: [] });
  assert.throws(() => edgeCoverage.validateCoverageProjection({ ...p }, 'project-1'), edgeCoverage.CoverageError);
  assert.throws(() => edgeCoverage.validateCoverageProjection(p, 'other'), edgeCoverage.CoverageError);
  await assert.rejects(edgeCoverage.evaluateSubject(p, 7, 'other'), edgeCoverage.CoverageError);
  for (const context of [{ repository_id: 1, pull_request_number: 2, tree_oid: 'f'.repeat(40), extra: true }, { repository_id: 0, pull_request_number: 2, tree_oid: 'f'.repeat(40) }]) {
    await assert.rejects(edgeCoverage.evaluateSubject(p, 7, 'agreement-1', context));
  }
  for (const type of ['exemption', 'agreement_activation_restored', 'override']) {
    const c = transitions.cases.find(c => c.input.record.event.type === type);
    const before = await edgeCoverage.coverageProjection(transitions.project_id, c.before.coverage);
    const { record, options } = coverageUpdateInput(c), pending = edgeCoverage.updateCoverage(before, record, options);
    record.event.target = {}; options.operationState[0].ops = { bad: {} }; options.expectedHead = 'f'.repeat(40);
    if (options.priorExemptionUnion) options.priorExemptionUnion.sources = {};
    if (options.restoredActivation) options.restoredActivation.event.target.version = 'wrong';
    assert.deepEqual((await pending).toDict(), c.after.coverage, type);
  }
});
test('M1-17 operational crash windows reproduce the reference without an append or private branch', async () => {
  for (const c of transitions.operational_cases) {
    const before = await edgeCoverage.coverageProjection(transitions.project_id, c.before.coverage);
    const after = await edgeCoverage.updateCoverageOperations(before, c.input.operation_state);
    assert.deepEqual(after.toDict(), c.after.coverage, c.id);
    assert.equal(after.toDict()['source.enc.json'].canonical_sha, before.toDict()['source.enc.json'].canonical_sha);
    const changed = edgeCoverage.coverageDelta(before, after).files;
    assert.ok(changed.every(path => ['inflight.enc.json', 'decision-fence.enc.json'].includes(path)));
  }
});
test('M1-17 dynamic agreement keys remain data and untouched empty rows are preserved', async () => {
  for (const agreement of ['__proto__', 'constructor', 'toString']) {
    const f = coverageFiles(); f['agreements/active.enc.json'].agreement_id = agreement;
    const p = await edgeCoverage.coverageProjection('project-1', f);
    assert.equal((await edgeCoverage.evaluateSubject(p, 7, agreement)).reason_code, 'not_signed');
    const c = structuredClone(transitions.cases.find(c => c.input.record.event.type === 'acceptance'));
    c.before.coverage['agreements/active.enc.json'].agreement_id = agreement;
    c.input.record.event.target.coverage_tuple.agreement_id = agreement;
    const event = c.input.record.event;
    Object.assign(event, await events.deriveEventIdentity({ project_id: event.project_id, operation_nonce: event.operation_nonce, actor: event.actor,
      type: event.type, target: event.target, payload: event.payload, confirmed_canonical_oid: event.confirmed_canonical_oid }));
    delete event.path;
    const before = await edgeCoverage.coverageProjection('project-1', c.before.coverage);
    const { record, options } = coverageUpdateInput(c), after = await edgeCoverage.updateCoverage(before, record, options);
    const agreements = after.toDict()['users/07.enc.json']['7'].agreements;
    assert.ok(Object.hasOwn(agreements, agreement));
    assert.equal((await edgeCoverage.evaluateSubject(after, 7, agreement)).reason_code, 'signed');
  }
  const c = structuredClone(transitions.cases.find(c => c.input.record.event.type === 'override_withdrawn'));
  c.before.coverage['users/31.enc.json']['31'] = { agreements: {}, overrides: {} };
  const { after } = await applyCoverageCase(c);
  assert.deepEqual(after.toDict()['users/31.enc.json']['31'], { agreements: {}, overrides: {} });
});
