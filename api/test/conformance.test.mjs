/** Shared checked-in corpus is the cross-runtime oracle. No Python process. */
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import test from 'node:test';
import * as canonical from '../.conformance-build/conformance/canonical.js';
import * as encoding from '../.conformance-build/conformance/encoding.js';
import * as artifacts from '../.conformance-build/conformance/artifacts.js';
import * as envelope from '../.conformance-build/conformance/envelope.js';
import * as limits from '../.conformance-build/conformance/releaseProfile.js';
import * as projections from '../.conformance-build/conformance/projections.js';

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
  }
  const stateTiny = new limits.ReleaseProfile({ ...profileValue, max_state_ciphertext_bytes: 1 });
  await assert.rejects(projections.decodeProjection(identity('derived/state.enc.json'), wire(assembled), { profile: stateTiny }), error => error instanceof projections.DerivedClassOverflow && error.derived_class === 'state');
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
