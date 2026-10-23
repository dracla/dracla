/** Source-test ledger. Claims follow semantic assertions, never fixture loading. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const label = (row, i) => row !== null && !Array.isArray(row) && typeof row === 'object' ? String(row.id ?? row.name ?? i) : String(i);
const id = (name, ref) => JSON.stringify([name, ref]);
export class Consumption {
  constructor(spec, manifest, values, runtime = 'typescript') {
    this.spec = spec; this.manifest = manifest; this.values = values; this.runtime = runtime;
    this.expected = new Set(); this.claimed = new Set(); this.metadata = new Set();
    assert.equal(spec.schema_version, 1);
    assert.deepEqual(Object.keys(spec.files).sort(), Object.keys(manifest.files).sort(), 'consumption file inventory mismatch');
    for (const [name, value] of Object.entries(values)) {
      const rule = spec.files[name];
      assert.deepEqual(Object.keys(rule.fields).sort(), Object.keys(value).sort(), `consumption field inventory mismatch: ${name}`);
      assert.ok(rule.runtimes.length && rule.runtimes.every(v => ['python', 'typescript'].includes(v)));
      const applicable = rule.runtimes.includes(runtime);
      if (!applicable) assert.ok(rule.inapplicable_reason, `missing applicability reason: ${name}`);
      const registry = [];
      for (const [field, data] of Object.entries(value)) {
        registry.push(field);
        if (Array.isArray(data)) registry.push(...data.map((row, i) => `${field}/${label(row, i)}`));
        else if (data !== null && typeof data === 'object') registry.push(...Object.keys(data).map(key => `${field}/${key}`));
        const definition = rule.fields[field];
        if (definition.mode === 'metadata') {
          assert.deepEqual(data, definition.expected, `metadata mismatch: ${name}:${field}`);
          this.metadata.add(id(name, field));
        } else if (definition.mode === 'cases') {
          assert.ok(data && typeof data === 'object' && Object.keys(data).length, `invalid case group: ${name}:${field}`);
          const labels = Array.isArray(data) ? data.map(label) : Object.keys(data);
          if (applicable) for (const key of labels) this.expected.add(id(name, `${field}/${key}`));
        } else {
          assert.equal(definition.mode, 'value');
          if (applicable) this.expected.add(id(name, field));
        }
      }
      assert.equal(new Set(registry).size, registry.length);
      assert.deepEqual(registry, manifest.files[name].cases, `manifest case registry mismatch: ${name}`);
    }
    for (const name of Object.keys(spec.contracts.wrapper_pairs)) this.expected.add(id('@contracts', `wrapper_pairs/${name}`));
    for (const [group, contracts] of Object.entries(spec.contracts)) {
      if (group === 'wrapper_pairs') continue;
      for (const references of Object.values(contracts)) {
        for (const [name, ref] of references) if (name === '@contracts') this.expected.add(id('@contracts', ref));
      }
    }
  }
  contract(group, name) { this.claim('@contracts', `${group}/${name}`); }
  claim(name, ref) {
    const key = id(name, ref);
    assert.ok(this.expected.has(key), `unknown or inapplicable claim: ${name}:${ref}`);
    this.claimed.add(key);
  }
  case(name, field, row) {
    const data = this.values[name][field];
    if (!Array.isArray(data)) return this.claim(name, `${field}/${row}`);
    const named = row !== null && !Array.isArray(row) && typeof row === 'object' && (Object.hasOwn(row, 'id') || Object.hasOwn(row, 'name'));
    const matches = data.flatMap((candidate, i) => {
      if (named) return label(candidate, i) === String(row.id ?? row.name) ? [i] : [];
      try { assert.deepEqual(candidate, row); return [i]; } catch { return []; }
    });
    assert.equal(matches.length, 1, `ambiguous or foreign case: ${name}:${field}`);
    assert.deepEqual(data[matches[0]], row, `foreign case content: ${name}:${field}`);
    this.claim(name, `${field}/${label(row, matches[0])}`);
  }
  value(name, ...fields) { for (const field of fields) this.claim(name, field); }
  equal(name, field, actual) {
    const expected = this.values[name][field];
    assert.deepEqual(actual, expected, `whole-group equality failed: ${name}:${field}`);
    if (this.spec.files[name].fields[field].mode === 'value') this.value(name, field);
    else for (const row of Array.isArray(expected) ? expected : Object.keys(expected)) this.case(name, field, row);
  }
  async assertComplete() {
    const missing = [...this.expected].filter(key => !this.claimed.has(key)).map(JSON.parse);
    assert.equal(missing.length, 0, `unconsumed applicable corpus cases:\n${missing.map(([n,r]) => `${n}:${r}`).join('\n')}`);
    const receipt = { runtime: this.runtime,
      spec_sha256: createHash('sha256').update(await readFile(new URL('consumption-v1.json', root))).digest('hex'),
      manifest_sha256: createHash('sha256').update(await readFile(new URL('vectors/manifest.json', root))).digest('hex'), semantic_claims: [...this.claimed].sort().map(JSON.parse), integrity_metadata: [...this.metadata].sort().map(JSON.parse) };
    if (this === CLAIMS && process.env.DRACLA_CONFORMANCE_RECEIPT) await writeFile(process.env.DRACLA_CONFORMANCE_RECEIPT, JSON.stringify(receipt, null, 2) + '\n');
    return receipt;
  }
}
const root = new URL('../../conformance/', import.meta.url);
const read = async path => JSON.parse(await readFile(new URL(path, root), 'utf8'));
const [spec, manifest] = await Promise.all([read('consumption-v1.json'), read('vectors/manifest.json')]);
const values = Object.fromEntries(await Promise.all(Object.keys(manifest.files).map(async name => [name, await read(`vectors/${name}`)])));
export const CLAIMS = new Consumption(spec, manifest, values);
