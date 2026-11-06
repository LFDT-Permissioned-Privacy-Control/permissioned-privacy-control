import { test } from 'node:test';
import assert from 'node:assert/strict';
import { importFiles, updateText, exportFile, textOf, syntaxHint, hasChanges, limits } from './model.mjs';

const file = (name, bytes) => ({ name, size: bytes.byteLength, arrayBuffer: async () => bytes.slice().buffer });
const enc = text => new TextEncoder().encode(text);

test('unedited CRLF, BOM and Unicode source keeps exact bytes', async () => {
  for (const text of ['{\r\n  "name": "Банк 🏦"\r\n}\r\n', '\ufeff{"name":"e\u0301"}\n']) {
    const raw = enc(text);
    const files = await importFiles([file('groups.json', raw)]);
    const exported = exportFile(files.get('groups.json'));
    assert.equal(exported.name, 'groups.json');
    assert.deepEqual(exported.bytes, raw);
    exported.bytes[0] = 0;
    assert.deepEqual(exportFile(files.get('groups.json')).bytes, raw);
    assert.equal(hasChanges(files), false);
  }
});

test('edits are proposals and original bytes stay available', async () => {
  const original = enc('{"groups":[]}\r\n');
  const files = await importFiles([file('groups.json', original)]);
  const edited = updateText(files, 'groups.json', '{"groups":[]}\n');
  assert.equal(hasChanges(edited), true);
  assert.equal(textOf(edited.get('groups.json')), '{"groups":[]}\n');
  assert.deepEqual(exportFile(edited.get('groups.json')).bytes, enc('{"groups":[]}\n'));
  assert.deepEqual(exportFile(files.get('groups.json')).bytes, original);
  assert.match(syntaxHint(edited.get('groups.json')), /Run the OPS checker/);
  assert.equal('approved' in edited.get('groups.json'), false);
  const malformed = updateText(edited, 'groups.json', '{');
  assert.match(syntaxHint(malformed.get('groups.json')), /not valid JSON/);
});

test('imports reject path, duplicate, invalid UTF8 and size/count failures atomically', async () => {
  for (const name of ['../draft.json', 'sub/groups.json', 'Group.JSON', 'a.json\n', 'x'.repeat(129)+'.json']) {
    await assert.rejects(importFiles([file(name, enc('{}'))]));
  }
  await assert.rejects(importFiles([file('a.json', enc('{}')), file('a.json', enc('{}'))]));
  await assert.rejects(importFiles([file('a.json', new Uint8Array([0xff]))]));
  await assert.rejects(importFiles([{ name: 'a.json', size: limits.fileBytes+1, arrayBuffer() { throw new Error('must reject before read'); } }]));
  await assert.rejects(importFiles(new Array(limits.files+1).fill(file('a.json', enc('{}')))));
  const files = await importFiles([file('a.json', enc('{}'))]);
  assert.throws(() => updateText(files, 'a.json', 'x'.repeat(limits.fileBytes+1)));
  assert.equal(textOf(files.get('a.json')), '{}');
});
