// Source editing helpers only. Authoritative validation is the Go checker.
export const limits = Object.freeze({ files: 1025, fileBytes: 1 << 20, totalBytes: 64 << 20 });
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function validName(name) {
  return typeof name === 'string' && name.length <= 128 && /^[a-z0-9][a-z0-9_-]*\.json$/.test(name);
}

function checkSize(size) {
  if (!Number.isSafeInteger(size) || size < 0 || size > limits.fileBytes) throw new Error('Each JSON file must be at most 1 MiB.');
}

export async function importFiles(files) {
  const selected = Array.from(files);
  if (selected.length === 0 || selected.length > limits.files) throw new Error('Select between 1 and 1,025 JSON files.');
  const names = new Set();
  let advertised = 0;
  for (const file of selected) {
    if (!validName(file.name) || names.has(file.name)) throw new Error('Use unique flat lowercase JSON filenames, without paths.');
    names.add(file.name);
    checkSize(file.size);
    advertised += file.size;
    if (advertised > limits.totalBytes) throw new Error('Selected files exceed 64 MiB.');
  }
  const result = new Map();
  let total = 0;
  for (const file of selected) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    checkSize(bytes.byteLength);
    total += bytes.byteLength;
    if (total > limits.totalBytes) throw new Error('Selected files exceed 64 MiB.');
    let text;
    try { text = decoder.decode(bytes); } catch { throw new Error(`File ${file.name} is not valid UTF-8.`); }
    result.set(file.name, { name: file.name, originalBytes: bytes.slice(), originalText: text, editedText: null });
  }
  return result;
}

export function textOf(file) { return file.editedText ?? file.originalText; }

export function bytesOf(file) {
  // Textarea line endings may be normalized by a browser. An unedited file is
  // therefore exported from its original byte buffer, never from DOM text.
  return file.editedText === null ? file.originalBytes.slice() : encoder.encode(file.editedText);
}

export function updateText(files, name, text) {
  const original = files.get(name);
  if (!original) throw new Error('Select a file first.');
  const bytes = encoder.encode(text);
  checkSize(bytes.byteLength);
  let total = bytes.byteLength;
  for (const [other, file] of files) if (other !== name) total += bytesOf(file).byteLength;
  if (total > limits.totalBytes) throw new Error('Edited files exceed 64 MiB.');
  const result = new Map(files);
  result.set(name, { ...original, editedText: text === original.originalText ? null : text });
  return result;
}

export function syntaxHint(file) {
  try { JSON.parse(textOf(file)); return 'JSON syntax looks valid. Run the OPS checker to validate the complete rules.'; }
  catch { return 'This file is not valid JSON yet. You can keep editing or export the draft.'; }
}

export function exportFile(file) { return { name: file.name, bytes: bytesOf(file) }; }

export function hasChanges(files) { return Array.from(files.values()).some(file => file.editedText !== null); }
