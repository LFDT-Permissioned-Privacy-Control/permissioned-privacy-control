import { importFiles, textOf, updateText, syntaxHint, exportFile, hasChanges } from './model.mjs';

const byId = id => document.getElementById(id);
let files = new Map();
let selected = null;
let invalidEdit = false;
let importGeneration = 0;
const editor = byId('editor');
const error = byId('error');

function showError(message) { error.textContent = message; error.hidden = !message; }

function renderList() {
  const list = byId('files');
  list.replaceChildren();
  for (const [name, file] of files) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = name === selected ? 'file selected' : 'file';
    button.textContent = name + (file.editedText !== null ? ' · edited' : '');
    button.setAttribute('aria-pressed', String(name === selected));
    button.addEventListener('click', () => {
      if (invalidEdit && !confirm('Discard the oversized text that could not be saved to this draft?')) return;
      importGeneration++;
      selected = name; invalidEdit = false; showError(''); render();
    });
    list.append(button);
  }
}

function renderDetails() {
  const file = files.get(selected);
  byId('workspace').hidden = !file;
  byId('empty').hidden = Boolean(file);
  byId('download').disabled = !file || invalidEdit;
  if (!file) return;
  byId('filename').textContent = file.name;
  byId('status').textContent = file.editedText === null ? 'Original file · not checked' : 'Edited draft · not checked';
  byId('syntax').textContent = syntaxHint(file);
  byId('original').textContent = file.originalText;
  byId('proposed').textContent = textOf(file);
}

function render() {
  renderList();
  if (files.has(selected)) editor.value = textOf(files.get(selected));
  renderDetails();
}

byId('open').addEventListener('change', async event => {
  const picked = Array.from(event.target.files);
  event.target.value = '';
  if (!picked.length) return;
  const generation = ++importGeneration;
  if ((hasChanges(files) || invalidEdit) && !confirm('Replace the current draft? Download any edits you want to keep first.')) return;
  try {
    const imported = await importFiles(picked);
    if (generation !== importGeneration) return;
    files = imported; selected = files.keys().next().value; invalidEdit = false; showError(''); render();
  } catch (err) { showError(err.message); }
});

editor.addEventListener('input', () => {
  importGeneration++;
  try {
    files = updateText(files, selected, editor.value);
    invalidEdit = false; showError(''); renderList(); renderDetails();
  } catch (err) { invalidEdit = true; byId('download').disabled = true; showError(err.message); }
});

byId('download').addEventListener('click', () => {
  if (invalidEdit || !files.has(selected)) return;
  const file = exportFile(files.get(selected));
  const url = URL.createObjectURL(new Blob([file.bytes], { type: 'application/json;charset=utf-8' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = file.name; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

window.addEventListener('beforeunload', event => {
  if (hasChanges(files) || invalidEdit) { event.preventDefault(); event.returnValue = ''; }
});
render();
