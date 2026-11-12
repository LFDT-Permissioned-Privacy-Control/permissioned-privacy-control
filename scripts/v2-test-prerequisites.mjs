#!/usr/bin/env node
// Public test circuits only. No identity keys, credentials or production config.
import { createRequire } from 'node:module'
import { createHash, randomUUID } from 'node:crypto'
import { readFile, mkdir, writeFile, rename, rm } from 'node:fs/promises'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { artifactNames, artifactHashes, circuitDirectory, walletModules } from '../tools/v2-test-wallet/artifacts.mjs'

const hash = data => createHash('sha256').update(data).digest('hex')
const expected = new Map(Object.entries(artifactHashes).flatMap(([id, hashes]) =>
  artifactNames.map((name, index) => [`${id}/${name}`, { id, name, hash: hashes[index] }])))

export async function verifyArtifacts() {
  for (const value of expected.values()) {
    try {
      if (hash(await readFile(path.join(circuitDirectory(value.id), value.name))) !== value.hash) return false
    } catch { return false }
  }
  return true
}

export async function provisionArtifacts() {
  if (await verifyArtifacts()) {
    process.stdout.write('V2 AuthV2 and SigV2 public circuits: all six pinned hashes verified.\n')
    return
  }
  const require = createRequire(path.join(walletModules, '../package.json'))
  const { Unzip, UnzipInflate } = require('fflate')
  const source = new URL(process.env.OPS_PRIVADO_CIRCUITS_ARCHIVE ?? 'https://circuits.privado.id/latest.zip')
  if (source.protocol !== 'https:' || source.username || source.password) throw new Error('Circuit archive must use HTTPS without URL credentials')
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 240_000)
  const found = new Map(), pending = new Set()
  let failure, compressedBytes = 0, inflatedBytes = 0
  const unzip = new Unzip(file => {
    // Only names derived from our six-entry manifest become filesystem paths.
    const match = /(?:^|\/)(authV2|credentialAtomicQuerySigV2)\/(circuit\.wasm|circuit_final\.zkey|verification_key\.json)$/.exec(file.name)
    if (!match) return
    const key = `${match[1]}/${match[2]}`
    if (!expected.has(key) || found.has(key) || pending.has(key)) {
      failure = new Error('Duplicate or unexpected selected circuit member'); return
    }
    pending.add(key)
    const chunks = []
    let size = 0
    file.ondata = (error, data, final) => {
      if (failure) return
      if (error) { failure = error; return }
      size += data.byteLength; inflatedBytes += data.byteLength
      if (size > 48 * 1024 * 1024 || inflatedBytes > 96 * 1024 * 1024) {
        failure = new Error('Selected public circuit exceeds its download budget'); return
      }
      chunks.push(data)
      if (final) {
        const raw = Buffer.concat(chunks)
        if (hash(raw) !== expected.get(key).hash) { failure = new Error(`Pinned circuit hash mismatch: ${key}`); return }
        found.set(key, raw); pending.delete(key)
      }
    }
    file.start()
  })
  unzip.register(UnzipInflate)
  try {
    process.stderr.write('Fetching public proving circuits; only six hash-pinned AuthV2/SigV2 members are extracted.\n')
    const response = await fetch(source, { signal: controller.signal, redirect: 'error' })
    if (!response.ok || !response.body) throw new Error(`Circuit archive request failed (${response.status})`)
    for await (const chunk of response.body) {
      compressedBytes += chunk.byteLength
      if (compressedBytes > 600 * 1024 * 1024) throw new Error('Circuit archive exceeds the download budget')
      unzip.push(chunk, false)
      if (failure) throw failure
    }
    unzip.push(new Uint8Array(), true)
    if (failure) throw failure
    if (pending.size || found.size !== expected.size) throw new Error('Archive did not contain all six pinned circuit members')
    for (const [key, data] of found) {
      const value = expected.get(key), target = path.join(circuitDirectory(value.id), value.name)
      await mkdir(path.dirname(target), { recursive: true })
      const temporary = `${target}.part-${randomUUID()}`
      try {
        await writeFile(temporary, data, { flag: 'wx', mode: 0o600 })
        await rename(temporary, target)
      } finally { await rm(temporary, { force: true }) }
    }
    if (!await verifyArtifacts()) throw new Error('Installed circuit verification failed')
    process.stdout.write('V2 AuthV2 and SigV2 public circuits installed and verified.\n')
  } finally { clearTimeout(timer); controller.abort() }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  provisionArtifacts().catch(error => { process.stderr.write(`V2 prerequisites: ${error.message}\n`); process.exitCode = 1 })
}
