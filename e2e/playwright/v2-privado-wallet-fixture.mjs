// PUBLIC TEST MATERIAL ONLY. No user identity/seed files or network artifacts
// are loaded. This is an actual SDK/prover client, not an authentication server.
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { once } from 'node:events'
import { createInterface } from 'node:readline'
import path from 'node:path'
import { artifactHashes, circuitDirectory, walletModules } from '../../tools/v2-test-wallet/artifacts.mjs'

const modules = walletModules
const require = createRequire(path.join(modules, '../package.json'))
assert.equal(JSON.parse(readFileSync(path.join(modules, '@0xpolygonid/js-sdk/package.json'), 'utf8')).version, '1.43.0')
const sdk = require('@0xpolygonid/js-sdk'), core = require('@iden3/js-iden3-core')
const jwz = require('@iden3/js-jwz')
const merkle = require('@iden3/js-merkletree'), { Interface } = require('ethers')
const stateABI = new Interface(JSON.parse(readFileSync(path.join(modules, '@0xpolygonid/js-sdk/src/storage/blockchain/abi/State.json'), 'utf8')))
// Keep stdout a JSON-lines machine channel, even for SDK diagnostics.
console.log = (...args) => process.stderr.write(args.map(x => String(x).slice(0, 2048)).join(' ') + '\n')
const output = value => process.stdout.write(JSON.stringify(value) + '\n')
const digest = value => createHash('sha256').update(value).digest('hex')
const network = 'polygon:mumbai', chainId = '80001', stateContract = '0x1111111111111111111111111111111111111111'
const contextUrl = 'https://schemas.test/bank-role.jsonld', schemaUrl = 'https://schemas.test/bank-role.json'
const roleContext = { '@context': [{ '@version': 1.1, '@protected': true, id: '@id', type: '@type', BankRole: {
  '@id': 'https://schemas.test/BankRole', '@context': { '@propagate': true, '@protected': true,
    iden3_serialization: 'iden3:v1:slotIndexA=role', role: { '@id': 'https://schemas.test/role', '@type': 'http://www.w3.org/2001/XMLSchema#integer' } },
} }] }
const schema = { $schema: 'http://json-schema.org/draft-07/schema#', $metadata: { uris: { jsonLdContext: contextUrl } },
  type: 'object', required: ['credentialSubject'], properties: { credentialSubject: { type: 'object', required: ['role'], properties: { role: { type: 'integer' } } } } }
const documents = new Map([[contextUrl, roleContext], [schemaUrl, schema],
  [sdk.VerifiableConstants.JSONLD_SCHEMA.W3C_CREDENTIAL_2018, JSON.parse(sdk.VerifiableConstants.JSONLD_SCHEMA.W3C_VC_DOCUMENT_2018)],
  [sdk.VerifiableConstants.JSONLD_SCHEMA.IDEN3_CREDENTIAL, JSON.parse(sdk.VerifiableConstants.JSONLD_SCHEMA.IDEN3_PROOFS_DEFINITION_DOCUMENT)],
  [sdk.VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSONLD_URL, JSON.parse(sdk.VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSONLD)],
  [sdk.VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSON_URL, JSON.parse(sdk.VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSON)]])
const loader = async url => {
  assert.equal(typeof url, 'string'); assert.ok(documents.has(url), 'unapproved fixture document')
  return { contextUrl: null, documentUrl: url, document: structuredClone(documents.get(url)) }
}
const files = {
  authV2: { dir: circuitDirectory('authV2'), hashes: artifactHashes.authV2 },
  credentialAtomicQuerySigV2: { dir: circuitDirectory('credentialAtomicQuerySigV2'), hashes: artifactHashes.credentialAtomicQuerySigV2 },
}
const loaded = new Map()
const circuits = {
  async loadCircuitData(id) {
    assert.ok(Object.hasOwn(files, id), 'unapproved circuit')
    if (!loaded.has(id)) {
      const spec = files[id]
      const values = ['circuit.wasm', 'circuit_final.zkey', 'verification_key.json'].map((name, i) => {
        const b = readFileSync(path.join(spec.dir, name)); assert.equal(digest(b), spec.hashes[i]); return Uint8Array.from(b)
      })
      loaded.set(id, { circuitId: id, wasm: values[0], provingKey: values[1], verificationKey: values[2] })
    }
    return loaded.get(id)
  },
  async saveCircuitData() { throw new Error('fixture circuit storage is readonly') },
}
const known = new Map(), rpcCounts = {}
const gist = new merkle.Merkletree(new merkle.InMemoryDB(new Uint8Array([1, 2, 3])), true, 64)
const rootInfo = new Map([['0', { root: 0n, replacedByRoot: 0n, createdAtTimestamp: 1n,
  replacedAtTimestamp: 0n, createdAtBlock: 1n, replacedAtBlock: 0n }]])
const abiServer = createServer(async (req, res) => {
  try {
    assert.equal(req.method, 'POST')
    let bytes = 0, raw = ''
    for await (const c of req) { bytes += c.length; assert.ok(bytes <= 65536); raw += c.toString('utf8') }
    const incoming = JSON.parse(raw), batch = Array.isArray(incoming) ? incoming : [incoming]
    assert.ok(batch.length <= 8)
    const results = []
    for (const q of batch) {
      try {
      rpcCounts[q.method] = (rpcCounts[q.method] ?? 0) + 1
      let result
      if (q.method === 'eth_chainId') result = '0x13881'
      else if (q.method === 'eth_getCode') { assert.equal(q.params[0].toLowerCase(), stateContract); result = '0x01' }
      else {
        assert.equal(q.method, 'eth_call')
        assert.equal(q.params[0].to.toLowerCase(), stateContract)
        const parsed = stateABI.parseTransaction({ data: q.params[0].data ?? q.params[0].input })
        assert.ok(parsed)
        rpcCounts[parsed.name] = (rpcCounts[parsed.name] ?? 0) + 1
        let row
        if (parsed.name === 'getGISTProof') {
          assert.ok(known.has(parsed.args[0].toString()))
          const actual = await gist.generateProof(parsed.args[0])
          const siblings = actual.proof.allSiblings().map(x => x.bigInt())
          while (siblings.length < 64) siblings.push(0n)
          row = { root: (await gist.root()).bigInt(), existence: actual.proof.existence, siblings,
            index: parsed.args[0], value: actual.proof.existence ? known.get(parsed.args[0].toString()) : 0n, auxExistence: !!actual.proof.nodeAux,
            auxIndex: actual.proof.nodeAux?.key.bigInt() ?? 0n, auxValue: actual.proof.nodeAux?.value.bigInt() ?? 0n }
        } else if (parsed.name === 'getGISTRootInfo') {
          row = rootInfo.get(parsed.args[0].toString())
          if (!row) throw new Error('RootDoesNotExist')
        } else if (parsed.name === 'getStateInfoById' || parsed.name === 'getStateInfoByIdAndState') {
          const state = known.get(parsed.args[0].toString())
          if (state === undefined || parsed.name === 'getStateInfoByIdAndState' && state !== parsed.args[1]) throw new Error('StateDoesNotExist')
          row = { id: parsed.args[0], state, replacedByState: 0n, createdAtTimestamp: 1n, replacedAtTimestamp: 0n, createdAtBlock: 1n, replacedAtBlock: 0n }
        } else throw new Error('unsupported fixture getter')
        result = stateABI.encodeFunctionResult(parsed.name, [row])
      }
      results.push({ jsonrpc: '2.0', id: q.id, result })
      } catch (error) {
        const missing = ['StateDoesNotExist', 'RootDoesNotExist'].includes(error.message)
        let data
        if (missing) { try { data = stateABI.encodeErrorResult(error.message, []) } catch { /* Message remains explicit. */ } }
        results.push({ jsonrpc: '2.0', id: q.id, error: { code: missing ? -32000 : -32602,
          message: missing ? 'execution reverted: ' + error.message : 'invalid public fixture RPC', ...(data ? { data } : {}) } })
      }
    }
    res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(Array.isArray(incoming) ? results : results[0]))
  } catch (error) {
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32000, message: String(error.message).slice(0, 256) } }))
  }
})
abiServer.listen(0, '127.0.0.1'); await once(abiServer, 'listening')
const rpcUrl = 'http://127.0.0.1:' + abiServer.address().port
const stateStorage = new sdk.EthStateStorage({ ...sdk.defaultEthConnectionConfig, url: rpcUrl, contractAddress: stateContract, chainId: 80001 }, { disableCache: true })
stateStorage.disableCache()
const storage = { credential: new sdk.CredentialStorage(new sdk.InMemoryDataSource()),
  identity: new sdk.IdentityStorage(new sdk.InMemoryDataSource(), new sdk.InMemoryDataSource()),
  mt: new sdk.InMemoryMerkleTreeStorage(40), states: stateStorage }
const kms = new sdk.KMS(), privateKeys = new sdk.InMemoryPrivateKeyStore()
kms.registerKeyProvider(sdk.KmsKeyType.BabyJubJub, new sdk.BjjProvider(sdk.KmsKeyType.BabyJubJub, privateKeys))
const resolvers = new sdk.CredentialStatusResolverRegistry()
let wallet
resolvers.register(sdk.CredentialStatusType.Iden3ReverseSparseMerkleTreeProof, { resolve: async (status, opts) => {
  assert.ok(opts?.issuerDID)
  const model = await wallet.getDIDTreeModel(opts.issuerDID)
  const actual = await wallet.generateNonRevocationMtpWithNonce(opts.issuerDID, BigInt(status.revocationNonce))
  return { issuer: { state: model.state.hex(), claimsTreeRoot: actual.treeState.claimsRoot.hex(),
    revocationTreeRoot: actual.treeState.revocationRoot.hex(), rootOfRoots: actual.treeState.rootOfRoots.hex() }, mtp: actual.proof }
} })
const credentialWallet = new sdk.CredentialWallet(storage, resolvers)
wallet = new sdk.IdentityWallet(kms, storage, credentialWallet)
const makeIdentity = async byte => wallet.createIdentity({ method: core.DidMethod.Iden3, blockchain: core.Blockchain.Polygon,
  networkId: core.NetworkId.Mumbai, seed: new Uint8Array(32).fill(byte), revocationOpts: {
    type: sdk.CredentialStatusType.Iden3ReverseSparseMerkleTreeProof, id: 'https://fixture.invalid/rhs', nonce: 0, genesisPublishingDisabled: true } })

try {
  const demo = process.env.OPS_PRIVADO_WALLET_DEMO === '1'
  const a = await makeIdentity(0x42), b = await makeIdentity(0x44), issuer = await makeIdentity(0x43), verifier = await makeIdentity(0x45)
  const holders = demo ? Object.fromEntries(await Promise.all(['admin', 'deployer', 'reader', 'outsider']
    .map(async (id, index) => [id, await makeIdentity(0x50 + index)]))) : { a, b }
  const roles = demo ? { admin: 1, deployer: 2, reader: 3 } : { a: 7, b: 7 }
  const credentials = {}
  for (const [name, holder] of Object.entries(holders)) {
    if (!Object.hasOwn(roles, name)) continue // Outsider proves identity without a role grant.
    const credential = await wallet.issueCredential(issuer.did, { credentialSchema: schemaUrl, type: 'BankRole',
      credentialSubject: { id: holder.did.string(), role: roles[name] }, expiration: 4102444800,
      revocationOpts: { type: sdk.CredentialStatusType.Iden3ReverseSparseMerkleTreeProof, id: 'https://fixture.invalid/rhs', nonce: 7 } }, { documentLoader: loader })
    await credentialWallet.save(credential); credentials[name] = credential
  }
  for (const who of [...Object.values(holders), issuer, verifier]) {
    const model = await wallet.getDIDTreeModel(who.did)
    known.set(core.DID.idFromDID(who.did).bigInt().toString(), model.state.bigInt())
  }
  const proofCache = new sdk.InMemoryProofStorage(), realProver = new sdk.NativeProver(circuits)
  const generation = { role: 0, outerInputs: 0 }
  const prover = { generate: async (inputs, id) => { generation.role++; return realProver.generate(inputs, id) }, verify: realProver.verify.bind(realProver) }
  const proofService = new sdk.ProofService(wallet, credentialWallet, circuits, stateStorage,
    { documentLoader: loader, proofsCacheStorage: proofCache, prover })
  const authInputs = proofService.generateAuthInputs.bind(proofService)
  proofService.generateAuthInputs = async (...args) => { generation.outerInputs++; return authInputs(...args) }
  const packers = new sdk.PackageManager()
  packers.registerPackers([new sdk.DefaultZKPPacker(circuits, proofService), new sdk.PlainPacker()])
  const handler = new sdk.AuthHandler(packers, proofService)
  output({ type: 'ready', testOnly: 'NEW PUBLIC fixture seeds42/44/43/45;demo50-53;not user material', sdkVersion: '1.43.0',
    holderA: a.did.string(), holderB: b.did.string(), issuerDid: issuer.did.string(), verifierDid: verifier.did.string(),
    ...(demo ? { personas: Object.entries(holders).map(([id, holder]) => ({ id, holderDid: holder.did.string(),
      roleValue: roles[id] ?? null, profileId: `demo-${id}` })) } : {}),
    contextUrl, context: roleContext, network, chainId, stateContract, rpcUrl,
    states: [...known].map(([id, state]) => ({ id, state: state.toString() })) })
  const RealDate = globalThis.Date
  let gistAdvances = 0
  for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
    let id
    try {
      assert.ok(Buffer.byteLength(line) <= 128 * 1024)
      const input = JSON.parse(line); id = input.id
      assert.ok(typeof id === 'string' && id.length <= 128)
      if (input.action === 'advance-gist') {
        assert.ok(!demo, 'Mutable GIST controls are available only in the isolated test fixture')
        const who = [verifier, issuer, a, b][gistAdvances]
        assert.ok(who, 'fixture GIST advance bound')
        const previous = (await gist.root()).bigInt(), at = BigInt(Math.floor(RealDate.now() / 1000))
        const key = core.DID.idFromDID(who.did).bigInt()
        await gist.add(key, known.get(key.toString()))
        const root = (await gist.root()).bigInt(), old = rootInfo.get(previous.toString())
        rootInfo.set(previous.toString(), { ...old, replacedByRoot: root, replacedAtTimestamp: at, replacedAtBlock: BigInt(gistAdvances + 2) })
        rootInfo.set(root.toString(), { root, replacedByRoot: 0n, createdAtTimestamp: at,
          replacedAtTimestamp: 0n, createdAtBlock: BigInt(gistAdvances + 2), replacedAtBlock: 0n })
        gistAdvances++
        output({ id, root: root.toString(), previousRoot: previous.toString() })
        continue
      }
      assert.ok(Object.hasOwn(holders, input.holder))
      assert.ok(Buffer.byteLength(JSON.stringify(input.request)) <= 65536)
      const request = input.request
      assert.ok(Number.isSafeInteger(request.created_time) && request.created_time > 0)
      // A controlled fixture clock creates a NEW witness/proof. This never
      // edits an existing proof/public signal or resets cached source age.
      globalThis.Date = class extends RealDate {
        constructor(...args) { if (args.length) super(...args); else super(request.created_time * 1000) }
        static now() { return request.created_time * 1000 }
      }
      const holder = holders[input.holder], prior = { ...generation }, scope = request.body.scope
      assert.ok(Array.isArray(scope) && scope.length <= 16 && scope.every((s, i) => s.id === i + 1 && s.circuitId === 'credentialAtomicQuerySigV2'))
      assert.ok(credentials[input.holder] || scope.length === 0, 'This demo identity has no role credential')
      const hadCache = scope.length ? !!await proofCache.getProof(holder.did, credentials[input.holder].id, scope[0]) : false
      const bypass = input.cacheMode !== 'use'
      const response = await handler.handleAuthorizationRequest(holder.did, sdk.byteEncoder.encode(JSON.stringify(request)),
        { mediaType: sdk.PROTOCOL_CONSTANTS.MediaType.ZKPMessage, bypassProofsCache: bypass })
      for (const proof of response.authResponse.body.scope) assert.ok(await realProver.verify(proof, proof.circuitId), 'generated role proof verification failed')
      const token = await jwz.Token.parse(response.token)
      assert.ok(await token.verify((await circuits.loadCircuitData('authV2')).verificationKey), 'generated AuthV2 envelope verification failed')
      // Deliberately retain a REAL generated proof to test the next bypass,
      // rather than using an empty cache that could mask accidental reuse.
      for (let i = 0; i < scope.length; i++) await proofCache.storeProof(holder.did, credentials[input.holder].id, scope[i], response.authResponse.body.scope[i])
      const signals = response.authResponse.body.scope.map(p => p.pub_signals)
      output({ id, compact: response.token, claimsAsOf: signals.length ? Number(signals[0][7]) : request.created_time,
        diagnostics: { bypassProofsCache: bypass, stateCacheDisabled: true, hadCache, roleGenerations: generation.role - prior.role,
          outerGenerations: generation.outerInputs - prior.outerInputs, generatedCryptoVerified: true,
          innerProofDigests: response.authResponse.body.scope.map(p => digest(JSON.stringify(p.proof))), rpcCounts: { ...rpcCounts } } })
    } catch (error) { output({ id, error: String(error.message).slice(0, 2048) }) }
    finally { globalThis.Date = RealDate }
  }
} finally {
  stateStorage.provider.destroy(); abiServer.closeAllConnections(); await new Promise(resolve => abiServer.close(resolve))
}
