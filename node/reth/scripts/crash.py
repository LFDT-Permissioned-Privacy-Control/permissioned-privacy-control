#!/usr/bin/env python3
"""Stop the guarded node around block production and check it recovers.

Reth's persistence threshold is set to 0 (not its default), so each new chain
head is written at once, asynchronously: a SIGKILL can still lose the newest
blocks. SIGKILL rounds aim at three states, read from the node's log, and each
records the state it actually hit:
- `pooled`: a batch was accepted and waits in the pool, no block built with it;
- `built`: a block with the batch was built, its manifest published and the
  block imported, but it is not yet the chain head, so the crash loses it;
- `committed`: up to 50 ms after the block with the batch became the head,
  while it is being persisted.
One round stops the node cleanly with SIGTERM: Reth then restores its pool
from the backup, while the node holds no identities. After every restart:
- the node starts on its state directory, ready with the facts it had;
- every block Reth reported saved survives (after a clean stop, every committed
  block), and every transaction verified before keeps its block unless that
  block was lost;
- a transaction without a receipt has no status: `ops_transactionStatus`
  refuses it;
- every transaction with a canonical receipt reports `included` through
  `ops_transactionStatus`, from its block's manifest;
- a restored pooled transaction does not execute without an identity;
- transactions without a receipt are submitted again, as their sender would
  (OPS does not resubmit them); every submission is accepted, also when the
  pool still holds the transaction, and all are included;
- the chain keeps growing, so produced blocks keep self-importing (every
  produced block is replayed from its manifest through newPayload).
A last SIGKILL and restart without new facts reads every inclusion from disk.
Exact storage sync points are covered by the in-process crash tests. Uses
public deterministic development keys only. Not a load or throughput
measurement: a few dozen transactions.
"""
import argparse
import base64
import copy
import hashlib
import http.client
import json
import os
import pathlib
import random
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = pathlib.Path(__file__).resolve().parents[3]
TARGET = '0x1f98431c8ad98523631ae4a59f267346ea31f984'
TOKEN = 'isolated-public-development-crash-token'
KEY = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
NETWORK = dict(chain_id=31337, deployment_id='crash-l2')
ADDED = re.compile(r'Block added to canonical chain number=(\d+) hash=(0x[0-9a-f]+) .*?txs=(\d+)')
COMMITTED = re.compile(r'Canonical chain committed number=(\d+) ')
FORKCHOICE = re.compile(r'Forkchoice updated head_block_hash=(0x[0-9a-f]+)')
SAVED = re.compile(r'Saved range of blocks .*last=NumHash \{ number: (\d+), hash: (0x[0-9a-f]+)')
MARKERS = ['execution replay', 'execution manifest', 'archived execution identity']
PHASES = ['pooled', 'built', 'committed']
BUILT_ATTEMPTS = 8


def encode(value):
    return json.dumps(value, separators=(',', ':')).encode()


def seal(kind, payload):
    raw = encode(payload)
    preimage = b'OPS_NODE_POLICY_V1\0'
    for part in [kind.encode(), b'crash', raw]:
        preimage += len(part).to_bytes(4, 'big') + part
    return dict(version=1, kind=kind, key_id='crash', payload=base64.b64encode(raw).decode(),
                signature=base64.b64encode(KEY.sign(preimage)).decode())


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def header(lifetime=300):
    now = int(time.time())
    return dict(network=NETWORK, issued_at=now - 1, expires_at=now + lifetime)


class Tail:
    """New complete lines of a file that may not exist yet."""

    def __init__(self, path):
        self.path = path
        self.offset = path.stat().st_size if path.exists() else 0
        self.partial = b''

    def lines(self):
        if not self.path.exists():
            return []
        with open(self.path, 'rb') as log:
            log.seek(self.offset)
            chunk = log.read()
        self.offset += len(chunk)
        lines = (self.partial + chunk).split(b'\n')
        self.partial = lines.pop()
        return [line.decode(errors='replace') for line in lines]


class Events:
    """Block production and persistence the node logged since its last start."""

    def __init__(self, work):
        self.node_log = Tail(work / 'node.log')
        # Reth's debug file log names the chain; there is one under `logs/`.
        found = sorted(work.glob('logs/*/reth.log'))
        self.file_log = Tail(found[0]) if found else None
        self.work = work
        self.added = {}
        self.committed = 0
        self.restored_head = None
        self.saved = (0, None)

    def poll(self):
        for line in self.node_log.lines():
            if match := ADDED.search(line):
                self.added[int(match[1])] = int(match[3])
            elif match := COMMITTED.search(line):
                self.committed = max(self.committed, int(match[1]))
            elif self.restored_head is None and (match := FORKCHOICE.search(line)):
                self.restored_head = match[1]
        if self.file_log is None:
            found = sorted(self.work.glob('logs/*/reth.log'))
            self.file_log = Tail(found[0]) if found else None
            if self.file_log:
                self.file_log.offset = 0
        for line in self.file_log.lines() if self.file_log else []:
            if (match := SAVED.search(line)) and int(match[1]) > self.saved[0]:
                self.saved = (int(match[1]), match[2])
        return self

    def last_added(self):
        return max(self.added, default=0)

    def with_transactions(self, after):
        return [number for number, txs in sorted(self.added.items()) if number > after and txs]

    def hit(self, start):
        """The state of the first batch submitted after block `start`, from the log."""
        blocks = self.with_transactions(start)
        if not blocks:
            return 'pooled'
        return 'built' if self.committed < blocks[0] else 'committed'

    def wait(self, condition, timeout, what):
        deadline = time.time() + timeout
        while not condition(self.poll()):
            if time.time() > deadline:
                raise RuntimeError(f'timeout waiting for {what}')
            time.sleep(.002)


class Node:
    def __init__(self, binary, work, senders):
        self.work = work
        self.public, self.private, auth, p2p = [free_port() for _ in range(4)]
        alloc = {address: dict(balance='0x3635c9adc5dea00000') for address in senders}
        alloc[TARGET] = dict(balance='0x0', code='0x00')
        config = dict(chainId=31337, homesteadBlock=0, eip150Block=0, eip155Block=0, eip158Block=0,
                      byzantiumBlock=0, constantinopleBlock=0, petersburgBlock=0, istanbulBlock=0,
                      berlinBlock=0, londonBlock=0, terminalTotalDifficulty=0,
                      terminalTotalDifficultyPassed=True, shanghaiTime=0)
        (work / 'genesis.json').write_bytes(encode(dict(config=config, nonce='0x0', timestamp='0x0', gasLimit='0x1c9c380',
                                                         difficulty='0x0', baseFeePerGas='0x3b9aca00', alloc=alloc)))
        self.env = dict(os.environ, OPS_NODE_POLICY_CHAIN_ID='31337', OPS_NODE_POLICY_DEPLOYMENT_ID=NETWORK['deployment_id'],
                        OPS_NODE_POLICY_PUBLIC_KEYS=json.dumps({'crash': base64.b64encode(KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()}),
                        OPS_NODE_POLICY_STATE_DIR=str(work / 'policy'), OPS_NODE_POLICY_LISTEN=f'127.0.0.1:{self.private}',
                        OPS_NODE_POLICY_TOKEN=TOKEN)
        self.command = [str(pathlib.Path(binary).resolve()), 'node', '--chain', str(work / 'genesis.json'),
                        '--dev', '--dev.finality-depth', '1', '--dev.block-time', '1s',
                        # Write every new head at once, so a crash hits blocks that
                        # survive in the chain database and must keep their evidence.
                        '--engine.persistence-threshold', '0',
                        '--datadir', str(work / 'data'), '--http', '--http.addr', '127.0.0.1', '--http.port', str(self.public),
                        '--http.api', 'eth,net,web3', '--authrpc.port', str(auth), '--addr', '127.0.0.1',
                        '--port', str(p2p), '--disable-discovery',
                        '--log.file.directory', str(work / 'logs'), '--color', 'never']
        self.log = open(work / 'node.log', 'a')
        self.process = None
        self.events = None

    def start(self):
        self.log.write(f'\n==== start {time.time()} ====\n')
        self.log.flush()
        self.events = Events(self.work)
        self.process = subprocess.Popen(self.command, cwd=ROOT, env=self.env, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 120
        while time.time() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('node exited during startup:\n' + (self.work / 'node.log').read_text()[-6000:])
            try:
                return self.rpc('ops_policyStatus', [], True, timeout=2)
            except (OSError, RuntimeError, http.client.HTTPException):
                time.sleep(.1)
        raise RuntimeError('node startup timeout')

    def kill(self):
        assert self.process.poll() is None, 'node exited before the kill'
        self.process.send_signal(signal.SIGKILL)
        assert self.process.wait(timeout=30) == -signal.SIGKILL

    def terminate(self):
        assert self.process.poll() is None, 'node exited before the shutdown'
        self.process.terminate()
        code = self.process.wait(timeout=60)
        assert code == 0, f'node did not shut down cleanly: exit {code}'

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.log.close()

    def rpc(self, method, params, private=False, check=True, timeout=30):
        connection = http.client.HTTPConnection('127.0.0.1', self.private if private else self.public, timeout=timeout)
        headers = {'Content-Type': 'application/json'}
        if private:
            headers['Authorization'] = 'Bearer ' + TOKEN
        try:
            connection.request('POST', '/', encode(dict(jsonrpc='2.0', id='crash', method=method, params=params)), headers)
            result = json.loads(connection.getresponse().read())
        finally:
            connection.close()
        if check and 'error' in result:
            raise RuntimeError(f'{method}: {result}')
        return result if not check else result['result']

    def block_number(self):
        return int(self.rpc('eth_blockNumber', []), 16)


def identity(tx, generation):
    return seal('identity', dict(header(), scope='transaction', context_id=f'crash-{generation}-{tx["hash"][2:18]}',
                                 principal_id='fixture_principal', org_id='org_acme', signer=tx['signer'].lower(),
                                 binding_hash=tx['hash'], min_snapshot_version=1))


def build_record(binary):
    """Which binary and source tree ran."""
    git = lambda *args: subprocess.run(['git', *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    return dict(binary_sha256=hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),
                git_rev=git('rev-parse', 'HEAD'), git_dirty=bool(git('status', '--porcelain', '--untracked-files=no')))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--rounds', type=int, default=6, help='SIGKILL rounds, cycling through the phases')
    parser.add_argument('--per-round', type=int, default=4)
    parser.add_argument('--seed', type=int, default=1410)
    args = parser.parse_args()
    if args.rounds < len(PHASES):
        parser.error(f'--rounds must cover the {len(PHASES)} phases')
    # A terminated check still stops its node.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    random.seed(args.seed)
    (ROOT / '.tmp').mkdir(exist_ok=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix='ops-reth-crash-', dir=ROOT / '.tmp'))
    # One batch per round and for the SIGTERM round, plus the retries of `built` rounds.
    count = args.per_round * (args.rounds + 1 + (BUILT_ATTEMPTS - 1) * ((args.rounds + 1) // 3))
    generated = json.loads(subprocess.check_output(['go', 'run', './node/reth/scripts/load-sign', '-count', str(count),
                                                    '-senders', '1', '-target', TARGET], cwd=ROOT))
    transactions = generated['transactions'][:count]
    senders = sorted({tx['signer'] for tx in transactions})
    snapshot = copy.deepcopy(json.loads((ROOT / 'internal/policydsl/testdata/lifecycle-v1.json').read_text())['snapshot'])
    snapshot['principals'][0]['linked_addresses'] += [address.lower() for address in senders]
    node = Node(args.binary, work, senders)
    report = dict(workdir=str(work), seed=args.seed, build=build_record(args.binary), rounds=[])
    state = dict(version=snapshot['version'], generation=0, cursor=0)
    submitted, verified = [], {}

    def publish():
        state['version'] += 1
        snapshot.update(header(), version=state['version'])
        node.rpc('ops_policyApply', [seal('snapshot', snapshot)], True)
        assert node.rpc('ops_policyStatus', [], True)['ready']

    def receipt(tx):
        return node.rpc('eth_getTransactionReceipt', [tx['hash']])

    def pooled(tx):
        found = node.rpc('eth_getTransactionByHash', [tx['hash']])
        return found is not None and found['blockHash'] is None

    def take():
        batch = transactions[state['cursor']:state['cursor'] + args.per_round]
        assert len(batch) == args.per_round, 'ran out of signed transactions'
        state['cursor'] += args.per_round
        return batch

    def submit(batch):
        for tx in batch:
            result = node.rpc('ops_submitTransaction', [identity(tx, state['generation']), tx['raw']], True)
            assert result['status'] == 'accepted' and result['transaction_hash'] == tx['hash'].lower(), result

    def submit_fresh():
        """Submit a new batch right after a block was built, about a block interval before the next one."""
        seen = node.events.poll().last_added()
        node.events.wait(lambda events: events.last_added() > seen, 10, 'a block')
        start = node.events.last_added()
        batch = take()
        submit(batch)
        submitted.extend(batch)
        return start, batch

    def check_included():
        included = 0
        for tx in submitted:
            found = receipt(tx)
            if not found:
                continue
            status = node.rpc('ops_transactionStatus', [tx['hash']], True)
            assert status['execution']['status'] == 'included', status
            assert status['execution']['block_hash'] == found['blockHash'], status
            assert status['principal_id'] == 'fixture_principal', status
            verified[tx['hash']] = (int(found['blockNumber'], 16), found['blockHash'])
            included += 1
        return included

    def restart(stopped, clean):
        """Restart after a stop and check what survived; returns the round record."""
        state['generation'] += 1
        status = node.start()
        assert status['ready'] and status['version'] == state['version'], f'facts lost across the restart: {status}'
        node.events.wait(lambda events: events.restored_head, 10, 'the restored head')
        after = int(node.rpc('eth_getBlockByHash', [node.events.restored_head, False])['number'], 16)
        saved_number, saved_hash = stopped.saved
        assert after >= saved_number, f'block {saved_number}, reported saved, was lost (head {after})'
        if saved_number:
            kept = node.rpc('eth_getBlockByNumber', [hex(saved_number), False])['hash']
            assert kept == saved_hash, f'saved block {saved_number} changed from {saved_hash} to {kept}'
        if clean:
            assert after >= stopped.committed, f'a clean stop lost blocks: {stopped.committed} -> {after}'
        for tx_hash, (number, block_hash) in list(verified.items()):
            found = node.rpc('eth_getTransactionReceipt', [tx_hash])
            if found:
                assert found['blockHash'] == block_hash, f'{tx_hash} moved from {block_hash} to {found["blockHash"]}'
            else:
                assert number > after, f'{tx_hash} lost from block {number}, below the head {after}'
                del verified[tx_hash]
        missing = [tx for tx in submitted if not receipt(tx)]
        for tx in missing:
            answer = node.rpc('ops_transactionStatus', [tx['hash']], True, check=False)
            assert 'error' in answer, f'status disclosed for a transaction without a receipt: {answer}'
        return dict(committed_at_stop=stopped.committed, saved_at_stop=saved_number, last_built_at_stop=stopped.last_added(),
                    head_after_restart=after, lost_blocks_with_txs=len(stopped.with_transactions(after)),
                    status_refused=len(missing))

    def resubmit_and_include(record):
        missing = [tx for tx in submitted if not receipt(tx)]
        submit(missing)
        record['resubmitted'] = len(missing)
        head = node.block_number()
        deadline = time.time() + 30
        while (node.block_number() < head + 2 or any(not receipt(tx) for tx in missing)) and time.time() < deadline:
            time.sleep(.1)
        assert node.block_number() >= head + 2, f'chain stopped after restart at {node.block_number()}'
        left = [tx['hash'] for tx in missing if not receipt(tx)]
        assert not left, f'resubmitted transactions not included: {left}'
        record['included'] = check_included()

    try:
        node.start()
        publish()
        for round_index in range(args.rounds):
            phase = PHASES[round_index % len(PHASES)]
            attempts = 1
            if phase == 'pooled':
                start, _ = submit_fresh()
            elif phase == 'built':
                for attempts in range(1, BUILT_ATTEMPTS + 1):
                    start, _ = submit_fresh()
                    node.events.wait(lambda events: events.with_transactions(start), 10, 'a block with the batch')
                    if node.events.hit(start) == 'built':
                        break
                    # The same tick's forkchoice update made it the head at once: try the next block.
                else:
                    raise RuntimeError(f'no built-but-uncommitted block in {BUILT_ATTEMPTS} attempts')
            else:
                start, _ = submit_fresh()
                node.events.wait(lambda events: events.with_transactions(start), 10, 'a block with the batch')
                number = node.events.with_transactions(start)[0]
                node.events.wait(lambda events: events.committed >= number, 10, 'its commit')
                time.sleep(random.uniform(0, .05))
            node.kill()
            stopped = node.events.poll()
            record = dict(round=round_index, phase=phase, hit=stopped.hit(start), signal='SIGKILL', attempts=attempts,
                          **restart(stopped, clean=False))
            publish()
            # The pool and the identities are gone after SIGKILL.
            resubmit_and_include(record)
            report['rounds'].append(record)
        hits = {r['hit'] for r in report['rounds']}
        assert hits >= set(PHASES), f'phases never hit: {set(PHASES) - hits}'

        # Clean shutdown: Reth saves the pool and restores it at start, without identities.
        start, batch = submit_fresh()
        node.terminate()
        stopped = node.events.poll()
        record = dict(round=args.rounds, phase='pooled', hit=stopped.hit(start), signal='SIGTERM', attempts=1,
                      **restart(stopped, clean=True))
        restored = [tx for tx in batch if not receipt(tx) and pooled(tx)]
        assert restored, 'the pool was not restored from its backup'
        assert all(receipt(tx) or tx in restored for tx in batch), 'a pooled transaction was lost on a clean shutdown'
        publish()
        head = node.block_number()
        deadline = time.time() + 30
        while node.block_number() < head + 2 and time.time() < deadline:
            time.sleep(.1)
        assert node.block_number() >= head + 2, 'chain stopped after the clean restart'
        assert not any(receipt(tx) for tx in restored), 'a restored transaction executed without an identity'
        assert all(pooled(tx) for tx in restored), 'a restored transaction left the pool'
        record['restored_in_pool'] = len(restored)
        # Every resubmission, of the restored transactions too, must be accepted.
        resubmit_and_include(record)
        report['rounds'].append(record)
        missing = [tx['hash'] for tx in submitted if not receipt(tx)]
        assert not missing, f'never included: {missing}'
        assert check_included() == len(submitted)

        # Restart once more without new facts: every inclusion is answered from disk.
        last = max(number for number, _ in verified.values())
        node.events.wait(lambda events: events.saved[0] >= last, 10, 'the last inclusion to be saved')
        node.kill()
        record = dict(round=args.rounds + 1, phase='final', signal='SIGKILL', attempts=1,
                      **restart(node.events.poll(), clean=False))
        record['included'] = check_included()
        assert record['included'] == len(submitted), record
        report['rounds'].append(record)
        report['transactions'] = len(submitted)

        log = (work / 'node.log').read_text()
        report['log_markers'] = {marker: log.count(marker) for marker in MARKERS}
        assert not any(report['log_markers'].values()), report['log_markers']
        report['ok'] = True
        (work / 'result.json').write_text(json.dumps(report, indent=2))
        print(json.dumps(report))
    except Exception:
        print((work / 'node.log').read_text()[-12000:])
        raise
    finally:
        node.stop()


if __name__ == '__main__':
    main()
