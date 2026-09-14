#!/usr/bin/env python3
# Copyright (c) 2026 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Regression test: the per-input split commitment must be canonically encoded.

When an anon spend has more than one input (fSplitCommitments), each input's
witness (vDL) ends with a 33-byte split commitment consumed by both load_ge
(MLSAG) and pedersen_verify_tally.  The commitment is in the witness, which is
excluded from the txid the MLSAG signs, so a same-point re-encoding (prefix
08->02 where the quad-y root is even) is pure witness malleability: both
loaders still see the same point, so the pre-fix code accepts it, while the
canonical parse in VerifyMLSAG rejects it.  No MLSAG reconstruction or
re-signing is needed because nothing binds the raw split-commitment bytes.
"""

from test_framework.test_particl import ParticlTestFramework
from test_framework.util import assert_raises_rpc_error

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def quad_y_is_odd(x_hex: str) -> bool:
    x = int(x_hex, 16)
    rhs = (pow(x, 3, P) + 7) % P
    y = pow(rhs, (P + 1) // 4, P)
    if (y * y - rhs) % P != 0:
        return None
    y_is_qr = pow(y, (P - 1) // 2, P) == 1
    quad = y if y_is_qr else (P - y)
    return (quad & 1) == 1


def same_point_flip(commit_hex):
    """Non-canonical prefix both loaders still read as the same point.

    Works when the quad-y root is even (08->02) or, equivalently, the actual
    point's y is odd for a 09 commitment (09->03); the low bit is preserved so
    the quad loader is unchanged and the parity loader agrees.
    """
    pfx = commit_hex[:2]
    if pfx not in ('08', '09') or quad_y_is_odd(commit_hex[2:]) is not False:
        return None
    return {'08': '02', '09': '03'}[pfx] + commit_hex[2:]


class AnonSplitCommitmentTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-debug', '-acceptnonstdtxn', '-reservebalance=10000000']
                           for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()
        self.connect_nodes_bi(0, 1)
        self.sync_all()

    def run_test(self):
        nodes = self.nodes
        self.import_genesis_coins_a(nodes[0])
        nodes[1].extkeyimportmaster(nodes[1].mnemonic('new')['master'])
        sx = nodes[1].getnewstealthaddress('sx')

        for _ in range(8):
            nodes[0].sendtypeto('part', 'anon', [{'address': sx, 'amount': 5}])
        self.stakeBlocks(2)
        assert nodes[1].getwalletinfo()['anon_balance'] >= 40

        sx0 = nodes[0].getnewstealthaddress('sx0')
        found = None
        for attempt in range(20):
            ro = nodes[1].sendtypeto(
                'anon', 'part',
                [{'address': sx0, 'amount': 8}],
                '', '', 3, 1, False,
                {'show_hex': True, 'submit_tx': False},
            )
            raw = ro['hex']
            dec = nodes[1].decoderawtransaction(raw)
            anon_vins = [v for v in dec['vin'] if v.get('type') == 'anon']
            self.log.info(f'attempt {attempt}: {len(dec["vin"])} inputs')
            if len(dec['vin']) < 2:
                continue
            for v in anon_vins:
                wit = v.get('txinwitness')
                if not wit or len(wit) < 2:
                    continue
                commit = wit[1][-66:]
                flipped = same_point_flip(commit)
                if flipped and raw.count(commit) == 1:
                    found = (raw, commit, flipped)
                    break
            if found:
                break
        assert found, 'could not build a multi-input spend with a malleable split commitment'

        raw, commit, flipped = found
        self.log.info(f'split commitment {commit} -> {flipped} (same point)')
        assert_raises_rpc_error(-26, 'bad-anonin-split-commitment',
                                nodes[1].sendrawtransaction, raw.replace(commit, flipped))
        self.log.info('flipped split commitment rejected')

        assert nodes[1].sendrawtransaction(raw)
        self.log.info('unmodified multi-input spend accepted')


if __name__ == '__main__':
    AnonSplitCommitmentTest().main()
