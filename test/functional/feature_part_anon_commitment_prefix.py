#!/usr/bin/env python3
# Copyright (c) 2026 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Regression test: output commitments must be canonically encoded.

A 33-byte Pedersen commitment is decoded two ways on the consensus path.  The
CT/bulletproof/tally loader reconstructs the point by quadratic-residue lift of
x and uses only bit 0 of the prefix byte.  MLSAG's load_ge routes only prefix
0x08/0x09 to that loader and parses anything else as a compressed pubkey,
selecting y by parity, so the same bytes decode to a different point.  The fix
rejects any output commitment that does not parse canonically, in both
CheckBlindOutput and CheckAnonOutput.

Each case builds a real transaction, flips the output commitment prefix
(08->02, 09->03, which keeps the CT-loaded point so the rangeproof and tally
still verify), re-signs so the input signatures are valid over the modified
transaction, and asserts consensus rejects it on the commitment alone.
"""

from test_framework.test_particl import ParticlTestFramework
from test_framework.util import assert_raises_rpc_error


def flip_prefix(commit_hex: str) -> str:
    mapping = {'08': '02', '09': '03'}
    pfx = commit_hex[:2]
    assert pfx in mapping, f'unexpected commitment prefix {pfx}'
    return mapping[pfx] + commit_hex[2:]


class AnonCommitmentPrefixTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-debug', '-acceptnonstdtxn', '-reservebalance=10000000']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def flipped_signed_tx(self, node, type_out, sx_addr, amount):
        """Build part->type_out, flip the output commitment prefix, re-sign."""
        ro = node.sendtypeto(
            'part', type_out,
            [{'address': sx_addr, 'amount': amount}],
            '', '', 5, 1, False,
            {'show_hex': True, 'submit_tx': False},
        )
        raw = ro['hex']
        dec = node.decoderawtransaction(raw)
        target = next(o for o in dec['vout']
                      if o.get('type') == type_out and 'valueCommitment' in o)
        commit = target['valueCommitment']
        assert raw.count(commit) == 1, 'commitment not uniquely locatable in raw tx'
        flipped = flip_prefix(commit)
        signed = node.signrawtransactionwithwallet(raw.replace(commit, flipped))
        assert signed['complete'], 'wallet could not re-sign the modified tx'
        return signed['hex'], commit, flipped

    def run_test(self):
        node = self.nodes[0]
        self.import_genesis_coins_a(node)
        sx = node.getnewstealthaddress('sx')

        assert node.sendtypeto('part', 'anon', [{'address': sx, 'amount': 10}])
        assert node.sendtypeto('part', 'blind', [{'address': sx, 'amount': 10}])
        self.log.info('canonical anon and blind outputs accepted')

        tx, commit, flipped = self.flipped_signed_tx(node, 'anon', sx, 100)
        self.log.info(f'anon commitment {commit} -> {flipped}')
        assert_raises_rpc_error(-26, 'bad-rctout-commitment',
                                node.sendrawtransaction, tx)
        self.log.info('flipped-prefix anon output rejected')

        tx, commit, flipped = self.flipped_signed_tx(node, 'blind', sx, 100)
        self.log.info(f'blind commitment {commit} -> {flipped}')
        assert_raises_rpc_error(-26, 'bad-ctout-commitment',
                                node.sendrawtransaction, tx)
        self.log.info('flipped-prefix blind output rejected')


if __name__ == '__main__':
    AnonCommitmentPrefixTest().main()
