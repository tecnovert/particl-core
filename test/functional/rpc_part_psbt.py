#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Copyright (c) 2025 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Partially Signed Transaction RPCs.
"""
from test_framework.test_particl import ParticlTestFramework


class PSBTTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [ ['-debug','-noacceptnonstdtxn','-reservebalance=10000000'] for i in range(self.num_nodes)]

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

        wallet = self.nodes[0].get_wallet_rpc("default_wallet")
        unconfirmed_txid = wallet.sendtoaddress(wallet.getnewaddress(), 0.5)

        self.log.info("Crafting PSBT using an unconfirmed input")
        target_address = self.nodes[1].getnewaddress()
        psbtx1 = wallet.walletcreatefundedpsbt([], {target_address: 0.1}, 0, {'fee_rate': 1, 'maxconf': 0})['psbt']
        decoded = self.nodes[0].decodepsbt(psbtx1)
        signed_tx1 = wallet.walletprocesspsbt(psbtx1)
        txid1 = self.nodes[0].sendrawtransaction(signed_tx1['hex'])

        mempool = self.nodes[0].getrawmempool()
        assert txid1 in mempool


if __name__ == '__main__':
    PSBTTest().main()
