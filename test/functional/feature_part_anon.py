#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework, connect_nodes_bi, isclose
from test_framework.util import assert_raises_rpc_error

import random


class AnonTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [ ['-debug','-noacceptnonstdtxn','-reservebalance=10000000'] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        self.sync_all()

    def run_test(self):
        nodes = self.nodes

        self.import_genesis_coins_a(nodes[0])
        txnHashes = []

        nodes[1].extkeyimportmaster('drip fog service village program equip minute dentist series hawk crop sphere olympic lazy garbage segment fox library good alley steak jazz force inmate')
        sxAddrTo1_1 = nodes[1].getnewstealthaddress('lblsx11')
        assert(sxAddrTo1_1 == 'TetbYTGv5LiqyFiUD3a5HHbpSinQ9KiRYDGAMvRzPfz4RnHMbKGAwDr1fjLGJ5Eqg1XDwpeGyqWMiwdK3qM3zKWjzHNpaatdoHVzzA')
        nodes[2].extkeyimportmaster(nodes[2].mnemonic('new')['master'])

        sxAddrTo0_1 = nodes[0].getnewstealthaddress('lblsx01')

        txnHashes.append(nodes[0].sendparttoanon(sxAddrTo1_1, 1, '', '', False, 'node0 -> node1 p->a'))
        txnHashes.append(nodes[0].sendparttoblind(sxAddrTo0_1, 1000, '', '', False, 'node0 -> node0 p->b'))
        txnHashes.append(nodes[0].sendblindtoanon(sxAddrTo1_1, 100, '', '', False, 'node0 -> node1 b->a 1'))
        txnHashes.append(nodes[0].sendblindtoanon(sxAddrTo1_1, 100, '', '', False, 'node0 -> node1 b->a 2'))
        txnHashes.append(nodes[0].sendblindtoanon(sxAddrTo1_1, 100, '', '', False, 'node0 -> node1 b->a 3'))
        txnHashes.append(nodes[0].sendblindtoanon(sxAddrTo1_1, 10, '', '', False, 'node0 -> node1 b->a 4'))

        for k in range(5):
            txnHash = nodes[0].sendparttoanon(sxAddrTo1_1, 10, '', '', False, 'node0 -> node1 p->a')
            txnHashes.append(txnHash)
        for k in range(10):
            txnHash = nodes[0].sendblindtoanon(sxAddrTo1_1, 10, '', '', False, 'node0 -> node1 b->a')
            txnHashes.append(txnHash)

        for i, h in enumerate(txnHashes):
            assert (self.wait_for_mempool(nodes[1], h))
            tx0 = nodes[0].gettransaction(h)
            assert(tx0['type_in'] == ('plain' if i < 2 or (i > 5 and i < 11) else 'blind'))
            if i != 1:
                tx1 = nodes[1].gettransaction(h)
                assert(tx1['type_in'] == ('plain' if i < 2 or (i > 5 and i < 11) else 'blind'))

        assert('node0 -> node1 b->a 4' in self.dumpj(nodes[1].listtransactions('*', 100)))
        assert('node0 -> node1 b->a 4' in self.dumpj(nodes[0].listtransactions('*', 100)))

        self.stakeBlocks(2)

        block1_hash = nodes[1].getblockhash(1)
        ro = nodes[1].getblock(block1_hash)
        for i, h in enumerate(txnHashes):
            assert (h in ro['tx'])
            tx0 = nodes[0].gettransaction(h)
            assert(tx0['type_in'] == ('plain' if i < 2 or (i > 5 and i < 11) else 'blind'))
            if i != 1:
                tx1 = nodes[1].gettransaction(h)
                assert(tx1['type_in'] == ('plain' if i < 2 or (i > 5 and i < 11) else 'blind'))

        txnHash = nodes[1].sendanontoanon(sxAddrTo0_1, 1, '', '', False, 'node1 -> node0 a->a', 5)
        txnHashes = [txnHash,]
        assert(nodes[1].gettransaction(txnHash)['type_in'] == 'anon')

        # Get a change address
        change_addr2 = nodes[2].deriverangekeys(0, 0, 'internal', False, True)[0]
        addr_info = nodes[2].getaddressinfo(change_addr2)
        assert(addr_info['ischange'] is True)

        # Receiving wallet should not mark an output as change if tx spends no inputs
        txnHash2 = nodes[1].sendtypeto('anon', 'part', [{'address': change_addr2, 'amount': 1, 'narr': 'node1 -> node2 a->p'}, ], '', '', 5)
        txnHashes.append(txnHash2)

        assert(nodes[1].gettransaction(txnHash2)['type_in'] == 'anon')

        for h in txnHashes:
            assert (self.wait_for_mempool(nodes[0], h))
            assert (self.wait_for_mempool(nodes[2], h))
        self.stakeBlocks(1)

        assert(nodes[0].gettransaction(txnHash)['type_in'] == 'anon')
        assert(nodes[1].gettransaction(txnHash2)['type_in'] == 'anon')
        assert(nodes[2].gettransaction(txnHash2)['type_in'] == 'anon')

        ro = nodes[1].getblock(nodes[1].getblockhash(3))
        for txnHash in txnHashes:
            assert(txnHash in ro['tx'])

        assert(nodes[1].anonoutput()['lastindex'] == 29)

        self.log.info('Test listsinceblock')
        block2_hash = nodes[0].getblockhash(2)
        rv = nodes[0].listsinceblock(block2_hash)
        assert(len(rv['transactions']) == 2)
        found_txn = False
        for txn in rv['transactions']:
            if txn['txid'] == txnHashes[0]:
                found_txn = True
            else:
                assert(txn['category'] == 'stake')
        assert(found_txn is True)

        rv = nodes[1].listsinceblock(block2_hash)
        assert(len(rv['transactions']) == 2)
        for txn in rv['transactions']:
            assert(float(txn['amount']) == -1.0)
            assert(txn['category'] == 'send')

        rv = nodes[2].listsinceblock(block2_hash)
        assert(len(rv['transactions']) == 1)
        assert(rv['transactions'][0]['txid'] == txnHash2)

        txnHashes.clear()
        txnHashes.append(nodes[1].sendanontoanon(sxAddrTo0_1, 101, '', '', False, 'node1 -> node0 a->a', 5, 1))
        txnHashes.append(nodes[1].sendanontoanon(sxAddrTo0_1, 0.1, '', '', False, '', 5, 2))

        assert(nodes[1].getwalletinfo()['anon_balance'] > 10)

        outputs = [{'address': sxAddrTo0_1, 'amount': 10, 'subfee': True},]
        ro = nodes[1].sendtypeto('anon', 'part', outputs, 'comment_to', 'comment_from', 4, 32, True)
        assert(ro['bytes'] > 0)

        txnHashes.append(nodes[1].sendtypeto('anon', 'part', outputs, '', '', 5))
        txnHashes.append(nodes[1].sendtypeto('anon', 'anon', [{'address': sxAddrTo1_1, 'amount': 1},], '', '', 5))

        for txhash in txnHashes:
            assert(self.wait_for_mempool(nodes[0], txhash))

        self.log.info('Test filtertransactions with type filter')
        ro = nodes[1].filtertransactions({'type': 'anon', 'count': 20, 'show_anon_spends': True, 'show_change': True})
        assert(len(ro) > 2)
        foundTx = 0
        for t in ro:
            if t['txid'] == txnHashes[-1]:
                foundTx += 1
                assert(t['amount'] == t['fee'])
            elif t['txid'] == txnHashes[-2]:
                foundTx += 1
                assert ('anon_inputs' in t)
                assert (t['amount'] == -10.0)

                output_value = 0
                for i in range(2):
                    if 'is_change' in t['outputs'][i] and t['outputs'][i]['is_change']:
                        continue
                    output_value += t['outputs'][i]['amount']
                assert (isclose(output_value + t['fee'], -10.0))
                n_standard = 0
                n_anon = 0
                for to in t['outputs']:
                    if to['type'] == 'standard':
                        n_standard += 1
                    elif to['type'] == 'anon':
                        n_anon += 1
                        assert (to['is_change'] is True)
                assert (n_standard == 1)
                assert (n_anon > 0)
                assert (t['type_in'] == 'anon')
            if t['txid'] == txnHashes[-3]:
                foundTx += 1
                assert(t['outputs'][0]['type'] == 'anon')
            if foundTx > 2:
                break
        assert(foundTx > 2)

        self.log.info('Test unspent with address filter')
        unspent_filtered = nodes[1].listunspentanon(1, 9999, [sxAddrTo1_1])
        assert(unspent_filtered[0]['label'] == 'lblsx11')

        self.log.info('Test permanent lockunspent')
        unspent = nodes[1].listunspentanon()
        assert(nodes[1].lockunspent(False, [unspent[0]], True) == True)
        assert(nodes[1].lockunspent(False, [unspent[1]], True) == True)
        assert(len(nodes[1].listlockunspent()) == 2)
        locked_balances = nodes[1].getlockedbalances()
        assert(locked_balances['trusted_anon'] > 0.0)
        assert(locked_balances['num_locked'] == 2)
        # Restart node
        self.sync_all()
        self.stop_node(1)
        self.start_node(1, self.extra_args[1])
        connect_nodes_bi(self.nodes, 0, 1)
        assert(len(nodes[1].listlockunspent()) == 2)
        assert(len(nodes[1].listunspentanon()) < len(unspent))
        assert(nodes[1].lockunspent(True, [unspent[0]]) == True)
        assert_raises_rpc_error(-8, 'Invalid parameter, expected locked output', nodes[1].lockunspent, True, [unspent[0]])
        assert(len(nodes[1].listunspentanon()) == len(unspent)-1)
        assert(nodes[1].lockunspent(True) == True)
        assert(len(nodes[1].listunspentanon()) == len(unspent))
        assert(nodes[1].lockunspent(True) == True)

        ro = nodes[2].getblockstats(nodes[2].getblockchaininfo()['blocks'])
        assert(ro['height'] == 3)

        self.log.info('Test recover from mnemonic')
        # Txns currently in the mempool will be reprocessed in the next block
        self.stakeBlocks(1)
        wi_1 = nodes[1].getwalletinfo()

        nodes[1].createwallet('test_import')
        w1_2 = nodes[1].get_wallet_rpc('test_import')
        w1_2.extkeyimportmaster('drip fog service village program equip minute dentist series hawk crop sphere olympic lazy garbage segment fox library good alley steak jazz force inmate')
        w1_2.getnewstealthaddress('lblsx11')
        w1_2.rescanblockchain(0)
        wi_1_2 = w1_2.getwalletinfo()
        assert(wi_1_2['anon_balance'] == wi_1['anon_balance'])

        nodes[1].createwallet('test_import_locked')
        w1_3 = nodes[1].get_wallet_rpc('test_import_locked')
        w1_3.encryptwallet('test')

        assert_raises_rpc_error(-13, 'Error: Wallet locked, please enter the wallet passphrase with walletpassphrase first.', w1_3.filtertransactions, {'show_blinding_factors': True})
        assert_raises_rpc_error(-13, 'Error: Wallet locked, please enter the wallet passphrase with walletpassphrase first.', w1_3.filtertransactions, {'show_anon_spends': True})

        w1_3.walletpassphrase('test', 30)

        # Skip initial rescan by passing -1 as scan_chain_from
        w1_3.extkeyimportmaster('drip fog service village program equip minute dentist series hawk crop sphere olympic lazy garbage segment fox library good alley steak jazz force inmate',
            '', False, 'imported key', 'imported acc', -1)
        w1_3.getnewstealthaddress('lblsx11')
        w1_3.walletsettings('other', {'onlyinstance': False})
        w1_3.walletlock()
        assert(w1_3.getwalletinfo()['encryptionstatus'] == 'Locked')
        w1_3.rescanblockchain(0)

        w1_3.walletpassphrase('test', 30)

        wi_1_3 = w1_3.getwalletinfo()
        assert(wi_1_3['anon_balance'] == wi_1['anon_balance'])

        self.log.info('Test receiving from locked wallet')
        sxaddr_to = w1_3.getnewstealthaddress('locked receive')
        w1_3.walletlock()
        nodes[1].createwallet('test_genesis_coins_2')
        w1_4 = nodes[1].get_wallet_rpc('test_genesis_coins_2')
        self.import_genesis_coins_b(w1_4)
        assert(w1_3.getwalletinfo()['encryptionstatus'] == 'Locked')
        txid = w1_4.sendtypeto('part', 'anon', [{'address': sxaddr_to, 'amount': 5}, ])
        assert(self.wait_for_wtx(w1_3, txid))

        ft = w1_3.filtertransactions()
        found_tx = False
        for tx in ft:
            if tx['txid'] == txid:
                assert(tx['requires_unlock'] == 'true')
                found_tx = True
                break
        assert(found_tx)

        w1_3.walletpassphrase('test', 30)

        ft = w1_3.filtertransactions()
        found_tx = False
        for tx in ft:
            if tx['txid'] == txid:
                assert('requires_unlock' not in tx)
                found_tx = True
                break
        assert(found_tx)

        self.log.info('Test checkkeyimage')
        unspents = nodes[0].listunspentanon(0, 999999, [], True, {'show_pubkeys': True})
        anon_pubkey = unspents[0]['pubkey']
        keyimage = nodes[0].getkeyimage(anon_pubkey)['keyimage']
        spent = nodes[0].checkkeyimage(keyimage)
        assert(spent['spent'] is False)

        self.log.info('Test sendtypeto coincontrol')
        w1_inputs = w1_2.listunspentanon()
        assert(len(w1_inputs) > 1)
        use_input = w1_inputs[random.randint(0, len(w1_inputs) - 1)]

        coincontrol = {'inputs': [{'tx': use_input['txid'], 'n': use_input['vout']}]}
        txid = w1_2.sendtypeto('anon', 'anon', [{'address': sxAddrTo0_1, 'amount': 0.01}, ], '', '', 7, 1, False, coincontrol)

        w1_inputs_after = w1_2.listunspentanon()
        for txin in w1_inputs_after:
            if txin['txid'] == use_input['txid'] and txin['vout'] == use_input['vout']:
                raise ValueError('Output should be spent')

        # Test inputs are correct when detecting transaction in chain
        nodes[1].createwallet('test_detect_tx_in_chain')
        w1_5 = nodes[1].get_wallet_rpc('test_detect_tx_in_chain')
        w1_5.extkeyimportmaster(self.get_genesis_coins_a_mnemonic())
        ft = w1_5.filtertransactions({'count': 10000})
        for ftx in ft:
            gtx = w1_5.gettransaction(ftx['txid'])
            gtx0 = nodes[0].gettransaction(ftx['txid'])

            assert (ftx['type_in'] == gtx['type_in'])
            assert (ftx['amount'] == gtx['amount'])
            assert (gtx0['type_in'] == gtx['type_in'])
            assert (gtx0['amount'] == gtx['amount'])

        self.log.info('Test rollbackrctindex')
        nodes[0].rollbackrctindex()


if __name__ == '__main__':
    AnonTest().main()
