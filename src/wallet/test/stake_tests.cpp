// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/hdwallet.h>
#include <wallet/coincontrol.h>
#include <interfaces/chain.h>

#include <wallet/test/hdwallet_test_fixture.h>
#include <chainparams.h>
#include <miner.h>
#include <pos/miner.h>
#include <timedata.h>
#include <coins.h>
#include <net.h>
#include <validation.h>
#include <blind.h>
#include <rpc/rpcutil.h>

#include <consensus/validation.h>

#include <chrono>
#include <thread>

#include <boost/test/unit_test.hpp>

struct StakeTestingSetup: public TestingSetup {
    StakeTestingSetup(const std::string& chainName = CBaseChainParams::REGTEST):
        TestingSetup(chainName, /* fParticlMode */ true)
    {
        ECC_Start_Stealth();
        ECC_Start_Blinding();

        bool fFirstRun;
        pwalletMain = std::make_shared<CHDWallet>(m_chain.get(), WalletLocation(), WalletDatabase::CreateMock());
        AddWallet(pwalletMain);
        pwalletMain->LoadWallet(fFirstRun);
        pwalletMain->Initialise();
        pwalletMain->m_chain_notifications_handler = m_chain->handleNotifications(*pwalletMain);

        m_chain_client->registerRpcs();

        SetMockTime(0);
    }

    ~StakeTestingSetup()
    {
        RemoveWallet(pwalletMain);
        pwalletMain.reset();

        mapStakeSeen.clear();
        listStakeSeen.clear();

        ECC_Stop_Stealth();
        ECC_Stop_Blinding();
    }

    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain(m_node);
    std::unique_ptr<interfaces::ChainClient> m_chain_client = interfaces::MakeWalletClient(*m_chain, {});
    std::shared_ptr<CHDWallet> pwalletMain;
};

BOOST_FIXTURE_TEST_SUITE(stake_tests, StakeTestingSetup)


void StakeNBlocks(CHDWallet *pwallet, size_t nBlocks)
{
    int nBestHeight;
    size_t nStaked = 0;
    size_t k, nTries = 10000;
    for (k = 0; k < nTries; ++k) {
        {
            LOCK(cs_main);
            nBestHeight = ::ChainActive().Height();
        }

        int64_t nSearchTime = GetAdjustedTime() & ~Params().GetStakeTimestampMask(nBestHeight+1);
        if (nSearchTime <= pwallet->nLastCoinStakeSearchTime) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }

        CScript coinbaseScript;
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(coinbaseScript, false));
        BOOST_REQUIRE(pblocktemplate.get());

        if (pwallet->SignBlock(pblocktemplate.get(), nBestHeight+1, nSearchTime)) {
            CBlock *pblock = &pblocktemplate->block;

            if (CheckStake(pblock)) {
                nStaked++;
            }
        }

        if (nStaked >= nBlocks) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    BOOST_REQUIRE(k < nTries);
};

static void AddAnonTxn(CHDWallet *pwallet, CBitcoinAddress &address, CAmount amount)
{
    {
    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);
    LockAssertion lock(::cs_main);

    BOOST_REQUIRE(address.IsValid());

    std::vector<CTempRecipient> vecSend;
    std::string sError;
    CTempRecipient r;
    r.nType = OUTPUT_RINGCT;
    r.SetAmount(amount);
    r.address = address.Get();
    vecSend.push_back(r);

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, std::move(tx_new));
    CTransactionRecord rtx;
    CAmount nFee;
    CCoinControl coinControl;
    BOOST_CHECK(0 == pwallet->AddStandardInputs(*locked_chain, wtx, rtx, vecSend, true, nFee, &coinControl, sError));

    wtx.BindWallet(pwallet);
    std::string err_string;
    BOOST_REQUIRE(wtx.SubmitMemoryPoolAndRelay(err_string, true));
    } // cs_main
    SyncWithValidationInterfaceQueue();
}

static CTransactionRef CreateTxn(CHDWallet *pwallet, CBitcoinAddress &address, CAmount amount, int type_in, int type_out, int nRingSize = 5)
{
    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);
    LockAssertion lock(::cs_main);

    BOOST_REQUIRE(address.IsValid());

    std::vector<CTempRecipient> vecSend;
    std::string sError;
    CTempRecipient r;
    r.nType = type_out;
    r.SetAmount(amount);
    r.address = address.Get();
    vecSend.push_back(r);

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;
    CAmount nFee;
    CCoinControl coinControl;
    if (type_in == OUTPUT_STANDARD) {
        BOOST_CHECK(0 == pwallet->AddStandardInputs(*locked_chain, wtx, rtx, vecSend, true, nFee, &coinControl, sError));
    } else
    if (type_in == OUTPUT_CT) {
        BOOST_CHECK(0 == pwallet->AddBlindedInputs(*locked_chain, wtx, rtx, vecSend, true, nFee, &coinControl, sError));
    } else {
        int nInputsPerSig = 1;
        BOOST_CHECK(0 == pwallet->AddAnonInputs(*locked_chain, wtx, rtx, vecSend, true, nRingSize, nInputsPerSig, nFee, &coinControl, sError));
    }
    return wtx.tx;
}

static void DisconnectTip(CBlock &block, CBlockIndex *pindexDelete, CCoinsViewCache &view, const CChainParams &chainparams)
{
    BlockValidationState state;
    BOOST_REQUIRE(DISCONNECT_OK == DisconnectBlock(block, pindexDelete, view));
    BOOST_REQUIRE(FlushView(&view, state, true));
    BOOST_REQUIRE(::ChainstateActive().FlushStateToDisk(chainparams, state, FlushStateMode::IF_NEEDED));
    ::ChainActive().SetTip(pindexDelete->pprev);
    UpdateTip(pindexDelete->pprev, chainparams);
};

#include <chrono>

void timeAddToWallet(const char *test_name, const char *ismine, CHDWallet *pw, CTransactionRef &tx)
{
    CWalletTx::Confirmation confirm;
    LOCK(cs_main);
    LOCK(pw->cs_wallet);
    auto start = std::chrono::steady_clock::now();
    pw->AddToWalletIfInvolvingMe(tx, confirm, true);
    auto end = std::chrono::steady_clock::now();
    auto diff = end - start;
    printf("%s %s took %ld ns (%ld ms)\n", test_name, ismine, std::chrono::duration_cast<std::chrono::nanoseconds>(diff).count(), std::chrono::duration_cast<std::chrono::milliseconds>(diff).count());
}

BOOST_AUTO_TEST_CASE(wallet_timing_test)
{
    CHDWallet *pwallet = pwalletMain.get();
    {
        LOCK(pwallet->cs_wallet);
        pwallet->SetLastBlockProcessed(::ChainActive().Height(), ::ChainActive().Tip()->GetBlockHash());
    }

    //printf("std::chrono::high_resolution_clock::period::num %ld\n", std::chrono::high_resolution_clock::period::num);
    //printf("std::chrono::high_resolution_clock::period::den %ld\n", std::chrono::high_resolution_clock::period::den);
    //printf("std::chrono::high_resolution_clock::is_steady   %d\n", std::chrono::high_resolution_clock::is_steady);

    printf("std::chrono::steady_clock::period::num %ld\n", std::chrono::steady_clock::period::num);
    printf("std::chrono::steady_clock::period::den %ld\n", std::chrono::steady_clock::period::den);
    printf("std::chrono::steady_clock::is_steady   %d\n", std::chrono::steady_clock::is_steady);

    uint64_t wallet_creation_flags = 0;
    SecureString passphrase;
    std::string error;
    std::vector<std::string> warnings;

    WalletLocation location("a");
    std::shared_ptr<CHDWallet> pwallet_a = std::static_pointer_cast<CHDWallet>(CWallet::CreateWalletFromFile(*m_chain.get(), location, error, warnings, wallet_creation_flags));
    BOOST_REQUIRE(pwallet_a.get());
    pwallet_a->Initialise();
    AddWallet(pwallet_a);


    WalletLocation location_b("b");
    std::shared_ptr<CHDWallet> pwallet_b = std::static_pointer_cast<CHDWallet>(CWallet::CreateWalletFromFile(*m_chain.get(), location_b, error, warnings, wallet_creation_flags));
    BOOST_REQUIRE(pwallet_b.get());
    pwallet_b->Initialise();
    AddWallet(pwallet_b);

    {
        LOCK(pwallet_a->cs_wallet);
        pwallet_a->SetLastBlockProcessed(::ChainActive().Height(), ::ChainActive().Tip()->GetBlockHash());
    }
    {
        LOCK(pwallet_b->cs_wallet);
        pwallet_b->SetLastBlockProcessed(::ChainActive().Height(), ::ChainActive().Tip()->GetBlockHash());
    }

    UniValue rv;
    BOOST_CHECK_NO_THROW(rv = CallRPC("listwallets"));
    printf("listwallets %s\n", rv.write().c_str());

    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPeK5mCpvMsd1cwyT1JZsrBN82XkoYuZY1EVK7EwDaiL9sDfqUU5SntTfbRfnRedFWjg5xkDG5i3iwd3yP7neX5F2dtdCojk4", "a"));
    // Import the key to the last 5 outputs in the regtest genesis coinbase
    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPe3x7bUzkHAJZzCuGqN6y28zFFyg5i7Yqxqm897VCnmMJz6QScsftHDqsyWW5djx6FzrbkF9HSD3ET163z1SzRhfcWxvwL4G", "a"));
    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewextaddress lblHDKey", "a"));

    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewaddress addr", "a"));
    CBitcoinAddress addr_a(StripQuotes(rv.write()));
    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewstealthaddress sx_addr", "a"));
    CBitcoinAddress sx_addr_a(StripQuotes(rv.write()));

    BOOST_CHECK_NO_THROW(rv = CallRPC("getwalletinfo", "a"));
    printf("getwalletinfo a %s\n", rv.write().c_str());


    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster \"expect trouble pause odor utility palace ignore arena disorder frog helmet addict\"", "b"));

    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewaddress addr", "b"));
    CBitcoinAddress addr_b(StripQuotes(rv.write()));
    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewstealthaddress sx_addr", "b"));
    CBitcoinAddress sx_addr_b(StripQuotes(rv.write()));

    {
    const char *test_name = "plain->plain";
    CTransactionRef tx1, tx2;
    tx1 = CreateTxn(pwallet_a.get(), addr_a, 1000, OUTPUT_STANDARD, OUTPUT_STANDARD);
    tx2 = CreateTxn(pwallet_a.get(), addr_b, 1000, OUTPUT_STANDARD, OUTPUT_STANDARD);
    timeAddToWallet(test_name, "not owned", pwallet_b.get(), tx1);
    timeAddToWallet(test_name, "owned", pwallet_b.get(), tx2);
    //BOOST_CHECK_NO_THROW(rv = CallRPC("getwalletinfo", "b")); printf("getwalletinfo b %s\n", rv.write().c_str());
    }
    {
    const char *test_name = "plain->plain, sx addr";
    CTransactionRef tx1, tx2;
    tx1 = CreateTxn(pwallet_a.get(), sx_addr_a, 10000, OUTPUT_STANDARD, OUTPUT_STANDARD);
    tx2 = CreateTxn(pwallet_a.get(), sx_addr_b, 10000, OUTPUT_STANDARD, OUTPUT_STANDARD);
    timeAddToWallet(test_name, "not owned", pwallet_b.get(), tx1);
    timeAddToWallet(test_name, "owned", pwallet_b.get(), tx2);
    //BOOST_CHECK_NO_THROW(rv = CallRPC("getwalletinfo", "b")); printf("getwalletinfo b %s\n", rv.write().c_str());
    }

    {
    const char *test_name = "plain->blind";
    CTransactionRef tx1, tx2;
    tx1 = CreateTxn(pwallet_a.get(), sx_addr_a, 10000, OUTPUT_STANDARD, OUTPUT_CT);
    tx2 = CreateTxn(pwallet_a.get(), sx_addr_b, 10000, OUTPUT_STANDARD, OUTPUT_CT);
    timeAddToWallet(test_name, "not owned", pwallet_b.get(), tx1);
    timeAddToWallet(test_name, "owned", pwallet_b.get(), tx2);
    //BOOST_CHECK_NO_THROW(rv = CallRPC("getwalletinfo", "b")); printf("getwalletinfo b %s\n", rv.write().c_str());
    }

    {
    const char *test_name = "plain->anon";
    CTransactionRef tx1, tx2;
    tx1 = CreateTxn(pwallet_a.get(), sx_addr_a, 10000, OUTPUT_STANDARD, OUTPUT_RINGCT);
    tx2 = CreateTxn(pwallet_a.get(), sx_addr_b, 10000, OUTPUT_STANDARD, OUTPUT_RINGCT);
    timeAddToWallet(test_name, "not owned", pwallet_b.get(), tx1);
    timeAddToWallet(test_name, "owned", pwallet_b.get(), tx2);
    //BOOST_CHECK_NO_THROW(rv = CallRPC("getwalletinfo", "b")); printf("getwalletinfo b %s\n", rv.write().c_str());
    }


    RemoveWallet(pwallet_a);
    pwallet_a.reset();

    RemoveWallet(pwallet_b);
    pwallet_b.reset();
}

BOOST_AUTO_TEST_CASE(stake_test)
{
    //return;
    SeedInsecureRand();
    CHDWallet *pwallet = pwalletMain.get();
    {
        LOCK(pwallet->cs_wallet);
        pwallet->SetLastBlockProcessed(::ChainActive().Height(), ::ChainActive().Tip()->GetBlockHash());
    }
    UniValue rv;

    std::unique_ptr<CChainParams> regtestChainParams = CreateChainParams(CBaseChainParams::REGTEST);
    const CChainParams &chainparams = *regtestChainParams;

    BOOST_REQUIRE(chainparams.GenesisBlock().GetHash() == ::ChainActive().Tip()->GetBlockHash());

    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPeK5mCpvMsd1cwyT1JZsrBN82XkoYuZY1EVK7EwDaiL9sDfqUU5SntTfbRfnRedFWjg5xkDG5i3iwd3yP7neX5F2dtdCojk4"));

    // Import the key to the last 5 outputs in the regtest genesis coinbase
    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPe3x7bUzkHAJZzCuGqN6y28zFFyg5i7Yqxqm897VCnmMJz6QScsftHDqsyWW5djx6FzrbkF9HSD3ET163z1SzRhfcWxvwL4G"));
    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewextaddress lblHDKey"));

    {
        LOCK(pwallet->cs_wallet);
        CBitcoinAddress addr("pdtYqn1fBVpgRa6Am6VRRLH8fkrFr1TuDq");
        CKeyID idk;
        BOOST_CHECK(addr.GetKeyID(idk));
        BOOST_CHECK(pwallet->IsMine(idk) == ISMINE_SPENDABLE);

        const CEKAKey *pak = nullptr;
        const CEKASCKey *pasc = nullptr;
        CExtKeyAccount *pa = nullptr;
        BOOST_CHECK(pwallet->HaveKey(idk, pak, pasc, pa));
        BOOST_REQUIRE(pa);
        BOOST_REQUIRE(pak);
        BOOST_CHECK(pak->nParent == 1);
        BOOST_CHECK(pak->nKey == 1);
        BOOST_CHECK(!pasc);

        CEKAKey ak;
        CKey key;
        CKeyID idStealth;
        BOOST_CHECK(pwallet->GetKey(idk, key, pa, ak, idStealth));
        BOOST_CHECK(idk == key.GetPubKey().GetID());
    }

    {
        LOCK2(cs_main, pwallet->cs_wallet);
        const auto bal = pwallet->GetBalance();
        BOOST_REQUIRE(bal.m_mine_trusted == 12500000000000);
    }
    BOOST_REQUIRE(::ChainActive().Tip()->nMoneySupply == 12500000000000);

    StakeNBlocks(pwallet, 2);
    BOOST_REQUIRE(::ChainActive().Tip()->nMoneySupply == 12500000079274);

    CBlockIndex *pindexDelete = ::ChainActive().Tip();
    BOOST_REQUIRE(pindexDelete);

    CBlock block;
    BOOST_REQUIRE(ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()));

    const CTxIn &txin = block.vtx[0]->vin[0];

    {
    LOCK(cs_main);
    CCoinsViewCache &view = ::ChainstateActive().CoinsTip();
    const Coin &coin = view.AccessCoin(txin.prevout);
    BOOST_REQUIRE(coin.IsSpent());


    DisconnectTip(block, pindexDelete, view, chainparams);

    BOOST_REQUIRE(pindexDelete->pprev->GetBlockHash() == ::ChainActive().Tip()->GetBlockHash());

    const Coin &coin2 = view.AccessCoin(txin.prevout);
    BOOST_REQUIRE(!coin2.IsSpent());
    }

    BOOST_CHECK(::ChainActive().Height() == pindexDelete->nHeight - 1);
    BOOST_CHECK(::ChainActive().Tip()->GetBlockHash() == pindexDelete->pprev->GetBlockHash());
    BOOST_REQUIRE(::ChainActive().Tip()->nMoneySupply == 12500000039637);


    // Reconnect block
    {
        BlockValidationState state;
        std::shared_ptr<const CBlock> pblock = std::make_shared<const CBlock>(block);
        BOOST_REQUIRE(ActivateBestChain(state, chainparams, pblock));

        LOCK(cs_main);
        CCoinsViewCache &view = ::ChainstateActive().CoinsTip();
        const Coin &coin = view.AccessCoin(txin.prevout);
        BOOST_REQUIRE(coin.IsSpent());
        BOOST_REQUIRE(::ChainActive().Tip()->nMoneySupply == 12500000079274);
    }

    CKey kRecv;
    InsecureNewKey(kRecv, true);

    bool fSubtractFeeFromAmount = false;
    CAmount nAmount = 10000;
    CTransactionRef tx_new;

    // Parse Bitcoin address
    CScript scriptPubKey = GetScriptForDestination(PKHash(kRecv.GetPubKey()));

    // Create and send the transaction
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);

    CCoinControl coinControl;
    {
        auto locked_chain = pwallet->chain().lock();
        BOOST_CHECK(pwallet->CreateTransaction(*locked_chain, vecSend, tx_new, nFeeRequired, nChangePosRet, strError, coinControl));
    }
    {
        pwallet->SetBroadcastTransactions(true);
        mapValue_t mapValue;
        pwallet->CommitTransaction(tx_new, std::move(mapValue), {} /* orderForm */);
    }

    StakeNBlocks(pwallet, 1);

    CBlock blockLast;
    BOOST_REQUIRE(ReadBlockFromDisk(blockLast, ::ChainActive().Tip(), chainparams.GetConsensus()));

    BOOST_REQUIRE(blockLast.vtx.size() == 2);
    BOOST_REQUIRE(blockLast.vtx[1]->GetHash() == tx_new->GetHash());

    {
        uint256 tipHash = ::ChainActive().Tip()->GetBlockHash();
        uint256 prevTipHash = ::ChainActive().Tip()->pprev->GetBlockHash();

        // Disconnect last block
        CBlockIndex *pindexDelete = ::ChainActive().Tip();
        BOOST_REQUIRE(pindexDelete);

        CBlock block;
        BOOST_REQUIRE(ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()));

        {
        LOCK(cs_main);
        CCoinsViewCache &view = ::ChainstateActive().CoinsTip();
        DisconnectTip(block, pindexDelete, view, chainparams);
        }


        BOOST_CHECK(prevTipHash == ::ChainActive().Tip()->GetBlockHash());


        {
            LOCK(cs_main);

            // Reduce the reward
            RegtestParams().SetCoinYearReward(1 * CENT);
            BOOST_CHECK(Params().GetCoinYearReward(0) == 1 * CENT);

            BlockValidationState state;
            CCoinsViewCache view(&::ChainstateActive().CoinsTip());
            BOOST_REQUIRE(false == ConnectBlock(block, state, pindexDelete, view, chainparams, false));

            BOOST_CHECK(state.IsInvalid());
            BOOST_CHECK(state.GetRejectReason() == "bad-cs-amount");
            BOOST_CHECK(prevTipHash == ::ChainActive().Tip()->GetBlockHash());

            // restore the reward
            RegtestParams().SetCoinYearReward(2 * CENT);
            BOOST_CHECK(Params().GetCoinYearReward(0) == 2 * CENT);

            // block should connect now
            BlockValidationState clearstate;
            CCoinsViewCache &clearview = ::ChainstateActive().CoinsTip();
            BOOST_REQUIRE(ConnectBlock(block, clearstate, pindexDelete, clearview, chainparams, false));

            BOOST_CHECK(!clearstate.IsInvalid());
            BOOST_REQUIRE(FlushView(&clearview, state, false));
            BOOST_REQUIRE(::ChainstateActive().FlushStateToDisk(chainparams, clearstate, FlushStateMode::IF_NEEDED));
            ::ChainActive().SetTip(pindexDelete);
            UpdateTip(pindexDelete, chainparams);

            BOOST_CHECK(tipHash == ::ChainActive().Tip()->GetBlockHash());
            BOOST_CHECK(::ChainActive().Tip()->nMoneySupply == 12500000153511);
        }
    }

    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewextaddress lblTestKey"));
    std::string extaddr = StripQuotes(rv.write());

    BOOST_CHECK(pwallet->GetBalance().m_mine_trusted + pwallet->GetStaked() == 12500000108911);

    {
        BOOST_CHECK_NO_THROW(rv = CallRPC("getnewstealthaddress"));
        std::string sSxAddr = StripQuotes(rv.write());

        CBitcoinAddress address(sSxAddr);


        AddAnonTxn(pwallet, address, 10 * COIN);
        AddAnonTxn(pwallet, address, 20 * COIN);

        StakeNBlocks(pwallet, 2);
        CCoinControl coinControl;

        BOOST_CHECK_NO_THROW(rv = CallRPC("getwalletinfo"));
        printf("[rm] getwalletinfo %s\n", rv.write().c_str());
        printf("[rm] pwallet->GetAvailableAnonBalance(&coinControl) %ld\n", pwallet->GetAvailableAnonBalance(&coinControl));
        BOOST_CHECK(30 * COIN == pwallet->GetAvailableAnonBalance(&coinControl));

        BOOST_CHECK(::ChainActive().Tip()->nAnonOutputs == 4);

        for (size_t i = 0; i < 2; ++i) {
            LOCK(cs_main);
            // Disconnect last block
            uint256 prevTipHash = ::ChainActive().Tip()->pprev->GetBlockHash();
            CBlockIndex *pindexDelete = ::ChainActive().Tip();
            BOOST_REQUIRE(pindexDelete);

            CBlock block;
            BOOST_REQUIRE(ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()));

            CCoinsViewCache &view = ::ChainstateActive().CoinsTip();
            DisconnectTip(block, pindexDelete, view, chainparams);

            BOOST_CHECK(prevTipHash == ::ChainActive().Tip()->GetBlockHash());
        }

        BOOST_CHECK(::ChainActive().Tip()->nAnonOutputs == 0);
        BOOST_CHECK(::ChainActive().Tip()->nMoneySupply == 12500000153511);
    }
}

BOOST_AUTO_TEST_SUITE_END()
