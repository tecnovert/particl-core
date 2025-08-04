// Copyright (c) 2015-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H
#define BITCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H

#include <primitives/transaction.h>
#include <validationinterface.h>
#include <netaddress.h>

#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <thread>
#include <atomic>

class CBlock;
class CBlockIndex;
namespace smsg {
class SecureMessage;
}
class CZMQAbstractNotifier;
struct NewMempoolTransactionInfo;

class CZMQNotificationInterface final : public CValidationInterface
{
public:
    ~CZMQNotificationInterface();

    std::list<const CZMQAbstractNotifier*> GetActiveNotifiers() const;

    static std::unique_ptr<CZMQNotificationInterface> Create(std::function<bool(CBlock&, const CBlockIndex&)> get_block_by_index);

protected:
    bool Initialize();
    void Shutdown();

    // CValidationInterface
    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t mempool_sequence) override;
    void TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t mempool_sequence) override;
    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexConnected) override;
    void BlockDisconnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexDisconnected) override;
    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override;

    void TransactionAddedToWallet(const std::string &sWalletName, const CTransactionRef& tx) override;
    void NewSecureMessage(const smsg::SecureMessage *psmsg, const uint160 &hash) override;

private:
    CZMQNotificationInterface();

    void* pcontext{nullptr};
    std::list<std::unique_ptr<CZMQAbstractNotifier>> notifiers;

    bool IsWhitelistedRange(const CNetAddr &addr);
    void ThreadZAP();
    std::thread threadZAP;
    std::atomic_bool zapActive;
    std::vector<CSubNet> vWhitelistedRange;
};

extern std::unique_ptr<CZMQNotificationInterface> g_zmq_notification_interface;

#endif // BITCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H
