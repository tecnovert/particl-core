// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/transactionrecord.h>

#include <chain.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <wallet/types.h>

#include <stdint.h>

#include <wallet/hdwallet.h>

#include <QDateTime>

using wallet::ISMINE_NO;
using wallet::ISMINE_SPENDABLE;
using wallet::ISMINE_WATCH_ONLY;
using wallet::isminetype;

/* Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction()
{
    // There are currently no cases where we hide transactions, but
    // we may want to use this in the future for things like RBF.
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const interfaces::WalletTx& wtx)
{
    QList<TransactionRecord> parts;

    if (wtx.is_record) {
        const CTransactionRecord &rtx = wtx.irtx->second;

        const uint256 &hash = wtx.irtx->first;
        int64_t nTime = rtx.GetTxTime();
        TransactionRecord sub(hash, nTime);

        CTxDestination address = CNoDestination();
        uint8_t nFlags = 0;
        for (const auto &r : rtx.vout) {
            if (r.nFlags & ORF_CHANGE) {
                continue;
            }

            nFlags |= r.nFlags;
            if (r.vPath.size() > 0) {
                if (r.vPath[0] == ORA_STEALTH) {
                    if (r.vPath.size() < 5) {
                        LogPrintf("%s: Warning, malformed vPath.\n", __func__);
                    } else {
                        uint32_t sidx;
                        memcpy(&sidx, &r.vPath[1], 4);
                        CStealthAddress sx;
                        if (wtx.partWallet->GetStealthByIndex(sidx, sx))
                            address = sx;
                    }
                }
            } else {
                if (std::get_if<CNoDestination>(&address)) {
                    ExtractDestination(r.scriptPubKey, address);
                }
            }

            if (r.nType == OUTPUT_STANDARD) {
                sub.typeOut = 'P';
            } else
            if (r.nType == OUTPUT_CT) {
                sub.typeOut = 'B';
            } else
            if (r.nType == OUTPUT_RINGCT) {
                sub.typeOut = 'A';
            }

            if (nFlags & ORF_OWNED || nFlags & ORF_OWN_WATCH) {
                sub.credit += r.nValue;
            }
            if (nFlags & ORF_FROM) {
                sub.debit -= r.nValue;
            }
        }

        if (!std::get_if<CNoDestination>(&address)) {
            sub.address = EncodeDestination(address);
        }
        if (sub.debit != 0) {
            sub.debit -= rtx.nFee;
        }

        //if (nFlags & ORF_OWNED && nFlags & ORF_FROM) {
            //sub.type = TransactionRecord::SendToSelf;
        //} else
        if (nFlags & ORF_OWNED) {
            sub.type = TransactionRecord::RecvWithAddress;
        } else
        if (nFlags & ORF_FROM) {
            sub.type = TransactionRecord::SendToAddress;
        }

        if (rtx.nFlags & ORF_ANON_IN) {
            sub.typeIn = 'A';
        } else
        if (rtx.nFlags & ORF_BLIND_IN) {
            sub.typeIn = 'B';
        }

        sub.involvesWatchAddress = nFlags & ORF_OWN_WATCH;
        parts.append(sub);
        return parts;
    }

    if (wtx.is_coinstake) {
        int64_t nTime = wtx.time;
        CAmount nCredit = wtx.credit;
        CAmount nDebit = wtx.debit;
        uint256 hash = wtx.tx->GetHash();

        bool involvesWatchAddress = false;
        TransactionRecord sub(hash, nTime);

        sub.type = TransactionRecord::Staked;
        sub.debit = -nDebit;
        for (size_t i = 0; i < wtx.tx->vpout.size(); ++i) {
            const CTxOutBase *txout = wtx.tx->vpout[i].get();
            if (!txout->IsType(OUTPUT_STANDARD)) {
                continue;
            }
            isminetype mine = wtx.txout_is_mine[i];
            if (!mine) {
                continue;
            }
            sub.address = EncodeDestination(wtx.txout_address[i]);
            break;
        }
        sub.credit = nCredit;
        sub.involvesWatchAddress = involvesWatchAddress;
        parts.append(sub);

        return parts;
    }

    int64_t nTime = wtx.time;
    CAmount nCredit = wtx.credit;
    CAmount nDebit = wtx.debit;
    CAmount nNet = nCredit - nDebit;
    uint256 hash = wtx.tx->GetHash();
    std::map<std::string, std::string> mapValue = wtx.value_map;

    bool involvesWatchAddress = false;
    isminetype fAllFromMe = ISMINE_SPENDABLE;
    bool any_from_me = false;
    if (wtx.is_coinbase) {
        fAllFromMe = ISMINE_NO;
    } else {
        for (const isminetype mine : wtx.txin_is_mine)
        {
            if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
            if(fAllFromMe > mine) fAllFromMe = mine;
            if (mine) any_from_me = true;
        }
    }

    if (fAllFromMe || !any_from_me) {
        for (const isminetype mine : wtx.txout_is_mine)
        {
            if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
        }

        CAmount nTxFee = nDebit - wtx.tx->GetValueOut();

        for(unsigned int i = 0; i < wtx.tx->vpout.size(); i++)
        {
            const CTxOutBase *txout = wtx.tx->vpout[i].get();

            if (!txout->IsType(OUTPUT_STANDARD)) {
                continue;
            }

            if (fAllFromMe) {
                // Change is only really possible if we're the sender
                // Otherwise, someone just sent bitcoins to a change address, which should be shown
                if (wtx.txout_is_change[i]) {
                    continue;
                }

                //
                // Debit
                //

                TransactionRecord sub(hash, nTime);
                sub.idx = i;
                sub.involvesWatchAddress = involvesWatchAddress;

                if (!std::get_if<CNoDestination>(&wtx.txout_address[i]))
                {
                    // Sent to Bitcoin Address
                    sub.type = TransactionRecord::SendToAddress;
                    sub.address = EncodeDestination(wtx.txout_address[i]);
                }
                else
                {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    sub.type = TransactionRecord::SendToOther;
                    sub.address = mapValue["to"];
                }

                CAmount nValue = txout->GetValue();
                /* Add fee to first output */
                if (nTxFee > 0)
                {
                    nValue += nTxFee;
                    nTxFee = 0;
                }
                sub.debit = -nValue;

                parts.append(sub);
            }

            isminetype mine = wtx.txout_is_mine[i];
            if (mine)
            {
                //
                // Credit
                //

                TransactionRecord sub(hash, nTime);
                sub.idx = i; // vout index
                sub.credit = txout->GetValue();
                sub.involvesWatchAddress = mine & ISMINE_WATCH_ONLY;
                if (wtx.txout_address_is_mine[i])
                {
                    // Received by Bitcoin Address
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = EncodeDestination(wtx.txout_address[i]);
                }
                else
                {
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = mapValue["from"];
                }
                if (wtx.is_coinbase)
                {
                    // Generated
                    sub.type = TransactionRecord::Generated;
                }

                parts.append(sub);
            }
        }
    } else {
        //
        // Mixed debit transaction, can't break down payees
        //
        parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "", nNet, 0));
        parts.last().involvesWatchAddress = involvesWatchAddress;
    }

    return parts;
}

void TransactionRecord::updateStatus(const interfaces::WalletTxStatus& wtx, const uint256& block_hash, int numBlocks, int64_t block_time)
{
    // Determine transaction status

    // Sort order, unrecorded transactions sort to the top
    int typesort;
    switch (type) {
    case SendToAddress: case SendToOther:
        typesort = 2; break;
    case RecvWithAddress: case RecvFromOther:
        typesort = 3; break;
    default:
        typesort = 9;
    }
    status.sortKey = strprintf("%010d-%01d-%010u-%03d-%d",
        wtx.block_height,
        wtx.is_coinbase ? 1 : 0,
        wtx.time_received,
        idx,
        typesort);
    status.countsForBalance = wtx.is_trusted && !(wtx.blocks_to_maturity > 0);
    status.depth = wtx.depth_in_main_chain;
    status.m_cur_block_hash = block_hash;

    // For generated transactions, determine maturity
    if (type == TransactionRecord::Generated) {
        if (wtx.blocks_to_maturity > 0)
        {
            status.status = TransactionStatus::Immature;

            if (wtx.is_in_main_chain)
            {
                status.matures_in = wtx.blocks_to_maturity;
            }
            else
            {
                status.status = TransactionStatus::NotAccepted;
            }
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    else
    {
        if (status.depth < 0)
        {
            status.status = TransactionStatus::Conflicted;
        }
        else if (status.depth == 0)
        {
            status.status = TransactionStatus::Unconfirmed;
            if (wtx.is_abandoned)
                status.status = TransactionStatus::Abandoned;
        }
        else if (status.depth < RecommendedNumConfirmations)
        {
            status.status = TransactionStatus::Confirming;
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    status.needsUpdate = false;
}

bool TransactionRecord::statusUpdateNeeded(const uint256& block_hash) const
{
    assert(!block_hash.IsNull());
    return status.m_cur_block_hash != block_hash || status.needsUpdate;
}

QString TransactionRecord::getTxHash() const
{
    return QString::fromStdString(hash.ToString());
}

int TransactionRecord::getOutputIndex() const
{
    return idx;
}
