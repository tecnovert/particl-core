// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <wallet/receive.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>
#include <wallet/hdwallet.h>

isminetype InputIsMine(const CWallet& wallet, const CTxIn &txin)
{
    AssertLockHeld(wallet.cs_wallet);

    if (wallet.IsParticlWallet()) {
        const CHDWallet *phdw = GetParticlWallet(&wallet);
        LOCK(phdw->cs_wallet); // LockAssertion
        if (txin.IsAnonInput()) {
            return ISMINE_NO;
        }

        MapWallet_t::const_iterator mi = phdw->mapWallet.find(txin.prevout.hash);
        if (mi != phdw->mapWallet.end()) {
            const CWalletTx &prev = mi->second;
            if (txin.prevout.n < prev.tx->vpout.size()) {
                return phdw->IsMine(prev.tx->vpout[txin.prevout.n].get());
            }
        }

        MapRecords_t::const_iterator mri = phdw->mapRecords.find(txin.prevout.hash);
        if (mri != phdw->mapRecords.end()) {
            const COutputRecord *oR = mri->second.GetOutput(txin.prevout.n);

            if (oR) {
                if (oR->nFlags & ORF_OWNED) {
                    return ISMINE_SPENDABLE;
                }
                /* TODO
                if ((filter & ISMINE_WATCH_ONLY)
                    && (oR->nFlags & ORF_WATCH_ONLY))
                    return ISMINE_WATCH_ONLY;
                */
            }
        }

        return ISMINE_NO;
    }

    std::map<uint256, CWalletTx>::const_iterator mi = wallet.mapWallet.find(txin.prevout.hash);
    if (mi != wallet.mapWallet.end())
    {
        const CWalletTx& prev = (*mi).second;
        if (txin.prevout.n < prev.tx->vout.size())
            return wallet.IsMine(prev.tx->vout[txin.prevout.n]);
    }
    return ISMINE_NO;
}

bool AllInputsMine(const CWallet& wallet, const CTransaction& tx, const isminefilter& filter)
{
    LOCK(wallet.cs_wallet);

    if (wallet.IsParticlWallet()) {
        const CHDWallet *phdw = GetParticlWallet(&wallet);
        return phdw->IsAllFromMe(tx, filter);
    }

    for (const CTxIn& txin : tx.vin)
    {
        auto mi = wallet.mapWallet.find(txin.prevout.hash);
        if (mi == wallet.mapWallet.end())
            return false; // any unknown inputs can't be from us

        const CWalletTx& prev = (*mi).second;

        if (txin.prevout.n >= prev.tx->vout.size())
            return false; // invalid input!

        if (!(wallet.IsMine(prev.tx->vout[txin.prevout.n]) & filter))
            return false;
    }
    return true;
}

CAmount OutputGetCredit(const CWallet& wallet, const CTxOut& txout, const isminefilter& filter)
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    LOCK(wallet.cs_wallet);
    return ((wallet.IsMine(txout) & filter) ? txout.nValue : 0);
}

CAmount TxGetCredit(const CWallet& wallet, const CTransaction& tx, const isminefilter& filter)
{
    CAmount nCredit = 0;
    if (wallet.IsParticlWallet()) {
        const CHDWallet *phdw = GetParticlWallet(&wallet);
        LOCK(phdw->cs_wallet);
        for (const auto &txout : tx.vpout) {
            nCredit += phdw->GetCredit(txout.get(), filter);
            if (!MoneyRange(nCredit)) {
                throw std::runtime_error(std::string(__func__) + ": value out of range");
            }
        }
        return nCredit;
    }
    for (const CTxOut& txout : tx.vout)
    {
        nCredit += OutputGetCredit(wallet, txout, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nCredit;
}

bool ScriptIsChange(const CWallet& wallet, const CScript& script)
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    AssertLockHeld(wallet.cs_wallet);
    if (wallet.IsMine(script))
    {
        CTxDestination address;
        if (!ExtractDestination(script, address))
            return true;
        if (!wallet.FindAddressBookEntry(address)) {
            return true;
        }
    }
    return false;
}

bool OutputIsChange(const CWallet& wallet, const CTxOut& txout)
{
    return ScriptIsChange(wallet, txout.scriptPubKey);
}

CAmount OutputGetChange(const CWallet& wallet, const CTxOut& txout)
{
    AssertLockHeld(wallet.cs_wallet);
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return (OutputIsChange(wallet, txout) ? txout.nValue : 0);
}

CAmount TxGetChange(const CWallet& wallet, const CTransaction& tx)
{
    LOCK(wallet.cs_wallet);
    CAmount nChange = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nChange += OutputGetChange(wallet, txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nChange;
}

static CAmount GetCachableAmount(const CWallet& wallet, const CWalletTx& wtx, CWalletTx::AmountType type, const isminefilter& filter, bool recalculate = false)
{
    auto& amount = wtx.m_amounts[type];
    if (recalculate || !amount.m_cached[filter]) {
        amount.Set(filter, type == CWalletTx::DEBIT ? wallet.GetDebit(*wtx.tx, filter) : TxGetCredit(wallet, *wtx.tx, filter));
        wtx.m_is_cache_empty = false;
    }
    return amount.m_value[filter];
}

CAmount CachedTxGetCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter, bool allow_immature)
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (!allow_immature && wallet.IsTxImmatureCoinBase(wtx))
        return 0;

    CAmount credit = 0;
    if (filter & ISMINE_SPENDABLE) {
        // GetBalance can assume transactions in mapWallet won't change
        credit += GetCachableAmount(wallet, wtx, CWalletTx::CREDIT, ISMINE_SPENDABLE);
    }
    if (filter & ISMINE_WATCH_ONLY) {
        credit += GetCachableAmount(wallet, wtx, CWalletTx::CREDIT, ISMINE_WATCH_ONLY);
    }
    return credit;
}

CAmount CachedTxGetDebit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    if (wtx.tx->vin.empty())
        return 0;

    CAmount debit = 0;
    if (filter & ISMINE_SPENDABLE) {
        debit += GetCachableAmount(wallet, wtx, CWalletTx::DEBIT, ISMINE_SPENDABLE);
    }
    if (filter & ISMINE_WATCH_ONLY) {
        debit += GetCachableAmount(wallet, wtx, CWalletTx::DEBIT, ISMINE_WATCH_ONLY);
    }
    return debit;
}

CAmount CachedTxGetChange(const CWallet& wallet, const CWalletTx& wtx)
{
    if (wtx.fChangeCached)
        return wtx.nChangeCached;
    wtx.nChangeCached = TxGetChange(wallet, *wtx.tx);
    wtx.fChangeCached = true;
    return wtx.nChangeCached;
}

CAmount CachedTxGetImmatureCredit(const CWallet& wallet, const CWalletTx& wtx, bool fUseCache)
{
    if (wtx.IsCoinBase() && wallet.IsTxImmatureCoinBase(wtx) && wallet.IsTxInMainChain(wtx)) {
        return GetCachableAmount(wallet, wtx, CWalletTx::IMMATURE_CREDIT, ISMINE_SPENDABLE, !fUseCache);
    }

    return 0;
}

CAmount CachedTxGetImmatureWatchOnlyCredit(const CWallet& wallet, const CWalletTx& wtx, const bool fUseCache)
{
    if (wallet.IsTxImmatureCoinBase(wtx) && wallet.IsTxInMainChain(wtx)) {
        return GetCachableAmount(wallet, wtx, CWalletTx::IMMATURE_CREDIT, ISMINE_WATCH_ONLY, !fUseCache);
    }

    return 0;
}

CAmount CachedTxGetAvailableCredit(const CWallet& wallet, const CWalletTx& wtx, bool fUseCache, const isminefilter& filter)
{
    // Avoid caching ismine for NO or ALL cases (could remove this check and simplify in the future).
    bool allow_cache = (filter & ISMINE_ALL) && (filter & ISMINE_ALL) != ISMINE_ALL;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (wallet.IsTxImmatureCoinBase(wtx))
        return 0;

    if (fUseCache && allow_cache && wtx.m_amounts[CWalletTx::AVAILABLE_CREDIT].m_cached[filter]) {
        return wtx.m_amounts[CWalletTx::AVAILABLE_CREDIT].m_value[filter];
    }

    bool allow_used_addresses = (filter & ISMINE_USED) || !wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
    CAmount nCredit = 0;
    uint256 hashTx = wtx.GetHash();
    for (unsigned int i = 0; i < wtx.tx->GetNumVOuts(); i++)
    {
        if (!wallet.IsSpent(hashTx, i) && (allow_used_addresses || !wallet.IsSpentKey(hashTx, i))) {
            nCredit += wallet.IsParticlWallet()
                       ? wallet.GetCredit(wtx.tx->vpout[i].get(), filter)
                       : OutputGetCredit(wallet, wtx.tx->vout[i], filter);
            if (!MoneyRange(nCredit))
                throw std::runtime_error(std::string(__func__) + " : value out of range");
        }
    }

    if (allow_cache) {
        wtx.m_amounts[CWalletTx::AVAILABLE_CREDIT].Set(filter, nCredit);
        wtx.m_is_cache_empty = false;
    }

    return nCredit;
}

void CachedTxGetAmounts(const CWallet& wallet, const CWalletTx& wtx,
                  std::list<COutputEntry>& listReceived,
                  std::list<COutputEntry>& listSent,
                  std::list<COutputEntry>& listStaked, CAmount& nFee, const isminefilter& filter, bool fForFilterTx)
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    listStaked.clear();

    // Compute fee:
    CAmount nDebit = CachedTxGetDebit(wallet, wtx, filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = wtx.tx->GetValueOut();
        nFee = nDebit - nValueOut;
    };

    LOCK(wallet.cs_wallet);
    // staked
    if (wtx.tx->IsCoinStake()) {
        CAmount nCredit = 0;
        CTxDestination address = CNoDestination();
        CTxDestination addressStake = CNoDestination();

        isminetype isMineAll = ISMINE_NO;
        for (unsigned int i = 0; i < wtx.tx->vpout.size(); ++i) {
            const CTxOutBase *txout = wtx.tx->vpout[i].get();
            if (!txout->IsType(OUTPUT_STANDARD)) {
                continue;
            }

            isminetype mine = wallet.IsMine(txout);
            if (!(mine & filter)) {
                continue;
            }
            isMineAll = (isminetype)((uint8_t)isMineAll |(uint8_t)mine);

            if (fForFilterTx || address.index() == DI::_CNoDestination) {
                const CScript &scriptPubKey = *txout->GetPScriptPubKey();
                ExtractDestination(scriptPubKey, address);

                if (HasIsCoinstakeOp(scriptPubKey)) {
                    CScript scriptOut;
                    if (GetCoinstakeScriptPath(scriptPubKey, scriptOut)) {
                        ExtractDestination(scriptOut, addressStake);
                    }
                }
            }
            nCredit += txout->GetValue();

            if (fForFilterTx) {
                COutputEntry output = {address, txout->GetValue(), (int)i, mine, addressStake};
                listStaked.push_back(output);
            }
        }
        // Recalc fee as GetValueOut might include treasury fund output
        nFee = nDebit - nCredit;

        if (fForFilterTx || !(isMineAll & filter)) {
            return;
        }

        COutputEntry output = {address, nCredit, 1, isMineAll, addressStake};
        listStaked.push_back(output);
        return;
    }

    // Sent/received.
    if (wtx.tx->IsParticlVersion()) {
        for (unsigned int i = 0; i < wtx.tx->vpout.size(); ++i) {
            const CTxOutBase *txout = wtx.tx->vpout[i].get();
            if (!txout->IsStandardOutput()) {
                continue;
            }

            isminetype fIsMine = wallet.IsMine(txout);

            // Only need to handle txouts if AT LEAST one of these is true:
            //   1) they debit from us (sent)
            //   2) the output is to us (received)
            if (nDebit > 0) {
                // Don't report 'change' txouts
                if (wallet.IsChange(txout))
                    continue;
            } else
            if (!(fIsMine & filter)) {
                continue;
            }

            // In either case, we need to get the destination address
            const CScript &scriptPubKey = *txout->GetPScriptPubKey();
            CTxDestination address;
            CTxDestination addressStake = CNoDestination();

            if (!ExtractDestination(scriptPubKey, address) && !scriptPubKey.IsUnspendable()) {
                wallet.WalletLogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                                        wtx.GetHash().ToString());
                address = CNoDestination();
            }

            if (HasIsCoinstakeOp(scriptPubKey)) {
                CScript scriptOut;
                if (GetCoinstakeScriptPath(scriptPubKey, scriptOut)) {
                    ExtractDestination(scriptOut, addressStake);
                }
            }

            COutputEntry output = {address, txout->GetValue(), (int)i, fIsMine, addressStake};

            // If we are debited by the transaction, add the output as a "sent" entry
            if (nDebit > 0){
                listSent.push_back(output);
            }

            // If we are receiving the output, add it as a "received" entry
            if (fIsMine & filter) {
                listReceived.push_back(output);
            }
        }
    } else
    {
        for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i)
        {
            const CTxOut& txout = wtx.tx->vout[i];
            isminetype fIsMine = wallet.IsMine(txout);
            // Only need to handle txouts if AT LEAST one of these is true:
            //   1) they debit from us (sent)
            //   2) the output is to us (received)
            if (nDebit > 0)
            {
                // Don't report 'change' txouts
                if (OutputIsChange(wallet, txout))
                    continue;
            }
            else if (!(fIsMine & filter))
                continue;

            // In either case, we need to get the destination address
            CTxDestination address;
            CTxDestination addressStake = CNoDestination();

            if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable())
            {
                wallet.WalletLogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                                        wtx.GetHash().ToString());
                address = CNoDestination();
            }
            COutputEntry output = {address, txout.nValue, (int)i, fIsMine, addressStake};

            // If we are debited by the transaction, add the output as a "sent" entry
            if (nDebit > 0)
                listSent.push_back(output);

            // If we are receiving the output, add it as a "received" entry
            if (fIsMine & filter)
                listReceived.push_back(output);
        }
    }
}

bool CachedTxIsFromMe(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    return (CachedTxGetDebit(wallet, wtx, filter) > 0);
}

bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx, std::set<uint256>& trusted_parents)
{
    AssertLockHeld(wallet.cs_wallet);
    // Quick answer in most cases
    if (wtx.tx->IsCoinStake() && wtx.isAbandoned()) { // Ignore failed stakes
        return false;
    }
    if (!wallet.chain().checkFinalTx(*wtx.tx)) return false;
    int nDepth = wallet.GetTxDepthInMainChain(wtx);
    if (nDepth >= 1) return true;
    if (nDepth < 0) return false;
    // using wtx's cached debit
    if (!wallet.m_spend_zero_conf_change || !CachedTxIsFromMe(wallet, wtx, ISMINE_ALL)) return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!wtx.InMempool()) return false;

    // Trusted if all inputs are from us and are in the mempool:
    for (const CTxIn& txin : wtx.tx->vin)
    {
        // Transactions not sent by us: not trusted
        const CWalletTx* parent = wallet.GetWalletTx(txin.prevout.hash);
        if (parent == nullptr) return false;
        if (wtx.tx->IsParticlVersion()) {
            const CTxOutBase *parentOut = parent->tx->vpout[txin.prevout.n].get();
            if (!(wallet.IsMine(parentOut) & ISMINE_SPENDABLE)) {
                return false;
            }
        } else {
            const CTxOut& parentOut = parent->tx->vout[txin.prevout.n];
            // Check that this specific input being spent is trusted
            if (wallet.IsMine(parentOut) != ISMINE_SPENDABLE) return false;
        }
        // If we've already trusted this parent, continue
        if (trusted_parents.count(parent->GetHash())) continue;
        // Recurse to check that the parent is also trusted
        if (!CachedTxIsTrusted(wallet, *parent, trusted_parents)) return false;
        trusted_parents.insert(parent->GetHash());
    }
    return true;
}

bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx)
{
    std::set<uint256> trusted_parents;
    LOCK(wallet.cs_wallet);
    return CachedTxIsTrusted(wallet, wtx, trusted_parents);
}

Balance GetBalance(const CWallet& wallet, const int min_depth, bool avoid_reuse)
{
    Balance ret;

    if (wallet.IsParticlWallet()) {
        const CHDWallet *phdw = GetParticlWallet(&wallet);
        LOCK(phdw->cs_wallet);
        bool allow_used_addresses = avoid_reuse || !phdw->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
        for (const auto &ri : phdw->mapRecords) {
            const auto &txhash = ri.first;
            const auto &rtx = ri.second;

            bool is_trusted = phdw->IsTrusted(txhash, rtx);
            int tx_depth = phdw->GetDepthInMainChain(rtx);
            for (const auto &r : rtx.vout) {
                if (r.nType != OUTPUT_STANDARD
                    || phdw->IsSpent(txhash, r.n)
                    || (!allow_used_addresses && phdw->IsSpentKey(&r.scriptPubKey))) {
                    continue;
                }
                if (is_trusted && tx_depth >= min_depth) {
                    if (r.nFlags & ORF_OWNED) {
                        ret.m_mine_trusted += r.nValue;
                    }
                    if (r.nFlags & ORF_OWN_WATCH) {
                        ret.m_watchonly_trusted += r.nValue;
                    }
                }
                if (!is_trusted && tx_depth == 0) {
                    if (!phdw->InMempool(txhash)) {
                        continue;
                    }
                    if (r.nFlags & ORF_OWNED) {
                        ret.m_mine_untrusted_pending += r.nValue;
                    }
                    if (r.nFlags & ORF_OWN_WATCH) {
                        ret.m_watchonly_untrusted_pending += r.nValue;
                    }
                }
            }
        }
    }

    isminefilter reuse_filter = avoid_reuse ? ISMINE_NO : ISMINE_USED;
    {
        LOCK(wallet.cs_wallet);
        std::set<uint256> trusted_parents;
        for (const auto& entry : wallet.mapWallet)
        {
            const CWalletTx& wtx = entry.second;
            const bool is_trusted{CachedTxIsTrusted(wallet, wtx, trusted_parents)};
            const int tx_depth{wallet.GetTxDepthInMainChain(wtx)};
            const CAmount tx_credit_mine{CachedTxGetAvailableCredit(wallet, wtx, /* fUseCache */ true, ISMINE_SPENDABLE | reuse_filter)};
            const CAmount tx_credit_watchonly{CachedTxGetAvailableCredit(wallet, wtx, /* fUseCache */ true, ISMINE_WATCH_ONLY | reuse_filter)};
            if (is_trusted && tx_depth >= min_depth) {
                ret.m_mine_trusted += tx_credit_mine;
                ret.m_watchonly_trusted += tx_credit_watchonly;
            }
            if (!is_trusted && tx_depth == 0 && wtx.InMempool()) {
                ret.m_mine_untrusted_pending += tx_credit_mine;
                ret.m_watchonly_untrusted_pending += tx_credit_watchonly;
            }
            ret.m_mine_immature += CachedTxGetImmatureCredit(wallet, wtx);
            ret.m_watchonly_immature += CachedTxGetImmatureWatchOnlyCredit(wallet, wtx);
        }
    }
    return ret;
}

std::map<CTxDestination, CAmount> GetAddressBalances(const CWallet& wallet)
{
    if (wallet.IsParticlWallet()) {
        const CHDWallet *phdw = GetParticlWallet(&wallet);
        return phdw->GetAddressBalances();
    }

    std::map<CTxDestination, CAmount> balances;

    {
        LOCK(wallet.cs_wallet);
        std::set<uint256> trusted_parents;
        for (const auto& walletEntry : wallet.mapWallet)
        {
            const CWalletTx& wtx = walletEntry.second;

            if (!CachedTxIsTrusted(wallet, wtx, trusted_parents))
                continue;

            if (wallet.IsTxImmatureCoinBase(wtx))
                continue;

            int nDepth = wallet.GetTxDepthInMainChain(wtx);
            if (nDepth < (CachedTxIsFromMe(wallet, wtx, ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < wtx.tx->vout.size(); i++)
            {
                CTxDestination addr;
                if (!wallet.IsMine(wtx.tx->vout[i]))
                    continue;
                if(!ExtractDestination(wtx.tx->vout[i].scriptPubKey, addr))
                    continue;

                CAmount n = wallet.IsSpent(walletEntry.first, i) ? 0 : wtx.tx->vout[i].nValue;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

std::set< std::set<CTxDestination> > GetAddressGroupings(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    if (wallet.IsParticlWallet()) {
        const CHDWallet *phdw = GetParticlWallet(&wallet);
        LOCK(phdw->cs_wallet); // LockAssertion
        return phdw->GetAddressGroupings();
    }

    std::set< std::set<CTxDestination> > groupings;
    std::set<CTxDestination> grouping;

    for (const auto& walletEntry : wallet.mapWallet)
    {
        const CWalletTx& wtx = walletEntry.second;

        if (wtx.tx->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            for (const CTxIn& txin : wtx.tx->vin)
            {
                CTxDestination address;
                if(!InputIsMine(wallet, txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(wallet.mapWallet.at(txin.prevout.hash).tx->vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
               for (const CTxOut& txout : wtx.tx->vout)
                   if (OutputIsChange(wallet, txout))
                   {
                       CTxDestination txoutAddr;
                       if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                           continue;
                       grouping.insert(txoutAddr);
                   }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (const auto& txout : wtx.tx->vout)
            if (wallet.IsMine(txout))
            {
                CTxDestination address;
                if(!ExtractDestination(txout.scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    std::set< std::set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    std::map< CTxDestination, std::set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    for (std::set<CTxDestination> _grouping : groupings)
    {
        // make a set of all the groups hit by this new group
        std::set< std::set<CTxDestination>* > hits;
        std::map< CTxDestination, std::set<CTxDestination>* >::iterator it;
        for (const CTxDestination& address : _grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        std::set<CTxDestination>* merged = new std::set<CTxDestination>(_grouping);
        for (std::set<CTxDestination>* hit : hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (const CTxDestination& element : *merged)
            setmap[element] = merged;
    }

    std::set< std::set<CTxDestination> > ret;
    for (const std::set<CTxDestination>* uniqueGrouping : uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}


isminetype CWallet::IsMine(const CKeyID &address) const
{
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (spk_man) {
        LOCK(spk_man->cs_KeyStore);
        if (!IsCrypted()) {
            isminetype ismine = spk_man->FillableSigningProvider::IsMine(address);
            if (ismine == ISMINE_NO && spk_man->mapWatchKeys.count(address) > 0) {
                return ISMINE_WATCH_ONLY_;
            }
            return ismine;
        }
        if (spk_man->mapCryptedKeys.count(address) > 0) {
            return ISMINE_SPENDABLE;
        }
        if (spk_man->mapWatchKeys.count(address) > 0) {
            return ISMINE_WATCH_ONLY_;
        }
    }
    return ISMINE_NO;
}
