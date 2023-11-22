// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>


// Particl dependencies
#include <blind.h>
#include <insight/balanceindex.h>
#include <consensus/params.h>
#include <chainparams.h>
#include <timedata.h>
#include <common/args.h>
#include <util/strencodings.h>
#include <util/moneystr.h>
#include <script/interpreter.h>


static bool CheckStandardOutput(TxValidationState &state, const CTxOutStandard *p, CAmount &nValueOut)
{
    if (p->nValue < 0)
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
    if (p->nValue > MAX_MONEY)
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
    nValueOut += p->nValue;

    if (HasIsCoinstakeOp(p->scriptPubKey)) {
        if (TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()) < state.m_consensus_params->OpIsCoinstakeTime) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-opiscoinstake");
        }
        if (!state.m_consensus_params->fAllowOpIsCoinstakeWithP2PKH) {
            if (IsSpendScriptP2PKH(p->scriptPubKey)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-opiscoinstake-spend-p2pkh");
            }
        }
    }

    return true;
}

static bool CheckBlindOutput(TxValidationState &state, const CTxOutCT *p)
{
    if (p->vData.size() < 33 || p->vData.size() > 33 + 5 + 33) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-ctout-ephem-size");
    }
    size_t nRangeProofLen = 5134;
    if (p->vRangeproof.size() < 500 || p->vRangeproof.size() > nRangeProofLen) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-ctout-rangeproof-size");
    }

    if (state.m_skip_rangeproof) {
        return true;
    }

    uint64_t min_value = 0, max_value = 0;
    int rv = 0;

    if (state.fBulletproofsActive) {
        rv = secp256k1_bulletproof_rangeproof_verify(secp256k1_ctx_blind,
            blind_scratch, blind_gens, p->vRangeproof.data(), p->vRangeproof.size(),
            nullptr, &p->commitment, 1, 64, &secp256k1_generator_const_h, nullptr, 0);
    } else {
        rv = secp256k1_rangeproof_verify(secp256k1_ctx_blind, &min_value, &max_value,
            &p->commitment, p->vRangeproof.data(), p->vRangeproof.size(),
            nullptr, 0,
            secp256k1_generator_h);
    }

    if (LogAcceptCategory(BCLog::VALIDATION, BCLog::Level::Debug)) {
        LogPrintf("%s: rv, min_value, max_value %d, %s, %s\n", __func__,
            rv, FormatMoney((CAmount)min_value), FormatMoney((CAmount)max_value));
    }

    if (rv != 1) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-ctout-rangeproof-verify");
    }

    return true;
}

bool CheckAnonOutput(TxValidationState &state, const CTxOutRingCT *p)
{
    if (!state.rct_active) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "rctout-before-active");
    }
    if (p->vData.size() < 33 || p->vData.size() > 33 + 5 + 33) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-rctout-ephem-size");
    }

    size_t nRangeProofLen = 5134;
    if (p->vRangeproof.size() < 500 || p->vRangeproof.size() > nRangeProofLen) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-rctout-rangeproof-size");
    }

    if (state.m_skip_rangeproof) {
        return true;
    }

    uint64_t min_value = 0, max_value = 0;
    int rv = 0;

    if (state.fBulletproofsActive) {
        rv = secp256k1_bulletproof_rangeproof_verify(secp256k1_ctx_blind,
            blind_scratch, blind_gens, p->vRangeproof.data(), p->vRangeproof.size(),
            nullptr, &p->commitment, 1, 64, &secp256k1_generator_const_h, nullptr, 0);
    } else {
        rv = secp256k1_rangeproof_verify(secp256k1_ctx_blind, &min_value, &max_value,
            &p->commitment, p->vRangeproof.data(), p->vRangeproof.size(),
            nullptr, 0,
            secp256k1_generator_h);
    }

    if (LogAcceptCategory(BCLog::VALIDATION, BCLog::Level::Debug)) {
        LogPrintf("%s: rv, min_value, max_value %d, %s, %s\n", __func__,
            rv, FormatMoney((CAmount)min_value), FormatMoney((CAmount)max_value));
    }

    if (rv != 1) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-rctout-rangeproof-verify");
    }

    return true;
}

static bool CheckDataOutput(TxValidationState &state, const CTxOutData *p)
{
    if (p->vData.size() < 1) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-output-data-size");
    }

    if (p->vData.size() > MAX_DATA_OUTPUT_SIZE) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-output-data-size");
    }

    return true;
}

bool CheckTransaction(const CTransaction& tx, TxValidationState &state)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");

    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");

    if (tx.IsParticlVersion()) {
        if (state.m_clamp_tx_version && tx.GetParticlVersion() != PARTICL_TXN_VERSION) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txn-version");
        }
        if (tx.vpout.empty()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vpout-empty");
        }
        if (!tx.vout.empty()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-not-empty");
        }

        size_t nStandardOutputs = 0, nDataOutputs = 0, nBlindOutputs = 0, nAnonOutputs = 0;
        CAmount nValueOut = 0;
        for (const auto &txout : tx.vpout) {
            switch (txout->nVersion) {
                case OUTPUT_STANDARD:
                    if (!CheckStandardOutput(state, (CTxOutStandard*) txout.get(), nValueOut)) {
                        return false;
                    }
                    nStandardOutputs++;
                    break;
                case OUTPUT_CT:
                    if (!CheckBlindOutput(state, (CTxOutCT*) txout.get())) {
                        return false;
                    }
                    nBlindOutputs++;
                    break;
                case OUTPUT_RINGCT:
                    if (!CheckAnonOutput(state, (CTxOutRingCT*) txout.get())) {
                        return false;
                    }
                    nAnonOutputs++;
                    break;
                case OUTPUT_DATA:
                    if (!CheckDataOutput(state, (CTxOutData*) txout.get())) {
                        return false;
                    }
                    nDataOutputs++;
                    break;
                default:
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-unknown-output-version");
            }

            if (!MoneyRange(nValueOut)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
            }
        }

        size_t max_data_outputs = 1 + nStandardOutputs; // extra 1 for ct fee output
        if (state.m_clamp_tx_version) {
            max_data_outputs += nBlindOutputs + nAnonOutputs;
        }
        if (nDataOutputs > max_data_outputs) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "too-many-data-outputs");
        }
    } else {
        if (state.m_particl_mode) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txn-version");
        }
        if (tx.vout.empty()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
        }

        // Check for negative or overflow output values
        CAmount nValueOut = 0;
        for (const auto& txout : tx.vout)
        {
            if (txout.nValue < 0)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
            if (txout.nValue > MAX_MONEY)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
            nValueOut += txout.nValue;
            if (!MoneyRange(nValueOut))
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
        }
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin)
    {
        if (!txin.IsAnonInput() &&
            !vInOutPoints.insert(txin.prevout).second) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
        }
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin) {
            if (!txin.IsAnonInput() && txin.prevout.IsNull()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
            }
        }
    }

    return true;
}
