// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CHAINPARAMS_H
#define BITCOIN_KERNEL_CHAINPARAMS_H

#include <consensus/params.h>
#include <kernel/messagestartchars.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/hash_type.h>
#include <util/vector.h>

#include <cstdint>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

class CBlockIndex;

namespace particl {
static const uint32_t CHAIN_NO_GENESIS = 444444;
static const uint32_t CHAIN_NO_STEALTH_SPEND = 444445; // used hardened

class CImportedCoinbaseTxn
{
public:
    CImportedCoinbaseTxn(uint32_t nHeightIn, uint256 hashIn) : nHeight(nHeightIn), hash(hashIn) {};
    uint32_t nHeight;
    uint256 hash; // hash of output data
};

class TreasuryFundSettings
{
public:
    TreasuryFundSettings(std::string sAddrTo, int nMinTreasuryStakePercent_, int nTreasuryOutputPeriod_)
        : sTreasuryFundAddresses(sAddrTo), nMinTreasuryStakePercent(nMinTreasuryStakePercent_), nTreasuryOutputPeriod(nTreasuryOutputPeriod_) {};

    std::string sTreasuryFundAddresses;
    int nMinTreasuryStakePercent; // [0, 100]
    int nTreasuryOutputPeriod; // treasury fund output is created every n blocks
};
} // namespace particl

typedef std::map<int, uint256> MapCheckpoints;

struct CCheckpointData {
    MapCheckpoints mapCheckpoints;

    int GetHeight() const {
        const auto& final_checkpoint = mapCheckpoints.rbegin();
        return final_checkpoint->first /* height */;
    }
};

struct AssumeutxoHash : public BaseHash<uint256> {
    explicit AssumeutxoHash(const uint256& hash) : BaseHash(hash) {}
};

/**
 * Holds configuration for use during UTXO snapshot load and validation. The contents
 * here are security critical, since they dictate which UTXO snapshots are recognized
 * as valid.
 */
struct AssumeutxoData {
    int height;

    //! The expected hash of the deserialized UTXO set.
    AssumeutxoHash hash_serialized;

    //! Used to populate the nChainTx value, which is used during BlockManager::LoadBlockIndex().
    //!
    //! We need to hardcode the value here because this is computed cumulatively using block data,
    //! which we do not necessarily have at the time of snapshot load.
    unsigned int nChainTx;

    //! The hash of the base block for this snapshot. Used to refer to assumeutxo data
    //! prior to having a loaded blockindex.
    uint256 blockhash;
};

/**
 * Holds various statistics on transactions within a chain. Used to estimate
 * verification progress during chain sync.
 *
 * See also: CChainParams::TxData, GuessVerificationProgress.
 */
struct ChainTxData {
    int64_t nTime;    //!< UNIX timestamp of last known number of transactions
    int64_t nTxCount; //!< total number of transactions between genesis and that timestamp
    double dTxRate;   //!< estimated number of transactions per second after that timestamp
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system.
 */
class CChainParams
{
public:
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,
        STEALTH_ADDRESS,
        EXT_KEY_HASH,
        EXT_ACC_HASH,
        EXT_PUBLIC_KEY_BTC,
        EXT_SECRET_KEY_BTC,
        PUBKEY_ADDRESS_256,
        SCRIPT_ADDRESS_256,
        STAKE_ONLY_PKADDR,

        MAX_BASE58_TYPES
    };

    const Consensus::Params& GetConsensus() const { return consensus; }
    const MessageStartChars& MessageStart() const { return pchMessageStart; }
    uint16_t GetDefaultPort() const { return nDefaultPort; }
    std::vector<int> GetAvailableSnapshotHeights() const;

    const CBlock& GenesisBlock() const { return genesis; }
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** If this chain is exclusively used for testing */
    bool IsTestChain() const { return m_chain_type != ChainType::MAIN; }
    /** If this chain allows time to be mocked */
    bool IsMockableChain() const { return m_is_mockable_chain; }
    uint64_t PruneAfterHeight() const { return nPruneAfterHeight; }
    /** Minimum free space (in GB) needed for data directory */
    uint64_t AssumedBlockchainSize() const { return m_assumed_blockchain_size; }
    /** Minimum free space (in GB) needed for data directory when pruned; Does not include prune target*/
    uint64_t AssumedChainStateSize() const { return m_assumed_chain_state_size; }
    /** Whether it is possible to mine blocks on demand (no retargeting) */
    bool MineBlocksOnDemand() const { return consensus.fPowNoRetargeting; }
    /** Return the chain type string */
    std::string GetChainTypeString() const { return ChainTypeToString(m_chain_type); }
    /** Return the chain type */
    ChainType GetChainType() const { return m_chain_type; }
    /** Return the list of hostnames to look up for DNS seeds */
    const std::vector<std::string>& DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const std::string& Bech32HRP() const { return bech32_hrp; }
    const std::vector<uint8_t>& FixedSeeds() const { return vFixedSeeds; }
    const CCheckpointData& Checkpoints() const { return checkpointData; }

    std::optional<AssumeutxoData> AssumeutxoForHeight(int height) const
    {
        return FindFirst(m_assumeutxo_data, [&](const auto& d) { return d.height == height; });
    }
    std::optional<AssumeutxoData> AssumeutxoForBlockhash(const uint256& blockhash) const
    {
        return FindFirst(m_assumeutxo_data, [&](const auto& d) { return d.blockhash == blockhash; });
    }

    const ChainTxData& TxData() const { return chainTxData; }

    /**
     * SigNetOptions holds configurations for creating a signet CChainParams.
     */
    struct SigNetOptions {
        std::optional<std::vector<uint8_t>> challenge{};
        std::optional<std::vector<std::string>> seeds{};
    };

    /**
     * VersionBitsParameters holds activation parameters
     */
    struct VersionBitsParameters {
        int64_t start_time;
        int64_t timeout;
        int min_activation_height;
    };

    /**
     * RegTestOptions holds configurations for creating a regtest CChainParams.
     */
    struct RegTestOptions {
        std::unordered_map<Consensus::DeploymentPos, VersionBitsParameters> version_bits_parameters{};
        std::unordered_map<Consensus::BuriedDeployment, int> activation_heights{};
        bool fastprune{false};
    };

    static std::unique_ptr<CChainParams> RegTest(const RegTestOptions& options);
    static std::unique_ptr<CChainParams> SigNet(const SigNetOptions& options);
    static std::unique_ptr<CChainParams> Main();
    static std::unique_ptr<CChainParams> TestNet();

    // Particl
    int BIP44ID() const { return nBIP44ID; }
    void SetOld();
    Consensus::Params& GetConsensus_nc() { assert(GetChainType() == ChainType::REGTEST); return consensus; }

    uint32_t GetModifierInterval() const { return nModifierInterval; }
    uint32_t GetStakeMinConfirmations() const { return nStakeMinConfirmations; }
    uint32_t GetTargetSpacing() const { return nTargetSpacing; }
    uint32_t GetTargetTimespan() const { return nTargetTimespan; }

    uint32_t GetStakeTimestampMask(int nHeight) const { return nStakeTimestampMask; }
    int64_t GetCoinYearReward(int64_t nTime) const;

    const particl::TreasuryFundSettings *GetTreasuryFundSettings(int64_t nTime) const;
    const std::vector<std::pair<int64_t, particl::TreasuryFundSettings> > &GetTreasuryFundSettings() const {return vTreasuryFundSettings;};
    bool PushTreasuryFundSettings(int64_t time_from, particl::TreasuryFundSettings &settings);

    int64_t GetMaxSmsgFeeRateDelta(int64_t smsg_fee_prev, int64_t time) const;

    bool CheckImportCoinbase(int nHeight, uint256 &hash) const;
    uint32_t GetLastImportHeight() const { return consensus.nLastImportHeight; }

    const std::vector<unsigned char>& Bech32Prefix(Base58Type type) const { return bech32Prefixes[type]; }
    bool IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn) const;
    bool IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn, CChainParams::Base58Type &rtype) const;
    bool IsBech32Prefix(const char *ps, size_t slen, CChainParams::Base58Type &rtype) const;

    void SetCoinYearReward(int64_t nCoinYearReward_)
    {
        assert(GetChainType() == ChainType::REGTEST);
        nCoinYearReward = nCoinYearReward_;
    }
protected:
    CChainParams() {}

    Consensus::Params consensus;
    MessageStartChars pchMessageStart;
    uint16_t nDefaultPort;
    uint64_t nPruneAfterHeight;
    uint64_t m_assumed_blockchain_size;
    uint64_t m_assumed_chain_state_size;
    std::vector<std::string> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    std::string bech32_hrp;
    ChainType m_chain_type;
    CBlock genesis;
    std::vector<uint8_t> vFixedSeeds;
    bool fDefaultConsistencyChecks;
    bool m_is_mockable_chain;
    CCheckpointData checkpointData;
    std::vector<AssumeutxoData> m_assumeutxo_data;
    ChainTxData chainTxData;

    // Particl
    void SetLastImportHeight()
    {
        consensus.nLastImportHeight = 0;
        for (const auto cth : vImportedCoinbaseTxns) {
            consensus.nLastImportHeight = std::max(consensus.nLastImportHeight, cth.nHeight);
        }
    }
    int nBIP44ID;
    std::vector<unsigned char> bech32Prefixes[MAX_BASE58_TYPES];
    uint32_t nModifierInterval;         // seconds to elapse before new modifier is computed
    uint32_t nStakeMinConfirmations;    // min depth in chain before staked output is spendable
    uint32_t nTargetSpacing;            // targeted number of seconds between blocks
    uint32_t nTargetTimespan;

    uint32_t nStakeTimestampMask = (1 << 4) - 1; // 4 bits, every kernel stake hash will change every 16 seconds
    int64_t nCoinYearReward = 2 * CENT; // 2% per year, See GetCoinYearReward

    std::vector<particl::CImportedCoinbaseTxn> vImportedCoinbaseTxns;
    std::vector<std::pair<int64_t, particl::TreasuryFundSettings> > vTreasuryFundSettings;
};

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& pchMessageStart);

#endif // BITCOIN_KERNEL_CHAINPARAMS_H
