// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PIVX_QUORUMS_UTILS_H
#define PIVX_QUORUMS_UTILS_H

#include "consensus/params.h"
#include "evo/deterministicmns.h"
#include "net.h"

#include <vector>

class CBLSPublicKey;

namespace llmq
{

namespace utils
{

std::vector<CDeterministicMNCPtr> GetAllQuorumMembers(Consensus::LLMQType llmqType, const CBlockIndex* pindexQuorum);

uint256 BuildCommitmentHash(Consensus::LLMQType llmqType, const uint256& blockHash, const std::vector<bool>& validMembers, const CBLSPublicKey& pubKey, const uint256& vvecHash);
uint256 BuildSignHash(Consensus::LLMQType llmqType, const uint256& quorumHash, const uint256& id, const uint256& msgHash);

// works for sig shares and recovered sigs
template<typename T>
uint256 BuildSignHash(const T& s)
{
   return BuildSignHash((Consensus::LLMQType)s.llmqType, s.quorumHash, s.id, s.msgHash);
}

std::string ToHexStr(const std::vector<bool>& vBits);

} // namespace llmq::utils

} // namespace llmq

#endif // PIVX_QUORUMS_UTILS_H