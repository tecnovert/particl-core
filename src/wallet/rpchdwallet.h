// Copyright (c) 2017-2021 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RPCHDWALLET_H
#define BITCOIN_WALLET_RPCHDWALLET_H

class CRPCCommand;
class CHDWallet;

void EnsureWalletIsUnlocked(CHDWallet *pwallet);

Span<const CRPCCommand> GetHDWalletRPCCommands();

#endif //BITCOIN_WALLET_RPCHDWALLET_H
