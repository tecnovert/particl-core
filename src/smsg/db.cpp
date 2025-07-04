// Copyright (c) 2017-2024 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <clientversion.h>
#include <common/args.h>
#include <compat/endian.h>
#include <smsg/db.h>
#include <smsg/keystore.h>
#include <smsg/smessage.h>
#include <streams.h>

#include <leveldb/db.h>
#include <string.h>

namespace smsg {

const std::string DBK_PUBLICKEY         = "pk";
const std::string DBK_SECRETKEY         = "sk";
const std::string DBK_INBOX             = "IM";
const std::string DBK_OUTBOX            = "SM";
const std::string DBK_QUEUED            = "QM";
const std::string DBK_STASHED           = "TM";
const std::string DBK_PURGED_TOKEN      = "pm";
const std::string DBK_FUNDING_TX_DATA   = "fd";
const std::string DBK_FUNDING_TX_LINK   = "fl";
const std::string DBK_BEST_BLOCK        = "bb";

RecursiveMutex cs_smsgDB;
leveldb::DB *smsgDB = nullptr;

class SecMsgBatchScanner : public leveldb::WriteBatch::Handler
{
public:
    std::string needle;
    bool *deleted;
    std::string *foundValue;
    bool foundEntry{false};

    virtual void Put(const leveldb::Slice &key, const leveldb::Slice &value) override
    {
        if (key.ToString() == needle) {
            foundEntry = true;
            *deleted = false;
            *foundValue = value.ToString();
        }
    }

    virtual void Delete(const leveldb::Slice &key) override
    {
        if (key.ToString() == needle) {
            foundEntry = true;
            *deleted = true;
        }
    }
};

bool SecMsgDB::Open(const char *pszMode)
{
    if (smsgDB) {
        pdb = smsgDB;
        return true;
    }

    bool fCreate = strchr(pszMode, 'c');

    fs::path fullpath = gArgs.GetDataDirNet() / "smsgdb";

    if (!fCreate &&
        (!fs::exists(fullpath) ||
         !fs::is_directory(fullpath))) {
        LogPrintf("%s: DB does not exist.\n", __func__);
        return false;
    }

    leveldb::Options options;
    options.create_if_missing = fCreate;
    leveldb::Status s = leveldb::DB::Open(options, fs::PathToString(fullpath), &smsgDB);

    if (!s.ok()) {
        LogPrintf("%s: Error opening db: %s.\n", __func__, s.ToString());
        return false;
    }

    pdb = smsgDB;

    return true;
}

// When performing a read, if we have an active batch we need to check it first
// before reading from the database, as the rest of the code assumes that once
// a database transaction begins reads are consistent with it. It would be good
// to change that assumption in future and avoid the performance hit, though in
// practice it does not appear to be large.
bool SecMsgDB::ScanBatch(const DataStream &key, std::string *value, bool *deleted) const
{
    if (!activeBatch) {
        return false;
    }

    *deleted = false;
    SecMsgBatchScanner scanner;
    scanner.needle = key.str();
    scanner.deleted = deleted;
    scanner.foundValue = value;
    leveldb::Status s = activeBatch->Iterate(&scanner);
    if (!s.ok()) {
        LogError("SecMsgDB ScanBatch error: %s\n", s.ToString());
        return false;
    }

    return scanner.foundEntry;
}

bool SecMsgDB::TxnBegin()
{
    if (activeBatch) {
        return true;
    }
    activeBatch = new leveldb::WriteBatch();
    return true;
}

bool SecMsgDB::TxnCommit()
{
    if (!activeBatch) {
        return false;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status status = pdb->Write(writeOptions, activeBatch);
    delete activeBatch;
    activeBatch = nullptr;

    if (!status.ok()) {
        LogError("SecMsgDB batch commit failure: %s\n", status.ToString());
        return false;
    }

    return true;
}

bool SecMsgDB::TxnAbort()
{
    delete activeBatch;
    activeBatch = nullptr;
    return true;
}

bool SecMsgDB::CommitBatch(leveldb::WriteBatch *batch)
{
    if (!batch) {
        return false;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status status = pdb->Write(writeOptions, batch);

    if (!status.ok()) {
        LogError("SecMsgDB batch commit failure: %s\n", status.ToString());
        return false;
    }

    return true;
}

bool SecMsgDB::ReadPK(const CKeyID &addr, CPubKey &pubkey)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{};
    ssKey.reserve(sizeof(addr) + 2);
    ssKey << uint8_t(DBK_PUBLICKEY[0]);
    ssKey << uint8_t(DBK_PUBLICKEY[1]);
    ssKey << addr;
    std::string strValue;

    bool readFromDb = true;
    if (activeBatch) {
        // Check activeBatch first
        bool deleted = false;
        readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
        if (deleted) {
            return false;
        }
    }

    if (readFromDb) {
        leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);
        if (!s.ok()) {
            if (s.IsNotFound()) {
                return false;
            }
            LogError("LevelDB read failure: %s\n", s.ToString());
            return false;
        }
    }

    try {
        DataStream ssValue{MakeUCharSpan(strValue)};
        ssValue >> pubkey;
    } catch (std::exception &e) {
        LogPrintf("%s unserialize threw: %s.\n", __func__, e.what());
        return false;
    }

    return true;
}

bool SecMsgDB::WritePK(const CKeyID &addr, const CPubKey &pubkey)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{};
    ssKey.reserve(sizeof(addr) + 2);
    ssKey << uint8_t(DBK_PUBLICKEY[0]);
    ssKey << uint8_t(DBK_PUBLICKEY[1]);
    ssKey << addr;
    DataStream ssValue{};
    ssValue.reserve(sizeof(pubkey));
    ssValue << pubkey;

    if (activeBatch) {
        activeBatch->Put(ssKey.str(), ssValue.str());
        return true;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Put(writeOptions, ssKey.str(), ssValue.str());
    if (!s.ok()) {
        LogError("SecMsgDB write failure: %s\n", s.ToString());
        return false;
    }

    return true;
}

bool SecMsgDB::ExistsPK(const CKeyID &addr)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{};
    ssKey.reserve(sizeof(addr)+2);
    ssKey << uint8_t(DBK_PUBLICKEY[0]);
    ssKey << uint8_t(DBK_PUBLICKEY[1]);
    ssKey << addr;
    std::string unused;

    if (activeBatch) {
        bool deleted;
        if (ScanBatch(ssKey, &unused, &deleted) && !deleted) {
            return true;
        }
    }

    leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &unused);
    return s.IsNotFound() == false;
};

bool SecMsgDB::ErasePK(const CKeyID &addr)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{};
    ssKey.reserve(sizeof(addr)+2);
    ssKey << uint8_t(DBK_PUBLICKEY[0]);
    ssKey << uint8_t(DBK_PUBLICKEY[1]);
    ssKey << addr;

    if (activeBatch) {
        activeBatch->Delete(ssKey.str());
        return true;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Delete(writeOptions, ssKey.str());

    if (s.ok() || s.IsNotFound()) {
        return true;
    }
    LogError("SecMsgDB erase failed: %s\n", s.ToString());
    return false;
};

bool SecMsgDB::NextPKKey(leveldb::Iterator *it, CKeyID &key_id)
{
    if (!pdb) {
        return false;
    }

    if (!it->Valid()) { // First run
        it->Seek(DBK_PUBLICKEY);
    } else {
        it->Next();
    }

    if (!(it->Valid()
        && it->key().size() == DBK_PUBLICKEY.size() + 20
        && memcmp(it->key().data(), DBK_PUBLICKEY.data(), DBK_PUBLICKEY.size()) == 0)) {
        return false;
    }

    memcpy(key_id.begin(), it->key().data() + DBK_PUBLICKEY.size(), 20);

    return true;
}

bool SecMsgDB::ReadKey(const CKeyID &idk, SecMsgKey &key)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{};
    ssKey.reserve(sizeof(idk) + 2);
    ssKey << uint8_t(DBK_SECRETKEY[0]);
    ssKey << uint8_t(DBK_SECRETKEY[1]);
    ssKey << idk;
    std::string strValue;

    bool readFromDb = true;
    if (activeBatch) {
        // Check activeBatch first
        bool deleted = false;
        readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
        if (deleted) {
            return false;
        }
    }

    if (readFromDb) {
        leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);
        if (!s.ok()) {
            if (s.IsNotFound()) {
                return false;
            }
            LogError("LevelDB read failure: %s\n", s.ToString());
            return false;
        }
    }

    try {
        DataStream ssValue{MakeUCharSpan(strValue)};
        ssValue >> key;
    } catch (std::exception &e) {
        LogPrintf("%s unserialize threw: %s.\n", __func__, e.what());
        return false;
    }

    return true;
}

bool SecMsgDB::WriteKey(const CKeyID &idk, const SecMsgKey &key)
{
    if (!pdb) {
        return false;
    }
    DataStream ssKey{};
    ssKey.reserve(sizeof(idk) + 2);
    ssKey << uint8_t(DBK_SECRETKEY[0]);
    ssKey << uint8_t(DBK_SECRETKEY[1]);
    ssKey << idk;

    DataStream ssValue{};
    ssValue.reserve(sizeof(key));
    ssValue << key;

    if (activeBatch) {
        activeBatch->Put(ssKey.str(), ssValue.str());
        return true;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Put(writeOptions, ssKey.str(), ssValue.str());
    if (!s.ok()) {
        LogError("%s failed: %s\n", __func__, s.ToString());
        return false;
    }

    return true;
}

bool SecMsgDB::EraseKey(const CKeyID &idk)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{};
    ssKey.reserve(sizeof(idk)+2);
    ssKey << uint8_t(DBK_SECRETKEY[0]);
    ssKey << uint8_t(DBK_SECRETKEY[1]);
    ssKey << idk;

    if (activeBatch) {
        activeBatch->Delete(ssKey.str());
        return true;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Delete(writeOptions, ssKey.str());

    if (s.ok() || s.IsNotFound()) {
        return true;
    }
    LogError("SecMsgDB erase failed: %s\n", s.ToString());
    return false;
};


bool SecMsgDB::NextSmesg(leveldb::Iterator *it, const std::string &prefix, uint8_t *chKey, SecMsgStored &smsgStored)
{
    if (!pdb) {
        return false;
    }

    if (!it->Valid()) { // First run
        it->Seek(prefix);
    } else {
        it->Next();
    }

    if (!(it->Valid() &&
        it->key().size() == 30 &&
        memcmp(it->key().data(), prefix.data(), 2) == 0)) {
        return false;
    }

    memcpy(chKey, it->key().data(), 30);

    try {
        DataStream ssValue(MakeUCharSpan(it->value()));
        ssValue >> smsgStored;
    } catch (std::exception &e) {
        LogPrintf("%s unserialize threw: %s.\n", __func__, e.what());
        return false;
    }

    return true;
}

bool SecMsgDB::NextSmesgKey(leveldb::Iterator *it, const std::string &prefix, uint8_t *chKey)
{
    if (!pdb) {
        return false;
    }

    if (!it->Valid()) { // First run
        it->Seek(prefix);
    } else {
        it->Next();
    }

    if (!(it->Valid()
        && it->key().size() == 30
        && memcmp(it->key().data(), prefix.data(), 2) == 0)) {
        return false;
    }

    memcpy(chKey, it->key().data(), 30);

    return true;
}

bool SecMsgDB::ReadSmesg(const uint8_t *chKey, SecMsgStored &smsgStored)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{};
    ssKey.write(AsBytes(Span{(const char*)chKey, 30}));
    std::string strValue;

    bool readFromDb = true;
    if (activeBatch) {
        // Check activeBatch first
        bool deleted = false;
        readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
        if (deleted) {
            return false;
        }
    }

    if (readFromDb) {
        leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);
        if (!s.ok()) {
            if (s.IsNotFound()) {
                return false;
            }
            LogError("LevelDB read failure: %s\n", s.ToString());
            return false;
        }
    }

    try {
        DataStream ssValue(MakeUCharSpan(strValue));
        ssValue >> smsgStored;
    } catch (std::exception &e) {
        LogPrintf("%s unserialize threw: %s.\n", __func__, e.what());
        return false;
    }

    return true;
}

bool SecMsgDB::WriteSmesg(const uint8_t *chKey, const SecMsgStored &smsgStored)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{}, ssValue{};
    ssKey.write(AsBytes(Span{(const char*)chKey, 30}));
    ssValue << smsgStored;

    if (activeBatch) {
        activeBatch->Put(ssKey.str(), ssValue.str());
        return true;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Put(writeOptions, ssKey.str(), ssValue.str());
    if (!s.ok()) {
        LogError("SecMsgDB write failed: %s\n", s.ToString());
        return false;
    }

    return true;
}

bool SecMsgDB::ExistsSmesg(const uint8_t *chKey)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{};
    ssKey.write(AsBytes(Span{(const char*)chKey, 30}));
    std::string unused;

    if (activeBatch) {
        bool deleted;
        if (ScanBatch(ssKey, &unused, &deleted) && !deleted) {
            return true;
        }
    }

    leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &unused);
    return s.IsNotFound() == false;
}

bool SecMsgDB::EraseSmesg(const uint8_t *chKey)
{
    DataStream ssKey{};
    ssKey.write(AsBytes(Span{(const char*)chKey, 30}));

    if (activeBatch) {
        activeBatch->Delete(ssKey.str());
        return true;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Delete(writeOptions, ssKey.str());

    if (s.ok() || s.IsNotFound()) {
        return true;
    }
    LogError("SecMsgDB erase failed: %s\n", s.ToString());
    return false;
}

bool SecMsgDB::ReadPurged(const uint8_t *chKey, SecMsgPurged &smsgPurged)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{};
    ssKey.write(AsBytes(Span{(const char*)chKey, 30}));
    std::string strValue;

    bool readFromDb = true;
    if (activeBatch) {
        // Check activeBatch first
        bool deleted = false;
        readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
        if (deleted) {
            return false;
        }
    }

    if (readFromDb) {
        leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);
        if (!s.ok()) {
            if (s.IsNotFound()) {
                return false;
            }
            LogError("LevelDB read failure: %s\n", s.ToString());
            return false;
        }
    }

    try {
        DataStream ssValue(MakeUCharSpan(strValue));
        ssValue >> smsgPurged;
    } catch (std::exception &e) {
        LogPrintf("%s unserialize threw: %s.\n", __func__, e.what());
        return false;
    }

    return true;
}

bool SecMsgDB::WritePurged(const uint8_t *chKey, const SecMsgPurged &smsgPurged)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{}, ssValue{};
    ssKey.write(AsBytes(Span{(const char*)chKey, 30}));
    ssValue << smsgPurged;

    if (activeBatch) {
        activeBatch->Put(ssKey.str(), ssValue.str());
        return true;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Put(writeOptions, ssKey.str(), ssValue.str());
    if (!s.ok()) {
        LogError("SecMsgDB write failed: %s\n", s.ToString());
        return false;
    }

    return true;
}

bool SecMsgDB::ErasePurged(const uint8_t *chKey)
{
    return EraseSmesg(chKey);
}


bool SecMsgDB::NextPurged(leveldb::Iterator *it, const std::string &prefix, uint8_t *chKey, SecMsgPurged &smsgPurged)
{
    if (!pdb) {
        return false;
    }

    if (!it->Valid()) { // First run
        it->Seek(prefix);
    } else {
        it->Next();
    }

    if (!(it->Valid()
        && it->key().size() == 30
        && memcmp(it->key().data(), prefix.data(), 2) == 0)) {
        return false;
    }

    memcpy(chKey, it->key().data(), 30);

    try {
        DataStream ssValue(MakeUCharSpan(it->value()));
        ssValue >> smsgPurged;
    } catch (std::exception &e) {
        LogPrintf("%s unserialize threw: %s.\n", __func__, e.what());
        return false;
    }

    return true;
}

bool SecMsgDB::NextPrivKey(leveldb::Iterator *it, const std::string &prefix, CKeyID &idk, SecMsgKey &key)
{
    if (!pdb) {
        return false;
    }

    if (!it->Valid()) { // First run
        it->Seek(prefix);
    } else {
        it->Next();
    }

    if (!(it->Valid()
        && it->key().size() == 22
        && memcmp(it->key().data(), prefix.data(), 2) == 0)) {
        return false;
    }

    memcpy(idk.begin(), it->key().data()+2, 20);

    try {
        DataStream ssValue(MakeUCharSpan(it->value()));
        ssValue >> key;
    } catch (std::exception &e) {
        LogPrintf("%s unserialize threw: %s.\n", __func__, e.what());
        return false;
    }

    return true;
}

bool SecMsgDB::ReadFundingData(const uint256 &key, std::vector<uint8_t> &data)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{};
    ssKey.write(AsBytes(Span{(const char*)DBK_FUNDING_TX_DATA.data(), DBK_FUNDING_TX_DATA.size()}));
    ssKey.write(AsBytes(Span{(const char*)key.begin(), 32}));
    std::string strValue;

    bool readFromDb = true;
    if (activeBatch) {
        // Check activeBatch first
        bool deleted = false;
        readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
        if (deleted) {
            return false;
        }
    }

    if (readFromDb) {
        leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);
        if (!s.ok()) {
            if (s.IsNotFound()) {
                return false;
            }
            LogError("LevelDB read failure: %s\n", s.ToString());
            return false;
        }
    }

    try {
        DataStream ssValue(MakeUCharSpan(strValue));
        ssValue >> data;
    } catch (std::exception &e) {
        LogPrintf("%s unserialize threw: %s.\n", __func__, e.what());
        return false;
    }

    return true;
}

bool SecMsgDB::WriteFundingData(const uint256 &key, int height, const std::vector<uint8_t> &data)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{}, ssValue{};
    ssKey.write(AsBytes(Span{(const char*)DBK_FUNDING_TX_DATA.data(), DBK_FUNDING_TX_DATA.size()}));
    ssKey.write(AsBytes(Span{(const char*)key.begin(), 32}));
    ssValue << data;

    uint32_t be_height = htobe32((uint32_t)height);
    DataStream ssKeyI{}, ssValueI{};
    ssKeyI.write(AsBytes(Span{(const char*)DBK_FUNDING_TX_LINK.data(), DBK_FUNDING_TX_LINK.size()}));
    ssKeyI.write(AsBytes(Span{(const char*)&be_height, 4}));
    ssKeyI.write(AsBytes(Span{(const char*)key.begin(), 32}));

    if (activeBatch) {
        activeBatch->Put(ssKey.str(), ssValue.str());
        activeBatch->Put(ssKeyI.str(), ssValueI.str());
        return true;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Put(writeOptions, ssKey.str(), ssValue.str());
    if (!s.ok()) {
        LogError("SecMsgDB write failed: %s\n", s.ToString());
        return false;
    }
    s = pdb->Put(writeOptions, ssKeyI.str(), ssValueI.str());
    if (!s.ok()) {
        LogError("SecMsgDB write failed: %s\n", s.ToString());
        return false;
    }

    return true;
}

bool SecMsgDB::EraseFundingData(int height, const uint256 &key)
{
    DataStream ssKey{}, ssKeyI{};
    ssKey.write(AsBytes(Span{(const char*)DBK_FUNDING_TX_DATA.data(), DBK_FUNDING_TX_DATA.size()}));
    ssKey.write(AsBytes(Span{(const char*)key.begin(), 32}));

    uint32_t be_height = htobe32((uint32_t)height);
    ssKeyI.write(AsBytes(Span{(const char*)DBK_FUNDING_TX_LINK.data(), DBK_FUNDING_TX_LINK.size()}));
    ssKeyI.write(AsBytes(Span{(const char*)&be_height, 4}));
    ssKeyI.write(AsBytes(Span{(const char*)key.begin(), 32}));

    if (activeBatch) {
        activeBatch->Delete(ssKey.str());
        activeBatch->Delete(ssKeyI.str());
        return true;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Delete(writeOptions, ssKey.str());
    leveldb::Status s1 = pdb->Delete(writeOptions, ssKeyI.str());
    if ((s.ok() || s.IsNotFound()) && (s1.ok() || s1.IsNotFound())) {
        return true;
    }
    LogError("SecMsgDB erase failed: %s, %s\n", s.ToString(), s1.ToString());
    return false;
}

bool SecMsgDB::NextFundingDataLink(leveldb::Iterator *it, int &height, uint256 &key)
{
    if (!pdb) {
        return false;
    }

    if (!it->Valid()) { // First run
        it->Seek(DBK_FUNDING_TX_LINK);
    } else {
        it->Next();
    }

    if (!(it->Valid()
        && it->key().size() == DBK_FUNDING_TX_LINK.size() + 4 + 32
        && memcmp(it->key().data(), DBK_FUNDING_TX_LINK.data(), DBK_FUNDING_TX_LINK.size()) == 0)) {
        return false;
    }

    uint32_t be_height;
    memcpy(&be_height, it->key().data() + DBK_FUNDING_TX_LINK.size(), 4);
    height = (int) be32toh(be_height);
    memcpy(key.begin(), it->key().data() + DBK_FUNDING_TX_LINK.size() + 4, 32);

    return true;
}

bool SecMsgDB::WriteBestBlock(const uint256 &block_hash, int height)
{
    if (!pdb) {
        return false;
    }

    DataStream ssKey{}, ssValue{};
    ssKey.write(AsBytes(Span{(const char*)DBK_BEST_BLOCK.data(), DBK_BEST_BLOCK.size()}));
    ssValue << block_hash;
    ssValue << height;

    if (activeBatch) {
        activeBatch->Put(ssKey.str(), ssValue.str());
        return true;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Put(writeOptions, ssKey.str(), ssValue.str());
    if (!s.ok()) {
        LogError("SecMsgDB write failed: %s\n", s.ToString());
        return false;
    }

    return true;
}

bool SecMsgDB::ReadBestBlock(uint256 &block_hash, int &height)
{
    DataStream ssKey{};
    ssKey.write(AsBytes(Span{(const char*)DBK_BEST_BLOCK.data(), DBK_BEST_BLOCK.size()}));
    std::string strValue;

    bool readFromDb = true;
    if (activeBatch) {
        // Check activeBatch first
        bool deleted = false;
        readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
        if (deleted) {
            return false;
        }
    }

    if (readFromDb) {
        leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);
        if (!s.ok()) {
            if (s.IsNotFound()) {
                return false;
            }
            LogError("LevelDB read failure: %s\n", s.ToString());
            return false;
        }
    }

    try {
        DataStream ssValue(MakeUCharSpan(strValue));
        ssValue >> block_hash;
        ssValue >> height;
    } catch (std::exception &e) {
        LogPrintf("%s unserialize threw: %s.\n", __func__, e.what());
        return false;
    }

    return true;
}

bool SecMsgDB::EraseBestBlock()
{
    DataStream ssKey{};
    ssKey.write(AsBytes(Span{(const char*)DBK_BEST_BLOCK.data(), DBK_BEST_BLOCK.size()}));

    if (activeBatch) {
        activeBatch->Delete(ssKey.str());
        return true;
    }

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Delete(writeOptions, ssKey.str());
    if (s.ok() || s.IsNotFound()) {
        return true;
    }
    LogError("SecMsgDB erase failed: %s\n", s.ToString());
    return false;
}

void SecMsgDB::Compact() const
{
    pdb->CompactRange(nullptr, nullptr);
}

bool PutBestBlock(leveldb::WriteBatch *batch, const uint256 &block_hash, int height)
{
    DataStream ssKey{}, ssValue{};
    ssKey.write(AsBytes(Span{(const char*)DBK_BEST_BLOCK.data(), DBK_BEST_BLOCK.size()}));
    ssValue << block_hash;
    ssValue << height;

    batch->Put(ssKey.str(), ssValue.str());
    return true;
}

bool PutFundingData(leveldb::WriteBatch *batch, const uint256 &key, int height, const std::vector<uint8_t> &data)
{
    DataStream ssKey{}, ssValue{};
    ssKey.write(AsBytes(Span{(const char*)DBK_FUNDING_TX_DATA.data(), DBK_FUNDING_TX_DATA.size()}));
    ssKey.write(AsBytes(Span{(const char*)key.begin(), 32}));
    ssValue << data;

    uint32_t be_height = htobe32((uint32_t)height);
    DataStream ssKeyI{}, ssValueI{};
    ssKeyI.write(AsBytes(Span{(const char*)DBK_FUNDING_TX_LINK.data(), DBK_FUNDING_TX_LINK.size()}));
    ssKeyI.write(AsBytes(Span{(const char*)&be_height, 4}));
    ssKeyI.write(AsBytes(Span{(const char*)key.begin(), 32}));

    batch->Put(ssKey.str(), ssValue.str());
    batch->Put(ssKeyI.str(), ssValueI.str());
    return true;
}

} // namespace smsg
