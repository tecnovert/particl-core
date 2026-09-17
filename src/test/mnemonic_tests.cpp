// Copyright (c) 2017-2023 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <test/data/bip39_vectors_english.json.h>
#include <test/data/bip39_vectors_japanese.json.h>

#include <key/extkey.h>
#include <key_io.h>
#include <key/mnemonic.h>
#include <random.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <string>

#include <boost/test/unit_test.hpp>


extern UniValue read_json(const std::string& jsondata);

BOOST_FIXTURE_TEST_SUITE(mnemonic_tests, BasicTestingSetup)


const char *mnemonic_1 = "deer clever bitter bonus unable menu satoshi chaos dwarf inmate robot drama exist nuclear raise";
const char *mnemonic_2 = "zoologie ficeler xénon voyelle village viande vignette sécréter séduire torpille remède abolir";

BOOST_AUTO_TEST_CASE(mnemonic_test)
{
    SecureString words = mnemonic_1;
    std::string expect_seed = "1da563986981b82c17a76160934f4b532eac77e14b632c6adcf31ba4166913e063ce158164c512cdce0672cbc9256dd81e7be23a8d8eb331de1a497493c382b1";

    std::vector<uint8_t, secure_allocator<unsigned char>> vSeed;
    SecureString password;
    BOOST_CHECK(0 == mnemonic::ToSeed(words, password, vSeed));

    std::vector<uint8_t> hex_seed(vSeed.begin(), vSeed.end());
    BOOST_CHECK(HexStr(hex_seed) == expect_seed);
}

BOOST_AUTO_TEST_CASE(mnemonic_test_fails)
{
    // Fail tests

    int nLanguage = -1;
    std::string sError;
    std::vector<uint8_t, secure_allocator<unsigned char>> vEntropy;
    SecureString sWords = "legals winner thank year wave sausage worth useful legal winner thank yellow";
    BOOST_CHECK_MESSAGE(3 == mnemonic::Decode(nLanguage, sWords, vEntropy, sError), "MnemonicDecode: " << sError);

    sWords = "winner legal thank year wave sausage worth useful legal winner thank yellow";
    BOOST_CHECK_MESSAGE(5 == mnemonic::Decode(nLanguage, sWords, vEntropy, sError), "MnemonicDecode: " << sError);
}

BOOST_AUTO_TEST_CASE(mnemonic_addchecksum)
{
    std::string sError;
    SecureString sWordsIn = "abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab";
    SecureString sWordsOut;

    BOOST_CHECK_MESSAGE(0 == mnemonic::AddChecksum(-1, sWordsIn, sWordsOut, sError), "MnemonicAddChecksum: " << sError);

    BOOST_CHECK_MESSAGE(sWordsOut == "abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb", "sWordsOut: " << sWordsOut);

    // Must fail, len % 3 != 0
    SecureString sWordsInFail = "abandon baby cabbage dad eager fabric gadget habit ice kangaroo";
    BOOST_CHECK_MESSAGE(4 == mnemonic::AddChecksum(-1, sWordsInFail, sWordsOut, sError), "MnemonicAddChecksum: " << sError);


    SecureString sWordsInFrench = "zoologie ficeler xénon voyelle village viande vignette sécréter séduire torpille remède";

    BOOST_CHECK(0 == mnemonic::AddChecksum(-1, sWordsInFrench, sWordsOut, sError));
    BOOST_CHECK(sWordsOut == mnemonic_2);
}

static void runTests(int nLanguage, UniValue &tests)
{
    std::string sError;
    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue &test = tests[idx];

        assert(test.size() > 2);

        SecureString sEntropy = test[0].get_str().c_str();
        SecureString sWords = test[1].get_str().c_str();
        std::string sSeed;
        SecureString sPassphrase;
        if (test.size() > 3) {
            sPassphrase = test[2].get_str().c_str();
            sSeed = test[3].get_str().c_str();
        } else {
            sPassphrase = "TREZOR";
            sSeed = test[2].get_str();
        }
        std::vector<uint8_t> entropy_in = ParseHex(sEntropy);
        std::vector<uint8_t, secure_allocator<unsigned char>> vEntropy(entropy_in.begin(), entropy_in.end());
        std::vector<uint8_t, secure_allocator<unsigned char>> vEntropyTest;

        SecureString sWordsTest;
        BOOST_CHECK_MESSAGE(0 == mnemonic::Encode(nLanguage, vEntropy, sWordsTest, sError), "MnemonicEncode: " << sError);

        BOOST_CHECK(sWords == sWordsTest);

        int nLanguage = -1;
        BOOST_CHECK_MESSAGE(0 == mnemonic::Decode(nLanguage, sWords, vEntropyTest, sError), "MnemonicDecode: " << sError);
        BOOST_CHECK(vEntropy == vEntropyTest);

        std::vector<uint8_t> vSeed = ParseHex(sSeed);
        std::vector<uint8_t, secure_allocator<unsigned char>> seed_check(vSeed.begin(), vSeed.end());
        std::vector<uint8_t, secure_allocator<unsigned char>> vSeedTest;

        BOOST_CHECK(0 == mnemonic::ToSeed(sWords, sPassphrase, vSeedTest));
        BOOST_CHECK(seed_check == vSeedTest);

        if (test.size() > 4) {
            CExtKey58 eKey58;
            std::string sExtKey = test[4].get_str();

            CExtKey ekTest;
            ekTest.SetSeed(&vSeed[0], vSeed.size());

            eKey58.SetKey(CExtKeyPair(ekTest), CChainParams::EXT_SECRET_KEY_BTC);
            BOOST_CHECK(eKey58.ToString() == sExtKey);
        }
    }
}

BOOST_AUTO_TEST_CASE(mnemonic_test_json)
{
    UniValue tests_english = read_json(json_tests::bip39_vectors_english);
    runTests(mnemonic::WLL_ENGLISH, tests_english);

    UniValue tests_japanese = read_json(json_tests::bip39_vectors_japanese);
    runTests(mnemonic::WLL_JAPANESE, tests_japanese);
}

BOOST_AUTO_TEST_CASE(mnemonic_french_wordlist_bom)
{
    // The French wordlist used to begin with a UTF-8 BOM, making word 0 "\ufeffabaisser"
    const auto to_hex = [](const auto &v) { return HexStr(std::vector<uint8_t>(v.begin(), v.end())); };
    std::string sError;
    SecureString word0;
    BOOST_REQUIRE_EQUAL(0, mnemonic::GetWord(mnemonic::WLL_FRENCH, 0, word0, sError));
    BOOST_CHECK_EQUAL(std::string(word0.c_str()), "abaisser");

    std::vector<uint8_t, secure_allocator<unsigned char>> entropy(16, 0), entropy_out, vSeed;
    SecureString words;
    BOOST_REQUIRE_EQUAL(0, mnemonic::Encode(mnemonic::WLL_FRENCH, entropy, words, sError));
    BOOST_CHECK_EQUAL(std::string(words.c_str()), "abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abeille");

    SecureString passphrase = "TREZOR";
    BOOST_REQUIRE_EQUAL(0, mnemonic::ToSeed(words, passphrase, vSeed));
    BOOST_CHECK_EQUAL(to_hex(vSeed),
        "3bf3366c40256d7e2fca716fddf8673425c7c7e444af290ee1edf1bbf095e6e78a7190253f3e46f1e2069345d4b05ac17b242faa225c0a3e4d268976744e0698");

    // Legacy mode reproduces the seed of the old wordlist from the words as written down
    BOOST_REQUIRE_EQUAL(0, mnemonic::ToSeed(words, passphrase, vSeed, true));
    BOOST_CHECK_EQUAL(to_hex(vSeed),
        "06770fb231ab54f483953e034db26719c346ff1c4fbf5ebbd70779468456e1a162fe45cdb83ccfd425eb73fb96f7afbded1b6e982034e31b791883192e594917");

    // A mnemonic saved from an old release still carries the BOMs
    SecureString words_old;
    for (size_t i = 0; i < 11; ++i) {
        words_old += "\xef\xbb\xbf";
        words_old += "abaisser ";
    }
    words_old += "abeille";

    int language = -1;
    BOOST_CHECK(0 != mnemonic::Decode(language, words_old, entropy_out, sError));

    SecureString words_stripped = words_old;
    mnemonic::RemoveBOM(words_stripped);
    BOOST_CHECK(words_stripped == words);
    language = -1;
    BOOST_REQUIRE_EQUAL(0, mnemonic::Decode(language, words_stripped, entropy_out, sError));
    BOOST_CHECK_EQUAL(language, (int)mnemonic::WLL_FRENCH);
    BOOST_CHECK(entropy_out == entropy);

    BOOST_REQUIRE_EQUAL(0, mnemonic::ToSeed(words_old, passphrase, vSeed, true));
    BOOST_CHECK_EQUAL(to_hex(vSeed),
        "06770fb231ab54f483953e034db26719c346ff1c4fbf5ebbd70779468456e1a162fe45cdb83ccfd425eb73fb96f7afbded1b6e982034e31b791883192e594917");

    // Legacy mode changes nothing when the first word is absent
    SecureString words_other = "zoologie zoologie zoologie";
    std::vector<uint8_t, secure_allocator<unsigned char>> seed_a, seed_b;
    BOOST_REQUIRE_EQUAL(0, mnemonic::ToSeed(words_other, passphrase, seed_a));
    BOOST_REQUIRE_EQUAL(0, mnemonic::ToSeed(words_other, passphrase, seed_b, true));
    BOOST_CHECK(seed_a == seed_b);
}

BOOST_AUTO_TEST_CASE(random_issuer_test)
{
    int test;
    shamir39::StrongRandomIssuer random_issuer;
    for (size_t k = 0; k < 7; k++) {
        BOOST_CHECK(0 == random_issuer.GetBits(1, test));
        BOOST_CHECK(random_issuer.m_bits_used == k + 1);
        BOOST_CHECK(random_issuer.m_bytes_used == 0);
        BOOST_CHECK(test == 1 or test == 0);
    }
    BOOST_CHECK(0 == random_issuer.GetBits(1, test));
    BOOST_CHECK(random_issuer.m_bits_used == 0);
    BOOST_CHECK(random_issuer.m_bytes_used == 1);
    BOOST_CHECK(0 == random_issuer.GetBits(8, test));
    BOOST_CHECK(test >= 0 && test <= 255);
    BOOST_CHECK(random_issuer.m_bits_used == 0);
    BOOST_CHECK(random_issuer.m_bytes_used == 2);

    BOOST_CHECK(0 == random_issuer.GetBits(11, test));
    BOOST_CHECK(test >= 0 && test < (1 << 11));
    BOOST_CHECK(random_issuer.m_bits_used == 3);
    BOOST_CHECK(random_issuer.m_bytes_used == 3);

    for (size_t k = 0; k < 63; k++) {
        BOOST_CHECK(0 == random_issuer.GetBits(32, test));
    }
    BOOST_CHECK(0 == random_issuer.GetBits(8, test));
    BOOST_CHECK(test >= 0 && test < (1 << 8));
    BOOST_CHECK(random_issuer.m_bits_used == 3);
    BOOST_CHECK(random_issuer.m_bytes_used == 0);

    BOOST_CHECK(0 != random_issuer.GetBits(33, test));
    BOOST_CHECK(test == 0);

    // Ensure a known pattern is read back
    unsigned char test_bytes[256], check_bytes[256];
    memset(test_bytes, 0, 256);
    random_issuer.m_bits_used = 0;
    random_issuer.m_bytes_used = 0;
    for (size_t k = 0; k < 256; k++) {
        random_issuer.m_cached_bytes[k] = k;
        check_bytes[k] = k;
    }
    for (size_t k = 0; k < 256; k++) {
        int output;
        random_issuer.GetBits(8, output);
        test_bytes[k] = (unsigned char)output;
    }
    BOOST_CHECK(random_issuer.m_bits_used == 0);
    BOOST_CHECK(random_issuer.m_bytes_used == 256);
    BOOST_CHECK(memcmp(test_bytes, check_bytes, 256) == 0);
}

BOOST_AUTO_TEST_CASE(shamir39_test)
{
    std::string error_str;
    SecureString words = mnemonic_1;
    SecureString words_recovered;
    std::vector<SecureString> shares_out;

    BOOST_CHECK(2 == shamir39::splitmnemonic(words, 100, 2, 2, shares_out, error_str));
    BOOST_CHECK(error_str == "Unknown language");
    error_str.clear();

    BOOST_CHECK(0 == shamir39::splitmnemonic(words, -1, 2, 2, shares_out, error_str));
    BOOST_CHECK(shares_out.size() == 2);

    BOOST_CHECK(0 == shamir39::combinemnemonic(shares_out, -1, words_recovered, error_str));
    BOOST_REQUIRE(words_recovered == words);

    words = mnemonic_2;
    BOOST_REQUIRE(0 == shamir39::splitmnemonic(words, -1, 4, 3, shares_out, error_str));
    shares_out.pop_back();
    BOOST_CHECK(0 == shamir39::combinemnemonic(shares_out, -1, words_recovered, error_str));
    BOOST_REQUIRE(words_recovered == words);

    BOOST_REQUIRE(0 == shamir39::splitmnemonic(words, -1, 186, 91, shares_out, error_str));
    for (int k = 0; k < 80; ++k) {
        shares_out.erase(shares_out.begin() + GetRand(shares_out.size()));
    }
    BOOST_CHECK(0 == shamir39::combinemnemonic(shares_out, -1, words_recovered, error_str));
    BOOST_REQUIRE(words_recovered == words);
}

BOOST_AUTO_TEST_SUITE_END()
