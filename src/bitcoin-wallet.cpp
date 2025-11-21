// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include "addresstype.h"
#include <crypto/sha3.h>

#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <common/globals.h>
#include <common/url.h>
#include <compat/compat.h>
#include <interfaces/init.h>
#include <key.h>
#include <logging.h>
#include <pubkey.h>
#include <tinyformat.h>
#include <util/exception.h>
#include <util/translation.h>
#include <wallet/wallettool.h>

#include <exception>
#include <functional>
#include <string>
#include <tuple>
#include <vector>

#include <condition_variable>
#include <mutex>
#include <atomic>
#include <queue>
#include <thread>

// Particl includes
#include <key/mnemonic.h>

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;
UrlDecodeFn* const URL_DECODE = nullptr;


void print_ts(const std::string &message) {
    static std::mutex cout_mutex;
    std::lock_guard<std::mutex> lock{cout_mutex};
    puts(message.c_str());
}

std::vector<std::string> character_options = {
    // *
    " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
    // C
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    // A
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    // a
    "0123456789abcdefghijklmnopqrstuvwxyz",
    // L
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    // l
    "abcdefghijklmnopqrstuvwxyz",
    // d
    "0123456789",
    // s
    " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
};

bool get_char_options(std::string **s, char c)
{
    switch (c) {
        case '*':
            *s = &character_options[0];
            return true;
        case 'C':
            *s = &character_options[1];
            return true;
        case 'A':
            *s = &character_options[2];
            return true;
        case 'a':
            *s = &character_options[3];
            return true;
        case 'L':
            *s = &character_options[4];
            return true;
        case 'l':
            *s = &character_options[5];
            return true;
        case 'd':
            *s = &character_options[6];
            return true;
        case 's':
            *s = &character_options[7];
            return true;
        default:
            *s = nullptr;
            return false;
    }
    *s = nullptr;
    return false;
}

static void SetupWalletToolArgs(ArgsManager& argsman)
{
    SetupHelpOptions(argsman);
    SetupChainParamsBaseOptions(argsman);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-wallet=<wallet-name>", "Specify wallet name", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::OPTIONS);
    argsman.AddArg("-dumpfile=<file name>", "When used with 'dump', writes out the records to this file. When used with 'createfromdump', loads the records into a new wallet.", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::OPTIONS);
    argsman.AddArg("-debug=<category>", "Output debugging information (default: 0).", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-descriptors", "Create descriptors wallet. Only for 'create'", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-legacy", "Create legacy wallet. Only for 'create'", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-format=<format>", "The format of the wallet file to create. Either \"bdb\" or \"sqlite\". Only used with 'createfromdump'", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-printtoconsole", "Send trace/debug info to console (default: 1 when no -debug is true, 0 otherwise).", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);

    argsman.AddCommand("info", "Get wallet info");
    argsman.AddCommand("create", "Create new wallet file");
    argsman.AddCommand("salvage", "Attempt to recover private keys from a corrupt wallet. Warning: 'salvage' is experimental.");
    argsman.AddCommand("dump", "Print out all of the wallet key-value records");
    argsman.AddCommand("createfromdump", "Create new wallet file from dumped records");

    // Particl
    argsman.AddCommand("generatemnemonic", "Generate a new mnemonic: <language> <bytes_entropy>");
    argsman.AddCommand("mpbf", "Mnemonic password brute forcer");
    argsman.AddArg("-btcmode", "", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-targetaddress=<address>", "Target address for mpbf", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-targetpubkey=<pubkey>", "Target pubkey for mpbf", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-testnumderives=<n>", "Number of addresses to derive for each test (default: 50)", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-insertchars=<str>", "Characters to insert into the password", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-passwordistemplate", "Password is in template format (default: false).", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-modifycase", "Test all case variations (default: true).", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-mininsertchars=<n>", "Minimum number of charcters to insert into password (default: 1).", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-maxinsertchars=<n>", "Maximum number of charcters to insert into password (default: 2).", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-dropchars=<n>", "Maximum number of charcters to drop from password (default: 0).", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-replacechars=<bool>", "Replace chars in the input password with insertchars (default: true).", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-startat=<n>", "Base password offset to start from (default: 0).", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-insertfrom=<n>", "Insert chars from offset (default: 0).", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
}

static std::optional<int> WalletAppInit(ArgsManager& args, int argc, char* argv[])
{
    SetupWalletToolArgs(args);
    std::string error_message;
    if (!args.ParseParameters(argc, argv, error_message)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error_message);
        return EXIT_FAILURE;
    }
    const bool missing_args{argc < 2};
    if (missing_args || HelpRequested(args) || args.IsArgSet("-version")) {
        std::string strUsage = strprintf("%s particl-wallet version", PACKAGE_NAME) + " " + FormatFullVersion() + "\n";

        if (args.IsArgSet("-version")) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                        "particl-wallet is an offline tool for creating and interacting with " PACKAGE_NAME " wallet files.\n"
                        "By default particl-wallet will act on wallets in the default mainnet wallet directory in the datadir.\n"
                        "To change the target wallet, use the -datadir, -wallet and -regtest/-signet/-testnet arguments.\n\n"
                        "Usage:\n"
                        "  particl-wallet [options] <command>\n";
            strUsage += "\n" + args.GetHelpMessage();
        }
        tfm::format(std::cout, "%s", strUsage);
        if (missing_args) {
            tfm::format(std::cerr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    fParticlMode = !gArgs.GetBoolArg("-btcmode", false); // qa tests

    // check for printtoconsole, allow -debug
    LogInstance().m_print_to_console = args.GetBoolArg("-printtoconsole", args.GetBoolArg("-debug", false));

    if (!CheckDataDirOption(args)) {
        tfm::format(std::cerr, "Error: Specified data directory \"%s\" does not exist.\n", args.GetArg("-datadir", ""));
        return EXIT_FAILURE;
    }
    // Check for chain settings (Params() calls are only valid after this clause)
    SelectParams(args.GetChainType());
    if (!fParticlMode) {
        WITNESS_SCALE_FACTOR = WITNESS_SCALE_FACTOR_BTC;
        if (args.GetChainType() == ChainType::REGTEST) {
            ResetParams(ChainType::REGTEST, fParticlMode);
        }
    }

    return std::nullopt;
}

class PasswordCharacter {
public:
    PasswordCharacter(size_t index): m_index(index) {};
    PasswordCharacter(size_t index, bool actual, char value): m_index(index), m_actual(actual), m_value(value) {
        m_can_switch_case = (m_value >= 'a' && m_value <= 'z') || (m_value >= 'A' && m_value <= 'Z');
    }

    size_t m_index;
    bool m_actual{false};
    char m_value{'*'};
    char m_current_value{0};
    bool m_can_switch_case{false};
};

class PasswordFinderState {
public:
    PasswordFinderState(ArgsManager &args): m_args(args) {
        m_print_to_console = m_args.GetBoolArg("-printtoconsole", false);
        m_modify_case = m_args.GetBoolArg("-modifycase", true);
        m_replace_chars = m_args.GetBoolArg("-replacechars", true);
        m_test_num_derives = m_args.GetIntArg("-testnumderives", 50);
        m_min_inserts = m_args.GetIntArg("-mininsertchars", 1);
        m_max_inserts = m_args.GetIntArg("-maxinsertchars", 2);
        m_num_drop_chars = m_args.GetIntArg("-dropchars", 0);
        m_start_at = m_args.GetIntArg("-startat", 0);
        m_bip44_id = (uint32_t)Params().BIP44ID();
        m_insert_from = m_args.GetIntArg("-insertfrom", 0);
    };
    ArgsManager &m_args;
    std::string m_mnemonic;
    std::string m_insert_chars;
    size_t m_num_tests{0};
    size_t m_num_drop_chars{0};
    std::atomic<bool> m_found_password{false};
    bool m_print_to_console{false};
    bool m_modify_case{true};
    size_t m_test_num_derives{10};
    CKeyID m_id_find;
    size_t m_min_inserts{1};
    size_t m_max_inserts{2};
    uint32_t m_bip44_id;
    bool m_eth_mode{false};
    bool m_replace_chars{false};
    uint64_t m_start_at{0};
    bool m_pubkey_set{false};
    CPubKey m_target_pubkey;
    uint32_t m_insert_from{0};
};

bool test_password(PasswordFinderState &pfs, const std::string &password_iteration)
{
    pfs.m_num_tests++;

    if (pfs.m_num_tests % 1000 == 0) {
        print_ts(tfm::format("Passwords tried: %d", pfs.m_num_tests));
    }

    if (pfs.m_print_to_console) {
        print_ts(tfm::format("\"%s\"", password_iteration));
        //tfm::format(std::cout, "t: %d - \"%s\"\n", std::this_thread::get_id(), password_iteration);
    }
    std::vector<uint8_t> seed;
    // purpose'/coin_type'/account'/chain/nkey
    std::vector<uint32_t> bip44_account_chain_path {WithHardenedBit(44), pfs.m_bip44_id, WithHardenedBit(0), 0};
    if (0 != mnemonic::ToSeed(pfs.m_mnemonic, password_iteration, seed)) {
        tfm::format(std::cerr, "Error: mnemonic::ToSeed failed.\n");
        return false;
    }
    CExtKeyPair ekp;
    ekp.SetSeed(seed.data(), seed.size());

    CExtKey vkOut, vkWork = ekp.GetExtKey();
    for (auto chain_node : bip44_account_chain_path) {
        if (!vkWork.Derive(vkOut, chain_node)) {
            tfm::format(std::cerr, "Error: CExtKey Derive failed.\n");
            return false;
        }
        vkWork = vkOut;
    }

    CExtPubKey epk_test, epk_chain = vkWork.Neutered();
    for (size_t i = 0; i < pfs.m_test_num_derives; i++) {
        if (!epk_chain.Derive(epk_test, i)) {
            tfm::format(std::cerr, "Error: epk_chain.Derive failed: %d.\n", i);
            return false;
        }
        bool found{false};
        if (pfs.m_pubkey_set){
            found = epk_test.pubkey == pfs.m_target_pubkey;
        } else {
            CKeyID id_test;
            if (pfs.m_eth_mode) {
                SHA3_256 sha;
                unsigned char out[SHA3_256::OUTPUT_SIZE];
                CPubKey pk = epk_test.pubkey;
                pk.Decompress();
                std::vector<uint8_t> data64(pk.begin() + 1, pk.end());
                sha.Write(data64).Finalize_keccak256(out);
                memcpy(id_test.data(), out + 12, 20);
            } else {
                id_test = epk_test.pubkey.GetID();
            }
            found = id_test == pfs.m_id_find;
        }

        if (found) {
            pfs.m_found_password = true;
            if (password_iteration.empty()) {
                print_ts(tfm::format("Found without password, key number %d", i));
            } else {
                print_ts(tfm::format("Found password: %s, key number %d", password_iteration, i));
            }
            return true;
        }
    }

    return false;
}

class ThreadPool {
public:
    ThreadPool(PasswordFinderState &pfs, size_t num_threads = std::thread::hardware_concurrency()) : m_pfs(pfs)
    {
        for (size_t i = 0; i < num_threads; ++i) {
            m_threads.emplace_back([this] {
                while (true) {
                    std::string task;
                    {
                        std::unique_lock<std::mutex> lock(m_queue_mutex);

                        m_cv.wait(lock, [this] {
                            return !m_tasks.empty() || m_stop;
                        });

                        if (m_stop && m_tasks.empty()) {
                            return;
                        }

                        //if (m_pfs.m_found_password) {
                            //return;
                        //}

                        task = std::move(m_tasks.front());
                        m_tasks.pop();
                    }
                    m_cv_not_full.notify_one();

                    if (!m_pfs.m_found_password && test_password(m_pfs, task)) {
                        m_stop = true;
                        m_cv.notify_all();
                    }
                }
            });
        }
    }

    ~ThreadPool()
    {
        stop();
    }

    void stop()
    {
        m_stop = true;

        m_cv.notify_all();

        for (auto &t : m_threads) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

    bool enqueue(const std::string &task)
    {
        if (m_pfs.m_found_password) {
            return true;
        }

        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            m_cv_not_full.wait(lock, [this]{ return m_tasks.size() < m_max_tasks_size; });
            //m_tasks.emplace(std::move(task));
            m_tasks.push(task);
        }
        m_cv.notify_one();

        return false;
    }

public:
    PasswordFinderState &m_pfs;
private:
    std::vector<std::thread> m_threads;

    std::queue<std::string> m_tasks;

    size_t m_max_tasks_size{1000};
    std::mutex m_queue_mutex;

    std::condition_variable m_cv;
    std::condition_variable m_cv_not_full;

    std::atomic<bool> m_stop{false};
};

bool try_inserts(ThreadPool &pool, std::string test_string, size_t c_depth, size_t max_depth)
{
    if (c_depth > max_depth) {
        return false;
    }
    if (pool.m_pfs.m_found_password) {
        return true;
    }

    std::vector<std::string> v_found[2];
    v_found[0].push_back(test_string);
    for (size_t i = 0; i < max_depth; ++i) {
        v_found[(i+1) % 2].clear();
        std::set<std::string> set_found;
        for (const auto &c_string : v_found[i % 2]) {
            for (char insert_c : pool.m_pfs.m_insert_chars) {
                for (size_t insert_i = pool.m_pfs.m_insert_from; insert_i <= c_string.size(); insert_i++) {
                    if (pool.m_pfs.m_found_password) {
                        return true;
                    }
                    std::string password_iteration = c_string;
                    password_iteration.insert(insert_i, 1, insert_c);

                    if (set_found.find(password_iteration) != set_found.end()) {
                        continue;
                    }
                    if (i >= pool.m_pfs.m_min_inserts - 1) {
                        pool.enqueue(password_iteration);
                    }
                    set_found.insert(password_iteration);
                    v_found[(i+1) % 2].push_back(password_iteration);
                }
            }
        }
    }

    /*
    for (char insert_c : pool.m_pfs.m_insert_chars) {
        // Replace
        if (pool.m_pfs.m_replace_chars) {
            for (size_t replace_i = 0; replace_i < test_string.size(); replace_i++) {
                std::string password_iteration = test_string;
                password_iteration[replace_i] = insert_c;
                pool.enqueue(password_iteration);
                if (c_depth < max_depth) {
                    if (try_inserts(pool, password_iteration, c_depth + 1, max_depth)) {
                        return true;
                    }
                }
            }
        }

        // Insert
        for (size_t insert_i = 0; insert_i <= test_string.size(); insert_i++) {
            std::string password_iteration = test_string;
            password_iteration.insert(insert_i, 1, insert_c);
            if (c_depth >= pool.m_pfs.m_min_inserts) {
                pool.enqueue(password_iteration);
            }
            if (c_depth < max_depth) {
                if (try_inserts(pool, password_iteration, c_depth + 1, max_depth)) {
                    return true;
                }
            }
        }
    }
    */
    return false;
}

static int64_t ipow(int64_t base, int exp)
{
    int64_t result = 1;
    while (exp) {
        if (exp & 1) {
            result *= base;
        }
        exp >>= 1;
        base *= base;
    }
    return result;
}

int mpbf(ArgsManager& args)
{
    PasswordFinderState pfs(args);
    std::string password_template_in, target_address, errmsg;
    std::vector<uint8_t> entropy;

    tfm::format(std::cout, "Enter mnemonic:\n");
    std::getline(std::cin, pfs.m_mnemonic);
    tfm::format(std::cout, "mnemonic: %s\n", pfs.m_mnemonic);

    int language_ind = -1;
    if (0 != mnemonic::Decode(language_ind, pfs.m_mnemonic, entropy, errmsg)) {
        tfm::format(std::cerr, "Error: Invalid mnemonic: %s.\n", errmsg);
        return EXIT_FAILURE;
    }

    // password template: 1as,2vn,11a,.
    // char num, actual / variable, char / *-any char, a-alpha any_case, c-lowercase alpha, C-uppercase alpha, n-numeric, s-special
    tfm::format(std::cout, "Enter password%s:\n", args.IsArgSet("-passwordistemplate") ? " template" : "");
    std::getline(std::cin, password_template_in);
    tfm::format(std::cout, "password_template: %s\n", password_template_in);

    std::vector<PasswordCharacter> password_template;
    size_t i = 0;

    if (!args.IsArgSet("-passwordistemplate")) {
        for (size_t i = 0; i < password_template_in.size(); i++) {
            char c = password_template_in[i];
            password_template.emplace_back(i, true, c);
        }
    } else
    while (i < password_template_in.size()) {
        char c = password_template_in[i];
        std::string word_index_s;
        if (c == ',') {
            i++;
            continue;
        }
        while (IsDigit(c)) {
            word_index_s += c;
            i++;
            if (i >= password_template_in.size()) {
                tfm::format(std::cerr, "Error: Invalid password_template.\n");
                return EXIT_FAILURE;
            }
            c = password_template_in[i];
        }
        uint32_t word_index{0};
        if (word_index_s.size() < 1 || !ParseUInt32(word_index_s, &word_index)) {
            tfm::format(std::cerr, "Error: Invalid password_template, invalid word index.\n");
            return EXIT_FAILURE;
        }

        bool actual{false};
        if (c == 'a') {
            actual = true;
        } else if (c == 'v') {
        } else {
            tfm::format(std::cerr, "Error: Invalid password_template, unknown actual/variable indicator.\n");
            return EXIT_FAILURE;
        }

        i++;
        if (i >= password_template_in.size()) {
            tfm::format(std::cerr, "Error: Invalid password_template.\n");
            return EXIT_FAILURE;
        }
        c = password_template_in[i];

        if (!actual) {
            std::string possible_values{"*CAaLlds"};
            if (possible_values.find(c) == std::string::npos) {
                tfm::format(std::cerr, "Error: Invalid password_template, unknown variable type.\n");
                return EXIT_FAILURE;
            }
        }

        if (!password_template.empty()) {
            const auto &last_entry = password_template.back();
            if (word_index <= last_entry.m_index) {
                tfm::format(std::cerr, "Error: Invalid password_template, word index must be > last index.\n");
                return EXIT_FAILURE;
            }

            for (size_t expand_i = last_entry.m_index + 1; expand_i < word_index; expand_i++) {
                password_template.emplace_back(expand_i);
            }
        }

        password_template.emplace_back(word_index, actual, c);
        i++;
    }
    /*
    for (const auto &ct : password_template) {
        tfm::format(std::cerr, "ct %d %d %c.\n", ct.m_index, ct.m_actual, ct.m_value);
    }
    */

    if (gArgs.IsArgSet("-insertchars")) {
        pfs.m_insert_chars = gArgs.GetArg("-insertchars", "");
    } else {
        tfm::format(std::cout, "Enter insert chars, leave blank to default to all ascii chars:\n");
        std::getline(std::cin, pfs.m_insert_chars);
    }
    if (pfs.m_insert_chars.size() == 0) {
        pfs.m_insert_chars = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    }
    tfm::format(std::cout, "insert_chars: %s\n", pfs.m_insert_chars);


    if (gArgs.IsArgSet("-targetpubkey")) {
        if (gArgs.IsArgSet("-targetaddress")) {
            tfm::format(std::cerr, "Error: targetaddress and targetpubkey both set.\n");
            return EXIT_FAILURE;
        }
        std::string target_pubkey = gArgs.GetArg("-targetpubkey", "");
        pfs.m_pubkey_set = true;
        std::vector<uint8_t> v = ParseHex(target_pubkey);
        if (v.size() != 33) {
            tfm::format(std::cerr, "Error: Invalid pubkey size.\n");
            return EXIT_FAILURE;
        }
        pfs.m_target_pubkey = CPubKey(v.begin(), v.end());
    } else
    if (gArgs.IsArgSet("-targetaddress")) {
        target_address = gArgs.GetArg("-targetaddress", "");
    } else {
        tfm::format(std::cout, "Enter target address:\n");
        std::getline(std::cin, target_address);
    }

    if (pfs.m_pubkey_set) {
        tfm::format(std::cout, "target_pubkey: %s\n", HexStr(pfs.m_target_pubkey));
    } else {
        tfm::format(std::cout, "target_address: %s\n", target_address);
        if (target_address.size() == 42 && target_address.starts_with("0x")) {
            // eth address
            std::vector<uint8_t> id_data = ParseHex(target_address.substr(2));
            if (id_data.size() != 20) {
                tfm::format(std::cerr, "Error: Invalid target eth address.\n");
                return EXIT_FAILURE;
            }

            std::string str_data = target_address.substr(2);
            memcpy(pfs.m_id_find.data(), id_data.data(), id_data.size());
            pfs.m_bip44_id = WithHardenedBit(60);
            pfs.m_eth_mode = true;
        } else {
            CTxDestination dest = DecodeDestination(target_address);
            if (!IsValidDestination(dest)) {
                tfm::format(std::cerr, "Error: Invalid target address.\n");
                return EXIT_FAILURE;
            }
            if (!std::holds_alternative<PKHash>(dest)) {
                tfm::format(std::cerr, "Error: target address must be a legacy address.\n");
                return EXIT_FAILURE;
            }
            pfs.m_id_find = ToKeyID(std::get<PKHash>(dest));
        }
    }

    auto start = std::chrono::high_resolution_clock::now();

    uint64_t max_combinations{1};
    for (const auto &ct : password_template) {
        if (ct.m_actual) {
            max_combinations *= 1;
            continue;
        }
        std::string *ps{nullptr};
        if (!get_char_options(&ps, ct.m_value)) {
            tfm::format(std::cerr, "Error: Unknown char template option %c.\n", ct.m_value);
            return EXIT_FAILURE;
        }
        max_combinations *= ps->size();
    }

    tfm::format(std::cout, "Trying %d base password combination%s.\n", max_combinations, max_combinations == 1 ? "" : "s");
    tfm::format(std::cout, "Starting from %d (-startat).\n", pfs.m_start_at);

    // Try empty password
    std::string empty_pwd;
    test_password(pfs, empty_pwd);

    ThreadPool pool(pfs);
    for (uint64_t ti = pfs.m_start_at; ti < max_combinations; ti++) {

        if (ti && ti % 1000 == 0) {
            print_ts(tfm::format("Base password offset %d.", ti));
        }
        if (pfs.m_found_password) {
            break;
        }
        std::string password_try;
        uint64_t ci = ti;
        for (const auto &ct : password_template) {
            if (ct.m_actual) {
                max_combinations *= 1;
                password_try += ct.m_value;
                continue;
            }
            std::string *ps{nullptr};
            if (!get_char_options(&ps, ct.m_value)) {
                tfm::format(std::cerr, "Error: Unknown char template option %c.\n", ct.m_value);
                return EXIT_FAILURE;
            }
            password_try += (*ps)[ci % ps->size()];
            ci /= ps->size();
        }

        std::set<std::string> try_passwords;
        try_passwords.insert(password_try);

        std::function<void(std::string, size_t, size_t)> drop_chars = [&](std::string string_work, size_t c_depth, size_t max_depth) -> void {
            if (string_work.size() <= 1) {
                return;
            }
            for (size_t i = 0; i < string_work.size(); i++) {
                std::string string_next = string_work;
                string_next.erase(i, 1);
                try_passwords.insert(string_next);
                if (c_depth < max_depth) {
                    drop_chars(string_next, c_depth + 1, max_depth);
                }
            }
        };
        if (pfs.m_num_drop_chars) {
            std::string lc_password;
            for (auto c : password_try) {
                lc_password += ToLower(c);
            }
            drop_chars(lc_password, 1, 2);
        }
        /*
        // Try password as entered first
        if (!test_password(pfs, password_try)) {
            try_inserts(pool, password_try, 1, pfs.m_max_inserts);
        }
        */

        for (const auto &c_pwd_try : try_passwords) {
            if (pfs.m_found_password) {
                break;
            }
            std::vector<size_t> case_changeable_chars;
            if (pfs.m_modify_case)
            for (size_t ic = 0; ic < c_pwd_try.size(); ic++) {
                char c = c_pwd_try[ic];
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                    case_changeable_chars.push_back(ic);
                }
            }

            if (case_changeable_chars.size()) {
                size_t nc = case_changeable_chars.size();
                size_t max_case_combinations = ipow(2, nc);
                print_ts(tfm::format("Trying %d case combinations.", max_case_combinations));
                for (size_t icc = 0; icc < max_case_combinations; icc++) {
                    std::string password_current = c_pwd_try;
                    for (size_t ic = 0; ic < case_changeable_chars.size(); ic++) {
                        bool upper_case = (icc & (1 << ic)) != 0;
                        char c = password_current[case_changeable_chars[ic]];
                        password_current[case_changeable_chars[ic]] = upper_case ? ToUpper(c) : ToLower(c);
                    }
                    // if (password_current == password_try) {
                    //     continue;
                    // }

                    //print_ts(tfm::format("password_current %s", password_current));
                    if (pool.enqueue(password_current)) {
                        break;
                    }
                    if (try_inserts(pool, password_current, 1, pfs.m_max_inserts)) {
                        break;
                    }
                }
            } else {
                //print_ts(tfm::format("c_pwd_try %s", c_pwd_try));
                if (pool.enqueue(c_pwd_try)) {
                    break;
                }
                if (try_inserts(pool, c_pwd_try, 1, pfs.m_max_inserts)) {
                    break;
                }
            }
        }
    }

    std::chrono::duration<double> elapsed = std::chrono::high_resolution_clock::now() - start;

    pool.stop();

    tfm::format(std::cout, "Tried: %d combinations in %d seconds\n", pfs.m_num_tests, elapsed.count());

    if (pfs.m_found_password) {
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
#ifdef WIN32
    common::WinCmdLineArgs winArgs;
    std::tie(argc, argv) = winArgs.get();
#endif

    int exit_status;
    std::unique_ptr<interfaces::Init> init = interfaces::MakeWalletInit(argc, argv, exit_status);
    if (!init) {
        return exit_status;
    }

    SetupEnvironment();
    RandomInit();


    bool show_help = false;
    for (int i = 1; i < argc; ++i) {
        if (IsSwitchChar(argv[i][0])) {
            char *p = argv[i];
            while (*p == '-') p++;
            if (strcmp(p, "?") == 0 || strcmp(p, "h") == 0 || strcmp(p, "help") == 0) {
                show_help = true;
            }
            continue;
        }
    }


    try {
        if (const auto maybe_exit{WalletAppInit(args, argc, argv)}) return *maybe_exit;
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "WalletAppInit()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "WalletAppInit()");
        return EXIT_FAILURE;
    }

    const auto command = args.GetCommand();
    if (!command) {
        tfm::format(std::cerr, "No method provided. Run `particl-wallet -help` for valid methods.\n");
        return EXIT_FAILURE;
    }

    ECC_Start();

    if (command->command == "generatemnemonic") {
        if (show_help) {
            std::string usage = "generatemnemonic <language> <bytes_entropy>\n"
                "\nArguments:\n"
                "1. language        (string, optional, default=english) Which wordlist to use (" + mnemonic::ListEnabledLanguages(", ") + ").\n"
                "2. bytes_entropy   (numeric, optional, default=32) Affects length of mnemonic, [16, 64].\n";
            tfm::format(std::cout, "%s\n", usage);
            return EXIT_SUCCESS;
        }

        int nLanguage = mnemonic::WLL_ENGLISH;
        int nBytesEntropy = 32;

        if (command->args.size() >= 1) {
            nLanguage = mnemonic::GetLanguageOffset(command->args[1]);
        }
        if (command->args.size() >= 2) {
            if (!ParseInt32(command->args[2], &nBytesEntropy)) {
                tfm::format(std::cerr, "Error: Invalid num bytes entropy.\n");
                return EXIT_FAILURE;
            }
            if (nBytesEntropy < 16 || nBytesEntropy > 64) {
                tfm::format(std::cerr, "Error: Num bytes entropy out of range [16,64].\n");
                return EXIT_FAILURE;
            }
        }
        std::string sMnemonic, sError;
        std::vector<uint8_t> vEntropy(nBytesEntropy);

        GetStrongRandBytes2(&vEntropy[0], nBytesEntropy);
        if (0 != mnemonic::Encode(nLanguage, vEntropy, sMnemonic, sError)) {
            tfm::format(std::cerr, "Error: MnemonicEncode failed %s.\n", sError);
            return EXIT_FAILURE;
        }

        tfm::format(std::cout, "%s\n", sMnemonic);
        return EXIT_SUCCESS;
    } else if (command->command == "mpbf") {
        return mpbf(args);
    }

    if (command->args.size() != 0) {
        tfm::format(std::cerr, "Error: Additional arguments provided (%s). Methods do not take arguments. Please refer to `-help`.\n", Join(command->args, ", "));
        return EXIT_FAILURE;
    }

    if (!wallet::WalletTool::ExecuteWalletToolFunc(args, command->command)) {
        return EXIT_FAILURE;
    }
    ECC_Stop();
    return EXIT_SUCCESS;
}
