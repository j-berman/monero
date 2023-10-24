// Copyright (c) 2014-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <boost/range/adaptor/transformed.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/filesystem/operations.hpp>
#include <thread>
#include "common/command_line.h"
#include "common/varint.h"
#include "cryptonote_basic/subaddress_index.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/blockchain.h"
#include "async/threadpool.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/enote_store_utils.h"
#include "seraphis_impl/scan_context_simple.h"
#include "seraphis_impl/scan_process_basic.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_mocks/scan_chunk_consumer_mocks.h"
#include "seraphis_mocks/scan_context_async_mock.h"
#include "seraphis_mocks/enote_finding_context_mocks.h"
#include "seraphis_mocks/mock_http_client_pool.h"
#include "seraphis_mocks/mock_http_client_pool_curl.h"
#include "version.h"
#include <algorithm>
#include <stdio.h>

// wallet2 dependencies
#include "wallet/wallet2.h"
#include "wipeable_string.h"
#include "common/scoped_message_writer.h"
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bcutil"

const std::string DEFAULT_WALLET_FILE = "monero_blockchain_scanner_test_wallet_file";

const std::uint64_t DEFAULT_LOOP_COUNT = 5;

namespace po = boost::program_options;
using namespace epee;
using namespace cryptonote;

class Wallet2Callback : public tools::i_wallet2_callback
{
    public:
        Wallet2Callback(tools::wallet2 &wallet2, std::chrono::milliseconds &scanner_duration) :
            m_refresh_progress_reporter(wallet2),
            m_scanner_duration(scanner_duration)
        {
        }

        virtual void on_new_block(uint64_t height, const cryptonote::block& block)
        {
            m_refresh_progress_reporter.update(height);
        }

        virtual void on_scanner_complete(std::chrono::milliseconds duration)
        {
            m_scanner_duration = duration;
        }

    private:
        friend class refresh_progress_reporter_t;

        class refresh_progress_reporter_t
        {
            public:
                refresh_progress_reporter_t(tools::wallet2 &wallet2)
                    : m_wallet2(wallet2)
                    , m_blockchain_height(0)
                    , m_blockchain_height_update_time()
                    , m_print_time()
                {
                }

            void update(uint64_t height, bool force = false)
            {
                auto current_time = std::chrono::system_clock::now();
                const auto node_update_threshold = std::chrono::seconds(DIFFICULTY_TARGET_V1 / 2); // use min of V1/V2
                if (node_update_threshold < current_time - m_blockchain_height_update_time || m_blockchain_height <= height)
                {
                    update_blockchain_height();
                    m_blockchain_height = (std::max)(m_blockchain_height, height);
                }

                if (std::chrono::milliseconds(20) < current_time - m_print_time || force)
                {
                    std::cout << QT_TRANSLATE_NOOP("blockchain_scanner", "Height ") << height << " / " << m_blockchain_height << '\r' << std::flush;
                    m_print_time = current_time;
                }
            }

            private:
                void update_blockchain_height()
                {
                    std::string err;
                    uint64_t blockchain_height = m_wallet2.get_daemon_blockchain_height(err);
                    if (err.empty())
                    {
                        m_blockchain_height = blockchain_height;
                        m_blockchain_height_update_time = std::chrono::system_clock::now();
                    }
                    else
                    {
                        LOG_ERROR("Failed to get current blockchain height: " << err);
                    }
                }

            private:
                tools::wallet2 &m_wallet2;
                uint64_t m_blockchain_height;
                std::chrono::system_clock::time_point m_blockchain_height_update_time;
                std::chrono::system_clock::time_point m_print_time;
        };

    private:
        refresh_progress_reporter_t m_refresh_progress_reporter;
        std::chrono::milliseconds &m_scanner_duration;
};

void add_default_subaddresses(
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map)
{
    const uint32_t SUBADDR_MAJOR_DEFAULT_LOOKAHEAD = 50;
    const uint32_t SUBADDR_MINOR_DEFAULT_LOOKAHEAD = 200;

    for (uint32_t i = 0; i < SUBADDR_MAJOR_DEFAULT_LOOKAHEAD; ++i)
    {
        for (uint32_t j = 0; j < SUBADDR_MINOR_DEFAULT_LOOKAHEAD; ++j)
        {
            const cryptonote::subaddress_index subaddr_index{i, j};

            rct::key legacy_subaddress_spendkey;
            sp::make_legacy_subaddress_spendkey(
                legacy_base_spend_pubkey,
                legacy_view_privkey,
                subaddr_index,
                hw::get_device("default"),
                legacy_subaddress_spendkey);

            legacy_subaddress_map[legacy_subaddress_spendkey] = subaddr_index;
        }
    }
};

std::chrono::milliseconds scan_chain(const uint64_t start_height, const std::string &legacy_spend_privkey_str, const std::string &legacy_view_privkey_str,
    const std::string daemon_address, const boost::optional<epee::net_utils::http::login> daemon_login, const epee::net_utils::ssl_options_t ssl_support, const bool use_curl = false)
{
    // load keys
    /// spend key
    crypto::secret_key legacy_spend_privkey;
    crypto::public_key legacy_base_spend_pubkey_t;
    rct::key legacy_base_spend_pubkey;
    epee::string_tools::hex_to_pod(legacy_spend_privkey_str, legacy_spend_privkey);
    crypto::secret_key_to_public_key(legacy_spend_privkey, legacy_base_spend_pubkey_t);
    legacy_base_spend_pubkey = rct::pk2rct(legacy_base_spend_pubkey_t);
    /// view key
    crypto::secret_key legacy_view_privkey;
    epee::string_tools::hex_to_pod(legacy_view_privkey_str, legacy_view_privkey);

    const sp::scanning::ScanMachineConfig scan_config{
        .reorg_avoidance_increment = 1,
        .max_chunk_size_hint = 1000,
        .max_partialscan_attempts = 0};

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map{};
    add_default_subaddresses(legacy_base_spend_pubkey, legacy_view_privkey, legacy_subaddress_map);

    sp::mocks::CurlConnectionPool curl_pool{daemon_address, daemon_login, ssl_support};
    sp::mocks::ClientConnectionPool conn_pool{daemon_address, daemon_login, ssl_support};

    {
        // Make sure daemon RPC version matches
        // TODO: return version info in /getblocks.bin
        cryptonote::COMMAND_RPC_GET_VERSION::request req_t = AUTO_VAL_INIT(req_t);
        cryptonote::COMMAND_RPC_GET_VERSION::response resp_t = AUTO_VAL_INIT(resp_t);
        bool r = use_curl
            ? curl_pool.rpc_command<cryptonote::COMMAND_RPC_GET_VERSION>(sp::mocks::CurlConnectionPool::invoke_http_mode::JON_RPC, "get_version", req_t, resp_t)
            : conn_pool.rpc_command<cryptonote::COMMAND_RPC_GET_VERSION>(sp::mocks::ClientConnectionPool::invoke_http_mode::JON_RPC, "get_version", req_t, resp_t);
        CHECK_AND_ASSERT_THROW_MES(r && resp_t.status == CORE_RPC_STATUS_OK, "failed /get_version");
        CHECK_AND_ASSERT_THROW_MES(resp_t.version >= MAKE_CORE_RPC_VERSION(CORE_RPC_VERSION_MAJOR, CORE_RPC_VERSION_MINOR),
            "unexpected daemon version (must be running an updated daemon for accurate benchmarks)");
    }

    const std::function<bool(const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request&, cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response&)> rpc_get_blocks =
        [&curl_pool, &conn_pool, use_curl](const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request &req, cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res)
            {
                LOG_PRINT_L0("Querying for onchain chunk (req.start_height=" << req.start_height << ")");
                // TODO: retry logic
                bool r = use_curl
                    ? curl_pool.rpc_command<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST>(sp::mocks::CurlConnectionPool::invoke_http_mode::BIN, "/getblocks.bin", req, res)
                    : conn_pool.rpc_command<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST>(sp::mocks::ClientConnectionPool::invoke_http_mode::BIN, "/getblocks.bin", req, res);
                if (r)
                {
                    LOG_PRINT_L0("Successfully queried for onchain chunk (req.start_height=" << req.start_height
                            << ", res.current_height=" << res.current_height << ", blocks=" << res.blocks.size() << ")");
                    return true;
                }
                else
                {
                    LOG_ERROR("Failed to /getblocks.bin at block index " << req.start_height);
                    return false;
                }
            };

    sp::mocks::EnoteFindingContextMockLegacy enote_finding_context{
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        rpc_get_blocks};

    const uint64_t pending_chunk_queue_size = std::min((std::uint64_t)(std::thread::hardware_concurrency() + 2), static_cast<std::uint64_t>(10));
    LOG_PRINT_L0("Pending chunk queue size: " << pending_chunk_queue_size);

    sp::scanning::mocks::AsyncScanContext scan_context_ledger{
        pending_chunk_queue_size, // TODO: stick this in scan conifg
        scan_config.max_chunk_size_hint,
        enote_finding_context};

    sp::SpEnoteStore user_enote_store{start_height == 0 ? 1 : start_height, 3000000, 10};
    sp::mocks::ChunkConsumerMockLegacy chunk_consumer{
        legacy_base_spend_pubkey,
        legacy_spend_privkey,
        legacy_view_privkey,
        user_enote_store};

    sp::scanning::ScanContextNonLedgerDummy scan_context_nonledger{};

    LOG_PRINT_L0("Scanning using the updated Seraphis lib...");
    auto start = std::chrono::high_resolution_clock::now();

    if (!sp::refresh_enote_store(scan_config,
        scan_context_nonledger,
        scan_context_ledger,
        chunk_consumer))
    {
        throw std::runtime_error("Failed to refresh enote store");
    };

    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);

    return duration;
    // return sp::get_balance(user_enote_store,
    //       {sp::SpEnoteOriginStatus::ONCHAIN, sp::SpEnoteOriginStatus::UNCONFIRMED},
    //       {sp::SpEnoteSpentStatus::SPENT_ONCHAIN, sp::SpEnoteSpentStatus::SPENT_UNCONFIRMED}).str();
}

int main(int argc, char* argv[])
{
    TRY_ENTRY();

    epee::string_tools::set_module_name_and_folder(argv[0]);

    uint32_t log_level = 0;

    tools::on_startup();

    boost::filesystem::path output_file_path;

    po::options_description desc_cmd_only("Command line options");
    po::options_description desc_cmd_sett("Command line options and settings options");
    const command_line::arg_descriptor<std::string> arg_log_level  = {"log-level",  "0-4 or categories", ""};
    const command_line::arg_descriptor<std::string> arg_daemon_address  = {"daemon-address",  "Use daemon instance at <host>:<port>", ""};
    const command_line::arg_descriptor<std::uint64_t> arg_start_height  = {"start-height", "Scan from height", 0};
    const command_line::arg_descriptor<std::uint64_t> arg_loop_count  = {"loop-count",  "Attempt to scan this many times", DEFAULT_LOOP_COUNT};

    command_line::add_arg(desc_cmd_sett, cryptonote::arg_testnet_on);
    command_line::add_arg(desc_cmd_sett, cryptonote::arg_stagenet_on);
    command_line::add_arg(desc_cmd_sett, arg_log_level);
    command_line::add_arg(desc_cmd_sett, arg_daemon_address);
    command_line::add_arg(desc_cmd_sett, arg_start_height);
    command_line::add_arg(desc_cmd_sett, arg_loop_count);
    command_line::add_arg(desc_cmd_only, command_line::arg_help);

    po::options_description desc_options("Allowed options");
    desc_options.add(desc_cmd_only).add(desc_cmd_sett);

    po::variables_map vm;
    bool r = command_line::handle_error_helper(desc_options, [&]()
    {
        auto parser = po::command_line_parser(argc, argv).options(desc_options);
        po::store(parser.run(), vm);
        po::notify(vm);
        return true;
    });
    if (!r)
        return 1;

    if (command_line::get_arg(vm, command_line::arg_help))
    {
        std::cout << "Monero '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
        std::cout << desc_options << std::endl;
        return 1;
    }

    mlog_configure(mlog_get_default_log_path("monero-blockchain-scanner.log"), true);
    if (!command_line::is_arg_defaulted(vm, arg_log_level))
        mlog_set_log(command_line::get_arg(vm, arg_log_level).c_str());
    else
        mlog_set_log(std::string(std::to_string(log_level) + ",bcutil:INFO").c_str());

    std::string daemon_address;
    if (command_line::is_arg_defaulted(vm, arg_daemon_address))
        throw std::runtime_error("Missing daemon address");
    else
        daemon_address = command_line::get_arg(vm, arg_daemon_address);

    std::uint64_t start_height = 0;
    if (!command_line::is_arg_defaulted(vm, arg_start_height))
        start_height = command_line::get_arg(vm, arg_start_height);

    if (boost::filesystem::exists(DEFAULT_WALLET_FILE))
    {
        std::remove(DEFAULT_WALLET_FILE.c_str());
        std::remove((DEFAULT_WALLET_FILE + ".keys").c_str());
    }

    std::uint64_t loop_count = DEFAULT_LOOP_COUNT;
    if (!command_line::is_arg_defaulted(vm, arg_loop_count))
        loop_count = command_line::get_arg(vm, arg_loop_count);
    if (loop_count == 0)
        loop_count = DEFAULT_LOOP_COUNT;

    LOG_PRINT_L0("Starting... (loop_count=" << loop_count << ")");

    bool opt_testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
    bool opt_stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
    network_type net_type = opt_testnet ? TESTNET : opt_stagenet ? STAGENET : MAINNET;

    // TODO: allow user to securely input seed manually (make sure I password protect the file wallet2 generates)
    const std::string mnemonic = "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly";
    const std::string priv_spend_key = "b0ef6bd527b9b23b9ceef70dc8b4cd1ee83ca14541964e764ad23f5151204f0f";
    const std::string pub_spend_key = "7d996b0f2db6dbb5f2a086211f2399a4a7479b2c911af307fdc3f7f61a88cb0e";
    const std::string priv_view_key = "42ba20adb337e5eca797565be11c9adb0a8bef8c830bccc2df712535d3b8f608";

    std::vector<std::chrono::milliseconds> seraphis_lib_results;
    std::vector<std::chrono::milliseconds> seraphis_lib_results_curl;

    seraphis_lib_results.reserve(loop_count);
    seraphis_lib_results_curl.reserve(loop_count);

    for (std::uint64_t i = 0; i < loop_count; ++i)
    {
        LOG_PRINT_L0("Starting loop " << i+1 << " / " << loop_count);

        // seraphis lib
        LOG_PRINT_L0("Initializing the client using the updated Seraphis lib (with epee http client)...");
        auto seraphis_lib_duration = scan_chain(start_height, priv_spend_key, priv_view_key, daemon_address, boost::none, epee::net_utils::ssl_support_t::e_ssl_support_disabled);
        LOG_PRINT_L0("Time to scan using the updated Seraphis lib (with epee http client): " << seraphis_lib_duration.count() << "ms");
        seraphis_lib_results.push_back(std::move(seraphis_lib_duration));
        // end seraphis lib

        // seraphis lib with libcurl
        LOG_PRINT_L0("Initializing the client using the updated Seraphis lib (with libcurl)...");
        bool use_curl = true;
        auto seraphis_lib_duration_curl = scan_chain(start_height, priv_spend_key, priv_view_key, daemon_address, boost::none, epee::net_utils::ssl_support_t::e_ssl_support_disabled, use_curl);
        LOG_PRINT_L0("Time to scan using the updated Seraphis lib (with libcurl): " << seraphis_lib_duration_curl.count() << "ms");
        seraphis_lib_results_curl.push_back(std::move(seraphis_lib_duration_curl));
        // end seraphis lib with libcurl
    }

    std::sort(seraphis_lib_results.begin(), seraphis_lib_results.end());
    std::sort(seraphis_lib_results_curl.begin(), seraphis_lib_results_curl.end());

    // print final results
    LOG_PRINT_L0("**********************************************************************");
    std::chrono::milliseconds min_seraphis_lib_duration = seraphis_lib_results[0];
    std::chrono::milliseconds min_seraphis_lib_duration_curl = seraphis_lib_results_curl[0];

    if (min_seraphis_lib_duration_curl > min_seraphis_lib_duration)
    {
        auto percent_diff = (min_seraphis_lib_duration_curl.count() - min_seraphis_lib_duration.count()) / (double) min_seraphis_lib_duration_curl.count();
        LOG_PRINT_L0("The Seraphis lib with the epee http client was " << percent_diff * 100 << "\% faster than with libcurl\n");
    }
    else
    {
        auto percent_diff = (min_seraphis_lib_duration.count() - min_seraphis_lib_duration_curl.count()) / (double) min_seraphis_lib_duration_curl.count();
        LOG_PRINT_L0("The Seraphis lib with libcurl was " << percent_diff * 100 << "\% slower than with the epee http client\n");
    }

    if (loop_count > 1)
    {
        LOG_PRINT_L0("Seraphis lib with epee http client (min):   " << min_seraphis_lib_duration.count() << "ms");
        LOG_PRINT_L0("Seraphis lib with libcurl          (min):   " << min_seraphis_lib_duration_curl.count() << "ms");

        auto median_seraphis_lib_result = seraphis_lib_results[loop_count / 2];
        auto median_seraphis_lib_result_curl = seraphis_lib_results_curl[loop_count / 2];

        LOG_PRINT_L0("Seraphis lib with epee http client (median):   " << median_seraphis_lib_result.count() << "ms");
        LOG_PRINT_L0("Seraphis lib with libcurl          (median):   " << median_seraphis_lib_result_curl.count() << "ms");
    }
    else
    {
        LOG_PRINT_L0("Seraphis lib with epee http client:   " << min_seraphis_lib_duration.count() << "ms");
        LOG_PRINT_L0("Seraphis lib with libcurl         :   " << min_seraphis_lib_duration_curl.count() << "ms");
    }
    LOG_PRINT_L0("**********************************************************************");


    LOG_PRINT_L0("Blockchain scanner complete");
    return 0;

    CATCH_ENTRY("Scanner error", 1);
}
