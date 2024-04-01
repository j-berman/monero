// Copyright (c) 2014-2024, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "common/rpc_client.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/enote_store_utils.h"
#include "seraphis_impl/scan_context_simple.h"
#include "seraphis_impl/scan_process_basic.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/enote_finding_context.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_mocks/scan_chunk_consumer_mocks.h"
#include "seraphis_mocks/scan_context_async_mock.h"
#include "seraphis_mocks/mock_http_client_pool.h"
#include "wallet/wallet2.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/thread/thread.hpp>

#include <algorithm>
#include <memory>
#include <string>

const std::uint64_t fake_outs_count = 15;

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void reset(tools::t_daemon_rpc_client &daemon)
{
    printf("Resetting blockchain\n");
    std::uint64_t height = daemon.get_height().height;
    daemon.pop_blocks(height - 1);
    daemon.flush_txpool();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::unique_ptr<tools::wallet2> generate_wallet(const std::string &daemon_addr,
    const boost::optional<epee::net_utils::http::login> &daemon_login,
    const epee::net_utils::ssl_options_t ssl_support)
{
    std::unique_ptr<tools::wallet2> wal(new tools::wallet2(cryptonote::MAINNET, 1, true/*unattended keeps spend key decrypted*/));

    wal->init(daemon_addr, daemon_login, "", 0UL, true/*trusted_daemon*/, ssl_support);
    wal->allow_mismatched_daemon_version(true);
    wal->set_refresh_from_block_height(1); // setting to 1 skips height estimate in wal->generate()

    // Generate wallet in memory with empty wallet file name
    wal->generate("", "");

    return wal;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void transfer(std::unique_ptr<tools::wallet2> &sendr_wallet,
    cryptonote::account_public_address &dest_addr,
    bool is_subaddress,
    std::uint64_t amount_to_transfer,
    cryptonote::transaction &tx_out)
{
    std::vector<cryptonote::tx_destination_entry> dsts;
    dsts.reserve(1);

    cryptonote::tx_destination_entry de;
    de.addr = dest_addr;
    de.is_subaddress = is_subaddress;
    de.amount = amount_to_transfer;
    dsts.push_back(de);

    std::vector<tools::wallet2::pending_tx> ptx;
    ptx = sendr_wallet->create_transactions_2(dsts, fake_outs_count, 0, 0, std::vector<uint8_t>(), 0, {});
    CHECK_AND_ASSERT_THROW_MES(ptx.size() == 1, "unexpected num pending txs");
    sendr_wallet->commit_tx(ptx[0]);

    tx_out = std::move(ptx[0].tx);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t mine_tx(tools::t_daemon_rpc_client &daemon,
    const crypto::hash &tx_hash,
    const std::string &miner_addr_str)
{
    const std::string txs_hash = epee::string_tools::pod_to_hex(tx_hash);

    // Make sure tx is in the pool
    auto res = daemon.get_transactions(std::vector<std::string>{txs_hash});
    CHECK_AND_ASSERT_THROW_MES(res.txs.size() == 1 && res.txs[0].tx_hash == txs_hash && res.txs[0].in_pool,
        "tx not found in pool");

    // Mine the tx
    const std::uint64_t height = daemon.generateblocks(miner_addr_str, 1).height;

    // Make sure tx was mined
    res = daemon.get_transactions(std::vector<std::string>{txs_hash});
    CHECK_AND_ASSERT_THROW_MES(res.txs.size() == 1 && res.txs[0].tx_hash == txs_hash
        && res.txs[0].block_height == height, "tx not yet mined");

    return daemon.get_last_block_header().block_header.reward;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_wallet2_scan(std::unique_ptr<tools::wallet2> &sendr_wallet,
    std::unique_ptr<tools::wallet2> &recvr_wallet,
    std::uint64_t sendr_wallet_expected_balance,
    std::uint64_t recvr_wallet_expected_balance,
    const crypto::hash &tx_hash,
    std::uint64_t transfer_amount)
{
    sendr_wallet->refresh(true);
    recvr_wallet->refresh(true);
    std::uint64_t sendr_wallet_final_balance = sendr_wallet->balance(0, true);
    std::uint64_t recvr_wallet_final_balance = recvr_wallet->balance(0, true);

    CHECK_AND_ASSERT_THROW_MES(sendr_wallet_final_balance == sendr_wallet_expected_balance,
        "sendr_wallet has unexpected balance");
    CHECK_AND_ASSERT_THROW_MES(recvr_wallet_final_balance == recvr_wallet_expected_balance,
        "recvr_wallet has unexpected balance");

    // Find all transfers with matching tx hash
    tools::wallet2::transfer_container recvr_wallet_incoming_transfers;
    recvr_wallet->get_transfers(recvr_wallet_incoming_transfers);

    std::uint64_t received_amount = 0;
    auto it = recvr_wallet_incoming_transfers.begin();
    const auto end = recvr_wallet_incoming_transfers.end();
    const auto is_same_hash = [&tx_hash](const tools::wallet2::transfer_details& td) { return td.m_txid == tx_hash; };
    while ((it = std::find_if(it, end, is_same_hash)) != end)
    {
        CHECK_AND_ASSERT_THROW_MES(it->m_block_height > 0, "recvr_wallet did not see tx in chain");
        received_amount += it->m_amount;
        it++;
    }
    CHECK_AND_ASSERT_THROW_MES(received_amount == transfer_amount, "recvr_wallet did not receive correct amount");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void add_default_subaddresses(const rct::key &legacy_base_spend_pubkey,
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
            sp::make_legacy_subaddress_spendkey(legacy_base_spend_pubkey,
                legacy_view_privkey,
                subaddr_index,
                hw::get_device("default"),
                legacy_subaddress_spendkey);

            legacy_subaddress_map[legacy_subaddress_spendkey] = subaddr_index;
        }
    }
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static boost::multiprecision::uint128_t scan_chain(const std::uint64_t start_height,
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    sp::mocks::ClientConnectionPool &conn_pool)
{
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map{};
    add_default_subaddresses(legacy_base_spend_pubkey, legacy_view_privkey, legacy_subaddress_map);

    // Default config pointing to updated daemon
    const sp::scanning::ScanMachineConfig updated_scan_config{
            .reorg_avoidance_increment  = 1,
            .max_chunk_size_hint        = 20, // the lower this is, the quicker feedback gets to the user on scanner progress
            .max_partialscan_attempts   = 0
        };

    const std::uint64_t updated_pending_chunk_queue_size = std::min(
        (std::uint64_t)(boost::thread::hardware_concurrency() + 2),
        static_cast<std::uint64_t>(10));

    const sp::scanning::mocks::AsyncScanContextLegacyConfig config{
            .pending_chunk_queue_size = updated_pending_chunk_queue_size,
            .max_get_blocks_attempts  = 3,
            .trusted_daemon           = true
        };

    const std::function<bool(const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request&, cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response&)> rpc_get_blocks =
        [&conn_pool](const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request &req, cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res)
            {
                return conn_pool.rpc_command<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST>(
                    sp::mocks::ClientConnectionPool::http_mode::BIN,
                    "/getblocks.bin",
                    req,
                    res);
            };

    sp::EnoteFindingContextLegacySimple enote_finding_context{legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey};

    sp::scanning::mocks::AsyncScanContextLegacy scan_context_ledger{config,
        enote_finding_context,
        async::get_default_threadpool(),
        rpc_get_blocks};

    sp::SpEnoteStore user_enote_store{
            /*refresh_index*/                   start_height == 0 ? 1 : start_height,
            /*first_sp_allowed_block_in_chain*/ std::uint64_t(-1),
            /*default_spendable_age*/           CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE
        };

    sp::mocks::ChunkConsumerMockLegacy chunk_consumer{legacy_base_spend_pubkey,
        legacy_spend_privkey,
        legacy_view_privkey,
        user_enote_store};

    sp::scanning::ScanContextNonLedgerDummy scan_context_nonledger{};

    bool r = sp::refresh_enote_store(updated_scan_config,
        scan_context_nonledger,
        scan_context_ledger,
        chunk_consumer);
    CHECK_AND_ASSERT_THROW_MES(r, "Failed to refresh enote store");

    // Now that we're done scanning, we can close all open connections and keep 1 open for more RPC calls
    conn_pool.close_connections(1);

    return sp::get_balance(user_enote_store,
        {sp::SpEnoteOriginStatus::ONCHAIN, sp::SpEnoteOriginStatus::UNCONFIRMED},
        {sp::SpEnoteSpentStatus::SPENT_ONCHAIN, sp::SpEnoteSpentStatus::SPENT_UNCONFIRMED});
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
// TODO: remove after hard fork
static boost::multiprecision::uint128_t scan_using_old_daemon_version_config(const std::uint64_t start_height,
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    sp::mocks::ClientConnectionPool &conn_pool)
{
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map{};
    add_default_subaddresses(legacy_base_spend_pubkey, legacy_view_privkey, legacy_subaddress_map);

    // Config when pointing to a daemon that has not yet updated
    const sp::scanning::ScanMachineConfig backwards_compatible_scan_config{
            .reorg_avoidance_increment       = 3,    // since older daemons ban clients that request a height > chain height, give cushion to be safe
            .force_reorg_avoidance_increment = true, // be safe by making sure we always start the index below last known height
            .max_chunk_size_hint             = 1000, // an older daemon won't respect this value anyway
            .max_partialscan_attempts        = 3
        };

    const sp::scanning::mocks::AsyncScanContextLegacyConfig config{
            .pending_chunk_queue_size = 1, // won't do any "gap filling" inside the async scanner
            .max_get_blocks_attempts  = 3,
            .trusted_daemon           = true
        };

    const std::function<bool(const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request&, cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response&)> rpc_get_blocks =
        [&conn_pool](const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request &req, cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res)
            {
                cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req_get_blocks = req;
                req_get_blocks.fail_on_high_height = true;
                return conn_pool.rpc_command<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST>(
                    sp::mocks::ClientConnectionPool::http_mode::BIN,
                    "/getblocks.bin",
                    req_get_blocks,
                    res);
            };

    sp::EnoteFindingContextLegacyMultithreaded enote_finding_context{legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        async::get_default_threadpool()};

    sp::scanning::mocks::AsyncScanContextLegacy scan_context_ledger{config,
        enote_finding_context,
        async::get_default_threadpool(),
        rpc_get_blocks};

    sp::SpEnoteStore user_enote_store{
            /*refresh_index*/                   start_height == 0 ? 1 : start_height,
            /*first_sp_allowed_block_in_chain*/ std::uint64_t(-1),
            /*default_spendable_age*/           CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE
        };

    sp::mocks::ChunkConsumerMockLegacy chunk_consumer{legacy_base_spend_pubkey,
        legacy_spend_privkey,
        legacy_view_privkey,
        user_enote_store};

    sp::scanning::ScanContextNonLedgerDummy scan_context_nonledger{};

    bool r = sp::refresh_enote_store(backwards_compatible_scan_config,
        scan_context_nonledger,
        scan_context_ledger,
        chunk_consumer);
    CHECK_AND_ASSERT_THROW_MES(r, "Failed to refresh enote store using old daemon version config");

    return sp::get_balance(user_enote_store,
        {sp::SpEnoteOriginStatus::ONCHAIN, sp::SpEnoteOriginStatus::UNCONFIRMED},
        {sp::SpEnoteSpentStatus::SPENT_ONCHAIN, sp::SpEnoteSpentStatus::SPENT_UNCONFIRMED});
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_seraphis_scan(std::unique_ptr<tools::wallet2> &sendr_wallet,
    std::unique_ptr<tools::wallet2> &recvr_wallet,
    std::uint64_t sendr_wallet_expected_balance,
    std::uint64_t recvr_wallet_expected_balance,
    sp::mocks::ClientConnectionPool &conn_pool)
{
    // TEST 1: default config pointing to updated daemon
    MDEBUG("Using default Seraphis lib scanner config");

    boost::multiprecision::uint128_t sp_balance_sendr_wallet = scan_chain(0/*start_height*/,
            rct::pk2rct(sendr_wallet->get_account().get_keys().m_account_address.m_spend_public_key),
            sendr_wallet->get_account().get_keys().m_spend_secret_key,
            sendr_wallet->get_account().get_keys().m_view_secret_key,
            conn_pool
        );
    boost::multiprecision::uint128_t sp_balance_recvr_wallet = scan_chain(0/*start_height*/,
            rct::pk2rct(recvr_wallet->get_account().get_keys().m_account_address.m_spend_public_key),
            recvr_wallet->get_account().get_keys().m_spend_secret_key,
            recvr_wallet->get_account().get_keys().m_view_secret_key,
            conn_pool
        );

    CHECK_AND_ASSERT_THROW_MES(sp_balance_sendr_wallet == boost::multiprecision::uint128_t(sendr_wallet_expected_balance),
        "sendr_wallet Seraphis lib balance incorrect");
    CHECK_AND_ASSERT_THROW_MES(sp_balance_recvr_wallet == boost::multiprecision::uint128_t(recvr_wallet_expected_balance),
        "recvr_wallet Seraphis lib balance incorrect");

    // TODO: remove after hard fork
    // TEST 2: config when pointing to a daemon that has not yet updated
    MDEBUG("Using Seraphis lib scanner non-updated daemon config");

    sp_balance_sendr_wallet = scan_using_old_daemon_version_config(0/*start_height*/,
            rct::pk2rct(sendr_wallet->get_account().get_keys().m_account_address.m_spend_public_key),
            sendr_wallet->get_account().get_keys().m_spend_secret_key,
            sendr_wallet->get_account().get_keys().m_view_secret_key,
            conn_pool
        );
    sp_balance_recvr_wallet = scan_using_old_daemon_version_config(0/*start_height*/,
            rct::pk2rct(recvr_wallet->get_account().get_keys().m_account_address.m_spend_public_key),
            recvr_wallet->get_account().get_keys().m_spend_secret_key,
            recvr_wallet->get_account().get_keys().m_view_secret_key,
            conn_pool
        );

    CHECK_AND_ASSERT_THROW_MES(sp_balance_sendr_wallet == boost::multiprecision::uint128_t(sendr_wallet_expected_balance),
        "sendr_wallet Seraphis lib balance incorrect using old daemon version config");
    CHECK_AND_ASSERT_THROW_MES(sp_balance_recvr_wallet == boost::multiprecision::uint128_t(recvr_wallet_expected_balance),
        "recvr_wallet Seraphis lib balance incorrect using old daemon version config");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
// Tests
//-------------------------------------------------------------------------------------------------------------------
static void check_normal_transfer(tools::t_daemon_rpc_client &daemon,
    std::unique_ptr<tools::wallet2> &sendr_wallet,
    std::unique_ptr<tools::wallet2> &recvr_wallet,
    sp::mocks::ClientConnectionPool &conn_pool)
{
    printf("Checking normal transfer\n");

    // Assert sendr_wallet has enough money to send to recvr_wallet
    std::uint64_t amount_to_transfer = 1000000000000;
    sendr_wallet->refresh(true);
    recvr_wallet->refresh(true);
    CHECK_AND_ASSERT_THROW_MES(sendr_wallet->unlocked_balance(0, true) > (amount_to_transfer*2)/*2x for fee*/,
        "sendr_wallet does not have enough money");

    // Save initial state
    std::uint64_t sendr_wallet_init_balance = sendr_wallet->balance(0, true);
    std::uint64_t recvr_wallet_init_balance = recvr_wallet->balance(0, true);

    // Send from sendr_wallet to recvr_wallet's primary adddress
    cryptonote::transaction tx;
    cryptonote::account_public_address dest_addr = recvr_wallet->get_account().get_keys().m_account_address;
    transfer(sendr_wallet, dest_addr, false/*is_subaddress*/, amount_to_transfer, tx);
    std::uint64_t fee = cryptonote::get_tx_fee(tx);
    crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);

    // Mine the tx
    const std::string sender_addr = sendr_wallet->get_account().get_public_address_str(cryptonote::MAINNET);
    std::uint64_t block_reward = mine_tx(daemon, tx_hash, sender_addr);

    // Use wallet2 to scan tx and make sure it's in the chain
    std::uint64_t sendr_wallet_expected_balance = sendr_wallet_init_balance - amount_to_transfer - fee + block_reward;
    std::uint64_t recvr_wallet_expected_balance = recvr_wallet_init_balance + amount_to_transfer;
    check_wallet2_scan(sendr_wallet,
            recvr_wallet,
            sendr_wallet_expected_balance,
            recvr_wallet_expected_balance,
            tx_hash,
            amount_to_transfer
        );

    // Use Seraphis lib to scan chain
    check_seraphis_scan(sendr_wallet,
            recvr_wallet,
            sendr_wallet_expected_balance,
            recvr_wallet_expected_balance,
            conn_pool
        );
}
//-------------------------------------------------------------------------------------------------------------------
static void check_sweep_single(tools::t_daemon_rpc_client &daemon,
    std::unique_ptr<tools::wallet2> &sendr_wallet,
    std::unique_ptr<tools::wallet2> &recvr_wallet,
    sp::mocks::ClientConnectionPool &conn_pool)
{
    printf("Checking sweep single\n");

    sendr_wallet->refresh(true);
    recvr_wallet->refresh(true);

    // Find a spendable output
    crypto::key_image ki;
    std::uint64_t amount;
    {
        tools::wallet2::transfer_container tc;
        sendr_wallet->get_transfers(tc);
        bool found = false;
        for (const auto &td : tc)
        {
            if (td.m_amount > 0 && !td.m_spent && sendr_wallet->is_transfer_unlocked(td))
            {
                ki = td.m_key_image;
                amount = td.m_amount;
                found = true;
                break;
            }
        }
        CHECK_AND_ASSERT_THROW_MES(found, "did not find spendable output");
    }

    // Save initial state
    std::uint64_t sendr_wallet_init_balance = sendr_wallet->balance(0, true);
    std::uint64_t recvr_wallet_init_balance = recvr_wallet->balance(0, true);

    // Sweep single output from sendr_wallet to recvr_wallet so no change
    cryptonote::transaction tx;
    {
        std::vector<tools::wallet2::pending_tx> ptx = sendr_wallet->create_transactions_single(ki,
            recvr_wallet->get_account().get_keys().m_account_address,
            false /*is_subaddress*/,
            1 /*outputs*/,
            fake_outs_count,
            0 /*unlock_time*/,
            0 /*priority*/,
            std::vector<uint8_t>() /*extra*/
        );
        CHECK_AND_ASSERT_THROW_MES(ptx.size() == 1, "unexpected num pending txs");
        sendr_wallet->commit_tx(ptx[0]);
        tx = std::move(ptx[0].tx);
    }
    std::uint64_t fee = cryptonote::get_tx_fee(tx);
    crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);

    // Mine the tx
    const std::string sender_addr = sendr_wallet->get_account().get_public_address_str(cryptonote::MAINNET);
    std::uint64_t block_reward = mine_tx(daemon, tx_hash, sender_addr);

    // Use wallet2 to scan tx and make sure it's in the chain
    std::uint64_t sendr_wallet_expected_balance = sendr_wallet_init_balance - amount + block_reward;
    std::uint64_t recvr_wallet_expected_balance = recvr_wallet_init_balance + (amount - fee);
    check_wallet2_scan(sendr_wallet,
            recvr_wallet,
            sendr_wallet_expected_balance,
            recvr_wallet_expected_balance,
            tx_hash,
            (amount - fee)
        );

    // Use Seraphis lib to scan chain
    check_seraphis_scan(sendr_wallet,
            recvr_wallet,
            sendr_wallet_expected_balance,
            recvr_wallet_expected_balance,
            conn_pool
        );
}
//-------------------------------------------------------------------------------------------------------------------
static void check_transfer_to_subaddress(tools::t_daemon_rpc_client &daemon,
    std::unique_ptr<tools::wallet2> &sendr_wallet,
    std::unique_ptr<tools::wallet2> &recvr_wallet,
    sp::mocks::ClientConnectionPool &conn_pool)
{
    printf("Checking transfer to subaddress\n");

    // Assert sendr_wallet has enough money to send to recvr_wallet
    std::uint64_t amount_to_transfer = 1000000000000;
    sendr_wallet->refresh(true);
    recvr_wallet->refresh(true);
    CHECK_AND_ASSERT_THROW_MES(sendr_wallet->unlocked_balance(0, true) > (amount_to_transfer*2)/*2x for fee*/,
        "sendr_wallet does not have enough money");

    // Save initial state
    std::uint64_t sendr_wallet_init_balance = sendr_wallet->balance(0, true);
    std::uint64_t recvr_wallet_init_balance = recvr_wallet->balance(0, true);

    // Send from sendr_wallet to recvr_wallet subaddress major idx 0, minor idx 1
    cryptonote::transaction tx;
    cryptonote::account_public_address dest_addr = recvr_wallet->get_subaddress({0, 1});
    transfer(sendr_wallet, dest_addr, true/*is_subaddress*/, amount_to_transfer, tx);
    std::uint64_t fee = cryptonote::get_tx_fee(tx);
    crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);

    // Mine the tx
    const std::string sender_addr = sendr_wallet->get_account().get_public_address_str(cryptonote::MAINNET);
    std::uint64_t block_reward = mine_tx(daemon, tx_hash, sender_addr);

    // Use wallet2 to scan tx and make sure it's in the chain
    std::uint64_t sendr_wallet_expected_balance = sendr_wallet_init_balance - amount_to_transfer - fee + block_reward;
    std::uint64_t recvr_wallet_expected_balance = recvr_wallet_init_balance + amount_to_transfer;
    check_wallet2_scan(sendr_wallet,
            recvr_wallet,
            sendr_wallet_expected_balance,
            recvr_wallet_expected_balance,
            tx_hash,
            amount_to_transfer
        );

    // Use Seraphis lib to scan chain
    check_seraphis_scan(sendr_wallet,
            recvr_wallet,
            sendr_wallet_expected_balance,
            recvr_wallet_expected_balance,
            conn_pool
        );
}
//-------------------------------------------------------------------------------------------------------------------
static void check_transfer_to_multiple_subaddresses(tools::t_daemon_rpc_client &daemon,
    std::unique_ptr<tools::wallet2> &sendr_wallet,
    std::unique_ptr<tools::wallet2> &recvr_wallet,
    sp::mocks::ClientConnectionPool &conn_pool)
{
    printf("Checking transfer to multiple subaddresses\n");

    // Assert sendr_wallet has enough money to send to recvr_wallet
    std::uint64_t amount_to_transfer = 1000000000000;
    sendr_wallet->refresh(true);
    recvr_wallet->refresh(true);
    CHECK_AND_ASSERT_THROW_MES(sendr_wallet->unlocked_balance(0, true) > (amount_to_transfer*2)/*2x for fee*/,
        "sendr_wallet does not have enough money");

    // Save initial state
    std::uint64_t sendr_wallet_init_balance = sendr_wallet->balance(0, true);
    std::uint64_t recvr_wallet_init_balance = recvr_wallet->balance(0, true);

    // Send from sendr_wallet to 2 recvr_wallet subaddresses
    cryptonote::transaction tx;
    {
        const uint32_t num_subaddress = 2;

        std::vector<cryptonote::tx_destination_entry> dsts;
        dsts.reserve(num_subaddress);
        for (uint32_t i = 1; i <= num_subaddress; ++i)
        {
            cryptonote::tx_destination_entry de;
            de.addr = recvr_wallet->get_subaddress({0, i});
            de.is_subaddress = true;
            de.amount = amount_to_transfer / num_subaddress;
            dsts.push_back(de);
        }

        std::vector<tools::wallet2::pending_tx> ptx;
        ptx = sendr_wallet->create_transactions_2(dsts, fake_outs_count, 0, 0, std::vector<uint8_t>(), 0, {});
        CHECK_AND_ASSERT_THROW_MES(ptx.size() == 1, "unexpected num pending txs");
        sendr_wallet->commit_tx(ptx[0]);

        tx = std::move(ptx[0].tx);

        // Ensure tx has correct num additional pub keys
        const auto additional_pub_keys = cryptonote::get_additional_tx_pub_keys_from_extra(tx);
        CHECK_AND_ASSERT_THROW_MES(additional_pub_keys.size() == (num_subaddress + 1),
            "unexpected num additional pub keys");
    }
    std::uint64_t fee = cryptonote::get_tx_fee(tx);
    crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);

    // Mine the tx
    const std::string sender_addr = sendr_wallet->get_account().get_public_address_str(cryptonote::MAINNET);
    std::uint64_t block_reward = mine_tx(daemon, tx_hash, sender_addr);

    // Use wallet2 to scan tx and make sure it's in the chain
    std::uint64_t sendr_wallet_expected_balance = sendr_wallet_init_balance - amount_to_transfer - fee + block_reward;
    std::uint64_t recvr_wallet_expected_balance = recvr_wallet_init_balance + amount_to_transfer;
    check_wallet2_scan(sendr_wallet,
            recvr_wallet,
            sendr_wallet_expected_balance,
            recvr_wallet_expected_balance,
            tx_hash,
            amount_to_transfer
        );

    // Use Seraphis lib to scan chain
    check_seraphis_scan(sendr_wallet,
            recvr_wallet,
            sendr_wallet_expected_balance,
            recvr_wallet_expected_balance,
            conn_pool
        );
}
//-------------------------------------------------------------------------------------------------------------------
bool wallet_scanner(const std::string& daemon_addr)
{
    const boost::optional<epee::net_utils::http::login> daemon_login = boost::none;
    const epee::net_utils::ssl_options_t ssl_support = epee::net_utils::ssl_support_t::e_ssl_support_disabled;

    // Reset chain
    tools::t_daemon_rpc_client daemon(daemon_addr, daemon_login, ssl_support);
    reset(daemon);

    // Create wallets
    std::unique_ptr<tools::wallet2> sendr_wallet = generate_wallet(daemon_addr, daemon_login, ssl_support);
    std::unique_ptr<tools::wallet2> recvr_wallet = generate_wallet(daemon_addr, daemon_login, ssl_support);

    // Mine to sender
    printf("Mining to sender wallet\n");
    daemon.generateblocks(sendr_wallet->get_account().get_public_address_str(cryptonote::MAINNET), 80);

    // Initialize Seraphis lib connection pool
    sp::mocks::ClientConnectionPool conn_pool(daemon_addr, daemon_login, ssl_support);

    // Run the tests
    check_normal_transfer(daemon, sendr_wallet, recvr_wallet, conn_pool);
    check_sweep_single(daemon, sendr_wallet, recvr_wallet, conn_pool);
    check_transfer_to_subaddress(daemon, sendr_wallet, recvr_wallet, conn_pool);
    check_transfer_to_multiple_subaddresses(daemon, sendr_wallet, recvr_wallet, conn_pool);

    // TODO: add test that advances chain AFTER scanner starts (use conditional variables)
    // TODO: add reorg tests (both after scanning and while scanning)

    return true;
}
