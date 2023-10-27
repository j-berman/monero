// Copyright (c) 2022, The Monero Project
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

//paired header
#include "scan_context_async_mock.h"

//local headers
#include "async/misc_utils.h"
#include "async/threadpool.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "net/http.h"
#include "ringct/rctTypes.h"
#include "seraphis_impl/scan_ledger_chunk_simple.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/enote_record_utils_legacy.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_misc_utils.h"
#include "seraphis_main/scan_balance_recovery_utils.h"
#include "storages/http_abstract_invoke.h"
#include "wallet/wallet_errors.h"

//standard headers
#include <future>
#include <exception>
#include <utility>
#include <string>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_impl"

namespace sp
{
namespace scanning
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void validate_get_blocks_res(const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res)
{
    THROW_WALLET_EXCEPTION_IF(res.blocks.size() != res.output_indices.size(), tools::error::get_blocks_error,
        "mismatched blocks (" + boost::lexical_cast<std::string>(res.blocks.size()) + ") and output_indices (" +
        boost::lexical_cast<std::string>(res.output_indices.size()) + ") sizes from daemon");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static uint64_t get_total_output_count_before_tx(std::vector<uint64_t> output_indices)
{
    // total_output_count_before_tx == global output index of first output in tx.
    // Some txs have no enotes, in which case we set this value to 0 as it isn't useful.
    // TODO: pre-RCT outputs yield incorrect values here but this is only used for spending
    return !output_indices.empty() ? output_indices[0] : 0;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void view_scan_raw_chunk(sp::mocks::EnoteFindingContextMockLegacy &enote_finding_context,
    const std::vector<legacy_transaction_to_scan_t> &txs_to_scan,
    sp::scanning::ChunkData &chunk_data)
{
    std::vector<std::pair<rct::key, std::list<sp::ContextualBasicRecordVariant>>> basic_records_per_tx;
    basic_records_per_tx.resize(txs_to_scan.size());
    for (size_t i = 0; i < txs_to_scan.size(); ++i)
    {
        const legacy_transaction_to_scan_t &tx_to_scan = txs_to_scan[i];

        if (tx_to_scan.enotes.size() > 0)
        {
            std::list<sp::ContextualBasicRecordVariant> collected_records;
            enote_finding_context.find_basic_records(
                tx_to_scan.block_index,
                tx_to_scan.timestamp,
                tx_to_scan.tx_hash,
                tx_to_scan.total_output_count_before_tx,
                tx_to_scan.unlock_time,
                tx_to_scan.tx_extra,
                tx_to_scan.enotes,
                collected_records);
            basic_records_per_tx[i] = {txs_to_scan[i].tx_hash, std::move(collected_records)};
        }
        else
        {
            // always add an entry for tx in the basic records map (since we save key images for every tx)
            basic_records_per_tx[i] = {tx_to_scan.tx_hash, std::list<sp::ContextualBasicRecordVariant>{}};
        }

        sp::SpContextualKeyImageSetV1 collected_key_images;
        if (sp::scanning::try_collect_key_images_from_tx(
                tx_to_scan.block_index,
                tx_to_scan.timestamp,
                tx_to_scan.tx_hash,
                tx_to_scan.legacy_key_images,
                std::vector<crypto::key_image>(),
                sp::SpEnoteSpentStatus::SPENT_ONCHAIN,
                collected_key_images))
        {
            chunk_data.contextual_key_images.emplace_back(std::move(collected_key_images));
        }
    }

    for (auto &brpt : basic_records_per_tx)
        chunk_data.basic_records_per_tx.emplace(std::move(brpt));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void parse_rpc_get_blocks(const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res,
    std::vector<parsed_block_t> &parsed_blocks,
    const std::uint64_t requested_chunk_size = std::numeric_limits<uint64_t>::max())
{
    validate_get_blocks_res(res);

    const std::uint64_t num_blocks = std::min((std::uint64_t)res.blocks.size(), requested_chunk_size);

    parsed_blocks.clear();
    parsed_blocks.resize(num_blocks);
    std::vector<std::vector<crypto::hash>> non_miner_tx_hashes;
    non_miner_tx_hashes.resize(num_blocks);

    // parse blocks and txs
    for (size_t block_idx = 0; block_idx < num_blocks; ++block_idx)
    {
        auto &parsed_block = parsed_blocks[block_idx];
        parsed_block.parsed_txs.resize(1 + res.blocks[block_idx].txs.size());

        cryptonote::block block;
        THROW_WALLET_EXCEPTION_IF(!cryptonote::parse_and_validate_block_from_blob(res.blocks[block_idx].block, block),
            tools::error::wallet_internal_error, "failed to parse block blob at index " + std::to_string(block_idx));

        parsed_block.block_index = cryptonote::get_block_height(block);
        parsed_block.timestamp = block.timestamp;
        parsed_block.block_hash = cryptonote::get_block_hash(block);
        parsed_block.prev_block_hash = block.prev_id;

        crypto::hash miner_tx_hash = cryptonote::get_transaction_hash(block.miner_tx);
        parsed_block.parsed_txs[0] = parsed_transaction_t{
                std::move(block.miner_tx),
                miner_tx_hash,
                get_total_output_count_before_tx(res.output_indices[block_idx].indices[0].indices)
            };

        non_miner_tx_hashes[block_idx] = std::move(block.tx_hashes);

        // parse txs
        for (size_t tx_idx = 0; tx_idx < res.blocks[block_idx].txs.size(); ++tx_idx)
        {
            auto &parsed_tx = parsed_block.parsed_txs[1+tx_idx];

            cryptonote::transaction tx;
            THROW_WALLET_EXCEPTION_IF(!cryptonote::parse_and_validate_tx_base_from_blob(res.blocks[block_idx].txs[tx_idx].blob, tx),
                tools::error::wallet_internal_error, "failed to parse tx blob at index " + std::to_string(tx_idx));

            parsed_tx = parsed_transaction_t{
                        std::move(tx),
                        crypto::hash{},
                        get_total_output_count_before_tx(res.output_indices[block_idx].indices[1+tx_idx].indices)
                };
        }
    }

    for (size_t block_idx = 0; block_idx < non_miner_tx_hashes.size(); ++block_idx)
    {
        THROW_WALLET_EXCEPTION_IF(parsed_blocks[block_idx].parsed_txs.size() != non_miner_tx_hashes[block_idx].size() + 1,
            tools::error::wallet_internal_error, "Unexpected number of tx hashes");
        for (size_t tx_idx = 0; tx_idx < non_miner_tx_hashes[block_idx].size(); ++tx_idx)
            parsed_blocks[block_idx].parsed_txs[1+tx_idx].tx_hash = std::move(non_miner_tx_hashes[block_idx][tx_idx]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_tx_for_scanner(
    const uint64_t block_index,
    const uint64_t timestamp,
    const crypto::hash &tx_hash,
    const cryptonote::transaction &tx,
    const uint64_t total_output_count_before_tx,
    legacy_transaction_to_scan_t &tx_to_scan)
{
    tx_to_scan = legacy_transaction_to_scan_t{};

    tx_to_scan.block_index = block_index;
    tx_to_scan.timestamp = timestamp;
    tx_to_scan.tx_hash = rct::hash2rct(tx_hash);
    tx_to_scan.total_output_count_before_tx = total_output_count_before_tx;
    tx_to_scan.unlock_time = tx.unlock_time;

    tx_to_scan.tx_extra = sp::TxExtra(
            (const unsigned char *) tx.extra.data(),
            (const unsigned char *) tx.extra.data() + tx.extra.size()
        );

    sp::legacy_outputs_to_enotes(tx, tx_to_scan.enotes);

    tx_to_scan.legacy_key_images.reserve(tx.vin.size());
    for (const auto &in: tx.vin)
    {
        if (in.type() != typeid(cryptonote::txin_to_key))
            continue;
        const auto &txin = boost::get<cryptonote::txin_to_key>(in);
        tx_to_scan.legacy_key_images.emplace_back(txin.k_image);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_chunk_out(
    const std::vector<parsed_block_t> &blocks,
    std::vector<rct::key> &block_ids,
    uint64_t &start_index,
    rct::key &prefix_block_id,
    std::vector<legacy_transaction_to_scan_t> &txs_to_scan)
{
    block_ids.clear();
    block_ids.reserve(blocks.size());
    for (size_t i = 0; i < blocks.size(); ++i)
    {
        const parsed_block_t &parsed_block = blocks[i];

        if (i == 0)
        {
            start_index = parsed_block.block_index;
            prefix_block_id = rct::hash2rct(parsed_block.prev_block_hash);
        }

        block_ids.emplace_back(rct::hash2rct(parsed_block.block_hash));

        for (size_t tx_idx = 0; tx_idx < parsed_block.parsed_txs.size(); ++tx_idx)
        {
            const parsed_transaction_t &parsed_tx = parsed_block.parsed_txs[tx_idx];
            legacy_transaction_to_scan_t tx_to_scan;
            prepare_tx_for_scanner(
                parsed_block.block_index,
                parsed_block.timestamp,
                parsed_tx.tx_hash,
                parsed_tx.tx,
                parsed_tx.total_output_count_before_tx,
                tx_to_scan);
            txs_to_scan.emplace_back(std::move(tx_to_scan));
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool is_terminal_chunk(const sp::scanning::ChunkContext &context, const std::uint64_t num_blocks_in_chain)
{
    if (sp::scanning::chunk_context_is_empty(context))
    {
        MDEBUG("Chunk context is empty starting at " << context.start_index);
        return true;
    }

    // is the chunk the terminal chunk in the chain
    const std::uint64_t current_chunk_end_index{context.start_index + sp::scanning::chunk_size(context)};
    if (current_chunk_end_index >= num_blocks_in_chain)
    {
        MDEBUG("Chunk context end index: " << current_chunk_end_index << " (num_blocks_in_chain=" << num_blocks_in_chain << ")");
        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void rpc_get_blocks(const ChunkRequest &chunk_request,
    sp::mocks::EnoteFindingContextMockLegacy &enote_finding_context,
    const std::uint64_t max_get_blocks_attempts,
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res,
    bool trusted_daemon = false) // TODO: pass trusted_daemon in scan config
{
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req = AUTO_VAL_INIT(req);

    req.start_height = chunk_request.start_index;
    req.max_block_count = chunk_request.requested_chunk_size;
    req.prune = true;
    req.no_miner_tx = false;

    bool r = false;
    size_t try_count = 0;
    do
    {
        ++try_count;
        try
        {
            MDEBUG("Pulling blocks at requested start height: " << req.start_height << " (try_count=" << try_count << ")");

            // TODO: if the client requests a `start_height` higher than chain tip, older node versions will fail
            // the request. If we're pointing to an older node version and the request fails, we can query for
            // the chain height and make sure that the requested `start_height` is actually greater than the chain
            // tip and stop scanning without erroring.
            r = enote_finding_context.rpc_get_blocks(req, res);

            const std::string status = cryptonote::get_rpc_status(trusted_daemon, res.status);
            THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "getblocks.bin", tools::error::get_blocks_error, status);
            validate_get_blocks_res(res);
        }
        catch (tools::error::deprecated_rpc_access&)
        {
            // No need to retry
            std::rethrow_exception(std::current_exception());
        }
        catch (...)
        {
            r = false;
            if (try_count >= max_get_blocks_attempts)
                std::rethrow_exception(std::current_exception());
        }
    } while (!r && try_count < max_get_blocks_attempts);

    THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "failed to get blocks");

    MDEBUG("Pulled blocks: requested start height " << req.start_height << ", count " << res.blocks.size()
        << ", node height " << res.current_height << ", top hash " << res.top_block_hash
        << ", pool info " << static_cast<unsigned int>(res.pool_info_extent));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
// TODO: make this a member of the AsyncScanContextLegacy class and reduce number of params
bool launch_non_gap_fill_chunk_task(sp::mocks::EnoteFindingContextMockLegacy &enote_finding_context,
    async::TokenQueue<PendingChunk> &pending_chunks,
    const std::unique_lock<std::mutex> &pending_queue_lock,
    std::mutex &m_pending_queue_mutex,
    bool &m_pause_pending_queue,
    std::atomic<std::uint64_t> &num_pending_chunks,
    const std::uint64_t pending_chunk_max_queue_size,
    const std::uint64_t max_get_blocks_attempts,
    std::atomic<std::uint64_t> &next_start_index,
    const std::uint64_t chunk_size_increment,
    std::uint64_t &num_blocks_in_chain,
    rct::key &top_block_hash); // forward declaration
//-------------------------------------------------------------------------------------------------------------------
// TODO: make this a member of the AsyncScanContextLegacy class and reduce number of params
PendingChunk launch_chunk_task(const ChunkRequest &chunk_request,
    sp::mocks::EnoteFindingContextMockLegacy &enote_finding_context,
    async::TokenQueue<PendingChunk> &pending_chunks,
    const std::unique_lock<std::mutex> &pending_queue_lock,
    std::mutex &m_pending_queue_mutex,
    bool &m_pause_pending_queue,
    std::atomic<std::uint64_t> &num_pending_chunks,
    const std::uint64_t pending_chunk_max_queue_size,
    const std::uint64_t max_get_blocks_attempts,
    std::atomic<std::uint64_t> &next_start_index,
    const std::uint64_t chunk_size_increment,
    std::uint64_t &num_blocks_in_chain,
    rct::key &top_block_hash
) {
    THROW_WALLET_EXCEPTION_IF(!pending_queue_lock.owns_lock(), tools::error::wallet_internal_error,
        "Pending queue must be locked to launch a chunk task");

    MDEBUG("Launching chunk task at " << chunk_request.start_index << " (requested_chunk_size=" << chunk_request.requested_chunk_size << ")");

    async::Threadpool &threadpool{async::get_default_threadpool()};

    // prepare chunk task
    std::promise<void> context_stop_signal{};
    std::promise<void> data_stop_signal{};
    std::promise<sp::scanning::ChunkContext> chunk_context_handle{};
    std::promise<sp::scanning::ChunkData> chunk_data_handle{};
    std::shared_future<sp::scanning::ChunkContext> chunk_context_future = chunk_context_handle.get_future().share();
    std::shared_future<sp::scanning::ChunkData> chunk_data_future       = chunk_data_handle.get_future().share();
    async::join_signal_t context_join_signal                        = threadpool.make_join_signal();
    async::join_signal_t data_join_signal                           = threadpool.make_join_signal();
    async::join_token_t context_join_token                          = threadpool.get_join_token(context_join_signal);
    async::join_token_t data_join_token                             = threadpool.get_join_token(data_join_signal);

    // TODO: clean this up
    auto task =
        [
            &threadpool,
            &enote_finding_context,
            &pending_chunks,
            &m_pending_queue_mutex,
            &m_pause_pending_queue,
            &num_pending_chunks,
            &next_start_index,
            &num_blocks_in_chain,
            &top_block_hash,
            l_context_stop_flag            = context_stop_signal.get_future().share(),
            l_data_stop_flag               = data_stop_signal.get_future().share(),
            l_chunk_request                = chunk_request,
            l_pending_chunk_max_queue_size = pending_chunk_max_queue_size,
            l_max_get_blocks_attempts      = max_get_blocks_attempts,
            l_chunk_size_increment         = chunk_size_increment,
            l_chunk_context                = std::make_shared<std::promise<sp::scanning::ChunkContext>>(std::move(chunk_context_handle)),
            l_chunk_data                   = std::make_shared<std::promise<sp::scanning::ChunkData>>(std::move(chunk_data_handle)),
            l_context_join_token           = context_join_token,
            l_data_join_token              = data_join_token
        ]() mutable -> async::TaskVariant
        {
            async::fanout_token_t fanout_token{threadpool.launch_temporary_worker()};

            // check if canceled
            if (async::future_is_ready(l_context_stop_flag))
            {
                num_pending_chunks.fetch_sub(1, std::memory_order_relaxed);
                return boost::none;
            }

            sp::scanning::ChunkContext chunk_context{};
            std::vector<legacy_transaction_to_scan_t> txs_to_scan{};
            bool chunk_is_terminal_chunk = false;
            try
            {
                // Daemon query
                cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res = AUTO_VAL_INIT(res);
                rpc_get_blocks(l_chunk_request, enote_finding_context, l_max_get_blocks_attempts, res);

                // Parse the chunk
                std::vector<parsed_block_t> blocks;
                parse_rpc_get_blocks(res, blocks, l_chunk_request.requested_chunk_size);

                // TODO: make this thread safe
                if (res.current_height > num_blocks_in_chain)
                {
                    num_blocks_in_chain = res.current_height;
                    top_block_hash = rct::hash2rct(res.top_block_hash);
                    MDEBUG("Updated num_blocks_in_chain: " << num_blocks_in_chain);
                }

                if (!blocks.empty())
                {
                    // Prepare chunk for scanning
                    prepare_chunk_out(blocks,
                        chunk_context.block_ids,
                        chunk_context.start_index,
                        chunk_context.prefix_block_id,
                        txs_to_scan);
                }
                else
                {
                    // We expect to have scanned to the tip
                    chunk_context.prefix_block_id = rct::hash2rct(res.top_block_hash);
                    chunk_context.start_index = res.current_height;
                    chunk_context.block_ids.clear();
                }

                // check if the chunk was smaller than expected and fill the gap if necessary
                chunk_is_terminal_chunk = is_terminal_chunk(chunk_context, num_blocks_in_chain);
                if (!chunk_is_terminal_chunk)
                {
                    CHECK_AND_ASSERT_THROW_MES(l_chunk_request.requested_chunk_size >= sp::scanning::chunk_size(chunk_context),
                            "chunk size is larger than expected");
                    const uint64_t gap = l_chunk_request.requested_chunk_size - sp::scanning::chunk_size(chunk_context);
                    if (gap > 0)
                    {
                        // there was a gap, we'll need to launch a new task to fill the gap
                        std::unique_lock<std::mutex> lock{m_pending_queue_mutex};

                        const ChunkRequest next_chunk_request = {
                                .start_index          = chunk_context.start_index + sp::scanning::chunk_size(chunk_context),
                                .requested_chunk_size = gap,
                                .gap_fill             = true
                            };

                        pending_chunks.force_push(launch_chunk_task(next_chunk_request,
                            enote_finding_context,
                            pending_chunks,
                            lock,
                            m_pending_queue_mutex,
                            m_pause_pending_queue,
                            num_pending_chunks,
                            l_pending_chunk_max_queue_size,
                            l_max_get_blocks_attempts,
                            next_start_index,
                            l_chunk_size_increment,
                            num_blocks_in_chain,
                            top_block_hash));
                    }
                }
            }
            catch (...)
            {
                LOG_ERROR("Failed to get chunk context at start index " << l_chunk_request.start_index);
                l_chunk_context->set_exception(std::move(std::current_exception()));
                l_context_join_token = nullptr;
                num_pending_chunks.fetch_sub(1, std::memory_order_relaxed);
                return boost::none;
            }

            l_chunk_context->set_value(std::move(chunk_context));
            l_context_join_token = nullptr;

            // check if canceled
            if (async::future_is_ready(l_data_stop_flag))
            {
                num_pending_chunks.fetch_sub(1, std::memory_order_relaxed);
                return boost::none;
            }

            // find-received-scan raw data
            // set data
            // - note: process chunk data can 'do nothing' if the chunk is empty (i.e. don't launch any tasks)
            MDEBUG("View scanning chunk starting at " << l_chunk_request.start_index);
            sp::scanning::ChunkData chunk_data;
            view_scan_raw_chunk(enote_finding_context, txs_to_scan, chunk_data);

            l_chunk_data->set_value(std::move(chunk_data));
            l_data_join_token = nullptr;

            // we finished this task, decrement pending chunk queue
            if (!l_chunk_request.gap_fill)
                num_pending_chunks.fetch_sub(1, std::memory_order_relaxed);

            // launch the next task if we expect more and the queue has room
            if (!chunk_is_terminal_chunk)
            {
                std::unique_lock<std::mutex> lock{m_pending_queue_mutex};
                launch_non_gap_fill_chunk_task(enote_finding_context,
                    pending_chunks,
                    lock,
                    m_pending_queue_mutex,
                    m_pause_pending_queue,
                    num_pending_chunks,
                    l_pending_chunk_max_queue_size,
                    l_max_get_blocks_attempts,
                    next_start_index,
                    l_chunk_size_increment,
                    num_blocks_in_chain,
                    top_block_hash);
            }

            MDEBUG("Finished scanning chunk starting at " << l_chunk_request.start_index);

            return boost::none;
        };

    // launch the task
    threadpool.submit(async::make_simple_task(async::DefaultPriorityLevels::MEDIUM, std::move(task)));

    // return pending chunk for caller to deal with as needed
    async::join_condition_t chunk_context_join_condition{
            threadpool.get_join_condition(std::move(context_join_signal), std::move(context_join_token))
        };

    async::join_condition_t chunk_data_join_condition{
            threadpool.get_join_condition(std::move(data_join_signal), std::move(data_join_token))
        };

    return PendingChunk{
            .chunk_request = chunk_request,
            .pending_context = sp::scanning::PendingChunkContext{
                .stop_signal            = std::move(context_stop_signal),
                .chunk_context          = chunk_context_future,
                .context_join_condition = std::move(chunk_context_join_condition)
            },
            .pending_data    = sp::scanning::PendingChunkData{
                .stop_signal         = std::move(data_stop_signal),
                .chunk_data          = std::move(chunk_data_future),
                .data_join_condition = std::move(chunk_data_join_condition)
            }
        };
}
//-------------------------------------------------------------------------------------------------------------------
bool launch_non_gap_fill_chunk_task(sp::mocks::EnoteFindingContextMockLegacy &enote_finding_context,
    async::TokenQueue<PendingChunk> &pending_chunks,
    const std::unique_lock<std::mutex> &pending_queue_lock,
    std::mutex &m_pending_queue_mutex,
    bool &m_pause_pending_queue,
    std::atomic<std::uint64_t> &num_pending_chunks,
    const std::uint64_t pending_chunk_max_queue_size,
    const std::uint64_t max_get_blocks_attempts,
    std::atomic<std::uint64_t> &next_start_index,
    const std::uint64_t chunk_size_increment,
    std::uint64_t &num_blocks_in_chain,
    rct::key &top_block_hash)
{
    if (!pending_queue_lock.owns_lock())
    {
        LOG_ERROR("Pending queue is not locked");
        return false;
    }

    if (m_pause_pending_queue)
    {
        MDEBUG("Pending queue is paused, no more tasks can be launched");
        return false;
    }

    const std::uint64_t pending_queue_size = num_pending_chunks.fetch_add(1, std::memory_order_relaxed);
    if (pending_queue_size >= pending_chunk_max_queue_size)
    {
        MDEBUG("Pending queue is already at max capacity");
        num_pending_chunks.fetch_sub(1, std::memory_order_relaxed);
        return false;
    }

    const std::uint64_t start_index = next_start_index.fetch_add(chunk_size_increment);
    if (num_blocks_in_chain == 0 || start_index < num_blocks_in_chain)
    {
        pending_chunks.force_push(launch_chunk_task({ start_index, chunk_size_increment, false },
            enote_finding_context,
            pending_chunks,
            pending_queue_lock,
            m_pending_queue_mutex,
            m_pause_pending_queue,
            num_pending_chunks,
            pending_chunk_max_queue_size,
            max_get_blocks_attempts,
            next_start_index,
            chunk_size_increment,
            num_blocks_in_chain,
            top_block_hash));
        return true;
    }
    else
    {
        MDEBUG("Finished scanning already, not launching another task");
        next_start_index.fetch_sub(chunk_size_increment);
        return false;
    }
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::wait_until_pending_queue_clears(const std::unique_lock<std::mutex> &pending_queue_lock)
{
    // TODO: implement a clean safe cancel instead of waiting
    MDEBUG("Waiting until pending queue clears");

    THROW_WALLET_EXCEPTION_IF(!pending_queue_lock.owns_lock(),
        tools::error::wallet_internal_error, "Pending queue lock not owned");

    // Pausing ensures no new work will be pushed into the queue
    m_pause_pending_queue = true;

    PendingChunk clear_chunk;
    async::TokenQueueResult clear_chunk_result = m_pending_chunks.try_pop(clear_chunk);
    while (clear_chunk_result != async::TokenQueueResult::QUEUE_EMPTY)
    {
        THROW_WALLET_EXCEPTION_IF(clear_chunk_result != async::TokenQueueResult::SUCCESS,
            tools::error::wallet_internal_error, "Failed to clear onchain chunks");

        // Wait until all work in the pending queue is done, not just contexts
        // TODO: wait until every task in the pool has returned
        async::get_default_threadpool().work_while_waiting(clear_chunk.pending_data.data_join_condition,
            async::DefaultPriorityLevels::MAX);

        clear_chunk_result = m_pending_chunks.try_pop(clear_chunk);
    }

    MDEBUG("Pending queue cleared");
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::begin_scanning_from_index(const std::uint64_t start_index, const std::uint64_t max_chunk_size)
{
    MDEBUG("Begin scanning from index " << start_index);

    std::unique_lock<std::mutex> pending_queue_lock{m_pending_queue_mutex};
    wait_until_pending_queue_clears(pending_queue_lock);
    m_pause_pending_queue = false;

    m_start_index.store(start_index, std::memory_order_relaxed);
    m_num_pending_chunks.store(0, std::memory_order_relaxed);
    m_num_blocks_in_chain = 0;
    m_top_block_hash = rct::hash2rct(crypto::null_hash);
    m_last_scanned_index = start_index;

    // launch tasks until the queue fills up
    while (launch_non_gap_fill_chunk_task(m_enote_finding_context,
            m_pending_chunks,
            pending_queue_lock,
            m_pending_queue_mutex,
            m_pause_pending_queue,
            m_num_pending_chunks,
            m_pending_chunk_max_queue_size,
            m_max_get_blocks_attempts,
            m_start_index,
            m_chunk_size_increment,
            m_num_blocks_in_chain,
            m_top_block_hash)){};
;
}
//-------------------------------------------------------------------------------------------------------------------
std::unique_ptr<sp::scanning::LedgerChunk> AsyncScanContextLegacy::get_onchain_chunk()
{
    // Get the chunk with the lowest start height
    PendingChunk oldest_chunk;
    {
        std::lock_guard<std::mutex> lock{m_pending_queue_mutex};
        async::TokenQueueResult oldest_chunk_result = m_pending_chunks.try_remove_min(oldest_chunk);
        if (oldest_chunk_result == async::TokenQueueResult::QUEUE_EMPTY)
        {
            // end condition
            MDEBUG("No pending chunks remaining, num blocks in chain " << m_num_blocks_in_chain
                << ", top hash " << m_top_block_hash);

            THROW_WALLET_EXCEPTION_IF(m_num_blocks_in_chain == 0 || m_top_block_hash == rct::hash2rct(crypto::null_hash),
                tools::error::wallet_internal_error, "finished scanning but num blocks in chain or top block hash not set");

            sp::scanning::ChunkContext terminal_chunk{
                    .prefix_block_id = m_top_block_hash,
                    .start_index     = m_num_blocks_in_chain,
                    .block_ids       = {}
                };

            return std::make_unique<sp::scanning::LedgerChunkEmpty>(terminal_chunk);
        }
        THROW_WALLET_EXCEPTION_IF(oldest_chunk_result != async::TokenQueueResult::SUCCESS,
            tools::error::wallet_internal_error, "Failed to remove earliest onchain chunk");
    }

    sp::scanning::mocks::ChunkRequest &oldest_request = oldest_chunk.chunk_request;
    sp::scanning::PendingChunkContext &oldest_pending_context = oldest_chunk.pending_context;
    MDEBUG("Waiting for onchain chunk starting at " << oldest_request.start_index);

    THROW_WALLET_EXCEPTION_IF(oldest_request.start_index != m_last_scanned_index,
        tools::error::wallet_internal_error, "Chunk has index that is higher than expected");

    // Wait until the earliest chunk context is ready
    async::get_default_threadpool().work_while_waiting(oldest_pending_context.context_join_condition,
        async::DefaultPriorityLevels::MAX);

    MDEBUG("Done waiting for onchain chunk starting at " << oldest_request.start_index);

    // Expect the earliest chunk context to be ready
    THROW_WALLET_EXCEPTION_IF(!async::future_is_ready(oldest_pending_context.chunk_context),
        tools::error::wallet_internal_error, "Earliest onchain chunk context is not ready");

    // If there was an exception fetching the chunk context, .get() will throw it here
    sp::scanning::ChunkContext oldest_context = std::move(oldest_pending_context.chunk_context.get());
    m_last_scanned_index = oldest_context.start_index + sp::scanning::chunk_size(oldest_context);

    THROW_WALLET_EXCEPTION_IF(m_num_blocks_in_chain > 0 && m_num_blocks_in_chain > oldest_request.start_index &&
        oldest_request.start_index != oldest_context.start_index, tools::error::wallet_internal_error,
        "Requested start index does not match actual start index");

    // If it's the terminal chunk, we don't care about any more pending chunks
    if (is_terminal_chunk(oldest_context, m_num_blocks_in_chain))
    {
        MDEBUG("Encountered terminal chunk starting at " << oldest_context.start_index
            << " (expected to start at " << oldest_request.start_index << ")");
        std::unique_lock<std::mutex> lock{m_pending_queue_mutex};
        wait_until_pending_queue_clears(lock);
    }

    std::vector<sp::scanning::PendingChunkData> pending_chunk_data;
    pending_chunk_data.emplace_back(std::move(oldest_chunk.pending_data));

    if (m_num_blocks_in_chain > 0)
        LOG_PRINT_L0("Block " << oldest_request.start_index << " / " << m_num_blocks_in_chain);

    return std::make_unique<sp::scanning::AsyncLedgerChunk>(async::get_default_threadpool(),
            std::move(oldest_chunk.pending_context),
            std::move(pending_chunk_data),
            std::vector<rct::key>{rct::zero()});
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace scanning
} //namespace scanning
} //namespace sp
