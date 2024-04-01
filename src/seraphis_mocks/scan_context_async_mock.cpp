// Copyright (c) 2024, The Monero Project
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
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "misc_log_ex.h"
#include "net/http.h"
#include "seraphis_impl/scan_ledger_chunk_simple.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/enote_finding_context.h"
#include "seraphis_main/enote_record_utils_legacy.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_misc_utils.h"
#include "seraphis_main/scan_balance_recovery_utils.h"
#include "storages/http_abstract_invoke.h"
#include "wallet/wallet_errors.h"

//standard headers
#include <exception>
#include <future>
#include <string>
#include <utility>

//3rd party headers
#include <boost/thread/thread.hpp>

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
static void validate_get_blocks_res(const ChunkRequest &req,
    const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res)
{
    THROW_WALLET_EXCEPTION_IF(res.blocks.size() != res.output_indices.size(), tools::error::get_blocks_error,
        "mismatched blocks (" + boost::lexical_cast<std::string>(res.blocks.size()) + ") and output_indices (" +
        boost::lexical_cast<std::string>(res.output_indices.size()) + ") sizes from daemon");

    if (!res.blocks.empty())
    {
        THROW_WALLET_EXCEPTION_IF(req.start_index >= res.current_height, tools::error::get_blocks_error,
            "returned non-empty blocks in getblocks.bin but requested start index is >= chain height");
    }
    else
    {
        // We expect to have scanned to the tip
        THROW_WALLET_EXCEPTION_IF(req.start_index < res.current_height, tools::error::get_blocks_error,
            "no blocks returned in getblocks.bin but requested start index is < chain height");

        // Scanner is not designed to support retrieving empty chunks when no top block hash is returned (i.e. when
        // pointing to an older daemon version)
        THROW_WALLET_EXCEPTION_IF(res.top_block_hash == crypto::null_hash, tools::error::wallet_internal_error,
            "did not expect empty chunk when top block hash is null");
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static uint64_t get_total_output_count_before_tx(std::vector<uint64_t> output_indices)
{
    // total_output_count_before_tx == global output index of first output in tx.
    // Some txs have no enotes, in which case we set this value to 0 as it isn't useful.
    // TODO: pre-RCT outputs yield incorrect values here but this is only used for spending
    // need https://github.com/UkoeHB/monero/pull/40 in order to handle pre-RCT outputs
    return !output_indices.empty() ? output_indices[0] : 0;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_unscanned_legacy_transaction(const crypto::hash &tx_hash,
    const cryptonote::transaction &tx,
    const uint64_t total_output_count_before_tx,
    sp::LegacyUnscannedTransaction &unscanned_tx_out)
{
    unscanned_tx_out = LegacyUnscannedTransaction{};

    unscanned_tx_out.transaction_id = rct::hash2rct(tx_hash);
    unscanned_tx_out.total_enotes_before_tx = total_output_count_before_tx;
    unscanned_tx_out.unlock_time = tx.unlock_time;

    unscanned_tx_out.tx_memo = sp::TxExtra(
            (const unsigned char *) tx.extra.data(),
            (const unsigned char *) tx.extra.data() + tx.extra.size()
        );

    sp::legacy_outputs_to_enotes(tx, unscanned_tx_out.enotes);

    unscanned_tx_out.legacy_key_images.reserve(tx.vin.size());
    for (const auto &in: tx.vin)
    {
        if (in.type() != typeid(cryptonote::txin_to_key))
            continue;
        const auto &txin = boost::get<cryptonote::txin_to_key>(in);
        unscanned_tx_out.legacy_key_images.emplace_back(txin.k_image);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool is_terminal_chunk(const sp::scanning::ChunkContext &context, const std::uint64_t end_scan_index)
{
    if (sp::scanning::chunk_context_is_empty(context))
    {
        MDEBUG("Chunk context is empty starting at " << context.start_index);
        return true;
    }

    // is the chunk the terminal chunk in the chain
    const std::uint64_t current_chunk_end_index{context.start_index + sp::scanning::chunk_size(context)};
    if (current_chunk_end_index >= end_scan_index)
    {
        MDEBUG("Chunk context end index: " << current_chunk_end_index
            << " (end_scan_index=" << end_scan_index << ")");
        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void rpc_get_blocks_internal(const ChunkRequest &chunk_request,
    const std::function<bool(const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request&, cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response&)> &rpc_get_blocks,
    const std::uint64_t max_get_blocks_attempts,
    const bool trusted_daemon,
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res_out)
{
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req = AUTO_VAL_INIT(req);

    req.start_height = chunk_request.start_index;
    req.max_block_count = chunk_request.requested_chunk_size;
    req.prune = true;
    req.no_miner_tx = false;
    req.fail_on_high_height = false;

    bool r = false;
    std::size_t try_count = 0;
    do
    {
        ++try_count;
        try
        {
            MDEBUG("Pulling blocks at req start height: " << req.start_height << " (try_count=" << try_count << ")");
            r = rpc_get_blocks(req, res_out);
            const std::string status = cryptonote::get_rpc_status(trusted_daemon, res_out.status);
            THROW_ON_RPC_RESPONSE_ERROR(r, {}, res_out, "getblocks.bin", tools::error::get_blocks_error, status);
            validate_get_blocks_res(chunk_request, res_out);
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

    MDEBUG("Pulled blocks: requested start height " << req.start_height << ", count " << res_out.blocks.size()
        << ", node height " << res_out.current_height << ", top hash " << res_out.top_block_hash
        << ", pool info " << static_cast<unsigned int>(res_out.pool_info_extent));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void parse_rpc_get_blocks(const ChunkRequest &chunk_request,
    const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res,
    sp::scanning::ChunkContext &chunk_context_out,
    sp::LegacyUnscannedChunk &unscanned_chunk_out)
{
    validate_get_blocks_res(chunk_request, res);

    // Older daemons can return more blocks than requested because they did not support a max_block_count req param.
    // The scanner expects requested_chunk_size blocks however, so we only care about the blocks up until that point.
    // Note the scanner can also return *fewer* blocks than requested if at chain tip or the chunk exceeded max size.
    const std::uint64_t num_blocks = std::min((std::uint64_t)res.blocks.size(), chunk_request.requested_chunk_size);

    chunk_context_out.block_ids.clear();

    unscanned_chunk_out.clear();
    unscanned_chunk_out.resize(num_blocks);

    if (num_blocks == 0)
    {
        // must have requested the tip of the chain
        chunk_context_out.prefix_block_id = rct::hash2rct(res.top_block_hash);
        chunk_context_out.start_index = res.current_height;
        return;
    }

    // parse blocks and txs
    for (std::size_t block_idx = 0; block_idx < num_blocks; ++block_idx)
    {
        auto &unscanned_block = unscanned_chunk_out[block_idx];
        unscanned_block.unscanned_txs.resize(1 + res.blocks[block_idx].txs.size());

        cryptonote::block block;
        bool r = cryptonote::parse_and_validate_block_from_blob(res.blocks[block_idx].block, block);
        THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error,
            "failed to parse block blob at index " + std::to_string(block_idx));

        unscanned_block.block_index = cryptonote::get_block_height(block);
        unscanned_block.block_timestamp = block.timestamp;
        unscanned_block.block_hash = rct::hash2rct(cryptonote::get_block_hash(block));
        unscanned_block.prev_block_hash = rct::hash2rct(block.prev_id);

        chunk_context_out.block_ids.emplace_back(unscanned_block.block_hash);
        if (block_idx == 0)
        {
            chunk_context_out.start_index = unscanned_block.block_index;
            chunk_context_out.prefix_block_id = unscanned_block.prev_block_hash;
        }

        crypto::hash miner_tx_hash = cryptonote::get_transaction_hash(block.miner_tx);

        prepare_unscanned_legacy_transaction(miner_tx_hash,
            block.miner_tx,
            get_total_output_count_before_tx(res.output_indices[block_idx].indices[0].indices),
            unscanned_block.unscanned_txs[0]);

        // parse txs
        for (std::size_t tx_idx = 0; tx_idx < res.blocks[block_idx].txs.size(); ++tx_idx)
        {
            auto &unscanned_tx = unscanned_block.unscanned_txs[1+tx_idx];

            cryptonote::transaction tx;
            r = cryptonote::parse_and_validate_tx_base_from_blob(res.blocks[block_idx].txs[tx_idx].blob, tx);
            THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error,
                "failed to parse tx blob at index " + std::to_string(tx_idx));

            THROW_WALLET_EXCEPTION_IF(tx_idx >= block.tx_hashes.size(), tools::error::wallet_internal_error,
                "unexpected number of tx hashes");

            prepare_unscanned_legacy_transaction(block.tx_hashes[tx_idx],
                std::move(tx),
                get_total_output_count_before_tx(res.output_indices[block_idx].indices[1+tx_idx].indices),
                unscanned_tx);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool AsyncScanContextLegacy::check_launch_next_task(const std::unique_lock<std::mutex> &pending_queue_lock)
{
    MDEBUG("Attempting to launch chunk task at " << m_scan_index.load(std::memory_order_relaxed)
        << " (chunk_size_increment=" << m_max_chunk_size_hint << ")");

    THROW_WALLET_EXCEPTION_IF(!pending_queue_lock.owns_lock(), tools::error::wallet_internal_error,
        "Pending queue must be locked to check next task launch");

    if (!m_scanner_ready.load(std::memory_order_relaxed))
    {
        MDEBUG("Pending queue is not available for use, no tasks can be launched");
        return false;
    }

    if (m_end_scan_index != 0 && m_scan_index.load(std::memory_order_relaxed) >= m_end_scan_index)
    {
        MDEBUG("Scan tasks are scheduled to scan to chain tip, not launching another task");
        return false;
    }

    if (m_num_pending_chunks.load(std::memory_order_relaxed) >= m_config.pending_chunk_queue_size)
    {
        MDEBUG("Pending queue is already at max capacity");
        return false;
    }

    // We use a separate counter for scanning chunks so we don't overload memory.
    // Continuously fetching chunks while the scanner is backstopped can overload memory.
    if (m_num_scanning_chunks.load(std::memory_order_relaxed) >= m_config.pending_chunk_queue_size)
    {
        MDEBUG("Scanning queue is already at max capacity");
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::fill_gap_if_needed(bool chunk_is_terminal_chunk,
    const std::uint64_t &requested_chunk_size,
    const sp::scanning::ChunkContext &chunk_context)
{
    if (!chunk_is_terminal_chunk)
    {
        // If chunk was smaller than requested, will need to fill the gap
        const std::size_t chunk_size = sp::scanning::chunk_size(chunk_context);
        const std::uint64_t gap = requested_chunk_size - chunk_size;
        if (gap > 0)
        {
            const std::uint64_t gap_start_index = chunk_context.start_index + chunk_size;

            if (m_config.pending_chunk_queue_size > 1)
            {
                // Launch a new task to fill the gap
                std::unique_lock<std::mutex> lock{m_pending_queue_mutex};

                const ChunkRequest next_chunk_request{
                        .start_index          = gap_start_index,
                        .requested_chunk_size = gap
                    };

                m_pending_chunk_queue.force_push(launch_chunk_task(next_chunk_request, lock));
            }
            else
            {
                // Advance scan index to the start of the gap for next task
                m_scan_index.store(gap_start_index, std::memory_order_relaxed);
            }
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::update_chain_state(const sp::scanning::ChunkContext &chunk_context,
    const std::uint64_t num_blocks_in_chain,
    const crypto::hash &top_block_hash,
    bool &chunk_is_terminal_chunk_out)
{
    std::lock_guard<std::mutex> lock{m_chain_state_mutex};

    MDEBUG("Updating chain state");

    if (m_end_scan_index == 0)
    {
        m_end_scan_index = num_blocks_in_chain;
        MDEBUG("Set m_end_scan_index: " << m_end_scan_index);
    }

    if (top_block_hash != crypto::null_hash && rct::hash2rct(top_block_hash) != m_top_block_hash)
    {
        m_num_blocks_in_chain = num_blocks_in_chain;
        m_top_block_hash = rct::hash2rct(top_block_hash);
        MDEBUG("Updated top_block_hash " << top_block_hash
            << " (num_blocks_in_chain=" << m_num_blocks_in_chain << ")");
    }
    else if (num_blocks_in_chain > m_num_blocks_in_chain)
    {
        m_num_blocks_in_chain = num_blocks_in_chain;
        MDEBUG("Updated num_blocks_in_chain: " << m_num_blocks_in_chain);
    }

    // Check if it's the scanner's final chunk
    chunk_is_terminal_chunk_out = is_terminal_chunk(chunk_context, m_end_scan_index);

    // When pointing to an older daemon version, we have to use the terminal chunk to set the top block hash since
    // the daemon doesn't return it.
    // Warning: it may not line up with m_num_blocks_in_chain in the event the chain has advanced past
    // m_end_scan_index, in which case get_onchain_chunk will make sure the scanner resets and does another pass to
    // finish when handling the terminal chunk.
    if (top_block_hash == crypto::null_hash && chunk_is_terminal_chunk_out && !chunk_context.block_ids.empty())
    {
        m_top_block_hash = chunk_context.block_ids[chunk_context.block_ids.size() - 1];
        MDEBUG("Used terminal chunk to update top_block_hash " << m_top_block_hash
            << " (num_blocks_in_chain=" << m_num_blocks_in_chain << ")");
    }

    if (chunk_is_terminal_chunk_out)
    {
        THROW_WALLET_EXCEPTION_IF(m_scan_index.load(std::memory_order_relaxed) < m_end_scan_index,
            tools::error::wallet_internal_error,
            "scan index is < m_end_scan_index even though we encountered the terminal chunk");

        THROW_WALLET_EXCEPTION_IF(m_end_scan_index == 0, tools::error::wallet_internal_error,
            "expected >0 end scan index at terminal chunk");

        THROW_WALLET_EXCEPTION_IF(m_num_blocks_in_chain == 0, tools::error::wallet_internal_error,
            "expected >0 num blocks in the chain at terminal chunk");

        THROW_WALLET_EXCEPTION_IF(m_top_block_hash == rct::hash2rct(crypto::null_hash),
            tools::error::wallet_internal_error, "expected top block hash to be set at terminal chunk");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::handle_chunk_context(const ChunkRequest &chunk_request,
    sp::scanning::ChunkContext &chunk_context_out,
    LegacyUnscannedChunk &unscanned_chunk_out,
    bool &chunk_is_terminal_chunk_out)
{
    // Query daemon for chunk of blocks
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res = AUTO_VAL_INIT(res);
    rpc_get_blocks_internal(chunk_request,
        rpc_get_blocks,
        m_config.max_get_blocks_attempts,
        m_config.trusted_daemon,
        res);

    // Parse the result
    parse_rpc_get_blocks(chunk_request,
        res,
        chunk_context_out,
        unscanned_chunk_out);

    // Update scanner's known top block height and hash
    update_chain_state(chunk_context_out,
        res.current_height,
        res.top_block_hash,
        chunk_is_terminal_chunk_out);

    // Check if the chunk was smaller than requested and fill gap if needed
    fill_gap_if_needed(chunk_is_terminal_chunk_out,
        chunk_request.requested_chunk_size,
        chunk_context_out);
}
//-------------------------------------------------------------------------------------------------------------------
async::TaskVariant AsyncScanContextLegacy::chunk_task(const ChunkRequest &chunk_request,
    std::shared_future<void> &context_stop_flag,
    std::shared_future<void> &data_stop_flag,
    std::shared_ptr<std::promise<sp::scanning::ChunkContext>> &chunk_context_ptr_out,
    std::shared_ptr<std::promise<sp::scanning::ChunkData>> &chunk_data_ptr_out,
    async::join_token_t &context_join_token_out,
    async::join_token_t &data_join_token_out)
{
    async::fanout_token_t fanout_token{m_threadpool.launch_temporary_worker()};

    // Check if canceled
    if (async::future_is_ready(context_stop_flag))
    {
        m_num_pending_chunks.fetch_sub(1, std::memory_order_relaxed);
        return boost::none;
    }

    // Get the chunk from the daemon and prepare to scan
    sp::scanning::ChunkContext chunk_context{};
    LegacyUnscannedChunk unscanned_chunk{};
    bool chunk_is_terminal_chunk = false;
    try
    {
        handle_chunk_context(chunk_request,
            chunk_context,
            unscanned_chunk,
            chunk_is_terminal_chunk);
    }
    catch (...)
    {
        LOG_ERROR("Failed to get chunk context at start index " << chunk_request.start_index);
        chunk_context_ptr_out->set_exception(std::move(std::current_exception()));
        context_join_token_out = nullptr;
        m_num_pending_chunks.fetch_sub(1, std::memory_order_relaxed);
        return boost::none;
    }

    // Finished retrieving the chunk
    chunk_context_ptr_out->set_value(std::move(chunk_context));
    context_join_token_out = nullptr;
    m_num_pending_chunks.fetch_sub(1, std::memory_order_relaxed);

    // Check if canceled
    if (async::future_is_ready(data_stop_flag))
        return boost::none;

    // launch the next task if we expect more and the queue has room
    launch_next_task_if_room(chunk_is_terminal_chunk);

    // Retrieved the chunk, now need to scan it
    m_num_scanning_chunks.fetch_add(1, std::memory_order_relaxed);

    // find-received-scan raw data
    // - note: process chunk data can 'do nothing' if the chunk is empty (i.e. don't launch any tasks)
    sp::scanning::ChunkData chunk_data;
    m_enote_finding_context.view_scan_chunk(unscanned_chunk, chunk_data);

    // Finished scanning the chunk
    chunk_data_ptr_out->set_value(std::move(chunk_data));
    data_join_token_out = nullptr;
    m_num_scanning_chunks.fetch_sub(1, std::memory_order_relaxed);

    MDEBUG("Finished scanning chunk starting at " << chunk_request.start_index);

    launch_next_task_if_room(chunk_is_terminal_chunk);

    return boost::none;
}
//-------------------------------------------------------------------------------------------------------------------
PendingChunk AsyncScanContextLegacy::launch_chunk_task(const ChunkRequest &chunk_request,
    const std::unique_lock<std::mutex> &pending_queue_lock)
{
    THROW_WALLET_EXCEPTION_IF(!pending_queue_lock.owns_lock(), tools::error::wallet_internal_error,
        "Pending queue must be locked to launch a chunk task");

    MDEBUG("Launching chunk task at " << chunk_request.start_index
        << " (requested_chunk_size=" << chunk_request.requested_chunk_size << ")");

    // prepare chunk task
    std::promise<void> context_stop_signal{};
    std::promise<void> data_stop_signal{};
    std::promise<sp::scanning::ChunkContext> chunk_context_handle{};
    std::promise<sp::scanning::ChunkData> chunk_data_handle{};
    std::shared_future<sp::scanning::ChunkContext> chunk_context_future = chunk_context_handle.get_future().share();
    std::shared_future<sp::scanning::ChunkData> chunk_data_future       = chunk_data_handle.get_future().share();
    async::join_signal_t context_join_signal                        = m_threadpool.make_join_signal();
    async::join_signal_t data_join_signal                           = m_threadpool.make_join_signal();
    async::join_token_t context_join_token                          = m_threadpool.get_join_token(context_join_signal);
    async::join_token_t data_join_token                             = m_threadpool.get_join_token(data_join_signal);

    auto task =
        [
            this,
            l_chunk_request                = chunk_request,
            l_context_stop_flag            = context_stop_signal.get_future().share(),
            l_data_stop_flag               = data_stop_signal.get_future().share(),
            l_chunk_context                = std::make_shared<std::promise<sp::scanning::ChunkContext>>(std::move(chunk_context_handle)),
            l_chunk_data                   = std::make_shared<std::promise<sp::scanning::ChunkData>>(std::move(chunk_data_handle)),
            l_context_join_token           = context_join_token,
            l_data_join_token              = data_join_token
        ]() mutable -> async::TaskVariant
        {
            return chunk_task(l_chunk_request,
                l_context_stop_flag,
                l_data_stop_flag,
                l_chunk_context,
                l_chunk_data,
                l_context_join_token,
                l_data_join_token);
        };

    // launch the task
    m_num_pending_chunks.fetch_add(1, std::memory_order_relaxed);
    m_threadpool.submit(async::make_simple_task(async::DefaultPriorityLevels::MEDIUM, std::move(task)));

    // return pending chunk for caller to deal with as needed
    async::join_condition_t chunk_context_join_condition{
            m_threadpool.get_join_condition(std::move(context_join_signal), std::move(context_join_token))
        };

    async::join_condition_t chunk_data_join_condition{
            m_threadpool.get_join_condition(std::move(data_join_signal), std::move(data_join_token))
        };

    return PendingChunk{
            .chunk_request = chunk_request,
            .pending_context = sp::scanning::PendingChunkContext{
                    .stop_signal            = std::move(context_stop_signal),
                    .chunk_context          = std::move(chunk_context_future),
                    .context_join_condition = std::move(chunk_context_join_condition)
                },
            .pending_data    = sp::scanning::PendingChunkData{
                    .stop_signal            = std::move(data_stop_signal),
                    .chunk_data             = std::move(chunk_data_future),
                    .data_join_condition    = std::move(chunk_data_join_condition)
                }
        };
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::launch_next_chunk_task(const std::unique_lock<std::mutex> &pending_queue_lock)
{
    THROW_WALLET_EXCEPTION_IF(!pending_queue_lock.owns_lock(), tools::error::wallet_internal_error,
        "Pending queue must be locked to launch the next chunk task");

    // Advance the scanner's scanning index
    const std::uint64_t start_index = m_scan_index.fetch_add(m_max_chunk_size_hint);

    const ChunkRequest next_chunk_request{
            .start_index          = start_index,
            .requested_chunk_size = m_max_chunk_size_hint
        };

    m_pending_chunk_queue.force_push(launch_chunk_task(next_chunk_request, pending_queue_lock));
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::launch_next_task_if_room(bool chunk_is_terminal_chunk)
{
    // Don't need to launch the next task if found the terminal chunk, we're done!
    if (!chunk_is_terminal_chunk)
    {
        std::unique_lock<std::mutex> lock{m_pending_queue_mutex};
        if (check_launch_next_task(lock))
        {
            launch_next_chunk_task(lock);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::handle_terminal_chunk()
{
    // Clear up everything left in the queue
    wait_until_pending_queue_clears();

    // Make sure we scanned to current tip
    if (m_last_scanned_index == m_num_blocks_in_chain)
    {
        // We're good to go, advance the end scan index
        MDEBUG("We're prepared for the end condition, we scanned to " << m_last_scanned_index);
        m_end_scan_index = m_last_scanned_index;
        m_scanner_ready.store(true, std::memory_order_relaxed); // mark the scanner ready for the end condition
    }
    else
    {
        // The chain must have advanced since we started scanning, restart scanning from the highest scan
        MDEBUG("The chain advanced since we started scanning, restart from last scan");
        std::unique_lock<std::mutex> lock{m_pending_queue_mutex};
        start_scanner(m_last_scanned_index, m_max_chunk_size_hint, lock);
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::unique_ptr<sp::scanning::LedgerChunk> AsyncScanContextLegacy::handle_end_condition()
{
    MDEBUG("No pending chunks remaining, num blocks in chain " << m_num_blocks_in_chain
        << ", top hash " << m_top_block_hash << " , last scanned index " << m_last_scanned_index);

    const bool unexpected_tip = m_num_blocks_in_chain == 0 || m_top_block_hash == rct::hash2rct(crypto::null_hash);
    THROW_WALLET_EXCEPTION_IF(unexpected_tip, tools::error::wallet_internal_error,
        "finished scanning but num blocks in chain or top block hash not set");

    THROW_WALLET_EXCEPTION_IF(m_last_scanned_index != m_num_blocks_in_chain,
        tools::error::wallet_internal_error, "finished scanning but did not scan to the tip of the chain");

    THROW_WALLET_EXCEPTION_IF(m_last_scanned_index != m_end_scan_index, tools::error::wallet_internal_error,
        "finished scanning but did not scan to expected end index");

    // Scanner must be restarted to be usable again
    m_scanner_ready.store(false, std::memory_order_relaxed);

    // Use an empty chunk to indicate to the caller the scanner is finished
    sp::scanning::ChunkContext empty_terminal_chunk{
            .prefix_block_id = m_top_block_hash,
            .start_index     = m_num_blocks_in_chain,
            .block_ids       = {}
        };

    return std::make_unique<sp::scanning::LedgerChunkEmpty>(std::move(empty_terminal_chunk));
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::wait_until_pending_queue_clears()
{
    // TODO: implement a clean safe cancel instead of waiting
    MDEBUG("Waiting until pending queue clears");

    // Don't allow scheduling any more chunk tasks until the scanner is restarted
    m_scanner_ready.store(false, std::memory_order_relaxed);

    PendingChunk clear_chunk;
    async::TokenQueueResult clear_chunk_result = m_pending_chunk_queue.try_pop(clear_chunk);
    while (clear_chunk_result != async::TokenQueueResult::QUEUE_EMPTY)
    {
        THROW_WALLET_EXCEPTION_IF(clear_chunk_result != async::TokenQueueResult::SUCCESS,
            tools::error::wallet_internal_error, "Failed to clear onchain chunks");

        // Wait until all work in the pending queue is done, not just contexts
        // TODO: wait until every task in the pool has returned
        m_threadpool.work_while_waiting(clear_chunk.pending_data.data_join_condition,
            async::DefaultPriorityLevels::MAX);

        clear_chunk_result = m_pending_chunk_queue.try_pop(clear_chunk);
    }

    MDEBUG("Pending queue cleared");
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::start_scanner(const std::uint64_t start_index,
    const std::uint64_t max_chunk_size_hint,
    const std::unique_lock<std::mutex> &pending_queue_lock)
{
    MDEBUG("Starting scanner from index " << start_index);

    THROW_WALLET_EXCEPTION_IF(!pending_queue_lock.owns_lock(),
        tools::error::wallet_internal_error, "Pending queue lock not owned");

    m_max_chunk_size_hint = max_chunk_size_hint;
    m_scanner_ready.store(true, std::memory_order_relaxed);

    m_num_pending_chunks.store(0, std::memory_order_relaxed);
    m_num_scanning_chunks.store(0, std::memory_order_relaxed);
    m_scan_index.store(start_index, std::memory_order_relaxed);
    m_last_scanned_index = start_index;
    m_end_scan_index = 0;

    m_num_blocks_in_chain = 0;
    m_top_block_hash = rct::hash2rct(crypto::null_hash);

    // launch tasks until the queue fills up
    while (check_launch_next_task(pending_queue_lock))
    {
        launch_next_chunk_task(pending_queue_lock);
    };
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::begin_scanning_from_index(const std::uint64_t start_index,
    const std::uint64_t max_chunk_size_hint)
{
    std::lock_guard<std::mutex> lg{m_async_scan_context_mutex};

    // Wait for any pending chunks to finish if there are any
    wait_until_pending_queue_clears();

    std::unique_lock<std::mutex> pending_queue_lock{m_pending_queue_mutex};
    start_scanner(start_index, max_chunk_size_hint, pending_queue_lock);
}
//-------------------------------------------------------------------------------------------------------------------
std::unique_ptr<sp::scanning::LedgerChunk> AsyncScanContextLegacy::get_onchain_chunk()
{
    std::lock_guard<std::mutex> lg{m_async_scan_context_mutex};
    THROW_WALLET_EXCEPTION_IF(!m_scanner_ready.load(std::memory_order_relaxed), tools::error::wallet_internal_error,
        "scanner is not ready for use");

    // Get the chunk with the lowest requested start index
    PendingChunk oldest_chunk;
    {
        std::lock_guard<std::mutex> lock{m_pending_queue_mutex};

        // Explicitly remove the min element (instead of the first element) because chunks might not be in the queue
        // in chain order. If we needed to fill a gap (fill_gap_if_needed), the pending chunk gets pushed to the end
        // of the queue even though the requested start index may be lower than pending chunks already in the queue.
        async::TokenQueueResult oldest_chunk_result = m_pending_chunk_queue.try_remove_min(oldest_chunk);
        if (oldest_chunk_result == async::TokenQueueResult::QUEUE_EMPTY)
        {
            // We should be done scanning now
            return handle_end_condition();
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
    m_threadpool.work_while_waiting(oldest_pending_context.context_join_condition,
        async::DefaultPriorityLevels::MAX);

    MDEBUG("Done waiting for onchain chunk starting at " << oldest_request.start_index);

    // Expect the earliest chunk context to be ready
    THROW_WALLET_EXCEPTION_IF(!async::future_is_ready(oldest_pending_context.chunk_context),
        tools::error::wallet_internal_error, "Earliest onchain chunk context is not ready");

    // If there was an exception fetching the chunk context, .get() will throw it here
    sp::scanning::ChunkContext oldest_context = std::move(oldest_pending_context.chunk_context.get());
    m_last_scanned_index = oldest_context.start_index + sp::scanning::chunk_size(oldest_context);

    // Make sure we got the expected chunk
    THROW_WALLET_EXCEPTION_IF(m_end_scan_index > 0 && m_end_scan_index > oldest_request.start_index &&
        oldest_request.start_index != oldest_context.start_index, tools::error::wallet_internal_error,
        "Requested start index does not match actual start index");

    // Handle the terminal chunk
    if (is_terminal_chunk(oldest_context, m_end_scan_index))
    {
        MDEBUG("Encountered terminal chunk starting at " << oldest_context.start_index
            << " (expected to start at " << oldest_request.start_index << ")");
        handle_terminal_chunk();
    }

    // We're ready to return the pending chunk now
    std::vector<sp::scanning::PendingChunkData> pending_chunk_data;
    pending_chunk_data.emplace_back(std::move(oldest_chunk.pending_data));

    if (m_num_blocks_in_chain > 0)
        LOG_PRINT_L0("Block " << m_last_scanned_index << " / " << m_num_blocks_in_chain);

    return std::make_unique<sp::scanning::AsyncLedgerChunk>(m_threadpool,
        std::move(oldest_chunk.pending_context),
        std::move(pending_chunk_data),
        std::vector<rct::key>{rct::zero()});
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace scanning
} //namespace scanning
} //namespace sp
