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

// NOT FOR PRODUCTION

// Simple implementations of enote scanning contexts.

#pragma once

//local headers
#include "common/variant.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "seraphis_mocks/enote_finding_context_mocks.h"
#include "seraphis_main/scan_context.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_ledger_chunk.h"
#include "seraphis_impl/scan_ledger_chunk_async.h"

//third party headers

//standard headers
#include <memory>
#include <atomic>

//forward declarations


namespace sp
{
namespace scanning
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
struct ChunkRequest final
{
    std::uint64_t start_index;
    std::uint64_t requested_chunk_size;
    bool gap_fill;
};

struct PendingChunk final
{
    ChunkRequest chunk_request;
    sp::scanning::PendingChunkContext pending_context;
    sp::scanning::PendingChunkData pending_data;
};

static inline bool operator<(const PendingChunk &pending_chunk1, const PendingChunk &pending_chunk2)
{
    return pending_chunk1.chunk_request.start_index < pending_chunk2.chunk_request.start_index;
}

typedef struct {
    cryptonote::transaction tx;
    crypto::hash tx_hash;
    uint64_t total_output_count_before_tx;
} parsed_transaction_t;

typedef struct {
    uint64_t block_index;
    uint64_t timestamp;
    crypto::hash block_hash;
    crypto::hash prev_block_hash;
    std::vector<parsed_transaction_t> parsed_txs;
} parsed_block_t;

typedef struct {
    rct::key tx_hash;
    uint64_t block_index;
    uint64_t timestamp;
    uint64_t total_output_count_before_tx;
    uint64_t unlock_time;
    sp::TxExtra tx_extra;
    std::vector<sp::LegacyEnoteVariant> enotes;
    std::vector<crypto::key_image> legacy_key_images;
} legacy_transaction_to_scan_t;
//-------------------------------------------------------------------------------------------------------------------
////
// WARNING: if the chunk size increment exceeds the max chunk size obtainable from the raw chunk data source, then
//          this will be less efficient because it will need to 'gap fill' continuously
///
class AsyncScanContextLegacy final : public ScanContextLedger
{
public:
    AsyncScanContextLegacy(const std::uint64_t pending_chunk_max_queue_size,
            const std::uint64_t chunk_size_increment,
            const std::uint64_t max_get_blocks_attempts,
            sp::mocks::EnoteFindingContextMockLegacy &enote_finding_context) :
        m_pending_chunk_max_queue_size{pending_chunk_max_queue_size},
        m_chunk_size_increment{chunk_size_increment},
        m_max_get_blocks_attempts{max_get_blocks_attempts},
        m_enote_finding_context{enote_finding_context},
        m_pause_pending_queue{false}
    {
        assert(m_pending_chunk_max_queue_size > 0);
        assert(m_chunk_size_increment > 0);
        assert(m_max_get_blocks_attempts > 0);
    }

    ~AsyncScanContextLegacy()
    {
        std::unique_lock<std::mutex> lock{m_pending_queue_mutex};
        wait_until_pending_queue_clears(lock);
    }

    void begin_scanning_from_index(const std::uint64_t start_index, const std::uint64_t max_chunk_size);

    std::unique_ptr<sp::scanning::LedgerChunk> get_onchain_chunk();

    /// stop the current scanning process (should be no-throw no-fail)
    void terminate_scanning() override { /* no-op */ }
    /// test if scanning has been aborted
    bool is_aborted() const override { return false; }

private:
    void wait_until_pending_queue_clears(const std::unique_lock<std::mutex> &pending_queue_lock);

private:
    /// config
    const std::uint64_t m_pending_chunk_max_queue_size;
    const std::uint64_t m_chunk_size_increment;
    const std::uint64_t m_max_get_blocks_attempts;

    /// finding context
    sp::mocks::EnoteFindingContextMockLegacy &m_enote_finding_context;

    /// pending chunks
    async::TokenQueue<PendingChunk> m_pending_chunks{};
    std::mutex m_pending_queue_mutex;
    bool m_pause_pending_queue;
    std::atomic<std::uint64_t> m_num_pending_chunks{0};
    std::atomic<std::uint64_t> m_start_index{0};
    std::uint64_t m_num_blocks_in_chain{0};
    rct::key m_top_block_hash;
    std::uint64_t m_last_scanned_index{0};
};
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace scanning
} //namespace sp
