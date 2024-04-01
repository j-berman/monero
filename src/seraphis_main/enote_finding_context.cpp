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
#include "enote_finding_context.h"

//local headers
#include "device/device.hpp"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/scan_balance_recovery_utils.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void EnoteFindingContextLegacySimple::view_scan_chunk(const LegacyUnscannedChunk &legacy_unscanned_chunk,
    sp::scanning::ChunkData &chunk_data_out)
{
    for (const auto &blk : legacy_unscanned_chunk)
    {
        for (const auto &tx : blk.unscanned_txs)
        {
            // Identify owned enotes
            if (tx.enotes.size() > 0)
            {
                std::list<sp::ContextualBasicRecordVariant> collected_records;
                sp::scanning::try_find_legacy_enotes_in_tx(m_legacy_base_spend_pubkey,
                    m_legacy_subaddress_map,
                    m_legacy_view_privkey,
                    blk.block_index,
                    blk.block_timestamp,
                    tx.transaction_id,
                    tx.total_enotes_before_tx,
                    tx.unlock_time,
                    tx.tx_memo,
                    tx.enotes,
                    sp::SpEnoteOriginStatus::ONCHAIN,
                    hw::get_device("default"),
                    collected_records);

                chunk_data_out.basic_records_per_tx[tx.transaction_id] = std::move(collected_records);
            }
            else
            {
                // always add an entry for tx in the legacy basic records map (since we save key images for every tx)
                chunk_data_out.basic_records_per_tx[tx.transaction_id] = std::list<sp::ContextualBasicRecordVariant>{};
            }

            // Collect key images
            sp::SpContextualKeyImageSetV1 collected_key_images;
            if (sp::scanning::try_collect_key_images_from_tx(blk.block_index,
                    blk.block_timestamp,
                    tx.transaction_id,
                    tx.legacy_key_images,
                    std::vector<crypto::key_image>()/*sp_key_images*/,
                    sp::SpEnoteSpentStatus::SPENT_ONCHAIN,
                    collected_key_images))
            {
                chunk_data_out.contextual_key_images.emplace_back(std::move(collected_key_images));
            }
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
