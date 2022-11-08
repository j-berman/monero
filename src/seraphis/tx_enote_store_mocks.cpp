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

//paired header
#include "tx_enote_store_mocks.h"

//local headers
#include "cryptonote_config.h"
#include "legacy_enote_utils.h"
#include "misc_log_ex.h"
#include "sp_misc_utils.h"
#include "tx_contextual_enote_record_types.h"
#include "tx_contextual_enote_record_utils.h"
#include "tx_enote_record_utils_legacy.h"

//third party headers

//standard headers
#include <algorithm>
#include <ctime>
#include <functional>
#include <iterator>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool onchain_legacy_enote_is_locked(const std::uint64_t enote_origin_height,
    const std::uint64_t enote_unlock_time,
    const std::uint64_t chain_height,
    const std::uint64_t default_spendable_age,
    const std::uint64_t current_time)
{
    // check default spendable age
    if (chain_height + 1 < enote_origin_height + std::max(std::uint64_t{1}, default_spendable_age))
        return true;

    // check unlock time: height encoding
    if (enote_unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER &&
        chain_height + 1 < enote_unlock_time)
        return true;

    // check unlock time: UNIX encoding
    return current_time < enote_unlock_time;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool onchain_sp_enote_is_locked(const std::uint64_t enote_origin_height,
    const std::uint64_t chain_height,
    const std::uint64_t default_spendable_age)
{
    return chain_height + 1 < enote_origin_height + std::max(std::uint64_t{1}, default_spendable_age);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockSimpleV1::add_record(const LegacyContextualEnoteRecordV1 &new_record)
{
    m_legacy_contextual_enote_records.emplace_back(new_record);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockSimpleV1::add_record(const SpContextualEnoteRecordV1 &new_record)
{
    m_sp_contextual_enote_records.emplace_back(new_record);
}
//-------------------------------------------------------------------------------------------------------------------
SpEnoteStoreMockV1::SpEnoteStoreMockV1(const std::uint64_t refresh_height,
    const std::uint64_t first_sp_enabled_block_in_chain,
    const std::uint64_t default_spendable_age) :
        m_refresh_height{refresh_height},
        m_legacy_fullscan_height{refresh_height - 1},
        m_legacy_partialscan_height{refresh_height - 1},
        m_sp_scanned_height{refresh_height - 1},
        m_first_sp_enabled_block_in_chain{first_sp_enabled_block_in_chain},
        m_default_spendable_age{default_spendable_age}
{}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::add_record(const LegacyContextualIntermediateEnoteRecordV1 &new_record)
{
    // 1. if key image is known, promote to a full enote record
    if (m_tracked_legacy_onetime_address_duplicates.find(onetime_address_ref(new_record.m_record.m_enote)) !=
        m_tracked_legacy_onetime_address_duplicates.end())
    {
        const auto &identifiers_of_known_enotes =
            m_tracked_legacy_onetime_address_duplicates.at(onetime_address_ref(new_record.m_record.m_enote));

        CHECK_AND_ASSERT_THROW_MES(identifiers_of_known_enotes.size() > 0,
            "add intermediate record (mock enote store): record's onetime address is known, but there are no identifiers "
            "(bug).");

        for (const rct::key &identifier : identifiers_of_known_enotes)
        {
            // key image is known if there is a full record associated with this intermediate record's onetime address
            if (m_mapped_legacy_contextual_enote_records.find(identifier) ==
                m_mapped_legacy_contextual_enote_records.end())
                continue;

            CHECK_AND_ASSERT_THROW_MES(identifier == *(identifiers_of_known_enotes.begin()),
                "add intermediate record (mock enote store): key image is known but there are intermediate "
                "records with this onetime address (a given onetime address should have only intermediate or only "
                "full legacy records).");

            LegacyContextualEnoteRecordV1 temp_full_record{};

            get_legacy_enote_record(new_record.m_record,
                m_mapped_legacy_contextual_enote_records.at(identifier).m_record.m_key_image,
                temp_full_record.m_record);
            temp_full_record.m_origin_context = new_record.m_origin_context;

            this->add_record(temp_full_record);
            return;
        }
    }

    // 2. else add the intermediate record or update an existing record's origin context
    rct::key new_record_identifier;
    get_legacy_enote_identifier(onetime_address_ref(new_record.m_record.m_enote),
        new_record.m_record.m_amount,
        new_record_identifier);

    if (m_mapped_legacy_intermediate_contextual_enote_records.find(new_record_identifier) ==
        m_mapped_legacy_intermediate_contextual_enote_records.end())
    {
        // add new intermediate record
        m_mapped_legacy_intermediate_contextual_enote_records[new_record_identifier] = new_record;
    }
    else
    {
        // update intermediate record's origin context
        try_update_enote_origin_context_v1(new_record.m_origin_context,
            m_mapped_legacy_intermediate_contextual_enote_records[new_record_identifier].m_origin_context);
    }

    // 3. save to the legacy duplicate tracker
    m_tracked_legacy_onetime_address_duplicates[onetime_address_ref(new_record.m_record.m_enote)]
        .insert(new_record_identifier);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::add_record(const LegacyContextualEnoteRecordV1 &new_record)
{
    rct::key new_record_identifier;
    get_legacy_enote_identifier(onetime_address_ref(new_record.m_record.m_enote),
        new_record.m_record.m_amount,
        new_record_identifier);

    // 1. add the record or update an existing record's contexts
    if (m_mapped_legacy_contextual_enote_records.find(new_record_identifier) ==
        m_mapped_legacy_contextual_enote_records.end())
    {
        m_mapped_legacy_contextual_enote_records[new_record_identifier] = new_record;
    }
    else
    {
        update_contextual_enote_record_contexts_v1(new_record.m_origin_context,
                new_record.m_spent_context,
                m_mapped_legacy_contextual_enote_records[new_record_identifier].m_origin_context,
                m_mapped_legacy_contextual_enote_records[new_record_identifier].m_spent_context
            );
    }

    // 2. if this enote is located in the legacy key image tracker for seraphis txs, update with the tracker's spent context
    if (m_legacy_key_images_in_sp_selfsends.find(new_record.m_record.m_key_image) !=
        m_legacy_key_images_in_sp_selfsends.end())
    {
        // update the record's spent context
        try_update_enote_spent_context_v1(m_legacy_key_images_in_sp_selfsends.at(new_record.m_record.m_key_image),
            m_mapped_legacy_contextual_enote_records[new_record_identifier].m_spent_context);

        // note: do not reset the tracker's spent context here, because the tracker is tied to seraphis scanning, so
        //       any updates to it should be handled by the seraphis scanning process
    }

    // 3. if this enote is located in the intermediate enote record map, update the full record with the intermediate
    //    record's origin context
    if (m_mapped_legacy_intermediate_contextual_enote_records.find(new_record_identifier) !=
        m_mapped_legacy_intermediate_contextual_enote_records.end())
    {
        // update the record's origin context
        try_update_enote_origin_context_v1(
                m_mapped_legacy_intermediate_contextual_enote_records.at(new_record_identifier).m_origin_context,
                m_mapped_legacy_contextual_enote_records[new_record_identifier].m_origin_context
            );
    }

    // 4. there may be other full legacy enote records with this record's key image, use them to update the spent context
    for (const rct::key &legacy_enote_identifier :
            m_tracked_legacy_onetime_address_duplicates[onetime_address_ref(new_record.m_record.m_enote)])
    {
        // a. skip identifiers not in the full legacy records map
        if (m_mapped_legacy_contextual_enote_records.find(legacy_enote_identifier) ==
            m_mapped_legacy_contextual_enote_records.end())
            continue;

        // b. update the spent context
        try_update_enote_spent_context_v1(
            m_mapped_legacy_contextual_enote_records.at(legacy_enote_identifier).m_spent_context,
            m_mapped_legacy_contextual_enote_records[new_record_identifier].m_spent_context);
    }

    // 5. remove the intermediate record with this identifier (must do this before importing the key image, since
    //    the key image importer assumes the intermediate and full legacy maps don't have any overlap)
    m_mapped_legacy_intermediate_contextual_enote_records.erase(new_record_identifier);

    // 6. save to the legacy duplicate tracker
    m_tracked_legacy_onetime_address_duplicates[onetime_address_ref(new_record.m_record.m_enote)]
        .insert(new_record_identifier);

    // 7. save to the legacy key image set
    m_legacy_key_images[new_record.m_record.m_key_image] = onetime_address_ref(new_record.m_record.m_enote);

    // 8. import this key image to force-promote all intermediate records with different identifiers to full records
    this->import_legacy_key_image(new_record.m_record.m_key_image, onetime_address_ref(new_record.m_record.m_enote));
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::add_record(const SpContextualEnoteRecordV1 &new_record)
{
    const crypto::key_image &record_key_image{new_record.key_image()};

    // add the record or update an existing record's contexts
    if (m_mapped_sp_contextual_enote_records.find(record_key_image) == m_mapped_sp_contextual_enote_records.end())
        m_mapped_sp_contextual_enote_records[record_key_image] = new_record;
    else
        update_contextual_enote_record_contexts_v1(new_record, m_mapped_sp_contextual_enote_records[record_key_image]);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::set_last_legacy_fullscan_height(const std::uint64_t new_height)
{
    // 1. set this scan height (+1 because initial scanned height is below refresh height)
    CHECK_AND_ASSERT_THROW_MES(new_height + 1 >= m_refresh_height,
        "mock enote store (set legacy fullscan height): new height is below refresh height.");
    CHECK_AND_ASSERT_THROW_MES(new_height + 1 <= m_refresh_height + m_block_ids.size(),
        "mock enote store (set legacy fullscan height): new height is above known block range.");

    m_legacy_fullscan_height = new_height;

    // 2. update other scan heights
    // a. legacy partial scan height (fullscan qualifies as partialscan)
    // note: this update won't fix inaccuracy in the m_legacy_partialscan_height caused by a reorg, although
    //       in practice reorgs that reduce the chain height are extremely rare/nonexistent outside unit tests;
    //       moreoever, the partialscan height is meaningless unless view-only scanning (in which case the fullscan
    //       height will almost certainly only be updated using a manual workflow that can only repair reorgs by
    //       re-running the workflow anyway)
    m_legacy_partialscan_height = std::max(m_legacy_partialscan_height + 1, m_legacy_fullscan_height + 1) - 1;

    // b. seraphis scan height (to avoid re-acquiring legacy-only block ids)
    m_sp_scanned_height = std::max(m_sp_scanned_height + 1,
        std::min(m_legacy_fullscan_height + 1, m_first_sp_enabled_block_in_chain)) - 1;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::set_last_legacy_partialscan_height(const std::uint64_t new_height)
{
    // 1. set this scan height
    CHECK_AND_ASSERT_THROW_MES(new_height + 1 >= m_refresh_height,
        "mock enote store (set legacy partialscan height): new height is below refresh height.");
    CHECK_AND_ASSERT_THROW_MES(new_height + 1 <= m_refresh_height + m_block_ids.size(),
        "mock enote store (set legacy partialscan height): new height is above known block range.");

    m_legacy_partialscan_height = new_height;

    // 2. update other scan heights
    // a. legacy full scan height (if partialscan height is below fullscan height, assume this means there was a reorg)
    m_legacy_fullscan_height = std::min(m_legacy_fullscan_height + 1, m_legacy_partialscan_height + 1) - 1;

    // b. seraphis scan height (to avoid re-acquiring legacy-only block ids)
    m_sp_scanned_height = std::max(m_sp_scanned_height + 1,
        std::min(m_legacy_partialscan_height + 1, m_first_sp_enabled_block_in_chain)) - 1;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::set_last_sp_scanned_height(const std::uint64_t new_height)
{
    // set this scan height
    CHECK_AND_ASSERT_THROW_MES(new_height + 1 >= m_refresh_height,
        "mock enote store (set seraphis scan height): new height is below refresh height.");
    CHECK_AND_ASSERT_THROW_MES(new_height + 1 <= m_refresh_height + m_block_ids.size(),
        "mock enote store (set seraphis scan height): new height is above known block range.");

    m_sp_scanned_height = new_height;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::import_legacy_key_image(const crypto::key_image &legacy_key_image, const rct::key &onetime_address)
{
    // 1. we are done if there are no enote records for this onetime address
    if (m_tracked_legacy_onetime_address_duplicates.find(onetime_address) ==
        m_tracked_legacy_onetime_address_duplicates.end())
        return;

    // 2. if this key image appeared in a seraphis tx, get the spent context
    SpEnoteSpentContextV1 spent_context{};

    if (m_legacy_key_images_in_sp_selfsends.find(legacy_key_image) != m_legacy_key_images_in_sp_selfsends.end())
    {
        spent_context = m_legacy_key_images_in_sp_selfsends.at(legacy_key_image);
    }

    // 3. there may be full legacy enote records with this key image, use them to update the spent context
    for (const rct::key &legacy_enote_identifier : m_tracked_legacy_onetime_address_duplicates[onetime_address])
    {
        // a. skip identifiers not in the full legacy records map
        if (m_mapped_legacy_contextual_enote_records.find(legacy_enote_identifier) ==
            m_mapped_legacy_contextual_enote_records.end())
            continue;

        // b. update the spent context
        try_update_enote_spent_context_v1(
            m_mapped_legacy_contextual_enote_records.at(legacy_enote_identifier).m_spent_context,
            spent_context);
    }

    // 4. promote intermediate enote records with this onetime address to full enote records
    for (const rct::key &legacy_enote_identifier : m_tracked_legacy_onetime_address_duplicates[onetime_address])
    {
        // a. skip identifiers not in the intermediate records map
        if (m_mapped_legacy_intermediate_contextual_enote_records.find(legacy_enote_identifier) ==
            m_mapped_legacy_intermediate_contextual_enote_records.end())
            continue;

        // b. if this identifier has an intermediate record, it should not have a full record
        CHECK_AND_ASSERT_THROW_MES(m_mapped_legacy_contextual_enote_records.find(legacy_enote_identifier) ==
                m_mapped_legacy_contextual_enote_records.end(),
            "import legacy key image (enote store mock): intermediate and full legacy maps inconsistent (bug).");

        // c. set the full record
        get_legacy_enote_record(
            m_mapped_legacy_intermediate_contextual_enote_records[legacy_enote_identifier].m_record,
            legacy_key_image,
            m_mapped_legacy_contextual_enote_records[legacy_enote_identifier].m_record);

        // d. set the full record's contexts
        update_contextual_enote_record_contexts_v1(
                m_mapped_legacy_intermediate_contextual_enote_records[legacy_enote_identifier].m_origin_context,
                spent_context,
                m_mapped_legacy_contextual_enote_records[legacy_enote_identifier].m_origin_context,
                m_mapped_legacy_contextual_enote_records[legacy_enote_identifier].m_spent_context
            );

        // e. remove the intermediate record
        m_mapped_legacy_intermediate_contextual_enote_records.erase(legacy_enote_identifier);

        // f. save to the legacy key image set
        m_legacy_key_images[legacy_key_image] = onetime_address;
    }
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::handle_legacy_key_images_from_sp_selfsends(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends)
{
    // handle each key image
    for (const auto &legacy_key_image_with_spent_context : legacy_key_images_in_sp_selfsends)
    {
        // 1. try to update the spent contexts of legacy enotes that have this key image
        for (auto &mapped_contextual_enote_record : m_mapped_legacy_contextual_enote_records)
        {
            // a. skip legacy enotes with different key images
            if (mapped_contextual_enote_record.second.m_record.m_key_image != legacy_key_image_with_spent_context.first)
                continue;

            // b. update the spent context of this legacy enote
            try_update_enote_spent_context_v1(legacy_key_image_with_spent_context.second,
                mapped_contextual_enote_record.second.m_spent_context);
        }

        // 2. save the key image's spent context in the tracker (or update an existing context)
        // note: these are always saved to help with reorg handling
        try_update_enote_spent_context_v1(legacy_key_image_with_spent_context.second,
            m_legacy_key_images_in_sp_selfsends[legacy_key_image_with_spent_context.first]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_intermediate_legacy_records_from_ledger(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids,
    const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images)
{
    // 1. update block tracking info
    this->update_with_new_blocks_from_ledger(ScanUpdateMode::LEGACY_INTERMEDIATE,
        first_new_block,
        alignment_block_id,
        new_block_ids);

    // 2. clean up enote store maps in preparation for adding fresh enotes and key images
    this->clean_maps_for_legacy_ledger_update(first_new_block, found_spent_key_images);

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second);

    // 4. update contexts of stored enotes with found spent key images
    this->update_legacy_with_fresh_found_spent_key_images(found_spent_key_images);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_legacy_records_from_ledger(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids,
    const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images)
{
    // 1. update block tracking info
    this->update_with_new_blocks_from_ledger(ScanUpdateMode::LEGACY_FULL,
        first_new_block,
        alignment_block_id,
        new_block_ids);

    // 2. clean up enote store maps in preparation for adding fresh enotes and key images
    this->clean_maps_for_legacy_ledger_update(first_new_block, found_spent_key_images);

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second);

    // 4. update contexts of stored enotes with found spent key images
    this->update_legacy_with_fresh_found_spent_key_images(found_spent_key_images);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_sp_records_from_ledger(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids,
    const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends)
{
    // 1. update block tracking info
    this->update_with_new_blocks_from_ledger(ScanUpdateMode::SERAPHIS,
        first_new_block,
        alignment_block_id,
        new_block_ids);

    // 2. remove records that will be replaced
    this->clean_maps_for_sp_ledger_update(first_new_block);

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second);

    // 4. update contexts of stored enotes with found spent key images
    this->update_sp_with_fresh_found_spent_key_images(found_spent_key_images);

    // 5. handle legacy key images attached to self-spends (this should be a subset of found_spent_key_images)
    this->handle_legacy_key_images_from_sp_selfsends(legacy_key_images_in_sp_selfsends);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_sp_records_from_offchain(
    const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends)
{
    // 1. remove records that will be replaced
    this->clean_maps_for_sp_offchain_update();

    // 2. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second);

    // 3. update spent contexts of stored enotes with found spent key images
    this->update_sp_with_fresh_found_spent_key_images(found_spent_key_images);

    // 4. handle legacy key images attached to self-spends
    this->handle_legacy_key_images_from_sp_selfsends(legacy_key_images_in_sp_selfsends);
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::has_enote_with_key_image(const crypto::key_image &key_image) const
{
    return m_mapped_sp_contextual_enote_records.find(key_image) != m_mapped_sp_contextual_enote_records.end() ||
        m_legacy_key_images.find(key_image) != m_legacy_key_images.end();
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const
{
    if (block_height < m_refresh_height ||
        block_height > m_refresh_height + m_block_ids.size() - 1 ||
        m_block_ids.size() == 0)
        return false;

    block_id_out = m_block_ids[block_height - m_refresh_height];

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::try_get_block_id_for_scan_mode(const std::uint64_t block_height,
    const ScanUpdateMode scan_update_mode,
    rct::key &block_id_out) const
{
    if (block_height < m_refresh_height ||
        block_height > m_refresh_height + m_block_ids.size() - 1 ||
        m_block_ids.size() == 0)
        return false;

    // assume a block id is 'unknown' to a given scan mode if its height is above the last scanned block height
    switch (scan_update_mode)
    {
        case (ScanUpdateMode::LEGACY_FULL) :
        {
            if (block_height + 1 > m_legacy_fullscan_height + 1)
                return false;
            else
                break;
        }

        case (ScanUpdateMode::LEGACY_INTERMEDIATE) :
        {
            if (block_height + 1 > m_legacy_partialscan_height + 1)
                return false;
            else
                break;
        }

        case (ScanUpdateMode::SERAPHIS) :
        {
            if (block_height + 1 > m_sp_scanned_height + 1)
                return false;
            else
                break;
        }

        default :
            CHECK_AND_ASSERT_THROW_MES(false, "enote store get block id for scan mode (mock): unknown scan mode.");
    }

    block_id_out = m_block_ids[block_height - m_refresh_height];

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t SpEnoteStoreMockV1::get_balance(
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
    const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const
{
    boost::multiprecision::uint128_t balance{0};

    // 1. intermediate legacy enotes (it is unknown if these enotes are spent)
    balance += this->get_balance_intermediate_legacy(origin_statuses, spent_statuses, exclusions);

    // 2. full legacy enotes
    balance += this->get_balance_full_legacy(origin_statuses, spent_statuses, exclusions);

    // 3. seraphis enotes
    balance += this->get_balance_seraphis(origin_statuses, spent_statuses, exclusions);

    return balance;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_new_blocks_from_ledger(const ScanUpdateMode scan_update_mode,
    const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids)
{
    // 1. set new block ids in range [first_new_block, end of chain]
    CHECK_AND_ASSERT_THROW_MES(first_new_block >= m_refresh_height,
        "enote store ledger records update (mock): first new block is below the refresh height.");
    CHECK_AND_ASSERT_THROW_MES(first_new_block - m_refresh_height <= m_block_ids.size(),
        "enote store ledger records update (mock): new blocks don't line up with existing blocks.");
    if (first_new_block > m_refresh_height)
    {
        CHECK_AND_ASSERT_THROW_MES(alignment_block_id == m_block_ids[first_new_block - m_refresh_height - 1],
            "enote store ledger records update (mock): alignment block id doesn't align with recorded block ids.");
    }

    // KLUDGE: assume if scan mode is legacy and there are no new block ids that there was not a reorg (in reality there
    //         could be a reorg that pops blocks into the legacy-supporting chain)
    // - reason: legacy scanning will terminate at the last legacy-supporting block, but seraphis scanning will continue
    //           past that point; a legacy scan with no new blocks (blocks that don't match known blocks) will therefore
    //           look like a reorg that pops blocks even if it just ran into the end of available legacy-supporting blocks,
    //           and if the kludge isn't used then all seraphis-only block ids past that point will get popped by this code
    // - general rule: always do a seraphis scan after any legacy scan to mitigate issues with the enote store caused by
    //                 ledger reorgs of any kind (ideal reorg handling for the legacy/seraphis boundary is an annoying
    //                 design problem that's probably not worth the effort to solve)
    if (new_block_ids.size() > 0 ||
        scan_update_mode == ScanUpdateMode::SERAPHIS)
    {
        // a. find the highest block that the new block ids align with (there can be some overlap in 'new_block_ids' with
        //   'm_block_ids' if a prior scan with a different mode collected some of the same blocks)
        std::uint64_t alignment_block_height{first_new_block - 1};  //we align on the input alignment block (first new - 1)
        for (const rct::key &new_block_id : new_block_ids)
        {
            if (alignment_block_height + 1 - m_refresh_height >= m_block_ids.size())
                break;

            if (!(new_block_id == m_block_ids[alignment_block_height + 1 - m_refresh_height]))
                break;

            ++alignment_block_height;  //we must also align on the next new block, so increment height
        }

        // b. if we are reorging, shove the scan-mode heights back to the last block that they scanned in the reorged chain
        m_legacy_fullscan_height = std::min(m_legacy_fullscan_height + 1, alignment_block_height + 1) - 1;
        m_legacy_partialscan_height = std::min(m_legacy_partialscan_height + 1, alignment_block_height + 1) - 1;
        m_sp_scanned_height = std::min(m_sp_scanned_height + 1, alignment_block_height + 1) - 1;

        // c. add the new block ids
        m_block_ids.resize(alignment_block_height + 1 - m_refresh_height);  //crop old blocks
        m_block_ids.insert(m_block_ids.end(),
            std::next(new_block_ids.begin(), alignment_block_height + 1 - first_new_block),
            new_block_ids.end());
    }

    // 2. update scanning height for this scan mode
    switch (scan_update_mode)
    {
        case (ScanUpdateMode::LEGACY_FULL) :
            this->set_last_legacy_fullscan_height(first_new_block + new_block_ids.size() - 1);
            break;

        case (ScanUpdateMode::LEGACY_INTERMEDIATE) :
            this->set_last_legacy_partialscan_height(first_new_block + new_block_ids.size() - 1);
            break;

        case (ScanUpdateMode::SERAPHIS) :
            this->set_last_sp_scanned_height(first_new_block + new_block_ids.size() - 1);
            break;

        default :
            CHECK_AND_ASSERT_THROW_MES(false, "enote store new blocks update (mock): unknown scan mode.");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::clean_maps_for_legacy_ledger_update(const std::uint64_t first_new_block,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images)
{
    // 1. remove records that will be replaced
    std::unordered_map<rct::key, std::unordered_set<rct::key>> mapped_identifiers_of_removed_enotes;

    auto legacy_contextual_record_is_removable_func =
        [&](const auto &mapped_contextual_enote_record) -> bool
        {
            // a. remove onchain enotes in range [first_new_block, end of chain]
            if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                    SpEnoteOriginStatus::ONCHAIN &&
                mapped_contextual_enote_record.second.m_origin_context.m_block_height >= first_new_block)
            {
                mapped_identifiers_of_removed_enotes[
                        onetime_address_ref(mapped_contextual_enote_record.second.m_record.m_enote)
                    ].insert(mapped_contextual_enote_record.first);

                return true;
            }

            // b. remove all unconfirmed enotes
            if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                    SpEnoteOriginStatus::UNCONFIRMED)
            {
                mapped_identifiers_of_removed_enotes[
                        onetime_address_ref(mapped_contextual_enote_record.second.m_record.m_enote)
                    ].insert(mapped_contextual_enote_record.first);

                return true;
            }

            return false;
        };

    // a. legacy full records
    std::unordered_map<rct::key, crypto::key_image> mapped_key_images_of_removed_enotes;  //mapped to onetime address

    for_all_in_map_erase_if(m_mapped_legacy_contextual_enote_records,
            [&](const std::pair<rct::key, LegacyContextualEnoteRecordV1> &mapped_contextual_enote_record) -> bool
            {
                // a. check if the record is removable
                if (!legacy_contextual_record_is_removable_func(mapped_contextual_enote_record))
                    return false;

                // b. save key images of full records that are to be removed
                mapped_key_images_of_removed_enotes[
                        onetime_address_ref(mapped_contextual_enote_record.second.m_record.m_enote)
                    ] = mapped_contextual_enote_record.second.m_record.m_key_image;

                // c. remove the record
                return true;
            }
        );

    // b. legacy intermediate records
    for_all_in_map_erase_if(m_mapped_legacy_intermediate_contextual_enote_records,
        legacy_contextual_record_is_removable_func);

    // 2. if a found legacy key image is in the 'legacy key images from sp txs' map, remove it from that map
    // - a fresh spent context for legacy key images implies seraphis txs were reorged; we want to guarantee that the
    //   fresh spent contexts are applied to our stored enotes, and doing this step achieves that
    // - save the key images removed so we can clear the corresponding spent contexts in the enote records
    std::unordered_map<crypto::key_image, rct::key> spent_contexts_removed_from_sp_selfsends;
    for (const auto &found_spent_key_image : found_spent_key_images)
    {
        if (m_legacy_key_images_in_sp_selfsends.find(found_spent_key_image.first) ==
            m_legacy_key_images_in_sp_selfsends.end())
            continue;

        spent_contexts_removed_from_sp_selfsends[found_spent_key_image.first] =
            m_legacy_key_images_in_sp_selfsends.at(found_spent_key_image.first).m_transaction_id;

        m_legacy_key_images_in_sp_selfsends.erase(found_spent_key_image.first);
    }

    // 3. clear spent contexts referencing removed blocks or the unconfirmed cache if the corresponding legacy key image
    //    is not in the seraphis legacy key image tracker
    for (auto &mapped_contextual_enote_record : m_mapped_legacy_contextual_enote_records)
    {
        // ignore legacy key images found in seraphis txs that still exist
        if (m_legacy_key_images_in_sp_selfsends.find(mapped_contextual_enote_record.second.m_record.m_key_image) !=
                m_legacy_key_images_in_sp_selfsends.end())
            continue;

        // clear spent contexts in removed legacy blocks
        if (mapped_contextual_enote_record.second.m_spent_context.m_spent_status == SpEnoteSpentStatus::SPENT_ONCHAIN &&
                mapped_contextual_enote_record.second.m_spent_context.m_block_height >= first_new_block)
            mapped_contextual_enote_record.second.m_spent_context = SpEnoteSpentContextV1{};

        // clear spent contexts in the unconfirmed cache
        if (mapped_contextual_enote_record.second.m_spent_context.m_spent_status == SpEnoteSpentStatus::SPENT_UNCONFIRMED)
            mapped_contextual_enote_record.second.m_spent_context = SpEnoteSpentContextV1{};

        // clear spent contexts of key images removed from the seraphis selfsends tracker if the entries removed from the
        //   tracker have the same transaction id (i.e. the spent context recorded next to the key image corresponds with
        //   the removed tracker)
        if (spent_contexts_removed_from_sp_selfsends.find(mapped_contextual_enote_record.second.m_record.m_key_image) !=
                spent_contexts_removed_from_sp_selfsends.end() &&
            spent_contexts_removed_from_sp_selfsends.at(mapped_contextual_enote_record.second.m_record.m_key_image) ==
                mapped_contextual_enote_record.second.m_spent_context.m_transaction_id)
            mapped_contextual_enote_record.second.m_spent_context = SpEnoteSpentContextV1{};
    }

    // 4. clean up legacy trackers
    // a. onetime address duplicate tracker: remove identifiers of removed txs
    for (const auto &mapped_identifiers : mapped_identifiers_of_removed_enotes)
    {
        if (m_tracked_legacy_onetime_address_duplicates.find(mapped_identifiers.first) ==
            m_tracked_legacy_onetime_address_duplicates.end())
            continue;

        for (const rct::key &identifier_of_removed_enote : mapped_identifiers.second)
        {
            m_tracked_legacy_onetime_address_duplicates[mapped_identifiers.first].erase(identifier_of_removed_enote);
        }

        if (m_tracked_legacy_onetime_address_duplicates[mapped_identifiers.first].size() == 0)
            m_tracked_legacy_onetime_address_duplicates.erase(mapped_identifiers.first);
    }

    // b. legacy key image tracker: remove any key images of removed txs if the corresponding onetime addresses don't have
    //    any identifiers registered in the duplicate tracker
    for (const auto &mapped_key_image : mapped_key_images_of_removed_enotes)
    {
        if (m_tracked_legacy_onetime_address_duplicates.find(mapped_key_image.first) == 
            m_tracked_legacy_onetime_address_duplicates.end())
        {
            m_legacy_key_images.erase(mapped_key_image.second);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::clean_maps_for_removed_sp_enotes(const std::unordered_set<rct::key> &tx_ids_of_removed_enotes)
{
    // clear spent contexts referencing the txs of removed enotes (key images appear at the same time as selfsends)

    // 1. seraphis enotes
    for (auto &mapped_contextual_enote_record : m_mapped_sp_contextual_enote_records)
    {
        if (tx_ids_of_removed_enotes.find(mapped_contextual_enote_record.second.m_spent_context.m_transaction_id) ==
                tx_ids_of_removed_enotes.end())
            continue;

        mapped_contextual_enote_record.second.m_spent_context = SpEnoteSpentContextV1{};
    }

    // 2. legacy enotes
    for (auto &mapped_contextual_enote_record : m_mapped_legacy_contextual_enote_records)
    {
        if (tx_ids_of_removed_enotes.find(mapped_contextual_enote_record.second.m_spent_context.m_transaction_id) ==
                tx_ids_of_removed_enotes.end())
            continue;

        mapped_contextual_enote_record.second.m_spent_context = SpEnoteSpentContextV1{};
    }

    // 3. remove legacy key images found in removed txs
    for_all_in_map_erase_if(m_legacy_key_images_in_sp_selfsends,
            [&tx_ids_of_removed_enotes](const std::pair<crypto::key_image, SpEnoteSpentContextV1> &mapped_legacy_key_images)
            -> bool
            {
                return tx_ids_of_removed_enotes.find(mapped_legacy_key_images.second.m_transaction_id) !=
                    tx_ids_of_removed_enotes.end();
            }
        );
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::clean_maps_for_sp_ledger_update(const std::uint64_t first_new_block)
{
    // 1. remove records
    std::unordered_set<rct::key> tx_ids_of_removed_enotes;  //note: only txs with selfsends are needed in practice

    for_all_in_map_erase_if(m_mapped_sp_contextual_enote_records,
            [&](const std::pair<crypto::key_image, SpContextualEnoteRecordV1> &mapped_contextual_enote_record) -> bool
            {
                // a. remove onchain enotes in range [first_new_block, end of chain]
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::ONCHAIN &&
                    mapped_contextual_enote_record.second.m_origin_context.m_block_height >= first_new_block)
                {
                    tx_ids_of_removed_enotes.insert(
                            mapped_contextual_enote_record.second.m_origin_context.m_transaction_id
                        );
                    return true;
                }

                // b. remove all unconfirmed enotes
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::UNCONFIRMED)
                {
                    tx_ids_of_removed_enotes.insert(
                            mapped_contextual_enote_record.second.m_origin_context.m_transaction_id
                        );
                    return true;
                }

                return false;
            }
        );

    // 2. clean maps for removed enotes
    this->clean_maps_for_removed_sp_enotes(tx_ids_of_removed_enotes);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::clean_maps_for_sp_offchain_update()
{
    // 1. remove records
    std::unordered_set<rct::key> tx_ids_of_removed_enotes;  //note: only txs with selfsends are needed in practice

    for_all_in_map_erase_if(m_mapped_sp_contextual_enote_records,
            [&tx_ids_of_removed_enotes](const std::pair<crypto::key_image,
                SpContextualEnoteRecordV1> &mapped_contextual_enote_record) -> bool
            {
                // remove all offchain enotes
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::OFFCHAIN)
                {
                    tx_ids_of_removed_enotes.insert(
                            mapped_contextual_enote_record.second.m_origin_context.m_transaction_id
                        );
                    return true;
                }

                return false;
            }
        );

    // 2. clean maps for removed enotes
    this->clean_maps_for_removed_sp_enotes(tx_ids_of_removed_enotes);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_legacy_with_fresh_found_spent_key_images(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images)
{
    for (const auto &found_spent_key_image : found_spent_key_images)
    {
        // a. ignore key images with unknown legacy enotes
        if (m_legacy_key_images.find(found_spent_key_image.first) == m_legacy_key_images.end())
            continue;

        // b. check that legacy key image map and tracked onetime address maps are consistent
        CHECK_AND_ASSERT_THROW_MES(m_tracked_legacy_onetime_address_duplicates.find(
                m_legacy_key_images.at(found_spent_key_image.first)) != m_tracked_legacy_onetime_address_duplicates.end(),
            "enote store update with legacy enote records (mock): duplicate tracker is missing a onetime address (bug).");

        // c. update spent contexts of any enotes associated with this key image
        const auto &identifiers_of_enotes_to_update =
            m_tracked_legacy_onetime_address_duplicates.at(m_legacy_key_images.at(found_spent_key_image.first));

        for (const rct::key &identifier_of_enote_to_update : identifiers_of_enotes_to_update)
        {
            CHECK_AND_ASSERT_THROW_MES(m_mapped_legacy_contextual_enote_records.find(identifier_of_enote_to_update) !=
                    m_mapped_legacy_contextual_enote_records.end(),
                "enote store update with legacy enote records (mock): full record map is missing identifier (bug).");
            CHECK_AND_ASSERT_THROW_MES(
                    m_mapped_legacy_contextual_enote_records[identifier_of_enote_to_update].m_record.m_key_image ==
                    found_spent_key_image.first,
                "enote store update with legacy enote records (mock): full record map is inconsistent (bug).");

            update_contextual_enote_record_contexts_v1(
                m_mapped_legacy_contextual_enote_records[identifier_of_enote_to_update].m_origin_context,
                found_spent_key_image.second,
                m_mapped_legacy_contextual_enote_records[identifier_of_enote_to_update].m_origin_context,
                m_mapped_legacy_contextual_enote_records[identifier_of_enote_to_update].m_spent_context);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_sp_with_fresh_found_spent_key_images(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images)
{
    for (const auto &found_spent_key_image : found_spent_key_images)
    {
        // a. ignore enotes with unknown key images
        if (m_mapped_sp_contextual_enote_records.find(found_spent_key_image.first) ==
            m_mapped_sp_contextual_enote_records.end())
            continue;

        // b. update this enote's spent context
        update_contextual_enote_record_contexts_v1(
            m_mapped_sp_contextual_enote_records[found_spent_key_image.first].m_origin_context,
            found_spent_key_image.second,
            m_mapped_sp_contextual_enote_records[found_spent_key_image.first].m_origin_context,
            m_mapped_sp_contextual_enote_records[found_spent_key_image.first].m_spent_context);
    }
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t SpEnoteStoreMockV1::get_balance_intermediate_legacy(
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
    const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const
{
    boost::multiprecision::uint128_t balance{0};

    // 1. ignore if requested
    if (exclusions.find(EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE) != exclusions.end())
        return 0;

    // 2. accumulate balance
    // note: it is unknown if enotes in intermediate records are spent
    for (const auto &mapped_contextual_record : m_mapped_legacy_intermediate_contextual_enote_records)
    {
        const LegacyContextualIntermediateEnoteRecordV1 &current_contextual_record{mapped_contextual_record.second};

        // a. only include this enote if its origin status is requested
        if (origin_statuses.find(current_contextual_record.m_origin_context.m_origin_status) == origin_statuses.end())
            continue;

        // b. ignore onchain enotes that are locked
        if (exclusions.find(EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED) != exclusions.end() &&
            current_contextual_record.m_origin_context.m_origin_status == SpEnoteOriginStatus::ONCHAIN &&
            onchain_legacy_enote_is_locked(
                    current_contextual_record.m_origin_context.m_block_height,
                    current_contextual_record.m_record.m_unlock_time,
                    this->top_block_height(),
                    m_default_spendable_age,
                    static_cast<std::uint64_t>(std::time(nullptr)))
                )
            continue;

        // c. ignore enotes that share onetime addresses with other enotes but don't have the highest amount among them
        CHECK_AND_ASSERT_THROW_MES(m_tracked_legacy_onetime_address_duplicates
                    .find(onetime_address_ref(current_contextual_record.m_record.m_enote)) !=
                m_tracked_legacy_onetime_address_duplicates.end(),
            "enote store balance check (mock): tracked legacy duplicates is missing a onetime address (bug).");

        if (!legacy_enote_has_highest_amount_amoung_duplicates(mapped_contextual_record.first,
                current_contextual_record.m_record.m_amount,
                origin_statuses,
                m_tracked_legacy_onetime_address_duplicates.at(
                    onetime_address_ref(current_contextual_record.m_record.m_enote)
                ),
                [this](const rct::key &identifier) -> const SpEnoteOriginStatus&
                {
                    CHECK_AND_ASSERT_THROW_MES(m_mapped_legacy_intermediate_contextual_enote_records.find(
                            identifier) != m_mapped_legacy_intermediate_contextual_enote_records.end(),
                        "enote store balance check (mock): tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy intermediate map even though it should (bug).");

                    return m_mapped_legacy_intermediate_contextual_enote_records
                        .at(identifier)
                        .m_origin_context
                        .m_origin_status;
                },
                [this](const rct::key &identifier) -> rct::xmr_amount
                {
                    CHECK_AND_ASSERT_THROW_MES(m_mapped_legacy_intermediate_contextual_enote_records.find(
                            identifier) != m_mapped_legacy_intermediate_contextual_enote_records.end(),
                        "enote store balance check (mock): tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy intermediate map even though it should (bug).");

                    return m_mapped_legacy_intermediate_contextual_enote_records.at(identifier).m_record.m_amount;
                }))
            continue;

        // d. update balance
        balance += current_contextual_record.m_record.m_amount;
    }

    return balance;
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t SpEnoteStoreMockV1::get_balance_full_legacy(
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
    const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const
{
    boost::multiprecision::uint128_t balance{0};

    // 1. ignore if requested
    if (exclusions.find(EnoteStoreBalanceUpdateExclusions::LEGACY_FULL) != exclusions.end())
        return 0;

    // 2. accumulate balance
    for (const auto &mapped_contextual_record : m_mapped_legacy_contextual_enote_records)
    {
        const LegacyContextualEnoteRecordV1 &current_contextual_record{mapped_contextual_record.second};

        // a. only include this enote if its origin status is requested
        if (origin_statuses.find(current_contextual_record.m_origin_context.m_origin_status) == origin_statuses.end())
            continue;

        // b. if the enote's spent status is requested, then DON'T include this enote
        if (spent_statuses.find(current_contextual_record.m_spent_context.m_spent_status) != spent_statuses.end())
            continue;

        // c. ignore onchain enotes that are locked
        if (exclusions.find(EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED) != exclusions.end() &&
            current_contextual_record.m_origin_context.m_origin_status == SpEnoteOriginStatus::ONCHAIN &&
            onchain_legacy_enote_is_locked(
                    current_contextual_record.m_origin_context.m_block_height,
                    current_contextual_record.m_record.m_unlock_time,
                    this->top_block_height(),
                    m_default_spendable_age,
                    static_cast<std::uint64_t>(std::time(nullptr)))
                )
            continue;

        // d. ignore enotes that share onetime addresses with other enotes but don't have the highest amount among them
        CHECK_AND_ASSERT_THROW_MES(m_tracked_legacy_onetime_address_duplicates
                    .find(onetime_address_ref(current_contextual_record.m_record.m_enote)) !=
                m_tracked_legacy_onetime_address_duplicates.end(),
            "enote store balance check (mock): tracked legacy duplicates is missing a onetime address (bug).");

        if (!legacy_enote_has_highest_amount_amoung_duplicates(mapped_contextual_record.first,
                current_contextual_record.m_record.m_amount,
                origin_statuses,
                m_tracked_legacy_onetime_address_duplicates.at(
                    onetime_address_ref(current_contextual_record.m_record.m_enote)
                ),
                [this](const rct::key &identifier) -> const SpEnoteOriginStatus&
                {
                    CHECK_AND_ASSERT_THROW_MES(m_mapped_legacy_contextual_enote_records.find(identifier) !=
                            m_mapped_legacy_contextual_enote_records.end(),
                        "enote store balance check (mock): tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy map even though it should (bug).");

                    return m_mapped_legacy_contextual_enote_records
                        .at(identifier)
                        .m_origin_context
                        .m_origin_status;
                },
                [this](const rct::key &identifier) -> rct::xmr_amount
                {
                    CHECK_AND_ASSERT_THROW_MES(m_mapped_legacy_contextual_enote_records.find(identifier) != 
                            m_mapped_legacy_contextual_enote_records.end(),
                        "enote store balance check (mock): tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy map even though it should (bug).");

                    return m_mapped_legacy_contextual_enote_records.at(identifier).m_record.m_amount;
                }))
            continue;

        // e. update balance
        balance += current_contextual_record.m_record.m_amount;
    }

    return balance;
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t SpEnoteStoreMockV1::get_balance_seraphis(
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
    const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const
{
    boost::multiprecision::uint128_t balance{0};

    // 1. ignore if requested
    if (exclusions.find(EnoteStoreBalanceUpdateExclusions::SERAPHIS) != exclusions.end())
        return 0;

    // 2. accumulate balance
    for (const auto &mapped_contextual_record : m_mapped_sp_contextual_enote_records)
    {
        const SpContextualEnoteRecordV1 &current_contextual_record{mapped_contextual_record.second};

        // a. only include this enote if its origin status is requested
        if (origin_statuses.find(current_contextual_record.m_origin_context.m_origin_status) == origin_statuses.end())
            continue;

        // b. if the enote's spent status is requested, then DON'T include this enote
        if (spent_statuses.find(current_contextual_record.m_spent_context.m_spent_status) != spent_statuses.end())
            continue;

        // c. ignore onchain enotes that are locked
        if (exclusions.find(EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED) != exclusions.end() &&
            current_contextual_record.m_origin_context.m_origin_status == SpEnoteOriginStatus::ONCHAIN &&
            onchain_sp_enote_is_locked(
                    current_contextual_record.m_origin_context.m_block_height,
                    this->top_block_height(),
                    m_default_spendable_age
                ))
            continue;

        // d. update balance
        balance += current_contextual_record.m_record.m_amount;
    }

    return balance;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockPaymentValidatorV1::add_record(const SpContextualIntermediateEnoteRecordV1 &new_record)
{
    rct::key record_onetime_address;
    new_record.get_onetime_address(record_onetime_address);

    // add the record or update an existing record's origin context
    if (m_mapped_sp_contextual_enote_records.find(record_onetime_address) == m_mapped_sp_contextual_enote_records.end())
    {
        m_mapped_sp_contextual_enote_records[record_onetime_address] = new_record;
    }
    else
    {
        try_update_enote_origin_context_v1(new_record.m_origin_context,
            m_mapped_sp_contextual_enote_records[record_onetime_address].m_origin_context);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockPaymentValidatorV1::update_with_sp_records_from_ledger(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records,
    const std::vector<rct::key> &new_block_ids)
{
    // 1. set new block ids in range [first_new_block, end of chain]
    CHECK_AND_ASSERT_THROW_MES(first_new_block >= m_refresh_height,
        "enote store ledger records update (mock): first new block is below the refresh height.");
    CHECK_AND_ASSERT_THROW_MES(first_new_block - m_refresh_height <= m_block_ids.size(),
        "enote store ledger records update (mock): new blocks don't line up with existing blocks.");
    if (first_new_block > m_refresh_height)
    {
        CHECK_AND_ASSERT_THROW_MES(alignment_block_id == m_block_ids[first_new_block - m_refresh_height - 1],
            "enote store ledger records update (mock): alignment block id doesn't align with recorded block ids.");
    }

    m_block_ids.resize(first_new_block - m_refresh_height);  //crop old blocks
    m_block_ids.insert(m_block_ids.end(), new_block_ids.begin(), new_block_ids.end());

    // 2. remove records that will be replaced
    for_all_in_map_erase_if(m_mapped_sp_contextual_enote_records,
            [first_new_block](
                const std::pair<rct::key, SpContextualIntermediateEnoteRecordV1> &mapped_contextual_enote_record) -> bool
            {
                // a. remove onchain enotes in range [first_new_block, end of chain]
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::ONCHAIN &&
                    mapped_contextual_enote_record.second.m_origin_context.m_block_height >= first_new_block)
                {
                    return true;
                }

                // b. remove all unconfirmed enotes
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::UNCONFIRMED)
                    return true;

                return false;
            }
        );

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockPaymentValidatorV1::update_with_sp_records_from_offchain(
    const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records)
{
    // 1. remove records that will be replaced
    for_all_in_map_erase_if(m_mapped_sp_contextual_enote_records,
            [](const std::pair<rct::key, SpContextualIntermediateEnoteRecordV1> &mapped_contextual_enote_record) -> bool
            {
                // remove all offchain enotes
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::OFFCHAIN)
                    return true;

                return false;
            }
        );

    // 2. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second);
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockPaymentValidatorV1::try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const
{
    if (block_height < m_refresh_height ||
        block_height > m_refresh_height + m_block_ids.size() - 1 ||
        m_block_ids.size() == 0)
        return false;

    block_id_out = m_block_ids[block_height - m_refresh_height];

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t SpEnoteStoreMockPaymentValidatorV1::get_received_sum(
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const
{
    boost::multiprecision::uint128_t received_sum{0};

    for (const auto &mapped_contextual_record : m_mapped_sp_contextual_enote_records)
    {
        const SpContextualIntermediateEnoteRecordV1 &contextual_record{mapped_contextual_record.second};

        // ignore enotes with unrequested origins
        if (origin_statuses.find(contextual_record.m_origin_context.m_origin_status) == origin_statuses.end())
            continue;

        // ignore onchain enotes that are locked
        if (exclusions.find(EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED) != exclusions.end() &&
            contextual_record.m_origin_context.m_origin_status == SpEnoteOriginStatus::ONCHAIN &&
            onchain_sp_enote_is_locked(
                    contextual_record.m_origin_context.m_block_height,
                    this->top_block_height(),
                    m_default_spendable_age
                ))
            continue;

        // update received sum
        received_sum += contextual_record.m_record.m_amount;
    }

    return received_sum;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
