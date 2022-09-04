// Copyright (c) 2021, The Monero Project
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
#include "tx_input_selector_mocks.h"

//local headers
#include "tx_contextual_enote_record_types.h"
#include "tx_contextual_enote_record_utils.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <algorithm>
#include <list>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
bool InputSelectorMockSimpleV1::try_select_input_v1(const boost::multiprecision::uint128_t desired_total_amount,
    const std::list<ContextualRecordVariant> &already_added_inputs,
    const std::list<ContextualRecordVariant> &already_excluded_inputs,
    ContextualRecordVariant &selected_input_out) const
{
    // note: the simple input selector only has sp contextual records
    for (const SpContextualEnoteRecordV1 &contextual_enote_record : m_enote_store.m_contextual_enote_records)
    {
        // only consider unspent enotes
        if (!contextual_enote_record.has_spent_status(SpEnoteSpentStatus::UNSPENT))
            continue;

        // prepare record finder
        auto record_finder =
            [&contextual_enote_record](const ContextualRecordVariant &comparison_record) -> bool
            {
                if (!comparison_record.is_type<SpContextualEnoteRecordV1>())
                    return false;

                return SpContextualEnoteRecordV1::same_destination(contextual_enote_record,
                    comparison_record.get_contextual_record<SpContextualEnoteRecordV1>());
            };

        // ignore already added inputs
        if (std::find_if(already_added_inputs.begin(), already_added_inputs.end(), record_finder) !=
                already_added_inputs.end())
            continue;

        // ignore already excluded inputs
        if (std::find_if(already_excluded_inputs.begin(), already_excluded_inputs.end(), record_finder) !=
                already_excluded_inputs.end())
            continue;

        selected_input_out = contextual_enote_record;
        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool InputSelectorMockV1::try_select_input_v1(const boost::multiprecision::uint128_t desired_total_amount,
    const std::list<ContextualRecordVariant> &already_added_inputs,
    const std::list<ContextualRecordVariant> &already_excluded_inputs,
    ContextualRecordVariant &selected_input_out) const
{
    // 1. try to select from legacy enotes
    const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &mapped_legacy_contextual_enote_records{
            m_enote_store.m_mapped_legacy_contextual_enote_records
        };
    for (const auto &mapped_enote_record : mapped_legacy_contextual_enote_records)
    {
        // only consider unspent enotes
        if (!mapped_enote_record.second.has_spent_status(SpEnoteSpentStatus::UNSPENT))
            continue;

        // prepare record finder
        auto record_finder =
            [&mapped_enote_record](const ContextualRecordVariant &comparison_record) -> bool
            {
                if (!comparison_record.is_type<LegacyContextualEnoteRecordV1>())
                    return false;

                return LegacyContextualEnoteRecordV1::same_destination(mapped_enote_record.second,
                    comparison_record.get_contextual_record<LegacyContextualEnoteRecordV1>());
            };

        // ignore already added inputs
        if (std::find_if(already_added_inputs.begin(), already_added_inputs.end(), record_finder) !=
                already_added_inputs.end())
            continue;

        // ignore already excluded inputs
        if (std::find_if(already_excluded_inputs.begin(), already_excluded_inputs.end(), record_finder) !=
                already_excluded_inputs.end())
            continue;

        // if this legacy enote shares a onetime address with any other legacy enotes, only proceed if this one
        //   has the highest amount
        if (!legacy_enote_has_highest_amount_amoung_duplicates(mapped_enote_record.first,
                mapped_enote_record.second.m_record.m_amount,
                {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED, SpEnoteOriginStatus::ONCHAIN},
                m_enote_store.m_tracked_legacy_onetime_address_duplicates.at(
                    mapped_enote_record.second.m_record.m_enote.onetime_address()
                ),
                [&mapped_legacy_contextual_enote_records](const rct::key &identifier)
                    -> const SpEnoteOriginStatus&
                {
                    CHECK_AND_ASSERT_THROW_MES(mapped_legacy_contextual_enote_records.find(identifier) !=
                            mapped_legacy_contextual_enote_records.end(),
                        "input selector (mock): tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy map even though it should (bug).");

                    return mapped_legacy_contextual_enote_records.at(identifier).m_origin_context.m_origin_status;
                },
                [&mapped_legacy_contextual_enote_records](const rct::key &identifier)
                    -> rct::xmr_amount
                {
                    CHECK_AND_ASSERT_THROW_MES(mapped_legacy_contextual_enote_records.find(identifier) != 
                            mapped_legacy_contextual_enote_records.end(),
                        "input selector (mock): tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy map even though it should (bug).");

                    return mapped_legacy_contextual_enote_records.at(identifier).m_record.m_amount;
                }))
            continue;

        selected_input_out = mapped_enote_record.second;
        return true;
    }

    // 2. try to select from seraphis enotes
    for (const auto &mapped_enote_record : m_enote_store.m_mapped_sp_contextual_enote_records)
    {
        // only consider unspent enotes
        if (!mapped_enote_record.second.has_spent_status(SpEnoteSpentStatus::UNSPENT))
            continue;

        // prepare record finder
        auto record_finder =
            [&mapped_enote_record](const ContextualRecordVariant &comparison_record) -> bool
            {
                if (!comparison_record.is_type<SpContextualEnoteRecordV1>())
                    return false;

                return SpContextualEnoteRecordV1::same_destination(mapped_enote_record.second,
                    comparison_record.get_contextual_record<SpContextualEnoteRecordV1>());
            };

        // ignore already added inputs
        if (std::find_if(already_added_inputs.begin(), already_added_inputs.end(), record_finder) !=
                already_added_inputs.end())
            continue;

        // ignore already excluded inputs
        if (std::find_if(already_excluded_inputs.begin(), already_excluded_inputs.end(), record_finder) !=
                already_excluded_inputs.end())
            continue;

        selected_input_out = mapped_enote_record.second;
        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
