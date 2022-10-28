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
#include "tx_contextual_enote_record_utils.h"

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "tx_contextual_enote_record_types.h"
#include "tx_input_selection.h"

//third party headers

//standard headers
#include <functional>
#include <list>
#include <map>
#include <unordered_set>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
bool legacy_enote_has_highest_amount_amoung_duplicates(const rct::key &searched_for_record_identifier,
    const rct::xmr_amount &searched_for_record_amount,
    const std::unordered_set<SpEnoteOriginStatus> &requested_origin_statuses,
    const std::unordered_set<rct::key> &duplicate_onetime_address_identifiers,
    const std::function<const SpEnoteOriginStatus&(const rct::key&)> &get_record_origin_status_for_identifier_func,
    const std::function<rct::xmr_amount(const rct::key&)> &get_record_amount_for_identifier_func)
{
    std::map<rct::xmr_amount, rct::key> eligible_amounts;

    for (const rct::key &candidate_identifier : duplicate_onetime_address_identifiers)
    {
        // only include enotes with requested origin statuses
        if (requested_origin_statuses.find(get_record_origin_status_for_identifier_func(candidate_identifier)) ==
                requested_origin_statuses.end())
            continue;

        // record this identifier
        const rct::xmr_amount amount{get_record_amount_for_identifier_func(candidate_identifier)};
        CHECK_AND_ASSERT_THROW_MES(eligible_amounts.find(amount) == eligible_amounts.end(),
            "legacy enote duplicate onetime address amount search: found the same amount multiple times (legacy enote "
            "identifiers are a hash of the amount, so there should not be multiple identifiers with the same amount, "
            "assuming all identifiers correspond to the same onetime address as they should here).");

        eligible_amounts[amount] = candidate_identifier;
    }

    // we should have found the searched-for record's amount
    CHECK_AND_ASSERT_THROW_MES(eligible_amounts.find(searched_for_record_amount) != eligible_amounts.end(),
        "legacy enote duplicate onetime address amount search: could not find the searched-for record's amount.");

    // success if the highest eligible amount is attached to the searched-for identifier
    return eligible_amounts.rbegin()->second == searched_for_record_identifier;
}
//-------------------------------------------------------------------------------------------------------------------
void split_selected_input_set(const input_set_tracker_t &input_set,
    std::list<LegacyContextualEnoteRecordV1> &legacy_contextual_records_out,
    std::list<SpContextualEnoteRecordV1> &sp_contextual_records_out)
{
    legacy_contextual_records_out.clear();
    sp_contextual_records_out.clear();

    if (input_set.find(InputSelectionType::LEGACY) != input_set.end())
    {
        for (const auto &mapped_contextual_enote_record : input_set.at(InputSelectionType::LEGACY))
        {
            CHECK_AND_ASSERT_THROW_MES(mapped_contextual_enote_record.second.is_type<LegacyContextualEnoteRecordV1>(),
                "splitting an input set (legacy): record is supposed to be legacy but is not.");

            legacy_contextual_records_out.emplace_back(
                    mapped_contextual_enote_record.second.contextual_record<LegacyContextualEnoteRecordV1>()
                );
        }
    }

    if (input_set.find(InputSelectionType::SERAPHIS) != input_set.end())
    {
        for (const auto &mapped_contextual_enote_record : input_set.at(InputSelectionType::SERAPHIS))
        {
            CHECK_AND_ASSERT_THROW_MES(mapped_contextual_enote_record.second.is_type<SpContextualEnoteRecordV1>(),
                "splitting an input set (legacy): record is supposed to be seraphis but is not.");

            sp_contextual_records_out.emplace_back(
                    mapped_contextual_enote_record.second.contextual_record<SpContextualEnoteRecordV1>()
                );
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool try_update_enote_origin_context_v1(const SpEnoteOriginContextV1 &fresh_origin_context,
    SpEnoteOriginContextV1 &current_origin_context_inout)
{
    // use the oldest origin context available (overwrite if apparently the same age)
    if (current_origin_context_inout.is_older_than(fresh_origin_context))
        return false;

    current_origin_context_inout = fresh_origin_context;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_update_enote_spent_context_v1(const SpEnoteSpentContextV1 &fresh_spent_context,
    SpEnoteSpentContextV1 &current_spent_context_inout)
{
    // use the oldest origin context available (overwrite if apparently the same age)
    if (current_spent_context_inout.is_older_than(fresh_spent_context))
        return false;

    current_spent_context_inout = fresh_spent_context;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_update_contextual_enote_record_spent_context_v1(const SpContextualKeyImageSetV1 &contextual_key_image_set,
    SpContextualEnoteRecordV1 &contextual_enote_record_inout)
{
    if (!contextual_key_image_set.has_key_image(contextual_enote_record_inout.key_image()))
        return false;

    return try_update_enote_spent_context_v1(contextual_key_image_set.m_spent_context,
        contextual_enote_record_inout.m_spent_context);
}
//-------------------------------------------------------------------------------------------------------------------
SpEnoteOriginStatus origin_status_from_spent_status_v1(const SpEnoteSpentStatus spent_status)
{
    switch (spent_status)
    {
        case (SpEnoteSpentStatus::UNSPENT) :
            return SpEnoteOriginStatus::OFFCHAIN;

        case (SpEnoteSpentStatus::SPENT_OFFCHAIN) :
            return SpEnoteOriginStatus::OFFCHAIN;

        case (SpEnoteSpentStatus::SPENT_UNCONFIRMED) :
            return SpEnoteOriginStatus::UNCONFIRMED;

        case (SpEnoteSpentStatus::SPENT_ONCHAIN) :
            return SpEnoteOriginStatus::ONCHAIN;

        default :
            return SpEnoteOriginStatus::OFFCHAIN;
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool try_bump_enote_record_origin_status_v1(const SpEnoteSpentStatus spent_status,
    SpEnoteOriginStatus &origin_status_inout)
{
    const SpEnoteOriginStatus implied_origin_status{origin_status_from_spent_status_v1(spent_status)};

    if (origin_status_inout > implied_origin_status)
        return false;

    origin_status_inout = implied_origin_status;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void update_contextual_enote_record_contexts_v1(const SpEnoteOriginContextV1 &new_origin_context,
    const SpEnoteSpentContextV1 &new_spent_context,
    SpEnoteOriginContextV1 &origin_context_inout,
    SpEnoteSpentContextV1 &spent_context_inout)
{
    try_update_enote_spent_context_v1(new_spent_context, spent_context_inout);
    try_update_enote_origin_context_v1(new_origin_context, origin_context_inout);
    try_bump_enote_record_origin_status_v1(spent_context_inout.m_spent_status,
       origin_context_inout.m_origin_status);
}
//-------------------------------------------------------------------------------------------------------------------
void update_contextual_enote_record_contexts_v1(const SpContextualEnoteRecordV1 &fresh_record,
    SpContextualEnoteRecordV1 &existing_record_inout)
{
    CHECK_AND_ASSERT_THROW_MES(fresh_record.m_record.m_key_image == existing_record_inout.m_record.m_key_image,
        "updating a contextual enote record: the fresh record doesn't represent the same enote.");

    update_contextual_enote_record_contexts_v1(fresh_record.m_origin_context,
        fresh_record.m_spent_context,
        existing_record_inout.m_origin_context,
        existing_record_inout.m_spent_context);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
