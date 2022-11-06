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

// Utilities for interacting with contextual enote records.


#pragma once

//local headers
#include "ringct/rctTypes.h"
#include "tx_contextual_enote_record_types.h"
#include "tx_input_selection.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <functional>
#include <list>
#include <unordered_set>

//forward declarations


namespace sp
{

//todo
bool legacy_enote_has_highest_amount_amoung_duplicates(const rct::key &searched_for_record_identifier,
    const rct::xmr_amount &searched_for_record_amount,
    const std::unordered_set<SpEnoteOriginStatus> &requested_origin_statuses,
    const std::unordered_set<rct::key> &duplicate_onetime_address_identifiers,
    const std::function<const SpEnoteOriginStatus&(const rct::key&)> &get_record_origin_status_for_identifier_func,
    const std::function<rct::xmr_amount(const rct::key&)> &get_record_amount_for_identifier_func);

//todo
void split_selected_input_set(const input_set_tracker_t &input_set,
    std::list<LegacyContextualEnoteRecordV1> &legacy_contextual_records_out,
    std::list<SpContextualEnoteRecordV1> &sp_contextual_records_out);

//todo
boost::multiprecision::uint128_t total_amount(const std::list<LegacyContextualEnoteRecordV1> &contextual_records);
boost::multiprecision::uint128_t total_amount(const std::list<SpContextualEnoteRecordV1> &contextual_records);

/// [ KI : enote index ] is a convenience map for connecting input proposals or partial inputs to their ledger locations,
///   which is needed when making membership proofs
//todo
bool try_get_membership_proof_real_reference_mappings(const std::list<LegacyContextualEnoteRecordV1> &contextual_records,
    std::unordered_map<crypto::key_image, std::uint64_t> &ledger_mappings_out);
bool try_get_membership_proof_real_reference_mappings(const std::list<SpContextualEnoteRecordV1> &contextual_records,
    std::unordered_map<crypto::key_image, std::uint64_t> &ledger_mappings_out);

//todo
bool try_update_enote_origin_context_v1(const SpEnoteOriginContextV1 &fresh_origin_context,
    SpEnoteOriginContextV1 &current_origin_context_inout);
bool try_update_enote_spent_context_v1(const SpEnoteSpentContextV1 &fresh_spent_context,
    SpEnoteSpentContextV1 &current_spent_context_inout);
bool try_update_contextual_enote_record_spent_context_v1(const SpContextualKeyImageSetV1 &contextual_key_image_set,
    SpContextualEnoteRecordV1 &contextual_enote_record_inout);
//todo
SpEnoteOriginStatus origin_status_from_spent_status_v1(const SpEnoteSpentStatus spent_status);
bool try_bump_enote_record_origin_status_v1(const SpEnoteSpentStatus spent_status,
    SpEnoteOriginStatus &origin_status_inout);
//todo
void update_contextual_enote_record_contexts_v1(const SpEnoteOriginContextV1 &new_origin_context,
    const SpEnoteSpentContextV1 &new_spent_context,
    SpEnoteOriginContextV1 &origin_context_inout,
    SpEnoteSpentContextV1 &spent_context_inout);
void update_contextual_enote_record_contexts_v1(const SpContextualEnoteRecordV1 &fresh_record,
    SpContextualEnoteRecordV1 &existing_record_inout);

} //namespace sp
