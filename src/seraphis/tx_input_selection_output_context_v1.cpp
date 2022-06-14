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
#include "tx_input_selection_output_context_v1.h"

//local headers
#include "crypto/crypto.h"
#include "jamtis_payment_proposal.h"
#include "jamtis_support_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "tx_builders_outputs.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <algorithm>
#include <unordered_set>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// check that all enote ephemeral pubkeys in an output proposal set are unique
//-------------------------------------------------------------------------------------------------------------------
static bool ephemeral_pubkeys_are_unique(const std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals,
    const std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals)
{
    // record all as 8*K_e to remove torsion elements if they exist
    std::unordered_set<rct::key> enote_ephemeral_pubkeys;
    rct::key temp_enote_ephemeral_pubkey;

    for (const jamtis::JamtisPaymentProposalV1 &normal_proposal : normal_payment_proposals)
    {
        normal_proposal.get_enote_ephemeral_pubkey(temp_enote_ephemeral_pubkey);
        enote_ephemeral_pubkeys.insert(rct::scalarmultKey(temp_enote_ephemeral_pubkey, rct::EIGHT));
    }

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_payment_proposals)
    {
        selfsend_proposal.get_enote_ephemeral_pubkey(temp_enote_ephemeral_pubkey);
        enote_ephemeral_pubkeys.insert(rct::scalarmultKey(temp_enote_ephemeral_pubkey, rct::EIGHT));
    }

    return enote_ephemeral_pubkeys.size() == normal_payment_proposals.size() + selfsend_payment_proposals.size();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::size_t compute_num_additional_outputs(const std::size_t num_outputs,
    const bool output_ephemeral_pubkeys_are_unique,
    const std::vector<jamtis::JamtisSelfSendType> &self_send_output_types,
    const rct::xmr_amount change_amount)
{
    // get additional outputs
    std::vector<OutputProposalSetExtraTypesV1> additional_outputs;

    get_additional_output_types_for_output_set_v1(num_outputs,
        self_send_output_types,
        output_ephemeral_pubkeys_are_unique,
        change_amount,
        additional_outputs);

    return additional_outputs.size();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
OutputSetContextForInputSelectionV1::OutputSetContextForInputSelectionV1(
    const std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals,
    const std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals) :
        m_num_outputs{normal_payment_proposals.size() + selfsend_payment_proposals.size()},
        m_output_ephemeral_pubkeys_are_unique{
                ephemeral_pubkeys_are_unique(normal_payment_proposals, selfsend_payment_proposals)
            }
{
    // collect self-send output types
    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_payment_proposals)
        m_self_send_output_types.emplace_back(selfsend_proposal.m_type);

    // collect total amount
    m_total_output_amount = 0;

    for (const jamtis::JamtisPaymentProposalV1 &normal_proposal : normal_payment_proposals)
        m_total_output_amount += normal_proposal.m_amount;

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_payment_proposals)
        m_total_output_amount += selfsend_proposal.m_amount;
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t OutputSetContextForInputSelectionV1::get_total_amount() const
{
    return m_total_output_amount;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t OutputSetContextForInputSelectionV1::get_num_outputs_nochange() const
{
    const std::size_t num_additional_outputs_no_change{
        compute_num_additional_outputs(m_num_outputs, m_output_ephemeral_pubkeys_are_unique, m_self_send_output_types, 0)
    };

    return m_num_outputs + num_additional_outputs_no_change;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t OutputSetContextForInputSelectionV1::get_num_outputs_withchange() const
{
    const std::size_t num_additional_outputs_with_change{
        compute_num_additional_outputs(m_num_outputs, m_output_ephemeral_pubkeys_are_unique, m_self_send_output_types, 1)
    };

    return m_num_outputs + num_additional_outputs_with_change;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp