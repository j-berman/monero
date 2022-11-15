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
#include "tx_builder_types_multisig.h"

//local headers
#include "crypto/crypto.h"
#include "cryptonote_basic/subaddress_index.h"
#include "legacy_core_utils.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_misc_utils.h"
#include "sp_core_enote_utils.h"
#include "tx_builder_types.h"
#include "tx_builder_types_legacy.h"
#include "tx_builders_inputs.h"
#include "tx_builders_legacy_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_component_types_legacy.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils_legacy.h"
#include "tx_extra.h"

//third party headers

//standard headers
#include <unordered_map>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void LegacyMultisigInputProposalV1::get_input_proposal_v1(const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    LegacyInputProposalV1 &input_proposal_out) const
{
    // extract legacy intermediate enote record from proposal
    LegacyIntermediateEnoteRecord legacy_intermediate_record;

    CHECK_AND_ASSERT_THROW_MES(try_get_legacy_intermediate_enote_record(m_enote,
            m_enote_ephemeral_pubkey,
            m_tx_output_index,
            m_unlock_time,
            legacy_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            legacy_intermediate_record),
        "legacy multisig public input proposal to legacy input proposal: could not recover intermediate enote record for "
        "input proposal's enote.");

    // upgrade to full legacy enote record
    LegacyEnoteRecord legacy_enote_record;
    get_legacy_enote_record(legacy_intermediate_record, m_key_image, legacy_enote_record);

    // make the legacy input proposal
    make_v1_legacy_input_proposal_v1(legacy_enote_record, m_commitment_mask, input_proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool LegacyMultisigInputProposalV1::matches_with(const multisig::CLSAGMultisigProposal &proof_proposal) const
{
    // onetime address to sign
    if (!(proof_proposal.main_proof_key() == onetime_address_ref(m_enote)))
        return false;

    // amount commitment to sign
    const rct::key amount_commitment{amount_commitment_ref(m_enote)};
    if (!(proof_proposal.auxilliary_proof_key() == amount_commitment))
        return false;

    // pseudo-output commitment
    rct::key masked_commitment;
    mask_key(m_commitment_mask, amount_commitment, masked_commitment);
    if (!(proof_proposal.masked_C == masked_commitment))
        return false;

    // key image
    if (!(proof_proposal.KI == m_key_image))
        return false;

    // auxilliary key image
    crypto::key_image auxilliary_key_image;
    make_legacy_auxilliary_key_image_v1(m_commitment_mask, onetime_address_ref(m_enote), auxilliary_key_image);

    if (!(proof_proposal.D == auxilliary_key_image))
        return false;

    // references line up 1:1
    if (m_reference_set.size() != proof_proposal.ring_members.size())
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool LegacyMultisigInputProposalV1::matches_with(const LegacyEnoteRecord &enote_record) const
{
    // onetime address
    if (!(onetime_address_ref(enote_record.m_enote) == onetime_address_ref(m_enote)))
        return false;

    // amount commitment
    if (!(amount_commitment_ref(enote_record.m_enote) == amount_commitment_ref(m_enote)))
        return false;

    // key image
    if (!(enote_record.m_key_image == m_key_image))
        return false;

    // misc
    if (!(enote_record.m_enote_ephemeral_pubkey == m_enote_ephemeral_pubkey))
        return false;
    if (!(enote_record.m_tx_output_index == m_tx_output_index))
        return false;
    if (!(enote_record.m_unlock_time >= m_unlock_time))  //>= in case of duplicate enotes
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultisigInputProposalV1::get_input_proposal_v1(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpInputProposalV1 &input_proposal_out) const
{
    CHECK_AND_ASSERT_THROW_MES(try_make_v1_input_proposal_v1(m_enote,
            m_enote_ephemeral_pubkey,
            m_input_context,
            jamtis_spend_pubkey,
            k_view_balance,
            m_address_mask,
            m_commitment_mask,
            input_proposal_out),
        "multisig seraphis public input proposal to seraphis input proposal: conversion failed (wallet may not own "
        "this input.");
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultisigTxProposalV1::get_v1_tx_proposal_v1(const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpTxProposalV1 &tx_proposal_out) const
{
    // extract legacy input proposals
    std::vector<LegacyInputProposalV1> legacy_input_proposals;

    for (const LegacyMultisigInputProposalV1 &multisig_input_proposal : m_legacy_multisig_input_proposals)
    {
        multisig_input_proposal.get_input_proposal_v1(legacy_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            add_element(legacy_input_proposals));
    }

    // extract seraphis input proposals
    std::vector<SpInputProposalV1> sp_input_proposals;

    for (const SpMultisigInputProposalV1 &multisig_input_proposal : m_sp_multisig_input_proposals)
    {
        multisig_input_proposal.get_input_proposal_v1(jamtis_spend_pubkey,
            k_view_balance,
            add_element(sp_input_proposals));
    }

    // extract memo field elements
    std::vector<ExtraFieldElement> additional_memo_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(m_partial_memo, additional_memo_elements),
        "multisig tx proposal: could not parse partial memo.");

    // make the tx proposal
    make_v1_tx_proposal_v1(m_normal_payment_proposals,
        m_selfsend_payment_proposals,
        m_tx_fee,
        std::move(legacy_input_proposals),
        std::move(sp_input_proposals),
        std::move(additional_memo_elements),
        tx_proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultisigTxProposalV1::get_proposal_prefix_v1(const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    rct::key &proposal_prefix_out) const
{
    // extract proposal
    SpTxProposalV1 tx_proposal;
    this->get_v1_tx_proposal_v1(legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    // get prefix from proposal
    tx_proposal.get_proposal_prefix(m_version_string, k_view_balance, proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
