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

// Seraphis tx-builder/component-builder implementations (legacy tx inputs).


#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_ledger_context.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types_legacy.h"
#include "tx_component_types_legacy.h"
#include "tx_enote_record_types.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

//todo
void prepare_legacy_input_commitment_factors_for_balance_proof_v1(const std::vector<LegacyInputProposalV1> &input_proposals,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out);
void prepare_legacy_input_commitment_factors_for_balance_proof_v1(const std::vector<LegacyInputV1> &inputs,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out);

/**
* brief: make_tx_legacy_ring_signature_message_v1 - message for legacy ring signatures
*   - H_32(tx proposal message, {reference set indices})
* param: tx_proposal_message - represents the transaction being signed (inputs, outputs, and memos), excluding proofs
* param: reference_set_indices - indices into the ledger's set of legacy enotes
* outparam: message_out - the message to sign in a legacy ring signature
*/
void make_tx_legacy_ring_signature_message_v1(const rct::key &tx_proposal_message,
    const std::vector<std::uint64_t> &reference_set_indices,
    rct::key &message_out);
//todo
void check_v1_legacy_input_proposal_semantics_v1(const LegacyInputProposalV1 &input_proposal,
    const rct::key &legacy_spend_pubkey);
void make_v1_legacy_input_proposal_v1(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    const crypto::key_image &key_image,
    const crypto::secret_key &enote_view_privkey,
    const crypto::secret_key &input_amount_blinding_factor,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &commitment_mask,
    SpInputProposal &proposal_out);
void make_v1_legacy_input_proposal_v1(const LegacyEnoteRecord &enote_record,
    const crypto::secret_key &commitment_mask,
    LegacyInputProposalV1 &proposal_out);
//todo
void make_v3_legacy_ring_signature_v1(const rct::key &tx_proposal_prefix,
    std::vector<std::uint64_t> reference_set,
    const rct::ctkeyV &referenced_enotes,
    const std::uint64_t real_reference_index,
    const rct::key &masked_commitment,
    const crypto::secret_key &reference_view_privkey,
    const crypto::secret_key &reference_commitment_mask,
    const crypto::secret_key &legacy_spend_privkey,
    LegacyRingSignatureV3 &ring_signature_out);
void make_v3_legacy_ring_signature_v1(LegacyRingSignaturePrepV1 ring_signature_prep,
    const crypto::secret_key &legacy_spend_privkey,
    LegacyRingSignatureV3 &ring_signature_out);
void make_v3_legacy_ring_signatures_v1(std::vector<LegacyRingSignaturePrepV1> ring_signature_preps,
    const crypto::secret_key &legacy_spend_privkey,
    std::vector<LegacyRingSignatureV3> &ring_signatures_out);
//todo
void check_v1_legacy_input_semantics_v1(const LegacyInputV1 &input);
void make_v1_legacy_input_v1(const rct::key &proposal_prefix,
    const LegacyInputProposalV1 &input_proposal,
    rct::ctkeyV referenced_enotes,
    LegacyRingSignatureV3 ring_signature,
    const rct::key &legacy_spend_pubkey,
    LegacyInputV1 &input_out);
void make_v1_legacy_input_v1(const rct::key &proposal_prefix,
    const LegacyInputProposalV1 &input_proposal,
    LegacyRingSignaturePrepV1 ring_signature_prep,
    const crypto::secret_key &legacy_spend_privkey,
    LegacyInputV1 &input_out);
void make_v1_legacy_inputs_v1(const rct::key &proposal_prefix,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    std::vector<LegacyRingSignaturePrepV1> ring_signature_preps,
    const crypto::secret_key &legacy_spend_privkey,
    std::vector<LegacyInputV1> &inputs_out);
//todo
std::vector<LegacyInputProposalV1> gen_mock_legacy_input_proposals_v1(const crypto::secret_key &legacy_spend_privkey,
    const std::vector<rct::xmr_amount> &input_amounts);
void gen_mock_legacy_ring_signature_members_for_enote_at_pos_v1(const std::uint64_t real_reference_index_in_ledger,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context,
    std::vector<std::uint64_t> &reference_set_out,
    rct::ctkeyV &referenced_enotes_out,
    std::uint64_t &real_reference_index_out);
LegacyRingSignaturePrepV1 gen_mock_legacy_ring_signature_prep_for_enote_at_pos_v1(const rct::key &proposal_prefix,
    const std::uint64_t real_reference_index_in_ledger,
    const LegacyEnoteImageV2 &real_reference_image,
    const crypto::secret_key &real_reference_view_privkey,
    const crypto::secret_key &commitment_mask,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context);
LegacyRingSignaturePrepV1 gen_mock_legacy_ring_signature_prep_v1(const rct::key &proposal_prefix,
    const rct::ctkey &real_reference_enote,
    const LegacyEnoteImageV2 &real_reference_image,
    const crypto::secret_key &real_reference_view_privkey,
    const crypto::secret_key &commitment_mask,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout);
std::vector<LegacyRingSignaturePrepV1> gen_mock_legacy_ring_signature_preps_v1(const rct::key &proposal_prefix,
    const rct::ctkeyV &real_referenced_enotes,
    const std::vector<LegacyEnoteImageV2> &real_reference_images,
    const std::vector<crypto::secret_key> &real_reference_view_privkeys,
    const std::vector<crypto::secret_key> &commitment_masks,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout);
std::vector<LegacyRingSignaturePrepV1> gen_mock_legacy_ring_signature_preps_v1(const rct::key &proposal_prefix,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout);
void make_mock_legacy_ring_signature_preps_for_inputs_v1(const rct::key &proposal_prefix,
    const std::unordered_map<crypto::key_image, std::uint64_t> &input_ledger_mappings,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context,
    std::vector<LegacyRingSignaturePrepV1> &ring_signature_preps_out);

} //namespace sp
