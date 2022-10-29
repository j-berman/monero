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
#include "tx_builders_mixed.h"

//local headers
#include "bulletproofs_plus2.h"
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "jamtis_core_utils.h"
#include "jamtis_support_types.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_config_temp.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_misc_utils.h"
#include "sp_transcript.h"
#include "tx_builder_types.h"
#include "tx_builders_inputs.h"
#include "tx_builders_legacy_inputs.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_contextual_enote_record_utils.h"
#include "tx_input_selection_output_context_v1.h"
#include "tx_legacy_component_types.h"
#include "tx_validation_context_mock.h"
#include "txtype_squashed_v1.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// convert a crypto::secret_key vector to an rct::key vector, and obtain a memwiper for the rct::key vector
//-------------------------------------------------------------------------------------------------------------------
static auto convert_skv_to_rctv(const std::vector<crypto::secret_key> &skv, rct::keyV &rctv_out)
{
    auto a_wiper = epee::misc_utils::create_scope_leave_handler(
            [&rctv_out]()
            {
                memwipe(rctv_out.data(), rctv_out.size()*sizeof(rct::key));
            }
        );

    rctv_out.clear();
    rctv_out.reserve(skv.size());

    for (const crypto::secret_key &skey : skv)
        rctv_out.emplace_back(rct::sk2rct(skey));

    return a_wiper;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool same_key_image(const LegacyInputV1 &input, const LegacyInputProposalV1 &input_proposal)
{
    return input.m_input_image.m_key_image == input_proposal.m_key_image;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool same_key_image(const SpPartialInputV1 &partial_input, const SpInputProposalV1 &input_proposal)
{
    return partial_input.m_input_image.m_core.m_key_image == input_proposal.m_core.m_key_image;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void legacy_enote_records_to_input_proposals(
    const std::list<LegacyContextualEnoteRecordV1> &legacy_contextual_records,
    std::vector<LegacyInputProposalV1> &legacy_input_proposals_out,
    std::unordered_map<crypto::key_image, std::uint64_t> &legacy_input_ledger_mappings_out)
{
    legacy_input_proposals_out.clear();
    legacy_input_ledger_mappings_out.clear();
    legacy_input_proposals_out.reserve(legacy_contextual_records.size());

    for (const LegacyContextualEnoteRecordV1 &legacy_contextual_input : legacy_contextual_records)
    {
        // save input indices for making legacy ring signatures
        legacy_input_ledger_mappings_out[legacy_contextual_input.m_record.m_key_image] = 
            legacy_contextual_input.m_origin_context.m_enote_ledger_index;

        // convert legacy inputs to input proposals
        make_v1_legacy_input_proposal_v1(legacy_contextual_input.m_record,
            rct::rct2sk(rct::skGen()),
            add_element(legacy_input_proposals_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void sp_enote_records_to_input_proposals(const std::list<SpContextualEnoteRecordV1> &sp_contextual_records,
    std::vector<SpInputProposalV1> &sp_input_proposals_out,
    std::unordered_map<crypto::key_image, std::uint64_t> &sp_input_ledger_mappings_out)
{
    sp_input_proposals_out.clear();
    sp_input_ledger_mappings_out.clear();
    sp_input_proposals_out.reserve(sp_contextual_records.size());

    for (const SpContextualEnoteRecordV1 &sp_contextual_input : sp_contextual_records)
    {
        // save input indices for making seraphis membership proofs
        sp_input_ledger_mappings_out[sp_contextual_input.m_record.m_key_image] = 
            sp_contextual_input.m_origin_context.m_enote_ledger_index;

        // convert seraphis inputs to input proposals
        make_v1_input_proposal_v1(sp_contextual_input.m_record,
            rct::rct2sk(rct::skGen()),
            rct::rct2sk(rct::skGen()),
            add_element(sp_input_proposals_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void collect_legacy_ring_signature_ring_members(const std::vector<LegacyRingSignatureV3> &legacy_ring_signatures,
    const std::vector<rct::ctkeyV> &legacy_ring_signature_rings,
    std::unordered_map<std::uint64_t, rct::ctkey> &legacy_reference_set_proof_elements_out)
{
    // map legacy ring members onto their on-chain legacy enote indices
    CHECK_AND_ASSERT_THROW_MES(legacy_ring_signatures.size() == legacy_ring_signature_rings.size(),
        "collect legacy ring signature ring members: legacy ring signatures don't line up with legacy ring signature rings.");

    for (std::size_t legacy_input_index{0}; legacy_input_index < legacy_ring_signatures.size(); ++legacy_input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(legacy_ring_signatures[legacy_input_index].m_reference_set.size() ==
                legacy_ring_signature_rings[legacy_input_index].size(),
            "collect legacy ring signature ring members: a reference set doesn't line up with the corresponding ring.");

        for (std::size_t ring_index{0}; ring_index < legacy_ring_signature_rings[legacy_input_index].size(); ++ring_index)
        {
            legacy_reference_set_proof_elements_out[
                    legacy_ring_signatures[legacy_input_index].m_reference_set[ring_index]
                ] = legacy_ring_signature_rings[legacy_input_index][ring_index];
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const std::string &version_string,
    const std::vector<crypto::key_image> &legacy_input_key_images,
    const std::vector<crypto::key_image> &sp_input_key_images,
    const std::vector<SpEnoteV1> &output_enotes,
    const SpTxSupplementV1 &tx_supplement,
    const rct::xmr_amount transaction_fee,
    rct::key &proposal_prefix_out)
{
    static const std::string project_name{CRYPTONOTE_NAME};

    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(legacy_input_key_images.begin(), legacy_input_key_images.end()),
        "tx proposal prefix (v1): legacy input key images are not sorted.");
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(sp_input_key_images.begin(), sp_input_key_images.end()),
        "tx proposal prefix (v1): seraphis input key images are not sorted.");
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(output_enotes.begin(), output_enotes.end(), equals_from_less{}),
        "tx proposal prefix (v1): output enotes are not sorted.");

    // H_32(crypto project name, version string, legacy input key images, seraphis input key images, output enotes,
    //         tx supplement, fee)
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_TX_PROPOSAL_MESSAGE_V1,
            project_name.size() +
                version_string.size() +
                (legacy_input_key_images.size() + sp_input_key_images.size())*sizeof(crypto::key_image) +
                output_enotes.size()*SpEnoteV1::size_bytes() +
                tx_supplement.size_bytes()
        };
    transcript.append("project_name", project_name);
    transcript.append("version_string", version_string);
    transcript.append("legacy_input_key_images", legacy_input_key_images);
    transcript.append("sp_input_key_images", sp_input_key_images);
    transcript.append("output_enotes", output_enotes);
    transcript.append("tx_supplement", tx_supplement);
    transcript.append("transaction_fee", transaction_fee);

    sp_hash_to_32(transcript, proposal_prefix_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const std::string &version_string,
    const std::vector<crypto::key_image> &legacy_input_key_images,
    const std::vector<crypto::key_image> &sp_input_key_images,
    const std::vector<SpEnoteV1> &output_enotes,
    const SpTxSupplementV1 &tx_supplement,
    const DiscretizedFee &transaction_fee,
    rct::key &proposal_prefix_out)
{
    // get raw fee value
    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(transaction_fee, raw_transaction_fee),
        "make image proposal prefix (v1): could not extract raw fee from discretized fee.");

    // get proposal prefix
    make_tx_proposal_prefix_v1(version_string,
        legacy_input_key_images,
        sp_input_key_images,
        output_enotes,
        tx_supplement,
        raw_transaction_fee,
        proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const std::string &version_string,
    const std::vector<LegacyEnoteImageV2> &input_legacy_enote_images,
    const std::vector<SpEnoteImageV1> &input_sp_enote_images,
    const std::vector<SpEnoteV1> &output_enotes,
    const SpTxSupplementV1 &tx_supplement,
    const DiscretizedFee &transaction_fee,
    rct::key &proposal_prefix_out)
{
    // get key images from enote images
    std::vector<crypto::key_image> legacy_input_key_images;
    std::vector<crypto::key_image> sp_input_key_images;
    legacy_input_key_images.reserve(input_legacy_enote_images.size());
    sp_input_key_images.reserve(input_sp_enote_images.size());

    for (const LegacyEnoteImageV2 &legacy_enote_image : input_legacy_enote_images)
        legacy_input_key_images.emplace_back(legacy_enote_image.m_key_image);

    for (const SpEnoteImageV1 &sp_enote_image : input_sp_enote_images)
        sp_input_key_images.emplace_back(sp_enote_image.m_core.m_key_image);

    // get proposal prefix
    make_tx_proposal_prefix_v1(version_string,
        legacy_input_key_images,
        sp_input_key_images,
        output_enotes,
        tx_supplement,
        transaction_fee,
        proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const std::string &version_string,
    const std::vector<crypto::key_image> &legacy_input_key_images,
    const std::vector<crypto::key_image> &sp_input_key_images,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const TxExtra &partial_memo,
    const DiscretizedFee &transaction_fee,
    rct::key &proposal_prefix_out)
{
    // extract info from output proposals
    std::vector<SpEnoteV1> output_enotes;
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    SpTxSupplementV1 tx_supplement;

    make_v1_outputs_v1(output_proposals,
        output_enotes,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement.m_output_enote_ephemeral_pubkeys);

    // collect full memo
    finalize_tx_extra_v1(partial_memo, output_proposals, tx_supplement.m_tx_extra);

    // get proposal prefix
    make_tx_proposal_prefix_v1(version_string,
        legacy_input_key_images,
        sp_input_key_images,
        output_enotes,
        tx_supplement,
        transaction_fee,
        proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const std::string &version_string,
    const std::vector<LegacyInputV1> &legacy_inputs,
    const std::vector<SpPartialInputV1> &sp_partial_inputs,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const TxExtra &partial_memo,
    const DiscretizedFee &transaction_fee,
    rct::key &proposal_prefix_out)
{
    // get key images from partial inputs
    std::vector<crypto::key_image> legacy_input_key_images;
    std::vector<crypto::key_image> sp_input_key_images;
    legacy_input_key_images.reserve(legacy_inputs.size());
    sp_input_key_images.reserve(sp_partial_inputs.size());

    for (const LegacyInputV1 &legacy_input : legacy_inputs)
        legacy_input_key_images.emplace_back(legacy_input.m_input_image.m_key_image);

    for (const SpPartialInputV1 &sp_partial_input : sp_partial_inputs)
        sp_input_key_images.emplace_back(sp_partial_input.m_input_image.m_core.m_key_image);

    // get proposal prefix
    make_tx_proposal_prefix_v1(version_string,
        legacy_input_key_images,
        sp_input_key_images,
        output_proposals,
        partial_memo,
        transaction_fee,
        proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const std::string &version_string,
    const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const TxExtra &partial_memo,
    const DiscretizedFee &transaction_fee,
    rct::key &proposal_prefix_out)
{
    // get key images from input proposals
    std::vector<crypto::key_image> legacy_input_key_images;
    std::vector<crypto::key_image> sp_input_key_images;
    legacy_input_key_images.reserve(legacy_input_proposals.size());
    sp_input_key_images.reserve(sp_input_proposals.size());

    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
        legacy_input_key_images.emplace_back(legacy_input_proposal.m_key_image);

    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
        sp_input_key_images.emplace_back(sp_input_proposal.m_core.m_key_image);

    // get proposal prefix
    make_tx_proposal_prefix_v1(version_string,
        legacy_input_key_images,
        sp_input_key_images,
        output_proposals,
        partial_memo,
        transaction_fee,
        proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proofs_prefix_v1(const SpBalanceProofV1 &balance_proof,
    const std::vector<LegacyRingSignatureV3> &legacy_ring_signatures,
    const std::vector<SpImageProofV1> &sp_image_proofs,
    const std::vector<SpMembershipProofV1> &sp_membership_proofs,
    rct::key &tx_proofs_prefix_out)
{
    // H_32(balance proof, legacy ring signatures, seraphis image proofs, seraphis membership proofs)
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_TRANSACTION_PROOFS_PREFIX_V1,
            balance_proof.size_bytes() +
                (legacy_ring_signatures.size()
                    ? legacy_ring_signatures.size() * legacy_ring_signatures[0].size_bytes()
                    : 0) +
                sp_image_proofs.size() * SpImageProofV1::size_bytes() +
                (sp_membership_proofs.size()
                    ? sp_membership_proofs.size() * sp_membership_proofs[0].size_bytes()
                    : 0)
        };
    transcript.append("balance_proof", balance_proof);
    transcript.append("legacy_ring_signatures", legacy_ring_signatures);
    transcript.append("sp_image_proofs", sp_image_proofs);
    transcript.append("sp_membership_proofs", sp_membership_proofs);

    sp_hash_to_32(transcript, tx_proofs_prefix_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_tx_proposal_semantics_v1(const SpTxProposalV1 &tx_proposal,
    const rct::key &legacy_spend_pubkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    /// validate self-send payment proposals

    // 1. there must be at least one self-send output
    CHECK_AND_ASSERT_THROW_MES(tx_proposal.m_selfsend_payment_proposals.size() > 0,
        "Semantics check tx proposal v1: there are no self-send outputs (at least one is expected).");

    // 2. there cannot be two self-send outputs of the same type and no other outputs
    if (tx_proposal.m_normal_payment_proposals.size() == 0 &&
        tx_proposal.m_selfsend_payment_proposals.size() == 2)
    {
        CHECK_AND_ASSERT_THROW_MES(tx_proposal.m_selfsend_payment_proposals[0].m_type !=
                tx_proposal.m_selfsend_payment_proposals[1].m_type,
            "Semantics check tx proposal v1: there are two self-send outputs of the same type but no other outputs "
            "(not allowed).");
    }

    // 3. all self-send destinations must be owned by the wallet
    rct::key input_context;
    make_standard_input_context_v1(tx_proposal.m_legacy_input_proposals, tx_proposal.m_sp_input_proposals, input_context);

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal : tx_proposal.m_selfsend_payment_proposals)
    {
        check_jamtis_payment_proposal_selfsend_semantics_v1(selfsend_payment_proposal,
            input_context,
            jamtis_spend_pubkey,
            k_view_balance);
    }


    /// check consistency of outputs

    // 1. extract output proposals from tx proposal (and check their semantics)
    std::vector<SpOutputProposalV1> output_proposals;
    tx_proposal.get_output_proposals_v1(k_view_balance, output_proposals);

    check_v1_output_proposal_set_semantics_v1(output_proposals);

    // 2. extract outputs from the output proposals
    std::vector<SpEnoteV1> output_enotes;
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    SpTxSupplementV1 tx_supplement;

    make_v1_outputs_v1(output_proposals,
        output_enotes,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement.m_output_enote_ephemeral_pubkeys);

    finalize_tx_extra_v1(tx_proposal.m_partial_memo, output_proposals, tx_supplement.m_tx_extra);

    // 3. at least two outputs are expected
    CHECK_AND_ASSERT_THROW_MES(output_enotes.size() >= 2,
        "Semantics check tx proposal v1: there are fewer than 2 outputs.");

    // 4. outputs should be sorted and unique
    CHECK_AND_ASSERT_THROW_MES(is_sorted_and_unique(output_enotes),
        "Semantics check tx proposal v1: output onetime addresses are not sorted and unique.");

    // 5. onetime addresses should be canonical (sanity check so our tx outputs don't have duplicate key images)
    for (const SpEnoteV1 &output_enote : output_enotes)
    {
        CHECK_AND_ASSERT_THROW_MES(output_enote.m_core.onetime_address_is_canonical(),
            "Semantics check tx proposal v1: an output onetime address is not in the prime subgroup.");
    }

    // 6. check that output amount commitments can be reproduced
    CHECK_AND_ASSERT_THROW_MES(output_enotes.size() == output_amounts.size(),
        "Semantics check tx proposal v1: outputs don't line up with output amounts.");
    CHECK_AND_ASSERT_THROW_MES(output_enotes.size() == output_amount_commitment_blinding_factors.size(),
        "Semantics check tx proposal v1: outputs don't line up with output amount commitment blinding factors.");

    for (std::size_t output_index{0}; output_index < output_enotes.size(); ++output_index)
    {
        CHECK_AND_ASSERT_THROW_MES(output_enotes[output_index].m_core.m_amount_commitment ==
                rct::commit(output_amounts[output_index],
                    rct::sk2rct(output_amount_commitment_blinding_factors[output_index])),
            "Semantics check tx proposal v1: could not reproduce an output's amount commitment.");
    }

    // 7. check tx supplement (especially enote ephemeral pubkeys)
    check_v1_tx_supplement_semantics_v1(tx_supplement, output_enotes.size());


    /// input checks

    // 1. there should be at least one input
    CHECK_AND_ASSERT_THROW_MES(tx_proposal.m_legacy_input_proposals.size() + tx_proposal.m_sp_input_proposals.size() >= 1,
        "Semantics check tx proposal v1: there are no inputs.");

    // 2. input proposals should be sorted and unique
    CHECK_AND_ASSERT_THROW_MES(is_sorted_and_unique(tx_proposal.m_legacy_input_proposals),
        "Semantics check tx proposal v1: legacy input proposals are not sorted and unique.");
    CHECK_AND_ASSERT_THROW_MES(is_sorted_and_unique(tx_proposal.m_sp_input_proposals),
        "Semantics check tx proposal v1: seraphis input proposals are not sorted and unique.");

    // 3. legacy input proposal semantics should be valid
    for (const LegacyInputProposalV1 &legacy_input_proposal : tx_proposal.m_legacy_input_proposals)
        check_v1_legacy_input_proposal_semantics_v1(legacy_input_proposal, legacy_spend_pubkey);

    // 4. seraphis input proposal semantics should be valid
    rct::key sp_spend_pubkey{jamtis_spend_pubkey};
    reduce_seraphis_spendkey_x(k_view_balance, sp_spend_pubkey);

    for (const SpInputProposalV1 &sp_input_proposal : tx_proposal.m_sp_input_proposals)
        check_v1_input_proposal_semantics_v1(sp_input_proposal, sp_spend_pubkey);


    /// check that amounts balance in the proposal

    // 1. extract the fee value
    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(tx_proposal.m_tx_fee, raw_transaction_fee),
        "Semantics check tx proposal v1: could not extract fee value from discretized fee.");

    // 2. get input amounts
    std::vector<rct::xmr_amount> in_amounts;
    in_amounts.reserve(tx_proposal.m_legacy_input_proposals.size() + tx_proposal.m_sp_input_proposals.size());

    for (const LegacyInputProposalV1 &legacy_input_proposal : tx_proposal.m_legacy_input_proposals)
        in_amounts.emplace_back(legacy_input_proposal.amount());

    for (const SpInputProposalV1 &sp_input_proposal : tx_proposal.m_sp_input_proposals)
        in_amounts.emplace_back(sp_input_proposal.amount());

    // 3. check: sum(input amnts) == sum(output amnts) + fee
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, output_amounts, raw_transaction_fee),
        "Semantics check tx proposal v1: input/output amounts did not balance with desired fee.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_proposal_v1(std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const DiscretizedFee &tx_fee,
    std::vector<LegacyInputProposalV1> legacy_input_proposals,
    std::vector<SpInputProposalV1> sp_input_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    SpTxProposalV1 &tx_proposal_out)
{
    // inputs should be sorted by key image
    std::sort(legacy_input_proposals.begin(), legacy_input_proposals.end());
    std::sort(sp_input_proposals.begin(), sp_input_proposals.end());

    // set fields
    tx_proposal_out.m_normal_payment_proposals = std::move(normal_payment_proposals);
    tx_proposal_out.m_selfsend_payment_proposals = std::move(selfsend_payment_proposals);
    tx_proposal_out.m_tx_fee = tx_fee;
    tx_proposal_out.m_legacy_input_proposals = std::move(legacy_input_proposals);
    tx_proposal_out.m_sp_input_proposals = std::move(sp_input_proposals);
    make_tx_extra(std::move(additional_memo_elements), tx_proposal_out.m_partial_memo);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_tx_proposal_for_transfer_v1(const jamtis::JamtisDestinationV1 &change_address,
    const jamtis::JamtisDestinationV1 &dummy_address,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    TxExtra partial_memo_for_tx,
    const crypto::secret_key &k_view_balance,
    SpTxProposalV1 &tx_proposal_out,
    std::unordered_map<crypto::key_image, std::uint64_t> &legacy_input_ledger_mappings_out,
    std::unordered_map<crypto::key_image, std::uint64_t> &sp_input_ledger_mappings_out)
{
    legacy_input_ledger_mappings_out.clear();
    sp_input_ledger_mappings_out.clear();

    // 1. try to select inputs for the tx
    const OutputSetContextForInputSelectionV1 output_set_context{
            normal_payment_proposals,
            selfsend_payment_proposals
        };

    rct::xmr_amount reported_final_fee;
    input_set_tracker_t selected_input_set;

    if (!try_get_input_set_v1(output_set_context,
            max_inputs,
            local_user_input_selector,
            fee_per_tx_weight,
            tx_fee_calculator,
            reported_final_fee,
            selected_input_set))
        return false;

    // 2. separate into legacy and seraphis inputs
    std::list<LegacyContextualEnoteRecordV1> legacy_contextual_inputs;
    std::list<SpContextualEnoteRecordV1> sp_contextual_inputs;

    split_selected_input_set(selected_input_set, legacy_contextual_inputs, sp_contextual_inputs);

    // a. handle legacy inputs
    std::vector<LegacyInputProposalV1> legacy_input_proposals;
    legacy_enote_records_to_input_proposals(legacy_contextual_inputs,
        legacy_input_proposals,
        legacy_input_ledger_mappings_out);

    // b. handle seraphis inputs
    std::vector<SpInputProposalV1> sp_input_proposals;
    sp_enote_records_to_input_proposals(sp_contextual_inputs,
        sp_input_proposals,
        sp_input_ledger_mappings_out);

    // 3.  get total input amount
    boost::multiprecision::uint128_t total_input_amount{0};

    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
        total_input_amount += legacy_input_proposal.m_amount;

    for (const SpInputProposalV1 &input_proposal : sp_input_proposals)
        total_input_amount += input_proposal.m_core.m_amount;

    // 4. finalize output set
    const DiscretizedFee discretized_transaction_fee{reported_final_fee};
    CHECK_AND_ASSERT_THROW_MES(discretized_transaction_fee == reported_final_fee,
        "make tx proposal for transfer (v1): the input selector fee was not properly discretized (bug).");

    finalize_v1_output_proposal_set_v1(total_input_amount,
        reported_final_fee,
        change_address,
        dummy_address,
        k_view_balance,
        normal_payment_proposals,
        selfsend_payment_proposals);

    CHECK_AND_ASSERT_THROW_MES(tx_fee_calculator.compute_fee(fee_per_tx_weight,
                legacy_contextual_inputs.size(), sp_contextual_inputs.size(),
                normal_payment_proposals.size() + selfsend_payment_proposals.size()) ==
            reported_final_fee,
        "make tx proposal for transfer (v1): final fee is not consistent with input selector fee (bug).");

    // 5. get memo elements
    std::vector<ExtraFieldElement> extra_field_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(partial_memo_for_tx, extra_field_elements),
        "make tx proposal for transfer (v1): unable to extract memo field elements for tx proposal.");

    // 6. assemble into tx proposal
    make_v1_tx_proposal_v1(std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        discretized_transaction_fee,
        std::move(legacy_input_proposals),
        std::move(sp_input_proposals),
        std::move(extra_field_elements),
        tx_proposal_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_balance_proof_v1(const std::vector<rct::xmr_amount> &legacy_input_amounts,
    const std::vector<rct::xmr_amount> &sp_input_amounts,
    const std::vector<rct::xmr_amount> &output_amounts,
    const rct::xmr_amount transaction_fee,
    const std::vector<crypto::secret_key> &legacy_input_image_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &sp_input_image_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    SpBalanceProofV1 &balance_proof_out)
{
    // for squashed enote model

    // 1. check balance
    std::vector<rct::xmr_amount> all_in_amounts{legacy_input_amounts};
    all_in_amounts.insert(all_in_amounts.end(), sp_input_amounts.begin(), sp_input_amounts.end());

    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(all_in_amounts, output_amounts, transaction_fee),
        "make v1 balance proof (v1): amounts don't balance.");

    // 2. combine seraphis inputs and outputs for range proof (legacy input masked commitments are not range proofed)
    std::vector<rct::xmr_amount> range_proof_amounts{sp_input_amounts};
    std::vector<crypto::secret_key> range_proof_blinding_factors{sp_input_image_amount_commitment_blinding_factors};

    range_proof_amounts.insert(range_proof_amounts.end(), output_amounts.begin(), output_amounts.end());
    range_proof_blinding_factors.insert(range_proof_blinding_factors.end(),
        output_amount_commitment_blinding_factors.begin(),
        output_amount_commitment_blinding_factors.end());

    // 3. make range proofs
    BulletproofPlus2 range_proofs;

    rct::keyV range_proof_amount_commitment_blinding_factors;
    auto vec_wiper = convert_skv_to_rctv(range_proof_blinding_factors, range_proof_amount_commitment_blinding_factors);
    make_bpp2_rangeproofs(range_proof_amounts, range_proof_amount_commitment_blinding_factors, range_proofs);

    balance_proof_out.m_bpp2_proof = std::move(range_proofs);

    // 4. set the remainder blinding factor
    // blinding_factor = sum(legacy input blinding factors) + sum(sp input blinding factors) - sum(output blinding factors)
    std::vector<crypto::secret_key> collected_input_blinding_factors{sp_input_image_amount_commitment_blinding_factors};
    crypto::secret_key remainder_blinding_factor;

    collected_input_blinding_factors.insert(collected_input_blinding_factors.end(),
        legacy_input_image_amount_commitment_blinding_factors.begin(),
        legacy_input_image_amount_commitment_blinding_factors.end());

    subtract_secret_key_vectors(collected_input_blinding_factors,
        output_amount_commitment_blinding_factors,
        remainder_blinding_factor);

    balance_proof_out.m_remainder_blinding_factor = rct::sk2rct(remainder_blinding_factor);
}
//-------------------------------------------------------------------------------------------------------------------
bool balance_check_in_out_amnts_v1(const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const DiscretizedFee &discretized_transaction_fee)
{
    // input amounts
    std::vector<rct::xmr_amount> in_amounts;
    in_amounts.reserve(legacy_input_proposals.size() + sp_input_proposals.size());

    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
        in_amounts.emplace_back(legacy_input_proposal.amount());

    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
        in_amounts.emplace_back(sp_input_proposal.amount());

    // output amounts
    std::vector<rct::xmr_amount> out_amounts;
    out_amounts.reserve(output_proposals.size());

    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        out_amounts.emplace_back(output_proposal.amount());

    // fee
    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(discretized_transaction_fee, raw_transaction_fee),
        "balance check in out amnts v1: unable to extract transaction fee from discretized fee representation.");

    // balance check
    return balance_check_in_out_amnts(in_amounts, out_amounts, raw_transaction_fee);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_partial_tx_semantics_v1(const SpPartialTxV1 &partial_tx,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version)
{
    // 1. prepare a mock ledger
    MockLedgerContext mock_ledger{0, 0};

    // 2. get parameters for making mock seraphis ref sets (use minimum parameters for efficiency when possible)
    const SemanticConfigSpRefSetV1 ref_set_config{semantic_config_sp_ref_sets_v1(semantic_rules_version)};
    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = static_cast<ref_set_bin_dimension_v1_t>(ref_set_config.m_bin_radius_min),
            .m_num_bin_members = static_cast<ref_set_bin_dimension_v1_t>(ref_set_config.m_num_bin_members_min),
        };

    // 3. make mock membership proof ref sets
    std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps{
            gen_mock_sp_membership_proof_preps_v1(partial_tx.m_sp_input_enotes,
                partial_tx.m_sp_address_masks,
                partial_tx.m_sp_commitment_masks,
                ref_set_config.m_decomp_n_min,
                ref_set_config.m_decomp_m_min,
                bin_config,
                mock_ledger)
        };

    // 4. make the mock seraphis membership proofs
    std::vector<SpMembershipProofV1> sp_membership_proofs;
    make_v1_membership_proofs_v1(std::move(sp_membership_proof_preps), sp_membership_proofs);

    // 5. collect legacy ring signature ring members for mock validation context
    std::unordered_map<std::uint64_t, rct::ctkey> legacy_reference_set_proof_elements;

    collect_legacy_ring_signature_ring_members(partial_tx.m_legacy_ring_signatures,
        partial_tx.m_legacy_ring_signature_rings,
        legacy_reference_set_proof_elements);

    // 6. make tx (use raw constructor instead of partial tx constructor to avoid infinite loop)
    SpTxSquashedV1 test_tx;
    make_seraphis_tx_squashed_v1(semantic_rules_version,
        partial_tx.m_legacy_input_images,
        partial_tx.m_sp_input_images,
        partial_tx.m_outputs,
        partial_tx.m_balance_proof,
        partial_tx.m_legacy_ring_signatures,
        partial_tx.m_sp_image_proofs,
        std::move(sp_membership_proofs),
        partial_tx.m_tx_supplement,
        partial_tx.m_tx_fee,
        test_tx);

    // 7. validate tx
    const TxValidationContextMockPartial tx_validation_context{mock_ledger, legacy_reference_set_proof_elements};

    CHECK_AND_ASSERT_THROW_MES(validate_tx(test_tx, tx_validation_context),
        "v1 partial tx semantics check (v1): test transaction was invalid using requested semantics rules version!");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_tx_v1(std::vector<LegacyInputV1> legacy_inputs,
    std::vector<SpPartialInputV1> sp_partial_inputs,
    std::vector<SpOutputProposalV1> output_proposals,
    const TxExtra &partial_memo,
    const DiscretizedFee &tx_fee,
    const std::string &version_string,
    SpPartialTxV1 &partial_tx_out)
{
    /// preparation and checks
    partial_tx_out = SpPartialTxV1{};

    // 1. sort the inputs by key image
    std::sort(legacy_inputs.begin(), legacy_inputs.end());
    std::sort(sp_partial_inputs.begin(), sp_partial_inputs.end());

    // 2. sort the outputs by onetime address
    std::sort(output_proposals.begin(), output_proposals.end());

    // 3. semantics checks for inputs and outputs
    for (const LegacyInputV1 &legacy_input : legacy_inputs)
        check_v1_legacy_input_semantics_v1(legacy_input);

    for (const SpPartialInputV1 &partial_input : sp_partial_inputs)
        check_v1_partial_input_semantics_v1(partial_input);

    check_v1_output_proposal_set_semantics_v1(output_proposals);  //do this after sorting the proposals

    // 4. extract info from output proposals
    std::vector<SpEnoteV1> output_enotes;
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    SpTxSupplementV1 tx_supplement;

    make_v1_outputs_v1(output_proposals,
        output_enotes,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement.m_output_enote_ephemeral_pubkeys);

    // 5. collect full memo
    finalize_tx_extra_v1(partial_memo, output_proposals, tx_supplement.m_tx_extra);

    // 6. check: inputs and proposal must have consistent proposal prefixes
    rct::key proposal_prefix;
    make_tx_proposal_prefix_v1(version_string,
        legacy_inputs,
        sp_partial_inputs,
        output_proposals,
        partial_memo,
        tx_fee,
        proposal_prefix);

    for (const LegacyInputV1 &legacy_input : legacy_inputs)
    {
        CHECK_AND_ASSERT_THROW_MES(proposal_prefix == legacy_input.m_proposal_prefix,
            "making partial tx: a legacy input's proposal prefix is invalid/inconsistent.");
    }

    for (const SpPartialInputV1 &partial_input : sp_partial_inputs)
    {
        CHECK_AND_ASSERT_THROW_MES(proposal_prefix == partial_input.m_proposal_prefix,
            "making partial tx: a seraphis partial input's proposal prefix is invalid/inconsistent.");
    }


    /// balance proof

    // 1. get input amounts and image amount commitment blinding factors
    std::vector<rct::xmr_amount> legacy_input_amounts;
    std::vector<crypto::secret_key> legacy_input_image_amount_commitment_blinding_factors;
    prepare_legacy_input_commitment_factors_for_balance_proof_v1(legacy_inputs,
        legacy_input_amounts,
        legacy_input_image_amount_commitment_blinding_factors);

    std::vector<rct::xmr_amount> sp_input_amounts;
    std::vector<crypto::secret_key> sp_input_image_amount_commitment_blinding_factors;
    prepare_input_commitment_factors_for_balance_proof_v1(sp_partial_inputs,
        sp_input_amounts,
        sp_input_image_amount_commitment_blinding_factors);

    // 2. extract the fee
    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(tx_fee, raw_transaction_fee),
        "making partial tx: could not extract a fee value from the discretized fee.");

    // 3. make balance proof
    make_v1_balance_proof_v1(legacy_input_amounts,
        sp_input_amounts,
        output_amounts,
        raw_transaction_fee,
        legacy_input_image_amount_commitment_blinding_factors,
        sp_input_image_amount_commitment_blinding_factors,
        output_amount_commitment_blinding_factors,
        partial_tx_out.m_balance_proof);


    /// copy misc tx pieces

    // 1. gather legacy tx input parts
    partial_tx_out.m_legacy_input_images.reserve(legacy_inputs.size());
    partial_tx_out.m_legacy_ring_signatures.reserve(legacy_inputs.size());
    partial_tx_out.m_legacy_ring_signature_rings.reserve(legacy_inputs.size());

    for (LegacyInputV1 &legacy_input : legacy_inputs)
    {
        partial_tx_out.m_legacy_input_images.emplace_back(legacy_input.m_input_image);
        partial_tx_out.m_legacy_ring_signatures.emplace_back(std::move(legacy_input.m_ring_signature));
        partial_tx_out.m_legacy_ring_signature_rings.emplace_back(std::move(legacy_input.m_ring_members));
    }

    // 2. gather seraphis tx input parts
    partial_tx_out.m_sp_input_images.reserve(sp_partial_inputs.size());
    partial_tx_out.m_sp_image_proofs.reserve(sp_partial_inputs.size());
    partial_tx_out.m_sp_input_enotes.reserve(sp_partial_inputs.size());
    partial_tx_out.m_sp_address_masks.reserve(sp_partial_inputs.size());
    partial_tx_out.m_sp_commitment_masks.reserve(sp_partial_inputs.size());

    for (SpPartialInputV1 &partial_input : sp_partial_inputs)
    {
        partial_tx_out.m_sp_input_images.emplace_back(partial_input.m_input_image);
        partial_tx_out.m_sp_image_proofs.emplace_back(std::move(partial_input.m_image_proof));
        partial_tx_out.m_sp_input_enotes.emplace_back(partial_input.m_input_enote_core);
        partial_tx_out.m_sp_address_masks.emplace_back(partial_input.m_address_mask);
        partial_tx_out.m_sp_commitment_masks.emplace_back(partial_input.m_commitment_mask);
    }

    // 3. gather tx output parts
    partial_tx_out.m_outputs = std::move(output_enotes);
    partial_tx_out.m_tx_supplement = std::move(tx_supplement);
    partial_tx_out.m_tx_fee = tx_fee;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_tx_v1(const SpTxProposalV1 &tx_proposal,
    std::vector<LegacyInputV1> legacy_inputs,
    std::vector<SpPartialInputV1> sp_partial_inputs,
    const std::string &version_string,
    const rct::key &legacy_spend_pubkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpPartialTxV1 &partial_tx_out)
{
    // 1. validate tx proposal
    check_v1_tx_proposal_semantics_v1(tx_proposal, legacy_spend_pubkey, jamtis_spend_pubkey, k_view_balance);

    // 2. sort the inputs by key image
    std::sort(legacy_inputs.begin(), legacy_inputs.end());
    std::sort(sp_partial_inputs.begin(), sp_partial_inputs.end());

    // 3. legacy inputs must line up with legacy input proposals in the tx proposal
    CHECK_AND_ASSERT_THROW_MES(legacy_inputs.size() == tx_proposal.m_legacy_input_proposals.size(),
        "making partial tx: number of legacy inputs doesn't match number of legacy input proposals.");

    for (std::size_t input_index{0}; input_index < legacy_inputs.size(); ++input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(same_key_image(legacy_inputs[input_index],
                tx_proposal.m_legacy_input_proposals[input_index]),
            "making partial tx: legacy inputs and input proposals don't line up (inconsistent key images).");
    }

    // 4. seraphis partial inputs must line up with seraphis input proposals in the tx proposal
    CHECK_AND_ASSERT_THROW_MES(sp_partial_inputs.size() == tx_proposal.m_sp_input_proposals.size(),
        "making partial tx: number of seraphis partial inputs doesn't match number of seraphis input proposals.");

    for (std::size_t input_index{0}; input_index < sp_partial_inputs.size(); ++input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(same_key_image(sp_partial_inputs[input_index],
                tx_proposal.m_sp_input_proposals[input_index]),
            "making partial tx: seraphis partial inputs and input proposals don't line up (inconsistent key images).");
    }

    // 5. extract output proposals from tx proposal
    std::vector<SpOutputProposalV1> output_proposals;
    tx_proposal.get_output_proposals_v1(k_view_balance, output_proposals);

    // 6. construct partial tx
    make_v1_partial_tx_v1(std::move(legacy_inputs),
        std::move(sp_partial_inputs),
        std::move(output_proposals),
        tx_proposal.m_partial_memo,
        tx_proposal.m_tx_fee,
        version_string,
        partial_tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
