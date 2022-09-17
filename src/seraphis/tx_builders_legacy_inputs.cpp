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
#include "tx_builders_inputs.h"

//local headers
#include "common/varint.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "grootle.h"
#include "jamtis_enote_utils.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_config_temp.h"
#include "sp_composition_proof.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"
#include "tx_binned_reference_set.h"
#include "tx_binned_reference_set_utils.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_legacy_component_types.h"
#include "tx_misc_utils.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"
#include "tx_ref_set_index_mapper_flat.h"

//third party headers

//standard headers
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void make_tx_legacy_ring_signature_message_v1(const rct::key &tx_proposal_message,
    const std::vector<std::uint64_t> &reference_set_indices,
    rct::key &message_out)
{
    // m = H_32(tx proposal message, {reference set indices})
    SpFSTranscript transcript{
            config::HASH_KEY_LEGACY_RING_SIGNATURES_MESSAGE_V1,
            32 + reference_set_indices.size() * 8
        };
    transcript.append("tx_proposal_message", tx_proposal_message);
    transcript.append("reference_set_indices", reference_set_indices);

    sp_hash_to_32(transcript, message_out.bytes);
}/*
//-------------------------------------------------------------------------------------------------------------------
void check_v1_legacy_input_proposal_semantics_v1(const LegacyInputProposalV1 &input_proposal,
    const rct::key &wallet_legacy_spend_pubkey)
{
    //todo (note: legacy key image can't be reproduced since it needs the legacy private spend key)

    // 1. the onetime address must be reproducible
    rct::key extended_wallet_spendkey{wallet_spend_pubkey_base};
    extend_seraphis_spendkey_u(input_proposal.m_core.m_enote_view_privkey_u, extended_wallet_spendkey);

    rct::key onetime_address_reproduced{extended_wallet_spendkey};
    extend_seraphis_spendkey_x(input_proposal.m_core.m_enote_view_privkey_x, onetime_address_reproduced);
    mask_key(input_proposal.m_core.m_enote_view_privkey_g, onetime_address_reproduced, onetime_address_reproduced);

    CHECK_AND_ASSERT_THROW_MES(onetime_address_reproduced == input_proposal.m_core.m_enote_core.m_onetime_address,
        "input proposal v1 semantics check: could not reproduce the one-time address.");

    // 2. the key image must be reproducible and canonical
    crypto::key_image key_image_reproduced;
    make_seraphis_key_image(input_proposal.m_core.m_enote_view_privkey_x,
        rct::rct2pk(extended_wallet_spendkey),
        key_image_reproduced);

    CHECK_AND_ASSERT_THROW_MES(key_image_reproduced == input_proposal.m_core.m_key_image,
        "input proposal v1 semantics check: could not reproduce the key image.");
    CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(rct::ki2rct(key_image_reproduced)),
        "input proposal v1 semantics check: the key image is not canonical.");

    // 3. the amount commitment must be reproducible
    const rct::key amount_commitment_reproduced{
            rct::commit(input_proposal.m_core.m_amount, rct::sk2rct(input_proposal.m_core.m_amount_blinding_factor))
        };

    CHECK_AND_ASSERT_THROW_MES(amount_commitment_reproduced == input_proposal.m_core.m_enote_core.m_amount_commitment,
        "input proposal v1 semantics check: could not reproduce the amount commitment.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_proposal_v1(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    const crypto::key_image &key_image,
    const crypto::secret_key &enote_view_privkey,
    const crypto::secret_key &input_amount_blinding_factor,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &commitment_mask,
    SpInputProposal &proposal_out)
{
    //todo

    // make an input proposal
    proposal_out.m_enote_core             = enote_core;
    proposal_out.m_key_image              = key_image;
    proposal_out.m_enote_view_privkey_g   = enote_view_privkey_g;
    proposal_out.m_enote_view_privkey_x   = enote_view_privkey_x;
    proposal_out.m_enote_view_privkey_u   = enote_view_privkey_u;
    proposal_out.m_amount_blinding_factor = input_amount_blinding_factor;
    proposal_out.m_amount                 = input_amount;
    proposal_out.m_address_mask           = address_mask;
    proposal_out.m_commitment_mask        = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_proposal_v1(const LegacyEnoteRecord &enote_record,
    const crypto::secret_key &commitment_mask,
    LegacyInputProposalV1 &proposal_out)
{
    //todo

    // make input proposal from enote record
    make_input_proposal(enote_record.m_enote.m_core,
        enote_record.m_key_image,
        enote_record.m_enote_view_privkey_g,
        enote_record.m_enote_view_privkey_x,
        enote_record.m_enote_view_privkey_u,
        enote_record.m_amount_blinding_factor,
        enote_record.m_amount,
        address_mask,
        commitment_mask,
        proposal_out.m_core);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v3_legacy_ring_signature_v1(std::vector<std::uint64_t> reference_set,
    const rct::ctkeyV &referenced_enotes,
    const std::uint64_t &real_reference_index,
    const crypto::key_image &key_image,
    const rct::key &masked_commitment,
    const crypto::secret_key &reference_view_privkey,
    const crypto::secret_key &reference_commitment_mask,
    const crypto::secret_key &legacy_spend_privkey,
    LegacyRingSignatureV3 &ring_signature_out)
{
    //todo

    // make membership proof

    /// checks and initialization

    // misc
    const std::size_t ref_set_size{ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m)};

    CHECK_AND_ASSERT_THROW_MES(referenced_enotes_squashed.size() == ref_set_size,
        "make membership proof: ref set size doesn't match number of referenced enotes.");
    CHECK_AND_ASSERT_THROW_MES(binned_reference_set.reference_set_size() == ref_set_size,
        "make membership proof: ref set size doesn't number of references in the binned reference set.");

    // make the real reference's squashed representation for later
    rct::key transformed_address;
    make_seraphis_squashed_address_key(real_reference_enote.m_onetime_address,
        real_reference_enote.m_amount_commitment,
        transformed_address);  //H_n(Ko,C) Ko

    rct::key real_Q;
    rct::addKeys(real_Q, transformed_address, real_reference_enote.m_amount_commitment);  //Hn(Ko, C) Ko + C

    // check binned reference set generator
    rct::key masked_address;
    mask_key(address_mask, transformed_address, masked_address);  //K" = t_k G + H_n(Ko,C) Ko

    rct::key masked_commitment;
    mask_key(commitment_mask, real_reference_enote.m_amount_commitment, masked_commitment);  //C" = t_c G + C

    rct::key generator_seed_reproduced;
    make_binned_ref_set_generator_seed_v1(masked_address, masked_commitment, generator_seed_reproduced);

    CHECK_AND_ASSERT_THROW_MES(generator_seed_reproduced == binned_reference_set.m_bin_generator_seed,
        "make membership proof: unable to reproduce binned reference set generator seed.");


    /// prepare to make proof

    // find the real referenced enote
    std::size_t real_spend_index_in_set{};  //l
    bool found_real{false};

    for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
    {
        if (real_Q == referenced_enotes_squashed[ref_index])  //Q[l]
        {
            real_spend_index_in_set = ref_index;
            found_real = true;
            break;
        }
    }
    CHECK_AND_ASSERT_THROW_MES(found_real,
        "make membership proof: could not find enote for membership proof in reference set.");

    // proof offset (only one in the squashed enote model)
    const rct::key image_offset{rct::addKeys(masked_address, masked_commitment)};  //Q" = K" + C"

    // secret key of: Q[l] - Q" = -(t_k + t_c) G
    static const rct::key MINUS_ONE{minus_one()};

    crypto::secret_key image_mask;
    sc_add(to_bytes(image_mask), to_bytes(address_mask), to_bytes(commitment_mask));  // t_k + t_c
    sc_mul(to_bytes(image_mask), to_bytes(image_mask), MINUS_ONE.bytes);  // -(t_k + t_c)

    // proof message
    rct::key message;
    make_tx_membership_proof_message_v1(binned_reference_set, message);


    /// make grootle proof
    membership_proof_out.m_grootle_proof = grootle_prove(referenced_enotes_squashed,
        real_spend_index_in_set,
        image_offset,
        image_mask,
        ref_set_decomp_n,
        ref_set_decomp_m,
        message);


    /// copy miscellaneous components
    membership_proof_out.m_binned_reference_set = std::move(binned_reference_set);
    membership_proof_out.m_ref_set_decomp_n     = ref_set_decomp_n;
    membership_proof_out.m_ref_set_decomp_m     = ref_set_decomp_m;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v3_legacy_ring_signature_v1(LegacyRingSignaturePrepV1 ring_signature_prep,
    const crypto::secret_key &legacy_spend_privkey,
    LegacyRingSignatureV3 &ring_signature_out)
{
    //todo

    make_v1_membership_proof_v1(membership_proof_prep.m_ref_set_decomp_n,
        membership_proof_prep.m_ref_set_decomp_m,
        std::move(membership_proof_prep.m_binned_reference_set),
        membership_proof_prep.m_referenced_enotes_squashed,
        membership_proof_prep.m_real_reference_enote,
        membership_proof_prep.m_address_mask,
        membership_proof_prep.m_commitment_mask,
        membership_proof_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v3_legacy_ring_signatures_v1(std::vector<LegacyRingSignaturePrepV1> ring_signature_preps,
    const crypto::secret_key &legacy_spend_privkey,
    std::vector<LegacyRingSignatureV3> &ring_signatures_out)
{
    //todo

    // make multiple membership proofs
    // note: proof preps are assumed to be pre-sorted, so alignable membership proofs are not needed
    membership_proofs_out.clear();
    membership_proofs_out.reserve(membership_proof_preps.size());

    for (SpMembershipProofPrepV1 &proof_prep : membership_proof_preps)
    {
        membership_proofs_out.emplace_back();
        make_v1_membership_proof_v1(std::move(proof_prep), membership_proofs_out.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_legacy_input_semantics_v1(const LegacyInputV1 &input)
{
    //todo

    // input amount commitment can be reconstructed
    const rct::key reconstructed_amount_commitment{
            rct::commit(partial_input.m_input_amount, rct::sk2rct(partial_input.m_input_amount_blinding_factor))
        };

    CHECK_AND_ASSERT_THROW_MES(reconstructed_amount_commitment == partial_input.m_input_enote_core.m_amount_commitment,
        "partial input semantics (v1): could not reconstruct amount commitment.");

    // input image masked address and commitment can be reconstructed
    rct::key reconstructed_masked_address;
    rct::key reconstructed_masked_commitment;
    make_seraphis_enote_image_masked_keys(partial_input.m_input_enote_core.m_onetime_address,
        partial_input.m_input_enote_core.m_amount_commitment,
        partial_input.m_address_mask,
        partial_input.m_commitment_mask,
        reconstructed_masked_address,
        reconstructed_masked_commitment);

    CHECK_AND_ASSERT_THROW_MES(reconstructed_masked_address == partial_input.m_input_image.m_core.m_masked_address,
        "partial input semantics (v1): could not reconstruct masked address.");
    CHECK_AND_ASSERT_THROW_MES(reconstructed_masked_commitment == partial_input.m_input_image.m_core.m_masked_commitment,
        "partial input semantics (v1): could not reconstruct masked address.");

    // image proof is valid
    CHECK_AND_ASSERT_THROW_MES(sp_composition_verify(partial_input.m_image_proof.m_composition_proof,
            partial_input.m_proposal_prefix,
            reconstructed_masked_address,
            partial_input.m_input_image.m_core.m_key_image),
        "partial input semantics (v1): image proof is invalid.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_v1(const LegacyInputProposalV1 &input_proposal,
    const rct::key &proposal_prefix,
    const crypto::secret_key &spendbase_privkey,
    LegacyInputV1 &input_out)
{
    //todo

    // check input proposal semantics
    rct::key wallet_spend_pubkey_base;
    make_seraphis_spendbase(spendbase_privkey, wallet_spend_pubkey_base);

    check_v1_input_proposal_semantics_v1(input_proposal, wallet_spend_pubkey_base);

    // prepare input image
    input_proposal.get_enote_image_v1(partial_input_out.m_input_image);

    // copy misc. proposal info
    partial_input_out.m_address_mask                 = input_proposal.m_core.m_address_mask;
    partial_input_out.m_commitment_mask              = input_proposal.m_core.m_commitment_mask;
    partial_input_out.m_proposal_prefix              = proposal_prefix;
    partial_input_out.m_input_amount                 = input_proposal.get_amount();
    partial_input_out.m_input_amount_blinding_factor = input_proposal.m_core.m_amount_blinding_factor;
    input_proposal.m_core.get_enote_core(partial_input_out.m_input_enote_core);

    // construct image proof
    make_v1_image_proof_v1(input_proposal.m_core,
        partial_input_out.m_proposal_prefix,
        spendbase_privkey,
        partial_input_out.m_image_proof);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_inputs_v1(const std::vector<LegacyInputProposalV1> &input_proposals,
    const rct::key &proposal_prefix,
    const crypto::secret_key &spendbase_privkey,
    std::vector<LegacyInputV1> &inputs_out)
{
    //todo

    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Can't make partial tx inputs without any input proposals.");

    partial_inputs_out.clear();
    partial_inputs_out.reserve(input_proposals.size());

    // make all inputs
    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        partial_inputs_out.emplace_back();
        make_v1_partial_input_v1(input_proposal, proposal_prefix, spendbase_privkey, partial_inputs_out.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<LegacyInputProposalV1> gen_mock_legacy_input_proposals_v1(const crypto::secret_key &legacy_spend_privkey,
    const std::vector<rct::xmr_amount> &input_amounts)
{
    //todo

    // generate random inputs
    std::vector<SpInputProposalV1> input_proposals;
    input_proposals.reserve(in_amounts.size());

    for (const rct::xmr_amount in_amount : in_amounts)
    {
        input_proposals.emplace_back();
        input_proposals.back().gen(spendbase_privkey, in_amount);
    }

    return input_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyRingSignaturePrepV1 gen_mock_legacy_ring_signature_prep_for_enote_at_pos_v1(const rct::ctkey &real_referenced_enote,,
    const std::uint64_t &real_reference_index_in_ledger,
    const LegacyEnoteImageV2 &real_reference_image,
    const crypto::secret_key &real_reference_view_privkey,
    const crypto::secret_key &commitment_mask,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context)
{
    //todo

    // generate a mock membership proof prep

    /// checks and initialization
    const std::size_t ref_set_size{ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m)};  // n^m

    CHECK_AND_ASSERT_THROW_MES(check_bin_config_v1(ref_set_size, bin_config),
        "gen mock membership proof prep: invalid binned reference set config.");


    /// make binned reference set
    SpMembershipProofPrepV1 proof_prep;

    // 1) flat index mapper for mock-up
    const SpRefSetIndexMapperFlat flat_index_mapper{
            0,
            ledger_context.max_sp_enote_index()
        };

    // 2) generator seed
    rct::key generator_seed;
    make_binned_ref_set_generator_seed_v1(real_reference_enote.m_onetime_address,
        real_reference_enote.m_amount_commitment,
        address_mask,
        commitment_mask,
        generator_seed);

    // 3) binned reference set
    make_binned_reference_set_v1(flat_index_mapper,
        bin_config,
        generator_seed,
        ref_set_size,
        real_reference_index_in_ledger,
        proof_prep.m_binned_reference_set);


    /// copy all referenced enotes from the ledger (in squashed enote representation)
    std::vector<std::uint64_t> reference_indices;
    CHECK_AND_ASSERT_THROW_MES(try_get_reference_indices_from_binned_reference_set_v1(proof_prep.m_binned_reference_set,
            reference_indices),
        "gen mock membership proof prep: could not extract reference indices from binned representation (bug).");

    ledger_context.get_reference_set_proof_elements_v2(reference_indices, proof_prep.m_referenced_enotes_squashed);


    /// copy misc pieces
    proof_prep.m_ref_set_decomp_n = ref_set_decomp_n;
    proof_prep.m_ref_set_decomp_m = ref_set_decomp_m;
    proof_prep.m_real_reference_enote = real_reference_enote;
    proof_prep.m_address_mask = address_mask;
    proof_prep.m_commitment_mask = commitment_mask;

    return proof_prep;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyRingSignaturePrepV1 gen_mock_legacy_ring_signature_prep_v1(const rct::ctkey &real_referenced_enote,
    const LegacyEnoteImageV2 &real_reference_image,
    const crypto::secret_key &real_reference_view_privkey,
    const crypto::secret_key &commitment_mask,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout)
{
    //todo

    // generate a mock membership proof prep

    /// add fake enotes to the ledger (2x the ref set size), with the real one at a random location

    // 1. make fake enotes
    const std::size_t ref_set_size{ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m)};  // n^m
    const std::size_t num_enotes_to_add{ref_set_size * 2};
    const std::size_t add_real_at_pos{crypto::rand_idx(num_enotes_to_add)};
    std::vector<SpEnoteV1> mock_enotes;
    mock_enotes.reserve(num_enotes_to_add);

    for (std::size_t enote_to_add{0}; enote_to_add < num_enotes_to_add; ++enote_to_add)
    {
        mock_enotes.emplace_back();

        if (enote_to_add == add_real_at_pos)
            mock_enotes.back().m_core = real_reference_enote;
        else
            mock_enotes.back().gen();
    }

    // 2. clear any txs lingering unconfirmed
    ledger_context_inout.commit_unconfirmed_txs_v1(rct::pkGen(), SpTxSupplementV1{}, std::vector<SpEnoteV1>{});

    // 3. add mock enotes as the outputs of a mock coinbase tx
    const std::uint64_t real_reference_index_in_ledger{ledger_context_inout.max_sp_enote_index() + add_real_at_pos + 1};
    ledger_context_inout.commit_unconfirmed_txs_v1(rct::pkGen(), SpTxSupplementV1{}, std::move(mock_enotes));


    /// finish making the proof prep
    return gen_mock_sp_membership_proof_prep_for_enote_at_pos_v1(real_reference_enote,
        real_reference_index_in_ledger,
        address_mask,
        commitment_mask,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpMembershipProofPrepV1> gen_mock_legacy_ring_signature_preps_v1(const rct::ctkeyV &real_referenced_enotes,
    const std::vector<LegacyEnoteImageV2> &real_reference_images,
    const std::vector<crypto::secret_key> &real_reference_view_privkeys,
    const std::vector<crypto::secret_key> &commitment_masks,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout)
{
    //todo

    // make mock membership ref sets from input enotes
    CHECK_AND_ASSERT_THROW_MES(real_referenced_enotes.size() == address_masks.size(),
        "gen mock membership proof preps: input enotes don't line up with address masks.");
    CHECK_AND_ASSERT_THROW_MES(real_referenced_enotes.size() == commitment_masks.size(),
        "gen mock membership proof preps: input enotes don't line up with commitment masks.");

    std::vector<SpMembershipProofPrepV1> proof_preps;
    proof_preps.reserve(real_referenced_enotes.size());

    for (std::size_t input_index{0}; input_index < real_referenced_enotes.size(); ++input_index)
    {
        proof_preps.emplace_back(
                gen_mock_sp_membership_proof_prep_v1(real_referenced_enotes[input_index],
                    address_masks[input_index],
                    commitment_masks[input_index],
                    ref_set_decomp_n,
                    ref_set_decomp_m,
                    bin_config,
                    ledger_context_inout)
            );
    }

    return proof_preps;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<LegacyRingSignaturePrepV1> gen_mock_legacy_ring_signature_preps_v1(
    const std::vector<LegacyInputProposalV1> &input_proposals,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout)
{
    //todo

    // make mock membership ref sets from input proposals
    std::vector<SpEnote> input_enotes;
    std::vector<crypto::secret_key> address_masks;
    std::vector<crypto::secret_key> commitment_masks;
    input_enotes.reserve(input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        input_enotes.emplace_back();
        input_proposal.m_core.get_enote_core(input_enotes.back());

        address_masks.emplace_back(input_proposal.m_core.m_address_mask);
        commitment_masks.emplace_back(input_proposal.m_core.m_commitment_mask);
    }

    return gen_mock_sp_membership_proof_preps_v1(input_enotes,
        address_masks,
        commitment_masks,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void make_mock_legacy_ring_signature_preps_for_inputs_v1(
    const std::unordered_map<crypto::key_image, std::uint64_t> &input_ledger_mappings,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context,
    std::vector<LegacyRingSignaturePrepV1> &ring_signature_preps_out)
{
    //todo

    CHECK_AND_ASSERT_THROW_MES(input_ledger_mappings.size() == input_proposals.size(),
        "make mock membership proof preps: input proposals don't line up with their enotes' ledger indices.");

    membership_proof_preps_out.clear();
    membership_proof_preps_out.reserve(input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        CHECK_AND_ASSERT_THROW_MES(
                input_ledger_mappings.find(input_proposal.m_core.m_key_image) != input_ledger_mappings.end(),
            "make mock membership proof preps: the enote ledger indices map is missing an expected key image.");

        membership_proof_preps_out.emplace_back(
                gen_mock_sp_membership_proof_prep_for_enote_at_pos_v1(input_proposal.m_core.m_enote_core,
                        input_ledger_mappings.at(input_proposal.m_core.m_key_image),
                        input_proposal.m_core.m_address_mask,
                        input_proposal.m_core.m_commitment_mask,
                        ref_set_decomp_n,
                        ref_set_decomp_m,
                        bin_config,
                        ledger_context)
            );
    }
}*/
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
