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
#include "tx_builders_legacy_inputs.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "device/device.hpp"
#include "jamtis_enote_utils.h"
#include "legacy_decoy_selector_flat.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"
#include "seraphis_config_temp.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"
#include "tx_legacy_builder_types.h"
#include "tx_legacy_component_types.h"
#include "tx_misc_utils.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"

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
//-------------------------------------------------------------------------------------------------------------------
static void prepare_clsag_proof_keys(const rct::ctkeyV &referenced_enotes,
    const rct::key &masked_commitment,
    rct::keyV referenced_onetime_addresses_out,
    rct::keyV referenced_amount_commitments_out,
    rct::keyV nominal_commitments_to_zero_out)
{
    referenced_onetime_addresses_out.clear();
    referenced_amount_commitments_out.clear();
    nominal_commitments_to_zero_out.clear();
    referenced_onetime_addresses_out.reserve(referenced_enotes.size());
    referenced_amount_commitments_out.reserve(referenced_enotes.size());
    nominal_commitments_to_zero_out.reserve(referenced_enotes.size());

    for (const rct::ctkey referenced_enote : referenced_enotes)
    {
        referenced_onetime_addresses_out.emplace_back(referenced_enote.dest);
        referenced_amount_commitments_out.emplace_back(referenced_enote.mask);
        nominal_commitments_to_zero_out.emplace_back();
        rct::subKeys(nominal_commitments_to_zero_out.back(), referenced_enote.mask, masked_commitment);
    }
}
//-------------------------------------------------------------------------------------------------------------------
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
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_legacy_input_proposal_semantics_v1(const LegacyInputProposalV1 &input_proposal,
    const rct::key &wallet_legacy_spend_pubkey)
{
    // 1. the onetime address must be reproducible
    // Ko ?= k_v_stuff + k^s G
    rct::key onetime_address_reproduced{wallet_legacy_spend_pubkey};
    mask_key(input_proposal.m_enote_view_privkey, onetime_address_reproduced, onetime_address_reproduced);

    CHECK_AND_ASSERT_THROW_MES(onetime_address_reproduced == input_proposal.m_onetime_address,
        "legacy input proposal v1 semantics check: could not reproduce the one-time address.");

    // 2. the key image must canonical (note: legacy key image can't be reproduced in a semantics checker because it needs
    //    the legacy private spend key [assumed not available in semantics checkers])
    CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(rct::ki2rct(input_proposal.m_key_image)),
        "legacy input proposal v1 semantics check: the key image is not canonical.");

    // 3. the amount commitment must be reproducible
    const rct::key amount_commitment_reproduced{
            rct::commit(input_proposal.m_amount, rct::sk2rct(input_proposal.m_amount_blinding_factor))
        };

    CHECK_AND_ASSERT_THROW_MES(amount_commitment_reproduced == input_proposal.m_amount_commitment,
        "legacy input proposal v1 semantics check: could not reproduce the amount commitment.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_proposal_v1(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    const crypto::key_image &key_image,
    const crypto::secret_key &enote_view_privkey,
    const crypto::secret_key &input_amount_blinding_factor,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &commitment_mask,
    LegacyInputProposalV1 &proposal_out)
{
    // make an input proposal
    proposal_out.m_onetime_address        = onetime_address;
    proposal_out.m_amount_commitment      = amount_commitment;
    proposal_out.m_key_image              = key_image;
    proposal_out.m_enote_view_privkey     = enote_view_privkey;
    proposal_out.m_amount_blinding_factor = input_amount_blinding_factor;
    proposal_out.m_amount                 = input_amount;
    proposal_out.m_commitment_mask        = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_proposal_v1(const LegacyEnoteRecord &enote_record,
    const crypto::secret_key &commitment_mask,
    LegacyInputProposalV1 &proposal_out)
{
    // make input proposal from enote record
    make_input_proposal(enote_record.m_enote.onetime_address(),
        enote_record.m_enote.amount_commitment(),
        enote_record.m_key_image,
        enote_record.m_enote_view_privkey,
        enote_record.m_amount_blinding_factor,
        enote_record.m_amount,
        commitment_mask,
        proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v3_legacy_ring_signature_v1(const rct::key &tx_proposal_prefix,
    std::vector<std::uint64_t> reference_set,
    const rct::ctkeyV &referenced_enotes,
    const std::uint64_t real_reference_index,
    const rct::key &masked_commitment,
    const crypto::secret_key &reference_view_privkey,
    const crypto::secret_key &reference_commitment_mask,
    const crypto::secret_key &legacy_spend_privkey,
    LegacyRingSignatureV3 &ring_signature_out)
{
    // make ring signature

    /// checks

    // reference sets
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(reference_set.begin(), reference_set.end()),
        "make v3 legacy ring signature: reference set indices are not sorted.");
    CHECK_AND_ASSERT_THROW_MES(!std::adjacent_find(reference_set.begin(), reference_set.end()),
        "make v3 legacy ring signature: reference set indices are not unique.");
    CHECK_AND_ASSERT_THROW_MES(reference_set.size() == referenced_enotes.size(),
        "make v3 legacy ring signature: reference set indices don't match referenced enotes.");
    CHECK_AND_ASSERT_THROW_MES(real_reference_index < referenced_enotes.size(),
        "make v3 legacy ring signature: real reference index is outside range of referenced enotes.");

    // reference onetime address is reproducible
    rct::key onetime_address_reproduced{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};
    rct::addKeys1(onetime_address_reproduced, rct::sk2rct(reference_view_privkey), onetime_address_reproduced);

    CHECK_AND_ASSERT_THROW_MES(onetime_address_reproduced == referenced_enotes[real_reference_index].dest,
        "make v3 legacy ring signature: could not reproduce onetime address.");

    // masked commitment is reproducible
    rct::key masked_commitment_reproduced{referenced_enotes[real_reference_index].mask};
    mask_key(reference_commitment_mask, masked_commitment_reproduced, masked_commitment_reproduced);

    CHECK_AND_ASSERT_THROW_MES(masked_commitment_reproduced == masked_commitment,
        "make v3 legacy ring signature: could not reproduce masked commitment (pseudo-output commitment).");


    /// prepare to make proof

    // prepare proof pubkeys
    rct::keyV referenced_onetime_addresses;
    rct::keyV referenced_amount_commitments
    rct::keyV nominal_commitments_to_zero;

    prepare_clsag_proof_keys(referenced_enotes,
        masked_commitment,
        referenced_onetime_addresses,
        referenced_amount_commitments,
        nominal_commitments_to_zero);

    // prepare signing key
    crypto::secret_key signing_privkey;
    sc_add(to_bytes(signing_privkey), to_bytes(reference_view_privkey), to_bytes(legacy_spend_privkey));

    // proof message
    rct::key message;
    make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix, reference_set, message);


    /// make clsag proof
    membership_proof_out.m_clsag_proof = CLSAG_Gen(message,
        referenced_onetime_addresses,
        rct::sk2rct(signing_privkey),
        nominal_commitments_to_zero,
        reference_commitment_mask,
        referenced_amount_commitments,
        masked_commitment,
        real_reference_index,
        hw::get_device("default"),
        message);


    /// save the reference set
    membership_proof_out.m_reference_set = std::move(reference_set);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v3_legacy_ring_signature_v1(LegacyRingSignaturePrepV1 ring_signature_prep,
    const crypto::secret_key &legacy_spend_privkey,
    LegacyRingSignatureV3 &ring_signature_out)
{
    make_v3_legacy_ring_signature_v1(ring_signature_prep.m_proposal_prefix,
        std::move(ring_signature_prep.m_reference_set),
        ring_signature_prep.m_referenced_enotes,
        ring_signature_prep.m_real_reference_index,
        ring_signature_prep.m_reference_image.m_masked_commitment,
        ring_signature_prep.m_reference_view_privkey,
        ring_signature_prep.m_reference_commitment_mask,
        legacy_spend_privkey,
        ring_signature_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v3_legacy_ring_signatures_v1(std::vector<LegacyRingSignaturePrepV1> ring_signature_preps,
    const crypto::secret_key &legacy_spend_privkey,
    std::vector<LegacyRingSignatureV3> &ring_signatures_out)
{
    // only allow signatures on the same tx proposal
    for (const LegacyRingSignaturePrepV1 &signature_prep : ring_signature_preps)
    {
        CHECK_AND_ASSERT_THROW_MES(signature_prep.m_proposal_prefix == ring_signature_preps.begin().m_proposal_prefix,
            "make v3 legacy ring signatures: inconsistent proposal prefixes.");
    }

    // sort ring signature preps
    std::sort(ring_signature_preps.begin(), ring_signature_preps.end());

    // make multiple ring signatures
    ring_signatures_out.clear();
    ring_signatures_out.reserve(membership_proof_preps.size());

    for (LegacyRingSignaturePrepV1 &signature_prep : ring_signature_preps)
    {
        ring_signatures_out.emplace_back();
        make_v1_membership_proof_v1(std::move(signature_prep), legacy_spend_privkey, ring_signatures_out.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_legacy_input_semantics_v1(const LegacyInputV1 &input)
{
    // masked commitment can be reconstructed
    const rct::key masked_commitment_reproduced{
            rct::commit(input.m_input_amount, rct::sk2rct(input.m_input_masked_commitment_blinding_factor))
        };

    CHECK_AND_ASSERT_THROW_MES(masked_commitment_reproduced == input.m_input_image.m_masked_commitment,
        "legacy input semantics (v1): could not reproduce masked commitment (pseudo-output commitment).");

    // key image is consistent between input image and cached value in the ring signature
    CHECK_AND_ASSERT_THROW_MES(input.m_input_image.m_key_image == input.m_ring_signature.m_clsag_proof.I,
        "legacy input semantics (v1): key image is not consistent between input image and ring signature.");

    // ring signature reference indices are sorted and unique and match with the cached reference enotes
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(input.m_ring_signature.m_reference_set.begin(),
            input.m_ring_signature.m_reference_set.end()),
        "legacy input semantics (v1): reference set indices are not sorted.");
    CHECK_AND_ASSERT_THROW_MES(!std::adjacent_find(input.m_ring_signature.m_reference_set.begin(),
            input.m_ring_signature.m_reference_set.end()),
        "legacy input semantics (v1): reference set indices are not unique.");
    CHECK_AND_ASSERT_THROW_MES(input.m_ring_signature.m_reference_set.size() == input.m_ring_members.size(),
        "legacy input semantics (v1): reference set indices don't match referenced enotes.");

    // ring signature message
    rct::key ring_signature_message;
    make_tx_legacy_ring_signature_message_v1(input.m_proposal_prefix,
        input.m_ring_signature.m_reference_set,
        ring_signature_message);

    // ring signature is valid
    CHECK_AND_ASSERT_THROW_MES(rct::verRctCLSAGSimple(ring_signature_message,
            input.m_ring_signature.m_clsag_proof,
            input.m_ring_members,
            input.m_input_image.m_masked_commitment),
        "legacy input semantics (v1): ring signature is invalid.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_v1(const rct::key &proposal_prefix,
    const LegacyInputProposalV1 &input_proposal,
    LegacyRingSignaturePrepV1 ring_signature_prep,
    const crypto::secret_key &legacy_spend_privkey,
    LegacyInputV1 &input_out)
{
    // check input proposal semantics
    const rct::key wallet_legacy_spend_pubkey{rct::scalarmultBase(rct:sk2rct(legacy_spend_privkey))};
    check_v1_legacy_input_proposal_semantics_v1(input_proposal, wallet_legacy_spend_pubkey);

    // ring signature prep must line up with specified proposal prefix
    CHECK_AND_ASSERT_THROW_MES(proposal_prefix == ring_signature_prep.m_proposal_prefix,
        "make v1 legacy input: ring signature prep does not have desired proposal prefix.");

    // prepare input image
    input_proposal.get_enote_image_v2(input_out.m_input_image);

    // copy misc. proposal info
    input_out.m_input_amount    = input_proposal.m_amount;
    sc_add(to_bytes(input_out.m_input_masked_commitment_blinding_factor),
        to_bytes(input_proposal.m_commitment_mask),
        to_bytes(input_proposal.m_amount_blinding_factor));
    input_out.m_ring_members    = ring_signature_prep.m_referenced_enotes;
    input_out.m_proposal_prefix = proposal_prefix;

    // construct ring signature
    make_v3_legacy_ring_signature_v1(std::move(ring_signature_prep), legacy_spend_privkey, input_out.m_ring_signature);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_inputs_v1(const rct::key &proposal_prefix,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    std::vector<LegacyRingSignaturePrepV1> ring_signature_preps,
    const crypto::secret_key &legacy_spend_privkey,
    std::vector<LegacyInputV1> &inputs_out)
{
    // checks
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Can't make legacy tx inputs without any input proposals.");
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == ring_signature_preps.size(),
        "make v1 legacy inputs: input proposals don't line up with ring signature preps.");

    inputs_out.clear();
    inputs_out.reserve(input_proposals.size());

    // make all inputs
    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        inputs_out.emplace_back();
        make_v1_legacy_input_v1(proposal_prefix,
            input_proposals[input_index],
            std::move(ring_signature_preps[input_index]),
            legacy_spend_privkey,
            inputs_out.back());
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
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
