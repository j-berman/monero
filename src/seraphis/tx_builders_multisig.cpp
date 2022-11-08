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
#include "tx_builders_multisig.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "crypto/generators.h"
#include "cryptonote_basic/subaddress_index.h"
#include "jamtis_address_utils.h"
#include "jamtis_core_utils.h"
#include "jamtis_enote_utils.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig_nonce_record.h"
#include "multisig_partial_sig_makers.h"
#include "multisig_signing_helper_types.h"
#include "multisig_signing_helper_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_config_temp.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "sp_misc_utils.h"
#include "tx_builder_types.h"
#include "tx_builder_types_multisig.h"
#include "tx_builders_inputs.h"
#include "tx_builders_legacy_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_contextual_enote_record_utils.h"
#include "tx_discretized_fee.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"
#include "tx_input_selection_output_context_v1.h"

//third party headers

//standard headers
#include <unordered_map>
#include <unordered_set>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// legacy proof context  [ legacy Ko : legacy input message ]
//-------------------------------------------------------------------------------------------------------------------
static void get_legacy_proof_contexts_v1(const rct::key &tx_proposal_prefix,
    const std::vector<LegacyMultisigInputProposalV1> &legacy_multisig_input_proposals,
    std::unordered_map<rct::key, rct::key> &proof_contexts_out)  //[ proof key : proof message ]
{
    proof_contexts_out.clear();

    for (const LegacyMultisigInputProposalV1 &input_proposal : legacy_multisig_input_proposals)
    {
        make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix,
            input_proposal.m_reference_set,
            proof_contexts_out[onetime_address_ref(input_proposal.m_enote)]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
// seraphis proof context  [ seraphis K" : tx proposal prefix ]
//-------------------------------------------------------------------------------------------------------------------
static void get_seraphis_proof_contexts_v1(const rct::key &tx_proposal_prefix,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    std::unordered_map<rct::key, rct::key> &proof_contexts_out)  //[ proof key : proof message ]
{
    proof_contexts_out.clear();
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &input_proposal : sp_input_proposals)
    {
        input_proposal.get_enote_image_v1(enote_image_temp);
        proof_contexts_out[enote_image_temp.m_core.m_masked_address] = tx_proposal_prefix;
    }
}
//-------------------------------------------------------------------------------------------------------------------
// legacy proof base points  [ legacy Ko : {G, Hp(legacy Ko)} ]
//-------------------------------------------------------------------------------------------------------------------
static void get_legacy_proof_base_keys_v1(const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    std::unordered_map<rct::key, rct::keyV> &legacy_proof_key_base_points_out)
{
    legacy_proof_key_base_points_out.clear();
    crypto::key_image KI_base_temp;

    for (const LegacyInputProposalV1 &input_proposal : legacy_input_proposals)
    {
        // Hp(Ko)
        crypto::generate_key_image(rct::rct2pk(input_proposal.m_onetime_address), rct::rct2sk(rct::I), KI_base_temp);

        // [ Ko : {G, Hp(Ko)} ]
        legacy_proof_key_base_points_out[input_proposal.m_onetime_address] =
            {
                rct::G,
                rct::ki2rct(KI_base_temp)
            };
    }
}
//-------------------------------------------------------------------------------------------------------------------
// seraphis proof keys  [ seraphis K" : {U} ]
//-------------------------------------------------------------------------------------------------------------------
static void get_sp_proof_base_keys_v1(const std::vector<SpInputProposalV1> &sp_input_proposals,
    std::unordered_map<rct::key, rct::keyV> &sp_proof_key_base_points_out)
{
    sp_proof_key_base_points_out.clear();
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &input_proposal : sp_input_proposals)
    {
        input_proposal.get_enote_image_v1(enote_image_temp);
        sp_proof_key_base_points_out[enote_image_temp.m_core.m_masked_address] = {rct::pk2rct(crypto::get_U())};
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_legacy_auxilliary_key_image_v1(const crypto::secret_key &commitment_mask,
    const rct::key &onetime_address,
    crypto::key_image &auxilliary_key_image_out)
{
    // z = - commitment mask
    crypto::secret_key z;
    sc_0(to_bytes(z));
    sc_sub(to_bytes(z), to_bytes(z), to_bytes(commitment_mask));

    // z Hp(Ko)
    crypto::generate_key_image(rct::rct2pk(onetime_address), z, auxilliary_key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_legacy_clsag_privkeys_for_multisig(const crypto::secret_key &enote_view_privkey,
    const crypto::secret_key &commitment_mask,
    crypto::secret_key &k_offset_out,
    crypto::secret_key &z_out)
{
    // prepare k_offset: legacy enote view prifkey
    k_offset_out = enote_view_privkey;

    // prepare z: - commitment mask
    // note: legacy commitments to zero are
    //  C_z = C[l] - C"
    //      = C[l] - (z G + C[l])
    //      = -z G
    sc_0(to_bytes(z_out));
    sc_sub(to_bytes(z_out), to_bytes(z_out), to_bytes(commitment_mask));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void collect_legacy_clsag_privkeys_for_multisig(const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    std::vector<crypto::secret_key> &proof_privkeys_k_offset_out,
    std::vector<crypto::secret_key> &proof_privkeys_z)
{
    CHECK_AND_ASSERT_THROW_MES(is_sorted_and_unique(legacy_input_proposals),
        "collect legacy clsag privkeys for multisig: legacy input proposals aren't sorted and unique.");

    proof_privkeys_k_offset_out.clear();
    proof_privkeys_z.clear();
    proof_privkeys_k_offset_out.reserve(legacy_input_proposals.size());
    proof_privkeys_z.reserve(legacy_input_proposals.size());

    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
    {
        prepare_legacy_clsag_privkeys_for_multisig(legacy_input_proposal.m_enote_view_privkey,
            legacy_input_proposal.m_commitment_mask,
            add_element(proof_privkeys_k_offset_out),
            add_element(proof_privkeys_z));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_sp_composition_proof_privkeys_for_multisig(const crypto::secret_key &enote_view_privkey_g,
    const crypto::secret_key &enote_view_privkey_x,
    const crypto::secret_key &enote_view_privkey_u,
    const crypto::secret_key &address_mask,
    const rct::key &squash_prefix,
    crypto::secret_key &x_out,
    crypto::secret_key &y_out,
    crypto::secret_key &z_offset_out,
    crypto::secret_key &z_multiplier_out)
{
    // prepare x: t_k + Hn(Ko, C) * k_mask
    sc_mul(to_bytes(x_out), squash_prefix.bytes, to_bytes(enote_view_privkey_g));
    sc_add(to_bytes(x_out), to_bytes(address_mask), to_bytes(x_out));

    // prepare y: Hn(Ko, C) * k_a
    sc_mul(to_bytes(y_out), squash_prefix.bytes, to_bytes(enote_view_privkey_x));

    // prepare z_offset: k_view_u
    z_offset_out = enote_view_privkey_u;

    // prepare z_multiplier: Hn(Ko, C)
    z_multiplier_out = rct::rct2sk(squash_prefix);

    // note: z = z_multiplier * (z_offset + sum_e(z_e))
    //         = Hn(Ko, C)    * (k_view_u + k_spend_u )
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void collect_sp_composition_proof_privkeys_for_multisig(const std::vector<SpInputProposalV1> &sp_input_proposals,
    std::vector<crypto::secret_key> &proof_privkeys_x_out,
    std::vector<crypto::secret_key> &proof_privkeys_y_out,
    std::vector<crypto::secret_key> &proof_privkeys_z_offset_out,
    std::vector<crypto::secret_key> &proof_privkeys_z_multiplier_out)
{
    CHECK_AND_ASSERT_THROW_MES(is_sorted_and_unique(sp_input_proposals),
        "collect sp composition proof privkeys for multisig: sp input proposals aren't sorted and unique.");

    proof_privkeys_x_out.clear();
    proof_privkeys_y_out.clear();
    proof_privkeys_z_offset_out.clear();
    proof_privkeys_z_multiplier_out.clear();
    proof_privkeys_x_out.reserve(sp_input_proposals.size());
    proof_privkeys_y_out.reserve(sp_input_proposals.size());
    proof_privkeys_z_offset_out.reserve(sp_input_proposals.size());
    proof_privkeys_z_multiplier_out.reserve(sp_input_proposals.size());
    rct::key squash_prefix_temp;

    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
    {
        // Hn(Ko, C)
        sp_input_proposal.get_squash_prefix(squash_prefix_temp);

        // x, y, z_offset, z_multiplier
        prepare_sp_composition_proof_privkeys_for_multisig(sp_input_proposal.m_core.m_enote_view_privkey_g,
            sp_input_proposal.m_core.m_enote_view_privkey_x,
            sp_input_proposal.m_core.m_enote_view_privkey_u,
            sp_input_proposal.m_core.m_address_mask,
            squash_prefix_temp,
            add_element(proof_privkeys_x_out),
            add_element(proof_privkeys_y_out),
            add_element(proof_privkeys_z_offset_out),
            add_element(proof_privkeys_z_multiplier_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_make_v1_legacy_input_v1(const rct::key &tx_proposal_prefix,
    const LegacyInputProposalV1 &input_proposal,
    std::vector<std::uint64_t> reference_set,
    rct::ctkeyV referenced_enotes,
    const rct::key &masked_commitment,
    const std::vector<CLSAGMultisigPartial> &input_proof_partial_sigs,
    const rct::key &legacy_spend_pubkey,
    LegacyInputV1 &input_out)
{
    try
    {
        // 1. make legacy ring signature message
        rct::key ring_signature_message;
        make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix, reference_set, ring_signature_message);

        // 2. all partial sigs must sign the expected message
        for (const CLSAGMultisigPartial &partial_sig : input_proof_partial_sigs)
        {
            CHECK_AND_ASSERT_THROW_MES(partial_sig.message == ring_signature_message,
                "multisig make partial input: a partial signature's message does not match the expected message.");
        }

        // 3. assemble proof (will throw if partial sig assembly doesn't produce a valid proof)
        LegacyRingSignatureV3 ring_signature;
        finalize_clsag_multisig_proof(input_proof_partial_sigs,
            referenced_enotes,
            masked_commitment,
            ring_signature.m_clsag_proof);

        ring_signature.m_reference_set = std::move(reference_set);

        // 4. make legacy input
        make_v1_legacy_input_v1(tx_proposal_prefix,
            input_proposal,
            std::move(referenced_enotes),
            std::move(ring_signature),
            legacy_spend_pubkey,
            input_out);

        // 5. validate semantics to minimize failure modes
        check_v1_legacy_input_semantics_v1(input_out);
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_make_v1_sp_partial_input_v1(const rct::key &expected_proposal_prefix,
    const SpInputProposalV1 &input_proposal,
    const std::vector<SpCompositionProofMultisigPartial> &input_proof_partial_sigs,
    const rct::key &sp_spend_pubkey,
    SpPartialInputV1 &partial_input_out)
{
    try
    {
        // all partial sigs must sign the expected message
        for (const SpCompositionProofMultisigPartial &partial_sig : input_proof_partial_sigs)
        {
            CHECK_AND_ASSERT_THROW_MES(partial_sig.message == expected_proposal_prefix,
                "multisig make partial input: a partial signature's message does not match the expected proposal prefix.");
        }

        // assemble proof (will throw if partial sig assembly doesn't produce a valid proof)
        SpImageProofV1 sp_image_proof;
        finalize_sp_composition_multisig_proof(input_proof_partial_sigs, sp_image_proof.m_composition_proof);

        // make the partial input
        make_v1_partial_input_v1(input_proposal,
            expected_proposal_prefix,
            std::move(sp_image_proof),
            sp_spend_pubkey,
            partial_input_out);

        // validate semantics to minimize failure modes
        check_v1_partial_input_semantics_v1(partial_input_out);
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_make_legacy_inputs_for_multisig_v1(const rct::key &tx_proposal_prefix,
    const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    const std::vector<LegacyMultisigInputProposalV1> &legacy_multisig_input_proposals,
    const std::vector<CLSAGMultisigProposal> &legacy_input_proof_proposals,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::unordered_map<crypto::public_key, std::vector<MultisigPartialSigSetV1>> &legacy_input_partial_sigs_per_signer,
    const rct::key &legacy_spend_pubkey,
    std::vector<LegacyInputV1> &legacy_inputs_out)
{
    // 1. process input proposals
    // - map legacy input proposals to their onetime addresses
    // - map masked commitments to the corresponding onetime addresses
    std::unordered_map<rct::key, LegacyInputProposalV1> mapped_legacy_input_proposals;
    std::unordered_map<rct::key, rct::key> mapped_masked_commitments;

    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
    {
        mapped_legacy_input_proposals[legacy_input_proposal.m_onetime_address] = legacy_input_proposal;
        mask_key(legacy_input_proposal.m_commitment_mask,
            legacy_input_proposal.m_amount_commitment,
            mapped_masked_commitments[legacy_input_proposal.m_onetime_address]);
    }

    // 2. process multisig input proposals
    // - map ring signature messages to onetime addresses
    // - map legacy reference sets to onetime addresses
    std::unordered_map<rct::key, rct::key> legacy_proof_contexts;  //[ proof key : proof message ]
    std::unordered_map<rct::key, std::vector<std::uint64_t>> mapped_reference_sets;
    rct::key message_temp;

    for (const LegacyMultisigInputProposalV1 &legacy_multisig_input_proposal : legacy_multisig_input_proposals)
    {
        // [ proof key : proof message ]
        make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix,
            legacy_multisig_input_proposal.m_reference_set,
            message_temp);
        legacy_proof_contexts[onetime_address_ref(legacy_multisig_input_proposal.m_enote)] = message_temp;

        // [ proof key : reference set ]
        mapped_reference_sets[onetime_address_ref(legacy_multisig_input_proposal.m_enote)] =
            legacy_multisig_input_proposal.m_reference_set;
    }

    // 3. map legacy ring members to onetime addresses
    std::unordered_map<rct::key, rct::ctkeyV> mapped_ring_members;

    for (const CLSAGMultisigProposal &legacy_input_proof_proposal : legacy_input_proof_proposals)
        mapped_ring_members[legacy_input_proof_proposal.main_proof_key()] = legacy_input_proof_proposal.ring_members;

    // 4. filter the legacy partial signatures into a map
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //proof key (onetime address)
            std::vector<MultisigPartialSigVariant>>> collected_sigs_per_key_per_filter;

    filter_multisig_partial_signatures_for_combining_v1(multisig_signers,
        legacy_proof_contexts,
        MultisigPartialSigVariant::type_index_of<CLSAGMultisigPartial>(),
        legacy_input_partial_sigs_per_signer,
        collected_sigs_per_key_per_filter);

    // 5. try to make one legacy input per input proposal, using the partial signatures from as many signing groups as
    //    necessary
    if (!try_assemble_multisig_partial_sigs_signer_group_attempts<CLSAGMultisigPartial, LegacyInputV1>(
                legacy_input_proposals.size(),
                collected_sigs_per_key_per_filter,
                [&](const rct::key &proof_key,
                    const std::vector<CLSAGMultisigPartial> &partial_sigs,
                    LegacyInputV1 &contextual_sig_out) -> bool
                {
                    // sanity check
                    if (legacy_proof_contexts.find(proof_key) == legacy_proof_contexts.end())
                        return false;

                    // try to make the input
                    return try_make_v1_legacy_input_v1(tx_proposal_prefix,
                        mapped_legacy_input_proposals.at(proof_key),
                        mapped_reference_sets.at(proof_key),
                        mapped_ring_members.at(proof_key),
                        mapped_masked_commitments.at(proof_key),
                        partial_sigs,
                        legacy_spend_pubkey,
                        contextual_sig_out);
                },
                legacy_inputs_out
            ))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_make_sp_partial_inputs_for_multisig_v1(const rct::key &tx_proposal_prefix,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::unordered_map<crypto::public_key, std::vector<MultisigPartialSigSetV1>> &sp_input_partial_sigs_per_signer,
    const rct::key &sp_spend_pubkey,
    std::vector<SpPartialInputV1> &sp_partial_inputs_out)
{
    // 1. collect seraphis masked addresses of input images and map seraphis input proposals to their masked addresses
    std::unordered_map<rct::key, rct::key> sp_proof_contexts;  //[ proof key : proof message ]
    std::unordered_map<rct::key, SpInputProposalV1> mapped_sp_input_proposals;
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
    {
        sp_input_proposal.get_enote_image_v1(enote_image_temp);
        sp_proof_contexts[enote_image_temp.m_core.m_masked_address] = tx_proposal_prefix;
        mapped_sp_input_proposals[enote_image_temp.m_core.m_masked_address] = sp_input_proposal;
    }

    // 2. filter the seraphis partial signatures into a map
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //proof key (masked address)
            std::vector<MultisigPartialSigVariant>>> collected_sigs_per_key_per_filter;

    filter_multisig_partial_signatures_for_combining_v1(multisig_signers,
        sp_proof_contexts,
        MultisigPartialSigVariant::type_index_of<SpCompositionProofMultisigPartial>(),
        sp_input_partial_sigs_per_signer,
        collected_sigs_per_key_per_filter);

    // 3. try to make one seraphis partial input per input proposal
    if (!try_assemble_multisig_partial_sigs_signer_group_attempts<SpCompositionProofMultisigPartial, SpPartialInputV1>(
                sp_input_proposals.size(),
                collected_sigs_per_key_per_filter,
                [&](const rct::key &proof_key,
                    const std::vector<SpCompositionProofMultisigPartial> &partial_sigs,
                    SpPartialInputV1 &sp_partial_input_out) -> bool
                {
                    // sanity check
                    if (sp_proof_contexts.find(proof_key) == sp_proof_contexts.end())
                        return false;

                    // try to make the partial input
                    return try_make_v1_sp_partial_input_v1(tx_proposal_prefix,
                        mapped_sp_input_proposals.at(proof_key),
                        partial_sigs,
                        sp_spend_pubkey,
                        sp_partial_input_out);
                },
                sp_partial_inputs_out
            ))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_v1_legacy_multisig_input_proposal_semantics_v1(const LegacyMultisigInputProposalV1 &multisig_input_proposal)
{
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(multisig_input_proposal.m_commitment_mask)),
        "legacy multisig input proposal: bad address mask (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(multisig_input_proposal.m_commitment_mask)) == 0,
        "legacy multisig input proposal: bad address mask (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(std::find(multisig_input_proposal.m_reference_set.begin(),
                multisig_input_proposal.m_reference_set.end(),
                multisig_input_proposal.m_tx_output_index) !=
            multisig_input_proposal.m_reference_set.end(),
        "legacy multisig input proposal: referenced enote index is not in the reference set.");
    CHECK_AND_ASSERT_THROW_MES(is_sorted_and_unique(multisig_input_proposal.m_reference_set),
        "legacy multisig input proposal: reference set indices are not sorted.");
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_sp_multisig_input_proposal_semantics_v1(const SpMultisigInputProposalV1 &multisig_input_proposal)
{
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(multisig_input_proposal.m_address_mask)),
        "sp multisig input proposal: bad address mask (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(multisig_input_proposal.m_address_mask)) == 0,
        "sp multisig input proposal: bad address mask (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(multisig_input_proposal.m_commitment_mask)),
        "sp multisig input proposal: bad address mask (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(multisig_input_proposal.m_commitment_mask)) == 0,
        "sp multisig input proposal: bad address mask (not canonical).");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_multisig_input_proposal_v1(const LegacyEnoteVariant &enote,
    const crypto::key_image &key_image,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const std::uint64_t unlock_time,
    const crypto::secret_key &commitment_mask,
    std::vector<std::uint64_t> reference_set,
    LegacyMultisigInputProposalV1 &proposal_out)
{
    // add components
    proposal_out.m_enote = enote;
    proposal_out.m_key_image = key_image;
    proposal_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    proposal_out.m_tx_output_index = tx_output_index;
    proposal_out.m_unlock_time = unlock_time;
    proposal_out.m_commitment_mask = commitment_mask;
    proposal_out.m_reference_set = std::move(reference_set);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_multisig_input_proposal_v1(const LegacyEnoteRecord &enote_record,
    const crypto::secret_key &commitment_mask,
    std::vector<std::uint64_t> reference_set,
    LegacyMultisigInputProposalV1 &proposal_out)
{
    make_v1_legacy_multisig_input_proposal_v1(enote_record.m_enote,
        enote_record.m_key_image,
        enote_record.m_enote_ephemeral_pubkey,
        enote_record.m_tx_output_index,
        enote_record.m_unlock_time,
        commitment_mask,
        std::move(reference_set),
        proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_sp_multisig_input_proposal_v1(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out)
{
    // add components
    proposal_out.m_enote = enote;
    proposal_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    proposal_out.m_input_context = input_context;
    proposal_out.m_address_mask = address_mask;
    proposal_out.m_commitment_mask = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_sp_multisig_input_proposal_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out)
{
    make_v1_sp_multisig_input_proposal_v1(enote_record.m_enote,
        enote_record.m_enote_ephemeral_pubkey,
        enote_record.m_input_context,
        address_mask,
        commitment_mask,
        proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_tx_proposal_semantics_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::string &expected_version_string,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    /// multisig signing config checks

    // 1. proposal should contain expected tx version encoding
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_version_string == expected_version_string,
        "multisig tx proposal: intended tx version encoding is invalid.");

    // 2. signer set filter must be valid (at least 'threshold' signers allowed, format is valid)
    CHECK_AND_ASSERT_THROW_MES(multisig::validate_aggregate_multisig_signer_set_filter(threshold,
            num_signers,
            multisig_tx_proposal.m_aggregate_signer_set_filter),
        "multisig tx proposal: invalid aggregate signer set filter.");


    /// input/output checks

    // 1. check the multisig input proposal semantics
    for (const LegacyMultisigInputProposalV1 &legacy_multisig_input_proposal :
            multisig_tx_proposal.m_legacy_multisig_input_proposals)
        check_v1_legacy_multisig_input_proposal_semantics_v1(legacy_multisig_input_proposal);

    for (const SpMultisigInputProposalV1 &sp_multisig_input_proposal :
            multisig_tx_proposal.m_sp_multisig_input_proposals)
        check_v1_sp_multisig_input_proposal_semantics_v1(sp_multisig_input_proposal);

    // 2. convert the proposal to a plain tx proposal and check its semantics (a comprehensive set of tests)
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    check_v1_tx_proposal_semantics_v1(tx_proposal, legacy_spend_pubkey, jamtis_spend_pubkey, k_view_balance);

    // - get prefix from proposal
    rct::key tx_proposal_prefix;
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, tx_proposal_prefix);

    // 3. collect legacy ring signature messages
    std::unordered_map<rct::key, rct::key> legacy_proof_contexts;  //[ proof key : proof message ]

    for (const LegacyMultisigInputProposalV1 &legacy_multisig_input_proposal :
            multisig_tx_proposal.m_legacy_multisig_input_proposals)
    {
        make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix,
            legacy_multisig_input_proposal.m_reference_set,
            legacy_proof_contexts[onetime_address_ref(legacy_multisig_input_proposal.m_enote)]);
    }


    /// multisig-related input checks

    // 1. input proposals line up 1:1 with multisig input proof proposals
    CHECK_AND_ASSERT_THROW_MES(tx_proposal.m_legacy_input_proposals.size() ==
            multisig_tx_proposal.m_legacy_input_proof_proposals.size(),
        "multisig tx proposal: legacy input proposals don't line up with input proposal proofs.");

    CHECK_AND_ASSERT_THROW_MES(tx_proposal.m_sp_input_proposals.size() ==
            multisig_tx_proposal.m_sp_input_proof_proposals.size(),
        "multisig tx proposal: sp input proposals don't line up with input proposal proofs.");

    // 2. assess each legacy input proof proposal (iterate through sorted legacy input vectors; note that multisig input
    //    proposals are NOT sorted)
    LegacyEnoteImageV2 legacy_enote_image_temp;
    crypto::key_image auxilliary_key_image_temp;

    for (std::size_t legacy_input_index{0};
        legacy_input_index < multisig_tx_proposal.m_legacy_input_proof_proposals.size();
        ++legacy_input_index)
    {
        const LegacyInputProposalV1 &input_proposal{
                tx_proposal.m_legacy_input_proposals[legacy_input_index]
            };
        const CLSAGMultisigProposal &input_proof_proposal{
                multisig_tx_proposal.m_legacy_input_proof_proposals[legacy_input_index]
            };

        // a. input proof proposal messages all equal expected values
        CHECK_AND_ASSERT_THROW_MES(legacy_proof_contexts.find(input_proposal.m_onetime_address) !=
                legacy_proof_contexts.end(),
            "multisig tx proposal: legacy input proof contexts is missing a proof key (bug).");
        CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.message ==
                legacy_proof_contexts.at(input_proposal.m_onetime_address),
            "multisig tx proposal: legacy input proof proposal does not match the tx proposal (unknown proof message).");

        // b. input proof proposal keys line up 1:1 and match with input proposals
        input_proposal.get_enote_image_v2(legacy_enote_image_temp);

        CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.main_proof_key() == input_proposal.m_onetime_address,
            "multisig tx proposal: legacy input proof proposal does not match input proposal (different proof keys).");
        CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.auxilliary_proof_key() == input_proposal.m_amount_commitment,
            "multisig tx proposal: legacy input proof proposal does not match input proposal (different amount "
            "commitments).");
        CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.masked_C == legacy_enote_image_temp.m_masked_commitment,
            "multisig tx proposal: legacy input proof proposal does not match input proposal (different masked "
            "commitments).");

        // c. input proof proposal key images line up 1:1 and match with input proposals
        CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.KI == legacy_enote_image_temp.m_key_image,
            "multisig tx proposal: legacy input proof proposal does not match input proposal (different KI).");

        make_legacy_auxilliary_key_image_v1(input_proposal.m_commitment_mask,
                input_proposal.m_onetime_address,
                auxilliary_key_image_temp);

        CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.D == auxilliary_key_image_temp,
            "multisig tx proposal: legacy input proof proposal does not match input proposal (different D).");

        // d. ring-related information is aligned
        CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.ring_members.size() ==
                input_proof_proposal.decoy_responses.size(),
            "multisig tx proposal: legacy input proof proposal has invalid number of decoy responses.");
        CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.l < input_proof_proposal.ring_members.size(),
            "multisig tx proposal: legacy input proof proposal has out-of-range real index.");
    }

    // 3. assess each seraphis input proof proposal (iterate through sorted legacy input vectors; note that multisig
    //    input proposals are NOT sorted)
    SpEnoteImageV1 sp_enote_image_temp;

    for (std::size_t sp_input_index{0};
        sp_input_index < multisig_tx_proposal.m_sp_input_proof_proposals.size();
        ++sp_input_index)
    {
        const SpInputProposalV1 &input_proposal{
                tx_proposal.m_sp_input_proposals[sp_input_index]
            };
        const SpCompositionProofMultisigProposal &input_proof_proposal{
                multisig_tx_proposal.m_sp_input_proof_proposals[sp_input_index]
            };

        // a. input proof proposal messages all equal proposal prefix of core tx proposal
        CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.message == tx_proposal_prefix,
            "multisig tx proposal: sp input proof proposal does not match the tx proposal (different proposal prefix).");

        // b. input proof proposal keys line up 1:1 and match with input proposals
        input_proposal.get_enote_image_v1(sp_enote_image_temp);

        CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.K == sp_enote_image_temp.m_core.m_masked_address,
            "multisig tx proposal: sp input proof proposal does not match input proposal (different proof keys).");

        // c. input proof proposal key images line up 1:1 and match with input proposals
        CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.KI == sp_enote_image_temp.m_core.m_key_image,
            "multisig tx proposal: sp input proof proposal does not match input proposal (different key images).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_tx_proposal_v1(std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    const DiscretizedFee &tx_fee,
    std::string version_string,
    std::vector<LegacyMultisigInputProposalV1> legacy_multisig_input_proposals,
    std::vector<SpMultisigInputProposalV1> sp_multisig_input_proposals,
    std::unordered_map<crypto::key_image, LegacyMultisigRingSignaturePrepV1> legacy_multisig_ring_signature_preps,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigTxProposalV1 &proposal_out)
{
    CHECK_AND_ASSERT_THROW_MES(keys_match_internal_values(legacy_multisig_ring_signature_preps,
            [](const LegacyMultisigRingSignaturePrepV1 &prep) -> const crypto::key_image&
            {
                return prep.m_key_image;
            }),
        "make v1 multisig tx proposal (v1): a legacy ring signature prep is mapped to the incorrect key image.");

    // 1. convert legacy multisig input proposals to input proposals
    std::vector<LegacyInputProposalV1> legacy_input_proposals;

    for (const LegacyMultisigInputProposalV1 &legacy_multisig_input_proposal : legacy_multisig_input_proposals)
    {
        legacy_multisig_input_proposal.get_input_proposal_v1(legacy_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            add_element(legacy_input_proposals));
    }

    // 2. convert seraphis multisig input proposals to input proposals
    std::vector<SpInputProposalV1> sp_input_proposals;

    for (const SpMultisigInputProposalV1 &sp_multisig_input_proposal : sp_multisig_input_proposals)
    {
        sp_multisig_input_proposal.get_input_proposal_v1(jamtis_spend_pubkey,
            k_view_balance,
            add_element(sp_input_proposals));
    }

    // 3. make a temporary normal tx proposal
    SpTxProposalV1 tx_proposal;
    make_v1_tx_proposal_v1(normal_payment_proposals,
        selfsend_payment_proposals,
        tx_fee,
        std::move(legacy_input_proposals),
        std::move(sp_input_proposals),
        additional_memo_elements,
        tx_proposal);

    // 4. sanity check the normal tx proposal
    check_v1_tx_proposal_semantics_v1(tx_proposal, legacy_spend_pubkey, jamtis_spend_pubkey, k_view_balance);

    // 5. get proposal prefix
    rct::key tx_proposal_prefix;
    tx_proposal.get_proposal_prefix(version_string, k_view_balance, tx_proposal_prefix);

    // 6. make sure the legacy proof preps align with legacy input proposals
    // note: if the legacy input proposals contain duplicates, then the call to check_v1_tx_proposal_semantics_v1()
    //       will catch it
    CHECK_AND_ASSERT_THROW_MES(legacy_multisig_ring_signature_preps.size() ==
            tx_proposal.m_legacy_input_proposals.size(),
        "make v1 multisig tx proposal (v1): legacy ring signature preps don't line up with input proposals.");

    // 7. prepare legacy proof proposals (note: using the tx proposal ensures proof proposals are sorted)
    proposal_out.m_legacy_input_proof_proposals.clear();
    proposal_out.m_legacy_input_proof_proposals.reserve(tx_proposal.m_legacy_input_proposals.size());
    rct::key legacy_ring_signature_message_temp;
    LegacyEnoteImageV2 legacy_enote_image_temp;
    crypto::key_image auxilliary_key_image_temp;

    for (const LegacyInputProposalV1 &legacy_input_proposal : tx_proposal.m_legacy_input_proposals)
    {
        CHECK_AND_ASSERT_THROW_MES(legacy_multisig_ring_signature_preps.find(legacy_input_proposal.m_key_image) !=
                legacy_multisig_ring_signature_preps.end(),
            "make v1 multisig tx proposal (v1): a legacy ring signature prep doesn't line up with an input proposal.");

        // legacy message (per-proof)
        make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix,
            legacy_multisig_ring_signature_preps.at(legacy_input_proposal.m_key_image).m_reference_set,
            legacy_ring_signature_message_temp);

        // legacy enote image
        legacy_input_proposal.get_enote_image_v2(legacy_enote_image_temp);

        // legacy auxilliary key image: D
        make_legacy_auxilliary_key_image_v1(
            legacy_input_proposal.m_commitment_mask,
            legacy_input_proposal.m_onetime_address,
            auxilliary_key_image_temp);

        // legacy multisig proof proposal
        make_clsag_multisig_proposal(legacy_ring_signature_message_temp,
            std::move(legacy_multisig_ring_signature_preps[legacy_input_proposal.m_key_image].m_referenced_enotes),
            legacy_enote_image_temp.m_masked_commitment,
            legacy_enote_image_temp.m_key_image,
            auxilliary_key_image_temp,
            legacy_multisig_ring_signature_preps.at(legacy_input_proposal.m_key_image).m_real_reference_index,
            add_element(proposal_out.m_legacy_input_proof_proposals));
    }

    // 8. prepare composition proof proposals for each seraphis input (note: using the tx proposal ensures proof
    //    proposals are sorted)
    proposal_out.m_sp_input_proof_proposals.clear();
    proposal_out.m_sp_input_proof_proposals.reserve(tx_proposal.m_sp_input_proposals.size());
    SpEnoteImageV1 sp_enote_image_temp;

    for (const SpInputProposalV1 &sp_input_proposal : tx_proposal.m_sp_input_proposals)
    {
        sp_input_proposal.get_enote_image_v1(sp_enote_image_temp);

        make_sp_composition_multisig_proposal(tx_proposal_prefix,
            sp_enote_image_temp.m_core.m_masked_address,
            sp_enote_image_temp.m_core.m_key_image,
            add_element(proposal_out.m_sp_input_proof_proposals));
    }

    // 9. add miscellaneous components
    proposal_out.m_legacy_multisig_input_proposals = std::move(legacy_multisig_input_proposals);
    proposal_out.m_sp_multisig_input_proposals = std::move(sp_multisig_input_proposals);
    proposal_out.m_normal_payment_proposals = std::move(normal_payment_proposals);
    proposal_out.m_selfsend_payment_proposals = std::move(selfsend_payment_proposals);
    make_tx_extra(std::move(additional_memo_elements), proposal_out.m_partial_memo);
    proposal_out.m_tx_fee = tx_fee;
    proposal_out.m_aggregate_signer_set_filter = aggregate_signer_set_filter;
    proposal_out.m_version_string = std::move(version_string);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_tx_proposal_v1(const std::list<LegacyContextualEnoteRecordV1> &legacy_contextual_inputs,
    const std::list<SpContextualEnoteRecordV1> &sp_contextual_inputs,
    std::unordered_map<crypto::key_image, LegacyMultisigRingSignaturePrepV1> legacy_multisig_ring_signature_preps,
    const sp::SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    const multisig::signer_set_filter aggregate_filter_of_requested_multisig_signers,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    TxExtra partial_memo_for_tx,
    const DiscretizedFee &tx_fee,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigTxProposalV1 &multisig_tx_proposal_out)
{
    // 1. convert legacy inputs to legacy multisig input proposals (inputs to spend)
    CHECK_AND_ASSERT_THROW_MES(legacy_contextual_inputs.size() == legacy_multisig_ring_signature_preps.size(),
        "make v1 multisig tx proposal (v1): legacy contextual inputs don't line up with ring signature preps.");

    std::vector<LegacyMultisigInputProposalV1> legacy_multisig_input_proposals;
    legacy_multisig_input_proposals.reserve(legacy_contextual_inputs.size());

    for (const LegacyContextualEnoteRecordV1 &legacy_contextual_input : legacy_contextual_inputs)
    {
        CHECK_AND_ASSERT_THROW_MES(legacy_multisig_ring_signature_preps.find(legacy_contextual_input.key_image()) !=
                legacy_multisig_ring_signature_preps.end(),
            "make v1 multisig tx proposal (v1): a legacy ring signature prep doesn't line up with a contextual input.");
        CHECK_AND_ASSERT_THROW_MES(
                legacy_multisig_ring_signature_preps.at(legacy_contextual_input.key_image()).m_key_image ==
                    legacy_contextual_input.key_image(),
            "make v1 multisig tx proposal (v1): a legacy ring signature prep is mapped to the incorrect key image.");

        // convert inputs to input proposals
        make_v1_legacy_multisig_input_proposal_v1(legacy_contextual_input.m_record,
            rct::rct2sk(rct::skGen()),
            legacy_multisig_ring_signature_preps
                    .at(legacy_contextual_input.key_image())
                    .m_reference_set,  //don't consume, the full prep needs to be consumed later
            add_element(legacy_multisig_input_proposals));
    }

    // 2. convert seraphis inputs to seraphis multisig input proposals (inputs to spend)
    std::vector<SpMultisigInputProposalV1> sp_multisig_input_proposals;
    sp_multisig_input_proposals.reserve(sp_contextual_inputs.size());

    for (const SpContextualEnoteRecordV1 &contextual_input : sp_contextual_inputs)
    {
        // convert inputs to input proposals
        make_v1_sp_multisig_input_proposal_v1(contextual_input.m_record,
            rct::rct2sk(rct::skGen()),
            rct::rct2sk(rct::skGen()),
            add_element(sp_multisig_input_proposals));
    }

    // 3. get memo elements
    std::vector<ExtraFieldElement> extra_field_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(partial_memo_for_tx, extra_field_elements),
        "make tx proposal for transfer (v1): unable to extract memo field elements for tx proposal.");

    // 4. finalize multisig tx proposal
    std::string version_string;
    make_versioning_string(semantic_rules_version, version_string);

    make_v1_multisig_tx_proposal_v1(std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        std::move(extra_field_elements),
        tx_fee,
        version_string,
        std::move(legacy_multisig_input_proposals),
        std::move(sp_multisig_input_proposals),
        std::move(legacy_multisig_ring_signature_preps),
        aggregate_filter_of_requested_multisig_signers,
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        multisig_tx_proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_init_sets_for_inputs_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::string &expected_version_string,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    MultisigNonceRecord &nonce_record_inout,
    std::unordered_map<rct::key, MultisigProofInitSetV1> &legacy_input_init_set_collection_out,
    std::unordered_map<rct::key, MultisigProofInitSetV1> &sp_input_init_set_collection_out)
{
    // 1. validate multisig tx proposal
    check_v1_multisig_tx_proposal_semantics_v1(multisig_tx_proposal,
        expected_version_string,
        threshold,
        multisig_signers.size(),
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance);

    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_legacy_multisig_input_proposals.size() +
            multisig_tx_proposal.m_sp_multisig_input_proposals.size() > 0,
        "make multisig input init sets: no inputs to initialize.");

    // 2. make tx proposal (for sorted inputs and the tx proposal prefix)
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    // 3. tx proposal prefix
    rct::key tx_proposal_prefix;
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, tx_proposal_prefix);

    // 4. prepare proof contexts and multisig proof base points
    // a. legacy proof context     [ legacy Ko : legacy input message ]
    // b. legacy proof base points [ legacy Ko : {G, Hp(legacy Ko)}   ]
    std::unordered_map<rct::key, rct::key> legacy_input_proof_contexts;
    std::unordered_map<rct::key, rct::keyV> legacy_proof_key_base_points;
    get_legacy_proof_contexts_v1(tx_proposal_prefix,
        multisig_tx_proposal.m_legacy_multisig_input_proposals,
        legacy_input_proof_contexts);
    get_legacy_proof_base_keys_v1(tx_proposal.m_legacy_input_proposals, legacy_proof_key_base_points);

    // c. seraphis proof context [ seraphis K" : tx proposal prefix ]
    // d. seraphis proof keys    [ seraphis K" : {U}                ]
    std::unordered_map<rct::key, rct::key> sp_input_proof_contexts;
    std::unordered_map<rct::key, rct::keyV> sp_proof_key_base_points;
    get_seraphis_proof_contexts_v1(tx_proposal_prefix, tx_proposal.m_sp_input_proposals, sp_input_proof_contexts);
    get_sp_proof_base_keys_v1(tx_proposal.m_sp_input_proposals, sp_proof_key_base_points);

    // 5. finish making multisig input init sets
    // a. legacy input init set
    make_v1_multisig_init_set_collection_v1(threshold,
        multisig_signers,
        multisig_tx_proposal.m_aggregate_signer_set_filter,
        signer_id,
        legacy_input_proof_contexts,
        legacy_proof_key_base_points,
        nonce_record_inout,
        legacy_input_init_set_collection_out);

    // b. seraphis input init set
    make_v1_multisig_init_set_collection_v1(threshold,
        multisig_signers,
        multisig_tx_proposal.m_aggregate_signer_set_filter,
        signer_id,
        sp_input_proof_contexts,
        sp_proof_key_base_points,
        nonce_record_inout,
        sp_input_init_set_collection_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_multisig_partial_sig_sets_for_legacy_inputs_v1(const multisig::multisig_account &signer_account,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const std::string &expected_version_string,
    //[ proof key : init set ]
    std::unordered_map<rct::key, MultisigProofInitSetV1> local_input_init_set_collection,
    //[ signer id : [ proof key : init set ] ]
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        other_input_init_set_collections,
    MultisigNonceRecord &nonce_record_inout,
    std::vector<MultisigPartialSigSetV1> &legacy_input_partial_sig_sets_out)
{
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "multisig legacy input partial sigs: signer account is not complete, so it can't make partial signatures.");
    CHECK_AND_ASSERT_THROW_MES(signer_account.get_era() == cryptonote::account_generator_era::cryptonote,
        "multisig legacy input partial sigs: signer account is not a cryptonote account, so it can't make legacy partial "
        "signatures.");

    // early return if there are no legacy inputs in the multisig tx proposal
    if (multisig_tx_proposal.m_legacy_multisig_input_proposals.size() == 0)
        return true;


    /// prepare pieces to use below

    // 1. misc. from account
    const crypto::secret_key &legacy_view_privkey{signer_account.get_common_privkey()};
    const std::uint32_t threshold{signer_account.get_threshold()};
    const rct::key legacy_spend_pubkey{rct::pk2rct(signer_account.get_multisig_pubkey())};

    // 2. validate multisig tx proposal (this may be redundant for the caller, but should be done for robustness)
    check_v1_multisig_tx_proposal_semantics_v1(multisig_tx_proposal,
        expected_version_string,
        threshold,
        signer_account.get_signers().size(),
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance);

    // 3. normal tx proposal (to get sorted inputs and the tx proposal prefix)
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    // 4. tx proposal prefix
    rct::key tx_proposal_prefix;
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, tx_proposal_prefix);

    // 5. legacy proof contexts: [ onetime address : legacy input message ]
    std::unordered_map<rct::key, rct::key> input_proof_contexts;  //[ proof key : proof message ]
    get_legacy_proof_contexts_v1(tx_proposal_prefix,
        multisig_tx_proposal.m_legacy_multisig_input_proposals,
        input_proof_contexts);

    // 6. legacy enote view privkeys and amount commitment masks (for signing)
    std::vector<crypto::secret_key> proof_privkeys_k_offset;
    std::vector<crypto::secret_key> proof_privkeys_z;

    collect_legacy_clsag_privkeys_for_multisig(tx_proposal.m_legacy_input_proposals,
        proof_privkeys_k_offset,
        proof_privkeys_z);

    // 7. signature maker for legacy CLSAG proofs
    const MultisigPartialSigMakerCLSAG partial_sig_maker{
            threshold,
            multisig_tx_proposal.m_legacy_input_proof_proposals,
            proof_privkeys_k_offset,
            proof_privkeys_z
        };


    /// finish making partial signatures
    if (!try_make_v1_multisig_partial_sig_sets_v1(signer_account,
            cryptonote::account_generator_era::cryptonote,
            multisig_tx_proposal.m_aggregate_signer_set_filter,
            input_proof_contexts,
            2,  //legacy multisig: sign on G and Hp(Ko)
            partial_sig_maker,
            std::move(local_input_init_set_collection),
            std::move(other_input_init_set_collections),
            nonce_record_inout,
            legacy_input_partial_sig_sets_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_multisig_partial_sig_sets_for_sp_inputs_v1(const multisig::multisig_account &signer_account,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const std::string &expected_version_string,
    //[ proof key : init set ]
    std::unordered_map<rct::key, MultisigProofInitSetV1> local_input_init_set_collection,
    //[ signer id : [ proof key : init set ] ]
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        other_input_init_set_collections,
    MultisigNonceRecord &nonce_record_inout,
    std::vector<MultisigPartialSigSetV1> &sp_input_partial_sig_sets_out)
{
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "multisig input partial sigs: signer account is not complete, so it can't make partial signatures.");
    CHECK_AND_ASSERT_THROW_MES(signer_account.get_era() == cryptonote::account_generator_era::seraphis,
        "multisig input partial sigs: signer account is not a seraphis account, so it can't make seraphis partial "
        "signatures.");

    // early return if there are no seraphis inputs in the multisig tx proposal
    sp_input_partial_sig_sets_out.clear();


    /// prepare pieces to use below

    // 1. misc. from account
    const crypto::secret_key &k_view_balance{signer_account.get_common_privkey()};
    const std::uint32_t threshold{signer_account.get_threshold()};

    // 2. wallet spend pubkey: k_vb X + k_m U
    rct::key jamtis_spend_pubkey{rct::pk2rct(signer_account.get_multisig_pubkey())};
    extend_seraphis_spendkey_x(k_view_balance, jamtis_spend_pubkey);

    // 3. validate multisig tx proposal (this may be redundant for the caller, but should be done for robustness)
    check_v1_multisig_tx_proposal_semantics_v1(multisig_tx_proposal,
        expected_version_string,
        threshold,
        signer_account.get_signers().size(),
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance);

    // 4. normal tx proposal (to get tx proposal prefix and sorted inputs)
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    // 5. tx proposal prefix
    rct::key tx_proposal_prefix;
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, tx_proposal_prefix);

    // 6. seraphis proof contexts: [ masked address : tx proposal prefix ]
    // note: for seraphis, all seraphis input image proofs sign the same message
    std::unordered_map<rct::key, rct::key> input_proof_contexts;  //[ proof key : proof message ]
    get_seraphis_proof_contexts_v1(tx_proposal_prefix, tx_proposal.m_sp_input_proposals, input_proof_contexts);

    // 7. seraphis enote view privkeys, address masks, and squash prefixes (for signing)
    std::vector<crypto::secret_key> proof_privkeys_x;
    std::vector<crypto::secret_key> proof_privkeys_y;
    std::vector<crypto::secret_key> proof_privkeys_z_offset;
    std::vector<crypto::secret_key> proof_privkeys_z_multiplier;

    collect_sp_composition_proof_privkeys_for_multisig(tx_proposal.m_sp_input_proposals,
        proof_privkeys_x,
        proof_privkeys_y,
        proof_privkeys_z_offset,
        proof_privkeys_z_multiplier);

    // 8. signature maker for seraphis composition proofs
    const MultisigPartialSigMakerSpCompositionProof partial_sig_maker{
            threshold,
            multisig_tx_proposal.m_sp_input_proof_proposals,
            proof_privkeys_x,
            proof_privkeys_y,
            proof_privkeys_z_offset,
            proof_privkeys_z_multiplier
        };


    /// finish making partial signatures
    if (!try_make_v1_multisig_partial_sig_sets_v1(signer_account,
            cryptonote::account_generator_era::seraphis,
            multisig_tx_proposal.m_aggregate_signer_set_filter,
            input_proof_contexts,
            1,  //sp multisig: sign on U
            partial_sig_maker,
            std::move(local_input_init_set_collection),
            std::move(other_input_init_set_collections),
            nonce_record_inout,
            sp_input_partial_sig_sets_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_inputs_for_multisig_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const std::unordered_map<crypto::public_key, std::vector<MultisigPartialSigSetV1>> &legacy_input_partial_sigs_per_signer,
    const std::unordered_map<crypto::public_key, std::vector<MultisigPartialSigSetV1>> &sp_input_partial_sigs_per_signer,
    std::vector<LegacyInputV1> &legacy_inputs_out,
    std::vector<SpPartialInputV1> &sp_partial_inputs_out)
{
    // note: we do not validate semantics of anything here, because this function is just optimistically attempting to
    //       combine partial sig sets into partial inputs if possible

    // 1. get tx proposal
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    // 2. the expected proof message is the tx's proposal prefix
    rct::key tx_proposal_prefix;
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, tx_proposal_prefix);

    // 3. try to make legacy inputs
    if (!try_make_legacy_inputs_for_multisig_v1(tx_proposal_prefix,
            tx_proposal.m_legacy_input_proposals,
            multisig_tx_proposal.m_legacy_multisig_input_proposals,
            multisig_tx_proposal.m_legacy_input_proof_proposals,
            multisig_signers,
            legacy_input_partial_sigs_per_signer,
            legacy_spend_pubkey,
            legacy_inputs_out))
        return false;

    // 4. try to make seraphis partial inputs
    rct::key sp_spend_pubkey{jamtis_spend_pubkey};
    reduce_seraphis_spendkey_x(k_view_balance, sp_spend_pubkey);

    if (!try_make_sp_partial_inputs_for_multisig_v1(tx_proposal_prefix,
            tx_proposal.m_sp_input_proposals,
            multisig_signers,
            sp_input_partial_sigs_per_signer,
            sp_spend_pubkey,
            sp_partial_inputs_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_gen_legacy_multisig_ring_signature_preps_v1(const std::list<LegacyContextualEnoteRecordV1> &contextual_records,
    const std::uint64_t legacy_ring_size,
    const MockLedgerContext &ledger_context,
    std::unordered_map<crypto::key_image, LegacyMultisigRingSignaturePrepV1> &mapped_preps_out)
{
    // extract map [ legacy KI : enote ledger index ] from contextual records
    std::unordered_map<crypto::key_image, std::uint64_t> enote_ledger_mappings;

    if (!try_get_membership_proof_real_reference_mappings(contextual_records, enote_ledger_mappings))
        return false;

    // generate legacy multisig ring signature preps for each legacy enote requested
    for (const auto &enote_ledger_mapping : enote_ledger_mappings)
    {
        LegacyMultisigRingSignaturePrepV1 &prep = mapped_preps_out[enote_ledger_mapping.first];
        prep.m_key_image = enote_ledger_mapping.first;

        gen_mock_legacy_ring_signature_members_for_enote_at_pos_v1(enote_ledger_mapping.second,
            legacy_ring_size,
            ledger_context,
            prep.m_reference_set,
            prep.m_referenced_enotes,
            prep.m_real_reference_index);
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
