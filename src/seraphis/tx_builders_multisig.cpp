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
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_config_temp.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "sp_multisig_nonce_record.h"
#include "tx_builder_types.h"
#include "tx_builder_types_multisig.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_contextual_enote_record_utils.h"
#include "tx_discretized_fee.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"
#include "tx_input_selection_output_context_v1.h"
#include "tx_misc_utils.h"
#include "tx_multisig_partial_sig_tools.h"

//third party headers
#include <boost/math/special_functions/binomial.hpp>
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <unordered_map>
#include <unordered_set>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//----------------------------------------------------------------------------------------------------------------------
// TODO: move to a 'math' library, with unit tests
//----------------------------------------------------------------------------------------------------------------------
static std::uint32_t n_choose_k(const std::uint32_t n, const std::uint32_t k)
{
    static_assert(std::numeric_limits<std::int32_t>::digits <= std::numeric_limits<double>::digits,
        "n_choose_k requires no rounding issues when converting between int32 <-> double.");

    if (n < k)
        return 0;

    double fp_result = boost::math::binomial_coefficient<double>(n, k);

    if (fp_result < 0)
        return 0;

    if (fp_result > std::numeric_limits<std::int32_t>::max())  // note: std::round() returns std::int32_t
        return 0;

    return static_cast<std::uint32_t>(std::round(fp_result));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_legacy_onetime_addresses_for_multisig_init_set(
    const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    std::vector<std::pair<rct::key, rct::keyV>> &legacy_onetime_addresses_for_multisig_init_set_out)
{
    legacy_onetime_addresses_for_multisig_init_set_out.clear();
    legacy_onetime_addresses_for_multisig_init_set_out.reserve(legacy_input_proposals.size());
    crypto::key_image key_image_base_temp;

    for (const LegacyInputProposalV1 &input_proposal : legacy_input_proposals)
    {
        crypto::generate_key_image(rct::rct2pk(input_proposal.m_onetime_address), rct::rct2sk(rct::I), key_image_base_temp);

        legacy_onetime_addresses_for_multisig_init_set_out.emplace_back(
                std::pair<rct::key, rct::keyV>{
                        input_proposal.m_onetime_address,
                        {rct::G, rct::ki2rct(key_image_base_temp)}
                    }
            );
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_masked_addresses_for_multisig_init_set(const std::vector<SpInputProposalV1> &sp_input_proposals,
    std::vector<std::pair<rct::key, rct::keyV>> &masked_addresses_for_multisig_init_set_out)
{
    masked_addresses_for_multisig_init_set_out.clear();
    masked_addresses_for_multisig_init_set_out.reserve(sp_input_proposals.size());
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &input_proposal : sp_input_proposals)
    {
        input_proposal.get_enote_image_v1(enote_image_temp);

        masked_addresses_for_multisig_init_set_out.emplace_back(
                std::pair<rct::key, rct::keyV>{
                        enote_image_temp.m_core.m_masked_address,
                        {rct::pk2rct(crypto::get_U())}
                    }
            );
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_masked_addresses(const std::vector<SpInputProposalV1> &sp_input_proposals,
    rct::keyV &masked_addresses_out)
{
    masked_addresses_out.clear();
    masked_addresses_out.reserve(sp_input_proposals.size());
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &input_proposal : sp_input_proposals)
    {
        input_proposal.get_enote_image_v1(enote_image_temp);
        masked_addresses_out.emplace_back(enote_image_temp.m_core.m_masked_address);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_v1_multisig_init_set_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &proof_message,
    const std::vector<std::pair<rct::key, rct::keyV>> &proof_infos,  //[ proof key : {multisig proof base points} ]
    const multisig::signer_set_filter aggregate_signer_set_filter,
    MultisigNonceRecord &nonce_record_inout,
    MultisigProofInitSetV1 &init_set_out)
{
    // 1. set components
    init_set_out.m_signer_id = signer_id;
    init_set_out.m_proof_message = proof_message;
    init_set_out.m_aggregate_signer_set_filter = aggregate_signer_set_filter;

    // 2. prepare init nonce map
    const std::uint32_t num_sets_with_signer_expected{
            n_choose_k(multisig::get_num_flags_set(aggregate_signer_set_filter) - 1, threshold - 1)
        };

    init_set_out.m_inits.clear();
    for (const auto &proof_info : proof_infos)
    {
        // enforce canonical proof keys
        // NOTE: this is only a sanity check
        CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(proof_info.first),
            "make multisig proof initializer: found proof key with non-canonical representation!");

        init_set_out.m_inits[proof_info.first].reserve(num_sets_with_signer_expected);
    }

    CHECK_AND_ASSERT_THROW_MES(init_set_out.m_inits.size() == proof_infos.size(),
        "make multisig proof initializer: found duplicate proof key (only unique proof keys expected/allowed).");

    // 3. add nonces for every possible signer set that includes the signer
    std::vector<multisig::signer_set_filter> filter_permutations;
    multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
        multisig_signers.size(),
        aggregate_signer_set_filter,
        filter_permutations);

    for (const multisig::signer_set_filter filter : filter_permutations)
    {
        // a. ignore filters that don't include the signer
        if (!multisig::signer_is_in_filter(init_set_out.m_signer_id, multisig_signers, filter))
            continue;

        // b. add nonces for each proof key we want to attempt to sign with this signer set
        for (const auto &proof_info : proof_infos)
        {
            // note: ignore failures to add nonces (using existing nonces is allowed)
            nonce_record_inout.try_add_nonces(proof_message, proof_info.first, filter);

            // add nonces to the inits at this filter permutation
            init_set_out.m_inits[proof_info.first].emplace_back();
            init_set_out.m_inits[proof_info.first].back().reserve(proof_info.second.size());

            // record the nonce pubkeys for each requested proof base point (should not fail)
            for (const rct::key &proof_base : proof_info.second)
            {
                init_set_out.m_inits[proof_info.first].back().emplace_back();
                CHECK_AND_ASSERT_THROW_MES(nonce_record_inout.try_get_nonce_pubkeys_for_base(proof_message,
                        proof_info.first,
                        filter,
                        proof_base,
                        init_set_out.m_inits[proof_info.first].back().back()),
                    "make multisig proof initializer: could not get nonce pubkeys from nonce record (bug).");
            }
        }
    }

    // 4. sanity check that the initializer is well-formed
    const std::size_t num_expected_nonce_sets_per_proofkey{
            proof_infos.size() > 0
            ? proof_infos[0].second.size()
            : 0
        };

    check_v1_multisig_init_set_semantics_v1(init_set_out,
        threshold,
        multisig_signers,
        num_expected_nonce_sets_per_proofkey);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool validate_v1_multisig_init_set_v1(const MultisigProofInitSetV1 &init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &expected_proof_message,
    const multisig::signer_set_filter expected_aggregate_signer_set_filter,
    const std::vector<rct::key> &expected_proof_keys,
    const std::size_t num_expected_nonce_sets_per_proofkey)
{
    // signer should be in signer list
    if (std::find(multisig_signers.begin(), multisig_signers.end(), init_set.m_signer_id) == multisig_signers.end())
        return false;

    // proof message should match the expected proof message
    if (!(init_set.m_proof_message == expected_proof_message))
        return false;

    // aggregate filter should match the expected aggregate filter
    if (init_set.m_aggregate_signer_set_filter != expected_aggregate_signer_set_filter)
        return false;

    // signer that provided the init set should be in the aggregate filter
    try
    {
        if (!multisig::signer_is_in_filter(init_set.m_signer_id,
                multisig_signers,
                expected_aggregate_signer_set_filter))
            return false;
    }
    catch (...) { return false; }

    // proof keys in init set should line up 1:1 with expected proof keys
    if (init_set.m_inits.size() != expected_proof_keys.size())
        return false;

    for (const rct::key &expected_proof_key : expected_proof_keys)
    {
        if (init_set.m_inits.find(expected_proof_key) == init_set.m_inits.end())
            return false;
    }

    // init set semantics must be valid
    try
    {
        check_v1_multisig_init_set_semantics_v1(init_set,
            threshold,
            multisig_signers,
            num_expected_nonce_sets_per_proofkey);
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void validate_and_prepare_multisig_inits_v1(const multisig::signer_set_filter aggregate_signer_set_filter,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const crypto::public_key &local_signer_id,
    const rct::keyV &proof_keys,
    const std::size_t num_expected_nonce_sets_per_proofkey,
    const rct::key &proof_message,
    MultisigProofInitSetV1 local_init_set,
    std::vector<MultisigProofInitSetV1> other_init_sets,
    std::vector<MultisigProofInitSetV1> &all_init_sets_out)
{
    /// validate and filter inits

    // 1. local init set must always be valid
    CHECK_AND_ASSERT_THROW_MES(local_init_set.m_signer_id == local_signer_id,
        "validate and prepare multisig inits: local init set is not from local signer.");
    CHECK_AND_ASSERT_THROW_MES(validate_v1_multisig_init_set_v1(local_init_set,
            threshold,
            multisig_signers,
            proof_message,
            aggregate_signer_set_filter,
            proof_keys,
            num_expected_nonce_sets_per_proofkey),
        "validate and prepare multisig inits: the local signer's initializer is invalid.");

    // 2. weed out invalid other init sets
    auto removed_end = std::remove_if(other_init_sets.begin(), other_init_sets.end(),
            [&](const MultisigProofInitSetV1 &other_init_set) -> bool
            {
                return !validate_v1_multisig_init_set_v1(other_init_set,
                    threshold,
                    multisig_signers,
                    proof_message,
                    aggregate_signer_set_filter,
                    proof_keys,
                    num_expected_nonce_sets_per_proofkey);
            }
        );
    other_init_sets.erase(removed_end, other_init_sets.end());

    // 3. collect all init sets
    all_init_sets_out = std::move(other_init_sets);
    all_init_sets_out.emplace_back(std::move(local_init_set));

    // 4. sort inits and remove inits from duplicate signers (including duplicate local signer inits)
    std::sort(all_init_sets_out.begin(), all_init_sets_out.end(),
            [](const MultisigProofInitSetV1 &set1, const MultisigProofInitSetV1 &set2) -> bool
            {
                return set1.m_signer_id < set2.m_signer_id;
            }
        );
    auto unique_end = std::unique(all_init_sets_out.begin(), all_init_sets_out.end(),
            [](const MultisigProofInitSetV1 &set1, const MultisigProofInitSetV1 &set2) -> bool
            {
                return set1.m_signer_id == set2.m_signer_id;
            }
        );
    all_init_sets_out.erase(unique_end, all_init_sets_out.end());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void attempt_make_v1_multisig_partial_sig_set_v1(const crypto::public_key &local_signer_id,
    const std::uint32_t threshold,
    const rct::key &proof_message,
    const multisig::signer_set_filter filter,
    const rct::keyV &proof_keys,
    const std::vector<MultisigProofInitSetV1> &all_init_sets,
    const std::vector<multisig::signer_set_filter> &available_signers_as_filters,
    const std::vector<std::size_t> &signer_nonce_trackers,
    const MultisigPartialSigMaker &partial_sig_maker,
    const crypto::secret_key &local_signer_privkey,
    MultisigNonceRecord &nonce_record_inout,
    MultisigPartialSigSetV1 &new_partial_sig_set_out)
{
    /// make partial signatures for one group of signers of size threshold that is presumed to include the local signer

    // 1. checks
    CHECK_AND_ASSERT_THROW_MES(all_init_sets.size() >= threshold,
        "make multisig partial sig set: there are fewer init sets than the signing threshold of the multisig group.");
    CHECK_AND_ASSERT_THROW_MES(available_signers_as_filters.size() == all_init_sets.size(),
        "make multisig partial sig set: available signers as filters don't line up with init sets (bug).");
    CHECK_AND_ASSERT_THROW_MES(signer_nonce_trackers.size() == all_init_sets.size(),
        "make multisig partial sig set: signer nonce trackers don't line up with init sets (bug).");

    // 2. try to make the partial sig set (if unable to make a partial signature on all proof proposals in the set, then
    //    an exception will be thrown)
    std::vector<MultisigPubNonces> signer_pub_nonces_temp;
    signer_pub_nonces_temp.reserve(threshold);

    std::vector<MultisigPubNonces> signer_pub_nonces_set_temp;
    new_partial_sig_set_out.m_partial_signatures.reserve(proof_keys.size());

    for (std::size_t proof_proposal_index{0}; proof_proposal_index < proof_keys.size(); ++proof_proposal_index)
    {
        // a. collect nonces from all signers in this signing group
        signer_pub_nonces_temp.clear();
        for (std::size_t signer_index{0}; signer_index < all_init_sets.size(); ++signer_index)
        {
            // ignore signers not in the requested signing group
            if ((available_signers_as_filters[signer_index] & filter) == 0)
                continue;

            // indexing:
            // - this signer's init set
            // - select the proof we are working on (via this proof's proof key)
            // - select the nonces that line up with the signer's nonce tracker
            if (!all_init_sets[signer_index].try_get_nonces(proof_keys[proof_proposal_index],
                    signer_nonce_trackers[signer_index],
                    signer_pub_nonces_set_temp))
                throw;

            // for seraphis proofs there should only be one nonce pubkey pair per nonce pubkey set
            //todo: make generic (unconstrained number of pub nonce pairs per set)
            if (signer_pub_nonces_set_temp.size() != 1)
                throw;

            signer_pub_nonces_temp.emplace_back(signer_pub_nonces_set_temp[0]);
        }

        // b. sanity check
        if (signer_pub_nonces_temp.size() != threshold)
            throw;

        // c. make a partial signature
        new_partial_sig_set_out.m_partial_signatures.emplace_back();

        partial_sig_maker.attempt_make_partial_sig(proof_proposal_index,
            filter,
            signer_pub_nonces_temp,
            local_signer_privkey,
            nonce_record_inout,
            new_partial_sig_set_out.m_partial_signatures.back());
    }

    // 3. copy miscellanea
    new_partial_sig_set_out.m_signer_id = local_signer_id;
    new_partial_sig_set_out.m_proof_message = proof_message;
    new_partial_sig_set_out.m_signer_set_filter = filter;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_v1_multisig_partial_sig_sets_v1(const multisig::multisig_account &signer_account,
    const rct::key &proof_message,
    const rct::keyV &proof_keys,
    const std::vector<multisig::signer_set_filter> &filter_permutations,
    const multisig::signer_set_filter local_signer_filter,
    const std::vector<MultisigProofInitSetV1> &all_init_sets,
    const multisig::signer_set_filter available_signers_filter,
    const std::vector<multisig::signer_set_filter> &available_signers_as_filters,
    const MultisigPartialSigMaker &partial_sig_maker,
    MultisigNonceRecord &nonce_record_inout,
    std::vector<MultisigPartialSigSetV1> &partial_sig_sets_out)
{
    /// make partial signatures for every available group of signers of size threshold that includes the local signer
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "make multisig input partial sigs: signer account is not complete, so it can't make partial signatures.");

    const std::size_t num_available_signers{available_signers_as_filters.size()};

    // signer nonce trackers are pointers into the nonce vectors in each signer's init set
    // - a signer's nonce vectors line up 1:1 with the filters in 'filter_permutations' of which the signer is a member
    // - we want to track through each signers' vectors as we go through the full set of 'filter_permutations'
    std::vector<std::size_t> signer_nonce_trackers(num_available_signers, 0);

    const std::uint32_t expected_num_partial_sig_sets{
            n_choose_k(num_available_signers - 1, signer_account.get_threshold() - 1)
        };
    partial_sig_sets_out.clear();
    partial_sig_sets_out.reserve(expected_num_partial_sig_sets);

    std::uint32_t num_aborted_partial_sig_sets{0};
    crypto::secret_key k_b_e_temp;

    for (const multisig::signer_set_filter filter : filter_permutations)
    {
        // for filters that contain only available signers (and include the local signer), make a partial signature set
        // - throw on failure so the partial sig set can be rolled back
        if ((filter & available_signers_filter) == filter &&
            (filter & local_signer_filter))
        {
            // if this throws, then the signer's nonces for this filter/proposal/init_set combo that were used before
            //   the throw will be completely lost (i.e. in the 'nonce_record_inout'); however, if it does throw then
            //   this signing attempt was futile to begin with (it's all or nothing)
            partial_sig_sets_out.emplace_back();
            try
            {
                // 1. get local signer's signing key for this group
                if (!signer_account.try_get_aggregate_signing_key(filter, k_b_e_temp))
                    throw;

                // 2. attempt to make the partial sig set
                attempt_make_v1_multisig_partial_sig_set_v1(signer_account.get_base_pubkey(),
                    signer_account.get_threshold(),
                    proof_message,
                    filter,
                    proof_keys,
                    all_init_sets,
                    available_signers_as_filters,
                    signer_nonce_trackers,
                    partial_sig_maker,
                    k_b_e_temp,
                    nonce_record_inout,
                    partial_sig_sets_out.back());

                // 3. sanity check
                check_v1_multisig_partial_sig_semantics_v1(partial_sig_sets_out.back(), signer_account.get_signers());
            }
            catch (...)
            {
                partial_sig_sets_out.pop_back();
                ++num_aborted_partial_sig_sets;
            }
        }

        // increment nonce trackers for all signers in this filter
        for (std::size_t signer_index{0}; signer_index < num_available_signers; ++signer_index)
        {
            if (available_signers_as_filters[signer_index] & filter)
                ++signer_nonce_trackers[signer_index];
        }
    }

    // sanity check
    CHECK_AND_ASSERT_THROW_MES(expected_num_partial_sig_sets - num_aborted_partial_sig_sets ==
            partial_sig_sets_out.size(),
        "make multisig partial sig sets: did not produce expected number of partial sig sets (bug).");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename PartialSigT>
static void filter_multisig_partial_signatures_for_combination_v1(const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &expected_proof_message,
    const std::unordered_set<rct::key> &expected_proof_keys,
    const std::unordered_map<crypto::public_key, std::vector<MultisigPartialSigSetV1>> &partial_sigs_per_signer,
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //proof key
            std::vector<PartialSigT>>> &collected_sigs_per_key_per_filter_out)
{
    // try to consume the partial signatures passed in by filtering them into the 'collected sigs' output map
    std::unordered_map<multisig::signer_set_filter, std::unordered_set<crypto::public_key>> collected_signers_per_filter;

    for (const auto &partial_sigs_for_signer : partial_sigs_per_signer)
    {
        for (const MultisigPartialSigSetV1 &partial_sig_set : partial_sigs_for_signer.second)
        {
            // a. skip sig sets with unexpected proof messages
            if (!(partial_sig_set.m_proof_message == expected_proof_message))
                continue;

            // b. skip sig sets that are invalid
            try { check_v1_multisig_partial_sig_semantics_v1(partial_sig_set, multisig_signers); }
            catch (...) { continue; }

            // c. skip sig sets if their signer ids don't match the input signer ids
            if (!(partial_sig_set.m_signer_id == partial_sigs_for_signer.first))
                continue;

            // d. skip sig sets that look like duplicates (same signer group and signer)
            // - do this after checking sig set validity to avoid inserting invalid filters into the collected signers map
            if (collected_signers_per_filter[partial_sig_set.m_signer_set_filter].find(partial_sig_set.m_signer_id) !=
                    collected_signers_per_filter[partial_sig_set.m_signer_set_filter].end())
                continue;

            // e. record that this signer/filter combo has been used
            collected_signers_per_filter[partial_sig_set.m_signer_set_filter]
                .insert(partial_sig_set.m_signer_id);

            // f. record the partial sigs
            for (const MultisigPartialSigVariant &partial_sig : partial_sig_set.m_partial_signatures)
            {
                // skip partial sigs with unknown proof keys
                if (expected_proof_keys.find(partial_sig.proof_key()) == expected_proof_keys.end())
                    continue;

                // skip partial sigs with unexpected partial sig types
                if (!partial_sig.is_type<PartialSigT>())
                    continue;

                collected_sigs_per_key_per_filter_out[partial_sig_set.m_signer_set_filter][partial_sig.proof_key()]
                    .emplace_back(partial_sig.get_partial_sig<PartialSigT>());
            }
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_make_v1_sp_partial_input_v1(const SpInputProposal &input_proposal,
    const rct::key &expected_proposal_prefix,
    const std::vector<SpCompositionProofMultisigPartial> &input_proof_partial_sigs,
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
        partial_input_out.m_image_proof.m_composition_proof = sp_composition_prove_multisig_final(input_proof_partial_sigs);

        // copy miscellaneous pieces
        input_proposal.get_enote_image_core(partial_input_out.m_input_image.m_core);
        partial_input_out.m_address_mask = input_proposal.m_address_mask;
        partial_input_out.m_commitment_mask = input_proposal.m_commitment_mask;
        partial_input_out.m_proposal_prefix = expected_proposal_prefix;
        input_proposal.get_enote_core(partial_input_out.m_input_enote_core);
        partial_input_out.m_input_amount = input_proposal.m_amount;
        partial_input_out.m_input_amount_blinding_factor = input_proposal.m_amount_blinding_factor;
    }
    catch (...)
    {
        return false;
    }

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
    LegacyMultisigInputProposalV1 &proposal_out)
{
    // add components
    proposal_out.m_enote = enote;
    proposal_out.m_key_image = key_image;
    proposal_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    proposal_out.m_tx_output_index = tx_output_index;
    proposal_out.m_unlock_time = unlock_time;
    proposal_out.m_commitment_mask = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_multisig_input_proposal_v1(const LegacyEnoteRecord &enote_record,
    const crypto::secret_key &commitment_mask,
    LegacyMultisigInputProposalV1 &proposal_out)
{
    make_v1_legacy_multisig_input_proposal_v1(enote_record.m_enote,
        enote_record.m_key_image,
        enote_record.m_enote_ephemeral_pubkey,
        enote_record.m_tx_output_index,
        enote_record.m_unlock_time,
        commitment_mask,
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

    // 1. check the public input proposal semantics
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
    rct::key proposal_prefix;
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, proposal_prefix);


    /// multisig-related input checks

    // 1. input proposals line up 1:1 with multisig input proof proposals
    /* todo:
    CHECK_AND_ASSERT_THROW_MES(tx_proposal.m_legacy_input_proposals.size() ==
            multisig_tx_proposal.m_legacy_input_proof_proposals.size(),
        "multisig tx proposal: legacy input proposals don't line up with input proposal proofs.");
    */

    CHECK_AND_ASSERT_THROW_MES(tx_proposal.m_sp_input_proposals.size() ==
            multisig_tx_proposal.m_sp_input_proof_proposals.size(),
        "multisig tx proposal: sp input proposals don't line up with input proposal proofs.");

    // 2. assess each legacy input proof proposal
    /*
    LegacyEnoteImageV2 legacy_enote_image_temp;

    for (std::size_t input_index{0};
        input_index < multisig_tx_proposal.m_legacy_input_proof_proposals.size();
        ++input_index)
    {
        // a. input proof proposal messages all equal proposal prefix of core tx proposal
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_legacy_input_proof_proposals[input_index].message ==
                proposal_prefix,
            "multisig tx proposal: legacy input proof proposal does not match the tx proposal (different proposal prefix).");

        //todo: legacy ring signature proposals
        // b. input proof proposal keys line up 1:1 and match with input proposals
        tx_proposal.m_legacy_input_proposals[input_index].get_enote_image_v2(legacy_enote_image_temp);

        //CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_legacy_input_proof_proposals[input_index].K ==
        //        legacy_enote_image_temp.m_core.m_masked_address,
        //    "multisig tx proposal: legacy input proof proposal does not match input proposal (different proof keys).");

        //todo: legacy ring signature proposals
        // c. input proof proposal key images line up 1:1 and match with input proposals
        //CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_legacy_input_proof_proposals[input_index].KI ==
        //        legacy_enote_image_temp.m_core.m_key_image,
        //    "multisig tx proposal: legacy input proof proposal does not match input proposal (different key images).");
    }
    */

    // 3. assess each seraphis input proof proposal
    SpEnoteImageV1 sp_enote_image_temp;

    for (std::size_t input_index{0}; input_index < multisig_tx_proposal.m_sp_input_proof_proposals.size(); ++input_index)
    {
        // a. input proof proposal messages all equal proposal prefix of core tx proposal
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_sp_input_proof_proposals[input_index].message == proposal_prefix,
            "multisig tx proposal: sp input proof proposal does not match the tx proposal (different proposal prefix).");

        // b. input proof proposal keys line up 1:1 and match with input proposals
        tx_proposal.m_sp_input_proposals[input_index].get_enote_image_v1(sp_enote_image_temp);

        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_sp_input_proof_proposals[input_index].K ==
                sp_enote_image_temp.m_core.m_masked_address,
            "multisig tx proposal: sp input proof proposal does not match input proposal (different proof keys).");

        // c. input proof proposal key images line up 1:1 and match with input proposals
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_sp_input_proof_proposals[input_index].KI ==
                sp_enote_image_temp.m_core.m_key_image,
            "multisig tx proposal: sp input proof proposal does not match input proposal (different key images).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_tx_proposal_v1(std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    const DiscretizedFee &tx_fee,
    std::string version_string,
    std::vector<SpMultisigInputProposalV1> sp_multisig_input_proposals,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigTxProposalV1 &proposal_out)
{
    // 1. convert multisig seraphis public input proposals to plain input proposals
    //todo: legacy
    std::vector<SpInputProposalV1> sp_input_proposals;

    for (const SpMultisigInputProposalV1 &sp_multisig_input_proposal : sp_multisig_input_proposals)
    {
        sp_input_proposals.emplace_back();
        sp_multisig_input_proposal.get_input_proposal_v1(jamtis_spend_pubkey, k_view_balance, sp_input_proposals.back());
    }

    // 2. make a temporary normal tx proposal
    SpTxProposalV1 tx_proposal;
    make_v1_tx_proposal_v1(normal_payment_proposals,
        selfsend_payment_proposals,
        tx_fee,
        {},  //todo: legacy
        std::move(sp_input_proposals),
        additional_memo_elements,
        tx_proposal);

    // 3. get proposal prefix
    rct::key proposal_prefix;
    tx_proposal.get_proposal_prefix(version_string, k_view_balance, proposal_prefix);

    //todo: legacy proof proposals

    // 4. prepare composition proof proposals for each seraphis input (note: using the tx proposal ensures proof
    //    proposals are sorted)
    proposal_out.m_sp_input_proof_proposals.clear();
    proposal_out.m_sp_input_proof_proposals.reserve(sp_multisig_input_proposals.size());
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &sp_input_proposal : tx_proposal.m_sp_input_proposals)
    {
        sp_input_proposal.get_enote_image_v1(enote_image_temp);

        proposal_out.m_sp_input_proof_proposals.emplace_back(
                sp_composition_multisig_proposal(proposal_prefix,
                    enote_image_temp.m_core.m_masked_address,
                    enote_image_temp.m_core.m_key_image)
            );
    }

    // 5. add miscellaneous components
    //proposal_out.m_legacy_multisig_input_proposals = std::move(legacy_multisig_input_proposals);
    proposal_out.m_sp_multisig_input_proposals = std::move(sp_multisig_input_proposals);
    proposal_out.m_normal_payment_proposals = std::move(normal_payment_proposals);
    proposal_out.m_selfsend_payment_proposals = std::move(selfsend_payment_proposals);
    make_tx_extra(std::move(additional_memo_elements), proposal_out.m_partial_memo);
    proposal_out.m_tx_fee = tx_fee;
    proposal_out.m_aggregate_signer_set_filter = aggregate_signer_set_filter;
    proposal_out.m_version_string = std::move(version_string);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_multisig_tx_proposal_for_transfer_v1(const jamtis::JamtisDestinationV1 &change_address,
    const jamtis::JamtisDestinationV1 &dummy_address,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const sp::SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    const multisig::signer_set_filter aggregate_filter_of_requested_multisig_signers,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    TxExtra partial_memo_for_tx,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigTxProposalV1 &multisig_tx_proposal_out,
    std::unordered_map<crypto::key_image, std::uint64_t> &sp_input_ledger_mappings_out)
{
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
    CHECK_AND_ASSERT_THROW_MES(legacy_contextual_inputs.size() == 0, "for now, legacy inputs aren't fully supported.");

    // a. convert legacy inputs to legacy multisig input proposals (inputs to spend) (TODO)

    // b. convert seraphis inputs to seraphis multisig input proposals (inputs to spend)
    sp_input_ledger_mappings_out.clear();

    std::vector<SpMultisigInputProposalV1> sp_multisig_input_proposals;
    sp_multisig_input_proposals.reserve(sp_contextual_inputs.size());

    for (const SpContextualEnoteRecordV1 &contextual_input : sp_contextual_inputs)
    {
        // save input indices for making membership proofs
        sp_input_ledger_mappings_out[contextual_input.m_record.m_key_image] = 
            contextual_input.m_origin_context.m_enote_ledger_index;

        // convert inputs to input proposals
        sp_multisig_input_proposals.emplace_back();
        make_v1_sp_multisig_input_proposal_v1(contextual_input.m_record,
            rct::rct2sk(rct::skGen()),
            rct::rct2sk(rct::skGen()),
            sp_multisig_input_proposals.back());
    }

    // 4. get total input amount
    boost::multiprecision::uint128_t total_input_amount{0};
    SpInputProposalV1 input_proposal_temp;

    for (const SpMultisigInputProposalV1 &sp_multisig_input_proposal : sp_multisig_input_proposals)
    {
        sp_multisig_input_proposal.get_input_proposal_v1(jamtis_spend_pubkey, k_view_balance, input_proposal_temp);
        total_input_amount += input_proposal_temp.get_amount();
    }

    // 5. finalize output set
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

    CHECK_AND_ASSERT_THROW_MES(tx_fee_calculator.get_fee(fee_per_tx_weight,
                legacy_contextual_inputs.size(), sp_contextual_inputs.size(),
                normal_payment_proposals.size() + selfsend_payment_proposals.size()) ==
            reported_final_fee,
        "make tx proposal for transfer (v1): final fee is not consistent with input selector fee (bug).");

    // 6. get memo elements
    std::vector<ExtraFieldElement> extra_field_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(partial_memo_for_tx, extra_field_elements),
        "make tx proposal for transfer (v1): unable to extract memo field elements for tx proposal.");

    // 7. assemble into tx proposal
    std::string version_string;
    make_versioning_string(semantic_rules_version, version_string);

    make_v1_multisig_tx_proposal_v1(std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        std::move(extra_field_elements),
        reported_final_fee,
        version_string,
        std::move(sp_multisig_input_proposals),
        aggregate_filter_of_requested_multisig_signers,
        jamtis_spend_pubkey,
        k_view_balance,
        multisig_tx_proposal_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_init_set_semantics_v1(const MultisigProofInitSetV1 &init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::size_t num_expected_nonce_sets_per_proofkey)
{
    // signer set filter must be valid (at least 'threshold' signers allowed, format is valid)
    CHECK_AND_ASSERT_THROW_MES(multisig::validate_aggregate_multisig_signer_set_filter(threshold,
            multisig_signers.size(),
            init_set.m_aggregate_signer_set_filter),
        "multisig init set semantics: invalid aggregate signer set filter.");

    // the init's signer must be in allowed signers list, and contained in the aggregate filter
    CHECK_AND_ASSERT_THROW_MES(std::find(multisig_signers.begin(), multisig_signers.end(), init_set.m_signer_id) !=
        multisig_signers.end(), "multisig init set semantics: initializer from unknown signer.");
    CHECK_AND_ASSERT_THROW_MES(multisig::signer_is_in_filter(init_set.m_signer_id,
            multisig_signers,
            init_set.m_aggregate_signer_set_filter),
        "multisig init set semantics: signer is not eligible.");

    // for each proof key to sign, there should be one nonce set (signing attempt) per signer subgroup that contains the
    //     signer
    // - there are 'num signers requested' choose 'threshold' total signer subgroups who can participate in signing this
    //   proof
    // - remove our init's signer, then choose 'threshold - 1' signers from the remaining 'num signers requested - 1' to
    //   get the number of permutations that include our init's signer
    const std::uint32_t num_sets_with_signer_expected(
            n_choose_k(multisig::get_num_flags_set(init_set.m_aggregate_signer_set_filter) - 1, threshold - 1)
        );

    for (const auto &init : init_set.m_inits)
    {
        CHECK_AND_ASSERT_THROW_MES(init.second.size() == num_sets_with_signer_expected,
            "multisig init set semantics: don't have expected number of nonce sets (one per signer set with signer).");

        for (const auto &nonce_pubkey_set : init.second)
        {
            CHECK_AND_ASSERT_THROW_MES(nonce_pubkey_set.size() == num_expected_nonce_sets_per_proofkey,
                "multisig init set semantics: don't have expected number of nonce pubkey pairs (each proof key should have "
                "(" << num_expected_nonce_sets_per_proofkey << ") nonce pubkey pairs).");
        }
    }
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
    MultisigProofInitSetV1 &legacy_input_init_set_out,
    MultisigProofInitSetV1 &sp_input_init_set_out)
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

    // 2. make proposal prefix
    SpTxProposalV1 tx_proposal;
    rct::key proposal_prefix;
    multisig_tx_proposal.get_v1_tx_proposal_v1(legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, proposal_prefix);

    // 3. prepare proof keys (mapped to multisig proof base point sets)
    // a. [ legacy Ko : {G, Hp(legacy Ko)} ]
    std::vector<std::pair<rct::key, rct::keyV>> legacy_onetime_addresses_for_multisig_init_set;
    get_legacy_onetime_addresses_for_multisig_init_set(tx_proposal.m_legacy_input_proposals,
        legacy_onetime_addresses_for_multisig_init_set);

    // b. [ seraphis K" : {U} ]
    std::vector<std::pair<rct::key, rct::keyV>> masked_addresses_for_multisig_init_set;
    get_masked_addresses_for_multisig_init_set(tx_proposal.m_sp_input_proposals, masked_addresses_for_multisig_init_set);

    // 4. finish making multisig input init sets
    // a. legacy input init set
    make_v1_multisig_init_set_v1(signer_id,
        threshold,
        multisig_signers,
        proposal_prefix,
        legacy_onetime_addresses_for_multisig_init_set,
        multisig_tx_proposal.m_aggregate_signer_set_filter,
        nonce_record_inout,
        legacy_input_init_set_out);

    // b. seraphis input init set
    make_v1_multisig_init_set_v1(signer_id,
        threshold,
        multisig_signers,
        proposal_prefix,
        masked_addresses_for_multisig_init_set,
        multisig_tx_proposal.m_aggregate_signer_set_filter,
        nonce_record_inout,
        sp_input_init_set_out);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_partial_sig_semantics_v1(const MultisigPartialSigSetV1 &partial_sig_set,
    const std::vector<crypto::public_key> &multisig_signers)
{
    // signer is in filter
    CHECK_AND_ASSERT_THROW_MES(multisig::signer_is_in_filter(partial_sig_set.m_signer_id,
            multisig_signers,
            partial_sig_set.m_signer_set_filter),
        "multisig partial sig set semantics: the signer is not a member of the signer group (or the filter is invalid).");

    // all proofs sign the same message
    for (const MultisigPartialSigVariant &partial_sig : partial_sig_set.m_partial_signatures)
    {
        CHECK_AND_ASSERT_THROW_MES(partial_sig.message() == partial_sig_set.m_proof_message,
            "multisig partial sig set semantics: a partial signature's message does not match the set's proposal prefix.");
    }

    // all partial sigs must have the same underlying type
    CHECK_AND_ASSERT_THROW_MES(std::adjacent_find(partial_sig_set.m_partial_signatures.begin(),
            partial_sig_set.m_partial_signatures.end(),
            [](const MultisigPartialSigVariant &v1, const MultisigPartialSigVariant &v2) -> bool
            {
                return !MultisigPartialSigVariant::same_type(v1, v2);  //find an adjacent pair that DONT have the same type
            }) == partial_sig_set.m_partial_signatures.end(),
        "multisig partial sig set semantics: partial signatures are not all the same type.");
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_multisig_partial_sig_sets_for_sp_inputs_v1(const multisig::multisig_account &signer_account,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const std::string &expected_version_string,
    MultisigProofInitSetV1 local_input_init_set,
    std::vector<MultisigProofInitSetV1> other_input_init_sets,
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

    if (multisig_tx_proposal.m_sp_multisig_input_proposals.size() == 0)
        return true;


    /// prepare pieces to use below

    // 1. misc. from account
    const crypto::secret_key &k_view_balance{signer_account.get_common_privkey()};
    const std::uint32_t threshold{signer_account.get_threshold()};
    const std::vector<crypto::public_key> &multisig_signers{signer_account.get_signers()};
    const crypto::public_key &local_signer_id{signer_account.get_base_pubkey()};

    // 2. wallet spend pubkey: k_vb X + k_m U
    rct::key jamtis_spend_pubkey{rct::pk2rct(signer_account.get_multisig_pubkey())};
    extend_seraphis_spendkey_x(k_view_balance, jamtis_spend_pubkey);

    // 3. validate multisig tx proposal
    // note: this check is effectively redundant because it is called when making the local input init set,
    //       so validating the local input init set (which was successfully created) with the tx proposal's proposal
    //       prefix should imply the multisig tx proposal here is valid; but, redundancy is good
    check_v1_multisig_tx_proposal_semantics_v1(multisig_tx_proposal,
        expected_version_string,
        threshold,
        multisig_signers.size(),
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance);

    // 4. misc. from multisig tx proposal
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    // a. tx proposal prefix
    rct::key tx_proposal_prefix;
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, tx_proposal_prefix);

    // b. seraphis masked addresses
    rct::keyV input_masked_addresses;
    get_masked_addresses(tx_proposal.m_sp_input_proposals, input_masked_addresses);

    // c. seraphis enote view privkeys, address masks, and squash prefixes (for signing)
    std::vector<crypto::secret_key> enote_view_privkeys_g;
    std::vector<crypto::secret_key> enote_view_privkeys_x;
    std::vector<crypto::secret_key> enote_view_privkeys_u;
    std::vector<crypto::secret_key> address_masks;
    rct::keyV squash_prefixes;
    enote_view_privkeys_g.reserve(tx_proposal.m_sp_input_proposals.size());
    enote_view_privkeys_x.reserve(tx_proposal.m_sp_input_proposals.size());
    enote_view_privkeys_u.reserve(tx_proposal.m_sp_input_proposals.size());
    address_masks.reserve(tx_proposal.m_sp_input_proposals.size());
    squash_prefixes.reserve(tx_proposal.m_sp_input_proposals.size());

    for (const SpInputProposalV1 &sp_input_proposal : tx_proposal.m_sp_input_proposals)
    {
        enote_view_privkeys_g.emplace_back(sp_input_proposal.m_core.m_enote_view_privkey_g);
        enote_view_privkeys_x.emplace_back(sp_input_proposal.m_core.m_enote_view_privkey_x);
        enote_view_privkeys_u.emplace_back(sp_input_proposal.m_core.m_enote_view_privkey_u);
        address_masks.emplace_back(sp_input_proposal.m_core.m_address_mask);
        squash_prefixes.emplace_back();
        sp_input_proposal.get_squash_prefix(squash_prefixes.back());
    }

    // 5. filter permutations
    std::vector<multisig::signer_set_filter> filter_permutations;
    multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
        multisig_signers.size(),
        multisig_tx_proposal.m_aggregate_signer_set_filter,
        filter_permutations);


    /// validate and assemble input inits
    std::vector<MultisigProofInitSetV1> all_input_init_sets;

    validate_and_prepare_multisig_inits_v1(multisig_tx_proposal.m_aggregate_signer_set_filter,
        threshold,
        multisig_signers,
        local_signer_id,
        input_masked_addresses,
        1, //sp multisig: only sign on U
        tx_proposal_prefix,
        std::move(local_input_init_set),
        std::move(other_input_init_sets),
        all_input_init_sets);


    /// prepare for signing (todo: move this part to separate function for use in legacy version of this function)

    // 1. save local signer as filter
    multisig::signer_set_filter local_signer_filter;
    multisig::multisig_signer_to_filter(local_signer_id, multisig_signers, local_signer_filter);

    // 2. collect available signers
    std::vector<crypto::public_key> available_signers;
    available_signers.reserve(all_input_init_sets.size());

    for (const MultisigProofInitSetV1 &input_init_set : all_input_init_sets)
        available_signers.emplace_back(input_init_set.m_signer_id);

    // give up if not enough signers
    if (available_signers.size() < threshold)
        return false;

    // 3. available signers as a filter
    multisig::signer_set_filter available_signers_filter;
    multisig::multisig_signers_to_filter(available_signers, multisig_signers, available_signers_filter);

    // 4. available signers as individual filters
    std::vector<multisig::signer_set_filter> available_signers_as_filters;
    available_signers_as_filters.reserve(available_signers.size());

    for (const crypto::public_key &available_signer : available_signers)
    {
        available_signers_as_filters.emplace_back();
        multisig::multisig_signer_to_filter(available_signer, multisig_signers, available_signers_as_filters.back());
    }


    /// make partial signatures

    // 1. prepare signature maker for seraphis composition proofs
    const MultisigPartialSigMakerSpCompositionProof &partial_sig_maker{
            signer_account.get_threshold(),
            multisig_tx_proposal.m_sp_input_proof_proposals,
            squash_prefixes,
            enote_view_privkeys_g,
            enote_view_privkeys_x,
            enote_view_privkeys_u,
            address_masks
        };

    // 2. make the partial signature sets
    make_v1_multisig_partial_sig_sets_v1(signer_account,
        tx_proposal_prefix,
        input_masked_addresses,
        filter_permutations,
        local_signer_filter,
        all_input_init_sets,
        available_signers_filter,
        available_signers_as_filters,
        partial_sig_maker,
        nonce_record_inout,
        sp_input_partial_sig_sets_out);

    if (sp_input_partial_sig_sets_out.size() == 0)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_partial_inputs_for_multisig_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
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
    // note: do not validate semantics of multisig tx proposal or partial sig sets here, because this function is
    //       just attempting to combine partial sig sets into partial inputs

    // 1. get normal tx proposal
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    // 2. collect onetime addresses of legacy inputs and map legacy input proposals to their onetime addresses
    std::unordered_set<rct::key> expected_legacy_onetime_addresses;
    std::unordered_map<rct::key, LegacyInputProposalV1> mapped_legacy_input_proposals;

    for (const LegacyInputProposalV1 &legacy_input_proposal : tx_proposal.m_legacy_input_proposals)
    {
        expected_legacy_onetime_addresses.insert(legacy_input_proposal.m_onetime_address);
        mapped_legacy_input_proposals[legacy_input_proposal.m_onetime_address] = legacy_input_proposal;
    }

    // 3. collect seraphis masked addresses of input images and map seraphis input proposals to their masked addresses
    std::unordered_set<rct::key> expected_sp_masked_addresses;
    std::unordered_map<rct::key, SpInputProposalV1> mapped_sp_input_proposals;
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &sp_input_proposal : tx_proposal.m_sp_input_proposals)
    {
        sp_input_proposal.get_enote_image_v1(enote_image_temp);
        expected_sp_masked_addresses.insert(enote_image_temp.m_core.m_masked_address);
        mapped_sp_input_proposals[enote_image_temp.m_core.m_masked_address] = sp_input_proposal;
    }

    // 4. the expected proof message is the tx's proposal prefix
    rct::key tx_proposal_prefix;
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, tx_proposal_prefix);

    // 5. todo: filter the legacy partial signatures into a map
    /*
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //proof key (onetime address)
            std::vector<CLSAGMultisigPartial>>> collected_legacy_sigs_per_key_per_filter;

    filter_multisig_partial_signatures_for_combination_v1(multisig_signers,
        tx_proposal_prefix,
        expected_legacy_onetime_addresses,
        legacy_input_partial_sigs_per_signer,
        collected_legacy_sigs_per_key_per_filter);
    */

    // 6. filter the seraphis partial signatures into a map
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //proof key (masked address)
            std::vector<SpCompositionProofMultisigPartial>>> collected_sp_sigs_per_key_per_filter;

    filter_multisig_partial_signatures_for_combination_v1<SpCompositionProofMultisigPartial>(multisig_signers,
        tx_proposal_prefix,
        expected_sp_masked_addresses,
        sp_input_partial_sigs_per_signer,
        collected_sp_sigs_per_key_per_filter);

    // 7. todo: try to make one legacy input per onetime address
    legacy_inputs_out.clear();
    legacy_inputs_out.reserve(expected_legacy_onetime_addresses.size());

    // 8. try to make one seraphis partial input per masked address
    sp_partial_inputs_out.clear();
    sp_partial_inputs_out.reserve(expected_sp_masked_addresses.size());
    std::unordered_set<rct::key> masked_addresses_with_partial_inputs;

    for (const auto &signer_group_partial_sigs : collected_sp_sigs_per_key_per_filter)
    {
        for (const auto &masked_address_partial_sigs : signer_group_partial_sigs.second)
        {
            // a. skip partial sig sets for masked addresses that already have a completed proof (from a different
            //   signer group)
            if (masked_addresses_with_partial_inputs.find(masked_address_partial_sigs.first) != 
                    masked_addresses_with_partial_inputs.end())
                continue;

            // b. try to make the partial input
            sp_partial_inputs_out.emplace_back();

            if (try_make_v1_sp_partial_input_v1(mapped_sp_input_proposals[masked_address_partial_sigs.first].m_core,
                    tx_proposal_prefix,
                    masked_address_partial_sigs.second,
                    sp_partial_inputs_out.back()))
                masked_addresses_with_partial_inputs.insert(masked_address_partial_sigs.first);
            else
                sp_partial_inputs_out.pop_back();
        }
    }

    if (legacy_inputs_out.size() != expected_legacy_onetime_addresses.size() ||
        sp_partial_inputs_out.size() != expected_sp_masked_addresses.size())
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
