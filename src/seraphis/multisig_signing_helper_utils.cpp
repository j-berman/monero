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
#include "multisig_signing_helper_utils.h"

//local headers
#include "crypto/crypto.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig_nonce_record.h"
#include "multisig_partial_sig_makers.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "sp_misc_utils.h"

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
static void attempt_make_v1_multisig_partial_sig_set_v1(const std::uint32_t threshold,
    const multisig::signer_set_filter filter,
    const rct::keyV &proof_keys,
    const std::vector<MultisigProofInitSetV1> &all_init_sets,
    const std::vector<multisig::signer_set_filter> &available_signers_as_filters,
    const std::vector<std::size_t> &signer_nonce_trackers,
    const MultisigPartialSigMaker &partial_sig_maker,
    const crypto::secret_key &local_signer_privkey,
    MultisigNonceRecord &nonce_record_inout,
    std::vector<MultisigPartialSigVariant> &partial_signatures_out)
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
    std::size_t pub_nonces_set_size{static_cast<std::size_t>(-1)};
    std::vector<MultisigPubNonces> signer_pub_nonces_set_temp;
    std::vector<std::vector<MultisigPubNonces>> signer_pub_nonce_sets_temp;
    signer_pub_nonce_sets_temp.reserve(threshold);

    partial_signatures_out.clear();
    partial_signatures_out.reserve(proof_keys.size());

    for (const rct::key &proof_key : proof_keys)
    {
        // a. collect nonces from all signers in this signing group
        signer_pub_nonce_sets_temp.clear();
        for (std::size_t signer_index{0}; signer_index < all_init_sets.size(); ++signer_index)
        {
            // ignore signers not in the requested signing group
            if ((available_signers_as_filters[signer_index] & filter) == 0)
                continue;

            // indexing:
            // - this signer's init set
            // - select the proof we are working on (via this proof's proof key)
            // - select the nonces that line up with the signer's nonce tracker
            if (!all_init_sets[signer_index].try_get_nonces(proof_key,
                    signer_nonce_trackers[signer_index],
                    signer_pub_nonces_set_temp))
                throw;

            // initialize nonce set size
            if (pub_nonces_set_size == static_cast<std::size_t>(-1))
            {
                pub_nonces_set_size = signer_pub_nonces_set_temp.size();
                signer_pub_nonce_sets_temp.resize(pub_nonces_set_size);
            }

            // expect nonce sets to be consistently sized
            if (signer_pub_nonces_set_temp.size() != pub_nonces_set_size)
                throw;

            // save nonce sets; the set members are split between rows in the signer_pub_nonce_sets_temp matrix
            for (std::size_t nonce_set_index{0}; nonce_set_index < pub_nonces_set_size; ++nonce_set_index)
                signer_pub_nonce_sets_temp[nonce_set_index].emplace_back(signer_pub_nonces_set_temp[nonce_set_index]);
        }

        // b. sanity check
        for (const std::vector<MultisigPubNonces> &signer_pub_nonce_set : signer_pub_nonce_sets_temp)
        {
            if (signer_pub_nonce_set.size() != threshold)
                throw;
        }

        // c. make a partial signature
        partial_sig_maker.attempt_make_partial_sig(proof_key,
            filter,
            signer_pub_nonce_sets_temp,
            local_signer_privkey,
            nonce_record_inout,
            add_element(partial_signatures_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
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
bool validate_v1_multisig_init_set_v1(const MultisigProofInitSetV1 &init_set,
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
void validate_and_prepare_multisig_init_sets_v1(const multisig::signer_set_filter aggregate_signer_set_filter,
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
void make_v1_multisig_init_set_v1(const crypto::public_key &signer_id,
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
            add_element(init_set_out.m_inits[proof_info.first]).reserve(proof_info.second.size());

            // record the nonce pubkeys for each requested proof base point (should not fail)
            for (const rct::key &proof_base : proof_info.second)
            {
                CHECK_AND_ASSERT_THROW_MES(nonce_record_inout.try_get_nonce_pubkeys_for_base(proof_message,
                        proof_info.first,
                        filter,
                        proof_base,
                        add_element(init_set_out.m_inits[proof_info.first].back())),
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
void check_v1_multisig_partial_sig_set_semantics_v1(const MultisigPartialSigSetV1 &partial_sig_set,
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
void make_v1_multisig_partial_sig_sets_v1(const multisig::multisig_account &signer_account,
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
        "make multisig partial sigs: signer account is not complete, so it can't make partial signatures.");

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
                attempt_make_v1_multisig_partial_sig_set_v1(signer_account.get_threshold(),
                    filter,
                    proof_keys,
                    all_init_sets,
                    available_signers_as_filters,
                    signer_nonce_trackers,
                    partial_sig_maker,
                    k_b_e_temp,
                    nonce_record_inout,
                    partial_sig_sets_out.back().m_partial_signatures);

                // 3. copy miscellanea
                partial_sig_sets_out.back().m_signer_id = signer_account.get_base_pubkey();
                partial_sig_sets_out.back().m_proof_message = proof_message;
                partial_sig_sets_out.back().m_signer_set_filter = filter;

                // 4. sanity check
                check_v1_multisig_partial_sig_set_semantics_v1(partial_sig_sets_out.back(), signer_account.get_signers());
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
void filter_multisig_partial_signatures_for_combining_v1(const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &expected_proof_message,
    const std::unordered_set<rct::key> &expected_proof_keys,
    const int expected_partial_sig_variant_index,
    const std::unordered_map<crypto::public_key, std::vector<MultisigPartialSigSetV1>> &partial_sigs_per_signer,
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //proof key
            std::vector<MultisigPartialSigVariant>>> &collected_sigs_per_key_per_filter_out)
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
            try { check_v1_multisig_partial_sig_set_semantics_v1(partial_sig_set, multisig_signers); }
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

                // skip partial sigs with unexpected internal variant type
                if (partial_sig.type_index() != expected_partial_sig_variant_index)
                    continue;

                collected_sigs_per_key_per_filter_out[partial_sig_set.m_signer_set_filter][partial_sig.proof_key()]
                    .emplace_back(partial_sig);
            }
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
