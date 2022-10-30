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

// Utilities to assist with multisig signing ceremonies.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "multisig/multisig_account.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig_signing_helper_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

//forward declarations
namespace sp
{
    class MultisigNonceRecord;
    class MultisigPartialSigMaker;
}


namespace sp
{

/**
* brief: check_v1_multisig_init_set_semantics_v1 - check semantics of a multisig initializer set
*   - throws if a check fails
* param: init_set -
* param: threshold -
* param: multisig_signers -
* param: num_expected_nonce_sets_per_proofkey -
*/
void check_v1_multisig_init_set_semantics_v1(const MultisigProofInitSetV1 &init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::size_t num_expected_nonce_sets_per_proofkey);
/**
* brief: validate_and_prepare_multisig_init_sets_v1 - validate multisig inits, clean them up, and combine into a
*      collection of init sets that can be used to initialize partial signatures for multisig signing attempts
* param: aggregate_signer_set_filter -
* param: threshold -
* param: multisig_signers -
* param: local_signer_id -
* param: proof_keys -
* param: num_expected_nonce_sets_per_proofkey -
* param: proof_message -
* param: local_init_set -
* param: other_init_sets -
* outparam: all_init_sets_out -
*/
bool validate_v1_multisig_init_set_v1(const MultisigProofInitSetV1 &init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &expected_proof_message,
    const multisig::signer_set_filter expected_aggregate_signer_set_filter,
    const std::vector<rct::key> &expected_proof_keys,
    const std::size_t num_expected_nonce_sets_per_proofkey);
void validate_and_prepare_multisig_init_sets_v1(const multisig::signer_set_filter aggregate_signer_set_filter,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const crypto::public_key &local_signer_id,
    const rct::keyV &proof_keys,
    const std::size_t num_expected_nonce_sets_per_proofkey,
    const rct::key &proof_message,
    MultisigProofInitSetV1 local_init_set,
    std::vector<MultisigProofInitSetV1> other_init_sets,
    std::vector<MultisigProofInitSetV1> &all_init_sets_out);
/**
* brief: make_v1_multisig_init_set_v1 - make a multisig initialization set for specified proof info
* param: signer_id -
* param: threshold -
* param: multisig_signers -
* param: proof_message -
* param: proof_infos -
* param: aggregate_signer_set_filter -
* inoutparam: nonce_record_inout -
* outparam: init_set_out -
*/
void make_v1_multisig_init_set_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &proof_message,
    const std::vector<std::pair<rct::key, rct::keyV>> &proof_infos,  //[ proof key : {multisig proof base points} ]
    const multisig::signer_set_filter aggregate_signer_set_filter,
    MultisigNonceRecord &nonce_record_inout,
    MultisigProofInitSetV1 &init_set_out);
/**
* brief: check_v1_multisig_partial_sig_set_semantics_v1 - check semantics of a multisig partial signature set
*   - throws if a check fails
* param: partial_sig_set -
* param: multisig_signers -
*/
void check_v1_multisig_partial_sig_set_semantics_v1(const MultisigPartialSigSetV1 &partial_sig_set,
    const std::vector<crypto::public_key> &multisig_signers);
/**
* brief: make_v1_multisig_partial_sig_sets_v1 - try to make multisig partial signature sets with an injected partial sig
*      maker
*   - weak preconditions: ignores invalid initializers from non-local signers
*   - will throw if local signer is not in the aggregate signer filter (or has an invalid initializer)
*   - will only succeed if a partial sig set can be made containing a partial sig on each of the requested proof keys
* param: signer_account -
* param: proof_message -
* param: proof_keys -
* param: filter_permutations -
* param: local_signer_filter -
* param: all_init_sets -
* param: available_signers_filter -
* param: available_signers_as_filters - expected to align 1:1 with signers in all_init_sets
* param: partial_sig_maker -
* inoutparam: nonce_record_inout -
* outparam: partial_sig_sets_out -
*/
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
    std::vector<MultisigPartialSigSetV1> &partial_sig_sets_out);
/**
* brief: filter_multisig_partial_signatures_for_combining_v1 - filter multisig partial signature sets into a convenient
*      map for combining them into complete signatures
*   - weak preconditions: ignores signature sets that don't conform to expectations
* param: multisig_signers -
* param: expected_proof_message -
* param: expected_proof_keys -
* param: expected_partial_sig_variant_index -
* param: partial_sigs_per_signer -
* outparam: collected_sigs_per_key_per_filter_out -
*/
void filter_multisig_partial_signatures_for_combining_v1(const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &expected_proof_message,
    const std::unordered_set<rct::key> &expected_proof_keys,
    const int expected_partial_sig_variant_index,
    const std::unordered_map<crypto::public_key, std::vector<MultisigPartialSigSetV1>> &partial_sigs_per_signer,
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //proof key
            std::vector<MultisigPartialSigVariant>>> &collected_sigs_per_key_per_filter_out);

} //namespace sp
