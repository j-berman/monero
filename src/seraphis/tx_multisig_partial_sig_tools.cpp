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
#include "tx_multisig_partial_sig_tools.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "misc_log_ex.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctTypes.h"
#include "sp_composition_proof.h"
#include "sp_crypto_utils.h"
#include "sp_multisig_nonce_record.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static SpCompositionProofMultisigPartial attempt_make_sp_composition_multisig_partial_sig(const rct::key &squash_prefix,
    const crypto::secret_key &enote_view_privkey_g,
    const crypto::secret_key &enote_view_privkey_x,
    const crypto::secret_key &enote_view_privkey_u,
    const crypto::secret_key &address_mask,
    const rct::key &one_div_threshold,
    const crypto::secret_key &k_b_e,
    const SpCompositionProofMultisigProposal &proof_proposal,
    const std::vector<MultisigPubNonces> &signer_pub_nonces,
    const multisig::signer_set_filter filter,
    MultisigNonceRecord &nonce_record_inout)
{
    crypto::secret_key x_temp;
    crypto::secret_key y_temp;
    crypto::secret_key z_e_temp;

    // prepare x: t_k + Hn(Ko, C) * k_mask
    sc_mul(to_bytes(x_temp), squash_prefix.bytes, to_bytes(enote_view_privkey_g));
    sc_add(to_bytes(x_temp), to_bytes(address_mask), to_bytes(x_temp));

    // prepare y: Hn(Ko, C) * k_a
    sc_mul(to_bytes(y_temp), squash_prefix.bytes, to_bytes(enote_view_privkey_x));

    // prepare z_e: Hn(Ko, C) * ((1/threshold)*k_view_u + k_b_e)
    // note: each signer adds (1/threshold)*k_view_u so the sum works out
    sc_mul(to_bytes(z_e_temp), one_div_threshold.bytes, to_bytes(enote_view_privkey_u));
    sc_add(to_bytes(z_e_temp), to_bytes(z_e_temp), to_bytes(k_b_e));
    sc_mul(to_bytes(z_e_temp), squash_prefix.bytes, to_bytes(z_e_temp));

    // local signer's partial sig for this input
    SpCompositionProofMultisigPartial partial_sig;

    if (!try_make_sp_composition_multisig_partial_sig(proof_proposal,
            x_temp,
            y_temp,
            z_e_temp,
            signer_pub_nonces,
            filter,
            nonce_record_inout,
            partial_sig))
        throw;

    return partial_sig;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
const rct::key& MultisigPartialSigVariant::message() const
{
    if (is_type<SpCompositionProofMultisigPartial>())
        return get_partial_sig<SpCompositionProofMultisigPartial>().message;
    //todo: legacy
    //else if (is_type<SpContextualBasicEnoteRecordV1>())
    //    return get_contextual_record<SpContextualBasicEnoteRecordV1>().m_origin_context;
    else
    {
        static const rct::key temp{};
        return temp;
    }
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& MultisigPartialSigVariant::proof_key() const
{
    if (is_type<SpCompositionProofMultisigPartial>())
        return get_partial_sig<SpCompositionProofMultisigPartial>().K;
    //todo: legacy
    //else if (is_type<SpContextualBasicEnoteRecordV1>())
    //    return get_contextual_record<SpContextualBasicEnoteRecordV1>().m_origin_context;
    else
    {
        static const rct::key temp{};
        return temp;
    }
}
//-------------------------------------------------------------------------------------------------------------------
MultisigPartialSigMakerSpCompositionProof::MultisigPartialSigMakerSpCompositionProof(const std::uint32_t threshold,
    const std::vector<SpCompositionProofMultisigProposal> &proof_proposals,
    const rct::keyV &squash_prefixes,
    const std::vector<crypto::secret_key> &enote_view_privkeys_g,
    const std::vector<crypto::secret_key> &enote_view_privkeys_x,
    const std::vector<crypto::secret_key> &enote_view_privkeys_u,
    const std::vector<crypto::secret_key> &address_masks) :
        m_inv_threshold{invert(rct::d2h(threshold))},  //throws if threshold is 0
        m_proof_proposals{proof_proposals},
        m_squash_prefixes{squash_prefixes},
        m_enote_view_privkeys_g{enote_view_privkeys_g},
        m_enote_view_privkeys_x{enote_view_privkeys_x},
        m_enote_view_privkeys_u{enote_view_privkeys_u},
        m_address_masks{address_masks}
{
    const std::size_t num_proposals{m_proof_proposals.size()};

    CHECK_AND_ASSERT_THROW_MES(threshold > 0,
        "MultisigPartialSigMakerSpCompositionProof: multisig threshold is zero.");
    CHECK_AND_ASSERT_THROW_MES(m_squash_prefixes.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: enote squash prefixes don't line up with proof proposals.");
    CHECK_AND_ASSERT_THROW_MES(m_enote_view_privkeys_g.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: enote view privkeys (g) don't line up with proof proposals.");
    CHECK_AND_ASSERT_THROW_MES(m_enote_view_privkeys_x.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: enote view privkeys (x) don't line up with proof proposals.");
    CHECK_AND_ASSERT_THROW_MES(m_enote_view_privkeys_u.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: enote view privkeys (u) don't line up with proof proposals.");
    CHECK_AND_ASSERT_THROW_MES(m_address_masks.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: address masks don't line up with proof proposals.");
}
//-------------------------------------------------------------------------------------------------------------------
void MultisigPartialSigMakerSpCompositionProof::attempt_make_partial_sig(
    const std::size_t signature_proposal_index,
    const multisig::signer_set_filter signer_group_filter,
    const std::vector<MultisigPubNonces> &signer_group_pub_nonces,
    const crypto::secret_key &local_multisig_signing_key,
    MultisigNonceRecord &nonce_record_inout,
    MultisigPartialSigVariant &partial_sig_out) const
{
    CHECK_AND_ASSERT_THROW_MES(signature_proposal_index < m_proof_proposals.size(),
        "MultisigPartialSigMakerSpCompositionProof (attempt make partial sig): requested signature proposal index is "
        "out of range.");

    partial_sig_out.m_partial_sig =
        attempt_make_sp_composition_multisig_partial_sig(m_squash_prefixes.at(signature_proposal_index),
            m_enote_view_privkeys_g.at(signature_proposal_index),
            m_enote_view_privkeys_x.at(signature_proposal_index),
            m_enote_view_privkeys_u.at(signature_proposal_index),
            m_address_masks.at(signature_proposal_index),
            m_inv_threshold,
            local_multisig_signing_key,
            m_proof_proposals.at(signature_proposal_index),
            signer_group_pub_nonces,
            signer_group_filter,
            nonce_record_inout);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
