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

// Seraphis transaction-builder helper types (multisig).


#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/subaddress_index.h"
#include "jamtis_payment_proposal.h"
#include "legacy_enote_types.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "sp_composition_proof.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_extra.h"
#include "tx_legacy_builder_types.h"
#include "tx_multisig_partial_sig_tools.h"

//third party headers

//standard headers
#include <unordered_map>
#include <vector>

//forward declarations


namespace sp
{

////
// LegacyMultisigInputProposalV1
// - propose a legacy tx input to be signed with multisig (for sending to other multisig participants)
///
struct LegacyMultisigInputProposalV1 final
{
    /// the enote to spend
    LegacyEnoteVariant m_enote;
    /// the enote's key image
    crypto::key_image m_key_image;
    /// the enote's ephemeral pubkey
    rct::key m_enote_ephemeral_pubkey;
    /// t: the enote's output index in the tx that created it
    std::uint64_t m_tx_output_index;
    /// u: the enote's unlock time
    std::uint64_t m_unlock_time;

    /// z
    crypto::secret_key m_commitment_mask;

    /**
    * brief: get_input_proposal_v1 - convert this input to a legacy input proposal (throws on failure to convert)
    * param: legacy_spend_pubkey -
    * param: legacy_subaddress_map -
    * param: legacy_view_privkey -
    * outparam: input_proposal_out -
    */
    void get_input_proposal_v1(const rct::key &legacy_spend_pubkey,
        const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
        const crypto::secret_key &legacy_view_privkey,
        LegacyInputProposalV1 &input_proposal_out) const;
};

////
// SpMultisigInputProposalV1
// - propose a seraphis tx input to be signed with multisig (for sending to other multisig participants)
///
struct SpMultisigInputProposalV1 final
{
    /// enote to spend
    SpEnoteV1 m_enote;
    /// the enote's ephemeral pubkey
    crypto::x25519_pubkey m_enote_ephemeral_pubkey;
    /// the enote's input context
    rct::key m_input_context;

    /// t_k
    crypto::secret_key m_address_mask;
    /// t_c
    crypto::secret_key m_commitment_mask;

    /**
    * brief: get_input_proposal_v1 - convert this input to a seraphis input proposal (throws on failure to convert)
    * param: jamtis_spend_pubkey -
    * param: k_view_balance -
    * outparam: input_proposal_out -
    */
    void get_input_proposal_v1(const rct::key &jamtis_spend_pubkey,
        const crypto::secret_key &k_view_balance,
        SpInputProposalV1 &input_proposal_out) const;
};

////
// SpMultisigTxProposalV1
// - propose to fund a set of outputs with multisig inputs
///
struct SpMultisigTxProposalV1 final
{
    /// normal tx outputs
    std::vector<jamtis::JamtisPaymentProposalV1> m_normal_payment_proposals;
    /// self-send tx outputs
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> m_selfsend_payment_proposals;
    /// miscellaneous memo elements to add to the tx memo
    TxExtra m_partial_memo;
    /// proposed transaction fee
    DiscretizedFee m_tx_fee;
    /// legacy tx inputs to sign with multisig
    std::vector<LegacyMultisigInputProposalV1> m_legacy_multisig_input_proposals;
    /// seraphis tx inputs to sign with multisig
    std::vector<SpMultisigInputProposalV1> m_sp_multisig_input_proposals;
    /// legacy ring signature proposals (CLSAGs) for each legacy input proposal
//    std::vector<CLSAGMultisigProposal> m_legacy_input_clsag_proposals;
    /// composition proof proposals for each seraphis input proposal
    std::vector<SpCompositionProofMultisigProposal> m_sp_input_proof_proposals;
    /// all multisig signers who should participate in signing this proposal
    /// - the set may be larger than 'threshold', in which case every permutation of 'threshold' signers will attempt to sign
    multisig::signer_set_filter m_aggregate_signer_set_filter;

    /// encoding of intended tx version
    std::string m_version_string;

    /// convert to plain tx proposal
    void get_v1_tx_proposal_v1(const rct::key &legacy_spend_pubkey,
        const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
        const crypto::secret_key &legacy_view_privkey,
        const rct::key &jamtis_spend_pubkey,
        const crypto::secret_key &k_view_balance,
        SpTxProposalV1 &tx_proposal_out) const;

    /// get the tx proposal prefix that will be signed by input composition proofs
    void get_proposal_prefix_v1(const rct::key &legacy_spend_pubkey,
        const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
        const crypto::secret_key &legacy_view_privkey,
        const rct::key &jamtis_spend_pubkey,
        const crypto::secret_key &k_view_balance,
        rct::key &proposal_prefix_out) const;
};

////
// MultisigProofInitSetV1
// - initialize a set of proofs to be signed by a multisig group
// - each proof has a set of proof nonces for every set of multisig signers that includes the signer in the signer's
//   multisig group
//   - the vectors of proof nonces map 1:1 with the signer sets that include the local signer that can be extracted
//     from the aggregate filter
///
struct MultisigProofInitSetV1 final
{
    /// id of signer who made this input initializer set
    crypto::public_key m_signer_id;
    /// message to be signed by the image proofs
    rct::key m_proof_message;
    /// all multisig signers who should participate in attempting to make these composition proofs
    multisig::signer_set_filter m_aggregate_signer_set_filter;

    // map [proof key to sign : { {alpha_{ki,1,e}*J_1, alpha_{ki,2,e}*J_1}, {alpha_{ki,1,e}*J_2, alpha_{ki,2,e}*J_2}, ... }]
    // - key: main proof key to sign on
    // - value: a set of signature nonce pubkeys for each signer set that includes the specified signer id (i.e. each tx
    //   attempt)
    //   - the set of nonce pubkeys corresponds to a set of nonce base keys across which the multisig signature will be made
    //     (for example: CLSAG signs across both G and Hp(Ko), where Ko is the proof key recorded here)
    //   - WARNING: ordering is dependent on the signer set filter permutation generator
    std::unordered_map<rct::key, std::vector<std::vector<MultisigPubNonces>>> m_inits;

    /// get set of nonces at a [proof key : nonce index] location (return false if the location doesn't exist)
    bool try_get_nonces(const rct::key &proof_key,
        const std::size_t nonces_index,
        std::vector<MultisigPubNonces> &nonces_out) const;
};

////
// MultisigPartialSigSetV1
// - set of partially signed multisigs; combine partial signatures to complete a proof
///
struct MultisigPartialSigSetV1 final
{
    /// id of signer who made these partial signatures
    crypto::public_key m_signer_id;
    /// proof message signed by these partial signatures
    rct::key m_proof_message;
    /// set of multisig signers these partial signatures correspond to
    multisig::signer_set_filter m_signer_set_filter;

    // partial signatures
    std::vector<MultisigPartialSigVariant> m_partial_signatures;
};

} //namespace sp
