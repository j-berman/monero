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

// Seraphis transaction-builder helper types
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "sp_base_types.h"
#include "sp_tx_component_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

////
// SpInputProposalV1 - Input V1
///
struct SpInputProposalV1 final : public SpInputProposal
{
    /// the enote to spend (e.g. found in the ledger, or in a tx that has not been added to the ledger)
    SpENoteV1 m_enote;
    /// the enote's pubkey (these are not stored in enotes directly)
    rct::key m_enote_pubkey;

    /// generate a v1 input (all random; does not support info recovery)
    void gen(const rct::xmr_amount amount);

protected:
    virtual const SpENote& get_enote_base() const { return m_enote; }
};

////
// SpDestinationV1 - Destination V1
///
struct SpDestinationV1 final : public SpDestination
{
    /// r_t
    crypto::secret_key m_enote_privkey;

    /// get the amount blinding factor
    void get_amount_blinding_factor(const std::size_t output_index, crypto::secret_key &amount_blinding_factor) const;

    /// convert this destination into a v1 enote
    SpENoteV1 to_enote_v1(const std::size_t output_index, rct::key &enote_pubkey_out) const;

    /**
    * brief: gen - generate a V1 Destination (random)
    * param: amount -
    */
    void gen(const rct::xmr_amount amount);
};

////
// SpMembershipReferenceSetV1 - Records info about a membership reference set, for producing a membership proof
///
struct SpMembershipReferenceSetV1 final
{
    /// ref set size = n^m
    std::size_t m_ref_set_decomp_n;
    std::size_t m_ref_set_decomp_m;
    /// locations in the ledger of the referenced enotes; only enotes in the ledger can have a membership proof
    std::vector<std::size_t> m_ledger_enote_indices;
    /// the referenced enotes
    std::vector<SpENoteV1> m_referenced_enotes;
    /// the index in the referenced enotes vector of the enote who will be proven a member of the ref set (via its image)
    std::size_t m_real_spend_index_in_set;
};

////
// SpMembershipProofSortableV1 - Sortable Membership Proof V1
// - not technically 'sortable', the masked address can be used to match this membership proof with its input image
//   - note: matching can fail if a masked address is reused in a tx, but that is almost definitely an implementation error!
///
struct SpMembershipProofSortableV1 final
{
    /// masked address used in the membership proof (for matching with actual input image)
    rct::key m_masked_address;
    /// the membership proof
    SpMembershipProofV1 m_membership_proof;
};

////
// SpTxProposalV1: set of destinations (and miscellaneous memos), and a balance proof
// - in this version, balance proofs are independent of inputs (the balance proof itself is implicit, only range proofs
//   require storage), so a tx's balance proof can be stored in the tx proposal
///
struct SpTxProposalV1 final
{
//constructors
    /// default constructor
    SpTxProposalV1() = default;

    /// normal constructor: make a tx proposal from destinations (a.k.a. outlays)
    SpTxProposalV1(std::vector<SpDestinationV1> destinations);

//member functions
    /// message to be signed by input spend proofs
    rct::key get_proposal_prefix(const std::string &version_string) const;

//member variables
    /// proposed destinations
    std::vector<SpDestinationV1> m_destinations;
    /// proposed outputs (created from the destinations)
    std::vector<SpENoteV1> m_outputs;
    /// proposed tx supplement
    SpTxSupplementV1 m_tx_supplement;
    /// output amounts and blinding factors (for future balance proofs)
    std::vector<rct::xmr_amount> m_output_amounts;
    std::vector<crypto::secret_key> m_output_amount_commitment_blinding_factors;
    //TODO: miscellaneous memo(s)
};

////
// SpTxPartialInputV1
// - enote spent
// - cached amount and amount blinding factor, image masks (for balance and membership proofs)
// - spend proof for input (and proof the input's key image is properly constructed)
// - proposal prefix (spend proof msg) [for consistency checks when handling this object]
///
struct SpTxPartialInputV1 final //needs to be InputSetPartial for merged composition proofs
{
//constructors
    /// default constructor
    SpTxPartialInputV1() = default;

    /// normal constructor: normal input
    SpTxPartialInputV1(const SpInputProposalV1 &input_proposal, const rct::key &proposal_prefix);

//destructor: default

//member functions

//member variables
    /// input's image
    SpENoteImageV1 m_input_image;
    /// input image's proof (demonstrates ownership of the underlying enote, and that the key image is correct)
    SpImageProofV1 m_image_proof;
    /// image masks
    crypto::secret_key m_image_address_mask;
    crypto::secret_key m_image_amount_mask;

    /// proposal prefix (represents the set of destinations and memos; image proofs must sign this)
    rct::key m_proposal_prefix;

    /// the input enote (won't be recorded in the final tx)
    SpENoteV1 m_input_enote;
    /// input amount
    rct::xmr_amount m_input_amount;
    /// input amount commitment's blinding factor; only used for making the balance proof's remainder blinding factor
    crypto::secret_key m_input_amount_blinding_factor;
};

////
// SpTxPartialV1: everything needed for a tx except input membership proofs
//
// TODO: from multisig - multisigproposal.txproposal, multisig inputs + extra inputs, balance proof
///
struct SpTxPartialV1 final
{
//constructors
    /// default constructor
    SpTxPartialV1() = default;

    /// normal constructor: standard assembly
    SpTxPartialV1(const SpTxProposalV1 &proposal,
        const std::vector<SpTxPartialInputV1> &inputs,
        const std::size_t max_rangeproof_splits,
        const std::string &version_string);

    /// normal constructor (TODO): assembly from multisig pieces

//destructor: default

//member variables
    /// tx input images  (spent e-notes)
    std::vector<SpENoteImageV1> m_input_images;
    /// tx outputs (new e-notes)
    std::vector<SpENoteV1> m_outputs;
    /// balance proof (balance proof and range proofs)
    std::shared_ptr<SpBalanceProofV1> m_balance_proof;
    /// composition proofs: ownership/unspentness for each input
    std::vector<SpImageProofV1> m_image_proofs;
    /// supplemental data for tx
    SpTxSupplementV1 m_tx_supplement;

    /// sorted input enotes
    std::vector<SpENoteV1> m_input_enotes;
    /// sorted image masks for creating input membership proofs
    std::vector<crypto::secret_key> m_image_address_masks;
    std::vector<crypto::secret_key> m_image_amount_masks;
};

} //namespace sp