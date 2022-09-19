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

// Legacy transaction-builder helper types.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "tx_legacy_component_types.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

////
// LegacyInputProposalV1
///
struct LegacyInputProposalV1 final
{
    /// core of the original enote
    rct::key m_onetime_address;
    rct::key m_amount_commitment;
    /// the enote's key image
    crypto::key_image m_key_image;

    /// Hn(k_v R_t, t) + [subaddresses: Hn(k_v, i)]  (does not include legacy spend privkey k_s)
    crypto::secret_key m_enote_view_privkey;
    /// x
    crypto::secret_key m_amount_blinding_factor;
    /// a
    rct::xmr_amount m_amount;

    /// z
    crypto::secret_key m_commitment_mask;

    /// less-than operator for sorting
    bool operator<(const LegacyInputProposalV1 &other_proposal) const { return m_key_image < other_proposal.m_key_image; }

    /**
    * brief: get_enote_image_v2 - get this input's enote image
    * outparam: image_out -
    */
    void get_enote_image_v2(LegacyEnoteImageV2 &image_out) const;

    /// get the amount of this proposal
    rct::xmr_amount get_amount() const { return m_amount; }

    /// generate a v1 input (does not support info recovery)
    void gen(const crypto::secret_key &legacy_spend_privkey, const rct::xmr_amount amount);
};

////
// LegacyRingSignaturePrepV1
// - data for producing a legacy ring signature
///
struct LegacyRingSignaturePrepV1 final
{
    /// tx proposal prefix (message to sign in the proof)
    rct::key m_proposal_prefix;
    /// ledger indices of legacy enotes referenced by the proof
    std::vector<std::uint64_t> m_reference_set;
    /// the referenced enotes ({Ko, C"}((legacy)) representation)
    rct::ctkeyV m_referenced_enotes;
    /// the index of the real enote being referenced within the reference set
    std::uint64_t m_real_reference_index;
    /// enote image of the real reference
    LegacyEnoteImageV2 m_reference_image;
    /// enote view privkey of the real reference's onetime address
    crypto::secret_key m_reference_view_privkey;
    /// commitment mask applied to the reference amount commitment to produce the image's masked commitment
    crypto::secret_key m_reference_commitment_mask;

    /// less-than operator for sorting
    bool operator<(const LegacyRingSignaturePrepV1 &other_prep) const
    {
        return m_reference_image < other_prep.m_reference_image;
    }
};

////
// LegacyInputV1: todo
// - enote spent
// - legacy ring signature for the input
// - cached amount and masked amount commitment's blinding factor (for balance proof)
// - proposal prefix (spend proof msg) [for consistency checks when handling this object]
///
struct LegacyInputV1 final
{
    /// input's image
    LegacyEnoteImageV2 m_input_image;
    /// input's ring signature (demonstrates ownership and membership of the underlying enote, and that the key image
    ///   is correct)
    LegacyRingSignatureV3 m_ring_signature;

    /// input amount
    rct::xmr_amount m_input_amount;
    /// input masked amount commitment's blinding factor; used for making the balance proof
    crypto::secret_key m_input_masked_commitment_blinding_factor;

    /// cached ring members of the ring signature; used for validating the ring signature
    rct::ctkeyV m_ring_members;

    /// proposal prefix (represents the inputs/outputs/fee/memo; signed by this input's ring signature)
    rct::key m_proposal_prefix;

    /// less-than operator for sorting
    bool operator<(const LegacyInputV1 &other_input) const
    {
        return m_input_image < other_input.m_input_image;
    }
};

} //namespace sp
