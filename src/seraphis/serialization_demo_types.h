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

//todo


#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"
#include "serialization/serialization.h"
#include "tx_binned_reference_set.h"
#include "tx_discretized_fee.h"
#include "txtype_squashed_v1.h"

//third party headers

//standard headers
#include <vector>

//forward declarations

namespace sp
{
namespace serialization
{

/// serializable jamtis::encrypted_address_tag_t
struct ser_encrypted_address_tag_t final
{
    unsigned char bytes[sizeof(jamtis::encrypted_address_tag_t)];
};

/// serializable SpEnote
struct ser_SpEnote final
{
    /// Ko
    rct::key m_onetime_address;
    /// C
    rct::key m_amount_commitment;

    BEGIN_SERIALIZE()
        FIELD(m_onetime_address)
        FIELD(m_amount_commitment)
    END_SERIALIZE()
};

/// serializable SpEnoteImage
struct ser_SpEnoteImage final
{
    /// K"
    rct::key m_masked_address;
    /// C"
    rct::key m_masked_commitment;
    /// KI
    crypto::key_image m_key_image;

    BEGIN_SERIALIZE()
        FIELD(m_masked_address)
        FIELD(m_masked_commitment)
        FIELD(m_key_image)
    END_SERIALIZE()
};

/// partially serializable BulletproofPlus2
struct ser_BulletproofPlus2_PARTIAL final
{
    //rct::keyV V;  (not serializable here)
    rct::key A, A1, B;
    rct::key r1, s1, d1;
    rct::keyV L, R;

    BEGIN_SERIALIZE()
        FIELD(A)
        FIELD(A1)
        FIELD(B)
        FIELD(r1)
        FIELD(s1)
        FIELD(d1)
        FIELD(L)
        FIELD(R)
    END_SERIALIZE()
};

/// partially serializable rct::clsag
struct ser_clsag_PARTIAL final
{
    rct::keyV s; // scalars
    rct::key c1;

    //rct::key I; // signing key image   (not serializable here)
    rct::key D; // commitment key image

    BEGIN_SERIALIZE()
        FIELD(s)
        FIELD(c1)
        FIELD(D)
    END_SERIALIZE()
};

/// serializable SpCompositionProof
struct ser_SpCompositionProof final
{
    // challenge
    rct::key c;
    // responses
    rct::key r_t1, r_t2, r_ki;
    // intermediate proof key
    rct::key K_t1;

    BEGIN_SERIALIZE()
        FIELD(c)
        FIELD(r_t1)
        FIELD(r_t2)
        FIELD(r_ki)
        FIELD(K_t1)
    END_SERIALIZE()
};

/// serializable GrootleProof
struct ser_GrootleProof final
{
    rct::key A, B;
    rct::keyM f;
    rct::keyV X;
    rct::key zA, z;

    BEGIN_SERIALIZE()
        FIELD(A)
        FIELD(B)
        FIELD(f)
        FIELD(X)
        FIELD(zA)
        FIELD(z)
    END_SERIALIZE()
};

/// partially serializable SpBinnedReferenceSetV1
struct ser_SpBinnedReferenceSetV1_PARTIAL final
{
    /// bin configuration details (shared by all bins)
    //SpBinnedReferenceSetConfigV1 m_bin_config;  (not serializable here)
    /// bin generator seed (shared by all bins)
    //rct::key m_bin_generator_seed;              (not serializable here)
    /// rotation factor (shared by all bins)
    std::uint16_t m_bin_rotation_factor;
    /// bin loci (serializable as index offsets)
    std::vector<std::uint64_t> m_bin_loci_COMPACT;

    BEGIN_SERIALIZE()
        VARINT_FIELD(m_bin_rotation_factor)
            static_assert(sizeof(m_bin_rotation_factor) == sizeof(ref_set_bin_dimension_v1_t), "");
        FIELD(m_bin_loci_COMPACT)
    END_SERIALIZE()
};

/// serializable LegacyEnoteImageV2
struct ser_LegacyEnoteImageV2 final
{
    /// masked commitment (aka 'pseudo-output commitment')
    rct::key m_masked_commitment;
    /// legacy key image
    crypto::key_image m_key_image;

    BEGIN_SERIALIZE()
        FIELD(m_masked_commitment)
        FIELD(m_key_image)
    END_SERIALIZE()
};

/// serializable SpEnoteImageV1
struct ser_SpEnoteImageV1 final
{
    /// enote image core
    ser_SpEnoteImage m_core;

    BEGIN_SERIALIZE()
        FIELD(m_core)
    END_SERIALIZE()
};

/// serializable SpEnoteV1
struct ser_SpEnoteV1 final
{
    /// enote core (one-time address, amount commitment)
    ser_SpEnote m_core;

    /// enc(a)
    rct::xmr_amount m_encoded_amount;
    /// addr_tag_enc
    ser_encrypted_address_tag_t m_addr_tag_enc;

    /// view_tag
    unsigned char m_view_tag;

    BEGIN_SERIALIZE()
        FIELD(m_core)
        VARINT_FIELD(m_encoded_amount)
        FIELD(m_addr_tag_enc)    static_assert(sizeof(m_addr_tag_enc) == sizeof(jamtis::encrypted_address_tag_t), "");
        VARINT_FIELD(m_view_tag) static_assert(sizeof(m_view_tag) == sizeof(jamtis::view_tag_t), "");
    END_SERIALIZE()
};

/// partially serializable SpBalanceProofV1
struct ser_SpBalanceProofV1_PARTIAL final
{
    /// an aggregate set of BP+ proofs (partial serialization)
    ser_BulletproofPlus2_PARTIAL m_bpp2_proof_PARTIAL;
    /// the remainder blinding factor
    rct::key m_remainder_blinding_factor;

    BEGIN_SERIALIZE()
        FIELD(m_bpp2_proof_PARTIAL)
        FIELD(m_remainder_blinding_factor)
    END_SERIALIZE()
};

/// partially serializable LegacyRingSignatureV3
struct ser_LegacyRingSignatureV3_PARTIAL final
{
    /// a clsag proof
    ser_clsag_PARTIAL m_clsag_proof_PARTIAL;
    /// on-chain indices of the proof's ring members (serializable as index offsets)
    std::vector<std::uint64_t> m_reference_set_COMPACT;

    BEGIN_SERIALIZE()
        FIELD(m_clsag_proof_PARTIAL)
        FIELD(m_reference_set_COMPACT)
    END_SERIALIZE()
};

/// serializable SpImageProofV1
struct ser_SpImageProofV1 final
{
    /// a seraphis composition proof
    ser_SpCompositionProof m_composition_proof;

    BEGIN_SERIALIZE()
        FIELD(m_composition_proof)
    END_SERIALIZE()
};

/// partially serializable SpMembershipProofV1 (does not include config info)
struct ser_SpMembershipProofV1_PARTIAL final
{
    /// a grootle proof
    ser_GrootleProof m_grootle_proof;
    /// binned representation of ledger indices of enotes referenced by the proof
    ser_SpBinnedReferenceSetV1_PARTIAL m_binned_reference_set_PARTIAL;
    /// ref set size = n^m
    //std::size_t m_ref_set_decomp_n;  (not serializable here)
    //std::size_t m_ref_set_decomp_m;  (not serializable here)

    BEGIN_SERIALIZE()
        FIELD(m_grootle_proof)
        FIELD(m_binned_reference_set_PARTIAL)
    END_SERIALIZE()
};

/// serializable SpTxSupplementV1
struct ser_SpTxSupplementV1 final
{
    /// xKe: enote ephemeral pubkeys for outputs
    std::vector<crypto::x25519_pubkey> m_output_enote_ephemeral_pubkeys;
    /// tx memo
    std::vector<unsigned char> m_tx_extra;

    BEGIN_SERIALIZE()
        FIELD(m_output_enote_ephemeral_pubkeys)
        FIELD(m_tx_extra)
    END_SERIALIZE()
};

/// serializable SpTxSquashedV1
struct ser_SpTxSquashedV1 final
{
    /// semantic rules version
    SpTxSquashedV1::SemanticRulesVersion m_tx_semantic_rules_version;

    /// legacy tx input images (spent legacy enotes)
    std::vector<ser_LegacyEnoteImageV2> m_legacy_input_images;
    /// seraphis tx input images (spent seraphis enotes)
    std::vector<ser_SpEnoteImageV1> m_sp_input_images;
    /// tx outputs (new enotes)
    std::vector<ser_SpEnoteV1> m_outputs;
    /// balance proof (balance proof and range proofs)
    ser_SpBalanceProofV1_PARTIAL m_balance_proof;
    /// ring signature proofs: membership and ownership/key-image-legitimacy for each legacy input
    std::vector<ser_LegacyRingSignatureV3_PARTIAL> m_legacy_ring_signatures;
    /// composition proofs: ownership/key-image-legitimacy for each seraphis input
    std::vector<ser_SpImageProofV1> m_sp_image_proofs;
    /// Grootle proofs on squashed enotes: membership for each seraphis input
    std::vector<ser_SpMembershipProofV1_PARTIAL> m_sp_membership_proofs;
    /// supplemental data for tx
    ser_SpTxSupplementV1 m_tx_supplement;
    /// the transaction fee (discretized representation)
    unsigned char m_tx_fee;

    BEGIN_SERIALIZE()
        VARINT_FIELD(m_tx_semantic_rules_version)
        FIELD(m_legacy_input_images)
        FIELD(m_sp_input_images)
        FIELD(m_outputs)
        FIELD(m_balance_proof)
        FIELD(m_legacy_ring_signatures)
        FIELD(m_sp_image_proofs)
        FIELD(m_sp_membership_proofs)
        FIELD(m_tx_supplement)
        VARINT_FIELD(m_tx_fee) static_assert(sizeof(m_tx_fee) == sizeof(DiscretizedFee), "");
    END_SERIALIZE()
};

} //namespace serialization
} //namespace sp

BLOB_SERIALIZER(sp::serialization::ser_encrypted_address_tag_t);
