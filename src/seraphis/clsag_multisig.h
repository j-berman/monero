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

////
// Schnorr-like composition proof for a secret key of the form K = x*G + y*X + z*U
// - demonstrates knowledge of x, y, z
//   - x >= 0
//   - y, z > 0
// - shows that key image KI = (z/y)*U
//
// proof outline
// 0. preliminaries
//    H_32(...) = blake2b(...) -> 32 bytes    hash to 32 bytes
//    H_n(...)  = H_64(...) mod l             hash to ed25519 scalar
//    G, X, U: ed25519 generators
// 1. pubkeys
//    K    = x*G + y*X + z*U
//    K_t1 = (x/y)*G + X + (z/y)*U
//    K_t2 = (x/y)*G            = K_t1 - X - KI
//    KI   = (z/y)*U
// 2. proof nonces and challenge
//    cm = H_32(X, U, m, K, KI, K_t1)   challenge message
//    a_t1, a_t2, a_ki = rand()                       prover nonces
//    c = H_n(cm, [a_t1 K], [a_t2 G], [a_ki U])       challenge
// 3. responses
//    r_t1 = a_t1 - c*(1/y)
//    r_t2 = a_t2 - c*(x/y)
//    r_ki = a_ki - c*(z/y)
// 4. proof: {m, c, r_t1, r_t2, r_ki, K, K_t1, KI}
//
// verification
// 1. K_t2 = K_t1 - X - KI, cm = ...
// 2. c' = H_n(cm, [r_t1*K + c*K_t1], [r_t2*G + c*K_t2], [r_ki*U + c*KI])
// 3. if (c' == c) then the proof is valid
//
// note: G_0 = G, G_1 = X, G_2 = U (for Seraphis paper notation)
// note: in practice, K is a masked address from a Seraphis enote image, and KI is the corresponding linking tag
// note: assume key image KI is in the prime subgroup (canonical bytes) and non-identity
//   - WARNING: the caller must validate KI (and check non-identity); either...
//     - 1) l*KI == identity
//     - 2) store (1/8)*KI with proof material (e.g. in a transaction); pass 8*[(1/8)*KI] as input to composition proof
//          validation
//
// multisig notation: alpha_{a,n,e}
// - a: indicates which part of the proof this is for
// - n: for MuSig2-style bi-nonce signing, alpha_{b,1,e} is nonce 'D', alpha_{b,2,e} is nonce 'E' (in their notation)
// - e: multisig signer index
//
// References:
// - Seraphis (UkoeHB): https://github.com/UkoeHB/Seraphis (temporary reference)
//
// Multisig references:
// - MuSig2 (Nick): https://eprint.iacr.org/2020/1261
// - FROST (Komlo): https://eprint.iacr.org/2020/852
// - Multisig/threshold security (Crites): https://eprint.iacr.org/2021/1375
// - MRL-0009 (Brandon Goodell and Sarang Noether): https://web.getmonero.org/resources/research-lab/pubs/MRL-0009.pdf
// - Zero to Monero: 2nd Edition Chapter 9 (UkoeHB): https://web.getmonero.org/library/Zero-to-Monero-2-0-0.pdf
// - (Technical Note) Multisig - Defeating Drijvers with Bi-Nonce Signing (UkoeHB):
//     https://github.com/UkoeHB/drijvers-multisig-tech-note
///


#pragma once

//local headers
#include "crypto/crypto.h"
#include "multisig_nonce_record.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////// Types ////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// CLSAG (see src/ringct/rctTypes.h)
///
/*
struct clsag
{
    keyV s; // scalars/responses
    key c1; // challenge

    key I; // signing key image
    key D; // commitment key image
}
*/

////
// Multisig signature proposal for CLSAG proofs
//
// WARNING: must only use a 'proposal' to make ONE 'signature' (or signature attempt),
//          after that the opening privkeys should be deleted immediately
///
struct CLSAGMultisigProposal final
{
    // message to be signed
    rct::key message;
    // ring of nominal proof keys
    rct::keyV nominal_proof_Ks;
    // ring of nominal ancillary proof keys (Pedersen commitments)
    rct::keyV nominal_pedersen_Cs;
    // masked Pedersen commitment at index l (commitment to zero: nominal_pedersen_Cs[l] - masked_C = z G)
    rct::key masked_C;
    // main key image KI
    crypto::key_image KI;
    // ancillary key image D (note: D is stored as '1/8 * D' in the rct::clsag struct, but is stored unmultiplied here)
    // note: D = z * Hp(nominal_proof_Ks[l])
    crypto::key_image D;
    // decoy responses for each nominal {proof key, ancillary proof key} pair (the decoy at index l will be replaced by
    //    the real multisig aggregate response in the final proof)
    rct::keyV decoy_responses;

    // real proof key's index in nominal proof keys
    std::uint32_t l;

    // range-checked access to the real proof key
    const rct::key& main_proof_key() const;
};

////
// Multisig partially signed CLSAG (from one multisig participant)
// - stores multisig partial response for proof position at index l
// note: does not store ring members because those are not included in the final rct::clsag; note that the ring members
//       are hashed into c_0, so checking that c_0 is consistent between partial sigs is sufficient to ensure partial sigs
//       are combinable
///
struct CLSAGMultisigPartial final
{
    // message
    rct::key message;
    // main proof key K
    rct::key main_proof_key_K;
    // real proof key's index in nominal proof keys
    std::uint32_t l;

    // responses for each nominal {proof key, ancillary proof key} pair 
    // - the response at index l is this multisig partial signature's partial response
    rct::keyV responses;
    // challenge
    rct::key c_0;
    // key image KI
    crypto::key_image KI;
    // ancillary key image D
    crypto::key_image D;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////// Multisig ///////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* brief: make_clsag_multisig_proposal - propose to make a multisig CLSAG proof
* param: message - message to insert in the proof's Fiat-Shamir transform hash
* param: nominal_proof_Ks - ring of main proof keys
* param: nominal_pedersen_Cs - ring of auxilliary proof keys (Pedersen commitments)
* param: masked_C - masked auxilliary proof key at index l (commitment to zero: nominal_pedersen_Cs[l] - masked_C = z G)
* param: KI - main key image
* param: D - auxilliary key image
* param: l - index of the real signing keys in the key rings
* outparam: proposal_out - CLSAG multisig proposal
*/
void make_clsag_multisig_proposal(const rct::key &message,
    rct::keyV nominal_proof_Ks,
    rct::keyV nominal_pedersen_Cs,
    const rct::key &masked_C,
    const crypto::key_image &KI,
    const crypto::key_image &D,
    const std::uint32_t l,
    CLSAGMultisigProposal &proposal_out);
/**
* brief: make_clsag_multisig_partial_sig - make local multisig signer's partial signature for a CLSAG proof
*   - caller must validate the CLSAG multisig proposal
*       - are the key images well-made?
*       - are the main key, ancillary key, and masked key legitimate?
*       - is the message correct?
*       - are all the decoy ring members valid?
* param: proposal - proof proposal to construct proof partial signature from
* param: k_e - secret key of multisig signer e for main proof key at position l
* param: z_e - secret key of multisig signer e for commitment to zero at position l (for the auxilliary component)
* param: signer_pub_nonces_G - signature nonce pubkeys (1/8) * {alpha_{1,e}*G,  alpha_{2,e}*G} from all signers
*                              (including local signer)
* param: signer_pub_nonces_Hp - signature nonce pubkeys (1/8) * {alpha_{1,e}*Hp(K[l]),  alpha_{2,e}*Hp(K[l])} from all
*                              signers (including local signer)
* param: local_nonce_1_priv - alpha_{1,e} for local signer
* param: local_nonce_2_priv - alpha_{2,e} for local signer
* outparam: partial_sig_out - partially signed Seraphis composition proof
*/
void make_clsag_multisig_partial_sig(const CLSAGMultisigProposal &proposal,
    const crypto::secret_key &k_e,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_G,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_Hp,
    const crypto::secret_key &local_nonce_1_priv,
    const crypto::secret_key &local_nonce_2_priv,
    CLSAGMultisigPartial &partial_sig_out);
/**
* brief: try_make_clsag_multisig_partial_sig - make a partial signature using a nonce record (nonce safety guarantee)
*   - caller must validate the CLSAG multisig proposal
* param: ...(see make_clsag_multisig_partial_sig())
* param: filter - filter representing the multisig signer group that is supposedly working on this signature
* inoutparam: nonce_record_inout - a record of nonces for makeing partial signatures; used nonces will be cleared
* outparam: partial_sig_out - the partial signature
* return: true if creating the partial signature succeeded
*/
bool try_make_clsag_multisig_partial_sig(const CLSAGMultisigProposal &proposal,
    const crypto::secret_key &k_e,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_G,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_Hp,
    const multisig::signer_set_filter filter,
    MultisigNonceRecord &nonce_record_inout,
    CLSAGMultisigPartial &partial_sig_out);
/**
* brief: finalize_clsag_multisig_proof - create a CLSAG proof from multisig partial signatures
* param: partial_sigs - partial signatures from enough multisig participants to complete a full proof
* param: nominal_proof_Ks - main proof ring member keys used by the proof (for validating the assembled proof)
* param: nominal_pedersen_Cs - main proof ring member keys used by the proof (for validating the assembled proof)
* param: masked_commitment - masked commitment used by the proof (for validating the assembled proof)
* outparam: proof_out - CLSAG
*/
void finalize_clsag_multisig_proof(const std::vector<CLSAGMultisigPartial> &partial_sigs,
    const rct::keyV &nominal_proof_Ks,
    const rct::keyV &nominal_pedersen_Cs,
    const rct::key &masked_commitment,
    rct::clsag &proof_out);

} //namespace sp
