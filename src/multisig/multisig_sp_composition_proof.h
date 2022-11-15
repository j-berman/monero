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

////
// Multisig utilities for the seraphis composition proof.
//
// multisig notation: alpha_{a,n,e}
// - a: indicates which part of the proof this is for
// - n: for MuSig2-style bi-nonce signing, alpha_{b,1,e} is nonce 'D', alpha_{b,2,e} is nonce 'E' (in their notation)
// - e: multisig signer index
//
// Multisig references:
// - MuSig2 (Nick): https://eprint.iacr.org/2020/1261
// - FROST (Komlo): https://eprint.iacr.org/2020/852
// - Multisig/threshold security (Crites): https://eprint.iacr.org/2021/1375
///


#pragma once

//local headers
#include "crypto/crypto.h"
#include "multisig_nonce_record.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_composition_proof.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace multisig
{

////
// Multisig signature proposal for seraphis composition proofs
//
// WARNING: must only use a 'proposal' to make ONE 'signature' (or signature attempt),
//          after that the opening privkeys should be deleted immediately
///
struct SpCompositionProofMultisigProposal final
{
    // message
    rct::key message;
    // main proof key K
    rct::key K;
    // key image KI
    crypto::key_image KI;

    // signature nonce (shared component): alpha_t1
    crypto::secret_key signature_nonce_K_t1;
    // signature nonce (shared component): alpha_t2
    crypto::secret_key signature_nonce_K_t2;
};

////
// Multisig partially signed composition proof (from one multisig participant)
// - multisig assumes only proof component KI is subject to multisig signing (key z is split between signers)
// - store signature opening for KI component (response r_ki)
///
struct SpCompositionProofMultisigPartial final
{
    // message
    rct::key message;
    // main proof key K
    rct::key K;
    // key image KI
    crypto::key_image KI;

    // challenge
    rct::key c;
    // responses r_t1, r_t2
    rct::key r_t1, r_t2;
    // intermediate proof key K_t1
    rct::key K_t1;

    // partial response for r_ki (from one multisig participant)
    rct::key r_ki_partial;
};

//todo: place challenge and response calculations in a detail namespace so multisig stuff can be moved to a separate
//      file without duplication

/**
* brief: make_sp_composition_multisig_proposal - propose to make a multisig Seraphis composition proof
* param: message - message to insert in the proof's Fiat-Shamir transform hash
* param: K - main proof key
* param: KI - key image
* outparam: proposal_out - Seraphis composition proof multisig proposal
*/
void make_sp_composition_multisig_proposal(const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI,
    SpCompositionProofMultisigProposal &proposal_out);
/**
* brief: make_sp_composition_multisig_partial_sig - make local multisig signer's partial signature for a Seraphis composition
*        proof
*   - caller must validate the multisig proposal
*       - is the key image well-made?
*       - is the main key legitimate?
*       - is the message correct?
* param: proposal - proof proposal to construct proof partial signature from
* param: x - secret key
* param: y - secret key
* param: z_e - secret key of multisig signer e
* param: signer_pub_nonces - signature nonce pubkeys (1/8) * {alpha_{ki,1,e}*U,  alpha_{ki,2,e}*U} from all signers
*                            (including local signer)
* param: local_nonce_1_priv - alpha_{ki,1,e} for local signer
* param: local_nonce_2_priv - alpha_{ki,2,e} for local signer
* outparam: partial_sig_out - partially signed Seraphis composition proof
*/
void make_sp_composition_multisig_partial_sig(const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces,
    const crypto::secret_key &local_nonce_1_priv,
    const crypto::secret_key &local_nonce_2_priv,
    SpCompositionProofMultisigPartial &partial_sig_out);
/**
* brief: try_make_sp_composition_multisig_partial_sig - make a partial signature using a nonce record (nonce safety guarantee)
*   - caller must validate the multisig proposal
* param: ...(see make_sp_composition_multisig_partial_sig())
* param: filter - filter representing the multisig signer group that is supposedly working on this signature
* inoutparam: nonce_record_inout - a record of nonces for makeing partial signatures; used nonces will be cleared
* outparam: partial_sig_out - the partial signature
* return: true if creating the partial signature succeeded
*/
bool try_make_sp_composition_multisig_partial_sig(const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces,
    const signer_set_filter filter,
    MultisigNonceRecord &nonce_record_inout,
    SpCompositionProofMultisigPartial &partial_sig_out);
/**
* brief: finalize_sp_composition_multisig_proof - create a Seraphis composition proof from multisig partial signatures
* param: partial_sigs - partial signatures from enough multisig participants to complete a full proof
* outparam: proof_out - Seraphis composition proof
*/
void finalize_sp_composition_multisig_proof(const std::vector<SpCompositionProofMultisigPartial> &partial_sigs,
    sp::SpCompositionProof &proof_out);

} //namespace multisig
