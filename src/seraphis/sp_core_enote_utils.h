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

// Seraphis core enote and enote image component builders.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations
namespace sp { struct SpEnote; }

namespace sp
{

/**
* brief: make_seraphis_key_image - create a Seraphis key image from 'y' and spend key base 'zU'
*   KI = (1/y) * z U
* param: y - private key 'y' (e.g. created from private view key secrets)
* param: zU - pubkey z U (e.g. the base spend key 'ks U')
* outparam: key_image_out - KI
*/
void make_seraphis_key_image(const crypto::secret_key &y, const crypto::public_key &zU, crypto::key_image &key_image_out);
/**
* brief: make_seraphis_key_image - create a Seraphis key image from private keys 'y' and 'z'
*   KI = (z/y)*U
*      = (k_{b, recipient} / (k_{a, sender} + k_{a, recipient}))*U
* param: y - private key '(k_{a, sender} + k_{a, recipient}))' (e.g. created from private view key secrets)
* param: z - private key 'k_{b, recipient}' (e.g. the private spend key 'ks')
* outparam: key_image_out - KI
*/
void make_seraphis_key_image(const crypto::secret_key &y, const crypto::secret_key &z, crypto::key_image &key_image_out);
/**
* brief: make_seraphis_key_image - create a Seraphis key image from sender/recipient pieces
*   KI = (k_{b. recipient} / (k_{a, sender} + k_{a, recipient})) * U
* param: k_a_sender - private key derived from sender (e.g. created from sender-recipient secret q_t)
* param: k_a_recipient - private key provided by recipient (e.g. based on the private view key)
* param: k_bU - recipient's spendbase pubkey (k_{b, recipient} * U)
* outparam: key_image_out - KI
*/
void make_seraphis_key_image(const crypto::secret_key &k_a_sender,
    const crypto::secret_key &k_a_recipient,
    const crypto::public_key &k_bU,
    crypto::key_image &key_image_out);
/**
* brief: make_seraphis_spendbase - create the base part of a Seraphis spendkey
*   spendbase = k_{b, recipient} U
* param: sp_spend_privkey - k_{b, recipient}
* outparam: spendbase_pubkey_out - k_{b, recipient} U
*/
void make_seraphis_spendbase(const crypto::secret_key &sp_spend_privkey, rct::key &spendbase_pubkey_out);
/**
* brief: extend_seraphis_spendkey_x - extend a Seraphis spendkey (or onetime address) on generator X
*   K = k_extender_x X + K_original
* param: k_extender_x - extends the existing pubkey
* inoutparam: spendkey_inout - [in: K_original] [out: k_extender_x X + K_original]
*/
void extend_seraphis_spendkey_x(const crypto::secret_key &k_extender_x, rct::key &spendkey_inout);
/**
* brief: extend_seraphis_spendkey_u - extend a Seraphis spendkey (or onetime address) on generator U
*   K = k_extender_u U + K_original
* param: k_extender_u - extends the existing pubkey
* inoutparam: spendkey_inout - [in: K_original] [out: k_extender_u U + K_original]
*/
void extend_seraphis_spendkey_u(const crypto::secret_key &k_extender_u, rct::key &spendkey_inout);
/**
* brief: reduce_seraphis_spendkey_g - remove private key material from a Seraphis spendkey (or onetime address) on generator G
*   K = K_original - k_reducer_g G
* param: k_reducer_g - material to remove from the existing pubkey
* inoutparam: spendkey_inout - [in: K_original] [out: K_original - k_reducer_g G]
*/
void reduce_seraphis_spendkey_g(const crypto::secret_key &k_reducer_g, rct::key &spendkey_inout);
/**
* brief: reduce_seraphis_spendkey_x - remove private key material from a Seraphis spendkey (or onetime address) on generator X
*   K = K_original - k_reducer_x X
* param: k_reducer_x - material to remove from the existing pubkey
* inoutparam: spendkey_inout - [in: K_original] [out: K_original - k_reducer_x X]
*/
void reduce_seraphis_spendkey_x(const crypto::secret_key &k_reducer_x, rct::key &spendkey_inout);
/**
* brief: reduce_seraphis_spendkey_u - remove private key material from a Seraphis spendkey (or onetime address) on generator U
*   K = K_original - k_reducer_u U
* param: k_reducer_u - material to remove from the existing pubkey
* inoutparam: spendkey_inout - [in: K_original] [out: K_original - k_reducer_u U]
*/
void reduce_seraphis_spendkey_u(const crypto::secret_key &k_reducer_u, rct::key &spendkey_inout);
/**
* brief: make_seraphis_spendkey - create a Seraphis spendkey (or onetime address)
*   K = k_a X + k_b U
* param: view_privkey - k_a
* param: sp_spend_privkey - k_b
* outparam: spendkey_out - k_a X + k_b U
*/
void make_seraphis_spendkey(const crypto::secret_key &k_a, const crypto::secret_key &k_b, rct::key &spendkey_out);
/**
* brief: make_seraphis_squash_prefix - make the prefix for squashing an enote in the squashed enote model
*   H_n(Ko,C)
* param: onetime_address - Ko
* param: amount_commitment - C
* outparam: squash_prefix_out - H_n(Ko,C)
*/
void make_seraphis_squash_prefix(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    rct::key &squash_prefix_out);
/**
* brief: make_seraphis_squashed_address_key - make a 'squashed' address in the squashed enote model
*   Ko^t = H_n(Ko,C) Ko
* param: onetime_address - Ko
* param: amount_commitment - C
* outparam: squashed_address_out - H_n(Ko,C) Ko
*/
void make_seraphis_squashed_address_key(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    rct::key &squashed_address_out);
/**
* brief: make_seraphis_squashed_enote_Q - make a 'squashed' enote in the squashed enote model
*   Q = Ko^t + C^t = H_n(Ko,C) Ko + C
* param: onetime_address - Ko
* param: amount_commitment - C
* outparam: Q_out - Q
*/
void make_seraphis_squashed_enote_Q(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    rct::key &Q_out);
/**
* brief: make_seraphis_enote_core - make a Seraphis enote from a pre-made onetime address
* param: onetime_address -
* param: amount_blinding_factor -
* param: amount -
* outparam: enote_core_out -
*/
void make_seraphis_enote_core(const rct::key &onetime_address,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount,
    SpEnote &enote_core_out);
/**
* brief: make_seraphis_enote_core - make a Seraphis enote by extending an existing address
* param: extension_privkey_g -
* param: extension_privkey_x -
* param: extension_privkey_u -
* param: initial_address -
* param: amount_blinding_factor -
* param: amount -
* outparam: enote_core_out -
*/
void make_seraphis_enote_core(const crypto::secret_key &extension_privkey_g,
    const crypto::secret_key &extension_privkey_x,
    const crypto::secret_key &extension_privkey_u,
    const rct::key &initial_address,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount,
    SpEnote &enote_core_out);
/**
* brief: make_seraphis_enote_core - make a Seraphis enote when all secrets are known
* param: enote_view_privkey_g -
* param: enote_view_privkey_x -
* param: enote_view_privkey_u -
* param: sp_spend_privkey -
* param: amount_blinding_factor -
* param: amount -
* outparam: enote_core_out -
*/
void make_seraphis_enote_core(const crypto::secret_key &enote_view_privkey_g,
    const crypto::secret_key &enote_view_privkey_x,
    const crypto::secret_key &enote_view_privkey_u,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount,
    SpEnote &enote_core_out);
/**
* brief: make_seraphis_enote_image_masked_keys - make the masked keys for a seraphis enote image
* param: onetime_address -
* param: amount_commitment -
* param: address_mask -
* param: commitment_mask -
* outparam: masked_address_out -
* outparam: masked_commitment_out -
*/
void make_seraphis_enote_image_masked_keys(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    rct::key &masked_address_out,
    rct::key &masked_commitment_out);

} //namespace sp
