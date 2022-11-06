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

//paired header
#include "jamtis_address_utils.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
#include "jamtis_address_tag_utils.h"
#include "jamtis_core_utils.h"
#include "jamtis_support_types.h"
#include "ringct/rctOps.h"
#include "sp_core_enote_utils.h"
#include "sp_hash_functions.h"
#include "sp_crypto_utils.h"
#include "sp_transcript.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_spendkey_extension_g(const crypto::secret_key &s_generate_address,
    const address_index_t j,
    crypto::secret_key &extension_out)
{
    // k^j_g = H_n[s_ga](j)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SPENDKEY_EXTENSION_G, ADDRESS_INDEX_BYTES};
    transcript.append("j", j.bytes);

    sp_derive_key(to_bytes(s_generate_address), transcript, to_bytes(extension_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_spendkey_extension_x(const crypto::secret_key &s_generate_address,
    const address_index_t j,
    crypto::secret_key &extension_out)
{
    // k^j_x = H_n[s_ga](j)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SPENDKEY_EXTENSION_X, ADDRESS_INDEX_BYTES};
    transcript.append("j", j.bytes);

    sp_derive_key(to_bytes(s_generate_address), transcript, to_bytes(extension_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_spendkey_extension_u(const crypto::secret_key &s_generate_address,
    const address_index_t j,
    crypto::secret_key &extension_out)
{
    // k^j_u = H_n[s_ga](j)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SPENDKEY_EXTENSION_U, ADDRESS_INDEX_BYTES};
    transcript.append("j", j.bytes);

    sp_derive_key(to_bytes(s_generate_address), transcript, to_bytes(extension_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_address_privkey(const crypto::secret_key &s_generate_address,
    const address_index_t j,
    crypto::x25519_secret_key &address_privkey_out)
{
    // xk^j_a = H_n_x25519[s_ga](j)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_ADDRESS_PRIVKEY, ADDRESS_INDEX_BYTES};
    transcript.append("j", j.bytes);

    sp_derive_x25519_key(to_bytes(s_generate_address), transcript, address_privkey_out.data);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_address_spend_key(const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t j,
    rct::key &address_spendkey_out)
{
    // K_1 = k^j_g G + k^j_x X + k^j_u U + K_s
    crypto::secret_key address_extension_key_u;
    crypto::secret_key address_extension_key_x;
    crypto::secret_key address_extension_key_g;
    make_jamtis_spendkey_extension_u(s_generate_address, j, address_extension_key_u);  //k^j_u
    make_jamtis_spendkey_extension_x(s_generate_address, j, address_extension_key_x);  //k^j_x
    make_jamtis_spendkey_extension_g(s_generate_address, j, address_extension_key_g);  //k^j_g

    address_spendkey_out = spend_pubkey;  //K_s
    extend_seraphis_spendkey_u(address_extension_key_u, address_spendkey_out);      //k^j_u U + K_s
    extend_seraphis_spendkey_x(address_extension_key_x, address_spendkey_out);      //k^j_x X + k^j_u U + K_s
    mask_key(address_extension_key_g, address_spendkey_out, address_spendkey_out);  //k^j_g G + k^j_x X + k^j_u U + K_s
}
//-------------------------------------------------------------------------------------------------------------------
bool test_jamtis_nominal_spend_key(const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t j,
    const rct::key &nominal_spend_key)
{
    // get the spend key of the address at the uncovered index: K_1
    rct::key address_spendkey;
    make_jamtis_address_spend_key(spend_pubkey, s_generate_address, j, address_spendkey);

    // check if the nominal spend key matches the real spend key: K'_1 ?= K_1
    return nominal_spend_key == address_spendkey;
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_key_image_jamtis_style(const rct::key &spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &spendkey_extension_x,
    const crypto::secret_key &spendkey_extension_u,
    const crypto::secret_key &sender_extension_x,
    const crypto::secret_key &sender_extension_u,
    crypto::key_image &key_image_out)
{
    // KI = ((H_n("..u..", q, C) + k^j_u + k_m)/(H_n("..x..", q, C) + k^j_x + k_vb)) U

    // k_m U = K_s - k_vb X
    rct::key master_pubkey{spend_pubkey};  //K_s = k_vb X + k_m U
    reduce_seraphis_spendkey_x(k_view_balance, master_pubkey);  //k_m U

    // k_b U = H_n("..u..", q, C) U + k^j_u U + k_m U
    extend_seraphis_spendkey_u(spendkey_extension_u, master_pubkey);  //k^j_u U + k_m U
    extend_seraphis_spendkey_u(sender_extension_u, master_pubkey);  //H_n("..u..", q, C) U + k^j_u U + k_m U

    // k_a_recipient = k^j_x + k_vb
    crypto::secret_key k_a_recipient;
    sc_add(to_bytes(k_a_recipient), to_bytes(spendkey_extension_x), to_bytes(k_view_balance));  //k^j_x + k_vb

    // k_a_sender = H_n("..x..", q, C)
    // KI = (1/(k_a_sender + k_a_recipient))*k_b*U
    make_seraphis_key_image(sender_extension_x, k_a_recipient, rct::rct2pk(master_pubkey), key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
