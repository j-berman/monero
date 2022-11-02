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
#include "tx_enote_record_utils.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "jamtis_address_tag_utils.h"
#include "jamtis_address_utils.h"
#include "jamtis_core_utils.h"
#include "jamtis_enote_utils.h"
#include "jamtis_support_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "tx_component_types.h"
#include "tx_enote_record_types.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_view_privkey_g_helper(const crypto::secret_key &s_generate_address,
    const jamtis::address_index_t j,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &enote_view_privkey_g_out)
{
    // enote view privkey: k_mask = H_n("..g..", q, C) + k^j_g
    crypto::secret_key spendkey_extension_g;  //k^j_g
    crypto::secret_key sender_extension_g;    //H_n("..g..", q, C)
    jamtis::make_jamtis_spendkey_extension_g(s_generate_address, j, spendkey_extension_g);
    jamtis::make_jamtis_onetime_address_extension_g(sender_receiver_secret, amount_commitment, sender_extension_g);

    // k^j_g
    enote_view_privkey_g_out = spendkey_extension_g;
    // H_n("..g..", q, C) + k^j_g
    sc_add(to_bytes(enote_view_privkey_g_out), to_bytes(sender_extension_g), to_bytes(enote_view_privkey_g_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_view_privkey_x_helper(const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    const jamtis::address_index_t j,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &enote_view_privkey_x_out)
{
    // enote view privkey: k_a = H_n("..x..", q, C) + k^j_x + k_vb
    crypto::secret_key spendkey_extension_x;  //k^j_x
    crypto::secret_key sender_extension_x;    //H_n("..x..", q, C)
    jamtis::make_jamtis_spendkey_extension_x(s_generate_address, j, spendkey_extension_x);
    jamtis::make_jamtis_onetime_address_extension_x(sender_receiver_secret, amount_commitment, sender_extension_x);

    // k_vb
    enote_view_privkey_x_out = k_view_balance;
    // k^j_x + k_vb
    sc_add(to_bytes(enote_view_privkey_x_out), to_bytes(spendkey_extension_x), to_bytes(enote_view_privkey_x_out));
    // H_n("..x..", q, C) + k^j_x + k_vb
    sc_add(to_bytes(enote_view_privkey_x_out), to_bytes(sender_extension_x), to_bytes(enote_view_privkey_x_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_view_privkey_u_helper(const crypto::secret_key &s_generate_address,
    const jamtis::address_index_t j,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &enote_view_privkey_u_out)
{
    // enote view privkey: k_b_view = H_n("..u..", q, C) + k^j_u
    crypto::secret_key spendkey_extension_u;  //k^j_u
    crypto::secret_key sender_extension_u;    //H_n("..u..", q, C)
    jamtis::make_jamtis_spendkey_extension_u(s_generate_address, j, spendkey_extension_u);
    jamtis::make_jamtis_onetime_address_extension_u(sender_receiver_secret, amount_commitment, sender_extension_u);

    // k^j_u
    enote_view_privkey_u_out = spendkey_extension_u;
    // H_n("..u..", q, C) + k^j_u
    sc_add(to_bytes(enote_view_privkey_u_out), to_bytes(sender_extension_u), to_bytes(enote_view_privkey_u_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_seraphis_key_image_helper(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &enote_view_privkey_x,
    const crypto::secret_key &enote_view_privkey_u,
    crypto::key_image &key_image_out)
{
    // make key image: (k_b_view + k_m)/k_a U
    rct::key spend_pubkey_U_component{jamtis_spend_pubkey};  //k_vb X + k_m U
    reduce_seraphis_spendkey_x(k_view_balance, spend_pubkey_U_component);  //k_m U
    extend_seraphis_spendkey_u(enote_view_privkey_u, spend_pubkey_U_component);  //(k_b_view + k_m) U
    make_seraphis_key_image(enote_view_privkey_x,
        rct::rct2pk(spend_pubkey_U_component),
        key_image_out);  //(k_b_view + k_m)/k_a U
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_basic_record_info_v1_helper(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::x25519_pubkey &derivation,
    jamtis::address_tag_t &nominal_address_tag_out,
    rct::key &nominal_sender_receiver_secret_out)
{
    // q' (jamtis plain variants)
    if (!jamtis::try_get_jamtis_sender_receiver_secret_plain(derivation,
            enote_ephemeral_pubkey,
            input_context,
            enote.m_core.m_onetime_address,
            enote.m_view_tag,
            nominal_sender_receiver_secret_out))
        return false;

    // t'_addr
    nominal_address_tag_out = jamtis::decrypt_address_tag(nominal_sender_receiver_secret_out,
        enote.m_core.m_onetime_address,
        enote.m_addr_tag_enc);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_basic_record_info_v1_helper(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::x25519_secret_key &xk_find_received,
    jamtis::address_tag_t &nominal_address_tag_out,
    rct::key &nominal_sender_receiver_secret_out)
{
    // xK_d = xk_fr * xK_e
    crypto::x25519_pubkey derivation;
    crypto::x25519_scmul_key(xk_find_received, enote_ephemeral_pubkey, derivation);

    return try_get_basic_record_info_v1_helper(enote,
        enote_ephemeral_pubkey,
        input_context,
        derivation,
        nominal_address_tag_out,
        nominal_sender_receiver_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_handle_basic_record_info_v1_helper(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const jamtis::address_tag_t &nominal_address_tag,
    const crypto::x25519_secret_key &xk_find_received,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    jamtis::address_index_t &nominal_address_index_out,
    rct::key &nominal_sender_receiver_secret_out)
{
    // j (fails if mac is 0)
    if (!jamtis::try_decipher_address_index(cipher_context, nominal_address_tag, nominal_address_index_out))
        return false;

    // xK_d = xk_fr * xK_e
    crypto::x25519_pubkey derivation;
    crypto::x25519_scmul_key(xk_find_received, enote_ephemeral_pubkey, derivation);

    // q' (jamtis plain variants)
    return jamtis::try_get_jamtis_sender_receiver_secret_plain(derivation,
        enote_ephemeral_pubkey,
        input_context,
        enote.m_core.m_onetime_address,
        enote.m_view_tag,
        nominal_sender_receiver_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_intermediate_record_info_v1_helper(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const jamtis::address_index_t &nominal_address_index,
    const rct::key &nominal_sender_receiver_secret,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::secret_key &s_generate_address,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // get intermediate info (validate address index, amount, amount blinding factor) for a plain jamtis enote

    // nominal spend key
    rct::key nominal_spendkey;
    jamtis::make_jamtis_nominal_spend_key(nominal_sender_receiver_secret,
        enote.m_core.m_onetime_address,
        enote.m_core.m_amount_commitment,
        nominal_spendkey);

    // check nominal spend key
    if (!jamtis::test_jamtis_nominal_spend_key(jamtis_spend_pubkey,
            s_generate_address,
            nominal_address_index,
            nominal_spendkey))
        return false;

    // make amount commitment baked key
    crypto::x25519_secret_key address_privkey;
    jamtis::make_jamtis_address_privkey(s_generate_address, nominal_address_index, address_privkey);

    crypto::x25519_pubkey amount_baked_key;
    jamtis::make_jamtis_amount_baked_key_plain_recipient(address_privkey,
        xk_unlock_amounts,
        enote_ephemeral_pubkey,
        amount_baked_key);

    // try to recover the amount
    if (!jamtis::try_get_jamtis_amount_plain(nominal_sender_receiver_secret,
            amount_baked_key,
            enote.m_core.m_amount_commitment,
            enote.m_encoded_amount,
            amount_out,
            amount_blinding_factor_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_final_record_info_v1_helper(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const jamtis::address_index_t j,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    crypto::secret_key &enote_view_privkey_g_out,
    crypto::secret_key &enote_view_privkey_x_out,
    crypto::secret_key &enote_view_privkey_u_out,
    crypto::key_image &key_image_out)
{
    // get final info (enote view privkey, key image)

    // construct enote view privkey for G component: k_mask = H_n("..g..", q, C) + k^j_g
    make_enote_view_privkey_g_helper(s_generate_address,
        j,
        sender_receiver_secret,
        amount_commitment,
        enote_view_privkey_g_out);

    // construct enote view privkey for X component: k_a = H_n("..x..", q, C) + k^j_x + k_vb
    make_enote_view_privkey_x_helper(k_view_balance,
        s_generate_address,
        j,
        sender_receiver_secret,
        amount_commitment,
        enote_view_privkey_x_out);

    // construct enote view privkey for U component: k_b_view = H_n("..x..", q, C) + k^j_u
    make_enote_view_privkey_u_helper(s_generate_address,
        j,
        sender_receiver_secret,
        amount_commitment,
        enote_view_privkey_u_out);

    // make key image: (k_b_view + k_m)/k_a U
    make_seraphis_key_image_helper(jamtis_spend_pubkey,
        k_view_balance,
        enote_view_privkey_x_out,
        enote_view_privkey_u_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_intermediate_enote_record_v1_finalize(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const jamtis::address_index_t &nominal_address_index,
    const rct::key &nominal_sender_receiver_secret,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // get intermediate enote record

    // use helper to get remaining info
    if (!try_get_intermediate_record_info_v1_helper(enote,
            enote_ephemeral_pubkey,
            nominal_address_index,
            nominal_sender_receiver_secret,
            jamtis_spend_pubkey,
            xk_unlock_amounts,
            s_generate_address,
            record_out.m_amount,
            record_out.m_amount_blinding_factor))
        return false;

    // copy enote and record sender-receiver secret
    record_out.m_enote = enote;
    record_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.m_input_context = input_context;
    record_out.m_address_index = nominal_address_index;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_enote_record_v1_plain_finalize(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const jamtis::address_index_t &nominal_address_index,
    const rct::key &nominal_sender_receiver_secret,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::secret_key &s_generate_address,
    SpEnoteRecordV1 &record_out)
{
    // get enote record

    // use helper to get remaining info
    if (!try_get_intermediate_record_info_v1_helper(enote,
            enote_ephemeral_pubkey,
            nominal_address_index,
            nominal_sender_receiver_secret,
            jamtis_spend_pubkey,
            xk_unlock_amounts,
            s_generate_address,
            record_out.m_amount,
            record_out.m_amount_blinding_factor))
        return false;

    // use helper to get final info (enote view privkey, key image)
    get_final_record_info_v1_helper(nominal_sender_receiver_secret,
        enote.m_core.m_amount_commitment,
        nominal_address_index,
        jamtis_spend_pubkey,
        k_view_balance,
        s_generate_address,
        record_out.m_enote_view_privkey_g,
        record_out.m_enote_view_privkey_x,
        record_out.m_enote_view_privkey_u,
        record_out.m_key_image);

    // copy enote and set type
    record_out.m_enote = enote;
    record_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.m_input_context = input_context;
    record_out.m_address_index = nominal_address_index;
    record_out.m_type = jamtis::JamtisEnoteType::PLAIN;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_get_basic_enote_record_v1(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::x25519_pubkey &sender_receiver_DH_derivation,
    SpBasicEnoteRecordV1 &basic_record_out)
{
    // get basic record

    // try to decrypt the address tag
    rct::key dummy_q;
    if (!try_get_basic_record_info_v1_helper(enote,
            enote_ephemeral_pubkey,
            input_context,
            sender_receiver_DH_derivation,
            basic_record_out.m_nominal_address_tag,
            dummy_q))
        return false;

    // copy enote
    basic_record_out.m_enote = enote;
    basic_record_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    basic_record_out.m_input_context = input_context;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_basic_enote_record_v1(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::x25519_secret_key &xk_find_received,
    SpBasicEnoteRecordV1 &basic_record_out)
{
    // compute DH derivation then get basic record

    // sender-receiver DH derivation
    crypto::x25519_pubkey derivation;
    crypto::x25519_scmul_key(xk_find_received, enote_ephemeral_pubkey, derivation);

    return try_get_basic_enote_record_v1(enote, enote_ephemeral_pubkey, input_context, derivation, basic_record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // try to process basic info then get intermediate record

    // q' and addr_tag'
    rct::key nominal_sender_receiver_secret;
    jamtis::address_tag_t nominal_address_tag;

    if (!try_get_basic_record_info_v1_helper(enote,
            enote_ephemeral_pubkey,
            input_context,
            xk_find_received,
            nominal_address_tag,
            nominal_sender_receiver_secret))
        return false;

    // j'
    jamtis::address_index_t nominal_address_index;
    if (!jamtis::try_decipher_address_index(cipher_context, nominal_address_tag, nominal_address_index))
        return false;

    return try_get_intermediate_enote_record_v1_finalize(enote,
        enote_ephemeral_pubkey,
        input_context,
        nominal_address_index,
        nominal_sender_receiver_secret,
        jamtis_spend_pubkey,
        xk_unlock_amounts,
        s_generate_address,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // get cipher context then get intermediate record
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{rct::sk2rct(s_cipher_tag)};

    return try_get_intermediate_enote_record_v1(enote,
        enote_ephemeral_pubkey,
        input_context,
        jamtis_spend_pubkey,
        xk_unlock_amounts,
        xk_find_received,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // process basic record then get intermediate enote record
    rct::key nominal_sender_receiver_secret;
    jamtis::address_index_t nominal_address_index;

    if (!try_handle_basic_record_info_v1_helper(basic_record.m_enote,
            basic_record.m_enote_ephemeral_pubkey,
            basic_record.m_input_context,
            basic_record.m_nominal_address_tag,
            xk_find_received,
            cipher_context,
            nominal_address_index,
            nominal_sender_receiver_secret))
        return false;

    return try_get_intermediate_enote_record_v1_finalize(basic_record.m_enote,
        basic_record.m_enote_ephemeral_pubkey,
        basic_record.m_input_context,
        nominal_address_index,
        nominal_sender_receiver_secret,
        jamtis_spend_pubkey,
        xk_unlock_amounts,
        s_generate_address,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // make cipher context then get intermediate enote record
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{rct::sk2rct(s_cipher_tag)};

    return try_get_intermediate_enote_record_v1(basic_record,
        jamtis_spend_pubkey,
        xk_unlock_amounts,
        xk_find_received,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // try to process basic info then get intermediate record
    crypto::x25519_secret_key xk_unlock_amounts;
    crypto::x25519_secret_key xk_find_received;
    crypto::secret_key s_generate_address;
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_unlockamounts_key(k_view_balance, xk_unlock_amounts);
    jamtis::make_jamtis_findreceived_key(k_view_balance, xk_find_received);
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{rct::sk2rct(s_cipher_tag)};

    // q' and addr_tag'
    rct::key nominal_sender_receiver_secret;
    jamtis::address_tag_t nominal_address_tag;
    if (!try_get_basic_record_info_v1_helper(enote,
            enote_ephemeral_pubkey,
            input_context,
            xk_find_received,
            nominal_address_tag,
            nominal_sender_receiver_secret))
        return false;

    // j'
    jamtis::address_index_t nominal_address_index;
    if (!jamtis::try_decipher_address_index(cipher_context, nominal_address_tag, nominal_address_index))
        return false;

    return try_get_enote_record_v1_plain_finalize(enote,
        enote_ephemeral_pubkey,
        input_context,
        nominal_address_index,
        nominal_sender_receiver_secret,
        jamtis_spend_pubkey,
        k_view_balance,
        xk_unlock_amounts,
        s_generate_address,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpEnoteRecordV1 &record_out)
{
    // process basic record then get enote record
    rct::key nominal_sender_receiver_secret;
    jamtis::address_index_t nominal_address_index;

    if (!try_handle_basic_record_info_v1_helper(basic_record.m_enote,
            basic_record.m_enote_ephemeral_pubkey,
            basic_record.m_input_context,
            basic_record.m_nominal_address_tag,
            xk_find_received,
            cipher_context,
            nominal_address_index,
            nominal_sender_receiver_secret))
        return false;

    return try_get_enote_record_v1_plain_finalize(basic_record.m_enote,
        basic_record.m_enote_ephemeral_pubkey,
        basic_record.m_input_context,
        nominal_address_index,
        nominal_sender_receiver_secret,
        jamtis_spend_pubkey,
        k_view_balance,
        xk_unlock_amounts,
        s_generate_address,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // make secrets then get enote record
    crypto::x25519_secret_key xk_unlock_amounts;
    crypto::x25519_secret_key xk_find_received;
    crypto::secret_key s_generate_address;
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_unlockamounts_key(k_view_balance, xk_unlock_amounts);
    jamtis::make_jamtis_findreceived_key(k_view_balance, xk_find_received);
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{rct::sk2rct(s_cipher_tag)};

    return try_get_enote_record_v1_plain(basic_record,
        jamtis_spend_pubkey,
        k_view_balance,
        xk_unlock_amounts,
        xk_find_received,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpIntermediateEnoteRecordV1 &intermediate_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // punt to full getter for enote records
    return try_get_enote_record_v1_plain(intermediate_record.m_enote,
        intermediate_record.m_enote_ephemeral_pubkey,
        intermediate_record.m_input_context,
        jamtis_spend_pubkey,
        k_view_balance,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_selfsend_for_type(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    const jamtis::JamtisSelfSendType expected_type,
    SpEnoteRecordV1 &record_out)
{
    // sender-receiver secret for expected self-send type
    rct::key q;
    jamtis::make_jamtis_sender_receiver_secret_selfsend(k_view_balance,
        enote_ephemeral_pubkey,
        input_context,
        expected_type,
        q);

    // decrypt encrypted address tag
    const jamtis::address_tag_t decrypted_addr_tag{
            decrypt_address_tag(q, enote.m_core.m_onetime_address, enote.m_addr_tag_enc)
        };

    // try to get the address index (includes MAC check)
    if (!try_get_address_index(decrypted_addr_tag, record_out.m_address_index))
        return false;

    // nominal spend key
    rct::key nominal_recipient_spendkey;
    jamtis::make_jamtis_nominal_spend_key(q,
        enote.m_core.m_onetime_address,
        enote.m_core.m_amount_commitment,
        nominal_recipient_spendkey);

    // check nominal spend key
    if (!jamtis::test_jamtis_nominal_spend_key(jamtis_spend_pubkey,
            s_generate_address,
            record_out.m_address_index,
            nominal_recipient_spendkey))
        return false;

    // try to recover the amount
    if (!jamtis::try_get_jamtis_amount_selfsend(q,
            enote.m_core.m_amount_commitment,
            enote.m_encoded_amount,
            record_out.m_amount,
            record_out.m_amount_blinding_factor))
        return false;

    // construct enote view privkey for G: k_mask = H_n("..g..", q, C) + k^j_g
    make_enote_view_privkey_g_helper(s_generate_address,
        record_out.m_address_index,
        q,
        enote.m_core.m_amount_commitment,
        record_out.m_enote_view_privkey_g);

    // construct enote view privkey for X: k_a = H_n("..x..", q, C) + k^j_x + k_vb
    make_enote_view_privkey_x_helper(k_view_balance,
        s_generate_address,
        record_out.m_address_index,
        q,
        enote.m_core.m_amount_commitment,
        record_out.m_enote_view_privkey_x);

    // construct enote view privkey for U: k_b_view = H_n("..u..", q, C) + k^j_u
    make_enote_view_privkey_u_helper(s_generate_address,
        record_out.m_address_index,
        q,
        enote.m_core.m_amount_commitment,
        record_out.m_enote_view_privkey_u);

    // make key image: (k_b_view + k_m)/k_a U
    make_seraphis_key_image_helper(jamtis_spend_pubkey,
        k_view_balance,
        record_out.m_enote_view_privkey_x,
        record_out.m_enote_view_privkey_u,
        record_out.m_key_image);

    // copy enote and set type
    record_out.m_enote = enote;
    record_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.m_input_context = input_context;
    CHECK_AND_ASSERT_THROW_MES(jamtis::try_get_jamtis_enote_type(expected_type, record_out.m_type),
        "getting self-send enote record: could not convert expected self-send type to enote type (bug).");

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_selfsend(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    SpEnoteRecordV1 &record_out)
{
    // try to get an enote record with all the self-send types
    for (unsigned char self_send_type{0};
        self_send_type <= static_cast<unsigned char>(jamtis::JamtisSelfSendType::MAX);
        ++self_send_type)
    {
        if (try_get_enote_record_v1_selfsend_for_type(enote,
            enote_ephemeral_pubkey,
            input_context,
            jamtis_spend_pubkey,
            k_view_balance,
            s_generate_address,
            static_cast<jamtis::JamtisSelfSendType>(self_send_type),
            record_out))
        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_selfsend(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // make generate-address secret then get enote record
    crypto::secret_key s_generate_address;
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);

    return try_get_enote_record_v1_selfsend(enote,
        enote_ephemeral_pubkey,
        input_context,
        jamtis_spend_pubkey,
        k_view_balance,
        s_generate_address,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // note: check for selfsend first since it is more efficient
    //       (assumes selfsends and plain enotes appear in similar quantities)
    return try_get_enote_record_v1_selfsend(enote,
            enote_ephemeral_pubkey,
            input_context,
            jamtis_spend_pubkey,
            k_view_balance,
            record_out) ||
        try_get_enote_record_v1_plain(enote,
            enote_ephemeral_pubkey,
            input_context,
            jamtis_spend_pubkey,
            k_view_balance,
            record_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp