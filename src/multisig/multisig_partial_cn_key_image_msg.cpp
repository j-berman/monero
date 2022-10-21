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

#include "multisig_partial_cn_key_image_msg.h"
#include "multisig_msg_serialization.h"

#include "common/base58.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "dual_base_vector_proof.h"
#include "include_base_utils.h"
#include "ringct/rctOps.h"
#include "serialization/binary_archive.h"
#include "serialization/serialization.h"

#include <boost/utility/string_ref.hpp>

#include <sstream>
#include <string>
#include <utility>
#include <vector>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

const boost::string_ref MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1{"MultisigPartialCNKIV1"};

namespace multisig
{
  //----------------------------------------------------------------------------------------------------------------------
  // INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  static void set_msg_magic(std::string &msg_out)
  {
    msg_out.clear();
    msg_out.append(MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1.data(), MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1.size());
  }
  //----------------------------------------------------------------------------------------------------------------------
  // INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  static bool try_get_message_no_magic(const std::string &original_msg,
    const boost::string_ref magic,
    std::string &msg_no_magic_out)
  {
    // abort if magic doesn't match the message
    if (original_msg.substr(0, magic.size()) != magic)
      return false;

    // decode message
    CHECK_AND_ASSERT_THROW_MES(tools::base58::decode(original_msg.substr(magic.size()), msg_no_magic_out),
      "Multisig cn key image msg decoding error.");

    return true;
  }
  //----------------------------------------------------------------------------------------------------------------------
  // INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  static void get_dualbase_proof_msg(const boost::string_ref magic,
    const crypto::public_key &signing_pubkey,
    const crypto::public_key &onetime_address,
    rct::key &proof_msg_out)
  {
    // proof_msg = versioning-domain-sep || signing_pubkey || onetime_address
    std::string data;
    data.reserve(magic.size() + 2*sizeof(crypto::public_key));

    // magic
    data.append(magic.data(), magic.size());

    // signing pubkey
    data.append(reinterpret_cast<const char *>(&signing_pubkey), sizeof(crypto::public_key));

    // onetime address
    data.append(reinterpret_cast<const char *>(&onetime_address), sizeof(crypto::public_key));

    rct::cn_fast_hash(proof_msg_out, data.data(), data.size());
  }
  //----------------------------------------------------------------------------------------------------------------------
  // INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  static crypto::hash get_signature_msg(const crypto::public_key &onetime_address,
    const crypto::DualBaseVectorProof &dualbase_proof)
  {
    // signature_msg = Ko || dualbase_proof_challenge || dualbase_proof_response
    std::string data;
    data.reserve(3*sizeof(crypto::public_key));
    data.append(reinterpret_cast<const char *>(&onetime_address), sizeof(crypto::public_key));
    data.append(reinterpret_cast<const char *>(&dualbase_proof.c), sizeof(rct::key));
    data.append(reinterpret_cast<const char *>(&dualbase_proof.r), sizeof(rct::key));

    return crypto::cn_fast_hash(data.data(), data.size());
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_partial_cn_key_image_msg: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  multisig_partial_cn_key_image_msg::multisig_partial_cn_key_image_msg(const crypto::secret_key &signing_privkey,
    const crypto::public_key &onetime_address,
    const std::vector<crypto::secret_key> &keyshare_privkeys) :
      m_onetime_address{onetime_address}
  {
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(signing_privkey)) == 0 && signing_privkey != crypto::null_skey,
      "Invalid msg signing key.");
    CHECK_AND_ASSERT_THROW_MES(!(rct::pk2rct(onetime_address) == rct::Z), "Empty onetime address in msig cn ki msg.");
    CHECK_AND_ASSERT_THROW_MES(keyshare_privkeys.size() > 0, "Can't make cn key image message with no keys to convert.");

    // save signing pubkey
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(signing_privkey, m_signing_pubkey),
      "Failed to derive public key");

    // prepare key image base key
    crypto::key_image key_image_base;
    crypto::generate_key_image(m_onetime_address, rct::rct2sk(rct::I), key_image_base);

    // make dual base vector proof
    rct::key proof_msg;
    get_dualbase_proof_msg(MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1, m_signing_pubkey, m_onetime_address, proof_msg);
    const crypto::DualBaseVectorProof proof{
        crypto::dual_base_vector_prove(proof_msg, crypto::get_G(),
          rct::rct2pk(rct::ki2rct(key_image_base)),
          keyshare_privkeys)
      };

    // sets message and signing pub key
    this->construct_msg(signing_privkey, proof);

    // set keyshares
    m_multisig_keyshares = std::move(proof.V_1);
    m_partial_key_images = std::move(proof.V_2);
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_partial_cn_key_image_msg: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  multisig_partial_cn_key_image_msg::multisig_partial_cn_key_image_msg(std::string msg) : m_msg{std::move(msg)}
  {
    this->parse_and_validate_msg();
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_partial_cn_key_image_msg: INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  void multisig_partial_cn_key_image_msg::construct_msg(const crypto::secret_key &signing_privkey,
    const crypto::DualBaseVectorProof &dualbase_proof)
  {
    ////
    // dualbase_proof_msg = domain-sep || signing_pubkey || Ko
    //
    // msg = versioning-domain-sep ||
    //       b58(signing_pubkey || Ko || {multisig_keyshares} || {partial_KI} || dualbase_proof_challenge ||
    //           dualbase_proof_response ||
    //           crypto_sig[signing_privkey](Ko || dualbase_proof_challenge || dualbase_proof_response))
    ///

    // sign the message
    crypto::signature msg_signature;
    crypto::generate_signature(get_signature_msg(m_onetime_address, dualbase_proof),
      m_signing_pubkey,
      signing_privkey,
      msg_signature);

    // mangle the dualbase proof into a crypto::signature
    const crypto::signature mangled_dualbase_proof{rct::rct2sk(dualbase_proof.c), rct::rct2sk(dualbase_proof.r)};

    // prepare the message
    std::stringstream serialized_msg_ss;
    binary_archive<true> b_archive(serialized_msg_ss);

    multisig_partial_cn_ki_msg_serializable msg_serializable;
    msg_serializable.onetime_address    = m_onetime_address;
    msg_serializable.multisig_keyshares = dualbase_proof.V_1;
    msg_serializable.partial_key_images = dualbase_proof.V_2;
    msg_serializable.signing_pubkey     = m_signing_pubkey;
    msg_serializable.dual_base_vector_proof_partial = mangled_dualbase_proof;
    msg_serializable.signature          = msg_signature;

    CHECK_AND_ASSERT_THROW_MES(::serialization::serialize(b_archive, msg_serializable),
      "Failed to serialize multisig cn key image msg.");

    // make the message
    set_msg_magic(m_msg);
    m_msg.append(tools::base58::encode(serialized_msg_ss.str()));
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_partial_cn_key_image_msg: INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  void multisig_partial_cn_key_image_msg::parse_and_validate_msg()
  {
    // early return on empty messages
    if (m_msg == "")
      return;

    // deserialize the message
    std::string msg_no_magic;
    CHECK_AND_ASSERT_THROW_MES(try_get_message_no_magic(m_msg, MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1, msg_no_magic),
      "Could not remove magic from cn key image message.");

    binary_archive<false> archived_msg{epee::strspan<std::uint8_t>(msg_no_magic)};

    // extract data from the message
    crypto::DualBaseVectorProof dualbase_proof;
    crypto::signature msg_signature;

    multisig_partial_cn_ki_msg_serializable deserialized_msg;
    if (::serialization::serialize(archived_msg, deserialized_msg))
    {
      m_onetime_address  = deserialized_msg.onetime_address;
      dualbase_proof.V_1 = std::move(deserialized_msg.multisig_keyshares);
      dualbase_proof.V_2 = std::move(deserialized_msg.partial_key_images);
      m_signing_pubkey   = deserialized_msg.signing_pubkey;
      memcpy(dualbase_proof.c.bytes, to_bytes(deserialized_msg.dual_base_vector_proof_partial.c), sizeof(crypto::ec_scalar));
      memcpy(dualbase_proof.r.bytes, to_bytes(deserialized_msg.dual_base_vector_proof_partial.r), sizeof(crypto::ec_scalar));
      msg_signature      = deserialized_msg.signature;
    }
    else CHECK_AND_ASSERT_THROW_MES(false, "Deserializing cn key image msg failed.");

    // checks
    CHECK_AND_ASSERT_THROW_MES(!(rct::pk2rct(m_onetime_address) == rct::Z), "cn key image msg onetime address is null.");
    CHECK_AND_ASSERT_THROW_MES(dualbase_proof.V_1.size() > 0, "cn key image message has no keyshares.");
    CHECK_AND_ASSERT_THROW_MES(dualbase_proof.V_1.size() == dualbase_proof.V_2.size(),
      "cn key image message key vectors don't line up.");
    CHECK_AND_ASSERT_THROW_MES(m_signing_pubkey != crypto::null_pkey && m_signing_pubkey != rct::rct2pk(rct::identity()),
      "Message signing key was invalid.");
    CHECK_AND_ASSERT_THROW_MES(rct::isInMainSubgroup(rct::pk2rct(m_signing_pubkey)),
      "Message signing key was not in prime subgroup.");

    // prepare key image base key
    crypto::key_image key_image_base;
    crypto::generate_key_image(m_onetime_address, rct::rct2sk(rct::I), key_image_base);

    // validate dualbase proof
    get_dualbase_proof_msg(MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1, m_signing_pubkey, m_onetime_address, dualbase_proof.m);
    CHECK_AND_ASSERT_THROW_MES(crypto::dual_base_vector_verify(dualbase_proof,
        crypto::get_G(),
        rct::rct2pk(rct::ki2rct(key_image_base))),
      "cn key image message dualbase proof invalid.");

    // validate signature
    CHECK_AND_ASSERT_THROW_MES(crypto::check_signature(get_signature_msg(m_onetime_address, dualbase_proof),
        m_signing_pubkey,
        msg_signature),
      "Multisig cn key image msg signature invalid.");

    // save keyshares (note: saving these after checking the signature ensures if the signature is invalid then the 
    //   message's internal state won't be usable even if the invalid-signature exception is caught)
    m_multisig_keyshares = std::move(dualbase_proof.V_1);
    m_partial_key_images = std::move(dualbase_proof.V_2);
  }
  //----------------------------------------------------------------------------------------------------------------------
} //namespace multisig
