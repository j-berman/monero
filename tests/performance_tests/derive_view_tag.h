// Copyright (c) 2014-2021, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
extern "C"
{
#include "crypto/siphash.h" // https://github.com/veorq/SipHash
#include "blake2.h"         // copied from randomx lib
#include "crypto/blake3.h"  // https://github.com/BLAKE3-team/BLAKE3/tree/master/c
}

#include "single_tx_test_base.h"

const int KECCAK = 0;
const int SIPHASH_2_4 = 1;
const int BLAKE2 = 2;
const int BLAKE3 = 3;

template<int test_ver>
class test_derive_view_tag : public single_tx_test_base
{
public:
  static const size_t loop_count = 100;
  static const size_t inner_loop_count = 10000;

  bool init()
  {
    if (!single_tx_test_base::init())
      return false;

    switch (test_ver)
    {
      case KECCAK:
      {
        printf("Keccak...\n");
        break;
      }
      case SIPHASH_2_4:
      {
        printf("\n\nSipHash 2-4...\n");
        break;
      }
      case BLAKE2:
      {
        printf("\n\nBlake2...\n");
        break;
      }
      case BLAKE3:
      {
        printf("\n\nBlake3...\n");
        break;
      }
      default:
        return false;
    }

    for (size_t i = 0; i < inner_loop_count; ++i)
    {
      cryptonote::account_base acc;
      acc.generate();
      crypto::key_derivation kd;
      crypto::generate_key_derivation(m_tx_pub_key, acc.get_keys().m_view_secret_key, kd);
      m_key_derivations.push_back(kd);
    }

    return true;
  }

  bool test()
  {
    switch (test_ver)
    {
      case KECCAK:
      {
        for (size_t i = 0; i < inner_loop_count; ++i)
        {
          crypto::view_tag view_tag;
          crypto::derive_view_tag(m_key_derivations[i], m_output_index, view_tag);
        }
        break;
      }
      case SIPHASH_2_4:
      {

        for (size_t i = 0; i < inner_loop_count; ++i)
        {
          struct {
            char salt[8]; // view tag domain-separator
            char output_index[(sizeof(size_t) * 8 + 6) / 7];
          } buf;

          memcpy(buf.salt, "view_tag", 8); // leave off null terminator
          char *end = buf.output_index;

          tools::write_varint(end, m_output_index);
          assert(end <= buf.output_index + sizeof buf.output_index);

          char siphash_key[16];
          memcpy(&siphash_key, &m_key_derivations[i], 16);

          // view_tag_full = H[siphash_key](salt, output_index)
          unsigned char view_tag_full[8];
          siphash(&buf, end - reinterpret_cast<char *>(&buf), siphash_key, view_tag_full, 8); // siphash result will be 8 bytes

          memwipe(siphash_key, 16);

          // only need a slice of view_tag_full to realize optimal perf/space efficiency
          crypto::view_tag view_tag;
          memcpy(&view_tag, &view_tag_full, sizeof(crypto::view_tag));
        }

        break;
      }
      case BLAKE2:
      {

        for (size_t i = 0; i < inner_loop_count; ++i)
        {
          struct {
            char salt[8]; // view tag domain-separator
            crypto::key_derivation derivation;
            char output_index[(sizeof(size_t) * 8 + 6) / 7];
          } buf;

          char *end = buf.output_index;
          memcpy(buf.salt, "view_tag", 8); // leave off null terminator
          buf.derivation = m_key_derivations[i];
          tools::write_varint(end, m_output_index);
          assert(end <= buf.output_index + sizeof buf.output_index);

          // view_tag_full = H[salt|derivation|output_index]
          crypto::hash view_tag_full;
          blake2b(&view_tag_full, 32, &buf, end - reinterpret_cast<char *>(&buf), nullptr, 0);

          // only need a slice of view_tag_full to realize optimal perf/space efficiency
          crypto::view_tag view_tag;
          memcpy(&view_tag, &view_tag_full, sizeof(crypto::view_tag));
        }

        break;
      }
      case BLAKE3:
      {

        for (size_t i = 0; i < inner_loop_count; ++i)
        {
          struct {
            char salt[8]; // view tag domain-separator
            crypto::key_derivation derivation;
            char output_index[(sizeof(size_t) * 8 + 6) / 7];
          } buf;

          char *end = buf.output_index;
          memcpy(buf.salt, "view_tag", 8); // leave off null terminator
          buf.derivation = m_key_derivations[i];
          tools::write_varint(end, m_output_index);
          assert(end <= buf.output_index + sizeof buf.output_index);

          // view_tag_full = H[salt|derivation|output_index]
          blake3_hasher hasher;
          blake3_hasher_init(&hasher);
          blake3_hasher_update(&hasher, &buf, end - reinterpret_cast<char *>(&buf));

          uint8_t view_tag_full[32];
          blake3_hasher_finalize(&hasher, view_tag_full, 32);

          // only need a slice of view_tag_full to realize optimal perf/space efficiency
          crypto::view_tag view_tag;
          memcpy(&view_tag, &view_tag_full, sizeof(crypto::view_tag));
        }

        break;
      }
      default:
        return false;
    }


    return true;
  }

private:
  std::vector<crypto::key_derivation> m_key_derivations;
  size_t m_output_index{0};
};

/*

Core i7-10510U 1.80 GHz - 32gb RAM - Ubuntu 20.04

Keccak...
test_derive_view_tag<0> (100 calls) - OK: 10410 µs/call (min 9498 µs, 90th 10675 µs, median 10362 µs, std dev 164 µs)


SipHash 2-4...
test_derive_view_tag<1> (100 calls) - OK: 200 µs/call (min 174 µs, 90th 211 µs, median 205 µs, std dev 11 µs)


Blake2...
test_derive_view_tag<2> (100 calls) - OK: 2230 µs/call (min 1909 µs, 90th 2262 µs, median 2254 µs, std dev 50 µs)


Blake3...
test_derive_view_tag<3> (100 calls) - OK: 880 µs/call (min 793 µs, 90th 906 µs, median 896 µs, std dev 24 µs)

*/
