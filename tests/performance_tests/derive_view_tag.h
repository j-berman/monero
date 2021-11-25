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
#include "common/threadpool.h"

#include "single_tx_test_base.h"

template<size_t parallel_batch_size>
class test_derive_view_tag : public single_tx_test_base
{
public:
  static const size_t loop_count = 1000;
  static const size_t reloop_count = 200;

  bool init()
  {
    if (!single_tx_test_base::init())
      return false;

    crypto::generate_key_derivation(m_tx_pub_key, m_bob.get_keys().m_view_secret_key, m_key_derivation);

    return true;
  }

  bool test()
  {
    crypto::key_derivation key_derivation = m_key_derivation;
    crypto::view_tag view_tag;

    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter(tpool);

    if (parallel_batch_size == 0)
    {
      // no threads, just test synchronous behavior
      for (size_t i = 0; i < reloop_count; ++i)
        crypto::derive_view_tag(key_derivation, i, view_tag);
    }
    else
    {
      // submit calls to derive_view_tag in batches of size parallel_batch_size to the thread pool
      size_t num_batches = std::floor(reloop_count / parallel_batch_size) + (reloop_count % parallel_batch_size > 0 ? 1 : 0);
      size_t num_derivations = 0;
      for (size_t i = 0, batch_start = 0; i < num_batches; ++i)
      {
        size_t batch_end = std::min(batch_start + parallel_batch_size, reloop_count);
        tpool.submit(&waiter, [&key_derivation, &view_tag, batch_start, batch_end]() {
          for (size_t k = batch_start; k < batch_end; ++k)
            crypto::derive_view_tag(key_derivation, k, view_tag);
        }, true);
        num_derivations += batch_end - batch_start;
        batch_start = batch_end;
      }

      if (num_derivations != reloop_count)
        return false;

      if (!waiter.wait())
        return false;
    }

    return true;
  }

private:
  crypto::key_derivation m_key_derivation;
};
