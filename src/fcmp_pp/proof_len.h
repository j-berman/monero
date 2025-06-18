// Copyright (c) 2024, The Monero Project
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

#pragma once

#include <limits>
#include <vector>

#include "cryptonote_config.h"
#include "fcmp_pp_rust/fcmp++.h"

namespace fcmp_pp
{
//----------------------------------------------------------------------------------------------------------------------

static_assert(FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP == 8, "FCMP++ proof len table expects max 8 inputs per FCMP");

// Constructed using ::_slow_membership_proof_size
static const uint16_t PROOF_LEN_TABLE[FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP][FCMP_PLUS_PLUS_MAX_LAYERS]
{
    {2880, 3296, 3520, 4064, 4416, 4832, 5056, 5600, 5248, 4768, 4960, 5312, },
    {3680, 4640, 4288, 5120, 5632, 5376, 5888, 6336, 6144, 5696, 6048, 6432, },
    {3360, 4736, 5312, 5728, 5408, 5472, 6016, 6592, 6976, 7552, 7424, 7136, },
    {3744, 5664, 5504, 5824, 6528, 6464, 7168, 7808, 7808, 7552, 8096, 8672, },
    {4288, 5728, 5408, 6016, 6784, 7744, 7616, 7680, 8256, 9024, 9600, 10208, },
    {3424, 5216, 6144, 6656, 6688, 7104, 7744, 8672, 9408, 10208, 10304, 10496, },
    {3616, 5632, 5856, 6656, 7456, 7904, 8832, 9792, 9888, 10144, 10912, 11712, },
    {3808, 6176, 6400, 7104, 8192, 8512, 9600, 10624, 11008, 11136, 12064, 13024, },
};

// Size of the membership proof alone
std::size_t membership_proof_len(const std::size_t n_fcmp_inputs, const uint8_t n_layers);

// Size of the FCMP++ proof (membership proof + spend-auth + linkability proofs & input tuples)
// https://github.com/kayabaNerve/fcmp-plus-plus/blob/78754718faa21f0a5751fbd30c9495d7f7f5c2b1/networks/monero/ringct/fcmp%2B%2B/src/lib.rs#L273-L274
std::size_t fcmp_pp_proof_len(const std::size_t n_fcmp_inputs, const uint8_t n_layers);

// Calculate how many FCMP++ proofs are in the tx (there are a max of FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP per FCMP, a
// tx can be composed of multiple FCMP++ proofs)
std::size_t get_n_fcmp_pps(const std::size_t n_tx_inputs);

// Each FCMP has up to FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP inputs, and the last one has the remainder
std::size_t get_last_fcmp_pp_n_inputs(const std::size_t n_tx_inputs);

std::size_t get_last_membership_proof_len(const std::size_t n_tx_inputs, const uint8_t n_layers);
std::size_t get_last_fcmp_pp_proof_len(const std::size_t n_tx_inputs, const uint8_t n_layers);

bool fcmp_pps_are_expected_size(const std::vector<std::vector<uint8_t>> &fcmp_pps,
    const std::size_t n_tx_inputs,
    const uint8_t n_layers);
//----------------------------------------------------------------------------------------------------------------------
}//namespace fcmp_pp
