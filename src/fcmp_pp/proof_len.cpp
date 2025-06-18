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

#include "proof_len.h"

#include "fcmp_pp_rust/fcmp++.h"
#include "misc_log_ex.h"

namespace fcmp_pp
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
template <typename T>
static T div_ceil(T dividend, T divisor)
{
    static_assert(std::is_unsigned_v<T>, "T not unsigned int");
    CHECK_AND_ASSERT_THROW_MES(divisor > 0, "div_ceil: divisor must be > 0");
    return (dividend + divisor - 1) / divisor;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
std::size_t membership_proof_len(const std::size_t n_fcmp_inputs, const uint8_t n_layers)
{
    CHECK_AND_ASSERT_THROW_MES(n_fcmp_inputs > 0, "membership_proof_len: n_fcmp_inputs must be >0");
    CHECK_AND_ASSERT_THROW_MES(n_layers > 0,      "membership_proof_len: n_layers must be >0");

    CHECK_AND_ASSERT_THROW_MES(n_fcmp_inputs <= FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP,
        "membership_proof_len: n_fcmp_inputs must be <= FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP");
    CHECK_AND_ASSERT_THROW_MES(n_layers <= FCMP_PLUS_PLUS_MAX_LAYERS,
        "membership_proof_len: n_layers must be <= FCMP_PLUS_PLUS_MAX_LAYERS");

    static_assert(
        sizeof(uint16_t) * FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP * FCMP_PLUS_PLUS_MAX_LAYERS == sizeof(PROOF_LEN_TABLE),
        "unexpected table size");

    // This will break platforms with < 16-bit word size. A solution is to use uint16_t for the proof len everywhere
    static_assert(sizeof(std::size_t) >= sizeof(uint16_t), "cannot cast uint16_t to size_t");
    return (std::size_t) PROOF_LEN_TABLE[n_fcmp_inputs-1][n_layers-1];
};

std::size_t fcmp_pp_proof_len(const std::size_t n_fcmp_inputs, const uint8_t n_layers)
{
    CHECK_AND_ASSERT_THROW_MES(n_fcmp_inputs > 0, "fcmp_pp_proof_len: n_fcmp_inputs must be >0");
    CHECK_AND_ASSERT_THROW_MES(n_layers > 0,      "fcmp_pp_proof_len: n_layers must be >0");

    CHECK_AND_ASSERT_THROW_MES(n_fcmp_inputs <= FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP,
        "fcmp_pp_proof_len: n_fcmp_inputs must be <= FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP");
    CHECK_AND_ASSERT_THROW_MES(n_layers <= FCMP_PLUS_PLUS_MAX_LAYERS,
        "fcmp_pp_proof_len: n_layers must be <= FCMP_PLUS_PLUS_MAX_LAYERS");

    return membership_proof_len(n_fcmp_inputs, n_layers)
        + (n_fcmp_inputs * (FCMP_PP_INPUT_TUPLE_SIZE_V1 + FCMP_PP_SAL_PROOF_SIZE_V1));
};
//----------------------------------------------------------------------------------------------------------------------
std::size_t get_n_fcmp_pps(const std::size_t n_tx_inputs)
{
    CHECK_AND_ASSERT_THROW_MES(n_tx_inputs > 0, "get_n_fcmp_pps: n_tx_inputs is 0");
    const std::size_t n_fcmp_pps = div_ceil<std::size_t>(n_tx_inputs, FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP);
    CHECK_AND_ASSERT_THROW_MES(n_fcmp_pps > 0, "get_n_fcmp_pps: n_fcmp_pps is 0");
    return n_fcmp_pps;
}
//----------------------------------------------------------------------------------------------------------------------
std::size_t get_last_fcmp_pp_n_inputs(const std::size_t n_tx_inputs)
{
    const std::size_t last_offset = n_tx_inputs % FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP;
    return last_offset > 0 ? last_offset : FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP;
}
//----------------------------------------------------------------------------------------------------------------------
std::size_t get_last_membership_proof_len(const std::size_t n_tx_inputs, const uint8_t n_layers)
{
    return membership_proof_len(get_last_fcmp_pp_n_inputs(n_tx_inputs), n_layers);
}
//----------------------------------------------------------------------------------------------------------------------
std::size_t get_last_fcmp_pp_proof_len(const std::size_t n_tx_inputs, const uint8_t n_layers)
{
    return fcmp_pp_proof_len(get_last_fcmp_pp_n_inputs(n_tx_inputs), n_layers);
}
//----------------------------------------------------------------------------------------------------------------------
bool fcmp_pps_are_expected_size(const std::vector<std::vector<uint8_t>> &fcmp_pps,
    const std::size_t n_tx_inputs,
    const uint8_t n_layers)
{
    if (fcmp_pps.empty())
        return false;
    if (n_tx_inputs == 0 || n_tx_inputs > FCMP_PLUS_PLUS_MAX_INPUTS_PER_TX)
        return false;
    if (n_layers == 0 || n_layers > FCMP_PLUS_PLUS_MAX_LAYERS)
        return false;
    // The first FCMP++ proofs are all expected to have max n inputs
    for (std::size_t i = 0; i < fcmp_pps.size()-1; ++i)
    {
        const std::size_t act_sz = fcmp_pps.at(i).size();
        if (act_sz == 0)
            return false;
        const std::size_t exp_sz = fcmp_pp::fcmp_pp_proof_len(FCMP_PLUS_PLUS_MAX_INPUTS_PER_FCMP, n_layers);
        if (act_sz != exp_sz)
            return false;
    }
    // The last FCMP++ proof has the remainder
    const std::size_t act_sz = fcmp_pps.back().size();
    if (act_sz == 0)
        return false;
    const std::size_t exp_sz = fcmp_pp::get_last_fcmp_pp_proof_len(n_tx_inputs, n_layers);
    if (act_sz != exp_sz)
        return false;
    return true;
}
//----------------------------------------------------------------------------------------------------------------------
}//namespace fcmp_pp
