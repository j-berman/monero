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

#include <vector>

#include "crypto/crypto.h"
#include "fcmp_pp_rust/fcmp++.h"
#include "serialization/crypto.h"
#include "serialization/serialization.h"

// TODO: consolidate more FCMP++ types into this file

namespace fcmp_pp
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// Rust types
//----------------------------------------------------------------------------------------------------------------------
using SeleneScalar = ::SeleneScalar;
static_assert(sizeof(SeleneScalar) == 32, "unexpected size of selene scalar");
using HeliosScalar = ::HeliosScalar;
static_assert(sizeof(HeliosScalar) == 32, "unexpected size of helios scalar");
//----------------------------------------------------------------------------------------------------------------------
struct SeleneT final
{
    using Scalar       = SeleneScalar;
    using Point        = ::SelenePoint;
    using Chunk        = ::SeleneScalarSlice;
    using CycleScalar  = HeliosScalar;
    using ScalarChunks = ::SeleneScalarChunks;
};
//----------------------------------------------------------------------------------------------------------------------
struct HeliosT final
{
    using Scalar       = HeliosScalar;
    using Point        = ::HeliosPoint;
    using Chunk        = ::HeliosScalarSlice;
    using CycleScalar  = SeleneScalar;
    using ScalarChunks = ::HeliosScalarChunks;
};
//----------------------------------------------------------------------------------------------------------------------
using OutputBytes = ::OutputBytes;
using OutputChunk = ::OutputSlice;
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// C++ types
//----------------------------------------------------------------------------------------------------------------------
// Byte buffer containing the fcmp++ proof
using FcmpPpSalProof = std::vector<uint8_t>;
using FcmpMembershipProof = std::vector<uint8_t>;
using FcmpPpProof = std::vector<uint8_t>;

struct ProofInput final
{
    FcmpRerandomizedOutputCompressed rerandomized_output;
    uint8_t *path;
    uint8_t *output_blinds;
    std::vector<const uint8_t *> selene_branch_blinds;
    std::vector<const uint8_t *> helios_branch_blinds;
};

struct ProofParams final
{
    uint64_t reference_block;
    std::vector<ProofInput> proof_inputs;
};

struct FcmpVerifyHelperData final
{
    const uint8_t *tree_root; // borrowing, *not* owning
    std::vector<crypto::key_image> key_images;
};

using OutputBlind = std::vector<uint8_t>;
using OutputBlinds = std::vector<uint8_t>;
using BranchBlind = std::vector<uint8_t>;

struct SerializableFcmpInput final
{
    crypto::ec_point O_tilde;
    crypto::ec_point I_tilde;
    crypto::ec_point R;
    crypto::ec_point C_tilde;

    template <class Archive>
    inline void serialize(Archive &a, const unsigned int ver)
    {
        a & O_tilde;
        a & I_tilde;
        a & R;
        a & C_tilde;
    }

    BEGIN_SERIALIZE_OBJECT()
        FIELD(O_tilde)
        FIELD(I_tilde)
        FIELD(R)
        FIELD(C_tilde)
    END_SERIALIZE()
};
static_assert(sizeof(SerializableFcmpInput) == sizeof(::FcmpInputCompressed), "Size mismatch FCMP inputs");

struct SerializableRerandomizedOutput final
{
    SerializableFcmpInput input;

    crypto::ec_point r_o;
    crypto::ec_point r_i;
    crypto::ec_point r_r_i;
    crypto::ec_point r_c;

    template <class Archive>
    inline void serialize(Archive &a, const unsigned int ver)
    {
        a & input;
        a & r_o;
        a & r_i;
        a & r_r_i;
        a & r_c;
    }

    BEGIN_SERIALIZE_OBJECT()
        FIELD(input)
        FIELD(r_o)
        FIELD(r_i)
        FIELD(r_r_i)
        FIELD(r_c)
    END_SERIALIZE()
};
static_assert(sizeof(SerializableRerandomizedOutput) == sizeof(::FcmpRerandomizedOutputCompressed),
    "Size mismatch FCMP re-randomized outputs");

// Serializable re-randomzed output to C re-randomized output
static inline const FcmpRerandomizedOutputCompressed &sro2cro(const SerializableRerandomizedOutput &sro)
{
    return (const FcmpRerandomizedOutputCompressed&) sro;
};

// C re-randomzed output to Serializable re-randomized output
static inline const SerializableRerandomizedOutput &cro2sro(const FcmpRerandomizedOutputCompressed &sro)
{
    return (const SerializableRerandomizedOutput&) sro;
};
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
}//namespace fcmp_pp
