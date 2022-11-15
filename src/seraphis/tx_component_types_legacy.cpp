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
#include "tx_component_types_legacy.h"

//local headers
#include "misc_log_ex.h"
#include "seraphis_crypto/sp_misc_utils.h"
#include "seraphis_crypto/sp_transcript.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const LegacyEnoteImageV2 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("C_masked", container.m_masked_commitment);
    transcript_inout.append("KI", container.m_key_image);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t LegacyRingSignatureV3::size_bytes(const std::size_t num_ring_members)
{
    return clsag_size_bytes(num_ring_members) + num_ring_members * 8;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t LegacyRingSignatureV3::size_bytes() const
{
    CHECK_AND_ASSERT_THROW_MES(m_clsag_proof.s.size() == m_reference_set.size(),
        "legacy ring signature v3 size: clsag proof doesn't match reference set size.");

    return LegacyRingSignatureV3::size_bytes(m_reference_set.size());
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const LegacyRingSignatureV3 &container, SpTranscriptBuilder &transcript_inout)
{
    append_clsag_to_transcript(container.m_clsag_proof, transcript_inout);
    transcript_inout.append("reference_set", container.m_reference_set);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
