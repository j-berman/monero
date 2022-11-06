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
#include "multisig_signing_helper_types.h"

//local headers
#include "clsag_multisig.h"
#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_composition_proof.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
bool MultisigProofInitSetV1::try_get_nonces(const std::size_t filter_index, std::vector<MultisigPubNonces> &nonces_out) const
{
    if (filter_index >= m_inits.size())
        return false;

    nonces_out = m_inits[filter_index];

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& MultisigPartialSigVariant::message() const
{
    if (this->is_type<CLSAGMultisigPartial>())
        return this->partial_sig<CLSAGMultisigPartial>().message;
    else if (this->is_type<SpCompositionProofMultisigPartial>())
        return this->partial_sig<SpCompositionProofMultisigPartial>().message;
    else
    {
        static constexpr rct::key temp{};
        return temp;
    }
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& MultisigPartialSigVariant::proof_key() const
{
    if (this->is_type<CLSAGMultisigPartial>())
        return this->partial_sig<CLSAGMultisigPartial>().main_proof_key_K;
    else if (this->is_type<SpCompositionProofMultisigPartial>())
        return this->partial_sig<SpCompositionProofMultisigPartial>().K;
    else
    {
        static constexpr rct::key temp{};
        return temp;
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
