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

// Error objects for reporting problems that occur during multisig signing ceremonies.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctTypes.h"
#include "sp_variant.h"

//third party headers

//standard headers

//forward declarations
#include <exception>
#include <string>


namespace sp
{

struct dummy_multisig_exception : public std::exception
{};

struct MultisigSigningErrorBadInitSet final
{
    enum class ErrorCode
    {
        SEMANTICS_EXCEPTION,
        UNEXPECTED_FILTER,
        UNEXPECTED_SIGNER,
        UNEXPECTED_PROOF_MESSAGE,
        UNEXPECTED_MAIN_PROOF_KEY
    };

    /// error code
    ErrorCode m_error_code;
    /// optional error message (e.g. for exceptions)
    std::string m_error_message;

    /// all multisig signers allowed to participate in signature attempts
    multisig::signer_set_filter m_aggregate_signer_set_filter;
    /// id of signer who made this proof initializer set
    crypto::public_key m_signer_id;
    /// message to be signed by the multisig proofs
    rct::key m_proof_message;
    /// main proof key to be signed by the multisig proofs
    rct::key m_proof_key;
};

struct MultisigSigningErrorBadInitSetCollection final
{
    enum class ErrorCode
    {
        EMPTY_COLLECTION_EXPECTED,
        PROOF_CONTEXT_MISMATCH,
        INVALID_MAPPING,
        GET_NONCES_FAIL,
        INVALID_NONCES_SET_SIZE
    };

    /// error code
    ErrorCode m_error_code;
    /// optional error message (e.g. for exceptions)
    std::string m_error_message;

    /// id of signer who supposedly made this collection of proof initializer sets
    crypto::public_key m_signer_id;
};

struct MultisigSigningErrorAvailableSigners final
{
    enum class ErrorCode
    {
        INCOMPLETE_AVAILABLE_SIGNERS
    };

    /// error code
    ErrorCode m_error_code;
    /// optional error message (e.g. for exceptions)
    std::string m_error_message;

    /// signers that are allowed to participate in a given multisig signing ceremony but are missing
    multisig::signer_set_filter m_missing_signers;
    /// signers that are not allowed to participate in a given multisig signing ceremony but are present anyway
    multisig::signer_set_filter m_unexpected_available_signers;
};

struct MultisigSigningErrorBadPartialSig final
{
    enum class ErrorCode
    {
        UNEXPECTED_MAIN_PROOF_KEY,
        UNEXPECTED_PROOF_MESSAGE,
        UNEXPECTED_VARIANT_TYPE
    };

    /// error code
    ErrorCode m_error_code;
    /// optional error message (e.g. for exceptions)
    std::string m_error_message;

    /// main proof key of the partial sig
    rct::key m_proof_key;
    /// proof message of the partial sig
    rct::key m_proof_message;
};

struct MultisigSigningErrorMakePartialSigSet final
{
    enum class ErrorCode
    {
        GET_KEY_FAIL,
        MAKE_SET_EXCEPTION,
        MAKE_SIGNATURE_EXCEPTION,
        INVALID_NONCES_SET_QUANTITY
    };

    /// error code
    ErrorCode m_error_code;
    /// optional error message (e.g. for exceptions)
    std::string m_error_message;

    /// set of multisig signers the partial signature set corresponds to
    multisig::signer_set_filter m_signature_set_filter;
};

struct MultisigSigningErrorBadPartialSigSet final
{
    enum class ErrorCode
    {
        SEMANTICS_EXCEPTION,
        INVALID_MAPPING
    };

    /// error code
    ErrorCode m_error_code;
    /// optional error message (e.g. for exceptions)
    std::string m_error_message;

    /// set of multisig signers the partial signature set corresponds to
    multisig::signer_set_filter m_signature_set_filter;
    /// signer that produced this partial sig set
    crypto::public_key m_signer_id;
};

struct MultisigSigningErrorBadSigAssembly final
{
    enum class ErrorCode
    {
        PROOF_KEYS_MISMATCH,
        SIG_ASSEMBLY_FAIL
    };

    /// error code
    ErrorCode m_error_code;
    /// optional error message (e.g. for exceptions)
    std::string m_error_message;

    /// set of multisig signers the partial signature set corresponds to
    multisig::signer_set_filter m_signer_set_filter;
};

struct MultisigSigningErrorBadSigSet final
{
    enum class ErrorCode
    {
        INVALID_SIG_SET
    };

    /// error code
    ErrorCode m_error_code;
    /// optional error message (e.g. for exceptions)
    std::string m_error_message;
};

////
// MultisigSigningErrorVariant
///
using MultisigSigningErrorVariant =
    SpVariant<
        MultisigSigningErrorBadInitSet,
        MultisigSigningErrorBadInitSetCollection,
        MultisigSigningErrorAvailableSigners,
        MultisigSigningErrorBadPartialSig,
        MultisigSigningErrorMakePartialSigSet,
        MultisigSigningErrorBadPartialSigSet,
        MultisigSigningErrorBadSigAssembly,
        MultisigSigningErrorBadSigSet
    >;
const std::string& error_message_ref(const MultisigSigningErrorVariant &variant);

} //namespace sp
