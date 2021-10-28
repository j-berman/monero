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

// Mock tx: Seraphis implemented with concise Grootle membership proofs and separate composition proofs for
//          each input image
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "mock_tx.h"
#include "mock_sp_base_types.h"
#include "mock_sp_component_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <memory>
#include <string>
#include <vector>

//forward declarations


namespace mock_tx
{
#if 0
// destinations
MockDestinationSpV1

////
// Tx proposal: set of destinations (and miscellaneous memos)
///
class MockTxProposalSpV1 final
{
    MockTxProposalSpV1() = default;

    // randomly sort destinations, validate semantics?
    MockTxProposalSpV1(std::vector<MockDestinationSpV1> destinations);

    std::string get_proposal_prefix();  // composition proof msg
    void get_outputs(std::vector<MockENoteSpV1> &outputs_out);
    void get_tx_supplement(MockSupplementSpV1 &supplement_out);

    std::vector<MockDestinationSpV1> m_destinations;
    //TODO: miscellaneous memo(s)
};

// input proposals
MockInputProposalSpV1

////
// Partial tx input
// - enote spent
// - cached amount and amount blinding factor, image masks
// - composition proof for input (MockImageProofSpV1)
// - proposal prefix (composition proof msg) [for consistency checks when handling this struct]
//
// - make last input: sets amount commitment mask to satisfy balance proof (caller should determine amount to satisfy fee)
///
class MockTxInputPartialSpV1 final //needs to be InputSetPartial for merged composition proofs
{
    vec<InputImage> get_input_images();
};

// make balance proof from proposal and partial inputs
MockTxProposalSpV1 + vec<MockTxInputPartialSpV1> -> MockBalanceProofSpV1

////
// Partial tx: no membership proofs
// - from multisig: multisigproposal.txproposal, multisig inputs + extra inputs, balance proof
///
class MockTxPartialSpV1 final
{
    MockTxPartialSpV1(MockTxProposalSpV1 &proposal, vec<MockTxInputPartialSpV1> &inputs, BalanceProof);
};

// complete membership proofs
MockTxInputPartialSpV1 + MockMembershipReferenceSetSpV1 -> MockMembershipProofSpV1

// assemble full tx
#endif

////
// Complete tx
///
class MockTxSpConcise final : public MockTx
{
public:
//member types
    enum ValidationRulesVersion : unsigned char
    {
        MIN = 1,
        ONE = 1,
        MAX = 1
    };

//constructors
    /// default constructor
    MockTxSpConcise() = default;

    /// normal constructor: new tx
    MockTxSpConcise(std::vector<MockENoteImageSpV1> &input_images,
        std::vector<MockENoteSpV1> &outputs,
        std::shared_ptr<MockBalanceProofSpV1> &balance_proof,
        std::vector<MockImageProofSpV1> &image_proofs,
        std::vector<MockMembershipProofSpV1> &membership_proofs,
        MockSupplementSpV1 &tx_supplement,
        ValidationRulesVersion validation_rules_version) :
            m_input_images{std::move(input_images)},
            m_outputs{std::move(outputs)},
            m_balance_proof{std::move(balance_proof)},
            m_image_proofs{std::move(image_proofs)},
            m_membership_proofs{std::move(membership_proofs)},
            m_supplement{std::move(tx_supplement)}
        {
            CHECK_AND_ASSERT_THROW_MES(validate_tx_semantics(), "Failed to assemble MockTxSpConcise.");
            CHECK_AND_ASSERT_THROW_MES(validation_rules_version >= ValidationRulesVersion::MIN &&
                validation_rules_version <= ValidationRulesVersion::MAX, "Invalid validation rules version.");

            m_tx_era_version = TxGenerationSp;
            m_tx_format_version = TxStructureVersionSp::TxTypeSpConciseGrootle1;
            m_tx_validation_rules_version = validation_rules_version;
        }

    /// normal constructor: from existing tx byte blob
    //mock tx doesn't do this

//destructor: default

//member functions
    /// validate tx
    bool validate(const std::shared_ptr<const LedgerContext> ledger_context,
        const bool defer_batchable = false) const override
    {
        // punt to the parent class
        return this->MockTx::validate(ledger_context, defer_batchable);
    }

    /// get size of tx
    std::size_t get_size_bytes() const override;

    /// get a short description of the tx type
    std::string get_descriptor() const override { return "Sp-Concise"; }

    /// get the tx version string: era | format | validation rules
    static void get_versioning_string(const unsigned char tx_validation_rules_version,
        std::string &version_string)
    {
        version_string += static_cast<char>(TxGenerationSp);
        version_string += static_cast<char>(TxStructureVersionSp::TxTypeSpConciseGrootle1);
        version_string += static_cast<char>(tx_validation_rules_version);
    }

    /// get balance proof
    const std::shared_ptr<const MockBalanceProofSpV1> get_balance_proof() const { return m_balance_proof; }

    /// add key images to ledger context
    void add_key_images_to_ledger(std::shared_ptr<LedgerContext> ledger_context) const override;

    //get_tx_byte_blob()

private:
    /// validate pieces of the tx
    bool validate_tx_semantics() const override;
    bool validate_tx_linking_tags(const std::shared_ptr<const LedgerContext> ledger_context) const override;
    bool validate_tx_amount_balance(const bool defer_batchable) const override;
    bool validate_tx_input_proofs(const std::shared_ptr<const LedgerContext> ledger_context,
        const bool defer_batchable) const override;

//member variables
    /// tx input images  (spent e-notes)
    std::vector<MockENoteImageSpV1> m_input_images;
    /// tx outputs (new e-notes)
    std::vector<MockENoteSpV1> m_outputs;
    /// balance proof (balance proof and range proofs)
    std::shared_ptr<MockBalanceProofSpV1> m_balance_proof;
    /// composition proofs: ownership/unspentness for each input
    std::vector<MockImageProofSpV1> m_image_proofs;
    /// concise Grootle proofs: membership for each input
    std::vector<MockMembershipProofSpV1> m_membership_proofs;
    /// supplemental data for tx
    MockSupplementSpV1 m_supplement;
};

/**
* brief: make_mock_tx - make a MockTxSpConcise transaction (function specialization)
* param: params -
* param: in_amounts -
* param: out_amounts -
* inoutparam: ledger_context_inout -
* return: a MockTxSpConcise tx
*/
template <>
std::shared_ptr<MockTxSpConcise> make_mock_tx<MockTxSpConcise>(const MockTxParamPack &params,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    std::shared_ptr<MockLedgerContext> ledger_context_inout);
/**
* brief: validate_mock_txs - validate a set of MockTxSpConcise transactions (function specialization)
* param: txs_to_validate -
* param: ledger_context -
* return: true/false on validation result
*/
template <>
bool validate_mock_txs<MockTxSpConcise>(const std::vector<std::shared_ptr<MockTxSpConcise>> &txs_to_validate,
    const std::shared_ptr<const LedgerContext> ledger_context);

} //namespace mock_tx
