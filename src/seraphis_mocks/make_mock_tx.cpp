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
#include "make_mock_tx.h"

//local headers
#include "crypto/crypto.h"
#include "mock_ledger_context.h"
#include "mock_tx_builders_inputs.h"
#include "mock_tx_builders_legacy_inputs.h"
#include "mock_tx_builders_outputs.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builder_types_legacy.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_builders_legacy_inputs.h"
#include "seraphis/tx_builders_mixed.h"
#include "seraphis/tx_discretized_fee.h"
#include "seraphis/txtype_squashed_v1.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
template <>
void make_mock_tx<SpTxSquashedV1>(const SpTxParamPackV1 &params,
    const std::vector<rct::xmr_amount> &legacy_in_amounts,
    const std::vector<rct::xmr_amount> &sp_in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    const DiscretizedFee &tx_fee,
    MockLedgerContext &ledger_context_inout,
    SpTxSquashedV1 &tx_out)
{
    CHECK_AND_ASSERT_THROW_MES(legacy_in_amounts.size() + sp_in_amounts.size() > 0,
        "SpTxSquashedV1: tried to make mock tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "SpTxSquashedV1: tried to make mock tx without any outputs.");

    // mock semantics version
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version{SpTxSquashedV1::SemanticRulesVersion::MOCK};

    // make legacy spend privkey
    const crypto::secret_key legacy_spend_privkey{rct::rct2sk(rct::skGen())};

    // make seraphis spendbase privkey (master key)
    const crypto::secret_key sp_spend_privkey{rct::rct2sk(rct::skGen())};

    // make mock legacy inputs
    std::vector<LegacyInputProposalV1> legacy_input_proposals{
            gen_mock_legacy_input_proposals_v1(legacy_spend_privkey, legacy_in_amounts)
        };
    std::sort(legacy_input_proposals.begin(), legacy_input_proposals.end());

    // make mock seraphis inputs
    std::vector<SpInputProposalV1> sp_input_proposals{gen_mock_sp_input_proposals_v1(sp_spend_privkey, sp_in_amounts)};
    std::sort(sp_input_proposals.begin(), sp_input_proposals.end());

    // make mock outputs
    std::vector<SpOutputProposalV1> output_proposals{
            gen_mock_sp_output_proposals_v1(out_amounts, params.num_random_memo_elements)
        };

    // for 2-out tx, the enote ephemeral pubkey is shared by both outputs
    if (output_proposals.size() == 2)
        output_proposals[1].m_enote_ephemeral_pubkey = output_proposals[0].m_enote_ephemeral_pubkey;

    // expect amounts to balance
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts_v1(legacy_input_proposals,
            sp_input_proposals,
            output_proposals,
            tx_fee),
        "SpTxSquashedV1: tried to make mock tx with unbalanced amounts.");

    // make partial memo
    std::vector<ExtraFieldElement> additional_memo_elements;
    additional_memo_elements.resize(params.num_random_memo_elements);

    for (ExtraFieldElement &element : additional_memo_elements)
        element.gen();

    TxExtra partial_memo;
    make_tx_extra(std::move(additional_memo_elements), partial_memo);

    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(semantic_rules_version, version_string);

    // proposal prefix
    rct::key proposal_prefix;
    make_tx_proposal_prefix_v1(version_string,
        legacy_input_proposals,
        sp_input_proposals,
        output_proposals,
        partial_memo,
        tx_fee,
        proposal_prefix);

    // make legacy ring signature preps
    std::vector<LegacyRingSignaturePrepV1> legacy_ring_signature_preps{
            gen_mock_legacy_ring_signature_preps_v1(proposal_prefix,
                legacy_input_proposals,
                params.legacy_ring_size,
                ledger_context_inout)
        };
    std::sort(legacy_ring_signature_preps.begin(), legacy_ring_signature_preps.end());

    // make legacy inputs
    std::vector<LegacyInputV1> legacy_inputs;

    make_v1_legacy_inputs_v1(proposal_prefix,
        legacy_input_proposals,
        std::move(legacy_ring_signature_preps),
        legacy_spend_privkey,
        legacy_inputs);
    std::sort(legacy_inputs.begin(), legacy_inputs.end());

    // make seraphis partial inputs
    std::vector<SpPartialInputV1> sp_partial_inputs;

    make_v1_partial_inputs_v1(sp_input_proposals, proposal_prefix, sp_spend_privkey, sp_partial_inputs);
    std::sort(sp_partial_inputs.begin(), sp_partial_inputs.end());

    // prepare partial tx
    SpPartialTxV1 partial_tx;

    make_v1_partial_tx_v1(std::move(legacy_inputs),
        std::move(sp_partial_inputs),
        std::move(output_proposals),
        partial_memo,
        tx_fee,
        version_string,
        partial_tx);

    // make mock seraphis membership proof ref sets
    std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps{
            gen_mock_sp_membership_proof_preps_v1(sp_input_proposals,
                params.ref_set_decomp_n,
                params.ref_set_decomp_m,
                params.bin_config,
                ledger_context_inout)
        };

    // seraphis membership proofs (assumes the caller prepared to make a membership proof for each input)
    std::vector<SpAlignableMembershipProofV1> sp_alignable_membership_proofs;
    make_v1_membership_proofs_v1(std::move(sp_membership_proof_preps), sp_alignable_membership_proofs);

    // make tx
    make_seraphis_tx_squashed_v1(semantic_rules_version,
        std::move(partial_tx),
        std::move(sp_alignable_membership_proofs),
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
