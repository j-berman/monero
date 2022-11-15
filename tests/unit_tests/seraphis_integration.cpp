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

#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/subaddress_index.h"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_address_tag_utils.h"
#include "seraphis/jamtis_address_utils.h"
#include "seraphis/jamtis_core_utils.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_enote_utils.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis/legacy_core_utils.h"
#include "seraphis/legacy_enote_utils.h"
#include "seraphis/mock_ledger_context.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/sp_core_types.h"
#include "seraphis/tx_base.h"
#include "seraphis/tx_binned_reference_set.h"
#include "seraphis/tx_binned_reference_set_utils.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_builders_legacy_inputs.h"
#include "seraphis/tx_builders_mixed.h"
#include "seraphis/tx_builders_outputs.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_contextual_enote_record_utils.h"
#include "seraphis/tx_discretized_fee.h"
#include "seraphis/tx_enote_finding_context_mocks.h"
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_enote_record_utils.h"
#include "seraphis/tx_enote_scanning.h"
#include "seraphis/tx_enote_scanning_context_simple.h"
#include "seraphis/tx_enote_store_mocks.h"
#include "seraphis/tx_enote_store_updater_mocks.h"
#include "seraphis/tx_extra.h"
#include "seraphis/tx_fee_calculator_mocks.h"
#include "seraphis/tx_fee_calculator_squashed_v1.h"
#include "seraphis/tx_input_selection.h"
#include "seraphis/tx_input_selection_output_context_v1.h"
#include "seraphis/tx_input_selector_mocks.h"
#include "seraphis/tx_validation_context_mock.h"
#include "seraphis/txtype_squashed_v1.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_misc_utils.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <memory>
#include <tuple>
#include <vector>


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_random_address_for_user(const sp::jamtis::jamtis_mock_keys &user_keys,
    sp::jamtis::JamtisDestinationV1 &user_address_out)
{
    using namespace sp;
    using namespace jamtis;

    address_index_t address_index;
    address_index.gen();

    ASSERT_NO_THROW(make_jamtis_destination_v1(user_keys.K_1_base,
        user_keys.xK_ua,
        user_keys.xK_fr,
        user_keys.s_ga,
        address_index,
        user_address_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void convert_outlay_to_payment_proposal(const rct::xmr_amount outlay_amount,
    const sp::jamtis::JamtisDestinationV1 &destination,
    const sp::TxExtra &partial_memo_for_destination,
    sp::jamtis::JamtisPaymentProposalV1 &payment_proposal_out)
{
    using namespace sp;
    using namespace jamtis;

    payment_proposal_out = JamtisPaymentProposalV1{
            .m_destination = destination,
            .m_amount = outlay_amount,
            .m_enote_ephemeral_privkey = crypto::x25519_secret_key_gen(),
            .m_partial_memo = partial_memo_for_destination
        };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void send_legacy_coinbase_amounts_to_user(const std::vector<rct::xmr_amount> &coinbase_amounts,
    const rct::key &destination_subaddr_spend_pubkey,
    const rct::key &destination_subaddr_view_pubkey,
    sp::MockLedgerContext &ledger_context_inout)
{
    using namespace sp;

    // prepare mock coinbase enotes
    std::vector<LegacyEnoteVariant> coinbase_enotes;
    std::vector<rct::key> collected_enote_ephemeral_pubkeys;
    TxExtra tx_extra;
    coinbase_enotes.reserve(coinbase_amounts.size());
    coinbase_enotes.reserve(coinbase_amounts.size());

    LegacyEnoteV4 enote_temp;

    for (std::size_t amount_index{0}; amount_index < coinbase_amounts.size(); ++amount_index)
    {
        // legacy enote ephemeral pubkey
        const crypto::secret_key enote_ephemeral_privkey{rct::rct2sk(rct::skGen())};
        collected_enote_ephemeral_pubkeys.emplace_back(
                rct::scalarmultKey(destination_subaddr_spend_pubkey, rct::sk2rct(enote_ephemeral_privkey))
            );

        // make legacy coinbase enote
        ASSERT_NO_THROW(make_legacy_enote_v4(destination_subaddr_spend_pubkey,
            destination_subaddr_view_pubkey,
            coinbase_amounts[amount_index],
            amount_index,
            enote_ephemeral_privkey,
            enote_temp));

        coinbase_enotes.emplace_back(enote_temp);
    }

    // set tx extra
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(collected_enote_ephemeral_pubkeys, tx_extra));

    // commit coinbase enotes as new block
    ASSERT_NO_THROW(ledger_context_inout.add_legacy_coinbase(
            rct::pkGen(),
            0,
            std::move(tx_extra),
            {},
            std::move(coinbase_enotes)
        ));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void send_sp_coinbase_amounts_to_user(const std::vector<rct::xmr_amount> &coinbase_amounts,
    const sp::jamtis::JamtisDestinationV1 &user_address,
    sp::MockLedgerContext &ledger_context_inout)
{
    using namespace sp;
    using namespace jamtis;

    // prepare mock coinbase enotes
    std::vector<SpEnoteV1> coinbase_enotes;
    SpTxSupplementV1 tx_supplement;
    JamtisPaymentProposalV1 payment_proposal_temp;
    const rct::key mock_input_context{rct::pkGen()};
    coinbase_enotes.reserve(coinbase_amounts.size());
    tx_supplement.m_output_enote_ephemeral_pubkeys.reserve(coinbase_amounts.size());

    for (const rct::xmr_amount coinbase_amount : coinbase_amounts)
    {
        // make payment proposal
        convert_outlay_to_payment_proposal(coinbase_amount, user_address, TxExtra{}, payment_proposal_temp);

        // get output proposal
        SpOutputProposalV1 output_proposal;
        payment_proposal_temp.get_output_proposal_v1(mock_input_context, output_proposal);

        // save enote and ephemeral pubkey
        output_proposal.get_enote_v1(add_element(coinbase_enotes));
        tx_supplement.m_output_enote_ephemeral_pubkeys.emplace_back(output_proposal.m_enote_ephemeral_pubkey);
    }

    // commit coinbase enotes as new block
    ASSERT_NO_THROW(ledger_context_inout.commit_unconfirmed_txs_v1(mock_input_context,
        std::move(tx_supplement),
        std::move(coinbase_enotes)));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void refresh_user_enote_store(const sp::jamtis::jamtis_mock_keys &user_keys,
    const sp::RefreshLedgerEnoteStoreConfig &refresh_config,
    const sp::MockLedgerContext &ledger_context,
    sp::SpEnoteStoreMockV1 &user_enote_store_inout)
{
    using namespace sp;
    using namespace jamtis;

    const EnoteFindingContextLedgerMock enote_finding_context{ledger_context, user_keys.xk_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context{enote_finding_context};
    EnoteStoreUpdaterLedgerMock enote_store_updater{user_keys.K_1_base, user_keys.k_vb, user_enote_store_inout};

    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config, enote_scanning_context, enote_store_updater));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void refresh_user_enote_store_legacy_full(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    const sp::RefreshLedgerEnoteStoreConfig &refresh_config,
    const sp::MockLedgerContext &ledger_context,
    sp::SpEnoteStoreMockV1 &user_enote_store_inout)
{
    using namespace sp;

    const EnoteFindingContextLedgerMockLegacy enote_finding_context{
            ledger_context,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            LegacyScanMode::SCAN
        };
    EnoteScanningContextLedgerSimple enote_scanning_context{enote_finding_context};
    EnoteStoreUpdaterLedgerMockLegacy enote_store_updater{
            legacy_base_spend_pubkey,
            legacy_spend_privkey,
            legacy_view_privkey,
            user_enote_store_inout
        };

    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config, enote_scanning_context, enote_store_updater));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void construct_tx_for_mock_ledger_v1(const sp::legacy_mock_keys &local_user_legacy_keys,
    const sp::jamtis::jamtis_mock_keys &local_user_sp_keys,
    const sp::InputSelectorV1 &local_user_input_selector,
    const sp::FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, sp::jamtis::JamtisDestinationV1, sp::TxExtra>> &outlays,
    const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const sp::SpBinnedReferenceSetConfigV1 &bin_config,
    sp::MockLedgerContext &ledger_context_inout,
    sp::SpTxSquashedV1 &tx_out)
{
    using namespace sp;
    using namespace jamtis;

    /// build transaction

    // 1. prepare dummy and change addresses
    JamtisDestinationV1 change_address;
    JamtisDestinationV1 dummy_address;
    make_random_address_for_user(local_user_sp_keys, change_address);
    make_random_address_for_user(local_user_sp_keys, dummy_address);

    // 2. convert outlays to normal payment proposals
    std::vector<JamtisPaymentProposalV1> normal_payment_proposals;
    normal_payment_proposals.reserve(outlays.size());

    for (const auto &outlay : outlays)
    {
        convert_outlay_to_payment_proposal(std::get<rct::xmr_amount>(outlay),
            std::get<JamtisDestinationV1>(outlay),
            std::get<TxExtra>(outlay),
            add_element(normal_payment_proposals));
    }

    // 3. prepare inputs and finalize outputs
    std::list<LegacyContextualEnoteRecordV1> legacy_contextual_inputs;
    std::list<SpContextualEnoteRecordV1> sp_contextual_inputs;
    std::vector<JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals;  //note: no user-defined selfsends
    DiscretizedFee discretized_transaction_fee;
    ASSERT_NO_THROW(ASSERT_TRUE(try_prepare_inputs_and_outputs_for_transfer_v1(change_address,
        dummy_address,
        local_user_input_selector,
        tx_fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        local_user_sp_keys.k_vb,
        legacy_contextual_inputs,
        sp_contextual_inputs,
        normal_payment_proposals,
        selfsend_payment_proposals,
        discretized_transaction_fee)));

    // 4. tx proposal
    SpTxProposalV1 tx_proposal;
    ASSERT_NO_THROW(make_v1_tx_proposal_v1(legacy_contextual_inputs,
        sp_contextual_inputs,
        std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        discretized_transaction_fee,
        TxExtra{},
        tx_proposal));

    // 5. tx proposal prefix
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(SpTxSquashedV1::SemanticRulesVersion::MOCK, version_string);

    rct::key tx_proposal_prefix;
    tx_proposal.get_proposal_prefix(version_string, local_user_sp_keys.k_vb, tx_proposal_prefix);

    // 6. get ledger mappings for the input membership proofs
    // note: do this after making the tx proposal to demo that inputs don't have to be on-chain when proposing a tx
    std::unordered_map<crypto::key_image, std::uint64_t> legacy_input_ledger_mappings;
    std::unordered_map<crypto::key_image, std::uint64_t> sp_input_ledger_mappings;
    ASSERT_TRUE(try_get_membership_proof_real_reference_mappings(legacy_contextual_inputs, legacy_input_ledger_mappings));
    ASSERT_TRUE(try_get_membership_proof_real_reference_mappings(sp_contextual_inputs, sp_input_ledger_mappings));

    // 7. prepare for legacy ring signatures
    std::vector<LegacyRingSignaturePrepV1> legacy_ring_signature_preps;
    ASSERT_NO_THROW(make_mock_legacy_ring_signature_preps_for_inputs_v1(tx_proposal_prefix,
        legacy_input_ledger_mappings,
        tx_proposal.m_legacy_input_proposals,
        legacy_ring_size,
        ledger_context_inout,
        legacy_ring_signature_preps));

    // 8. prepare for seraphis membership proofs
    std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps;
    ASSERT_NO_THROW(make_mock_sp_membership_proof_preps_for_inputs_v1(sp_input_ledger_mappings,
        tx_proposal.m_sp_input_proposals,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout,
        sp_membership_proof_preps));

    // 9. complete tx
    ASSERT_NO_THROW(make_seraphis_tx_squashed_v1(SpTxSquashedV1::SemanticRulesVersion::MOCK,
        tx_proposal,
        std::move(legacy_ring_signature_preps),
        std::move(sp_membership_proof_preps),
        local_user_legacy_keys.k_s,
        local_user_sp_keys.k_m,
        local_user_sp_keys.k_vb,
        tx_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void transfer_funds_single_mock_v1(const sp::legacy_mock_keys &local_user_legacy_keys,
    const sp::jamtis::jamtis_mock_keys &local_user_sp_keys,
    const sp::InputSelectorV1 &local_user_input_selector,
    const sp::FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, sp::jamtis::JamtisDestinationV1, sp::TxExtra>> &outlays,
    const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const sp::SpBinnedReferenceSetConfigV1 &bin_config,
    sp::MockLedgerContext &ledger_context_inout)
{
    using namespace sp;
    using namespace jamtis;

    // make one tx
    SpTxSquashedV1 single_tx;
    construct_tx_for_mock_ledger_v1(local_user_legacy_keys,
        local_user_sp_keys,
        local_user_input_selector,
        tx_fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        outlays,
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout,
        single_tx);

    // validate and submit to the mock ledger
    const sp::TxValidationContextMock tx_validation_context{ledger_context_inout};
    ASSERT_TRUE(validate_tx(single_tx, tx_validation_context));
    ASSERT_TRUE(try_add_tx_to_ledger(single_tx, ledger_context_inout));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_integration, txtype_squashed_v1)
{
    //// demo of sending and receiving SpTxTypeSquashedV1 transactions (WIP)
    using namespace sp;
    using namespace jamtis;


    /// config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{1};
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator for now (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    /// mock ledger context for this test
    MockLedgerContext ledger_context{0, 10000};


    /// prepare for membership proofs

    // a. add enough fake enotes to the ledger so we can reliably make legacy ring signatures
    std::vector<rct::xmr_amount> fake_legacy_enote_amounts(static_cast<std::size_t>(legacy_ring_size), 0);
    const rct::key fake_legacy_spendkey{rct::pkGen()};
    const rct::key fake_legacy_viewkey{rct::pkGen()};

    send_legacy_coinbase_amounts_to_user(fake_legacy_enote_amounts,
        fake_legacy_spendkey,
        fake_legacy_viewkey,
        ledger_context);

    // b. add enough fake enotes to the ledger so we can reliably make seraphis membership proofs
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
            static_cast<std::size_t>(compute_bin_width(bin_config.m_bin_radius)),
            0
        );
    JamtisDestinationV1 fake_destination;
    fake_destination.gen();

    send_sp_coinbase_amounts_to_user(fake_sp_enote_amounts, fake_destination, ledger_context);


    /// make two users

    // a. user keys
    legacy_mock_keys legacy_user_keys_A;
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_legacy_mock_keys(legacy_user_keys_A);
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // b. legacy user address
    rct::key legacy_subaddr_spendkey_A;
    rct::key legacy_subaddr_viewkey_A;
    cryptonote::subaddress_index legacy_subaddr_index_A;
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map_A;

    gen_legacy_subaddress(legacy_user_keys_A.Ks,
        legacy_user_keys_A.k_v,
        legacy_subaddr_spendkey_A,
        legacy_subaddr_viewkey_A,
        legacy_subaddr_index_A);

    legacy_subaddress_map_A[legacy_subaddr_spendkey_A] = legacy_subaddr_index_A;

    // c. seraphis user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);

    // d. user enote stores (refresh height = 0; seraphis initial block = 0; default spendable age = 0)
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockV1 enote_store_B{0, 0, 0};

    // e. user input selectors
    const sp::InputSelectorMockV1 input_selector_A{enote_store_A};
    const sp::InputSelectorMockV1 input_selector_B{enote_store_B};


    /// initial funding for user A: legacy 4000000 + seraphis 4000000
    send_legacy_coinbase_amounts_to_user(
            {1000000, 1000000, 1000000, 1000000},
            legacy_subaddr_spendkey_A,
            legacy_subaddr_viewkey_A,
            ledger_context
        );
    send_sp_coinbase_amounts_to_user({1000000, 1000000, 1000000, 1000000}, destination_A, ledger_context);


    /// send funds back and forth between users

    // A -> B: 6000000
    refresh_user_enote_store_legacy_full(legacy_user_keys_A.Ks,
        legacy_subaddress_map_A,
        legacy_user_keys_A.k_s,
        legacy_user_keys_A.k_v,
        refresh_config,
        ledger_context,
        enote_store_A);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) >= 8000000);
    transfer_funds_single_mock_v1(legacy_user_keys_A,
        user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{6000000, destination_B, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    // B -> A: 3000000
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) >= 6000000);
    transfer_funds_single_mock_v1(legacy_mock_keys{},
        user_keys_B,
        input_selector_B,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{3000000, destination_A, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    // A -> B: 4000000
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) >= 4000000);
    transfer_funds_single_mock_v1(legacy_user_keys_A,
        user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{4000000, destination_B, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
}
//-------------------------------------------------------------------------------------------------------------------
