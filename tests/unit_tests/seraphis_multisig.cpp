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

#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "crypto/generators.h"
#include "multisig/account_generator_era.h"
#include "multisig/multisig_account.h"
#include "multisig/multisig_account_era_conversion_msg.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_core_utils.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis/mock_ledger_context.h"
#include "seraphis/sp_composition_proof.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/sp_crypto_utils.h"
#include "seraphis/tx_binned_reference_set.h"
#include "seraphis/tx_binned_reference_set_utils.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builder_types_multisig.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_builders_mixed.h"
#include "seraphis/tx_builders_multisig.h"
#include "seraphis/tx_builders_outputs.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_contextual_enote_record_types.h"
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
#include "seraphis/tx_input_selection.h"
#include "seraphis/tx_input_selection_output_context_v1.h"
#include "seraphis/tx_input_selector_mocks.h"
#include "seraphis/tx_validation_context_mock.h"
#include "seraphis/txtype_squashed_v1.h"

#include "gtest/gtest.h"

#include <memory>
#include <vector>


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key make_secret_key()
{
    return rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_multisig_jamtis_mock_keys(const multisig::multisig_account &account, sp::jamtis::jamtis_mock_keys &keys_out)
{
    using namespace sp;
    using namespace jamtis;

    keys_out.k_m = rct::rct2sk(rct::Z);
    keys_out.k_vb = account.get_common_privkey();
    make_jamtis_unlockamounts_key(keys_out.k_vb, keys_out.xk_ua);
    make_jamtis_findreceived_key(keys_out.k_vb, keys_out.xk_fr);
    make_jamtis_generateaddress_secret(keys_out.k_vb, keys_out.s_ga);
    make_jamtis_ciphertag_secret(keys_out.s_ga, keys_out.s_ct);
    keys_out.K_1_base = rct::pk2rct(account.get_multisig_pubkey());
    extend_seraphis_spendkey_x(keys_out.k_vb, keys_out.K_1_base);
    crypto::x25519_scmul_base(keys_out.xk_ua, keys_out.xK_ua);
    crypto::x25519_scmul_key(keys_out.xk_fr, keys_out.xK_ua, keys_out.xK_fr);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_multisig_accounts(const cryptonote::account_generator_era account_era,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    std::vector<multisig::multisig_account> &accounts_out)
{
  std::vector<crypto::public_key> signers;
  std::vector<multisig::multisig_kex_msg> current_round_msgs;
  std::vector<multisig::multisig_kex_msg> next_round_msgs;
  accounts_out.clear();
  accounts_out.reserve(num_signers);
  signers.reserve(num_signers);
  next_round_msgs.reserve(accounts_out.size());

  // create multisig accounts for each signer
  for (std::size_t account_index{0}; account_index < num_signers; ++account_index)
  {
    // create account [[ROUND 0]]
    accounts_out.emplace_back(account_era, make_secret_key(), make_secret_key());

    // collect signer
    signers.emplace_back(accounts_out.back().get_base_pubkey());

    // collect account's first kex msg
    next_round_msgs.emplace_back(accounts_out.back().get_next_kex_round_msg());
  }

  // perform key exchange rounds until the accounts are ready
  while (accounts_out.size() && !accounts_out[0].multisig_is_ready())
  {
    current_round_msgs = std::move(next_round_msgs);
    next_round_msgs.clear();
    next_round_msgs.reserve(accounts_out.size());

    for (multisig::multisig_account &account : accounts_out)
    {
        // initialize or update account
        if (!account.account_is_active())
            account.initialize_kex(threshold, signers, current_round_msgs);  //[[ROUND 1]]
        else
            account.kex_update(current_round_msgs);  //[[ROUND 2+]]

        next_round_msgs.emplace_back(account.get_next_kex_round_msg());
    }
  }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void convert_multisig_accounts(const cryptonote::account_generator_era new_era,
    std::vector<multisig::multisig_account> &accounts_inout)
{
    if (accounts_inout.size() == 0 || new_era == accounts_inout[0].get_era())
        return;

    // collect messages
    std::vector<multisig::multisig_account_era_conversion_msg> conversion_msgs;
    conversion_msgs.reserve(accounts_inout.size());
    for (const multisig::multisig_account &account : accounts_inout)
        conversion_msgs.emplace_back(account.get_account_era_conversion_msg(new_era));

    // convert accounts to 'new_era'
    for (multisig::multisig_account &account : accounts_inout)
        get_multisig_account_with_new_generator_era(account, new_era, conversion_msgs, account);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool composition_proof_multisig_test(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const crypto::secret_key &x)
{
    try
    {
        // prepare multisig accounts (for seraphis)
        // - use 'converted' accounts to verify that old cryptonote accounts can be converted to seraphis accounts that work
        std::vector<multisig::multisig_account> accounts;
        make_multisig_accounts(cryptonote::account_generator_era::cryptonote, threshold, num_signers, accounts);
        convert_multisig_accounts(cryptonote::account_generator_era::seraphis, accounts);
        if (accounts.size() == 0)
            return false;

        // make a seraphis composition proof pubkey: x G + y X + z U
        rct::key K{rct::pk2rct(accounts[0].get_multisig_pubkey())};  //start with base key: z U
        sp::extend_seraphis_spendkey_x(accounts[0].get_common_privkey(), K);  //+ y X
        sp::mask_key(x, K, K);  //+ x G

        // make the corresponding key image: (z/y) U
        crypto::key_image KI;
        sp::make_seraphis_key_image(accounts[0].get_common_privkey(), accounts[0].get_multisig_pubkey(), KI);

        // tx proposer: make proposal and specify which other signers should try to co-sign (all of them)
        rct::key message{rct::zero()};
        sp::SpCompositionProofMultisigProposal proposal{sp::sp_composition_multisig_proposal(message, K, KI)};
        multisig::signer_set_filter aggregate_filter;
        multisig::multisig_signers_to_filter(accounts[0].get_signers(), accounts[0].get_signers(), aggregate_filter);

        // get signer group permutations (all signer groups that can complete a signature)
        std::vector<multisig::signer_set_filter> filter_permutations;
        multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
            num_signers,
            aggregate_filter,
            filter_permutations);

        // each signer prepares for each signer group it is a member of
        std::vector<sp::SpMultisigNonceRecord> signer_nonce_records(num_signers);

        for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
        {
            for (std::size_t filter_index{0}; filter_index < filter_permutations.size(); ++filter_index)
            {
                if (!multisig::signer_is_in_filter(accounts[signer_index].get_base_pubkey(),
                        accounts[signer_index].get_signers(),
                        filter_permutations[filter_index]))
                    continue;

                sp::SpMultisigPrep prep_temp{sp::sp_multisig_init(rct::pk2rct(crypto::get_U()))};
                EXPECT_TRUE(signer_nonce_records[signer_index].try_add_nonces(proposal.message,
                    proposal.K,
                    filter_permutations[filter_index],
                    prep_temp));
            }
        }

        // complete and validate each signature attempt
        std::vector<sp::SpCompositionProofMultisigPartial> partial_sigs;
        std::vector<sp::SpMultisigPubNonces> signer_nonces_pubs;  //stored with *(1/8)
        crypto::secret_key z_temp;
        sp::SpCompositionProof proof;

        for (const multisig::signer_set_filter filter : filter_permutations)
        {
            signer_nonces_pubs.clear();
            partial_sigs.clear();
            signer_nonces_pubs.reserve(threshold);
            partial_sigs.reserve(threshold);

            // assemble nonce pubkeys for this signing attempt
            for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
            {
                if (!multisig::signer_is_in_filter(accounts[signer_index].get_base_pubkey(),
                        accounts[signer_index].get_signers(),
                        filter))
                    continue;

                signer_nonces_pubs.emplace_back();

                EXPECT_TRUE(signer_nonce_records[signer_index].try_get_recorded_nonce_pubkeys(proposal.message,
                    proposal.K,
                    filter,
                    signer_nonces_pubs.back()));
            }

            // each signer partially signs for this attempt
            for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
            {
                if (!accounts[signer_index].try_get_aggregate_signing_key(filter, z_temp))
                    continue;

                partial_sigs.emplace_back();
                EXPECT_TRUE(try_make_sp_composition_multisig_partial_sig(
                    proposal,
                    x,
                    accounts[signer_index].get_common_privkey(),
                    z_temp,
                    signer_nonces_pubs,
                    filter,
                    signer_nonce_records[signer_index],
                    partial_sigs.back()));
            }

            // sanity checks
            EXPECT_TRUE(signer_nonces_pubs.size() == threshold);
            EXPECT_TRUE(partial_sigs.size() == threshold);

            // make proof
            proof = sp::sp_composition_prove_multisig_final(partial_sigs);

            // verify proof
            if (!sp::sp_composition_verify(proof, message, K, KI))
                return false;
        }
    }
    catch (...)
    {
        return false;
    }

    return true;
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
static void send_coinbase_amounts_to_user(const std::vector<rct::xmr_amount> &coinbase_amounts,
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
        coinbase_enotes.emplace_back();
        output_proposal.get_enote_v1(coinbase_enotes.back());
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
// v1: SpTxSquashedV1
//-------------------------------------------------------------------------------------------------------------------
static void seraphis_multisig_tx_v1_test(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const std::vector<std::uint32_t> &requested_signers,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts_normal,
    const std::vector<rct::xmr_amount> &out_amounts_selfsend,
    const sp::DiscretizedFee &fee,
    const sp::SpTxSquashedV1::SemanticRulesVersion semantic_rules_version)
{
    using namespace sp;
    using namespace jamtis;

    ASSERT_TRUE(num_signers > 0);
    ASSERT_TRUE(requested_signers.size() >= threshold);
    ASSERT_TRUE(requested_signers.size() <= num_signers);
    for (const std::uint32_t requested_signer : requested_signers)
        ASSERT_TRUE(requested_signer < num_signers);

    // config
    const std::size_t max_inputs{10000};
    rct::xmr_amount specified_fee;
    ASSERT_TRUE(try_get_fee_value(fee, specified_fee));
    const std::size_t tx_fee_per_weight{specified_fee};
    const std::size_t ref_set_decomp_m{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t bin_radius{1};
    const std::size_t num_bin_members{2};

    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = bin_radius,
            .m_num_bin_members = num_bin_members
        };


    // global
    MockLedgerContext ledger_context{0, 0};

    std::string version_string;
    make_versioning_string(semantic_rules_version, version_string);


    /// 1) setup multisig accounts

    // a) make accounts
    std::vector<multisig::multisig_account> accounts;
    ASSERT_NO_THROW(make_multisig_accounts(cryptonote::account_generator_era::seraphis, threshold, num_signers, accounts));
    ASSERT_TRUE(accounts.size() == num_signers);

    // b) get shared multisig wallet keys
    jamtis_mock_keys shared_keys;
    ASSERT_NO_THROW(make_multisig_jamtis_mock_keys(accounts[0], shared_keys));

    // c) make an enote store for the multisig group
    SpEnoteStoreMockV1 enote_store{0, 0, 0};


    /// 2) fund the multisig address

    // a) make a user address to receive funds
    address_index_t j;
    j.gen();
    JamtisDestinationV1 user_address;

    ASSERT_NO_THROW(make_jamtis_destination_v1(shared_keys.K_1_base,
        shared_keys.xK_ua,
        shared_keys.xK_fr,
        shared_keys.s_ga,
        j,
        user_address));

    // b) send coinbase enotes to the address, padded so there are enough for membership proofs
    std::vector<rct::xmr_amount> in_amounts_padded{in_amounts};

    if (in_amounts_padded.size() < compute_bin_width(bin_radius))
        in_amounts_padded.resize(compute_bin_width(bin_radius), 0);

    send_coinbase_amounts_to_user(in_amounts_padded, user_address, ledger_context);

    // c) recover balance
    refresh_user_enote_store(shared_keys, refresh_config, ledger_context, enote_store);

    // d) compute expected received amount
    boost::multiprecision::uint128_t total_input_amount{0};

    for (const rct::xmr_amount in_amount : in_amounts_padded)
        total_input_amount += in_amount;

    // e) balance check
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == total_input_amount);


    /// 3) propose tx

    // a) prepare outputs

    // - normal payments
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals;
    normal_payment_proposals.reserve(out_amounts_normal.size());

    for (const rct::xmr_amount out_amount : out_amounts_normal)
    {
        normal_payment_proposals.emplace_back();
        normal_payment_proposals.back().gen(out_amount, 0);
    }

    // - self-send payments
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals;
    selfsend_payment_proposals.reserve(out_amounts_selfsend.size());

    for (const rct::xmr_amount out_amount : out_amounts_selfsend)
    {
        selfsend_payment_proposals.emplace_back(
                JamtisPaymentProposalSelfSendV1{
                    .m_destination = user_address,
                    .m_amount = out_amount,
                    .m_type = JamtisSelfSendType::SELF_SPEND,
                    .m_enote_ephemeral_privkey = crypto::x25519_secret_key_gen(),
                    .m_partial_memo = TxExtra{}
                }
            );
    }

    // b) set requested signers filter
    std::vector<crypto::public_key> requested_signers_ids;
    requested_signers_ids.reserve(requested_signers.size());

    for (std::size_t signer_index{0}; signer_index < accounts.size(); ++signer_index)
    {
        if (std::find(requested_signers.begin(), requested_signers.end(), signer_index) != requested_signers.end())
            requested_signers_ids.emplace_back(accounts[signer_index].get_base_pubkey());
    }

    multisig::signer_set_filter aggregate_filter_of_requested_multisig_signers;
    multisig::multisig_signers_to_filter(requested_signers_ids,
        accounts[0].get_signers(),
        aggregate_filter_of_requested_multisig_signers);

    // c) make multisig tx proposal
    const sp::InputSelectorMockV1 input_selector{enote_store};
    const sp::FeeCalculatorMockTrivial tx_fee_calculator;  //trivial fee calculator so we can use specified input fee

    SpMultisigTxProposalV1 multisig_tx_proposal;
    std::unordered_map<crypto::key_image, std::uint64_t> input_ledger_mappings;
    ASSERT_NO_THROW(ASSERT_TRUE(try_make_v1_multisig_tx_proposal_for_transfer_v1(user_address,
        user_address,
        input_selector,
        tx_fee_calculator,
        tx_fee_per_weight,
        max_inputs,
        semantic_rules_version,
        aggregate_filter_of_requested_multisig_signers,
        std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        TxExtra{},
        shared_keys.K_1_base,
        shared_keys.k_vb,
        multisig_tx_proposal,
        input_ledger_mappings)));

    ASSERT_TRUE(multisig_tx_proposal.m_tx_fee == fee);


    /// 4) get inits from all requested signers
    std::vector<SpMultisigNonceRecord> signer_nonce_records;
    std::vector<SpMultisigInputInitSetV1> input_inits;
    input_inits.reserve(accounts.size());
    //signer_nonce_records.reserve(accounts.size());  //nonce records are non-copyable, so .reserve() doesn't work

    for (std::size_t signer_index{0}; signer_index < accounts.size(); ++signer_index)
    {
        input_inits.emplace_back();
        signer_nonce_records.emplace_back();

        if (std::find(requested_signers.begin(), requested_signers.end(), signer_index) != requested_signers.end())
        {
            ASSERT_NO_THROW(make_v1_multisig_input_init_set_v1(accounts[signer_index].get_base_pubkey(),
                accounts[signer_index].get_threshold(),
                accounts[signer_index].get_signers(),
                multisig_tx_proposal,
                version_string,
                shared_keys.K_1_base,
                shared_keys.k_vb,
                signer_nonce_records.back(),
                input_inits.back()));
        }
        else
        {
            ASSERT_ANY_THROW(make_v1_multisig_input_init_set_v1(accounts[signer_index].get_base_pubkey(),
                accounts[signer_index].get_threshold(),
                accounts[signer_index].get_signers(),
                multisig_tx_proposal,
                version_string,
                shared_keys.K_1_base,
                shared_keys.k_vb,
                signer_nonce_records.back(),
                input_inits.back()));
        }
    }


    /// 5) get partial signatures from all requested signers
    std::unordered_map<crypto::public_key, std::vector<SpMultisigInputPartialSigSetV1>> input_partial_sigs_per_signer;

    for (std::size_t signer_index{0}; signer_index < accounts.size(); ++signer_index)
    {
        if (std::find(requested_signers.begin(), requested_signers.end(), signer_index) != requested_signers.end())
        {
            ASSERT_NO_THROW(ASSERT_TRUE(try_make_v1_multisig_input_partial_sig_sets_v1(accounts[signer_index],
                multisig_tx_proposal,
                version_string,
                input_inits[signer_index],
                input_inits,  //don't need to remove the local init (will be filtered out internally)
                signer_nonce_records[signer_index],
                input_partial_sigs_per_signer[accounts[signer_index].get_base_pubkey()])));
        }
        else
        {
            ASSERT_ANY_THROW(try_make_v1_multisig_input_partial_sig_sets_v1(accounts[signer_index],
                multisig_tx_proposal,
                version_string,
                input_inits[signer_index],
                input_inits,  //don't need to remove the local init (will be filtered out internally)
                signer_nonce_records[signer_index],
                input_partial_sigs_per_signer[accounts[signer_index].get_base_pubkey()]));
        }
    }


    /// 6) any signer (or even a non-signer) can assemble partial signatures and complete txs
    /// note: even signers who didn't participate in making partial sigs can complete txs here

    // a) get partial inputs
    std::vector<SpPartialInputV1> partial_inputs;

    ASSERT_NO_THROW(
            ASSERT_TRUE(try_make_v1_partial_inputs_v1(multisig_tx_proposal,
                accounts[0].get_signers(),
                shared_keys.K_1_base,
                shared_keys.k_vb,
                input_partial_sigs_per_signer,
                partial_inputs))
        );

    // b) build partial tx
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(shared_keys.K_1_base, shared_keys.k_vb, tx_proposal);

    SpPartialTxV1 partial_tx;
    ASSERT_NO_THROW(make_v1_partial_tx_v1(tx_proposal,
        {},  //todo: legacy
        std::move(partial_inputs),
        version_string,
        rct::key{},  //todo: legacy
        shared_keys.K_1_base,
        shared_keys.k_vb,
        partial_tx));

    // c. prepare for membership proofs
    // note: use ring size 2^2 = 4 for speed
    std::vector<SpMembershipProofPrepV1> membership_proof_preps;
    ASSERT_NO_THROW(make_mock_sp_membership_proof_preps_for_inputs_v1(input_ledger_mappings,
        tx_proposal.m_sp_input_proposals,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context,
        membership_proof_preps));

    // d) make membership proofs
    std::vector<SpAlignableMembershipProofV1> alignable_membership_proofs;

    ASSERT_NO_THROW(make_v1_membership_proofs_v1(std::move(membership_proof_preps),
        alignable_membership_proofs));

    // e) complete tx
    SpTxSquashedV1 completed_tx;

    ASSERT_NO_THROW(make_seraphis_tx_squashed_v1(partial_tx,
        std::move(alignable_membership_proofs),
        semantic_rules_version,
        completed_tx));

    // - sanity check fee (can't do this with the trivial fee calculator)
    //ASSERT_TRUE(completed_tx.m_fee == tx_fee_calculator.get_fee(tx_fee_per_weight, completed_tx));

    // f) verify tx
    const TxValidationContextMock tx_validation_context{ledger_context};

    ASSERT_NO_THROW(ASSERT_TRUE(validate_tx(completed_tx, tx_validation_context)));

    // g) add tx to mock ledger
    ASSERT_NO_THROW(ASSERT_TRUE(try_add_tx_to_ledger(completed_tx, ledger_context)));


    /// 7) scan outputs for post-tx balance check

    // a) refresh enote store
    refresh_user_enote_store(shared_keys, refresh_config, ledger_context, enote_store);

    // b) compute expected spent amount
    boost::multiprecision::uint128_t total_spent_amount{0};

    for (const rct::xmr_amount out_amount : out_amounts_normal)
        total_spent_amount += out_amount;

    // c) balance check
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == total_input_amount - total_spent_amount - specified_fee);

    //todo: legacy balance recovery
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_multisig, composition_proof_multisig)
{
    // test various account combinations
    EXPECT_TRUE(composition_proof_multisig_test(1, 2, make_secret_key()));
    EXPECT_TRUE(composition_proof_multisig_test(2, 2, make_secret_key()));
    EXPECT_TRUE(composition_proof_multisig_test(1, 3, make_secret_key()));
    EXPECT_TRUE(composition_proof_multisig_test(2, 3, make_secret_key()));
    EXPECT_TRUE(composition_proof_multisig_test(3, 3, make_secret_key()));
    EXPECT_TRUE(composition_proof_multisig_test(2, 4, make_secret_key()));

    // test that setting x to zero works
    EXPECT_TRUE(composition_proof_multisig_test(2, 2, rct::rct2sk(rct::zero())));
    EXPECT_TRUE(composition_proof_multisig_test(2, 3, rct::rct2sk(rct::zero())));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_multisig, txtype_squashed_v1)
{
    const sp::SpTxSquashedV1::SemanticRulesVersion semantic_rules_version{
            sp::SpTxSquashedV1::SemanticRulesVersion::MOCK
        };

    // prepare fees to use (these should discretize perfectly)
    const sp::DiscretizedFee fee_zero{0};
    const sp::DiscretizedFee fee_one{1};
    EXPECT_TRUE(fee_zero == rct::xmr_amount{0});
    EXPECT_TRUE(fee_one == rct::xmr_amount{1});

    // test M-of-N combos (and combinations of requested signers)
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 2, {0,1},     {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {0},       {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {1},       {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 3, {0,2},     {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(3, 3, {0,1,2},   {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {1,3},     {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {0,1,2,3}, {2}, {1}, {}, fee_one, semantic_rules_version));

    // test various combinations of inputs/outputs
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   { },   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {2},   {0},   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {3},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {3},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {4},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {4},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {4},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {6,6}, {1,1}, {1,1}, fee_one,  semantic_rules_version));
}
//-------------------------------------------------------------------------------------------------------------------
