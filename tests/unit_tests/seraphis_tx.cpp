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
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/mock_ledger_context.h"
#include "seraphis/sp_misc_utils.h"
#include "seraphis/tx_base.h"
#include "seraphis/tx_binned_reference_set.h"
#include "seraphis/tx_validation_context_mock.h"
#include "seraphis/txtype_squashed_v1.h"

#include "gtest/gtest.h"

#include <iostream>
#include <memory>
#include <type_traits>
#include <vector>


enum class TestType
{
    ExpectTrue,
    ExpectAnyThrow
};

struct SpTxGenData
{
    std::size_t legacy_ring_size{0};
    std::size_t ref_set_decomp_n{1};
    std::size_t ref_set_decomp_m{1};
    sp::SpBinnedReferenceSetConfigV1 bin_config{0, 0};
    std::vector<rct::xmr_amount> alternate_input_amounts;  //alternate all-legacy then all-seraphis inputs
    std::vector<rct::xmr_amount> output_amounts;
    sp::DiscretizedFee discretized_transaction_fee{0};
    TestType expected_result{TestType::ExpectTrue};
    bool test_double_spend{false};
};

template <typename SpTxType>
static void run_mock_tx_test(const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const sp::SpBinnedReferenceSetConfigV1 bin_config,
    const std::vector<rct::xmr_amount> legacy_input_amounts,
    const std::vector<rct::xmr_amount> sp_input_amounts,
    const std::vector<rct::xmr_amount> output_amounts,
    const sp::DiscretizedFee discretized_transaction_fee,
    const TestType expected_result,
    const bool test_double_spend,
    sp::MockLedgerContext &ledger_context_inout)
{
    const sp::TxValidationContextMock tx_validation_context{ledger_context_inout};

    try
    {
        // mock params
        sp::SpTxParamPackV1 tx_params;

        tx_params.legacy_ring_size = legacy_ring_size;
        tx_params.ref_set_decomp_n = ref_set_decomp_n;
        tx_params.ref_set_decomp_m = ref_set_decomp_m;
        tx_params.bin_config = bin_config;

        // make tx
        SpTxType tx;
        sp::make_mock_tx<SpTxType>(tx_params,
            legacy_input_amounts,
            sp_input_amounts,
            output_amounts,
            discretized_transaction_fee,
            ledger_context_inout,
            tx);

        // validate tx
        EXPECT_TRUE(sp::validate_tx(tx, tx_validation_context));

        if (test_double_spend)
        {
            // add key images once validated
            EXPECT_TRUE(sp::try_add_tx_to_ledger(tx, ledger_context_inout));

            // re-validate tx
            // - should fail now that key images were added to the ledger
            EXPECT_FALSE(sp::validate_tx(tx, tx_validation_context));
        }
    }
    catch (...)
    {
        EXPECT_TRUE(expected_result == TestType::ExpectAnyThrow);
    }
}

template <typename SpTxType>
static void run_mock_tx_tests(const std::vector<SpTxGenData> &gen_data)
{
    sp::MockLedgerContext ledger_context{0, 10000};

    for (const SpTxGenData &gen : gen_data)
    {
        for (std::size_t i{0}; i < 2; ++i)
        {
            std::vector<rct::xmr_amount> legacy_input_amounts;
            std::vector<rct::xmr_amount> sp_input_amounts;

            if (i == 0)
                legacy_input_amounts = gen.alternate_input_amounts;
            else
                sp_input_amounts = gen.alternate_input_amounts;

            run_mock_tx_test<SpTxType>(gen.legacy_ring_size,
                gen.ref_set_decomp_n,
                gen.ref_set_decomp_m,
                gen.bin_config,
                legacy_input_amounts,
                sp_input_amounts,
                gen.output_amounts,
                gen.discretized_transaction_fee,
                gen.expected_result,
                gen.test_double_spend,
                ledger_context);
        }
    }
}

template <typename SpTxType>
static void run_mock_tx_test_batch(const std::vector<SpTxGenData> &gen_data)
{
    sp::MockLedgerContext ledger_context{0, 10000};
    const sp::TxValidationContextMock tx_validation_context{ledger_context};
    std::vector<SpTxType> txs_to_verify;
    std::vector<const SpTxType*> txs_to_verify_ptrs;
    txs_to_verify.reserve(gen_data.size() * 2);
    txs_to_verify_ptrs.reserve(gen_data.size() * 2);
    TestType expected_result = TestType::ExpectTrue;

    for (const SpTxGenData &gen : gen_data)
    {
        for (std::size_t i{0}; i < 2; ++i)
        {
            std::vector<rct::xmr_amount> legacy_input_amounts;
            std::vector<rct::xmr_amount> sp_input_amounts;

            if (i == 0)
                legacy_input_amounts = gen.alternate_input_amounts;
            else
                sp_input_amounts = gen.alternate_input_amounts;

            try
            {
                // update expected result
                expected_result = gen.expected_result;

                // mock params
                sp::SpTxParamPackV1 tx_params;

                tx_params.legacy_ring_size = gen.legacy_ring_size;
                tx_params.ref_set_decomp_n = gen.ref_set_decomp_n;
                tx_params.ref_set_decomp_m = gen.ref_set_decomp_m;
                tx_params.bin_config = gen.bin_config;

                // make tx
                sp::make_mock_tx<SpTxType>(tx_params,
                    legacy_input_amounts,
                    sp_input_amounts,
                    gen.output_amounts,
                    gen.discretized_transaction_fee,
                    ledger_context,
                    sp::add_element(txs_to_verify));
            }
            catch (...)
            {
                EXPECT_TRUE(expected_result == TestType::ExpectAnyThrow);
            }
        }
    }

    for (const SpTxType &tx : txs_to_verify)
        txs_to_verify_ptrs.push_back(&tx);

    try
    {
        // validate tx
        EXPECT_TRUE(sp::validate_txs(txs_to_verify_ptrs, tx_validation_context));
    }
    catch (...)
    {
        EXPECT_TRUE(expected_result == TestType::ExpectAnyThrow);
    }
}

static std::vector<SpTxGenData> get_mock_tx_gen_data_misc(const bool test_double_spend)
{
    /// success cases
    std::vector<SpTxGenData> gen_data;
    gen_data.reserve(20);

    // 1-in/1-out
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.alternate_input_amounts.push_back(1);
        temp.output_amounts.push_back(1);
        temp.legacy_ring_size = 2;
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 2;
        temp.bin_config = sp::SpBinnedReferenceSetConfigV1{.m_bin_radius = 0, .m_num_bin_members = 1};
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    // 1-in/1-out non-zero fee
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.alternate_input_amounts.push_back(2);
        temp.output_amounts.push_back(1);
        temp.discretized_transaction_fee = sp::DiscretizedFee{1};
        temp.legacy_ring_size = 2;
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 2;
        temp.bin_config = sp::SpBinnedReferenceSetConfigV1{.m_bin_radius = 0, .m_num_bin_members = 1};
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    // 1-in/2-out
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.alternate_input_amounts.push_back(2);
        temp.output_amounts.push_back(1);
        temp.output_amounts.push_back(1);
        temp.legacy_ring_size = 2;
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 2;
        temp.bin_config = sp::SpBinnedReferenceSetConfigV1{.m_bin_radius = 0, .m_num_bin_members = 1};
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    // 2-in/1-out
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.alternate_input_amounts.push_back(1);
        temp.alternate_input_amounts.push_back(1);
        temp.output_amounts.push_back(2);
        temp.legacy_ring_size = 2;
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 2;
        temp.bin_config = sp::SpBinnedReferenceSetConfigV1{.m_bin_radius = 0, .m_num_bin_members = 1};
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    // 8-in/8-out; legacy ref set 4; seraphis ref set 8
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.legacy_ring_size = 4;
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 3;
        temp.bin_config = sp::SpBinnedReferenceSetConfigV1{.m_bin_radius = 0, .m_num_bin_members = 1};
        for (std::size_t i{0}; i < 8; ++i)
        {
            temp.alternate_input_amounts.push_back(1);
            temp.output_amounts.push_back(1);
        }
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    // 4-in/4-out + amounts 0
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.legacy_ring_size = 2;
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 2;
        temp.bin_config = sp::SpBinnedReferenceSetConfigV1{.m_bin_radius = 0, .m_num_bin_members = 1};
        for (std::size_t i{0}; i < 4; ++i)
        {
            temp.alternate_input_amounts.push_back(0);
            temp.output_amounts.push_back(0);
        }
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    /// failure cases

    // no inputs
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectAnyThrow;
        temp.output_amounts.push_back(0);
        temp.legacy_ring_size = 2;
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 2;
        temp.bin_config = sp::SpBinnedReferenceSetConfigV1{.m_bin_radius = 0, .m_num_bin_members = 1};

        gen_data.push_back(temp);
    }

    // no outputs
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectAnyThrow;
        temp.alternate_input_amounts.push_back(0);
        temp.legacy_ring_size = 2;
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 2;
        temp.bin_config = sp::SpBinnedReferenceSetConfigV1{.m_bin_radius = 0, .m_num_bin_members = 1};

        gen_data.push_back(temp);
    }

    // no ref set size
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectAnyThrow;
        temp.alternate_input_amounts.push_back(1);
        temp.output_amounts.push_back(1);
        temp.legacy_ring_size = 0;
        temp.ref_set_decomp_n = 0;
        temp.bin_config = sp::SpBinnedReferenceSetConfigV1{.m_bin_radius = 0, .m_num_bin_members = 1};

        gen_data.push_back(temp);
    }

    // amounts don't balance
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectAnyThrow;
        temp.alternate_input_amounts.push_back(2);
        temp.output_amounts.push_back(1);
        temp.legacy_ring_size = 2;
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 2;
        temp.bin_config = sp::SpBinnedReferenceSetConfigV1{.m_bin_radius = 0, .m_num_bin_members = 1};

        gen_data.push_back(temp);
    }

    return gen_data;
}

static std::vector<SpTxGenData> get_mock_tx_gen_data_batching()
{
    /// a batch of 3 tx
    std::vector<SpTxGenData> gen_data;
    gen_data.resize(3);

    for (auto &gen : gen_data)
    {
        gen.alternate_input_amounts.push_back(3);
        gen.alternate_input_amounts.push_back(1);
        gen.output_amounts.push_back(2);
        gen.output_amounts.push_back(1);
        gen.discretized_transaction_fee = sp::DiscretizedFee{1};
        gen.legacy_ring_size = 2;
        gen.ref_set_decomp_n = 2;
        gen.ref_set_decomp_m = 2;
        gen.bin_config = sp::SpBinnedReferenceSetConfigV1{.m_bin_radius = 0, .m_num_bin_members = 1};
    }

    return gen_data;
}


/////////////////////////////////////////////////////////////////////
////////////////////////// Seraphis Squash //////////////////////////
/////////////////////////////////////////////////////////////////////

TEST(seraphis_tx, seraphis_squashed)
{
    run_mock_tx_tests<sp::SpTxSquashedV1>(get_mock_tx_gen_data_misc(true));
}

TEST(seraphis_tx_batching, seraphis_squashed)
{
    run_mock_tx_test_batch<sp::SpTxSquashedV1>(get_mock_tx_gen_data_batching());
}

TEST(seraphis_tx, seraphis_squashed_multi_input_type)
{
    sp::MockLedgerContext ledger_context{0, 10000};

    run_mock_tx_test<sp::SpTxSquashedV1>(2,
        2,
        2,
        sp::SpBinnedReferenceSetConfigV1{.m_bin_radius = 1, .m_num_bin_members = 2},
        {2, 2},
        {1, 1},
        {5},
        sp::DiscretizedFee{1},
        TestType::ExpectTrue,
        true,
        ledger_context);
}
