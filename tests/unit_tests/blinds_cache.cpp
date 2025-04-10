// Copyright (c) 2014, The Monero Project
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

#include "gtest/gtest.h"


#include "curve_trees.h"
#include "fcmp_pp/blinds_cache.h"
#include "fcmp_pp/curve_trees.h"

using Selene = fcmp_pp::curve_trees::Selene;
using Helios = fcmp_pp::curve_trees::Helios;

//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
TEST(blinds_cache, add_output)
{
    auto curve_trees = fcmp_pp::curve_trees::curve_trees_v1();
    auto blinds_cache = new fcmp_pp::curve_trees::BlindsCache<Selene, Helios>(curve_trees);

    const std::size_t INIT_LEAVES = 1;
    auto outputs = test::generate_random_outputs(*curve_trees, 0, INIT_LEAVES);
    CHECK_AND_ASSERT_THROW_MES(outputs.size() == INIT_LEAVES, "unexpected size of outputs");

    const auto &output_pair = outputs[0].output_pair;
    LOG_PRINT_L1("Adding output...");
    blinds_cache->add_output(output_pair);

    LOG_PRINT_L1("Getting output blinds...");
    FcmpRerandomizedOutputCompressed rerandomized_out;
    blinds_cache->get_output_blinds(output_pair, rerandomized_out);
    LOG_PRINT_L1("Got output blinds...");

    delete blinds_cache;
}
//----------------------------------------------------------------------------------------------------------------------
TEST(blinds_cache, add_many_outputs)
{
    auto curve_trees = fcmp_pp::curve_trees::curve_trees_v1();
    auto blinds_cache = new fcmp_pp::curve_trees::BlindsCache<Selene, Helios>(curve_trees);

    const std::size_t INIT_LEAVES = 10;
    auto outputs = test::generate_random_outputs(*curve_trees, 0, INIT_LEAVES);
    CHECK_AND_ASSERT_THROW_MES(outputs.size() == INIT_LEAVES, "unexpected size of outputs");

    LOG_PRINT_L0("Adding outputs to blinds cache");
    for (const auto &o : outputs)
        blinds_cache->add_output(o.output_pair);

    LOG_PRINT_L0("Reading calculated blinds from blinds cache");
    for (const auto &o : outputs)
    {
        LOG_PRINT_L2("Reading output blinds for output " << o.output_id);
        FcmpRerandomizedOutputCompressed rerandomized_out;
        blinds_cache->get_output_blinds(o.output_pair, rerandomized_out);
    }

    delete blinds_cache;
}
//----------------------------------------------------------------------------------------------------------------------
TEST(blinds_cache, get_branch_blinds)
{
    auto curve_trees = fcmp_pp::curve_trees::curve_trees_v1();
    auto blinds_cache = new fcmp_pp::curve_trees::BlindsCache<Selene, Helios>(curve_trees);

    LOG_PRINT_L0("Initiating branch blinds async calculation");
    blinds_cache->calc_needed_branch_blinds_async();

    // mainnet has ~150mn outputs at time of writing
    const uint8_t n_layers = curve_trees->n_layers(150000000);

    // c1
    LOG_PRINT_L0("Getting c1 branch blinds");
    const auto c1_branch_blinds = blinds_cache->get_c1_branch_blinds(n_layers, 2/*n_inputs*/);
    LOG_PRINT_L0("Got c1 branch blinds " << c1_branch_blinds.size());

    // c2
    LOG_PRINT_L0("Getting c2 branch blinds");
    const auto c2_branch_blinds = blinds_cache->get_c2_branch_blinds(n_layers, 2/*n_inputs*/);
    LOG_PRINT_L0("Got c2 branch blinds " << c2_branch_blinds.size());

    delete blinds_cache;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
