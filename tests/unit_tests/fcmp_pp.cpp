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

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "curve_trees.h"
#include "fcmp_pp/prove.h"
#include "fcmp_pp/tower_cycle.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"

#include "crypto/crypto.h"
#include "crypto/generators.h"

//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
struct OutputContextsAndKeys
{
    std::vector<crypto::secret_key> x_vec;
    std::vector<crypto::secret_key> y_vec;
    std::vector<fcmp_pp::curve_trees::OutputContext> outputs;
};
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
rct::key derive_key_image_generator(const rct::key O)
{
    crypto::public_key I;
    crypto::derive_key_image_generator(rct::rct2pk(O), I);
    return rct::pk2rct(I);
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static const OutputContextsAndKeys generate_random_outputs(const CurveTreesV1 &curve_trees,
    const std::size_t old_n_leaf_tuples,
    const std::size_t new_n_leaf_tuples)
{
    OutputContextsAndKeys outs;
    outs.x_vec.reserve(new_n_leaf_tuples);
    outs.y_vec.reserve(new_n_leaf_tuples);
    outs.outputs.reserve(new_n_leaf_tuples);

    for (std::size_t i = 0; i < new_n_leaf_tuples; ++i)
    {
        const std::uint64_t output_id = old_n_leaf_tuples + i;

        // Generate random output tuple
        crypto::secret_key o,c;
        crypto::public_key O,C;
        crypto::generate_keys(O, o, o, false);
        crypto::generate_keys(C, c, c, false);

        rct::key C_key = rct::pk2rct(C);
        auto output_pair = fcmp_pp::curve_trees::OutputPair{
                .output_pubkey = std::move(O),
                .commitment    = std::move(C_key)
            };

        auto output_context = fcmp_pp::curve_trees::OutputContext{
                .output_id   = output_id,
                .output_pair = std::move(output_pair)
            };

        // Output pubkey O = xG + yT
        // In this test, x is o, y is zero
        crypto::secret_key x = std::move(o);
        crypto::secret_key y;
        sc_0((unsigned char *)y.data);

        outs.x_vec.emplace_back(std::move(x));
        outs.y_vec.emplace_back(std::move(y));
        outs.outputs.emplace_back(std::move(output_context));
    }

    return outs;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
TEST(fcmp_pp, prove)
{
    static const std::size_t N_INPUTS = 8;

    static const std::size_t selene_chunk_width = fcmp_pp::curve_trees::SELENE_CHUNK_WIDTH;
    static const std::size_t helios_chunk_width = fcmp_pp::curve_trees::HELIOS_CHUNK_WIDTH;
    static const std::size_t tree_depth = 3;

    LOG_PRINT_L1("Test prove with selene chunk width " << selene_chunk_width
        << ", helios chunk width " << helios_chunk_width << ", tree depth " << tree_depth);

    uint64_t min_leaves_needed_for_tree_depth = 0;
    const auto curve_trees = test::init_curve_trees_test(selene_chunk_width,
        helios_chunk_width,
        tree_depth,
        min_leaves_needed_for_tree_depth);

    LOG_PRINT_L1("Initializing tree with " << min_leaves_needed_for_tree_depth << " leaves");

    // Init tree in memory
    CurveTreesGlobalTree global_tree(*curve_trees);
    const auto new_outputs = generate_random_outputs(*curve_trees, 0, min_leaves_needed_for_tree_depth);
    ASSERT_TRUE(global_tree.grow_tree(0, min_leaves_needed_for_tree_depth, new_outputs.outputs));

    LOG_PRINT_L1("Finished initializing tree with " << min_leaves_needed_for_tree_depth << " leaves");

    const auto tree_root = global_tree.get_tree_root();

    // Keep them cached across runs
    std::vector<const uint8_t *> selene_branch_blinds;
    std::vector<const uint8_t *> helios_branch_blinds;

    std::vector<const uint8_t *> fcmp_prove_inputs;
    std::vector<crypto::key_image> key_images;
    std::vector<crypto::ec_point> pseudo_outs;

    // Create proof for every leaf in the tree
    for (std::size_t leaf_idx = 0; leaf_idx < global_tree.get_n_leaf_tuples(); ++leaf_idx)
    {
        LOG_PRINT_L1("Constructing proof inputs for leaf idx " << leaf_idx);

        const auto path = global_tree.get_path_at_leaf_idx(leaf_idx);
        const std::size_t output_idx = leaf_idx % curve_trees->m_c1_width;

        const fcmp_pp::curve_trees::OutputPair output_pair = {rct::rct2pk(path.leaves[output_idx].O), path.leaves[output_idx].C};
        const auto output_tuple = fcmp_pp::curve_trees::output_to_tuple(output_pair);

        // ASSERT_TRUE(curve_trees->audit_path(path, output_pair, global_tree.get_n_leaf_tuples()));
        // LOG_PRINT_L1("Passed the audit...\n");

        const auto x = (uint8_t *) new_outputs.x_vec[leaf_idx].data;
        const auto y = (uint8_t *) new_outputs.y_vec[leaf_idx].data;

        // Leaves
        const auto path_for_proof = curve_trees->path_for_proof(path, output_tuple);

        const auto rerandomized_output = fcmp_pp::rerandomize_output(path_for_proof.leaves[output_idx]);

        pseudo_outs.emplace_back(fcmp_pp::pseudo_out(rerandomized_output));

        key_images.emplace_back();
        crypto::generate_key_image(rct::rct2pk(path.leaves[output_idx].O),
            new_outputs.x_vec[leaf_idx],
            key_images.back());

        // Set path
        const auto helios_scalar_chunks = fcmp_pp::tower_cycle::scalar_chunks_to_chunk_vector<fcmp_pp::HeliosT>(
            path_for_proof.c2_scalar_chunks);
        const auto selene_scalar_chunks = fcmp_pp::tower_cycle::scalar_chunks_to_chunk_vector<fcmp_pp::SeleneT>(
            path_for_proof.c1_scalar_chunks);

        const auto path_rust = fcmp_pp::path_new({path_for_proof.leaves.data(), path_for_proof.leaves.size()},
            path_for_proof.output_idx,
            {helios_scalar_chunks.data(), helios_scalar_chunks.size()},
            {selene_scalar_chunks.data(), selene_scalar_chunks.size()});

        // Collect blinds for rerandomized output
        const auto o_blind = fcmp_pp::o_blind(rerandomized_output);
        const auto i_blind = fcmp_pp::i_blind(rerandomized_output);
        const auto i_blind_blind = fcmp_pp::i_blind_blind(rerandomized_output);
        const auto c_blind = fcmp_pp::c_blind(rerandomized_output);

        const auto blinded_o_blind = fcmp_pp::blind_o_blind(o_blind);
        const auto blinded_i_blind = fcmp_pp::blind_i_blind(i_blind);
        const auto blinded_i_blind_blind = fcmp_pp::blind_i_blind_blind(i_blind_blind);
        const auto blinded_c_blind = fcmp_pp::blind_c_blind(c_blind);

        const auto output_blinds = fcmp_pp::output_blinds_new(blinded_o_blind,
            blinded_i_blind,
            blinded_i_blind_blind,
            blinded_c_blind);

        // Cache branch blinds
        if (selene_branch_blinds.empty())
            for (std::size_t i = 0; i < helios_scalar_chunks.size(); ++i)
                selene_branch_blinds.emplace_back(fcmp_pp::selene_branch_blind());

        if (helios_branch_blinds.empty())
            for (std::size_t i = 0; i < selene_scalar_chunks.size(); ++i)
                helios_branch_blinds.emplace_back(fcmp_pp::helios_branch_blind());

        auto fcmp_prove_input = fcmp_pp::fcmp_prove_input_new(x,
            y,
            rerandomized_output,
            path_rust,
            output_blinds,
            selene_branch_blinds,
            helios_branch_blinds);

        fcmp_prove_inputs.emplace_back(std::move(fcmp_prove_input));
        if (fcmp_prove_inputs.size() < N_INPUTS)
            continue;

        // This test does not have outputs, but this is where this would go if it did
        // fcmp_pp::balance_last_pseudo_out(sum_output_masks, fcmp_prove_inputs);

        LOG_PRINT_L1("Constructing proof and verifying");
        const crypto::hash tx_hash{};
        const std::size_t n_layers = 1 + tree_depth;
        const auto proof = fcmp_pp::prove(
                tx_hash,
                fcmp_prove_inputs,
                n_layers
            );

        bool verify = fcmp_pp::verify(
                tx_hash,
                proof,
                n_layers,
                tree_root,
                pseudo_outs,
                key_images
            );
        ASSERT_TRUE(verify);

        fcmp_prove_inputs.clear();
        pseudo_outs.clear();
        key_images.clear();
    }
}
//----------------------------------------------------------------------------------------------------------------------
TEST(fcmp_pp, sal_completeness)
{
    // O, I, C, L
    const rct::key x = rct::skGen();
    const rct::key y = rct::skGen();
    rct::key O;
    rct::addKeys2(O, x, y, rct::pk2rct(crypto::get_T())); // O = x G + y T
    const rct::key I = derive_key_image_generator(O);
    const rct::key C = rct::pkGen();
    crypto::key_image L;
    crypto::generate_key_image(rct::rct2pk(O), rct::rct2sk(x), L);

    // Rerandomize
    uint8_t *rerandomized_output{fcmp_pp::rerandomize_output(fcmp_pp::OutputBytes{
        .O_bytes = O.bytes,
        .I_bytes = I.bytes,
        .C_bytes = C.bytes
    })};

    // Generate signable_tx_hash
    const crypto::hash signable_tx_hash = crypto::rand<crypto::hash>();

    // Get the input
    void *fcmp_input = fcmp_input_ref(rerandomized_output);

    // Prove
    const fcmp_pp::FcmpPpSalProof sal_proof = fcmp_pp::prove_sal(signable_tx_hash,
        rct::rct2sk(x),
        rct::rct2sk(y),
        rerandomized_output);
    free(rerandomized_output);

    // Verify
    const bool ver = fcmp_pp::verify_sal(signable_tx_hash, fcmp_input, L, sal_proof);
    free(fcmp_input);

    EXPECT_TRUE(ver);
}
//----------------------------------------------------------------------------------------------------------------------