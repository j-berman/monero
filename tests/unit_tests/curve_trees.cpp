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

#include "fcmp/curve_trees.h"
#include "fcmp/tower_cycle.h"
#include "misc_log_ex.h"

#include <cmath>

template<typename C2>
static const fcmp::curve_trees::Leaves<C2> generate_leaves(const C2 &curve, const std::size_t num_leaves)
{
    std::vector<fcmp::curve_trees::LeafTuple<C2>> tuples;
    tuples.reserve(num_leaves);

    for (std::size_t i = 0; i < num_leaves; ++i)
    {
        // Generate random output tuple
        crypto::secret_key o,c;
        crypto::public_key O,C;
        crypto::generate_keys(O, o, o, false);
        crypto::generate_keys(C, c, c, false);

        auto leaf_tuple = fcmp::curve_trees::output_to_leaf_tuple<C2>(curve, O, C);

        tuples.emplace_back(std::move(leaf_tuple));
    }

    return fcmp::curve_trees::Leaves<C2>{
        .start_idx = 0,
        .tuples    = std::move(tuples)
    };
}

static void log_tree_extension(const fcmp::curve_trees::TreeExtension<fcmp::tower_cycle::helios::Helios, fcmp::tower_cycle::selene::Selene> &tree_extension)
{
    const auto &c1_extensions = tree_extension.c1_layer_extensions;
    const auto &c2_extensions = tree_extension.c2_layer_extensions;

    MDEBUG("Tree extension has " << tree_extension.leaves.tuples.size() << " leaves, "
        << c1_extensions.size() << " helios layers, " <<  c2_extensions.size() << " selene layers");

    MDEBUG("Leaf start idx: " << tree_extension.leaves.start_idx);
    for (std::size_t i = 0; i < tree_extension.leaves.tuples.size(); ++i)
    {
        const auto &leaf = tree_extension.leaves.tuples[i];

        const auto O_x = fcmp::tower_cycle::selene::SELENE.to_string(leaf.O_x);
        const auto I_x = fcmp::tower_cycle::selene::SELENE.to_string(leaf.I_x);
        const auto C_x = fcmp::tower_cycle::selene::SELENE.to_string(leaf.C_x);

        MDEBUG("Leaf idx " << ((i*fcmp::curve_trees::LEAF_TUPLE_SIZE) + tree_extension.leaves.start_idx)
            << " : { O_x: " << O_x << " , I_x: " << I_x << " , C_x: " << C_x << " }");
    }

    bool use_c2 = true;
    std::size_t c1_idx = 0;
    std::size_t c2_idx = 0;
    for (std::size_t i = 0; i < (c1_extensions.size() + c2_extensions.size()); ++i)
    {
        if (use_c2)
        {
            CHECK_AND_ASSERT_THROW_MES(c2_idx < c2_extensions.size(), "unexpected c2 layer");

            const fcmp::curve_trees::LayerExtension<fcmp::tower_cycle::selene::Selene> &c2_layer = c2_extensions[c2_idx];
            MDEBUG("Selene tree extension start idx: " << c2_layer.start_idx);

            for (std::size_t j = 0; j < c2_layer.hashes.size(); ++j)
                MDEBUG("Hash idx: " << (j + c2_layer.start_idx) << " , hash: "
                    << fcmp::tower_cycle::selene::SELENE.to_string(c2_layer.hashes[j]));

            ++c2_idx;
        }
        else
        {
            CHECK_AND_ASSERT_THROW_MES(c1_idx < c1_extensions.size(), "unexpected c1 layer");

            const fcmp::curve_trees::LayerExtension<fcmp::tower_cycle::helios::Helios> &c1_layer = c1_extensions[c1_idx];
            MDEBUG("Helios tree extension start idx: " << c1_layer.start_idx);

            for (std::size_t j = 0; j < c1_layer.hashes.size(); ++j)
                MDEBUG("Hash idx: " << (j + c1_layer.start_idx) << " , hash: "
                    << fcmp::tower_cycle::helios::HELIOS.to_string(c1_layer.hashes[j]));

            ++c1_idx;
        }

        use_c2 = !use_c2;
    }
}

static void log_tree(const fcmp::curve_trees::Tree<fcmp::tower_cycle::helios::Helios, fcmp::tower_cycle::selene::Selene> &tree)
{
    MDEBUG("Tree has " << tree.leaves.size() << " leaves, "
        << tree.c1_layers.size() << " helios layers, " <<  tree.c2_layers.size() << " selene layers");

    for (std::size_t i = 0; i < tree.leaves.size(); ++i)
    {
        const auto &leaf = tree.leaves[i];

        const auto O_x = fcmp::tower_cycle::selene::SELENE.to_string(leaf.O_x);
        const auto I_x = fcmp::tower_cycle::selene::SELENE.to_string(leaf.I_x);
        const auto C_x = fcmp::tower_cycle::selene::SELENE.to_string(leaf.C_x);

        MDEBUG("Leaf idx " << i << " : { O_x: " << O_x << " , I_x: " << I_x << " , C_x: " << C_x << " }");
    }

    bool use_c2 = true;
    std::size_t c1_idx = 0;
    std::size_t c2_idx = 0;
    for (std::size_t i = 0; i < (tree.c1_layers.size() + tree.c2_layers.size()); ++i)
    {
        if (use_c2)
        {
            CHECK_AND_ASSERT_THROW_MES(c2_idx < tree.c2_layers.size(), "unexpected c2 layer");

            const fcmp::curve_trees::Layer<fcmp::tower_cycle::selene::Selene> &c2_layer = tree.c2_layers[c2_idx];
            MDEBUG("Selene layer size: " << c2_layer.size() << " , tree layer: " << i);

            for (std::size_t j = 0; j < c2_layer.size(); ++j)
                MDEBUG("Hash idx: " << j << " , hash: " << fcmp::tower_cycle::selene::SELENE.to_string(c2_layer[j]));

            ++c2_idx;
        }
        else
        {
            CHECK_AND_ASSERT_THROW_MES(c1_idx < tree.c1_layers.size(), "unexpected c1 layer");

            const fcmp::curve_trees::Layer<fcmp::tower_cycle::helios::Helios> &c1_layer = tree.c1_layers[c1_idx];
            MDEBUG("Helios layer size: " << c1_layer.size() << " , tree layer: " << i);

            for (std::size_t j = 0; j < c1_layer.size(); ++j)
                MDEBUG("Hash idx: " << j << " , hash: " << fcmp::tower_cycle::helios::HELIOS.to_string(c1_layer[j]));

            ++c1_idx;
        }

        use_c2 = !use_c2;
    }
}

static void log_last_chunks(const fcmp::curve_trees::LastChunks<fcmp::tower_cycle::helios::Helios, fcmp::tower_cycle::selene::Selene> &last_chunks)
{
    const auto &c1_last_chunks = last_chunks.c1_last_chunks;
    const auto &c2_last_chunks = last_chunks.c2_last_chunks;

    MDEBUG("Total of " << c1_last_chunks.size() << " Helios last chunks and "
        << c2_last_chunks.size() << " Selene last chunks");

    bool use_c2 = true;
    std::size_t c1_idx = 0;
    std::size_t c2_idx = 0;
    for (std::size_t i = 0; i < (c1_last_chunks.size() + c2_last_chunks.size()); ++i)
    {
        if (use_c2)
        {
            CHECK_AND_ASSERT_THROW_MES(c2_idx < c2_last_chunks.size(), "unexpected c2 layer");

            const fcmp::curve_trees::LastChunkData<fcmp::tower_cycle::selene::Selene> &last_chunk = c2_last_chunks[c2_idx];

            MDEBUG("child_offset: "         << last_chunk.child_offset
                << " , last_child: "        << fcmp::tower_cycle::selene::SELENE.to_string(last_chunk.last_child)
                << " , last_parent: "       << fcmp::tower_cycle::selene::SELENE.to_string(last_chunk.last_parent)
                << " , child_layer_size: "  << last_chunk.child_layer_size
                << " , parent_layer_size: " << last_chunk.parent_layer_size);

            ++c2_idx;
        }
        else
        {
            CHECK_AND_ASSERT_THROW_MES(c1_idx < c1_last_chunks.size(), "unexpected c1 layer");

            const fcmp::curve_trees::LastChunkData<fcmp::tower_cycle::helios::Helios> &last_chunk = c1_last_chunks[c1_idx];

            MDEBUG("child_offset: "         << last_chunk.child_offset
                << " , last_child: "        << fcmp::tower_cycle::helios::HELIOS.to_string(last_chunk.last_child)
                << " , last_parent: "       << fcmp::tower_cycle::helios::HELIOS.to_string(last_chunk.last_parent)
                << " , child_layer_size: "  << last_chunk.child_layer_size
                << " , parent_layer_size: " << last_chunk.parent_layer_size);

            ++c1_idx;
        }

        use_c2 = !use_c2;
    }
}

TEST(curve_trees, grow_tree)
{
    const std::vector<std::size_t> N_LEAVES{
        1,
        2,
        3,
        fcmp::tower_cycle::selene::SELENE.WIDTH - 1,
        fcmp::tower_cycle::selene::SELENE.WIDTH,
        fcmp::tower_cycle::selene::SELENE.WIDTH + 1,
        (std::size_t)std::pow(fcmp::tower_cycle::selene::SELENE.WIDTH, 2) - 1,
        (std::size_t)std::pow(fcmp::tower_cycle::selene::SELENE.WIDTH, 2),
        (std::size_t)std::pow(fcmp::tower_cycle::selene::SELENE.WIDTH, 2) + 1,
        (std::size_t)std::pow(fcmp::tower_cycle::selene::SELENE.WIDTH, 3),
        (std::size_t)std::pow(fcmp::tower_cycle::selene::SELENE.WIDTH, 4)
    };

    for (const std::size_t init_leaves : N_LEAVES)
    {
        for (const std::size_t ext_leaves : N_LEAVES)
        {
            MDEBUG("Adding " << init_leaves << " leaves to tree, then extending by " << ext_leaves << " leaves");

            fcmp::curve_trees::Tree<fcmp::tower_cycle::helios::Helios, fcmp::tower_cycle::selene::Selene> global_tree;

            // TODO: use a class that's initialized with the curve cycle and don't need to call templated functions with curve instances every time

            // Initially extend global tree by `init_leaves`
            {
                MDEBUG("Adding " << init_leaves << " leaves to tree");

                const auto tree_extension = fcmp::curve_trees::get_tree_extension<fcmp::tower_cycle::helios::Helios, fcmp::tower_cycle::selene::Selene>(
                    fcmp::curve_trees::LastChunks<fcmp::tower_cycle::helios::Helios, fcmp::tower_cycle::selene::Selene>{},
                    generate_leaves<fcmp::tower_cycle::selene::Selene>(fcmp::tower_cycle::selene::SELENE, init_leaves),
                    fcmp::tower_cycle::helios::HELIOS,
                    fcmp::tower_cycle::selene::SELENE);

                log_tree_extension(tree_extension);

                fcmp::curve_trees::extend_tree<fcmp::tower_cycle::helios::Helios, fcmp::tower_cycle::selene::Selene>(
                    tree_extension,
                    fcmp::tower_cycle::helios::HELIOS,
                    fcmp::tower_cycle::selene::SELENE,
                    global_tree);

                log_tree(global_tree);

                const bool validated = fcmp::curve_trees::validate_tree<fcmp::tower_cycle::helios::Helios, fcmp::tower_cycle::selene::Selene>(
                    global_tree,
                    fcmp::tower_cycle::helios::HELIOS,
                    fcmp::tower_cycle::selene::SELENE);

                ASSERT_TRUE(validated);

                MDEBUG("Successfully added initial " << init_leaves << " leaves to tree");
            }

            // Then extend the global tree again by `ext_leaves`
            {
                MDEBUG("Extending tree by " << ext_leaves << " leaves");

                const auto last_chunks = fcmp::curve_trees::get_last_chunks<fcmp::tower_cycle::helios::Helios, fcmp::tower_cycle::selene::Selene>(
                    fcmp::tower_cycle::helios::HELIOS,
                    fcmp::tower_cycle::selene::SELENE,
                    global_tree);

                log_last_chunks(last_chunks);

                const auto tree_extension = fcmp::curve_trees::get_tree_extension<fcmp::tower_cycle::helios::Helios, fcmp::tower_cycle::selene::Selene>(
                    last_chunks,
                    generate_leaves<fcmp::tower_cycle::selene::Selene>(fcmp::tower_cycle::selene::SELENE, ext_leaves),
                    fcmp::tower_cycle::helios::HELIOS,
                    fcmp::tower_cycle::selene::SELENE);

                log_tree_extension(tree_extension);

                fcmp::curve_trees::extend_tree<fcmp::tower_cycle::helios::Helios, fcmp::tower_cycle::selene::Selene>(
                    tree_extension,
                    fcmp::tower_cycle::helios::HELIOS,
                    fcmp::tower_cycle::selene::SELENE,
                    global_tree);

                log_tree(global_tree);

                const bool validated = fcmp::curve_trees::validate_tree<fcmp::tower_cycle::helios::Helios, fcmp::tower_cycle::selene::Selene>(
                    global_tree,
                    fcmp::tower_cycle::helios::HELIOS,
                    fcmp::tower_cycle::selene::SELENE);

                ASSERT_TRUE(validated);

                MDEBUG("Successfully extended by " << ext_leaves << " leaves");
            }
        }
    }
}
