// Copyright (c) 2024, The Monero Project
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

#pragma once

#include "common/threadpool.h"
#include "common/unordered_containers_boost_serialization.h"
#include "curve_trees.h"
#include "fcmp_pp_types.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"
#include "serialization/pair.h"
#include "serialization/serialization.h"

#include <boost/serialization/deque.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/version.hpp>

#include <deque>
#include <memory>
#include <mutex>
#include <unordered_map>


namespace fcmp_pp
{
namespace curve_trees
{
//----------------------------------------------------------------------------------------------------------------------
static constexpr int BLINDS_CACHE_VERSION = 0;
//----------------------------------------------------------------------------------------------------------------------
struct OutputBlinds final
{
    FcmpRerandomizedOutputCompressed rerandomized_output;

    std::shared_ptr<OutputBlind> blinded_o_blind;
    std::shared_ptr<OutputBlind> blinded_i_blind;
    std::shared_ptr<OutputBlind> blinded_i_blind_blind;
    std::shared_ptr<OutputBlind> blinded_c_blind;
};

struct SerializableOutputBlinds final
{
    SerializableRerandomizedOutput rerandomized_output;

    OutputBlind blinded_o_blind;
    OutputBlind blinded_i_blind;
    OutputBlind blinded_i_blind_blind;
    OutputBlind blinded_c_blind;

    template <class Archive>
    inline void serialize(Archive &a, const unsigned int ver)
    {
        a & rerandomized_output;
        a & blinded_o_blind;
        a & blinded_i_blind;
        a & blinded_i_blind_blind;
        a & blinded_c_blind;
    }

    BEGIN_SERIALIZE_OBJECT()
        FIELD(rerandomized_output)
        FIELD(blinded_o_blind)
        FIELD(blinded_i_blind)
        FIELD(blinded_i_blind_blind)
        FIELD(blinded_c_blind)
    END_SERIALIZE()
};
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
class BlindsCache final
{
public:
    BlindsCache(std::shared_ptr<CurveTrees<C1, C2>> curve_trees,
        // Start with the expected n layers in the mainnet tree (curve_trees->n_layers(300000000))
        const uint8_t init_n_layers = 6,
        // Start by being immediately prepared for a complete tx
        const std::size_t prepare_n_min_inputs = FCMP_PLUS_PLUS_MAX_INPUTS):
            m_curve_trees{curve_trees},
            m_n_tree_layers{init_n_layers},
            m_prepare_n_min_inputs{prepare_n_min_inputs},
            // Use a new threadpool instance so that it does not interfere with scanner
            m_tpool{tools::threadpool::getNewInstance()},
            m_waiter{*m_tpool}
    {};

    ~BlindsCache();

    void set_n_tree_layers(uint8_t n_tree_layers);

    void add_output(const OutputPair &output);

    // Determines how many branch blinds we need and submits the branch calculation tasks to the threadpool
    void calc_needed_branch_blinds_async();

    uint8_t *get_output_blinds(const OutputPair &output, FcmpRerandomizedOutputCompressed &rerandomized_output_out);

    std::vector<const uint8_t *> get_c1_branch_blinds(uint8_t n_layers, uint8_t n_inputs);
    std::vector<const uint8_t *> get_c2_branch_blinds(uint8_t n_layers, uint8_t n_inputs);

    void clear();

// Internal helper functions
private:
    std::shared_ptr<OutputBlind> get_blinded_o_blind_async(const SeleneScalar o_blind);
    std::shared_ptr<OutputBlind> get_blinded_i_blind_async(const SeleneScalar i_blind);
    std::shared_ptr<OutputBlind> get_blinded_i_blind_blind_async(const SeleneScalar i_blind_blind);
    std::shared_ptr<OutputBlind> get_blinded_c_blind_async(const SeleneScalar c_blind);

    std::shared_ptr<BranchBlind> get_c1_branch_blind_async();
    std::shared_ptr<BranchBlind> get_c2_branch_blind_async();

    void export_serializable_members(std::unordered_map<OutputPairRef, SerializableOutputBlinds> &output_blinds_out,
        std::vector<BranchBlind> &c1_branch_blinds_out,
        std::vector<BranchBlind> &c2_branch_blinds_out);

    void import_serializable_members(std::unordered_map<OutputPairRef, SerializableOutputBlinds> &&output_blinds,
        std::vector<BranchBlind> &&c1_branch_blinds,
        std::vector<BranchBlind> &&c2_branch_blinds);

// State held in memory
private:
    std::mutex m_mutex;

    uint8_t m_n_tree_layers;

    std::unordered_map<OutputPairRef, OutputBlinds> m_output_blindings;

    std::deque<std::shared_ptr<BranchBlind>> m_pending_c1_branch_blinds;
    std::deque<std::shared_ptr<BranchBlind>> m_pending_c2_branch_blinds;

// Config
private:
    std::shared_ptr<CurveTrees<C1, C2>> m_curve_trees;
    const std::size_t m_prepare_n_min_inputs;

    std::shared_ptr<tools::threadpool> m_tpool;
    tools::threadpool::waiter m_waiter;

// Serialization
public:
    template <class Archive>
    inline void serialize(Archive &a, const unsigned int ver)
    {
        std::unordered_map<OutputPairRef, SerializableOutputBlinds> output_blinds;
        std::vector<BranchBlind> c1_branch_blinds;
        std::vector<BranchBlind> c2_branch_blinds;

        if (typename Archive::is_saving())
           this->export_serializable_members(output_blinds, c1_branch_blinds, c2_branch_blinds);

        a & output_blinds;
        a & c1_branch_blinds;
        a & c2_branch_blinds;

        if (!typename Archive::is_saving())
            this->import_serializable_members(std::move(output_blinds),
                std::move(c1_branch_blinds),
                std::move(c2_branch_blinds));
    }

    BEGIN_SERIALIZE_OBJECT()
        VERSION_FIELD(BLINDS_CACHE_VERSION)

        std::unordered_map<OutputPairRef, SerializableOutputBlinds> output_blinds;
        std::vector<BranchBlind> c1_branch_blinds;
        std::vector<BranchBlind> c2_branch_blinds;

        if (typename Archive<W>::is_saving())
            this->export_serializable_members(output_blinds, c1_branch_blinds, c2_branch_blinds);

        FIELD(output_blinds)
        FIELD(c1_branch_blinds)
        FIELD(c2_branch_blinds)

        if (!typename Archive<W>::is_saving())
            this->import_serializable_members(std::move(output_blinds),
                std::move(c1_branch_blinds),
                std::move(c2_branch_blinds));

    END_SERIALIZE()
};

using BlindsCacheV1 = BlindsCache<Selene, Helios>;

//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
}//namespace curve_trees
}//namespace fcmp_pp

// Since BOOST_CLASS_VERSION does not work for templated class, implement it
namespace boost
{
namespace serialization
{
template<typename C1, typename C2>
struct version<fcmp_pp::curve_trees::BlindsCache<C1, C2>>
{
    typedef mpl::int_<fcmp_pp::curve_trees::BLINDS_CACHE_VERSION> type;
    typedef mpl::integral_c_tag tag;
    static constexpr int value = version::type::value;
    BOOST_MPL_ASSERT((
        boost::mpl::less<
            boost::mpl::int_<fcmp_pp::curve_trees::BLINDS_CACHE_VERSION>,
            boost::mpl::int_<256>
        >
    ));
};
}
}
