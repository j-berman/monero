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

#include "blinds_cache.h"

#include "prove.h"


namespace fcmp_pp
{
namespace curve_trees
{
//----------------------------------------------------------------------------------------------------------------------
static std::size_t n_c1_branch_blinds_needed_per_input(const uint8_t n_tree_layers)
{
    if (n_tree_layers == 0)
        return 0;

    const std::size_t n_c1_layers = (n_tree_layers + 1) / 2;
    const bool is_c1_root = (n_tree_layers % 2) != 0;

    // We exclude the root
    CHECK_AND_ASSERT_THROW_MES(n_c1_layers > 0, "unexpected 0 n_c1_layers");
    return is_c1_root ? (n_c1_layers - 1) : n_c1_layers;
}
//----------------------------------------------------------------------------------------------------------------------
static std::size_t n_c2_branch_blinds_needed_per_input(const uint8_t n_tree_layers)
{
    if (n_tree_layers == 0)
        return 0;

    const std::size_t n_c2_layers = n_tree_layers / 2;
    const bool is_c2_root = (n_tree_layers % 2) == 0;

    // We exclude the root
    CHECK_AND_ASSERT_THROW_MES(n_c2_layers > 0 || !is_c2_root, "unexpected 0 n_c2_layers");
    return is_c2_root ? (n_c2_layers - 1) : n_c2_layers;
}
//----------------------------------------------------------------------------------------------------------------------
static bool need_more_c1_blinds(const std::size_t prepare_n_min_inputs,
    const std::size_t n_inputs,
    const uint8_t n_tree_layers,
    const std::size_t n_c1_branch_blinds)
{
    const std::size_t n_needed = (prepare_n_min_inputs + n_inputs) * n_c1_branch_blinds_needed_per_input(n_tree_layers);
    return n_c1_branch_blinds < n_needed;
}
//----------------------------------------------------------------------------------------------------------------------
static bool need_more_c2_blinds(const std::size_t prepare_n_min_inputs,
    const std::size_t n_inputs,
    const uint8_t n_tree_layers,
    const std::size_t n_c2_branch_blinds)
{
    const std::size_t n_needed = (prepare_n_min_inputs + n_inputs) * n_c2_branch_blinds_needed_per_input(n_tree_layers);
    return n_c2_branch_blinds < n_needed;
}
//----------------------------------------------------------------------------------------------------------------------
static std::vector<const uint8_t *> get_branch_blinds(std::mutex &mutex,
    const std::size_t n_needed,
    std::deque<std::shared_ptr<PendingBlind>> &global_pending_blinds,
    std::function<std::shared_ptr<PendingBlind>(void)> get_branch_blind_async,
    tools::threadpool::waiter &waiter)
{
    std::lock_guard<std::mutex> guard(mutex);

    std::vector<std::shared_ptr<PendingBlind>> pending_blinds;

    // Collect the pending blinds from the queue
    while (pending_blinds.size() < n_needed && global_pending_blinds.size())
    {
        pending_blinds.push_back(global_pending_blinds.front());

        // Remove from the global pending queue so no other callers will use it, maximizing safety (one-time use)
        global_pending_blinds.pop_front();
    }

    // Calculate more blinds if we need to
    while (pending_blinds.size() < n_needed)
        pending_blinds.push_back(get_branch_blind_async());

    CHECK_AND_ASSERT_THROW_MES(waiter.wait(), "Failed waiting on branch blinds");

    // Collect the resulting branch blinds
    std::vector<const uint8_t *> branch_blinds;
    branch_blinds.reserve(pending_blinds.size());
    for (auto &pending_blind : pending_blinds)
        branch_blinds.push_back(std::move(pending_blind->result));

    return branch_blinds;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
BlindsCache<C1, C2>::~BlindsCache()
{
    try
    {
        // Wait for all tasks to finish
        LOG_PRINT_L2("Destructing Blinds Cache");
        CHECK_AND_ASSERT_THROW_MES(m_mutex.try_lock(), "Failed to acquire blinds cache mutex");
        CHECK_AND_ASSERT_THROW_MES(m_waiter.wait(), "Failed to wait for blinds cache tasks");
        LOG_PRINT_L2("Finished destructing Blinds Cache");
    }
    catch (...)
    {}
}

template BlindsCache<Selene, Helios>::~BlindsCache();
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
void BlindsCache<C1, C2>::set_n_tree_layers(uint8_t n_tree_layers)
{
    bool increased = false;
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        increased = n_tree_layers > m_n_tree_layers;
        m_n_tree_layers = n_tree_layers;
    }

    // If we increased n tree layers, we want to prepare more branch blinds
    if (increased)
        this->calc_needed_branch_blinds_async();
}

template void BlindsCache<Selene, Helios>::set_n_tree_layers(uint8_t n_tree_layers);
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
void BlindsCache<C1, C2>::add_output(const OutputPair &output)
{
    std::lock_guard<std::mutex> guard(m_mutex);

    const auto output_ref = get_output_ref(output);
    if (m_output_blindings.find(output_ref) != m_output_blindings.end())
        return;

    // Re-randomize the output
    const auto output_tuple = output_to_tuple(output);
    auto rerandomized_output = rerandomize_output(output_tuple.to_output_bytes());

    // Prepare the output blindings for calculating
    SeleneScalar o_blind = fcmp_pp::o_blind(rerandomized_output);
    SeleneScalar i_blind = fcmp_pp::i_blind(rerandomized_output);
    SeleneScalar i_blind_blind = fcmp_pp::i_blind_blind(rerandomized_output);
    SeleneScalar c_blind = fcmp_pp::c_blind(rerandomized_output);

    m_output_blindings[output_ref] = PendingOutputBlinds{
            .rerandomized_output = std::move(rerandomized_output),

            .blinded_o_blind = get_blinded_o_blind_async(o_blind),
            .blinded_i_blind = get_blinded_i_blind_async(i_blind),
            .blinded_i_blind_blind = get_blinded_i_blind_blind_async(i_blind_blind),
            .blinded_c_blind = get_blinded_c_blind_async(c_blind)
        };
}

// Explicit instantiation
template void BlindsCache<Selene, Helios>::add_output(const OutputPair &output);
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
uint8_t *BlindsCache<C1, C2>::get_output_blinds(const OutputPair &output,
    FcmpRerandomizedOutputCompressed &rerandomized_output_out)
{
    std::lock_guard<std::mutex> guard(m_mutex);

    const auto output_ref = get_output_ref(output);
    // In theory we could call add_output() if the cache does not know about the output, but the code presently expects
    // the caller to knowingly call add_output() very early to maximize efficiency.
    CHECK_AND_ASSERT_THROW_MES(m_output_blindings.find(output_ref) != m_output_blindings.end(), "missing output");

    CHECK_AND_ASSERT_THROW_MES(m_waiter.wait(), "Failed waiting for output blinds");

    CHECK_AND_ASSERT_THROW_MES(m_output_blindings.find(output_ref) != m_output_blindings.end(), "missing output2");
    const auto &output_bindings = m_output_blindings[output_ref];
    rerandomized_output_out = output_bindings.rerandomized_output;
    return fcmp_pp::output_blinds_new(
            output_bindings.blinded_o_blind->result,
            output_bindings.blinded_i_blind->result,
            output_bindings.blinded_i_blind_blind->result,
            output_bindings.blinded_c_blind->result
        );
}

template uint8_t *BlindsCache<Selene, Helios>::get_output_blinds(const OutputPair &output,
    FcmpRerandomizedOutputCompressed &rerandomized_output_out);
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
std::vector<const uint8_t *> BlindsCache<C1, C2>::get_c1_branch_blinds(uint8_t n_layers, uint8_t n_inputs)
{
    // See how many branch blinds we will need to respond with
    const std::size_t n_needed = n_inputs * n_c1_branch_blinds_needed_per_input(n_layers);

    // Custom function to submit a task to get another c1 branch blind
    const auto get_branch_blind_async = [this]() -> std::shared_ptr<PendingBlind>
    {
        return this->get_c1_branch_blind_async();
    };

    const auto c1_branch_blinds = get_branch_blinds(m_mutex,
        n_needed,
        m_pending_c1_branch_blinds,
        get_branch_blind_async,
        m_waiter);

    return c1_branch_blinds;
}

template std::vector<const uint8_t *> BlindsCache<Selene, Helios>::get_c1_branch_blinds(uint8_t n_layers,
    uint8_t n_inputs);
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
std::vector<const uint8_t *> BlindsCache<C1, C2>::get_c2_branch_blinds(uint8_t n_layers, uint8_t n_inputs)
{
    // See how many branch blinds we will need to respond with
    const std::size_t n_needed = n_inputs * n_c2_branch_blinds_needed_per_input(n_layers);

    // Custom function to submit a task to get another c2 branch blind
    const auto get_branch_blind_async = [this]() -> std::shared_ptr<PendingBlind>
    {
       return this->get_c2_branch_blind_async();
    };

    const auto c2_branch_blinds = get_branch_blinds(m_mutex,
        n_needed,
        m_pending_c2_branch_blinds,
        get_branch_blind_async,
        m_waiter);

    return c2_branch_blinds;
}

template std::vector<const uint8_t *> BlindsCache<Selene, Helios>::get_c2_branch_blinds(uint8_t n_layers,
    uint8_t n_inputs);
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
void BlindsCache<C1, C2>::clear()
{
    std::lock_guard<std::mutex> guard(m_mutex);

    CHECK_AND_ASSERT_THROW_MES(m_waiter.wait(), "Failed waiting on tasks to clear");

    // Clear the output bindings
    m_output_blindings.clear();

    // Keep the min branch blinds
    const std::size_t n_c1_branch_blinds = m_pending_c1_branch_blinds.size();
    const std::size_t n_c2_branch_blinds = m_pending_c2_branch_blinds.size();

    const std::size_t n_c1_needed = m_prepare_n_min_inputs * n_c1_branch_blinds_needed_per_input(m_n_tree_layers);
    const std::size_t n_c2_needed = m_prepare_n_min_inputs * n_c2_branch_blinds_needed_per_input(m_n_tree_layers);

    if (n_c1_branch_blinds > n_c1_needed)
        m_pending_c1_branch_blinds.resize(n_c1_needed);
    if (n_c2_branch_blinds > n_c2_needed)
        m_pending_c2_branch_blinds.resize(n_c2_needed);
}

template void BlindsCache<Selene, Helios>::clear();
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
void BlindsCache<C1, C2>::calc_needed_branch_blinds_async()
{
    std::lock_guard<std::mutex> guard(m_mutex);

    while (true)
    {
        const std::size_t n_c1_branch_blinds = m_pending_c1_branch_blinds.size();
        const std::size_t n_c2_branch_blinds = m_pending_c2_branch_blinds.size();

        // Check if we need to calculate more branch blinds
        if (need_more_c1_blinds(m_prepare_n_min_inputs, m_output_blindings.size(), m_n_tree_layers, n_c1_branch_blinds))
        {
            // Calculate c1 branch blind in the background
            m_pending_c1_branch_blinds.push_back(this->get_c1_branch_blind_async());
            continue;
        }

        if (need_more_c2_blinds(m_prepare_n_min_inputs, m_output_blindings.size(), m_n_tree_layers, n_c2_branch_blinds))
        {
            // Calculate c1 branch blind in the background
            m_pending_c2_branch_blinds.push_back(this->get_c2_branch_blind_async());
            continue;
        }

        break;
    }
}

template void BlindsCache<Selene, Helios>::calc_needed_branch_blinds_async();
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// TODO: macro the below
template<typename Selene, typename Helios>
std::shared_ptr<PendingBlind> BlindsCache<Selene, Helios>::get_c1_branch_blind_async()
{
    std::shared_ptr<PendingBlind> pending_branch_blind = std::make_shared<PendingBlind>();

    m_tpool->submit(&m_waiter,
        [pending_branch_blind]()
        {
            // Do the expensive calculation
            pending_branch_blind->result = fcmp_pp::selene_branch_blind();
        },
        true);

    return pending_branch_blind;
}
//----------------------------------------------------------------------------------------------------------------------
template<typename Selene, typename Helios>
std::shared_ptr<PendingBlind> BlindsCache<Selene, Helios>::get_c2_branch_blind_async()
{
    std::shared_ptr<PendingBlind> pending_branch_blind = std::make_shared<PendingBlind>();

    m_tpool->submit(&m_waiter,
        [pending_branch_blind]()
        {
            // Do the expensive calculation
            pending_branch_blind->result = fcmp_pp::helios_branch_blind();
        },
        true);

    return pending_branch_blind;
}
//----------------------------------------------------------------------------------------------------------------------
template<typename Selene, typename Helios>
std::shared_ptr<PendingBlind> BlindsCache<Selene, Helios>::get_blinded_o_blind_async(const SeleneScalar o_blind)
{
    std::shared_ptr<PendingBlind> pending_o_blind = std::make_shared<PendingBlind>();

    m_tpool->submit(&m_waiter,
        [pending_o_blind, o_blind]()
        {
            // Do the expensive calculation
            pending_o_blind->result = fcmp_pp::blind_o_blind(o_blind);
        },
        true);

    return pending_o_blind;
}
//----------------------------------------------------------------------------------------------------------------------
template<typename Selene, typename Helios>
std::shared_ptr<PendingBlind> BlindsCache<Selene, Helios>::get_blinded_i_blind_async(const SeleneScalar i_blind)
{
    std::shared_ptr<PendingBlind> pending_i_blind = std::make_shared<PendingBlind>();

    m_tpool->submit(&m_waiter,
        [pending_i_blind, i_blind]()
        {
            // Do the expensive calculation
            pending_i_blind->result = fcmp_pp::blind_i_blind(i_blind);
        },
        true);

    return pending_i_blind;
}
//----------------------------------------------------------------------------------------------------------------------
template<typename Selene, typename Helios>
std::shared_ptr<PendingBlind> BlindsCache<Selene, Helios>::get_blinded_i_blind_blind_async(
    const SeleneScalar i_blind_blind)
{
    std::shared_ptr<PendingBlind> pending_i_blind_blind = std::make_shared<PendingBlind>();

    m_tpool->submit(&m_waiter,
        [pending_i_blind_blind, i_blind_blind]()
        {
            // Do the expensive calculation
            pending_i_blind_blind->result = fcmp_pp::blind_i_blind_blind(i_blind_blind);
        },
        true);

    return pending_i_blind_blind;
}
//----------------------------------------------------------------------------------------------------------------------
template<typename Selene, typename Helios>
std::shared_ptr<PendingBlind> BlindsCache<Selene, Helios>::get_blinded_c_blind_async(const SeleneScalar c_blind)
{
    std::shared_ptr<PendingBlind> pending_c_blind = std::make_shared<PendingBlind>();

    m_tpool->submit(&m_waiter,
        [pending_c_blind, c_blind]()
        {
            // Do the expensive calculation
            pending_c_blind->result = fcmp_pp::blind_c_blind(c_blind);
        },
        true);

    return pending_c_blind;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
}//namespace curve_trees
}//namespace fcmp_pp
