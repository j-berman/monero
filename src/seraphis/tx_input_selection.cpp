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

// NOT FOR PRODUCTION

//paired header
#include "tx_input_selection.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "tx_contextual_enote_record_types.h"
#include "tx_fee_calculator.h"
#include "tx_input_selection_output_context.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <algorithm>
#include <iterator>
#include <list>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{

struct InputSelectionTypePair
{
    InputSelectionType added;
    InputSelectionType excluded;
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static InputSelectionType input_selection_type(const ContextualRecordVariant &contextual_enote_record)
{
    if (contextual_enote_record.is_type<LegacyContextualEnoteRecordV1>())
        return InputSelectionType::LEGACY;
    else
        return InputSelectionType::SERAPHIS;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::size_t count_records(const input_set_tracker_t &input_set, const InputSelectionType type)
{
    if (input_set.find(type) == input_set.end())
        return 0;

    return input_set.at(type).size();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::size_t total_inputs(const input_set_tracker_t &input_set)
{
    return count_records(input_set, InputSelectionType::LEGACY) + count_records(input_set, InputSelectionType::SERAPHIS);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static boost::multiprecision::uint128_t compute_total_amount(const input_set_tracker_t &input_set)
{
    boost::multiprecision::uint128_t amount_sum{0};

    if (input_set.find(InputSelectionType::LEGACY) != input_set.end())
    {
        for (const auto &mapped_record : input_set.at(InputSelectionType::LEGACY))
            amount_sum += mapped_record.first;
    }

    if (input_set.find(InputSelectionType::SERAPHIS) != input_set.end())
    {
        for (const auto &mapped_record : input_set.at(InputSelectionType::SERAPHIS))
            amount_sum += mapped_record.first;
    }

    return amount_sum;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount fee_of_last_record_of_type(const input_set_tracker_t &input_set,
    const InputSelectionType type,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs)
{
    if (count_records(input_set, type) == 0)
        return -1;

    const std::size_t num_legacy_inputs_initial{count_records(input_set, InputSelectionType::LEGACY)};
    const std::size_t num_sp_inputs_initial{count_records(input_set, InputSelectionType::SERAPHIS)};
    const bool type_is_legacy{type == InputSelectionType::LEGACY};

    const rct::xmr_amount initial_fee{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs_initial,
                num_sp_inputs_initial,
                num_outputs)
        };
    const rct::xmr_amount fee_after_input_removed{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs_initial - (type_is_legacy ? 1 : 0),
                num_sp_inputs_initial - (!type_is_legacy ? 1 : 0),
                num_outputs)
        };

    CHECK_AND_ASSERT_THROW_MES(initial_fee >= fee_after_input_removed,
        "input selection (fee of last record of type): initial fee is lower than fee after input removed.");

    return initial_fee - fee_after_input_removed;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount fee_of_next_record_of_type(const input_set_tracker_t &input_set,
    const InputSelectionType type,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs)
{
    const std::size_t num_legacy_inputs_initial{count_records(input_set, InputSelectionType::LEGACY)};
    const std::size_t num_sp_inputs_initial{count_records(input_set, InputSelectionType::SERAPHIS)};
    const bool type_is_legacy{type == InputSelectionType::LEGACY};

    const rct::xmr_amount initial_fee{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs_initial,
                num_sp_inputs_initial,
                num_outputs)
        };
    const rct::xmr_amount fee_after_input_added{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs_initial + (type_is_legacy ? 1 : 0),
                num_sp_inputs_initial + (!type_is_legacy ? 1 : 0),
                num_outputs)
        };

    CHECK_AND_ASSERT_THROW_MES(fee_after_input_added >= initial_fee,
        "input selection (fee of next record of type): initial fee is lower than fee after input added.");

    return fee_after_input_added - initial_fee;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount fee_of_replacing_record(const input_set_tracker_t &input_set,
    const InputSelectionType type_to_remove,
    const InputSelectionType type_to_add,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs)
{
    if (count_records(input_set, type_to_remove) == 0)
        return -1;

    // calculate fee after removing an input
    const bool removed_type_is_legacy{type_to_add == InputSelectionType::LEGACY};
    const std::size_t num_legacy_inputs_removed{
            count_records(input_set, InputSelectionType::LEGACY) - (removed_type_is_legacy ? 1 : 0)
        };
    const std::size_t num_sp_inputs_removed{
            count_records(input_set, InputSelectionType::SERAPHIS) - (!removed_type_is_legacy ? 1 : 0)
        };

    const rct::xmr_amount fee_after_input_removed{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs_removed,
                num_sp_inputs_removed,
                num_outputs)
        };

    // calculate fee after adding a new input (after removing one)
    const bool new_type_is_legacy{type_to_add == InputSelectionType::LEGACY};
    const rct::xmr_amount fee_after_input_added{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs_removed + (new_type_is_legacy ? 1 : 0),
                num_sp_inputs_removed + (!new_type_is_legacy ? 1 : 0),
                num_outputs)
        };

    // return the marginal fee of the new input compared to before it was added
    CHECK_AND_ASSERT_THROW_MES(new_type_is_legacy >= fee_after_input_removed,
        "input selection (fee of replacing record): new fee is lower than fee after input removed.");

    return fee_after_input_added - fee_after_input_removed;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_swap_pair_v1(const InputSelectionType added_type_to_remove,
    const InputSelectionType excluded_type_to_add,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &excluded_inputs_inout)
{
    // fail if swap isn't possible
    if (count_records(added_inputs_inout, added_type_to_remove) == 0 ||
        count_records(excluded_inputs_inout, excluded_type_to_add) == 0)
        return false;

    // differential fee from removing lowest-amount added
    const boost::multiprecision::uint128_t differential_fee_replaceable{
            fee_of_last_record_of_type(added_inputs_inout,
                added_type_to_remove,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs)
        };

    // differential fee from adding highest-amount excluded after added is removed
    const boost::multiprecision::uint128_t differential_fee_candidate{
            fee_of_replacing_record(added_inputs_inout,
                added_type_to_remove,
                excluded_type_to_add,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs)
        };

    // fail if this combination is not an improvement over the current added set
    //   replaceable_amnt - added_fee >= candidate_amnt - candidate_fee
    //   replaceable_amnt + candidate_fee >= candidate_amnt + added_fee     (no overflow on subtraction)
    const boost::multiprecision::uint128_t candidate_combination_cost{
            added_inputs_inout.at(added_type_to_remove).begin()->first + differential_fee_candidate
        };
    const boost::multiprecision::uint128_t candidate_combination_reward{
            excluded_inputs_inout.at(excluded_type_to_add).rbegin()->first + differential_fee_replaceable
        };
    if (candidate_combination_cost >= candidate_combination_reward)
        return false;

    // swap
    auto worst_added_input =
        added_inputs_inout[added_type_to_remove].extract(added_inputs_inout[added_type_to_remove].begin());
    auto best_excluded_input =
        excluded_inputs_inout[excluded_type_to_add].extract(excluded_inputs_inout[excluded_type_to_add].rbegin()->first);

    added_inputs_inout[excluded_type_to_add].insert(std::move(best_excluded_input));
    excluded_inputs_inout[added_type_to_remove].insert(std::move(worst_added_input));

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_add_inputs_range_of_type_v1(const InputSelectionType type,
    const std::size_t max_inputs_allowed,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &excluded_inputs_inout)
{
    // current tx fee
    const std::size_t initial_inputs_count{total_inputs(added_inputs_inout)};
    std::size_t num_legacy_inputs{count_records(added_inputs_inout, InputSelectionType::LEGACY)};
    std::size_t num_sp_inputs{count_records(added_inputs_inout, InputSelectionType::SERAPHIS)};
    const rct::xmr_amount current_fee{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs,
                num_sp_inputs,
                num_outputs)
        };

    boost::multiprecision::uint128_t range_sum{0};
    std::size_t range_size{0};

    for (auto exclude_it = excluded_inputs_inout[type].rbegin();
        exclude_it != excluded_inputs_inout[type].rend();
        ++exclude_it)
    {
        range_sum += exclude_it->first;
        ++range_size;

        // we have failed if our range exceeds the input limit
        if (initial_inputs_count + range_size > max_inputs_allowed)
            return false;

        // total fee including this range of inputs
        if (type == InputSelectionType::LEGACY)
            ++num_legacy_inputs;
        else
            ++num_sp_inputs;

        const rct::xmr_amount range_fee{
                tx_fee_calculator.get_fee(fee_per_tx_weight,
                    num_legacy_inputs,
                    num_sp_inputs,
                    num_outputs)
            };

        // if range of excluded inputs can cover the differential fee from those inputs, insert them
        CHECK_AND_ASSERT_THROW_MES(range_fee >= current_fee,
            "updating an input set (range): range fee is less than current fee (bug).");

        if (range_sum > range_fee - current_fee)
        {
            for (std::size_t num_moved{0}; num_moved < range_size; ++num_moved)
            {
                CHECK_AND_ASSERT_THROW_MES(excluded_inputs_inout[type].size() != 0,
                    "updating an input set (range): excluded inputs range smaller than expected (bug).");

                auto input_to_move = excluded_inputs_inout[type].extract(excluded_inputs_inout[type].rbegin()->first);
                added_inputs_inout[type].insert(std::move(input_to_move));
            }

            return true;
        }
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_exclude_useless_v1(const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &excluded_inputs_inout)
{
    // fail if no added inputs to remove
    const std::size_t total_inputs_initial{total_inputs(added_inputs_inout)};
    if (total_inputs_initial == 0)
        return false;

    // remove all useless inputs
    std::size_t previous_total_inputs;

    do
    {
        previous_total_inputs = total_inputs(added_inputs_inout);

        // exclude useless legacy input
        if (count_records(added_inputs_inout, InputSelectionType::LEGACY) > 0)
        {
            const rct::xmr_amount last_legacy_input_fee{
                    fee_of_last_record_of_type(added_inputs_inout,
                        InputSelectionType::LEGACY,
                        fee_per_tx_weight,
                        tx_fee_calculator,
                        num_outputs)
                };
            const rct::xmr_amount last_legacy_input_amount{
                    added_inputs_inout.at(InputSelectionType::LEGACY).begin()->first
                };

            if (last_legacy_input_fee >= last_legacy_input_amount)
            {
                auto worst_legacy_input = added_inputs_inout[InputSelectionType::LEGACY].extract(last_legacy_input_amount);
                excluded_inputs_inout[InputSelectionType::LEGACY].insert(std::move(worst_legacy_input));
            }
        }

        // exclude useless seraphis input
        if (count_records(added_inputs_inout, InputSelectionType::SERAPHIS) > 0)
        {
            const rct::xmr_amount last_seraphis_input_fee{
                    fee_of_last_record_of_type(added_inputs_inout,
                        InputSelectionType::SERAPHIS,
                        fee_per_tx_weight,
                        tx_fee_calculator,
                        num_outputs)
                };
            const rct::xmr_amount last_seraphis_input_amount{
                    added_inputs_inout.at(InputSelectionType::SERAPHIS).begin()->first
                };

            if (last_seraphis_input_fee >= last_seraphis_input_amount)
            {
                auto worst_seraphis_input =
                    added_inputs_inout[InputSelectionType::SERAPHIS].extract(last_seraphis_input_amount);
                excluded_inputs_inout[InputSelectionType::SERAPHIS].insert(std::move(worst_seraphis_input));
            }
        }
    } while (previous_total_inputs > total_inputs(added_inputs_inout));

    return total_inputs(added_inputs_inout) != total_inputs_initial;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_replace_excluded_v1(const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &excluded_inputs_inout)
{
    // fail if no added or excluded inputs
    if (total_inputs(added_inputs_inout) == 0 ||
        total_inputs(excluded_inputs_inout) == 0)
        return false;

    // search for the best solution when removing one added input and adding one excluded input
    bool found_replacement_combination{false};
    std::list<InputSelectionTypePair> test_combinations =
        {
            {InputSelectionType::LEGACY, InputSelectionType::LEGACY},
            {InputSelectionType::LEGACY, InputSelectionType::SERAPHIS},
            {InputSelectionType::SERAPHIS, InputSelectionType::LEGACY},
            {InputSelectionType::SERAPHIS, InputSelectionType::SERAPHIS}
        };

    for (const InputSelectionTypePair &test_combination : test_combinations)
    {
        found_replacement_combination = found_replacement_combination &&
            try_swap_pair_v1(test_combination.added,
                test_combination.excluded,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs_inout,
                excluded_inputs_inout);
    }

    // success if at least one swap occurred
    return found_replacement_combination;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_add_excluded_v1(const std::size_t max_inputs_allowed,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &excluded_inputs_inout)
{
    // expect the inputs to not be full here
    if (total_inputs(added_inputs_inout) >= max_inputs_allowed)
        return false;

    // fail if no excluded inputs available
    if (total_inputs(excluded_inputs_inout) == 0)
        return false;

    // remove all useless inputs
    const std::size_t total_inputs_initial{total_inputs(added_inputs_inout)};
    std::size_t previous_total_inputs;

    do
    {
        previous_total_inputs = total_inputs(added_inputs_inout);

        // acquire useful legacy input
        if (count_records(excluded_inputs_inout, InputSelectionType::LEGACY) > 0)
        {
            const rct::xmr_amount next_legacy_input_fee{
                    fee_of_next_record_of_type(added_inputs_inout,
                        InputSelectionType::LEGACY,
                        fee_per_tx_weight,
                        tx_fee_calculator,
                        num_outputs)
                };
            const rct::xmr_amount best_legacy_input_amount{
                    excluded_inputs_inout.at(InputSelectionType::LEGACY).rbegin()->first
                };

            if (best_legacy_input_amount > next_legacy_input_fee)
            {
                auto best_legacy_input =
                    excluded_inputs_inout[InputSelectionType::LEGACY].extract(best_legacy_input_amount);
                added_inputs_inout[InputSelectionType::LEGACY].insert(std::move(best_legacy_input));
            }
        }

        // acquire useful seraphis input
        if (count_records(excluded_inputs_inout, InputSelectionType::SERAPHIS) > 0)
        {
            const rct::xmr_amount next_seraphis_input_fee{
                    fee_of_next_record_of_type(added_inputs_inout,
                        InputSelectionType::SERAPHIS,
                        fee_per_tx_weight,
                        tx_fee_calculator,
                        num_outputs)
                };
            const rct::xmr_amount best_seraphis_input_amount{
                    excluded_inputs_inout.at(InputSelectionType::SERAPHIS).rbegin()->first
                };

            if (best_seraphis_input_amount > next_seraphis_input_fee)
            {
                auto best_seraphis_input =
                    excluded_inputs_inout[InputSelectionType::SERAPHIS].extract(best_seraphis_input_amount);
                added_inputs_inout[InputSelectionType::SERAPHIS].insert(std::move(best_seraphis_input));
            }
        }
    } while (previous_total_inputs < total_inputs(added_inputs_inout) &&
        total_inputs(added_inputs_inout) < max_inputs_allowed);

    return total_inputs(added_inputs_inout) != total_inputs_initial;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_excluded_inputs_selection_v1(const boost::multiprecision::uint128_t output_amount,
    const InputSelectorV1 &input_selector,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    const input_set_tracker_t &added_inputs,
    input_set_tracker_t &excluded_inputs_inout)
{
    // current legacy record counts
    const std::size_t num_legacy_inputs{count_records(added_inputs, InputSelectionType::LEGACY)};
    const std::size_t num_sp_inputs{count_records(added_inputs, InputSelectionType::SERAPHIS)};
    const rct::xmr_amount current_fee{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs,
                num_sp_inputs,
                num_outputs)
        };

    // reference amount for input selection algorithm
    const boost::multiprecision::uint128_t selection_amount{output_amount + current_fee};

    // try to get a new input from the selector
    ContextualRecordVariant requested_input;
    if (!input_selector.try_select_input_v1(selection_amount, added_inputs, excluded_inputs_inout, requested_input))
        return false;

    // add the new input to the excluded pile - we will try to move it into the added pile in later passthroughs
    excluded_inputs_inout[input_selection_type(requested_input)].insert({requested_input.get_amount(), requested_input});

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_range_v1(const std::size_t max_inputs_allowed,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &excluded_inputs_inout)
{
    // note: this algorithm assumes only a range of same-type inputs can produce a solution; there may be solutions
    //       created by combinations of legacy/seraphis inputs, but since discovering those is a brute force exercise,
    //       they are ignored here; in general, as seraphis enotes become relatively more common than legacy enotes, this
    //       algorithm is expected to return relatively fewer false negatives

    // expect the added inputs list is not full
    if (total_inputs(added_inputs_inout) >= max_inputs_allowed)
        return false;

    // try to add a range of excluded legacy inputs
    if (try_add_inputs_range_of_type_v1(InputSelectionType::LEGACY,
            max_inputs_allowed,
            fee_per_tx_weight,
            tx_fee_calculator,
            num_outputs,
            added_inputs_inout,
            excluded_inputs_inout))
        return true;

    // try to add a range of excluded seraphis inputs
    if (try_add_inputs_range_of_type_v1(InputSelectionType::SERAPHIS,
            max_inputs_allowed,
            fee_per_tx_weight,
            tx_fee_calculator,
            num_outputs,
            added_inputs_inout,
            excluded_inputs_inout))
        return true;

    // no luck
    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_select_inputs_v1(const boost::multiprecision::uint128_t output_amount,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &input_set_out)
{
    CHECK_AND_ASSERT_THROW_MES(max_inputs_allowed > 0, "selecting an input set: zero inputs were allowed.");
    input_set_out.clear();

    // prepare input set trackers
    input_set_tracker_t added_inputs;
    input_set_tracker_t excluded_inputs;

    added_inputs[InputSelectionType::LEGACY];
    added_inputs[InputSelectionType::SERAPHIS];
    excluded_inputs[InputSelectionType::LEGACY];
    excluded_inputs[InputSelectionType::SERAPHIS];

    // update the input set until the output amount + fee is satisfied (or updating fails)
    while (true)
    {
        // 1. try to exclude added inputs that don't pay for their differential fees
        // note: do this before checking if there is a solution to make sure useless inputs will never be returned
        if (try_update_added_inputs_exclude_useless_v1(fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                excluded_inputs))
            continue;

        // 2. check if we have a solution
        CHECK_AND_ASSERT_THROW_MES(total_inputs(added_inputs) <= max_inputs_allowed,
            "selecting an input set: there are more inputs than the number allowed (bug).");

        // a. compute current fee
        const rct::xmr_amount current_fee{
                tx_fee_calculator.get_fee(fee_per_tx_weight,
                    count_records(added_inputs, InputSelectionType::LEGACY),
                    count_records(added_inputs, InputSelectionType::SERAPHIS),
                    num_outputs)
            };

        // b. check if we have covered the required amount
        if (compute_total_amount(added_inputs) >= output_amount + current_fee)
        {
            input_set_out = std::move(added_inputs);
            return true;
        }

        // 3. try to replace an added input with a better excluded input
        if (try_update_added_inputs_replace_excluded_v1(fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                excluded_inputs))
            continue;

        // 4. try to add the best excluded input to the added inputs set
        if (try_update_added_inputs_add_excluded_v1(max_inputs_allowed,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                excluded_inputs))
            continue;

        // 5. try to select a new input that is a candidate for improving the solution
        if (try_update_excluded_inputs_selection_v1(output_amount,
                input_selector,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                excluded_inputs))
            continue;

        // 6. try to use a range of excluded inputs to get us closer to a solution
        // note: this is a an inefficient last-ditch effort, so we only attempt it after no more inputs can be selected
        if (try_update_added_inputs_range_v1(max_inputs_allowed,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                excluded_inputs))
            continue;

        // 7. no attempts to update the added inputs worked, so we have failed
        return false;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_input_set_v1(const OutputSetContextForInputSelection &output_set_context,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    rct::xmr_amount &final_fee_out,
    input_set_tracker_t &input_set_out)
{
    input_set_out.clear();

    // 1. select inputs to cover requested output amount (assume 0 change)
    const boost::multiprecision::uint128_t output_amount{output_set_context.get_total_amount()};
    const std::size_t num_outputs_nochange{output_set_context.get_num_outputs_nochange()};

    if (!try_select_inputs_v1(output_amount,
            max_inputs_allowed,
            input_selector,
            fee_per_tx_weight,
            tx_fee_calculator,
            num_outputs_nochange,
            input_set_out))
        return false;

    // 2. compute fee for selected inputs
    const std::size_t num_legacy_inputs_first_try{count_records(input_set_out, InputSelectionType::LEGACY)};
    const std::size_t num_sp_inputs_first_try{count_records(input_set_out, InputSelectionType::SERAPHIS)};
    const rct::xmr_amount zero_change_fee{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs_first_try,
                num_sp_inputs_first_try,
                num_outputs_nochange)
        };

    // 3. return if we are done (zero change is covered by input amounts) (very rare case)
    if (compute_total_amount(input_set_out) == output_amount + zero_change_fee)
    {
        final_fee_out = zero_change_fee;
        return true;
    }

    // 4. if non-zero change with computed fee, assume change must be non-zero (typical case)
    // a. update fee assuming non-zero change
    const std::size_t num_outputs_withchange{output_set_context.get_num_outputs_withchange()};
    rct::xmr_amount nonzero_change_fee{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs_first_try,
                num_sp_inputs_first_try,
                num_outputs_withchange)
        };

    CHECK_AND_ASSERT_THROW_MES(zero_change_fee <= nonzero_change_fee,
        "getting an input set: adding a change output reduced the tx fee (bug).");

    // b. if previously selected inputs are insufficient for non-zero change, select inputs again (very rare case)
    if (compute_total_amount(input_set_out) <= output_amount + nonzero_change_fee)
    {
        if (!try_select_inputs_v1(output_amount + 1,  //+1 to force a non-zero change
                max_inputs_allowed,
                input_selector,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs_withchange,
                input_set_out))
            return false;

        const std::size_t num_legacy_inputs_second_try{count_records(input_set_out, InputSelectionType::LEGACY)};
        const std::size_t num_sp_inputs_second_try{count_records(input_set_out, InputSelectionType::SERAPHIS)};
        nonzero_change_fee =
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs_second_try,
                num_sp_inputs_second_try,
                num_outputs_withchange);
    }

    // c. we are done (non-zero change is covered by input amounts)
    CHECK_AND_ASSERT_THROW_MES(compute_total_amount(input_set_out) > output_amount + nonzero_change_fee,
        "getting an input set: selecting inputs for the non-zero change amount case failed (bug).");

    final_fee_out = nonzero_change_fee;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
