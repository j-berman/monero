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
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool is_legacy_record(const ContextualRecordVariant &contextual_enote_record)
{
    return contextual_enote_record.is_type<LegacyContextualEnoteRecordV1>();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool is_sp_record(const ContextualRecordVariant &contextual_enote_record)
{
    return contextual_enote_record.is_type<SpContextualEnoteRecordV1>();
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
rct::xmr_amount fee_of_last_record_of_type(const input_set_tracker_t &input_set,
    const InputSelectionType type,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs)
{
    if (count_records(input_set, type) == 0)
        return -1;

    const std::size_t num_legacy_inputs_initial{count_records(added_inputs_inout, InputSelectionType::LEGACY)};
    const std::size_t num_sp_inputs_initial{count_records(added_inputs_inout, InputSelectionType::SERAPHIS)};
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
rct::xmr_amount fee_of_replacing_record(const input_set_tracker_t &input_set,
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
            count_records(added_inputs_inout, InputSelectionType::LEGACY) - (removed_type_is_legacy ? 1 : 0)
        };
    const std::size_t num_sp_inputs_removed{
            count_records(added_inputs_inout, InputSelectionType::SERAPHIS) - (!removed_type_is_legacy ? 1 : 0)
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
                    added_inputs_inout.at(InputSelectionType::LEGACY).front().first
                };

            if (last_legacy_input_fee >= last_legacy_input_amount)
            {
                auto worst_legacy_input = added_inputs_inout[InputSelectionType::LEGACY].extract(last_legacy_input_amount);
                added_inputs_inout[InputSelectionType::LEGACY].insert(std::move(worst_legacy_input));
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
                    added_inputs_inout.at(InputSelectionType::SERAPHIS).front().first
                };

            if (last_seraphis_input_fee >= last_seraphis_input_amount)
            {
                auto worst_seraphis_input =
                    added_inputs_inout[InputSelectionType::SERAPHIS].extract(last_seraphis_input_amount);
                added_inputs_inout[InputSelectionType::SERAPHIS].insert(std::move(worst_seraphis_input));
            }
        }
    } while (previous_total_inputs > total_inputs(added_inputs_inout));

    return total_inputs(added_inputs_inout) != total_inputs_initial;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_replace_excluded_v1(input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &excluded_inputs_inout)
{
    // fail if no added or excluded inputs
    if (total_inputs(added_inputs_inout) == 0 ||
        total_inputs(excluded_inputs_inout) == 0)
        return false;

    // search for the best solution when removing one added input and adding one excluded input
    struct InputSelectionTypePair
    {
        InputSelectionType added;
        InputSelectionType excluded;
    };

    boost::optional<InputSelectionTypePair> best_combination;

    for (const InputSelectionTypePair test_combination :
        {
            {InputSelectionType::LEGACY, InputSelectionType::LEGACY},
            {InputSelectionType::LEGACY, InputSelectionType::SERAPHIS},
            {InputSelectionType::SERAPHIS, InputSelectionType::LEGACY},
            {InputSelectionType::SERAPHIS, InputSelectionType::SERAPHIS}
        })
    {
        // skip if combination isn't possible
        if (count_records(added_inputs_inout, test_combination.added) == 0 ||
            count_records(excluded_inputs_inout, test_combination.excluded) == 0)
            continue;

        // differential fee from removing lowest-amount added
        const boost::multiprecision::uint128_t differential_fee_replaceable{
                fee_of_last_record_of_type(added_inputs_inout,
                    test_combination.added,
                    fee_per_tx_weight,
                    tx_fee_calculator,
                    num_outputs)
            };

        // differential fee from adding highest-amount excluded after added is removed
        const boost::multiprecision::uint128_t differential_fee_candidate{
                fee_of_replacing_record(added_inputs_inout,
                    test_combination.added,
                    test_combination.excluded,
                    fee_per_tx_weight,
                    tx_fee_calculator,
                    num_outputs)
            };

        // if this combination is worse than the last, ignore it
        //   replaceable_amnt - added_fee >= candidate_amnt - candidate_fee
        //   replaceable_amnt + candidate_fee >= candidate_amnt + added_fee     (no overflow on subtraction)
        if (added_inputs_inout.at(test_combination.added).front().first + differential_fee_candidate >=
            excluded_inputs_inout.at(test_combination.excluded).back().first + differential_fee_replaceable)
            continue;

        // save this combination (it's the best so far)
        best_combination = test_combination;
    }

    // fail if we found no good combinations
    if (!best_combination)
        return false;

    // swap
    auto worst_added_input =
        added_inputs_inout[best_combination.added].extract(added_inputs_inout[best_combination.added].begin());
    auto best_excluded_input =
        excluded_inputs_inout[best_combination.excluded].extract(excluded_inputs_inout[best_combination.excluded].rbegin());

    added_inputs_inout[best_combination.excluded].insert(std::move(best_excluded_input));
    excluded_inputs_inout[best_combination.added].insert(std::move(worst_added_input));

    return true;
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

    // current tx fee
    const std::size_t num_legacy_inputs_current{count_records(added_inputs_inout, InputSelectionType::LEGACY)};
    const std::size_t num_sp_inputs_current{count_records(added_inputs_inout, InputSelectionType::SERAPHIS)};
    const rct::xmr_amount current_fee{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs_current,
                num_sp_inputs_current,
                num_outputs)
        };

    // next tx fee (from adding the frontmost excluded input)
    const bool next_excluded_is_legacy{is_legacy_record(excluded_inputs_inout.front())};
    const rct::xmr_amount next_fee{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs_current + (next_excluded_is_legacy ? 1 : 0),
                num_sp_inputs_current + (!next_excluded_is_legacy ? 1 : 0),
                num_outputs)
        };

    // use the highest excluded input if it exceeds the differential fee from adding it
    CHECK_AND_ASSERT_THROW_MES(next_fee >= current_fee,
        "updating an input set (add excluded): next fee is less than current fee (bug).");

    if (excluded_inputs_inout.front().get_amount() <= next_fee - current_fee)
        return false;

    added_inputs_inout.splice(added_inputs_inout.end(), excluded_inputs_inout, excluded_inputs_inout.begin());

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_selection_v1(const boost::multiprecision::uint128_t output_amount,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &excluded_inputs_inout)
{
    // current legacy record counts
    std::size_t num_legacy_inputs{count_records(added_inputs_inout, InputSelectionType::LEGACY)};
    std::size_t num_sp_inputs{count_records(added_inputs_inout, InputSelectionType::SERAPHIS)};
    const rct::xmr_amount initial_fee{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs,
                num_sp_inputs,
                num_outputs)
        };

    // reference amounts for input selection algorithm
    boost::multiprecision::uint128_t comparison_amount{0};
    const boost::multiprecision::uint128_t selection_amount{output_amount + initial_fee};

    // if added inputs are full, remove the lowest-amount input temporarily
    // - a new input will have to exceed the differential amount of that input
    bool trying_to_replace_last_added_input{false};

    if (total_inputs(added_inputs_inout) == max_inputs_allowed &&
        max_inputs_allowed > 0)
    {
        trying_to_replace_last_added_input = true;

        if (is_legacy_record(added_inputs_inout.back()))
            --num_legacy_inputs;
        else
            --num_sp_inputs;

        const rct::xmr_amount last_input_fee{
                tx_fee_calculator.get_fee(fee_per_tx_weight,
                    num_legacy_inputs,
                    num_sp_inputs,
                    num_outputs)
            };

        CHECK_AND_ASSERT_THROW_MES(initial_fee >= last_input_fee,
            "updating an input set (selection): fee higher after removing last added input (bug).");
        CHECK_AND_ASSERT_THROW_MES(added_inputs_inout.back().get_amount() >= last_input_fee,
            "updating an input set (selection): last input has lower amount than its differential fee, which is a case "
            "that should be prevented by another input set updating filter (bug).");

        comparison_amount = added_inputs_inout.back().get_amount() - (initial_fee - last_input_fee);
    }

    // fee to use for input selection
    const rct::xmr_amount fee_pre_selection{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs,
                num_sp_inputs,
                num_outputs)
        };

    // try to get a new input from the selector until we run out of inputs or find one that will improve our amount total
    ContextualRecordVariant requested_input;

    // - fail if we can't select even one input
    if (!input_selector.try_select_input_v1(selection_amount, added_inputs_inout, excluded_inputs_inout, requested_input))
        return false;

    // - search for an input that can be used immediately; shunt failures into the exclude pile so they can be examined later
    do
    {
        const bool new_input_is_legacy{is_legacy_record(requested_input)};
        const rct::xmr_amount new_input_fee{
                tx_fee_calculator.get_fee(fee_per_tx_weight,
                    num_legacy_inputs + (new_input_is_legacy ? 1 : 0),
                    num_sp_inputs + (!new_input_is_legacy ? 1 : 0),
                    num_outputs)
            };

        CHECK_AND_ASSERT_THROW_MES(new_input_fee >= fee_pre_selection,
            "updating an input set (selection): fee lower after adding new input (bug).");

        // new input can't be used if it's amount doesn't exceed its fee
        if (requested_input.get_amount() <= (new_input_fee - fee_pre_selection))
        {
            excluded_inputs_inout.emplace_back(requested_input);
        }
        // if requested input can cover the comparison amount, add it to the added inputs list
        else if (requested_input.get_amount() - (new_input_fee - fee_pre_selection) > comparison_amount)
        {
            // remove last added input if we are replacing it here
            if (trying_to_replace_last_added_input)
                added_inputs_inout.pop_back();

            added_inputs_inout.emplace_back(std::move(requested_input));
            break;  //done searching
        }
        // otherwise, add it to the excluded list
        else
        {
            excluded_inputs_inout.emplace_back(requested_input);  //don't move - requested_input may be used again later
        }
    } while (input_selector.try_select_input_v1(selection_amount,
        added_inputs_inout,
        excluded_inputs_inout,
        requested_input));

    // return true even if no inputs were added, because we have at least increased the excluded inputs pile, which can
    //   be examined later to possibly improve the added inputs set
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
    // expect the added inputs list is not full
    if (total_inputs(added_inputs_inout) >= max_inputs_allowed)
        return false;

    // current tx fee
    std::size_t num_legacy_inputs{count_records(added_inputs_inout, InputSelectionType::LEGACY)};
    std::size_t num_sp_inputs{count_records(added_inputs_inout, InputSelectionType::SERAPHIS)};
    const rct::xmr_amount current_fee{
            tx_fee_calculator.get_fee(fee_per_tx_weight,
                num_legacy_inputs,
                num_sp_inputs,
                num_outputs)
        };

    // try to add a range of excluded inputs
    boost::multiprecision::uint128_t range_sum{0};
    std::size_t range_size{0};

    for (auto exclude_it = excluded_inputs_inout.begin(); exclude_it != excluded_inputs_inout.end(); ++exclude_it)
    {
        range_sum += exclude_it->get_amount();
        ++range_size;

        // we have failed if our range exceeds the input limit
        if (total_inputs(added_inputs_inout) + range_size > max_inputs_allowed)
            return false;

        // total fee including this range of inputs
        if (is_legacy_record(*exclude_it))
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
            added_inputs_inout.splice(added_inputs_inout.end(),
                excluded_inputs_inout,
                excluded_inputs_inout.begin(),
                std::next(exclude_it));

            return true;
        }
    }

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

    // update the input set until the output amount + fee is satisfied (or updating fails)
    input_set_tracker_t added_inputs;
    input_set_tracker_t excluded_inputs;

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
        if (try_update_added_inputs_replace_excluded_v1(added_inputs, excluded_inputs))
            continue;

        // 4. try to add the best excluded input to the added inputs set
        if (try_update_added_inputs_add_excluded_v1(max_inputs_allowed,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                excluded_inputs))
            continue;

        // 5. try to get a new input that can get us closer to a solution
        if (try_update_added_inputs_selection_v1(output_amount,
                max_inputs_allowed,
                input_selector,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                excluded_inputs))
            continue;

        // 6. try to use a range of excluded inputs to get us closer to a solution
        if (try_update_added_inputs_range_v1(max_inputs_allowed,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                excluded_inputs))
            continue;

        // 6. no attempts to update the added inputs worked, so we have failed
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
