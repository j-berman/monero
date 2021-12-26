// Copyright (c) 2014-2020, The Monero Project
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

#include <boost/range/adaptor/transformed.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem/path.hpp>
#include "common/command_line.h"
#include "common/varint.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/blockchain.h"
#include "blockchain_db/blockchain_db.h"
#include "version.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bcutil"

namespace po = boost::program_options;
using namespace epee;
using namespace cryptonote;

const uint64_t START_HEIGHT = 2508000;
const uint64_t END_HEIGHT = 2522940; // core_storage->get_current_blockchain_height() - 1;

const uint64_t MIN_OUTPUT_AGE = 3 * 720; // 60 * 720;
const uint64_t OUTPUT_AGE_DIFF = 60; // 2 * 720;

#define GAMMA_SHAPE 19.28
#define GAMMA_SCALE (1/1.61)
#define DEFAULT_UNLOCK_TIME (CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE * DIFFICULTY_TARGET_V2)
#define RECENT_SPEND_WINDOW_v17_3_0 (15 * DIFFICULTY_TARGET_V2)
#define RECENT_SPEND_WINDOW_v17_2_3 (50 * DIFFICULTY_TARGET_V2)

#define v17_3_0 1
#define v17_2_3 2
#define pre_v17_2_3 3
#define mymonero_monero_lws 4

std::gamma_distribution<double> gamma_dist = std::gamma_distribution<double>(GAMMA_SHAPE, GAMMA_SCALE);
const size_t blocks_in_a_year = 86400 * 365 / DIFFICULTY_TARGET_V2;

struct gamma_engine
{
  typedef uint64_t result_type;
  static constexpr result_type min() { return 0; }
  static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }
  result_type operator()() { return crypto::rand<result_type>(); }
} engine;

uint64_t get_output_age(std::vector<uint64_t> &output_heights, uint64_t output_index, uint64_t blockchain_height, std::string tx_hash = "")
{
  if (output_index >= output_heights.size())
    throw std::logic_error("output_index not found " + std::to_string(output_index) + " " + std::to_string(output_heights.size()));

  uint64_t output_height = output_heights[output_index];
  uint64_t output_age = blockchain_height - output_height;

  // sanity checks
  if ((output_index == 40408 && output_height != 1227180) ||
      (output_index == 27478088 && output_height != 2300000) ||
      (output_index == 45373870 && output_height != 2522238))
    throw std::logic_error("Failed output height sanity check...");

  if (output_index == 35468500 && output_age != 10 && tx_hash == "41526a1870bb3e92735b69989d782044029a4375915b11b6664f2754481a7dea")
    throw std::logic_error("Failed output age sanity check...");

  return output_age;
};

uint64_t gamma_pick(std::vector<uint64_t> &output_heights, std::vector<uint64_t> &rct_offsets, uint64_t rct_offsets_start_height, uint64_t blockchain_height, size_t version)
{
  size_t rct_offset_index_for_current_height = blockchain_height - rct_offsets_start_height;
  const size_t blocks_to_consider = std::min<size_t>(rct_offset_index_for_current_height, blocks_in_a_year);
  const size_t outputs_to_consider = rct_offsets[rct_offset_index_for_current_height] - (blocks_to_consider < rct_offset_index_for_current_height ? rct_offsets[rct_offset_index_for_current_height - blocks_to_consider - 1] : 0);

  uint64_t num_rct_outputs;
  switch (version)
  {
    case v17_3_0:
    case v17_2_3:
    case pre_v17_2_3:
      num_rct_outputs = rct_offsets[rct_offset_index_for_current_height - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE];
      break;
    case mymonero_monero_lws:
      num_rct_outputs = rct_offsets[rct_offset_index_for_current_height];
      break;
    default:
      throw std::runtime_error("Unknown version");
      break;
  };

  double average_output_time;
  switch (version)
  {
    case v17_3_0:
    case mymonero_monero_lws:
      average_output_time = DIFFICULTY_TARGET_V2 * blocks_to_consider / static_cast<double>(outputs_to_consider);
      break;
    case v17_2_3:
    case pre_v17_2_3:
      average_output_time = DIFFICULTY_TARGET_V2 * blocks_to_consider / outputs_to_consider;
      break;
    default:
      throw std::runtime_error("Unknown version");
      break;
  };

  double x = gamma_dist(engine);
  x = exp(x);
  switch (version)
  {
    case v17_3_0:
    case v17_2_3:
      if (x > DEFAULT_UNLOCK_TIME)
        x -= DEFAULT_UNLOCK_TIME;
      else
        x = crypto::rand_idx(static_cast<uint64_t>(version == v17_3_0 ? RECENT_SPEND_WINDOW_v17_3_0 : RECENT_SPEND_WINDOW_v17_2_3));
      break;
    case pre_v17_2_3:
    case mymonero_monero_lws:
      break;
    default:
      throw std::runtime_error("Unknown version");
      break;
  };

  uint64_t output_index = x / average_output_time;
  if (output_index >= num_rct_outputs)
    return gamma_pick(output_heights, rct_offsets, rct_offsets_start_height, blockchain_height, version); // bad pick
  output_index = num_rct_outputs - 1 - output_index;

  uint64_t output_age = get_output_age(output_heights, output_index, blockchain_height);

  if (output_age < CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE)
  {
    if (version == mymonero_monero_lws)
      return gamma_pick(output_heights, rct_offsets, rct_offsets_start_height, blockchain_height, version); // bad pick
    else
      throw std::logic_error("Should never be younger than unlock time in non-MyMonero/monero-lws versions");
  }

  return output_age;
};

std::vector<uint64_t> set_output_heights(std::vector<uint64_t> &rct_offsets, uint64_t rct_offsets_start_height)
{
  std::vector<uint64_t> output_heights;
  output_heights.reserve(rct_offsets[rct_offsets.size() - 1]);

  uint64_t start = 0;
  for (uint64_t i = 0; i < rct_offsets.size(); ++i)
  {
    uint64_t end = rct_offsets[i];
    while (start < end)
    {
      output_heights.push_back(rct_offsets_start_height + i);
      ++start;
    }
  }

  // if ((output_heights[40408] != 1227180) ||
  //   (output_heights[27478088] != 2300000) ||
  //   (output_heights[45373870] != 2522238) ||
  //   (output_heights[45317542] != 2521386) ||
  //   (output_heights[45317542] != output_heights[45317541]) ||
  //   (output_heights[45317542] != output_heights[45317477]))
  //   throw std::logic_error("Failed output height sanity check...");

  return output_heights;
}

int main(int argc, char* argv[])
{
  TRY_ENTRY();

  epee::string_tools::set_module_name_and_folder(argv[0]);

  uint32_t log_level = 0;

  tools::on_startup();

  boost::filesystem::path output_file_path;

  po::options_description desc_cmd_only("Command line options");
  po::options_description desc_cmd_sett("Command line options and settings options");
  const command_line::arg_descriptor<std::string> arg_log_level  = {"log-level",  "0-4 or categories", ""};
  const command_line::arg_descriptor<bool> arg_rct_only  = {"rct-only", "Only work on ringCT outputs", false};
  const command_line::arg_descriptor<std::string> arg_input = {"input", ""};

  command_line::add_arg(desc_cmd_sett, cryptonote::arg_testnet_on);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_stagenet_on);
  command_line::add_arg(desc_cmd_sett, arg_log_level);
  command_line::add_arg(desc_cmd_sett, arg_rct_only);
  command_line::add_arg(desc_cmd_sett, arg_input);
  command_line::add_arg(desc_cmd_only, command_line::arg_help);

  po::options_description desc_options("Allowed options");
  desc_options.add(desc_cmd_only).add(desc_cmd_sett);

  po::positional_options_description positional_options;
  positional_options.add(arg_input.name, -1);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    auto parser = po::command_line_parser(argc, argv).options(desc_options).positional(positional_options);
    po::store(parser.run(), vm);
    po::notify(vm);
    return true;
  });
  if (! r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << "Monero '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
    std::cout << desc_options << std::endl;
    return 1;
  }

  mlog_configure(mlog_get_default_log_path("monero-blockchain-usage.log"), true);
  if (!command_line::is_arg_defaulted(vm, arg_log_level))
    mlog_set_log(command_line::get_arg(vm, arg_log_level).c_str());
  else
    mlog_set_log(std::string(std::to_string(log_level) + ",bcutil:INFO").c_str());

  LOG_PRINT_L0("Starting...");

  bool opt_testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
  bool opt_stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
  network_type net_type = opt_testnet ? TESTNET : opt_stagenet ? STAGENET : MAINNET;
  bool opt_rct_only = command_line::get_arg(vm, arg_rct_only);

  // If we wanted to use the memory pool, we would set up a fake_core.

  // Use Blockchain instead of lower-level BlockchainDB for two reasons:
  // 1. Blockchain has the init() method for easy setup
  // 2. exporter needs to use get_current_blockchain_height(), get_block_id_by_height(), get_block_by_hash()
  //
  // cannot match blockchain_storage setup above with just one line,
  // e.g.
  //   Blockchain* core_storage = new Blockchain(NULL);
  // because unlike blockchain_storage constructor, which takes a pointer to
  // tx_memory_pool, Blockchain's constructor takes tx_memory_pool object.
  LOG_PRINT_L0("Initializing source blockchain (BlockchainDB)");
  const std::string input = command_line::get_arg(vm, arg_input);
  std::unique_ptr<Blockchain> core_storage;
  tx_memory_pool m_mempool(*core_storage);
  core_storage.reset(new Blockchain(m_mempool));
  BlockchainDB* db = new_db();
  if (db == NULL)
  {
    LOG_ERROR("Failed to initialize a database");
    throw std::runtime_error("Failed to initialize a database");
  }
  LOG_PRINT_L0("database: LMDB");

  const std::string filename = input;
  LOG_PRINT_L0("Loading blockchain from folder " << filename << " ...");

  try
  {
    db->open(filename, DBF_RDONLY);
  }
  catch (const std::exception& e)
  {
    LOG_PRINT_L0("Error opening database: " << e.what());
    return 1;
  }
  r = core_storage->init(db, net_type);

  CHECK_AND_ASSERT_MES(r, 1, "Failed to initialize source blockchain storage");
  LOG_PRINT_L0("Source blockchain storage initialized OK");

  LOG_PRINT_L0("Building usage patterns...");

  size_t done = 0;
  std::unordered_map<uint64_t,uint64_t> indices;

  LOG_PRINT_L0("Reading blockchain from " << input);

  LOG_PRINT_L0("Loading rct_offsets...");
  uint64_t amount = 0;
  uint64_t from_height = 0;
  uint64_t return_height = 0;
  std::vector<uint64_t> rct_offsets;
  uint64_t base = 0;
  core_storage->get_output_distribution(amount, from_height, END_HEIGHT, return_height, rct_offsets, base);
  uint64_t rct_offsets_start_height = END_HEIGHT - rct_offsets.size() + 1;
  LOG_PRINT_L0("Finished loading rct_offsets... ");

  LOG_PRINT_L0("Setting output_heights to speed things up...");
  std::vector<uint64_t> output_heights = set_output_heights(rct_offsets, rct_offsets_start_height);
  LOG_PRINT_L0("Finished setting output_heights...");

  uint64_t count_2_input_txes_total = 0;
  uint64_t count_2_input_txes_observed = 0;

  uint64_t count_2_input_txes_wallet2_v17_3_0 = 0;
  uint64_t count_2_input_txes_wallet2_v17_2_3 = 0;
  uint64_t count_2_input_txes_wallet2_pre_v17_2_3 = 0;
  uint64_t count_2_input_txes_mymonero_monero_lws = 0;

  LOG_PRINT_L0("Minimum output age: " << MIN_OUTPUT_AGE << ", Maximum output age difference: " << OUTPUT_AGE_DIFF);
  uint64_t range_start_height = START_HEIGHT;
  uint64_t next_log = range_start_height;
  while (range_start_height < END_HEIGHT)
  {
    size_t min_block_count = 0;
    size_t max_block_count = 1000;
    size_t max_tx_count = max_block_count * 100;
    size_t max_size = (100*1024*1024); // 100 MB
    bool pruned = true;
    bool skip_coinbase = true;
    bool get_miner_tx_hash = false;

    std::vector<std::pair<std::pair<cryptonote::blobdata, crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::blobdata>>>> blocks;
    core_storage->get_db().get_blocks_from(range_start_height, min_block_count, max_block_count, max_tx_count, max_size, blocks, pruned, skip_coinbase, get_miner_tx_hash);
    if (!blocks.size())
      break;

    // iterate over every tx in every block
    uint64_t blk_no = range_start_height;
    for (const auto &blk : blocks)
    {
      uint64_t LOG_INTERVAL = 1000;
      if (blk_no % LOG_INTERVAL == 0)
      {
        double percent_observed = count_2_input_txes_observed > 0 ? 100 * (double) count_2_input_txes_observed / count_2_input_txes_total : 0;

        double percent_expected_v17_3_0 = count_2_input_txes_observed > 0 ? 100 * (double) count_2_input_txes_wallet2_v17_3_0 / count_2_input_txes_total : 0;
        double percent_expected_v17_2_3 = count_2_input_txes_observed > 0 ? 100 * (double) count_2_input_txes_wallet2_v17_2_3 / count_2_input_txes_total : 0;
        double percent_expected_pre_v17_2_3 = count_2_input_txes_observed > 0 ? 100 * (double) count_2_input_txes_wallet2_pre_v17_2_3 / count_2_input_txes_total : 0;
        double percent_expected_mymonero_monero_lws = count_2_input_txes_observed > 0 ? 100 * (double) count_2_input_txes_mymonero_monero_lws / count_2_input_txes_total : 0;

        LOG_PRINT_L0("Reading blocks " << blk_no << " - " << std::min(blk_no + LOG_INTERVAL, END_HEIGHT) << " (observed: " << percent_observed << "%, v17.3.0: " << percent_expected_v17_3_0 << "%, v17.2.3: " <<  percent_expected_v17_2_3 << "%, pre v17.2.3: " << percent_expected_pre_v17_2_3 << "%, MyMonero+monero-lws: " << percent_expected_mymonero_monero_lws << "%)");
      }

      for (const auto &tx_blob : blk.second)
      {
        cryptonote::transaction tx;
        if (!parse_and_validate_tx_base_from_blob(tx_blob.second, tx))
          throw std::runtime_error("Messed up parsing");

        // only care about 2-input tx's for this analysis
        if (tx.vin.size() == 2)
        {
          if (tx.vin[0].type() != typeid(txin_to_key) || tx.vin[1].type() != typeid(txin_to_key))
            continue;
          const auto &txin0 = boost::get<txin_to_key>(tx.vin[0]);
          const auto &txin1 = boost::get<txin_to_key>(tx.vin[1]);
          if (txin0.amount != 0 || txin1.amount != 0)
            continue;
          if (txin0.key_offsets.size() != 11 || txin1.key_offsets.size() != 11)
            continue;

          std::string tx_hash = epee::string_tools::pod_to_hex(tx_blob.first);
          ++count_2_input_txes_total;

          /**
           *
           *
           * Check if observed ring 1 has output older than X blocks old, and ring 2 has output within Y blocks of that output.
           *
           *
          */
          const std::vector<uint64_t> actual_absolute0 = cryptonote::relative_output_offsets_to_absolute(txin0.key_offsets);
          const std::vector<uint64_t> actual_absolute1 = cryptonote::relative_output_offsets_to_absolute(txin1.key_offsets);

          // iterate over each ring member of actual ring 1
          for (size_t i = 0; i < txin0.key_offsets.size(); ++i)
          {
            uint64_t output_age0 = get_output_age(output_heights, actual_absolute0[i], blk_no, tx_hash);

            // only care about outputs that are older than X blocks old
            if (output_age0 >= MIN_OUTPUT_AGE)
            {
              // iterate over each ring member of ring 1
              for (size_t j = 0; j < txin1.key_offsets.size(); ++j)
              {
                uint64_t output_age1 = get_output_age(output_heights, actual_absolute1[j], blk_no, tx_hash);

                if (std::abs((double) output_age0 - (double) output_age1) <= OUTPUT_AGE_DIFF)
                {
                  ++count_2_input_txes_observed;

                  // manually break for loops
                  j = txin1.key_offsets.size();
                  i = txin0.key_offsets.size();
                }
              }
            }
          }

          /**
           *
           *
           * v17.3.0 gamma selection algorithm
           *
           *
          */
          // now gamma select outputs for every input, and check the gammas
          std::vector<uint64_t> expected_absolute0;
          std::vector<uint64_t> expected_absolute1;
          for (size_t i = 0; i < txin0.key_offsets.size(); ++i)
          {
            expected_absolute0.push_back(gamma_pick(output_heights, rct_offsets, rct_offsets_start_height, blk_no, v17_3_0));
            expected_absolute1.push_back(gamma_pick(output_heights, rct_offsets, rct_offsets_start_height, blk_no, v17_3_0));
          }

          // iterate over each ring member of expected ring 1
          for (size_t i = 0; i < txin0.key_offsets.size(); ++i)
          {
            uint64_t expected_output_age0 = expected_absolute0[i];

            // only care about outputs that are older than X blocks old
            if (expected_output_age0 >= MIN_OUTPUT_AGE)
            {
              // iterate over each ring member of ring 1
              for (size_t j = 0; j < txin1.key_offsets.size(); ++j)
              {
                uint64_t expected_output_age1 = expected_absolute1[j];

                if (std::abs((double) expected_output_age0 - (double) expected_output_age1) <= OUTPUT_AGE_DIFF)
                {
                  ++count_2_input_txes_wallet2_v17_3_0;

                  // manually break for loops
                  j = txin1.key_offsets.size();
                  i = txin0.key_offsets.size();
                }

              }
            }
          }

          /**
           *
           *
           * v17.2.3
           *
           *
          */
          // now gamma select outputs for every input, and check the gammas
          std::vector<uint64_t> v17_2_3_abs0;
          std::vector<uint64_t> v17_2_3_abs1;
          for (size_t i = 0; i < txin0.key_offsets.size(); ++i)
          {
            v17_2_3_abs0.push_back(gamma_pick(output_heights, rct_offsets, rct_offsets_start_height, blk_no, v17_2_3));
            v17_2_3_abs1.push_back(gamma_pick(output_heights, rct_offsets, rct_offsets_start_height, blk_no, v17_2_3));
          }

          // iterate over each ring member of expected ring 1
          for (size_t i = 0; i < txin0.key_offsets.size(); ++i)
          {
            uint64_t expected_output_age0 = v17_2_3_abs0[i];

            // only care about outputs that are older than X blocks old
            if (expected_output_age0 >= MIN_OUTPUT_AGE)
            {
              // iterate over each ring member of ring 1
              for (size_t j = 0; j < txin1.key_offsets.size(); ++j)
              {
                uint64_t expected_output_age1 = v17_2_3_abs1[j];

                if (std::abs((double) expected_output_age0 - (double) expected_output_age1) <= OUTPUT_AGE_DIFF)
                {
                  ++count_2_input_txes_wallet2_v17_2_3;

                  // manually break for loops
                  j = txin1.key_offsets.size();
                  i = txin0.key_offsets.size();
                }

              }
            }
          }

          /**
           *
           *
           * pre v17.2.3
           *
           *
          */
          // now gamma select outputs for every input, and check the gammas
          std::vector<uint64_t> pre_v17_2_3_abs0;
          std::vector<uint64_t> pre_v17_2_3_abs1;
          for (size_t i = 0; i < txin0.key_offsets.size(); ++i)
          {
            pre_v17_2_3_abs0.push_back(gamma_pick(output_heights, rct_offsets, rct_offsets_start_height, blk_no, pre_v17_2_3));
            pre_v17_2_3_abs1.push_back(gamma_pick(output_heights, rct_offsets, rct_offsets_start_height, blk_no, pre_v17_2_3));
          }

          // iterate over each ring member of expected ring 1
          for (size_t i = 0; i < txin0.key_offsets.size(); ++i)
          {
            uint64_t expected_output_age0 = pre_v17_2_3_abs0[i];

            // only care about outputs that are older than X blocks old
            if (expected_output_age0 >= MIN_OUTPUT_AGE)
            {
              // iterate over each ring member of ring 1
              for (size_t j = 0; j < txin1.key_offsets.size(); ++j)
              {
                uint64_t expected_output_age1 = pre_v17_2_3_abs1[j];

                if (std::abs((double) expected_output_age0 - (double) expected_output_age1) <= OUTPUT_AGE_DIFF)
                {
                  ++count_2_input_txes_wallet2_pre_v17_2_3;

                  // manually break for loops
                  j = txin1.key_offsets.size();
                  i = txin0.key_offsets.size();
                }

              }
            }
          }

          /**
           *
           *
           * MyMonero+monero-lws
           *
           *
          */
          // now gamma select outputs for every input, and check the gammas
          std::vector<uint64_t> mymonero_monero_lws_abs0;
          std::vector<uint64_t> mymonero_monero_lws_abs1;
          for (size_t i = 0; i < txin0.key_offsets.size(); ++i)
          {
            mymonero_monero_lws_abs0.push_back(gamma_pick(output_heights, rct_offsets, rct_offsets_start_height, blk_no, mymonero_monero_lws));
            mymonero_monero_lws_abs1.push_back(gamma_pick(output_heights, rct_offsets, rct_offsets_start_height, blk_no, mymonero_monero_lws));
          }

          // iterate over each ring member of expected ring 1
          for (size_t i = 0; i < txin0.key_offsets.size(); ++i)
          {
            uint64_t expected_output_age0 = mymonero_monero_lws_abs0[i];

            // only care about outputs that are older than X blocks old
            if (expected_output_age0 >= MIN_OUTPUT_AGE)
            {
              // iterate over each ring member of ring 1
              for (size_t j = 0; j < txin1.key_offsets.size(); ++j)
              {
                uint64_t expected_output_age1 = mymonero_monero_lws_abs1[j];

                if (std::abs((double) expected_output_age0 - (double) expected_output_age1) <= OUTPUT_AGE_DIFF)
                {
                  ++count_2_input_txes_mymonero_monero_lws;

                  // manually break for loops
                  j = txin1.key_offsets.size();
                  i = txin0.key_offsets.size();
                }

              }
            }
          }
        }
      }
      blk_no += 1;
      if (blk_no >= END_HEIGHT)
        break;
    }

    range_start_height += blocks.size();
  }

  LOG_PRINT_L0("Count of 2 input txes total: " << count_2_input_txes_total);

  LOG_PRINT_L0("Count of 2 input txes observed: " << count_2_input_txes_observed << " (" << 100 * (double) count_2_input_txes_observed / count_2_input_txes_total << "%)");

  LOG_PRINT_L0("Count of 2 input txes v17.3.0 expected: " << count_2_input_txes_wallet2_v17_3_0 << " (" << 100 * (double) count_2_input_txes_wallet2_v17_3_0 / count_2_input_txes_total << "%)");
  LOG_PRINT_L0("Count of 2 input txes v17.2.3 expected: " << count_2_input_txes_wallet2_v17_2_3 << " (" <<  100 *(double) count_2_input_txes_wallet2_v17_2_3 / count_2_input_txes_total << "%)");
  LOG_PRINT_L0("Count of 2 input txes pre v17.2.3 expected: " << count_2_input_txes_wallet2_pre_v17_2_3 << " (" << 100 * (double) count_2_input_txes_wallet2_pre_v17_2_3 / count_2_input_txes_total << "%)");
  LOG_PRINT_L0("Count of 2 input txes MyMonero + monero-lws expected: " << count_2_input_txes_mymonero_monero_lws << " (" << 100 * (double) count_2_input_txes_mymonero_monero_lws / count_2_input_txes_total << "%)");

  LOG_PRINT_L0("Blockchain usage exported OK");
  return 0;

  CATCH_ENTRY("Export error", 1);
}
