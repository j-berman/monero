// Copyright (c) 2022, The Monero Project
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

// Mock-up of interface for interacting with a wallet2 instance.
// WARNING: read EVERY TODO carefully before ready for production

//local headers
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/subaddress_index.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/enote_record_utils_legacy.h"
#include "wallet2_migration.h"

//third party headers

//standard headers
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <utility>
#include <vector>

//forward declarations

// TODO: the enote store doesn't have all data to 100% match the wallet2 data store. See this issue to capture
// all data necessary to match the wallet2 data store: https://github.com/UkoeHB/monero/issues/48 

namespace sp
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
/// Helper function to set the tx prefix on each transfer record in wallet2 m_transfers container
/// Warning: the tx prefix will not necessarily match chain data. It only saves minimal data necessary for wallet2
// TODO: implement vin for watch-only wallets
static cryptonote::transaction_prefix enote_to_tx_prefix(const sp::LegacyContextualEnoteRecordV1 &enote_record,
    std::size_t &tx_pub_key_index_out)
{
    // Construct a synthetix tx prefix that has the info we'll need: the output with its pubkey, the tx pubkey in extra
    cryptonote::transaction_prefix tx = {};

    CHECK_AND_ASSERT_THROW_MES(enote_record.origin_context.enote_tx_index < 65536,
        "internal output index seems outrageously high, rejecting");

    // View tag
    bool use_view_tags = false;
    crypto::view_tag view_tag;
    if (const sp::LegacyEnoteV4 *enote_ptr = enote_record.record.enote.try_unwrap<sp::LegacyEnoteV4>())
    {
        view_tag = enote_ptr->view_tag;
        use_view_tags = true;
    }
    else if (const sp::LegacyEnoteV5 *enote_ptr = enote_record.record.enote.try_unwrap<sp::LegacyEnoteV5>())
    {
        view_tag = enote_ptr->view_tag;
        use_view_tags = true;
    }
    else
    {
        use_view_tags = false;
    }

    // Set cryptonote tx out
    cryptonote::tx_out out;
    cryptonote::set_tx_out(enote_record.record.amount,
        rct::rct2pk(sp::onetime_address_ref(enote_record.record.enote)),
        use_view_tags,
        view_tag,
        out);

    // Add the tx out to the position it should be in the vout vector
    tx.vout.resize(enote_record.origin_context.enote_tx_index);
    tx.vout.push_back(std::move(out));

    // Set the tx pubkey (WARNING: this could move an additional pub key into main tx pubkey spot)
    // TODO: I could also put the additional in its correct spot (with 0'd out additional pub keys before it)
    tx_pub_key_index_out = 0;
    cryptonote::add_tx_pub_key_to_extra(tx, rct::rct2pk(enote_record.record.enote_ephemeral_pubkey));

    tx.unlock_time = enote_record.record.unlock_time;

    // TODO: vin is left unimplemented. This is a problem for import_key_images, which uses those key images to determine spends

    return tx;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint32_t get_spending_subaddr_account(const crypto::hash &tx_hash,
    const std::unordered_multimap<crypto::hash, std::size_t> &outgoing_enotes,
    const tools::wallet2::transfer_container &transfers,
    std::set<std::uint32_t> &subaddr_indices_out)
{
    subaddr_indices_out.clear();
    std::uint32_t spending_subaddr_account = (std::uint32_t)-1;

    const auto outgoing_enote_range = outgoing_enotes.equal_range(tx_hash);
    for (auto i = outgoing_enote_range.first; i != outgoing_enote_range.second; ++i)
    {
        const std::size_t idx = i->second;
        if (spending_subaddr_account != (uint32_t)-1 && spending_subaddr_account != transfers[idx].m_subaddr_index.major)
            LOG_PRINT_L0("WARNING: This tx spends outputs received by different subaddress accounts, which isn't supposed to happen");

        subaddr_indices_out.insert(transfers[idx].m_subaddr_index.minor);
        spending_subaddr_account = transfers[idx].m_subaddr_index.major;
    }

    return spending_subaddr_account;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void SeraphisMigrationTools::import_sp_enote_record(const sp::LegacyContextualEnoteRecordV1 &legacy_enote_record,
    std::unique_ptr<tools::wallet2> &wallet2_inout,
    std::unordered_set<crypto::hash> &incoming_tx_hashes_inout,
    std::unordered_set<crypto::hash> &outgoing_tx_hashes_inout,
    std::unordered_multimap<crypto::hash, std::size_t> &incoming_enotes_inout,
    std::unordered_multimap<crypto::hash, std::size_t> &outgoing_enotes_inout)
{
    const std::size_t idx = wallet2_inout->m_transfers.size();

    // 1. m_transfers
    wallet2_inout->m_transfers.push_back(tools::wallet2::transfer_details{});
    tools::wallet2::transfer_details &td = wallet2_inout->m_transfers.back();

    td.m_block_height          = legacy_enote_record.origin_context.block_index;
    td.m_tx                    = enote_to_tx_prefix(legacy_enote_record, td.m_pk_index);
    td.m_txid                  = rct::rct2hash(legacy_enote_record.origin_context.transaction_id);
    td.m_internal_output_index = legacy_enote_record.origin_context.enote_tx_index;
    td.m_global_output_index   = legacy_enote_record.origin_context.enote_ledger_index;
    td.m_spent                 = legacy_enote_record.spent_context.spent_status != sp::SpEnoteSpentStatus::UNSPENT;
    td.m_frozen                = false; // TODO: frozen feature
    td.m_spent_height          = legacy_enote_record.spent_context.spent_status == sp::SpEnoteSpentStatus::SPENT_ONCHAIN
                                    ? legacy_enote_record.spent_context.block_index : 0;
    td.m_key_image             = sp::key_image_ref(legacy_enote_record);
    td.m_mask                  = rct::sk2rct(legacy_enote_record.record.amount_blinding_factor);
    td.m_amount                = legacy_enote_record.record.amount;
    td.m_rct                   = true; // TODO: pre-RCT
    td.m_key_image_known       = true; // TODO: watch-only, multisig, background scanning
    td.m_key_image_request     = false; // TODO: watch-only, multisig, cold wallets
    td.m_subaddr_index         = legacy_enote_record.record.address_index
                                    ? *legacy_enote_record.record.address_index
                                    : cryptonote::subaddress_index{0, 0};
    td.m_key_image_partial     = false; // TODO: multisig
    td.m_multisig_k            = std::vector<rct::key>{}; // TODO: multisig
    td.m_multisig_info         = std::vector<tools::wallet2::multisig_info>{}; // TODO: multisig
    td.m_uses                  = std::vector<std::pair<std::uint64_t, crypto::hash>>{}; // TODO: track uses

    // 2. Expand subaddresses if we should
    if (wallet2_inout->should_expand(td.m_subaddr_index))
        wallet2_inout->expand_subaddresses(td.m_subaddr_index);

    // 3. m_key_images
    wallet2_inout->m_key_images[td.m_key_image] = idx;

    // 4. m_pub_keys
    wallet2_inout->m_pub_keys[rct::rct2pk(sp::onetime_address_ref(legacy_enote_record.record.enote))] = idx;

    // 5. Collect incoming enotes for m_payments (and to know change for m_confirmed_txs)
    incoming_tx_hashes_inout.emplace(td.m_txid);
    incoming_enotes_inout.emplace(td.m_txid, idx);

    // 6. Collect outgoing enotes for m_confirmed_txs (and to know change for m_payments)
    if (td.m_spent && td.m_spent_height > 0)
    {
        crypto::hash spent_tx_hash = rct::rct2hash(legacy_enote_record.spent_context.transaction_id);
        outgoing_tx_hashes_inout.emplace(spent_tx_hash);
        outgoing_enotes_inout.emplace(spent_tx_hash, idx);
    }

    // TODO: m_unconfirmed_txs, m_unconfirmed_payments
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void SeraphisMigrationTools::import_incoming_payments(const crypto::hash &tx_hash,
    const std::unordered_multimap<crypto::hash, std::size_t> &outgoing_enotes,
    const std::unordered_multimap<crypto::hash, std::size_t> &incoming_enotes,
    const std::vector<sp::LegacyContextualEnoteRecordV1> &legacy_enote_records,
    std::unique_ptr<tools::wallet2> &wallet2_inout)
{
    // 1. Get the spending subaddr account, if there is one
    std::set<std::uint32_t> unused_subaddr_indices;
    const std::uint32_t spending_subaddr_account = get_spending_subaddr_account(tx_hash,
        outgoing_enotes,
        wallet2_inout->m_transfers,
        unused_subaddr_indices);

    // 2. Group non-change incoming enotes by subaddress
    std::unordered_set<cryptonote::subaddress_index> subaddrs;
    std::unordered_multimap<cryptonote::subaddress_index, std::size_t> received_enotes_by_subaddr_index;
    const auto incoming_enote_range = incoming_enotes.equal_range(tx_hash);
    for (auto i = incoming_enote_range.first; i != incoming_enote_range.second; ++i)
    {
        const auto &received_enote = legacy_enote_records[i->second];

        // Get the receiving subaddr index
        const cryptonote::subaddress_index subaddr_index = received_enote.record.address_index
            ? received_enote.record.address_index.get()
            : cryptonote::subaddress_index{0, 0};

        // If change, ignore it
        if (spending_subaddr_account == subaddr_index.major)
            continue;

        subaddrs.emplace(subaddr_index);
        received_enotes_by_subaddr_index.emplace(subaddr_index, i->second);
    }

    // 3. Set the incoming payments
    for (const auto &subaddr : subaddrs)
    {
        tools::wallet2::payment_details pd{};

        pd.m_tx_hash       = tx_hash;
        pd.m_subaddr_index = subaddr;

        const auto enote_range = received_enotes_by_subaddr_index.equal_range(subaddr);
        for (auto enote_idx = enote_range.first; enote_idx != enote_range.second; ++enote_idx)
        {
            const auto &received_enote = legacy_enote_records[enote_idx->second];

            pd.m_amount += received_enote.record.amount;
            pd.m_amounts.push_back(received_enote.record.amount);

            pd.m_block_height  = received_enote.origin_context.block_index;
            pd.m_unlock_time   = received_enote.record.unlock_time;
            pd.m_timestamp     = received_enote.origin_context.block_timestamp;
        }

        // TODO: m_coinbase, m_fee

        // TODO: payment_id
        crypto::hash payment_id = crypto::null_hash;

        // Done
        wallet2_inout->m_payments.emplace(payment_id, std::move(pd));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void SeraphisMigrationTools::import_outgoing_tx(const crypto::hash &tx_hash,
    const std::unordered_multimap<crypto::hash, std::size_t> &outgoing_enotes,
    const std::unordered_multimap<crypto::hash, std::size_t> &incoming_enotes,
    const std::vector<sp::LegacyContextualEnoteRecordV1> &legacy_enote_records,
    std::unique_ptr<tools::wallet2> &wallet2_inout)
{
    // 1. Get the spending subaddr account
    std::set<std::uint32_t> subaddr_indices;
    const std::uint32_t spending_subaddr_account = get_spending_subaddr_account(tx_hash,
        outgoing_enotes,
        wallet2_inout->m_transfers,
        subaddr_indices);

    CHECK_AND_ASSERT_THROW_MES(spending_subaddr_account != (std::uint32_t)-1, "spending subaddr account not set");
    CHECK_AND_ASSERT_THROW_MES(!subaddr_indices.empty(), "no subaddr indices found");

    tools::wallet2::confirmed_transfer_details ctd{};

    // 2. Set subaddr data
    ctd.m_subaddr_account = spending_subaddr_account;
    ctd.m_subaddr_indices = std::move(subaddr_indices);

    // 3. Set amount received, amount spent, and the change
    const auto incoming_enote_range = incoming_enotes.equal_range(tx_hash);
    const auto outgoing_enote_range = outgoing_enotes.equal_range(tx_hash);
    {
        // Sum the change received
        std::uint64_t change = 0;
        for (auto i = incoming_enote_range.first; i != incoming_enote_range.second; ++i)
        {
            std::size_t idx = i->second;
            const bool is_change = wallet2_inout->m_transfers[idx].m_subaddr_index.major == spending_subaddr_account;
            if (is_change)
                change += legacy_enote_records[idx].record.amount;
        }

        // Sum the outgoing enotes
        std::uint64_t amount_spent = 0;
        for (auto i = outgoing_enote_range.first; i != outgoing_enote_range.second; ++i)
            amount_spent += legacy_enote_records[i->second].record.amount;

        ctd.m_amount_in = amount_spent;
        ctd.m_amount_out = amount_spent; // - fee; // TODO: need to subtract by the fee, since m_amount_out is amount paid to counter-party in the tx
        ctd.m_change = change;
    }

    // 4. Set the spend context data
    const auto &spent_enote = legacy_enote_records[outgoing_enote_range.first->second];
    CHECK_AND_ASSERT_THROW_MES(spent_enote.spent_context.transaction_id == rct::hash2rct(tx_hash),
        "unepxected outgoing tx hash");
    ctd.m_block_height = spent_enote.spent_context.block_index;
    ctd.m_timestamp = spent_enote.spent_context.block_timestamp;

    // TODO: scanner should keep track of when sent txs will unlock, even if no change in the tx (sender might want to remember)
    ctd.m_unlock_time = incoming_enote_range.first == incoming_enote_range.second
        ? 0
        : legacy_enote_records[incoming_enote_range.first->second].record.unlock_time;

    // TODO (this is only used in Feather AFAIK: https://github.com/monero-project/monero/commit/5770265a166e4a319e53e26a2e42f41b0e13a9b0)
    ctd.m_tx = {}; 

    // TODO: keep the dests saved somewhere, they're unknown to enote store
    ctd.m_dests = {};

    // TODO: payment ID's (https://github.com/UkoeHB/monero/issues/46)
    ctd.m_payment_id = crypto::null_hash;

    // TODO: do this along with m_uses (just need to keep track of key offsets here)
    ctd.m_rings = {};

    // Done
    wallet2_inout->m_confirmed_txs.insert({tx_hash, std::move(ctd)});
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void SeraphisMigrationTools::import_sp_enote_store(const sp::SpEnoteStore &sp_enote_store,
    std::unique_ptr<tools::wallet2> &wallet2_inout)
{
    // 1. Prepare the containers
    const std::size_t num_records = sp_enote_store.legacy_records().size();
    wallet2_inout->m_transfers.reserve(num_records);
    wallet2_inout->m_key_images.reserve(num_records);
    wallet2_inout->m_pub_keys.reserve(num_records);

    // 2. Sort the legacy enote records by order they appear in the chain
    std::vector<sp::LegacyContextualEnoteRecordV1> legacy_enote_records;
    for (const auto &legacy_enote_record : sp_enote_store.legacy_records())
        legacy_enote_records.push_back(legacy_enote_record.second);
    // TODO: is_older_than should also use order of txs in the block
    std::sort(legacy_enote_records.begin(), legacy_enote_records.end(),
        [](const auto &a, const auto &b) { return is_older_than(a.origin_context, b.origin_context); });

    // 3. Set each record in the order they appear in the chain
    std::unordered_set<crypto::hash> incoming_tx_hashes;
    std::unordered_set<crypto::hash> outgoing_tx_hashes;
    std::unordered_multimap<crypto::hash, std::size_t> incoming_enotes;
    std::unordered_multimap<crypto::hash, std::size_t> outgoing_enotes;
    for (const auto &legacy_enote_record : legacy_enote_records)
    {
        import_sp_enote_record(legacy_enote_record,
            wallet2_inout,
            incoming_tx_hashes,
            outgoing_tx_hashes,
            incoming_enotes,
            outgoing_enotes);
    }

    // 4. m_payments (incoming payments that aren't change)
    for (const auto &tx_hash : incoming_tx_hashes)
    {
        import_incoming_payments(tx_hash,
            outgoing_enotes,
            incoming_enotes,
            legacy_enote_records,
            wallet2_inout);
    }

    // 5. m_confirmed_txs (outgoing spends)
    for (const auto &tx_hash : outgoing_tx_hashes)
    {
        import_outgoing_tx(tx_hash,
            outgoing_enotes,
            incoming_enotes,
            legacy_enote_records,
            wallet2_inout);
    }

    // TODO: m_blockchain (needed for adjust_priority, only need size to work correctly)

    // Note: m_tx_keys, m_additional_tx_keys, and m_dests cannot be determined when syncing. They're not kept in the
    // enote store at time of writing
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void SeraphisMigrationTools::check_wallet2_container_equality(const std::unique_ptr<tools::wallet2> &wallet2_base,
    const std::unique_ptr<tools::wallet2> &wallet2_from_enote_store)
{
    // 1. Get refs to the containers
    tools::wallet2::transfer_container                  &tc_a         = wallet2_base->m_transfers;
    tools::wallet2::transfer_container                  &tc_b         = wallet2_from_enote_store->m_transfers;
    std::unordered_map<crypto::public_key, std::size_t> &pub_keys_a   = wallet2_base->m_pub_keys;
    std::unordered_map<crypto::public_key, std::size_t> &pub_keys_b   = wallet2_from_enote_store->m_pub_keys;
    std::unordered_map<crypto::key_image, std::size_t>  &key_images_a = wallet2_base->m_key_images;
    std::unordered_map<crypto::key_image, std::size_t>  &key_images_b = wallet2_from_enote_store->m_key_images;
    tools::wallet2::payment_container                   &payments_a   = wallet2_base->m_payments;
    tools::wallet2::payment_container                   &payments_b   = wallet2_from_enote_store->m_payments;
    std::unordered_map<crypto::hash, tools::wallet2::confirmed_transfer_details> &ctxs_a = wallet2_base->m_confirmed_txs;
    std::unordered_map<crypto::hash, tools::wallet2::confirmed_transfer_details> &ctxs_b = wallet2_from_enote_store->m_confirmed_txs;

    // 2. Check container sizes
    CHECK_AND_ASSERT_THROW_MES(tc_a.size()         == tc_b.size(),         "unequal transfer container sizes");
    CHECK_AND_ASSERT_THROW_MES(pub_keys_a.size()   == tc_a.size(),         "unexpected pub key container size");
    CHECK_AND_ASSERT_THROW_MES(pub_keys_a.size()   == pub_keys_b.size(),   "unequal pub key container size");
    CHECK_AND_ASSERT_THROW_MES(key_images_a.size() == tc_a.size(),         "unexpected key image container size");
    CHECK_AND_ASSERT_THROW_MES(key_images_a.size() == key_images_b.size(), "unequal key image container size");
    // CHECK_AND_ASSERT_THROW_MES(payments_a.size()   == payments_b.size(),   "unequal payments size"); // TODO: fix payment ID handling
    CHECK_AND_ASSERT_THROW_MES(ctxs_a.size()       == ctxs_b.size(),       "unequal confirmed txs size");   

    // 3. Check container elems
    for (std::size_t i{0}; i < tc_a.size(); ++i)
    {
        // a. m_transfers
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_block_height          == tc_b[i].m_block_height,          "unequal block height");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_txid                  == tc_b[i].m_txid,                  "unequal tx ids");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_internal_output_index == tc_b[i].m_internal_output_index, "unequal internal index");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_global_output_index   == tc_b[i].m_global_output_index,   "unequal block height");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_spent                 == tc_b[i].m_spent,                 "unequal spent status");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_frozen                == tc_b[i].m_frozen,                "unequal frozen status");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_spent_height          == tc_b[i].m_spent_height,          "unequal spent height");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_key_image             == tc_b[i].m_key_image,             "unequal key images");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_mask                  == tc_b[i].m_mask,                  "unequal masks");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_amount                == tc_b[i].m_amount,                "unequal amounts");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_rct                   == tc_b[i].m_rct,                   "unequal rct flag");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_key_image_known       == tc_b[i].m_key_image_known,       "unequal key image known status");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_key_image_request     == tc_b[i].m_key_image_request,     "unequal key image request status");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_subaddr_index         == tc_b[i].m_subaddr_index,         "unequal subaddr index");
        CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_key_image_partial     == tc_b[i].m_key_image_partial,     "unequal key image partial status");

        // Get the tx pub key from tx extra using respective m_pk_index
        const crypto::public_key tx_pk_a = cryptonote::get_tx_pub_key_from_extra(tc_a[i].m_tx, tc_a[i].m_pk_index);
        const crypto::public_key tx_pk_b = cryptonote::get_tx_pub_key_from_extra(tc_b[i].m_tx, tc_b[i].m_pk_index);
        if (tx_pk_a != tx_pk_b || tx_pk_a == crypto::null_pkey)
        {
            // If an additional pub key was used, tx_pk_b may correspond to the additional pub key in wallet2 base
            const std::vector<crypto::public_key> additional_tx_pks = cryptonote::get_additional_tx_pub_keys_from_extra(tc_a[i].m_tx);

            CHECK_AND_ASSERT_THROW_MES(!additional_tx_pks.empty(), "tx pubkey did not match, and no additional tx pub keys found");
            CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_internal_output_index < additional_tx_pks.size(), "unexpected num additional tx pks");

            const crypto::public_key additional_tx_pk = additional_tx_pks[tc_a[i].m_internal_output_index];
            CHECK_AND_ASSERT_THROW_MES(tx_pk_b == additional_tx_pk, "could not find matching tx pubkey");
        }

        // Get output pub keys
        const crypto::public_key &output_pk_a = tc_a[i].get_public_key();
        const crypto::public_key &output_pk_b = tc_b[i].get_public_key();
        CHECK_AND_ASSERT_THROW_MES(output_pk_a == output_pk_b, "unequal output pub keys");

        // TODO: implement the correct checks of checks commented below
        // CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_multisig_k.empty()    && tc_b[i].m_multisig_k.empty(),    "unequal multisig k");
        // CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_multisig_info.empty() && tc_b[i].m_multisig_info.empty(), "unequal multisig info");
        // CHECK_AND_ASSERT_THROW_MES(tc_a[i].m_uses.empty()          && tc_b[i].m_uses.empty(),          "unequal usage tracking");

        // b. m_key_images
        CHECK_AND_ASSERT_THROW_MES(key_images_a.find(tc_a[i].m_key_image) != key_images_a.end(),                "did not find key image in wallet a");
        CHECK_AND_ASSERT_THROW_MES(key_images_b.find(tc_a[i].m_key_image) != key_images_b.end(),                "did not find key image in wallet b");
        CHECK_AND_ASSERT_THROW_MES(key_images_a[tc_a[i].m_key_image]      == i,                                 "unexpected key image index");
        CHECK_AND_ASSERT_THROW_MES(key_images_a[tc_a[i].m_key_image]      == key_images_b[tc_b[i].m_key_image], "unequal key key image indexes");

        // c. m_pub_keys
        CHECK_AND_ASSERT_THROW_MES(pub_keys_a.find(output_pk_a) != pub_keys_a.end(),        "did not find output pub key in wallet a");
        CHECK_AND_ASSERT_THROW_MES(pub_keys_b.find(output_pk_b) != pub_keys_b.end(),        "did not find output pub key in wallet b");
        CHECK_AND_ASSERT_THROW_MES(pub_keys_a[output_pk_a]      == i,                       "unexpected output pub key index");
        CHECK_AND_ASSERT_THROW_MES(pub_keys_a[output_pk_a]      == pub_keys_b[output_pk_a], "unequal output pub key indexes");
    }

    // 4. m_payments
    // TODO: handle payment ID correctly
    const auto range_a = payments_a.equal_range(crypto::null_hash);
    const auto range_b = payments_b.equal_range(crypto::null_hash);
    std::unordered_multimap<crypto::hash, cryptonote::subaddress_index> checked_subaddr_indexes;
    for (auto i = range_a.first; i != range_a.second; ++i)
    {
        const auto &pmt_a = i->second;

        // Find matching payment in other container
        bool checked = false;
        for (auto j = range_b.first; j != range_b.second; ++j)
        {
            const auto &pmt_b = j->second;
            if (pmt_a.m_tx_hash != pmt_b.m_tx_hash || pmt_a.m_subaddr_index != pmt_b.m_subaddr_index)
                continue;

            if (checked_subaddr_indexes.find(pmt_a.m_tx_hash) != checked_subaddr_indexes.end())
            {
                const auto checked_range = checked_subaddr_indexes.equal_range(pmt_a.m_tx_hash);
                for (auto it = checked_range.first; it != checked_range.second; ++it)
                    CHECK_AND_ASSERT_THROW_MES(it->second != pmt_a.m_subaddr_index, "duplicate subaddr index in payments");
            }

            CHECK_AND_ASSERT_THROW_MES(pmt_a.m_tx_hash      == pmt_b.m_tx_hash,      "unequal tx hashes in payment");
            CHECK_AND_ASSERT_THROW_MES(pmt_a.m_amount       == pmt_b.m_amount,       "unequal amount in payment");
            CHECK_AND_ASSERT_THROW_MES(pmt_a.m_amounts      == pmt_b.m_amounts,      "unequal amounts in payment");
            CHECK_AND_ASSERT_THROW_MES(pmt_a.m_block_height == pmt_b.m_block_height, "unequal block hashes in payment");
            CHECK_AND_ASSERT_THROW_MES(pmt_a.m_unlock_time  == pmt_b.m_unlock_time,  "unequal unlock times in payment");
            CHECK_AND_ASSERT_THROW_MES(pmt_a.m_timestamp    == pmt_b.m_timestamp,    "unequal timestamps in payment");

            // TODO: m_coinbase, m_fee
            // TODO: payment_id

            checked_subaddr_indexes.insert({pmt_a.m_tx_hash, pmt_a.m_subaddr_index});
            checked = true;
            break;
        }

        CHECK_AND_ASSERT_THROW_MES(checked, "did not find payment in wallet2 imported from enote store");
    }

    // 5. m_confirmed_txs
    for (const auto &ctx : ctxs_a)
    {
        CHECK_AND_ASSERT_THROW_MES(ctxs_b.find(ctx.first) != ctxs_b.end(),
            "did not find confirmed tx in wallet2 from enote store");

        const auto &ctx_a = ctx.second;
        const auto &ctx_b = ctxs_b[ctx.first]; 

        CHECK_AND_ASSERT_THROW_MES(ctx_a.m_amount_in       == ctx_b.m_amount_in,       "unequal amount in");
        CHECK_AND_ASSERT_THROW_MES(ctx_a.m_change          == ctx_b.m_change,          "unequal change");
        CHECK_AND_ASSERT_THROW_MES(ctx_a.m_block_height    == ctx_b.m_block_height,    "unequal block height");
        CHECK_AND_ASSERT_THROW_MES(ctx_a.m_timestamp       == ctx_b.m_timestamp,       "unequal timestamp");
        CHECK_AND_ASSERT_THROW_MES(ctx_a.m_unlock_time     == ctx_b.m_unlock_time,     "unequal unlock time");
        CHECK_AND_ASSERT_THROW_MES(ctx_a.m_subaddr_account == ctx_b.m_subaddr_account, "unequal subaddr account");
        CHECK_AND_ASSERT_THROW_MES(ctx_a.m_subaddr_indices == ctx_b.m_subaddr_indices, "unequal subaddr indices");

        // TODO: m_amount_out, m_payment_id, m_tx, m_dests, m_rings
    }

    // TODO: m_unconfirmed_txs, m_unconfirmed_payments, m_blockchain
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp
