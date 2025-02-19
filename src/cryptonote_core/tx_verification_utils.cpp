// Copyright (c) 2023-2024, The Monero Project
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

#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/tx_verification_utils.h"
#include "fcmp_pp/curve_trees.h"
#include "ringct/rctSigs.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain"

#define VER_ASSERT(cond, msgexpr) CHECK_AND_ASSERT_MES(cond, false, msgexpr)

using namespace cryptonote;

// Sanity checks on expanded pre-FCMP tx
static bool check_pre_fcmp_expanded_tx(const transaction& tx, const rct::ctkeyM& mix_ring)
{
    const rct::rctSig& rv = tx.rct_signatures;
    VER_ASSERT(!rct::is_rct_fcmp(rv.type), "Unexpected RCT type in pre-FCMP tx expansion");

    // Check that expanded RCT mixring == input mixring
    VER_ASSERT(rv.mixRing == mix_ring, "Failed to check ringct signatures: mismatched pubkeys/mixRing");

    // Check CLSAG/MLSAG size against transaction input
    const size_t n_sigs = rct::is_rct_clsag(rv.type) ? rv.p.CLSAGs.size() : rv.p.MGs.size();
    VER_ASSERT(n_sigs == tx.vin.size(), "Failed to check ringct signatures: mismatched input sigs/vin sizes");

    // For each input, check that the key images were copied into the expanded RCT sig correctly
    for (size_t n = 0; n < n_sigs; ++n)
    {
        const crypto::key_image& nth_vin_image = boost::get<txin_to_key>(tx.vin[n]).k_image;

        if (rct::is_rct_clsag(rv.type))
        {
            const bool ki_match = 0 == memcmp(&nth_vin_image, &rv.p.CLSAGs[n].I, 32);
            VER_ASSERT(ki_match, "Failed to check ringct signatures: mismatched CLSAG key image");
        }
        else
        {
            const bool mg_nonempty = !rv.p.MGs[n].II.empty();
            VER_ASSERT(mg_nonempty, "Failed to check ringct signatures: missing MLSAG key image");
            const bool ki_match = 0 == memcmp(&nth_vin_image, &rv.p.MGs[n].II[0], 32);
            VER_ASSERT(ki_match, "Failed to check ringct signatures: mismatched MLSAG key image");
        }
    }

    // Mix ring data is now known to be correctly incorporated into the RCT sig inside tx.
    return true;
}

// Sanity checks on expanded post-FCMP tx
static bool check_post_fcmp_expanded_tx(const transaction& tx)
{
    const rct::rctSig& rv = tx.rct_signatures;
    VER_ASSERT(rct::is_rct_fcmp(rv.type), "Unexpected RCT type in post-FCMP tx expansion");

    VER_ASSERT(rv.mixRing.empty(),        "Non-empty mixRing after expanding FCMP tx");
    VER_ASSERT(rv.p.CLSAGs.empty(),       "Non-empty CLSAGs after expanding FCMP tx");
    VER_ASSERT(rv.p.MGs.empty(),          "Non-empty MGs after expanding FCMP tx");
    VER_ASSERT(rv.p.rangeSigs.empty(),    "Non-empty range sigs after expanding FCMP tx");
    VER_ASSERT(rv.p.bulletproofs.empty(), "Non-empty bulletproofs after expanding FCMP tx");
    VER_ASSERT(rv.pseudoOuts.empty(),     "Non-empty old pseudo outs after expanding FCMP tx");

    // Make sure the tree root is set
    VER_ASSERT(rv.p.fcmp_ver_helper_data.tree_root != nullptr, "tree_root is not set");

    // Check pseudoOuts size against transaction inputs
    const size_t n_inputs = rv.p.pseudoOuts.size();
    VER_ASSERT(n_inputs == tx.vin.size(), "Mismatched pseudo outs to inputs after expanding FCMP tx");
    VER_ASSERT(n_inputs == rv.p.fcmp_ver_helper_data.key_images.size(), "Mismatched key images to inputs after expanding FCMP tx");

    // For each input, check that the key images were copied into the expanded RCT sig correctly
    for (size_t n = 0; n < n_inputs; ++n)
    {
        const crypto::key_image& nth_vin_image = boost::get<txin_to_key>(tx.vin[n]).k_image;
        const bool ki_match = 0 == memcmp(&nth_vin_image, &rv.p.fcmp_ver_helper_data.key_images[n], 32);
        VER_ASSERT(ki_match, "Failed to check ringct signatures: mismatched FCMP key image");
    }

    return true;
}

// Do pre FCMP++ RCT expansion, then do post-expansion sanity checks.
static bool expand_pre_fcmp_tx(transaction& tx, const crypto::hash& tx_prefix_hash, const rct::ctkeyM& mix_ring)
{
    // Expand mixRing, tx inputs, tx key images, prefix hash message, etc into the RCT sig
    const bool exp_res = Blockchain::expand_transaction_2(tx, tx_prefix_hash, mix_ring, nullptr/*tree_root*/);
    VER_ASSERT(exp_res, "Failed to expand rct signatures!");

    // Do sanity checks after expansion
    return check_pre_fcmp_expanded_tx(tx, mix_ring);
}

// Do post FCMP++ RCT expansion, then do post-expansion sanity checks.
static bool expand_post_fcmp_tx(transaction& tx, const crypto::hash& tx_prefix_hash, const crypto::ec_point& tree_root)
{
    // Expand the tree root
    const auto curve_trees = fcmp_pp::curve_trees::curve_trees_v1();
    const auto root = curve_trees->get_tree_root_from_bytes(tx.rct_signatures.p.n_tree_layers, tree_root);
    VER_ASSERT(root != nullptr, "Failed to decompress root");

    // Expand tree_root, tx inputs, tx key images, prefix hash message, etc into the RCT sig
    const bool exp_res = Blockchain::expand_transaction_2(tx, tx_prefix_hash, {}/*mixRing*/, root);
    VER_ASSERT(exp_res, "Failed to expand rct signatures!");

    // Do sanity checks after expansion
    return check_post_fcmp_expanded_tx(tx);
}

// Create a unique identifier for pair of tx blob + mix ring
static crypto::hash calc_tx_mixring_hash(const transaction& tx, const rct::ctkeyM& mix_ring)
{
    std::stringstream ss;

    // Start with domain seperation
    ss << config::HASH_KEY_TXHASH_AND_MIXRING;

    // Then add TX hash
    const crypto::hash tx_hash = get_transaction_hash(tx);
    ss.write(tx_hash.data, sizeof(crypto::hash));

    // Then serialize mix ring
    binary_archive<true> ar(ss);
    ::do_serialize(ar, const_cast<rct::ctkeyM&>(mix_ring));

    // Calculate hash of TX hash and mix ring blob
    crypto::hash tx_and_mixring_hash;
    get_blob_hash(ss.str(), tx_and_mixring_hash);

    return tx_and_mixring_hash;
}

// Create a unique identifier for pair of tx blob + tree root
static crypto::hash calc_tx_tree_root_hash(const transaction& tx, const crypto::ec_point& tree_root)
{
    std::stringstream ss;

    // Start with domain seperation
    ss << config::HASH_KEY_TXHASH_AND_TREE_ROOT;

    // Then add TX hash
    const crypto::hash tx_hash = get_transaction_hash(tx);
    ss.write(tx_hash.data, sizeof(crypto::hash));

    // Then serialize tree root
    binary_archive<true> ar(ss);
    ::do_serialize(ar, const_cast<crypto::ec_point&>(tree_root));

    // Calculate hash of TX hash and tree root
    crypto::hash tx_and_tree_root_hash;
    get_blob_hash(ss.str(), tx_and_tree_root_hash);

    return tx_and_tree_root_hash;
}

// Expand the RCT tx then do post-expansion semantics AND non-semantics verification.
static bool expand_tx_and_ver_rct_non_sem(cryptonote::transaction& tx_inout,
    const rct::ctkeyM& mix_ring,
    const crypto::ec_point& tree_root)
{
    // Pruned transactions can not be expanded and verified because they are missing RCT data
    VER_ASSERT(!tx_inout.pruned, "Pruned transaction will not pass verRctNonSemanticsSimple");
    const crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx_inout);

    const bool expanded = rct::is_rct_fcmp(tx_inout.rct_signatures.type)
        ? expand_post_fcmp_tx(tx_inout, tx_prefix_hash, tree_root)
        : expand_pre_fcmp_tx(tx_inout, tx_prefix_hash, mix_ring);
    VER_ASSERT(expanded, "Failed to expand RCT tx");

    return rct::verRctNonSemanticsSimple(tx_inout.rct_signatures);
}

// Create a unique identifer for a tx and its referenced anon set
static crypto::hash calc_tx_anon_set_hash(const cryptonote::transaction& tx,
    const rct::ctkeyM& mix_ring,
    const crypto::ec_point& tree_root)
{
    return rct::is_rct_fcmp(tx.rct_signatures.type)
        ? calc_tx_tree_root_hash(tx, tree_root)
        : calc_tx_mixring_hash(tx, mix_ring);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptonote
{

bool ver_rct_non_semantics_simple_cached
(
    transaction& tx,
    const rct::ctkeyM& mix_ring,
    const crypto::ec_point& tree_root,
    rct_ver_cache_t& cache,
    const std::uint8_t rct_type_to_cache
)
{
    // Hello future Monero dev! If you got this assert, read the following carefully:
    //
    // For this version of RCT, the way we guaranteed that verification caches do not generate false
    // positives (and thus possibly enabling double spends) is we take a hash of two things. One,
    // we use get_transaction_hash() which gives us a (cryptographically secure) unique
    // representation of all "knobs" controlled by the possibly malicious constructor of the
    // transaction. Two, we take a hash of all *previously validated* blockchain data referenced by
    // this transaction which is required to validate the membership proof. In our case, this is
    // either the mixring (from the ring signature era) or the tree root (from the FCMP era).
    // Future versions of the protocol may differ in this regard, but if this assumptions
    // holds true in the future, enable the verification hash by modifying the `untested_tx`
    // condition below.
    const bool untested_tx = tx.version > 2 || tx.rct_signatures.type > rct::RCTTypeFcmpPlusPlus;
    VER_ASSERT(!untested_tx, "Unknown TX type. Make sure RCT cache works correctly with this type and then enable it in the code here.");

    // Don't cache older (or newer) rctSig types
    // This cache only makes sense when it caches data from mempool first,
    // so only "current fork version-enabled" RCT types need to be cached
    if (tx.rct_signatures.type != rct_type_to_cache)
    {
        MDEBUG("RCT cache: tx " << get_transaction_hash(tx) << " skipped");
        return expand_tx_and_ver_rct_non_sem(tx, mix_ring, tree_root);
    }

    // Generate unique hash for tx+anon set identifier
    const crypto::hash cache_hash = calc_tx_anon_set_hash(tx, mix_ring, tree_root);

    // Search cache for successful verification of same TX + mix set hash combination
    if (cache.has(cache_hash))
    {
        MDEBUG("RCT cache: tx " << get_transaction_hash(tx) << " hit");
        return true;
    }

    // We had a cache miss, so now we must expand the mix ring and do full verification
    MDEBUG("RCT cache: tx " << get_transaction_hash(tx) << " missed");
    if (!expand_tx_and_ver_rct_non_sem(tx, mix_ring, tree_root))
    {
        return false;
    }

    // At this point, the TX RCT verified successfully, so add it to the cache and return true
    cache.add(cache_hash);

    return true;
}

} // namespace cryptonote
