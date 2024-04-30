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

#pragma once

//local headers
#include "seraphis_impl/enote_store.h"
#include "wallet/wallet2.h"

//third party headers

//standard headers
#include <memory>

//forward declarations


namespace sp
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
class SeraphisMigrationTools
{
public:
    /// Import a Seraphis enote store into a wallet2 instance
    static void import_sp_enote_store(const sp::SpEnoteStore &sp_enote_store,
        std::unique_ptr<tools::wallet2> &wallet2_inout);

    /// Helper function to test equality on wallet2 containers
    static void check_wallet2_container_equality(const std::unique_ptr<tools::wallet2> &wallet2_base,
        const std::unique_ptr<tools::wallet2> &wallet2_from_enote_store);
private:
    /// Import a Seraphis enote record into wallet2 m_transfers container
    static void import_sp_enote_record(const sp::LegacyContextualEnoteRecordV1 &legacy_enote_record,
        std::unique_ptr<tools::wallet2> &wallet2_inout,
        std::unordered_set<crypto::hash> &incoming_tx_hashes_inout,
        std::unordered_set<crypto::hash> &outgoing_tx_hashes_inout,
        std::unordered_multimap<crypto::hash, std::size_t> &incoming_enotes_inout,
        std::unordered_multimap<crypto::hash, std::size_t> &outgoing_enotes_inout);

    /// Import incoming payments into the wallet2 m_payments container 
    static void import_incoming_payments(const crypto::hash &tx_hash,
        const std::unordered_multimap<crypto::hash, std::size_t> &outgoing_enotes,
        const std::unordered_multimap<crypto::hash, std::size_t> &incoming_enotes,
        const  std::vector<sp::LegacyContextualEnoteRecordV1> &legacy_enote_records,
        std::unique_ptr<tools::wallet2> &wallet2_inout);

    /// Import outgoing txs into the wallet2 m_confirmed_txs container 
    static void import_outgoing_tx(const crypto::hash &tx_hash,
        const std::unordered_multimap<crypto::hash, std::size_t> &outgoing_enotes,
        const std::unordered_multimap<crypto::hash, std::size_t> &incoming_enotes,
        const  std::vector<sp::LegacyContextualEnoteRecordV1> &legacy_enote_records,
        std::unique_ptr<tools::wallet2> &wallet2_inout);
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp
