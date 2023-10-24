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

#pragma once

#include <curl/curl.h>

//local headers
#include "net/http.h"
#include "net/http_client.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/http_abstract_invoke.h"
#include "misc_language.h"

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

//third party headers

//standard headers

//forward declarations

namespace sp
{
namespace mocks
{
////
// CurlConnectionPool
// - wraps a pool of curl client connections to enable parallel requests
///
class CurlConnectionPool
{
public:
//constructors
    CurlConnectionPool(
        const std::string &daemon_address,
        const boost::optional<epee::net_utils::http::login> daemon_login = boost::none,
        const epee::net_utils::ssl_options_t ssl_support = epee::net_utils::ssl_support_t::e_ssl_support_autodetect,
        const size_t &max_connections = 20):
            m_daemon_address{daemon_address},
            m_daemon_login{daemon_login},
            m_ssl_support(ssl_support),
            m_max_connections{max_connections}
    {
        m_http_client_pool.reserve(max_connections);
    }

//member functions
    enum invoke_http_mode { JON, BIN, JON_RPC };

    /// Use an http client from the pool to make an RPC request to the daemon
    template <typename COMMAND_TYPE>
    bool rpc_command(const invoke_http_mode &mode, const std::string &command_name, const typename COMMAND_TYPE::request &req, typename COMMAND_TYPE::response &res)
    {
        // Acquire an http client from the connection pool
        size_t http_client_index = 0;
        CURL *curl = acquire_unused_http_client(
                m_daemon_address,
                m_daemon_login,
                m_ssl_support,
                http_client_index);
        auto scope_exit_handler = epee::misc_utils::create_scope_leave_handler([this, http_client_index]{
            release_http_client(http_client_index);
        });

        // Do the RPC command
        LOG_PRINT_L2("Invoking " << command_name << " with http client " << http_client_index);
        bool r = false;
        CURLcode curl_res;
        switch (mode)
        {
            case invoke_http_mode::JON:
            {
                // TODO
                break;
            }
            case invoke_http_mode::BIN:
            {
                const std::string url = m_daemon_address + command_name;
                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

                // Convert request to a string
                epee::byte_slice req_param;
                if(!epee::serialization::store_t_to_binary(req, req_param, 16 * 1024))
                    return false;
                std::string req_str = std::string(reinterpret_cast<const char*>(req_param.data()), req_param.size());

                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, req_str.size());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_str.c_str());

                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

                std::string read_buffer;
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);

                CURLcode curl_res = curl_easy_perform(curl);

                size_t http_code(0);
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

                if (curl_res == CURLE_OK && http_code == 200)
                {
                    static const constexpr epee::serialization::portable_storage::limits_t default_http_bin_limits = {
                        65536 * 3, // objects
                        65536 * 3, // fields
                        65536 * 3, // strings
                    };
                    if (!epee::serialization::load_t_from_binary(res, epee::strspan<uint8_t>(read_buffer), &default_http_bin_limits))
                        return false;
                    r = true;
                }
                break;
            }
            case invoke_http_mode::JON_RPC:
            {
                const std::string url = m_daemon_address + "/json_rpc";
                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

                struct curl_slist *headers = NULL;
                headers = curl_slist_append(headers, "Content-Type: application/json");
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

                // Convert request to a string
                epee::json_rpc::request<typename COMMAND_TYPE::request> req_t = AUTO_VAL_INIT(req_t);
                req_t.jsonrpc = "2.0";
                req_t.id = "0";
                req_t.method = command_name;
                req_t.params = req;
                std::string req_str;
                if (!epee::serialization::store_t_to_json(req_t, req_str))
                    return false;
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_str.c_str());

                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

                std::string read_buffer;
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);

                CURLcode curl_res = curl_easy_perform(curl);

                size_t http_code(0);
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

                if (curl_res == CURLE_OK && http_code == 200)
                {
                    epee::json_rpc::response<typename COMMAND_TYPE::response, epee::json_rpc::error> resp_t = AUTO_VAL_INIT(resp_t);
                    if (!epee::serialization::load_t_from_json(resp_t, read_buffer))
                        return false;
    
                    res = std::move(resp_t.result);
                    r = true;
                }

                break;
            }
            default:
                MERROR("Unknown invoke_http_mode: " << mode);
                r = false;
        }

        // Return an empty result on failure
        if (!r)
        {
            typename COMMAND_TYPE::response empty_res = AUTO_VAL_INIT(empty_res);
            res = std::move(empty_res);
            return true;
        }

        return r;
    }

private:
    /// If an http client is available, acquires it. If none are available,
    /// initializes a new http client.
    CURL *acquire_unused_http_client(
        const std::string &daemon_address,
        const boost::optional<epee::net_utils::http::login> daemon_login,
        const epee::net_utils::ssl_options_t ssl_support,
        size_t &http_client_index);

    /// Make http client available for use again.
    void release_http_client(size_t http_client_index);

//member variables
private:
    const std::string m_daemon_address;
    const boost::optional<epee::net_utils::http::login> m_daemon_login;
    const epee::net_utils::ssl_options_t m_ssl_support;

    const size_t m_max_connections;
    typedef std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl_ptr_t;
    struct pool_http_client_t {
        bool in_use;
        curl_ptr_t http_client;
    };
    mutable std::mutex m_http_client_pool_mutex;
    mutable std::vector<pool_http_client_t> m_http_client_pool;
};
} //namespace mocks
} //namespace sp
