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

// Variant wrapper class.


#pragma once

//local headers

//third party headers
#include <boost/blank.hpp>
#include <boost/none_t.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/get.hpp>
#include <boost/variant/static_visitor.hpp>
#include <boost/variant/variant.hpp>

//standard headers
#include <stdexcept>
#include <type_traits>

//forward declarations


namespace sp
{

////
// SpVariant: convenience wrapper around boost::variant with a cleaner interface
// - the value may be assigned to but is otherwise read-only
// - the variant is 'optional' - an empty variant will evaluate to 'false' and an initialized variant will be 'true'
///
template<typename ResultT>
struct SpVariantStaticVisitor : public boost::static_visitor<ResultT>
{
    /// provide visitation for empty variants
    /// - add to your visitor with: using SpVariantStaticVisitor::operator();
    ResultT operator()(const boost::blank) const
    {
        throw std::runtime_error("SpVariant: tried to visit an empty variant.");
        static const ResultT dummy{};
        return dummy;
    }
};

template<typename... Types>
class SpVariant final
{
    using VType = boost::variant<boost::blank, Types...>;

public:
//constructors
    /// default constructor
    SpVariant() = default;
    SpVariant(boost::none_t) : SpVariant{} {}  //act like boost::optional

    /// construct from variant type
    template <typename T>
    SpVariant(const T &value) : m_value{value} {}

//overloaded operators
    /// boolean operator: true if the variant isn't empty/uninitialized
    operator bool() const { return m_value.which() != 0; }

//member functions
    /// check if empty/uninitialized
    bool is_empty() const { return !static_cast<bool>(*this); }

    /// check the variant type
    template <typename T>
    bool is_type() const { return boost::strict_get<T>(&m_value) != nullptr; }

    /// get a read-only handle to the embedded value
    template <typename T>
    const T& unwrap() const
    {
        const T *value_ptr{boost::strict_get<T>(&m_value)};
        if (!value_ptr) throw std::runtime_error("SpVariant: tried to access value of incorrect type.");
        return *value_ptr;
    }

    /// get the type index of the current partial signature
    int type_index() const { return m_value.which(); }

    /// get the type index of a requested type (compile error for invalid types)
    template <typename T>
    static int type_index_of()
    {
        static const int type_index_of_T{VType{T{}}.which()};  //todo: this is slower than it needs to be
        return type_index_of_T;
    }

    /// check if two variants have the same type
    static bool same_type(const SpVariant<Types...> &v1, const SpVariant<Types...> &v2)
    { return v1.type_index() == v2.type_index(); }

    /// apply a visitor to the variant
    template <typename VisitorT>
    typename VisitorT::result_type visit(const VisitorT &visitor) const
    {
        return boost::apply_visitor(visitor, m_value);
    }

private:
//member variables
    /// variant of all value types
    VType m_value;
};

} //namespace sp
