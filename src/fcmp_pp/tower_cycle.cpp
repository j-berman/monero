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

#include "string_tools.h"
#include "tower_cycle.h"

namespace fcmp_pp
{
namespace tower_cycle
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
Helios::Point Helios::hash_init_point() const
{
    return fcmp_pp_rust::helios_hash_init_point();
}
//----------------------------------------------------------------------------------------------------------------------
Selene::Point Selene::hash_init_point() const
{
    return fcmp_pp_rust::selene_hash_init_point();
}
//----------------------------------------------------------------------------------------------------------------------
Helios::CycleScalar Helios::point_to_cycle_scalar(const Helios::Point &point) const
{
    return fcmp_pp_rust::helios_point_to_selene_scalar(point);
}
//----------------------------------------------------------------------------------------------------------------------
Selene::CycleScalar Selene::point_to_cycle_scalar(const Selene::Point &point) const
{
    return fcmp_pp_rust::selene_point_to_helios_scalar(point);
}
//----------------------------------------------------------------------------------------------------------------------
Helios::Point Helios::hash_grow(
    const Helios::Point &existing_hash,
    const std::size_t offset,
    const Helios::Scalar &existing_child_at_offset,
    const Helios::Chunk &new_children) const
{
    auto result = fcmp_pp_rust::hash_grow_helios(
        existing_hash,
        offset,
        existing_child_at_offset,
        new_children);

    if (result.err != nullptr)
    {
        free(result.err);
        throw std::runtime_error("failed to hash grow");
    }

    typename Helios::Point res;
    memcpy(&res, result.value, sizeof(typename Helios::Point));
    free(result.value);
    return res;
}
//----------------------------------------------------------------------------------------------------------------------
Helios::Point Helios::hash_trim(
    const Helios::Point &existing_hash,
    const std::size_t offset,
    const Helios::Chunk &children,
    const Helios::Scalar &child_to_grow_back) const
{
    auto result = fcmp_pp_rust::hash_trim_helios(
        existing_hash,
        offset,
        children,
        child_to_grow_back);

    if (result.err != nullptr)
    {
        free(result.err);
        throw std::runtime_error("failed to hash trim");
    }

    typename Helios::Point res;
    memcpy(&res, result.value, sizeof(typename Helios::Point));
    free(result.value);
    return res;
}
//----------------------------------------------------------------------------------------------------------------------
Selene::Point Selene::hash_grow(
    const Selene::Point &existing_hash,
    const std::size_t offset,
    const Selene::Scalar &existing_child_at_offset,
    const Selene::Chunk &new_children) const
{
    auto result = fcmp_pp_rust::hash_grow_selene(
        existing_hash,
        offset,
        existing_child_at_offset,
        new_children);

    if (result.err != nullptr)
    {
        free(result.err);
        throw std::runtime_error("failed to hash grow");
    }

    typename Selene::Point res;
    memcpy(&res, result.value, sizeof(typename Selene::Point));
    free(result.value);
    return res;
}
//----------------------------------------------------------------------------------------------------------------------
Selene::Point Selene::hash_trim(
    const Selene::Point &existing_hash,
    const std::size_t offset,
    const Selene::Chunk &children,
    const Selene::Scalar &child_to_grow_back) const
{
    auto result = fcmp_pp_rust::hash_trim_selene(
        existing_hash,
        offset,
        children,
        child_to_grow_back);

    if (result.err != nullptr)
    {
        free(result.err);
        throw std::runtime_error("failed to hash trim");
    }

    typename Selene::Point res;
    memcpy(&res, result.value, sizeof(typename Selene::Point));
    free(result.value);
    return res;
}
//----------------------------------------------------------------------------------------------------------------------
Helios::Scalar Helios::zero_scalar() const
{
    return fcmp_pp_rust::helios_zero_scalar();
}
//----------------------------------------------------------------------------------------------------------------------
Selene::Scalar Selene::zero_scalar() const
{
    return fcmp_pp_rust::selene_zero_scalar();
}
//----------------------------------------------------------------------------------------------------------------------
std::array<uint8_t, 32UL> Helios::to_bytes(const Helios::Scalar &scalar) const
{
    auto bytes = fcmp_pp_rust::helios_scalar_to_bytes(scalar);
    std::array<uint8_t, 32UL> res;
    memcpy(&res, bytes, 32);
    free(bytes);
    return res;
}
//----------------------------------------------------------------------------------------------------------------------
std::array<uint8_t, 32UL> Selene::to_bytes(const Selene::Scalar &scalar) const
{
    auto bytes = fcmp_pp_rust::selene_scalar_to_bytes(scalar);
    std::array<uint8_t, 32UL> res;
    memcpy(&res, bytes, 32);
    free(bytes);
    return res;
}
//----------------------------------------------------------------------------------------------------------------------
std::array<uint8_t, 32UL> Helios::to_bytes(const Helios::Point &point) const
{
    auto bytes = fcmp_pp_rust::helios_point_to_bytes(point);
    std::array<uint8_t, 32UL> res;
    memcpy(&res, bytes, 32);
    free(bytes);
    return res;
}
//----------------------------------------------------------------------------------------------------------------------
std::array<uint8_t, 32UL> Selene::to_bytes(const Selene::Point &point) const
{
    auto bytes = fcmp_pp_rust::selene_point_to_bytes(point);
    std::array<uint8_t, 32UL> res;
    memcpy(&res, bytes, 32);
    free(bytes);
    return res;
}
//----------------------------------------------------------------------------------------------------------------------
Helios::Point Helios::from_bytes(const std::array<uint8_t, 32UL> &bytes) const
{
    return fcmp_pp_rust::helios_point_from_bytes(bytes.data());
}
//----------------------------------------------------------------------------------------------------------------------
Selene::Point Selene::from_bytes(const std::array<uint8_t, 32UL> &bytes) const
{
    return fcmp_pp_rust::selene_point_from_bytes(bytes.data());
}
//----------------------------------------------------------------------------------------------------------------------
std::string Helios::to_string(const typename Helios::Scalar &scalar) const
{
    return epee::string_tools::pod_to_hex(this->to_bytes(scalar));
}
//----------------------------------------------------------------------------------------------------------------------
std::string Selene::to_string(const typename Selene::Scalar &scalar) const
{
    return epee::string_tools::pod_to_hex(this->to_bytes(scalar));
}
//----------------------------------------------------------------------------------------------------------------------
std::string Helios::to_string(const typename Helios::Point &point) const
{
    return epee::string_tools::pod_to_hex(this->to_bytes(point));
}
//----------------------------------------------------------------------------------------------------------------------
std::string Selene::to_string(const typename Selene::Point &point) const
{
    return epee::string_tools::pod_to_hex(this->to_bytes(point));
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// Exposed helper functions
//----------------------------------------------------------------------------------------------------------------------
SeleneScalar selene_scalar_from_bytes(const rct::key &scalar)
{
    return fcmp_pp_rust::selene_scalar_from_bytes(scalar.bytes);
}
//----------------------------------------------------------------------------------------------------------------------
template<typename C>
void extend_zeroes(const std::unique_ptr<C> &curve,
    const std::size_t num_zeroes,
    std::vector<typename C::Scalar> &zeroes_inout)
{
    zeroes_inout.reserve(zeroes_inout.size() + num_zeroes);

    for (std::size_t i = 0; i < num_zeroes; ++i)
        zeroes_inout.emplace_back(curve->zero_scalar());
}

// Explicit instantiations
template void extend_zeroes<Helios>(const std::unique_ptr<Helios> &curve,
    const std::size_t num_zeroes,
    std::vector<Helios::Scalar> &zeroes_inout);

template void extend_zeroes<Selene>(const std::unique_ptr<Selene> &curve,
    const std::size_t num_zeroes,
    std::vector<Selene::Scalar> &zeroes_inout);
//----------------------------------------------------------------------------------------------------------------------
template<typename C_POINTS, typename C_SCALARS>
void extend_scalars_from_cycle_points(const std::unique_ptr<C_POINTS> &curve,
    const std::vector<typename C_POINTS::Point> &points,
    std::vector<typename C_SCALARS::Scalar> &scalars_out)
{
    scalars_out.reserve(scalars_out.size() + points.size());

    for (const auto &point : points)
    {
        typename C_SCALARS::Scalar scalar = curve->point_to_cycle_scalar(point);
        scalars_out.push_back(std::move(scalar));
    }
}

// Explicit instantiations
template void extend_scalars_from_cycle_points<Helios, Selene>(const std::unique_ptr<Helios> &curve,
    const std::vector<Helios::Point> &points,
    std::vector<Selene::Scalar> &scalars_out);

template void extend_scalars_from_cycle_points<Selene, Helios>(const std::unique_ptr<Selene> &curve,
    const std::vector<Selene::Point> &points,
    std::vector<Helios::Scalar> &scalars_out);
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
} //namespace tower_cycle
} //namespace fcmp_pp