#pragma once
// ============================================================================
// μCore (mucore-kernel) — Explicit Value Error Handling (Option & Result)
// ============================================================================
// Replaces C++ exceptions with [[nodiscard]] value types.
//   - Zero hidden control flow (no stack unwinding, no RTTI).
//   - Zero union active-member UB or placement-new machinery.
//   - Automatically inherits copy/move constraints of `T` (if `T` deletes
//     implicit copy to prevent hidden memcpy, `Result<T>` is also move-only!).
//   - 100% usable in `constexpr` / `consteval` compile-time kernel proofs.
// ============================================================================

#include "mucore/types.hpp"

namespace mucore {

template <typename T>
struct RemoveRef { using Type = T; };
template <typename T>
struct RemoveRef<T&> { using Type = T; };
template <typename T>
struct RemoveRef<T&&> { using Type = T; };

template <typename T>
[[nodiscard]] constexpr typename RemoveRef<T>::Type&& move(T&& val) noexcept {
    return static_cast<typename RemoveRef<T>::Type&&>(val);
}

// ----------------------------------------------------------------------------
// Option<T>: Explicit optional value without magic sentinel numbers
// ----------------------------------------------------------------------------
template <typename T>
class [[nodiscard]] Option {
public:
    constexpr Option() noexcept = default;

    [[nodiscard]] static constexpr Option some(T val) noexcept {
        Option out{};
        out.val_     = mucore::move(val);
        out.has_val_ = true;
        return out;
    }

    [[nodiscard]] static constexpr Option none() noexcept {
        return Option{};
    }

    constexpr Option(Option const&) noexcept = default;
    constexpr Option(Option&&) noexcept      = default;
    constexpr Option& operator=(Option const&) noexcept = default;
    constexpr Option& operator=(Option&&) noexcept      = default;

    [[nodiscard]] constexpr bool is_some() const noexcept { return has_val_; }
    [[nodiscard]] constexpr bool is_none() const noexcept { return !has_val_; }

    [[nodiscard]] constexpr T const& value() const noexcept { return val_; }
    [[nodiscard]] constexpr T& value() noexcept { return val_; }

    [[nodiscard]] constexpr T value_or(T fallback) const noexcept {
        return has_val_ ? val_ : mucore::move(fallback);
    }

private:
    T    val_{};
    bool has_val_{false};
};

// ----------------------------------------------------------------------------
// Result<T, E>: Explicit fallible return value
// ----------------------------------------------------------------------------
template <typename T, typename E = Error>
class [[nodiscard]] Result {
public:
    [[nodiscard]] static constexpr Result ok(T val) noexcept {
        Result out{};
        out.val_   = mucore::move(val);
        out.err_   = E{};
        out.is_ok_ = true;
        return out;
    }

    [[nodiscard]] static constexpr Result err(E error) noexcept {
        Result out{};
        out.err_   = error;
        out.is_ok_ = false;
        return out;
    }

    constexpr Result(Result const&) noexcept = default;
    constexpr Result(Result&&) noexcept      = default;
    constexpr Result& operator=(Result const&) noexcept = default;
    constexpr Result& operator=(Result&&) noexcept      = default;

    [[nodiscard]] constexpr bool is_ok() const noexcept  { return is_ok_; }
    [[nodiscard]] constexpr bool is_err() const noexcept { return !is_ok_; }

    [[nodiscard]] constexpr T const& value() const noexcept { return val_; }
    [[nodiscard]] constexpr T& value() noexcept             { return val_; }
    [[nodiscard]] constexpr E error() const noexcept        { return err_; }

    [[nodiscard]] constexpr T value_or(T fallback) const noexcept {
        return is_ok_ ? val_ : mucore::move(fallback);
    }

private:
    constexpr Result() noexcept = default;

    T    val_{};
    E    err_{};
    bool is_ok_{false};
};

} // namespace mucore
