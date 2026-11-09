#pragma once
// ============================================================================
// μCore (mucore-kernel) — Bounded Zero-Allocation Containers (Span & StaticVec)
// ============================================================================
// Design Mandate: "No Hidden Mechanisms"
//   - Zero dynamic heap allocation (`operator new` is never called).
//   - Worst-Case Execution Time (WCET) and stack/BSS footprint are statically
//     known at compile time — mandatory for Hard Real-Time & Ring 0 safety.
//   - `StaticVec` deletes implicit copy construction so multi-element copies
//     can never happen invisibly; use `.clone()` when copying is intentional.
// ============================================================================

#include "mucore/result.hpp"

namespace mucore {

// ----------------------------------------------------------------------------
// Span<T>: Bounds-checked non-owning view over contiguous elements
// ----------------------------------------------------------------------------
template <typename T>
class Span {
public:
    constexpr Span() noexcept : ptr_(nullptr), len_(0) {}
    constexpr Span(T* ptr, usize len) noexcept : ptr_(ptr), len_(len) {}

    template <usize N>
    constexpr explicit Span(T (&arr)[N]) noexcept : ptr_(arr), len_(N) {}

    [[nodiscard]] constexpr usize size() const noexcept { return len_; }
    [[nodiscard]] constexpr bool empty() const noexcept { return len_ == 0; }
    [[nodiscard]] constexpr T* data() const noexcept    { return ptr_; }

    [[nodiscard]] constexpr Option<T> get_copy(usize idx) const noexcept {
        if (idx >= len_) {
            return Option<T>::none();
        }
        return Option<T>::some(ptr_[idx]);
    }

    [[nodiscard]] constexpr T& operator[](usize idx) const noexcept {
        return ptr_[idx];
    }

    [[nodiscard]] constexpr T* begin() const noexcept { return ptr_; }
    [[nodiscard]] constexpr T* end() const noexcept   { return ptr_ + len_; }

private:
    T*    ptr_;
    usize len_;
};

// ----------------------------------------------------------------------------
// StaticVec<T, Capacity>: Fixed-capacity inline vector (move-only by default)
// ----------------------------------------------------------------------------
template <typename T, usize Capacity>
class StaticVec {
public:
    constexpr StaticVec() noexcept = default;

    // Ban implicit copies to prevent hidden O(N) memcpy on function boundaries
    StaticVec(StaticVec const&)            = delete;
    StaticVec& operator=(StaticVec const&) = delete;

    // Allow explicit move / NRVO for returning TransitionPlan values from Core
    constexpr StaticVec(StaticVec&& other) noexcept : len_(other.len_) {
        for (usize i = 0; i < len_; ++i) {
            data_[i] = mucore::move(other.data_[i]);
        }
        other.len_ = 0;
    }

    constexpr StaticVec& operator=(StaticVec&& other) noexcept {
        if (this != &other) {
            len_ = other.len_;
            for (usize i = 0; i < len_; ++i) {
                data_[i] = mucore::move(other.data_[i]);
            }
            other.len_ = 0;
        }
        return *this;
    }

    // Explicit O(N) clone when a copy is genuinely desired
    [[nodiscard]] constexpr StaticVec clone() const noexcept {
        StaticVec out{};
        out.len_ = len_;
        for (usize i = 0; i < len_; ++i) {
            out.data_[i] = data_[i];
        }
        return out;
    }

    [[nodiscard]] constexpr Result<Unit, Error> push(T item) noexcept {
        if (len_ >= Capacity) {
            return Result<Unit, Error>::err(Error::TableFull);
        }
        data_[len_++] = mucore::move(item);
        return Result<Unit, Error>::ok(Unit{});
    }

    [[nodiscard]] constexpr Option<T> pop() noexcept {
        if (len_ == 0) {
            return Option<T>::none();
        }
        --len_;
        return Option<T>::some(mucore::move(data_[len_]));
    }

    constexpr void clear() noexcept { len_ = 0; }

    [[nodiscard]] constexpr usize size() const noexcept     { return len_; }
    [[nodiscard]] static constexpr usize capacity() noexcept { return Capacity; }
    [[nodiscard]] constexpr bool empty() const noexcept     { return len_ == 0; }
    [[nodiscard]] constexpr bool full() const noexcept      { return len_ == Capacity; }

    [[nodiscard]] constexpr T const& operator[](usize idx) const noexcept { return data_[idx]; }
    [[nodiscard]] constexpr T& operator[](usize idx) noexcept             { return data_[idx]; }

    [[nodiscard]] constexpr Span<T const> as_span() const noexcept {
        return Span<T const>(data_, len_);
    }

    [[nodiscard]] constexpr T const* begin() const noexcept { return data_; }
    [[nodiscard]] constexpr T const* end() const noexcept   { return data_ + len_; }
    [[nodiscard]] constexpr T* begin() noexcept             { return data_; }
    [[nodiscard]] constexpr T* end() noexcept               { return data_ + len_; }

private:
    T     data_[Capacity]{};
    usize len_{0};
};

} // namespace mucore
