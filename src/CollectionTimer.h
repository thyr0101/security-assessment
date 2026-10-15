#pragma once
#include <windows.h>
#include <chrono>
#include <iostream>
#include <syncstream>
#include <utility>

// Optional collector tracing; disabled tracing does not read the performance clock.
namespace sa {
class CollectionTimer {
    const wchar_t* label_;
    bool enabled_ = false;
    std::chrono::steady_clock::time_point start_{};
public:
    explicit CollectionTimer(const wchar_t* label) : label_(label) {
        wchar_t enabled[2]{};
        enabled_ = ::GetEnvironmentVariableW(L"SA_TRACE_TIMINGS", enabled, _countof(enabled)) != 0;
        if (enabled_) start_ = std::chrono::steady_clock::now();
    }
    CollectionTimer(const CollectionTimer&) = delete;
    CollectionTimer& operator=(const CollectionTimer&) = delete;
    ~CollectionTimer() {
        if (enabled_)
            std::wosyncstream(std::wcerr) << L"[timing] " << label_ << L": "
                << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_).count()
                << L" ms\n";
    }
};
template<class Function>
auto Timed(const wchar_t* label, Function&& function) {
    CollectionTimer timer(label);
    return std::forward<Function>(function)();
}
}
