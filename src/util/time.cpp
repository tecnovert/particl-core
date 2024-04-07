// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/time.h>

#include <compat/compat.h>
#include <tinyformat.h>
#include <util/check.h>

#include <atomic>
#include <chrono>
#include <string>
#include <cstring>
#include <thread>

void UninterruptibleSleep(const std::chrono::microseconds& n) { std::this_thread::sleep_for(n); }

static std::atomic<int64_t> nMockTime(0); //!< For testing
static std::atomic<bool> mockTimeOffset(false); //!< Treat nMockTime as an offset

NodeClock::time_point NodeClock::now() noexcept
{
    const std::chrono::seconds mocktime{nMockTime.load(std::memory_order_relaxed)};

    if (mockTimeOffset) {
        auto time_since_epoch = std::chrono::system_clock::now().time_since_epoch();
        const auto ret{
            mocktime.count() ?
                time_since_epoch - mocktime :
                time_since_epoch };
        assert(ret > 0s);
        return time_point{ret};
    }

    const auto ret{
        mocktime.count() ?
            mocktime :
            std::chrono::system_clock::now().time_since_epoch()};
    assert(ret > 0s);
    return time_point{ret};
};

void SetMockTime(int64_t nMockTimeIn)
{
    Assert(nMockTimeIn >= 0);
    mockTimeOffset = false;
    nMockTime.store(nMockTimeIn, std::memory_order_relaxed);
}

void SetMockTimeOffset(int64_t offset_value)
{
    mockTimeOffset = true;
    nMockTime.store(time(nullptr) - offset_value, std::memory_order_relaxed);
}

void SetMockTime(std::chrono::seconds mock_time_in)
{
    nMockTime.store(mock_time_in.count(), std::memory_order_relaxed);
}

std::chrono::seconds GetMockTime()
{
    return std::chrono::seconds(nMockTime.load(std::memory_order_relaxed));
}

int64_t GetTime() { return GetTime<std::chrono::seconds>().count(); }

std::string FormatISO8601DateTime(int64_t nTime)
{
    const std::chrono::sys_seconds secs{std::chrono::seconds{nTime}};
    const auto days{std::chrono::floor<std::chrono::days>(secs)};
    const std::chrono::year_month_day ymd{days};
    const std::chrono::hh_mm_ss hms{secs - days};
    return strprintf("%04i-%02u-%02uT%02i:%02i:%02iZ", signed{ymd.year()}, unsigned{ymd.month()}, unsigned{ymd.day()}, hms.hours().count(), hms.minutes().count(), hms.seconds().count());
}

std::string FormatISO8601Date(int64_t nTime)
{
    const std::chrono::sys_seconds secs{std::chrono::seconds{nTime}};
    const auto days{std::chrono::floor<std::chrono::days>(secs)};
    const std::chrono::year_month_day ymd{days};
    return strprintf("%04i-%02u-%02u", signed{ymd.year()}, unsigned{ymd.month()}, unsigned{ymd.day()});
}

struct timeval MillisToTimeval(int64_t nTimeout)
{
    struct timeval timeout;
    timeout.tv_sec  = nTimeout / 1000;
    timeout.tv_usec = (nTimeout % 1000) * 1000;
    return timeout;
}

struct timeval MillisToTimeval(std::chrono::milliseconds ms)
{
    return MillisToTimeval(count_milliseconds(ms));
}

/** Returns the system time (not mockable) */
int64_t GetTimeMillis()
{
    auto duration = SteadyClock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
};

namespace part
{
std::string GetTimeString(int64_t timestamp, char *buffer, size_t nBuffer)
{
    struct tm* dt;
    time_t t = timestamp;
    dt = localtime(&t);

    strftime(buffer, nBuffer, "%Y-%m-%dT%H:%M:%S%z", dt); // %Z shows long strings on windows
    return std::string(buffer); // copies the null-terminated character sequence
}

static int daysInMonth(int year, int month)
{
    return month == 2 ? (year % 4 ? 28 : (year % 100 ? 29 : (year % 400 ? 28 : 29))) : ((month - 1) % 7 % 2 ? 30 : 31);
}

int64_t strToEpoch(const char *input, bool fFillMax)
{
    int year, month, day, hours, minutes, seconds;
    int n = sscanf(input, "%d-%d-%dT%d:%d:%d",
        &year, &month, &day, &hours, &minutes, &seconds);

    struct tm tm;
    memset(&tm, 0, sizeof(tm));

    if (n > 0 && year >= 1970 && year <= 9999)
        tm.tm_year = year - 1900;
    if (n > 1 && month > 0 && month < 13)
        tm.tm_mon = month - 1;          else if (fFillMax) { tm.tm_mon = 11; month = 12; }
    if (n > 2 && day > 0 && day < 32)
        tm.tm_mday = day;               else tm.tm_mday = fFillMax ? daysInMonth(year, month) : 1;
    if (n > 3 && hours >= 0 && hours < 24)
        tm.tm_hour = hours;             else if (fFillMax) tm.tm_hour = 23;
    if (n > 4 && minutes >= 0 && minutes < 60)
        tm.tm_min = minutes;            else if (fFillMax) tm.tm_min = 59;
    if (n > 5 && seconds >= 0 && seconds < 60)
        tm.tm_sec = seconds;            else if (fFillMax) tm.tm_sec = 59;

    return (int64_t) mktime(&tm);
}
}
