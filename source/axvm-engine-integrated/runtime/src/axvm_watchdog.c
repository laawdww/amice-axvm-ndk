#include "axvm_watchdog.h"
#include "axvm_guard.h"
#include "axvm_guard_svc.h"

#include <pthread.h>
#include <unistd.h>

int axvm_watchdog_enabled(void)
{
#if defined(AXVM_WATCHDOG) && AXVM_WATCHDOG && defined(AXVM_SVC_ANTIDEBUG) && \
    AXVM_SVC_ANTIDEBUG && defined(AXVM_ENABLE_GUARD) && AXVM_ENABLE_GUARD
    return 1;
#else
    return 0;
#endif
}

#if defined(AXVM_WATCHDOG) && AXVM_WATCHDOG && defined(AXVM_SVC_ANTIDEBUG) && \
    AXVM_SVC_ANTIDEBUG && defined(AXVM_ENABLE_GUARD) && AXVM_ENABLE_GUARD

#define AXVM_WATCHDOG_PERIOD_US 400000u

static pthread_t g_wd_thread;
static volatile int g_wd_running;
static volatile int g_wd_started;
static volatile uint32_t g_wd_ticks;

static void *watchdog_thread(void *arg)
{
    (void)arg;
    while (g_wd_running) {
        usleep(AXVM_WATCHDOG_PERIOD_US);
        if (!g_wd_running) {
            break;
        }
        g_wd_ticks++;
        axvm_guard_state_t *st = axvm_guard_global();
        if (!st || st->pause_depth > 0) {
            continue;
        }
        if (axvm_guard_svc_probe_tracer()) {
            axvm_guard_trip(st, AXVM_GUARD_PTRACE | AXVM_GUARD_WATCHDOG);
        }
    }
    return NULL;
}

void axvm_watchdog_start(void)
{
    if (g_wd_started) {
        return;
    }
    g_wd_running = 1;
    if (pthread_create(&g_wd_thread, NULL, watchdog_thread, NULL) != 0) {
        g_wd_running = 0;
        return;
    }
    g_wd_started = 1;
}

void axvm_watchdog_stop(void)
{
    if (!g_wd_started) {
        return;
    }
    g_wd_running = 0;
    pthread_join(g_wd_thread, NULL);
    g_wd_started = 0;
}

uint32_t axvm_watchdog_ticks(void)
{
    return g_wd_ticks;
}

int axvm_watchdog_selftest(void)
{
    axvm_watchdog_start();
    usleep(AXVM_WATCHDOG_PERIOD_US + 100000u);
    uint32_t t = axvm_watchdog_ticks();
    return (g_wd_started && t > 0u) ? 0 : 1;
}

#else

void axvm_watchdog_start(void)
{
}

void axvm_watchdog_stop(void)
{
}

uint32_t axvm_watchdog_ticks(void)
{
    return 0;
}

int axvm_watchdog_selftest(void)
{
    return 0;
}

#endif
