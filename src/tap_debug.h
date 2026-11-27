/*
 * The debug switch: TAP_DEBUG 1 gives the USB serial console (banner, AUD lines, stats, keys).
 * TAP_DEBUG 0 leaves all of it out and starts no USB serial; reflash such a build with BOOTSEL.
 * CMakeLists.txt sets it per build; a host build gets 1.
 */
#ifndef TAP_DEBUG_H
#define TAP_DEBUG_H

/* printf, for the debug build's tap_printf. */
#include <stdio.h>

/* On unless a build turns it off. */
#ifndef TAP_DEBUG
#define TAP_DEBUG 1
#endif

/* A console line in a debug build, nothing otherwise; `if (0)` keeps the arguments type-checked. */
#if TAP_DEBUG
#define tap_printf(...) printf(__VA_ARGS__)
#else
#define tap_printf(...) do { if (0) { printf(__VA_ARGS__); } } while (0)
#endif

#endif /* TAP_DEBUG_H */
