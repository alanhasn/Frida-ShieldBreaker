// Raw C source for the Stalker hot-path callout, compiled at runtime by
// Frida's CModule directly into the target process (no build-time
// toolchain of ours is involved -- Frida supplies its own C compiler
// inside the agent runtime). Kept in its own file, separate from
// stalker_tracer.js's orchestration logic, so the C and the JS that
// drives it are easy to read independently.
//
// Design constraint: this file does as little as possible. Stalker
// calls on_hit() once per instrumented instruction *execution*, which
// for a hot loop can be millions of times a second -- so the only work
// here is a plain array write, no allocation, no syscalls, no JS/V8
// crossing at all. Everything else (deciding which instructions get
// instrumented in the first place, reading the buffer back out,
// formatting a report) happens in JS, but only at block-compile time or
// on an explicit drain request -- both comparatively rare.
//
// Single-thread-per-session by design (see stalker_tracer.js): each
// compiled instance of on_hit() is wired to at most one followed OS
// thread at a time, so plain (non-atomic) increments are correct and
// avoid depending on atomic builtins that aren't guaranteed to exist in
// every CModule toolchain (CModule defaults to TinyCC, not full
// GCC/Clang, unless the host explicitly configures a real toolchain).
export const NATIVE_TRACER_SOURCE = `
#include <gum/gumdefs.h>

#define RING_CAPACITY 8192

typedef struct _TraceRecord TraceRecord;

struct _TraceRecord
{
  guint64 seq;
  GumAddress address;
};

TraceRecord ring[RING_CAPACITY];
guint64 sequence = 0;

void
on_hit (GumCpuContext * ctx, gpointer user_data)
{
  guint64 slot = sequence % RING_CAPACITY;

#if defined (HAVE_ARM64) || defined (__aarch64__)
  ring[slot].address = (GumAddress) ctx->pc;
#elif defined (HAVE_ARM) || defined (__arm__)
  ring[slot].address = (GumAddress) ctx->pc;
#elif defined (HAVE_X86_64) || defined (__x86_64__)
  ring[slot].address = (GumAddress) ctx->rip;
#elif defined (HAVE_I386) || defined (__i386__)
  ring[slot].address = (GumAddress) ctx->eip;
#else
  ring[slot].address = 0;
#endif
  ring[slot].seq = sequence;

  sequence++;
}
`;

// Must match the C struct above exactly: two 8-byte fields (guint64 seq,
// GumAddress address -- GumAddress is itself a 64-bit unsigned value
// regardless of target word size), naturally 8-byte aligned, no padding.
export const RING_CAPACITY = 8192;
export const RECORD_SIZE_BYTES = 16;
