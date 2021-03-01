/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// Ensure we can't call OPENSSL_malloc circularly.
#define _BORINGSSL_PROHIBIT_OPENSSL_MALLOC
#include "internal.h"

#if defined(OPENSSL_WINDOWS_THREADS)

OPENSSL_MSVC_PRAGMA(warning(push, 3))
#include <windows.h>
OPENSSL_MSVC_PRAGMA(warning(pop))

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/mem.h>


#ifdef OPENSSL_WINDOWS_ALLOW_WINXP

union run_once_arg_t {
  void (*func)(void);
  void *data;
};

static void run_once(CRYPTO_once_t *once, void (*init)(union run_once_arg_t),
                     union run_once_arg_t arg) {
  /* Values must be aligned. */
  assert((((uintptr_t) once) & 3) == 0);

  /* This assumes that reading *once has acquire semantics. This should be true
   * on x86 and x86-64, where we expect Windows to run. */
#if !defined(OPENSSL_X86) && !defined(OPENSSL_X86_64)
#error "Windows once code may not work on other platforms." \
       "You can use InitOnceBeginInitialize on >=Vista"
#endif
  if (*once == 1) {
    return;
  }

  for (;;) {
    switch (InterlockedCompareExchange(once, 2, 0)) {
      case 0:
        /* The value was zero so we are the first thread to call |CRYPTO_once|
         * on it. */
        init(arg);
        /* Write one to indicate that initialisation is complete. */
        InterlockedExchange(once, 1);
        return;

      case 1:
        /* Another thread completed initialisation between our fast-path check
         * and |InterlockedCompareExchange|. */
        return;

      case 2:
        /* Another thread is running the initialisation. Switch to it then try
         * again. */
        SwitchToThread();
        break;

      default:
        abort();
    }
  }
}

static void call_once_init(union run_once_arg_t arg) {
  arg.func();
}

void CRYPTO_once(CRYPTO_once_t *in_once, void (*init)(void)) {
  union run_once_arg_t arg;
  arg.func = init;
  run_once(in_once, call_once_init, arg);
}

void CRYPTO_MUTEX_init(CRYPTO_MUTEX *lock) {
  if (!InitializeCriticalSectionAndSpinCount(lock, 0x400)) {
    abort();
  }
}

void CRYPTO_MUTEX_lock_read(CRYPTO_MUTEX *lock) {
  /* Since we have to support Windows XP, read locks are actually exclusive. */
  EnterCriticalSection(lock);
}

void CRYPTO_MUTEX_lock_write(CRYPTO_MUTEX *lock) {
  EnterCriticalSection(lock);
}

void CRYPTO_MUTEX_unlock_read(CRYPTO_MUTEX *lock) {
  LeaveCriticalSection(lock);
}

void CRYPTO_MUTEX_unlock_write(CRYPTO_MUTEX *lock) {
  LeaveCriticalSection(lock);
}

void CRYPTO_MUTEX_cleanup(CRYPTO_MUTEX *lock) {
  DeleteCriticalSection(lock);
}

static CRITICAL_SECTION g_destructors_lock;
static thread_local_destructor_t g_destructors[NUM_OPENSSL_THREAD_LOCALS];

static CRYPTO_once_t g_thread_local_init_once = CRYPTO_ONCE_INIT;
static DWORD g_thread_local_key;
static int g_thread_local_failed;

static void thread_local_init(void) {
  if (!InitializeCriticalSectionAndSpinCount(&g_destructors_lock, 0x400)) {
    g_thread_local_failed = 1;
    return;
  }
  g_thread_local_key = TlsAlloc();
  g_thread_local_failed = (g_thread_local_key == TLS_OUT_OF_INDEXES);
}

static void NTAPI thread_local_destructor(PVOID module, DWORD reason,
                                          PVOID reserved) {
  // Only free memory on |DLL_THREAD_DETACH|, not |DLL_PROCESS_DETACH|. In
  // VS2015's debug runtime, the C runtime has been unloaded by the time
  // |DLL_PROCESS_DETACH| runs. See https://crbug.com/575795. This is consistent
  // with |pthread_key_create| which does not call destructors on process exit,
  // only thread exit.
  if (reason != DLL_THREAD_DETACH) {
    return;
  }

  CRYPTO_once(&g_thread_local_init_once, thread_local_init);
  if (g_thread_local_failed) {
    return;
  }

  void **pointers = (void**) TlsGetValue(g_thread_local_key);
  if (pointers == NULL) {
    return;
  }

  thread_local_destructor_t destructors[NUM_OPENSSL_THREAD_LOCALS];

  EnterCriticalSection(&g_destructors_lock);
  OPENSSL_memcpy(destructors, g_destructors, sizeof(destructors));
  LeaveCriticalSection(&g_destructors_lock);

  for (unsigned i = 0; i < NUM_OPENSSL_THREAD_LOCALS; i++) {
    if (destructors[i] != NULL) {
      destructors[i](pointers[i]);
    }
  }

  free(pointers);
}

// Thread Termination Callbacks.
//
// Windows doesn't support a per-thread destructor with its TLS primitives.
// So, we build it manually by inserting a function to be called on each
// thread's exit. This magic is from http://www.codeproject.com/threads/tls.asp
// and it works for VC++ 7.0 and later.
//
// Force a reference to _tls_used to make the linker create the TLS directory
// if it's not already there. (E.g. if __declspec(thread) is not used). Force
// a reference to p_thread_callback_boringssl to prevent whole program
// optimization from discarding the variable.
//
// Note, in the prefixed build, |p_thread_callback_boringssl| may be a macro.
#define STRINGIFY(x) #x
#define EXPAND_AND_STRINGIFY(x) STRINGIFY(x)
#ifdef _WIN64
__pragma(comment(linker, "/INCLUDE:_tls_used"))
__pragma(comment(
    linker, "/INCLUDE:" EXPAND_AND_STRINGIFY(p_thread_callback_boringssl)))
#else
__pragma(comment(linker, "/INCLUDE:__tls_used"))
__pragma(comment(
    linker, "/INCLUDE:_" EXPAND_AND_STRINGIFY(p_thread_callback_boringssl)))
#endif

// .CRT$XLA to .CRT$XLZ is an array of PIMAGE_TLS_CALLBACK pointers that are
// called automatically by the OS loader code (not the CRT) when the module is
// loaded and on thread creation. They are NOT called if the module has been
// loaded by a LoadLibrary() call. It must have implicitly been loaded at
// process startup.
//
// By implicitly loaded, I mean that it is directly referenced by the main EXE
// or by one of its dependent DLLs. Delay-loaded DLL doesn't count as being
// implicitly loaded.
//
// See VC\crt\src\tlssup.c for reference.

// The linker must not discard p_thread_callback_boringssl. (We force a
// reference to this variable with a linker /INCLUDE:symbol pragma to ensure
// that.) If this variable is discarded, the OnThreadExit function will never
// be called.
#ifdef _WIN64

// .CRT section is merged with .rdata on x64 so it must be constant data.
#pragma const_seg(".CRT$XLC")
// When defining a const variable, it must have external linkage to be sure the
// linker doesn't discard it.
extern const PIMAGE_TLS_CALLBACK p_thread_callback_boringssl;
const PIMAGE_TLS_CALLBACK p_thread_callback_boringssl = thread_local_destructor;
// Reset the default section.
#pragma const_seg()

#else

#pragma data_seg(".CRT$XLC")
PIMAGE_TLS_CALLBACK p_thread_callback_boringssl = thread_local_destructor;
// Reset the default section.
#pragma data_seg()

#endif  // _WIN64

static void **get_thread_locals(void) {
  // |TlsGetValue| clears the last error even on success, so that callers may
  // distinguish it successfully returning NULL or failing. It is documented to
  // never fail if the argument is a valid index from |TlsAlloc|, so we do not
  // need to handle this.
  //
  // However, this error-mangling behavior interferes with the caller's use of
  // |GetLastError|. In particular |SSL_get_error| queries the error queue to
  // determine whether the caller should look at the OS's errors. To avoid
  // destroying state, save and restore the Windows error.
  //
  // https://msdn.microsoft.com/en-us/library/windows/desktop/ms686812(v=vs.85).aspx
  DWORD last_error = GetLastError();
  void **ret = TlsGetValue(g_thread_local_key);
  SetLastError(last_error);
  return ret;
}

void *CRYPTO_get_thread_local(thread_local_data_t index) {
  CRYPTO_once(&g_thread_local_init_once, thread_local_init);
  if (g_thread_local_failed) {
    return NULL;
  }

  void **pointers = get_thread_locals();
  if (pointers == NULL) {
    return NULL;
  }
  return pointers[index];
}

int CRYPTO_set_thread_local(thread_local_data_t index, void *value,
                            thread_local_destructor_t destructor) {
  CRYPTO_once(&g_thread_local_init_once, thread_local_init);
  if (g_thread_local_failed) {
    destructor(value);
    return 0;
  }

  void **pointers = get_thread_locals();
  if (pointers == NULL) {
    pointers = malloc(sizeof(void *) * NUM_OPENSSL_THREAD_LOCALS);
    if (pointers == NULL) {
      destructor(value);
      return 0;
    }
    OPENSSL_memset(pointers, 0, sizeof(void *) * NUM_OPENSSL_THREAD_LOCALS);
    if (TlsSetValue(g_thread_local_key, pointers) == 0) {
      free(pointers);
      destructor(value);
      return 0;
    }
  }

  EnterCriticalSection(&g_destructors_lock);
  g_destructors[index] = destructor;
  LeaveCriticalSection(&g_destructors_lock);

  pointers[index] = value;
  return 1;
}

#else // OPENSSL_WINDOWS_ALLOW_WINXP

static BOOL CALLBACK call_once_init(INIT_ONCE *once, void *arg, void **out) {
  void (**init)(void) = (void (**)(void))arg;
  (**init)();
  return TRUE;
}

void CRYPTO_once(CRYPTO_once_t *once, void (*init)(void)) {
  if (!InitOnceExecuteOnce(once, call_once_init, &init, NULL)) {
    abort();
  }
}

void CRYPTO_MUTEX_init(CRYPTO_MUTEX *lock) {
  InitializeSRWLock(lock);
}

void CRYPTO_MUTEX_lock_read(CRYPTO_MUTEX *lock) {
  AcquireSRWLockShared(lock);
}

void CRYPTO_MUTEX_lock_write(CRYPTO_MUTEX *lock) {
  AcquireSRWLockExclusive(lock);
}

void CRYPTO_MUTEX_unlock_read(CRYPTO_MUTEX *lock) {
  ReleaseSRWLockShared(lock);
}

void CRYPTO_MUTEX_unlock_write(CRYPTO_MUTEX *lock) {
  ReleaseSRWLockExclusive(lock);
}

void CRYPTO_MUTEX_cleanup(CRYPTO_MUTEX *lock) {
  // SRWLOCKs require no cleanup.
}

static SRWLOCK g_destructors_lock = SRWLOCK_INIT;

static thread_local_destructor_t g_destructors[NUM_OPENSSL_THREAD_LOCALS];

static CRYPTO_once_t g_thread_local_init_once = CRYPTO_ONCE_INIT;
static DWORD g_thread_local_key;
static int g_thread_local_failed;

static void NTAPI thread_local_destructor(void* data);

static void thread_local_init(void) {
  g_thread_local_key = FlsAlloc(thread_local_destructor);
  g_thread_local_failed = (g_thread_local_key == FLS_OUT_OF_INDEXES);
}

static void NTAPI thread_local_destructor(void* data) {
  CRYPTO_once(&g_thread_local_init_once, thread_local_init);
  if (g_thread_local_failed) {
    return;
  }

  void **pointers = (void**) data;
  if (pointers == NULL) {
    return;
  }

  thread_local_destructor_t destructors[NUM_OPENSSL_THREAD_LOCALS];

  AcquireSRWLockExclusive(&g_destructors_lock);
  OPENSSL_memcpy(destructors, g_destructors, sizeof(destructors));
  ReleaseSRWLockExclusive(&g_destructors_lock);

  for (unsigned i = 0; i < NUM_OPENSSL_THREAD_LOCALS; i++) {
    if (destructors[i] != NULL) {
      destructors[i](pointers[i]);
    }
  }

  free(pointers);
}

static void **get_thread_locals(void) {
  // |FlsGetValue| clears the last error even on success, so that callers may
  // distinguish it successfully returning NULL or failing. It is documented to
  // never fail if the argument is a valid index from |FlsAlloc|, so we do not
  // need to handle this.
  //
  // However, this error-mangling behavior interferes with the caller's use of
  // |GetLastError|. In particular |SSL_get_error| queries the error queue to
  // determine whether the caller should look at the OS's errors. To avoid
  // destroying state, save and restore the Windows error.
  //
  // https://msdn.microsoft.com/en-us/library/windows/desktop/ms686812(v=vs.85).aspx
  DWORD last_error = GetLastError();
  void **ret = FlsGetValue(g_thread_local_key);
  SetLastError(last_error);
  return ret;
}

void *CRYPTO_get_thread_local(thread_local_data_t index) {
  CRYPTO_once(&g_thread_local_init_once, thread_local_init);
  if (g_thread_local_failed) {
    return NULL;
  }

  void **pointers = get_thread_locals();
  if (pointers == NULL) {
    return NULL;
  }
  return pointers[index];
}

int CRYPTO_set_thread_local(thread_local_data_t index, void *value,
                            thread_local_destructor_t destructor) {
  CRYPTO_once(&g_thread_local_init_once, thread_local_init);
  if (g_thread_local_failed) {
    destructor(value);
    return 0;
  }

  void **pointers = get_thread_locals();
  if (pointers == NULL) {
    pointers = malloc(sizeof(void *) * NUM_OPENSSL_THREAD_LOCALS);
    if (pointers == NULL) {
      destructor(value);
      return 0;
    }
    OPENSSL_memset(pointers, 0, sizeof(void *) * NUM_OPENSSL_THREAD_LOCALS);
    if (FlsSetValue(g_thread_local_key, pointers) == 0) {
      free(pointers);
      destructor(value);
      return 0;
    }
  }

  AcquireSRWLockExclusive(&g_destructors_lock);
  g_destructors[index] = destructor;
  ReleaseSRWLockExclusive(&g_destructors_lock);

  pointers[index] = value;
  return 1;
}

#endif // OPENSSL_WINDOWS_ALLOW_WINXP

#endif  // OPENSSL_WINDOWS_THREADS
