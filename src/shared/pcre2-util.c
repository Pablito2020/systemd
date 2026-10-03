/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dlfcn-util.h"
#include "hash-funcs.h"
#include "log.h"
#include "pcre2-util.h"

#if HAVE_PCRE2
#define PCRE2_RESTRICTED_MAX_PATTERN_LENGTH 4096
#define PCRE2_RESTRICTED_MAX_COMPILED_LENGTH (256 * 1024)
#define PCRE2_RESTRICTED_MAX_PARENTHESES_NESTING 128
#define PCRE2_RESTRICTED_MATCH_LIMIT 100000
#define PCRE2_RESTRICTED_DEPTH_LIMIT 1000
#define PCRE2_RESTRICTED_HEAP_LIMIT 1024

DLSYM_PROTOTYPE(pcre2_match_data_create) = NULL;
DLSYM_PROTOTYPE(pcre2_match_data_free) = NULL;
DLSYM_PROTOTYPE(pcre2_code_free) = NULL;
DLSYM_PROTOTYPE(pcre2_compile) = NULL;
DLSYM_PROTOTYPE(pcre2_get_error_message) = NULL;
DLSYM_PROTOTYPE(pcre2_match) = NULL;
DLSYM_PROTOTYPE(pcre2_get_ovector_pointer) = NULL;
static void *pcre2_dl = NULL;

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        pcre2_code_hash_ops_free,
        pcre2_code,
        (void (*)(const pcre2_code *, struct siphash*))trivial_hash_func,
        (int (*)(const pcre2_code *, const pcre2_code*))trivial_compare_func,
        sym_pcre2_code_free);
#else
const struct hash_ops pcre2_code_hash_ops_free = {};
#endif

int dlopen_pcre2(int log_level) {
#if HAVE_PCRE2
        LIBPCRE2_NOTE(suggested);

        /* So here's something weird: PCRE2 actually renames the symbols exported by the library via C
         * macros, so that the exported symbols carry a suffix "_8" but when used from C the suffix is
         * gone. In the argument list below we ignore this mangling. Surprisingly (at least to me), we
         * actually get away with that. That's because DLSYM_ARG() uses STRINGIFY() to generate a string
         * version of the symbol name, and that resolves the macro mapping implicitly already, so that the
         * string actually contains the "_8" suffix already due to that and we don't have to append it
         * manually anymore. C is weird. 🤯 */

        return dlopen_many_sym_or_warn(
                        &pcre2_dl, "libpcre2-8.so.0", log_level,
                        DLSYM_ARG(pcre2_match_data_create),
                        DLSYM_ARG(pcre2_match_data_free),
                        DLSYM_ARG(pcre2_code_free),
                        DLSYM_ARG(pcre2_compile),
                        DLSYM_ARG(pcre2_get_error_message),
                        DLSYM_ARG(pcre2_match),
                        DLSYM_ARG(pcre2_get_ovector_pointer));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "PCRE2 support is not compiled in.");
#endif
}

int pattern_compile_restricted(const char *pattern, pcre2_code **ret) {
#if HAVE_PCRE2
        typedef pcre2_compile_context* (*context_create_t)(pcre2_general_context*);
        typedef void (*context_free_t)(pcre2_compile_context*);
        typedef int (*set_limit_t)(pcre2_compile_context*, PCRE2_SIZE);
        typedef int (*set_nesting_t)(pcre2_compile_context*, uint32_t);
        _cleanup_(pcre2_code_freep) pcre2_code *code = NULL;
        pcre2_compile_context *context;
        context_create_t create;
        context_free_t free_context;
        set_limit_t set_length, set_compiled_length;
        set_nesting_t set_nesting;
        PCRE2_SIZE erroroffset;
        int errorcode, r;

        assert(pattern);
        assert(ret);

        if (strlen(pattern) > PCRE2_RESTRICTED_MAX_PATTERN_LENGTH)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Pattern exceeds maximum length of %zu bytes.",
                                       (size_t) PCRE2_RESTRICTED_MAX_PATTERN_LENGTH);

        r = dlopen_pcre2(LOG_DEBUG);
        if (r < 0)
                return r;

        create = dlsym(pcre2_dl, STRINGIFY(pcre2_compile_context_create));
        free_context = dlsym(pcre2_dl, STRINGIFY(pcre2_compile_context_free));
        set_length = dlsym(pcre2_dl, STRINGIFY(pcre2_set_max_pattern_length));
        set_compiled_length = dlsym(pcre2_dl, STRINGIFY(pcre2_set_max_pattern_compiled_length));
        set_nesting = dlsym(pcre2_dl, STRINGIFY(pcre2_set_parens_nest_limit));
        if (!create || !free_context || !set_length || !set_compiled_length || !set_nesting)
                return -EOPNOTSUPP;

        context = create(NULL);
        if (!context)
                return -ENOMEM;

        r = set_length(context, PCRE2_RESTRICTED_MAX_PATTERN_LENGTH);
        if (r >= 0)
                r = set_compiled_length(context, PCRE2_RESTRICTED_MAX_COMPILED_LENGTH);
        if (r >= 0)
                r = set_nesting(context, PCRE2_RESTRICTED_MAX_PARENTHESES_NESTING);
        if (r >= 0)
                code = sym_pcre2_compile((PCRE2_SPTR8) pattern, PCRE2_ZERO_TERMINATED, 0,
                                         &errorcode, &erroroffset, context);
        free_context(context);
        if (r < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set PCRE2 pattern limits: %d", r);
        if (!code) {
                unsigned char buf[LINE_MAX];

                r = sym_pcre2_get_error_message(errorcode, buf, sizeof(buf));
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Bad pattern '%s' at offset %zu: %s",
                                       pattern, (size_t) erroroffset,
                                       r < 0 ? "unknown error" : (char*) buf);
        }

        *ret = TAKE_PTR(code);
        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int pattern_matches_restricted(pcre2_code *compiled_pattern, const char *message, size_t size) {
#if HAVE_PCRE2
        typedef pcre2_match_context* (*context_create_t)(pcre2_general_context*);
        typedef void (*context_free_t)(pcre2_match_context*);
        typedef int (*set_limit_t)(pcre2_match_context*, uint32_t);
        _cleanup_(pcre2_match_data_freep) pcre2_match_data *md = NULL;
        pcre2_match_context *context;
        context_create_t create;
        context_free_t free_context;
        set_limit_t set_match, set_depth, set_heap;
        int r;

        assert(compiled_pattern);
        assert(message);

        create = dlsym(pcre2_dl, STRINGIFY(pcre2_match_context_create));
        free_context = dlsym(pcre2_dl, STRINGIFY(pcre2_match_context_free));
        set_match = dlsym(pcre2_dl, STRINGIFY(pcre2_set_match_limit));
        set_depth = dlsym(pcre2_dl, STRINGIFY(pcre2_set_depth_limit));
        set_heap = dlsym(pcre2_dl, STRINGIFY(pcre2_set_heap_limit));
        if (!create || !free_context || !set_match || !set_depth || !set_heap)
                return -EOPNOTSUPP;

        context = create(NULL);
        if (!context)
                return -ENOMEM;

        r = set_match(context, PCRE2_RESTRICTED_MATCH_LIMIT);
        if (r >= 0)
                r = set_depth(context, PCRE2_RESTRICTED_DEPTH_LIMIT);
        if (r >= 0)
                r = set_heap(context, PCRE2_RESTRICTED_HEAP_LIMIT);
        if (r < 0) {
                free_context(context);
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set PCRE2 match limits: %d", r);
        }

        md = sym_pcre2_match_data_create(1, NULL);
        if (!md) {
                free_context(context);
                return log_oom();
        }

        r = sym_pcre2_match(compiled_pattern, (PCRE2_SPTR8) message, size, 0, 0, md, context);
        free_context(context);

        if (r == PCRE2_ERROR_NOMATCH)
                return false;
        if (r < 0) {
                unsigned char buf[LINE_MAX];
                int k;

                k = sym_pcre2_get_error_message(r, buf, sizeof(buf));
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Pattern matching failed: %s",
                                       k < 0 ? "unknown error" : (char*) buf);
        }
        return true;
#else
        return -EOPNOTSUPP;
#endif
}

int pattern_compile_and_log(const char *pattern, PatternCompileCase case_, pcre2_code **ret) {
#if HAVE_PCRE2
        PCRE2_SIZE erroroffset;
        _cleanup_(pcre2_code_freep) pcre2_code *p = NULL;
        unsigned flags = 0;
        int errorcode, r;

        assert(pattern);

        r = dlopen_pcre2(LOG_ERR);
        if (r < 0)
                return r;

        if (case_ == PATTERN_COMPILE_CASE_INSENSITIVE)
                flags = PCRE2_CASELESS;
        else if (case_ == PATTERN_COMPILE_CASE_AUTO) {
                _cleanup_(pcre2_match_data_freep) pcre2_match_data *md = NULL;
                bool has_case;
                _cleanup_(pcre2_code_freep) pcre2_code *cs = NULL;

                md = sym_pcre2_match_data_create(1, NULL);
                if (!md)
                        return log_oom();

                r = pattern_compile_and_log("[[:upper:]]", PATTERN_COMPILE_CASE_SENSITIVE, &cs);
                if (r < 0)
                        return r;

                r = sym_pcre2_match(cs, (PCRE2_SPTR8) pattern, PCRE2_ZERO_TERMINATED, 0, 0, md, NULL);
                has_case = r >= 0;

                flags = !has_case * PCRE2_CASELESS;
        }

        log_debug("Doing case %s matching based on %s",
                  flags & PCRE2_CASELESS ? "insensitive" : "sensitive",
                  case_ != PATTERN_COMPILE_CASE_AUTO ? "request" : "pattern casing");

        p = sym_pcre2_compile((PCRE2_SPTR8) pattern,
                              PCRE2_ZERO_TERMINATED, flags, &errorcode, &erroroffset, NULL);
        if (!p) {
                unsigned char buf[LINE_MAX];

                r = sym_pcre2_get_error_message(errorcode, buf, sizeof buf);

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Bad pattern \"%s\": %s", pattern,
                                       r < 0 ? "unknown error" : (char *)buf);
        }

        if (ret)
                *ret = TAKE_PTR(p);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "PCRE2 support is not compiled in.");
#endif
}

int pattern_matches_and_log(pcre2_code *compiled_pattern, const char *message, size_t size, size_t *ret_ovec) {
#if HAVE_PCRE2
        _cleanup_(pcre2_match_data_freep) pcre2_match_data *md = NULL;
        int r;

        assert(compiled_pattern);
        assert(message);
        /* pattern_compile_and_log() must be called before this function is called and that function already
         * dlopens pcre2 so we can assert on it being available here. */
        assert(sym_pcre2_match);

        md = sym_pcre2_match_data_create(1, NULL);
        if (!md)
                return log_oom();

        r = sym_pcre2_match(compiled_pattern,
                            (const unsigned char *)message,
                            size,
                            0,      /* start at offset 0 in the subject */
                            0,      /* default options */
                            md,
                            NULL);
        if (r == PCRE2_ERROR_NOMATCH)
                return false;
        if (r < 0) {
                unsigned char buf[LINE_MAX];

                r = sym_pcre2_get_error_message(r, buf, sizeof(buf));
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Pattern matching failed: %s",
                                       r < 0 ? "unknown error" : (char*) buf);
        }

        if (ret_ovec) {
                ret_ovec[0] = sym_pcre2_get_ovector_pointer(md)[0];
                ret_ovec[1] = sym_pcre2_get_ovector_pointer(md)[1];
        }

        return true;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "PCRE2 support is not compiled in.");
#endif
}
