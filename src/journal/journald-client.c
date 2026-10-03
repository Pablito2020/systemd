/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "journald-client.h"
#include "journald-context.h"
#include "log.h"
#include "nulstr-util.h"
#include "pcre2-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"

#define USER_LOG_FILTER_XATTRS_MAX (32U * 1024U)
#define USER_FILTERS_MAX 32

static int client_parse_log_filter_nulstr(const char *nulstr, size_t len, Set **ret, bool is_user_filter, unsigned *total_user_filters) {
        _cleanup_set_free_ Set *s = NULL;
        _cleanup_strv_free_ char **patterns_strv = NULL;
        int r;

        assert(nulstr);
        assert(ret);

        patterns_strv = strv_parse_nulstr(nulstr, len);
        if (!patterns_strv)
                return log_oom_debug();

        STRV_FOREACH(pattern, patterns_strv) {
                _cleanup_(pcre2_code_freep) pcre2_code *compiled_pattern = NULL;

                if (is_user_filter && (++*total_user_filters > USER_FILTERS_MAX))
                        return -E2BIG;

                r = is_user_filter ? pattern_compile_restricted(*pattern, &compiled_pattern)
                              : pattern_compile_and_log(*pattern, 0, &compiled_pattern);
                if (r < 0)
                        return r;

                r = set_ensure_consume(&s, &pcre2_code_hash_ops_free, TAKE_PTR(compiled_pattern));
                if (r < 0)
                        return log_debug_errno(r, "Failed to insert regex into set: %m");
        }

        *ret = TAKE_PTR(s);

        return 0;
}

static int client_read_log_filter_xattr(
                ClientContext *c,
                const char *cgroup,
                bool is_user_filter) {

        unsigned total_user_filters = 0;
        int r;

        Set **allowed_patterns = is_user_filter ? &c->user_log_filter_allowed_patterns : &c->log_filter_allowed_patterns;
        Set **denied_patterns = is_user_filter ? &c->user_log_filter_denied_patterns : &c->log_filter_denied_patterns;

        _cleanup_free_ char *xattr = NULL;
        size_t xattr_size = 0;
        r = cg_get_xattr(cgroup, "user.journald_log_filter_patterns", &xattr, &xattr_size);
        if (ERRNO_IS_NEG_XATTR_ABSENT(r)) {
                *allowed_patterns = set_free(*allowed_patterns);
                *denied_patterns = set_free(*denied_patterns);
                return 0;
        }
        if (r < 0)
                return is_user_filter ? r : log_debug_errno(r, "Failed to get user.journald_log_filter_patterns xattr for %s: %m", cgroup);

        if (is_user_filter && xattr_size > USER_LOG_FILTER_XATTRS_MAX)
                return -E2BIG;

        const char *xattr_end = xattr + xattr_size;

        /* We expect '0xff' to be present in the attribute, even if the lists are empty. We expect the
         * following:
         * - Allow list, but no deny list: 0xXX, ...., 0xff
         * - No allow list, but deny list: 0xff, 0xXX, ....
         * - Allow list, and deny list:    0xXX, ...., 0xff, 0xXX, ....
         * This is due to the fact allowed and denied patterns list are two nulstr joined together with '0xff'.
         * None of the allowed or denied nulstr have a nul-termination character.
         *
         * We do not expect both the allow list and deny list to be empty, as this condition is tested
         * before writing to xattr. */
        const char *deny_list_xattr = memchr(xattr, (char)0xff, xattr_size);
        if (!deny_list_xattr)
                return is_user_filter ? -EBADMSG : log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                        "Missing delimiter in cgroup user.journald_log_filter_patterns attribute.");

        _cleanup_set_free_ Set *allow_list = NULL;
        r = client_parse_log_filter_nulstr(xattr, deny_list_xattr - xattr, &allow_list, is_user_filter, &total_user_filters);
        if (r < 0)
                return r;

        /* Use 'deny_list_xattr + 1' to skip '0xff'. */
        ++deny_list_xattr;
        _cleanup_set_free_ Set *deny_list = NULL;
        r = client_parse_log_filter_nulstr(deny_list_xattr, xattr_end - deny_list_xattr, &deny_list, is_user_filter, &total_user_filters);
        if (r < 0)
                return r;

        set_free_and_replace(*allowed_patterns, allow_list);
        set_free_and_replace(*denied_patterns, deny_list);

        return 0;
}

int client_context_read_log_filter_patterns(ClientContext *c, const char *cgroup) {
        _cleanup_free_ char *system_unit_cgroup = NULL, *deepest_unit_cgroup = NULL;
        int r;

        assert(c);
        assert(cgroup);

        r = cg_path_get_unit_path(cgroup, &system_unit_cgroup);
        if (r < 0)
                return log_debug_errno(r, "Failed to get the unit's cgroup path for %s: %m", cgroup);

        c->user_log_filter_allowed_patterns = set_free(c->user_log_filter_allowed_patterns);
        c->user_log_filter_denied_patterns = set_free(c->user_log_filter_denied_patterns);

        r = client_read_log_filter_xattr(c, system_unit_cgroup, /* is_user_filter= */ false);
        if (r < 0)
                return r;

        if (cg_get_xattr_bool(system_unit_cgroup, "trusted.journald_log_filter_patterns_delegate") <= 0)
                return 0;

        r = cg_find_deepest_non_slice_unit(cgroup, &deepest_unit_cgroup);
        if (r <= 0)
                return r;

        if (streq(deepest_unit_cgroup, system_unit_cgroup))
                return 0;

        return client_read_log_filter_xattr(c, deepest_unit_cgroup, /* is_user_filter= */ true);
}

static bool system_log_filter_allows(
                const ClientContext *c,
                const char *message,
                size_t len) {

        pcre2_code *regex;

        SET_FOREACH(regex, c->log_filter_denied_patterns) {
                if (pattern_matches_and_log(regex, message, len, NULL) > 0)
                        return false;
        }

        if (set_isempty(c->log_filter_allowed_patterns))
                return true;

        SET_FOREACH(regex, c->log_filter_allowed_patterns) {
                if (pattern_matches_and_log(regex, message, len, NULL) > 0)
                        return true;
        }

        return false;
}

static bool user_log_filter_allows(
                const ClientContext *c,
                const char *message,
                size_t len) {

        pcre2_code *regex;
        bool deny_match = false, allow_match = false;
        int r;

        SET_FOREACH(regex, c->user_log_filter_denied_patterns) {
                r = pattern_matches_restricted(regex, message, len);
                if (r < 0)
                        return true;
                if (r > 0)
                        deny_match = true;
        }

        SET_FOREACH(regex, c->user_log_filter_allowed_patterns) {
                r = pattern_matches_restricted(regex, message, len);
                if (r < 0)
                        return true;
                if (r > 0)
                        allow_match = true;
        }

        if (deny_match)
                return false;

        if (set_isempty(c->user_log_filter_allowed_patterns))
                return true;

        return allow_match;
}

int client_context_check_keep_log(ClientContext *c, const char *message, size_t len) {
        if (!c || !message)
                return true;

        if (!system_log_filter_allows(c, message, len))
                return false;

        return user_log_filter_allows(c, message, len);
}
