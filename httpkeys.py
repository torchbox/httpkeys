#! /usr/bin/env python
# vim:sw=4 ts=4 et:
#
# Copyright (c) 2016 Torchbox Ltd.
# 2016-05-22 ft: created
#

from flask import Flask, request, make_response
app = Flask(__name__)

import ldap, ldap.filter
import settings

def text_response(text, code = 200):
    response = make_response(text, code)
    response.headers['Content-Type'] = 'text/plain;charset=UTF-8'
    return response

def get_ldap_connection(uri):
    conn = ldap.initialize(uri)
    conn.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
    conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    conn.set_option(ldap.OPT_X_TLS_CACERTFILE, settings.LDAP_TLS_CERT)
    conn.start_tls_s()
    return conn

# Given an access key, return a list of users matching the key.  Key format
# can be:
#
#   username
#   @groupname
#   $special:arg1:arg2:...
#
# Special keys are defined in settings.

def users_for_access(conn, acc):
    if acc == '':
        return []

    if acc[0] == '@':
        # Group lookup
        ret = conn.search_s(
                    settings.LDAP_GROUP_BASE,
                    ldap.SCOPE_SUBTREE,
                    settings.LDAP_GROUP_SEARCH_FILTER.format(group = ldap.filter.escape_filter_chars(acc[1:])),
                    [ settings.LDAP_GROUP_MEMBERSHIP_ATTR ])

        users = []
        for group in ret:
            users += group[1][settings.LDAP_GROUP_MEMBERSHIP_ATTR]

        return users

    elif acc[0] == '$':
        # Special lookup
        parts_ = acc.split(':')
        parts = [parts_[0]] + [ ldap.filter.escape_filter_chars(s) for s in parts_[1:] ]
        ret = conn.search_s(
                settings.LDAP_USER_BASE,
                ldap.SCOPE_SUBTREE,
                settings.LDAP_EXTENDED_FILTERS[parts[0]].format(*parts[1:]),
                [ settings.LDAP_USERNAME_ATTR ])

        users = []
        for user in ret:
            users += user[1][settings.LDAP_USERNAME_ATTR]
        return users
    else:
        return [ acc ]

# Given a list of users, return their SSH keys.

def keys_for_users(conn, users):
    # Construct a search filter matching all users.
    filt =      \
        "(|" +  \
        "".join([
            settings.LDAP_UID_SEARCH_FILTER.format(
                uid = ldap.filter.escape_filter_chars(u)
            ) for u in set(users)
        ]) +    \
        ")"

    ret = conn.search_s(
                settings.LDAP_USER_BASE,
                ldap.SCOPE_SUBTREE,
                filt,
                [ settings.LDAP_KEY_ATTR ])

    keys = []

    for user in ret:
        if settings.LDAP_KEY_ATTR in user[1]:
            keys += user[1][settings.LDAP_KEY_ATTR]

    return keys

# Convert a list of accesses into a list of users, and return their
# SSH keys.

def access_get(conn, acc):
    users = []

    for access in acc:
        users += users_for_access(conn, access)

    return keys_for_users(conn, users)

# Look up SSH keys for a list of one or more access list entries.

@app.route("/lookup", methods=[ 'POST' ])
def lookup():
    if 'access' not in request.form:
        return text_response("Invalid request.\n", 400)

    access = request.form['access'].split(',')
    conn = get_ldap_connection(settings.LDAP_URI)

    keys = access_get(conn, access)

    return text_response("\n".join(keys) + "\n")

if __name__ == "__main__":
    app.run(debug = settings.DEBUG)
