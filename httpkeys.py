#! /usr/bin/env python
# vim:sw=4 ts=4 et:
#
# Copyright (c) 2015, 2016 Torchbox Ltd.
# 2015-04-02 ft: created
# 2016-05-10 ft: modified for TS
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

def access_get(conn, acc):
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

        filt = "(|" + "".join([ settings.LDAP_UID_SEARCH_FILTER.format(uid = ldap.filter.escape_filter_chars(u)) for u in users ]) + ")"

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

    elif acc[0] == '$':
        # Special lookup
        parts_ = acc.split(':')
        parts = [parts_[0]] + [ ldap.filter.escape_filter_chars(s) for s in parts_[1:] ]
        ret = conn.search_s(
                settings.LDAP_USER_BASE,
                ldap.SCOPE_SUBTREE,
                settings.LDAP_EXTENDED_FILTERS[parts[0]].format(*parts[1:]),
                [ settings.LDAP_KEY_ATTR ])
        keys = []
        for user in ret:
            if settings.LDAP_KEY_ATTR in user[1]:
                keys += user[1][settings.LDAP_KEY_ATTR]
        return keys
    else:
        # User lookup
        ret = conn.search_s(
                    settings.LDAP_USER_BASE, 
                    ldap.SCOPE_SUBTREE,
                    settings.LDAP_UID_SEARCH_FILTER.format(uid = ldap.filter.escape_filter_chars(acc)),
                    [ settings.LDAP_KEY_ATTR ])
        keys = []
        for user in ret:
            if settings.LDAP_KEY_ATTR in user[1]:
                keys += user[1][settings.LDAP_KEY_ATTR]
        return keys

# Look up SSH keys for a list of one or more access list entries.

@app.route("/lookup", methods=[ 'POST' ])
def lookup():
    if 'access' not in request.form:
        return text_response("Invalid request.\n", 400)

    access = request.form['access'].split(',')
    conn = get_ldap_connection(settings.LDAP_URI)

    keys = []
    for acc in access:
        keys += access_get(conn, acc)

    return text_response("\n".join(keys) + "\n")

if __name__ == "__main__":
    app.run(debug = settings.DEBUG)
