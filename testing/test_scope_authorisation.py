#!/usr/bin/env python3
"""Verify the authorisation SQL in checkScopeWritable against a seeded DB.

The five tables the query joins are recreated in sqlite with the same
columns and relationships as justindb-create-tables.sql, then seeded with
one row of every shape that occurs in the real scope table. This tests the
JOIN and the decision rule, which is the part that has to be right. It does
not test the WSGI handler, which needs a live justIN.
"""

import sqlite3
import sys

SCHEMA = """
CREATE TABLE scopes (
  scope_id INTEGER PRIMARY KEY,
  scope_name TEXT NOT NULL,
  quota_id INTEGER NOT NULL DEFAULT 0,
  condor_group_id INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE named_quotas (
  quota_id INTEGER PRIMARY KEY,
  quota_name TEXT NOT NULL DEFAULT '',
  wlcg_group_id INTEGER NOT NULL DEFAULT 0,
  user_id INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE wlcg_groups (
  wlcg_group_id INTEGER PRIMARY KEY,
  wlcg_group_name TEXT NOT NULL
);
CREATE TABLE users (
  user_id INTEGER PRIMARY KEY,
  main_pn_id INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE principal_names (
  pn_id INTEGER PRIMARY KEY,
  principal_name TEXT NOT NULL,
  user_id INTEGER NOT NULL
);
"""

SEED = """
INSERT INTO wlcg_groups VALUES (1, '/dune'), (2, '/dune/production');
INSERT INTO principal_names VALUES (10, 'danielsc@fnal.gov', 100),
                                   (11, 'aahmad@fnal.gov',   101);
INSERT INTO users VALUES (100, 10), (101, 11);

-- group-owned quotas
INSERT INTO named_quotas VALUES (1, 'dune-general',    1, 0);
INSERT INTO named_quotas VALUES (2, 'dune-production', 2, 0);
-- user-owned quotas: no group, a user instead
INSERT INTO named_quotas VALUES (3, 'danielsc-quota',  0, 100);
INSERT INTO named_quotas VALUES (4, 'aahmad-quota',    0, 101);

INSERT INTO scopes VALUES (1, 'usertests',              1, 0);
INSERT INTO scopes VALUES (2, 'dc4',                    2, 0);
INSERT INTO scopes VALUES (3, 'user.danielsc.fnal.gov', 3, 0);
INSERT INTO scopes VALUES (4, 'user.aahmad.fnal.gov',   4, 0);
-- a scope with NO quota at all: usable by nobody
INSERT INTO scopes VALUES (5, 'orphan_scope',           0, 0);
"""

# Exactly the query from checkScopeWritable, with MySQL's double-quoted
# literal swapped for a parameter placeholder.
QUERY = ('SELECT scope_id,wlcg_group_name,quota_name,principal_name '
         'FROM scopes '
         'LEFT JOIN named_quotas ON named_quotas.quota_id=scopes.quota_id '
         'LEFT JOIN users ON users.user_id=named_quotas.user_id '
         'LEFT JOIN principal_names ON principal_names.pn_id=users.main_pn_id '
         'LEFT JOIN wlcg_groups '
         'ON wlcg_groups.wlcg_group_id=named_quotas.wlcg_group_id '
         'WHERE scope_name=?')


def checkScopeWritable(db, scopeName, userName, wlcgGroups):
    """The decision rule, transcribed from the patch."""
    row = db.execute(QUERY, (scopeName,)).fetchone()

    if row is None or not row['scope_id']:
        return ('400 Bad Request',
                'Failed to find scope %s in justIN database' % scopeName)

    if not row['quota_name']:
        return ('403 Forbidden',
                'Scope %s has no named quota defined and cannot yet be '
                'used via justIN' % scopeName)

    if row['wlcg_group_name']:
        if row['wlcg_group_name'] not in wlcgGroups:
            return ('403 Forbidden',
                    'You need to be in group %s to use scope %s'
                    % (row['wlcg_group_name'], scopeName))
    elif row['principal_name'] != userName:
        return ('403 Forbidden',
                'You need to be %s to use scope %s'
                % (row['principal_name'], scopeName))

    return None


db = sqlite3.connect(':memory:')
db.row_factory = sqlite3.Row
db.executescript(SCHEMA)
db.executescript(SEED)

ME = 'danielsc@fnal.gov'

cases = [
    # scope,                   user,  groups,                      allowed?
    ('usertests',              ME, ['/dune'],                       True),
    ('usertests',              ME, [],                              False),
    ('dc4',                    ME, ['/dune', '/dune/production'],   True),
    ('dc4',                    ME, ['/dune'],                       False),
    ('user.danielsc.fnal.gov', ME, [],                              True),
    ('user.danielsc.fnal.gov', ME, ['/dune/production'],            True),
    ('user.aahmad.fnal.gov',   ME, ['/dune/production'],            False),
    ('orphan_scope',           ME, ['/dune', '/dune/production'],   False),
    ('no_such_scope',          ME, ['/dune'],                       False),
    ('user.aahmad.fnal.gov',   'aahmad@fnal.gov', [],               True),
]

print('%-26s %-18s %-26s %-8s %s'
      % ('SCOPE', 'AS', 'GROUPS', 'ALLOWED', 'OK'))
print('-' * 100)

failures = 0
for scope, who, groups, wantAllowed in cases:
    refusal = checkScopeWritable(db, scope, who, groups)
    allowed = refusal is None
    ok = allowed == wantAllowed
    if not ok:
        failures += 1
    print('%-26s %-18s %-26s %-8s %s'
          % (scope, who, ','.join(groups) or '-', allowed,
             'yes' if ok else 'NO (wanted %s)' % wantAllowed))

print()
print('=== the refusal messages ===')
for scope, who, groups, _ in cases:
    r = checkScopeWritable(db, scope, who, groups)
    if r:
        print('%-26s %s  %s' % (scope, r[0], r[1]))

print()
print('=== the key property: production membership does NOT open a')
print('    personal scope, because that branch compares identity ===')
r = checkScopeWritable(db, 'user.aahmad.fnal.gov', ME,
                       ['/dune', '/dune/production'])
print('danielsc with /dune/production on aahmad scope -> %s' % (r[1] if r else 'ALLOWED'))
if r is None:
    failures += 1
    print('   ^^ FAIL: production membership must not grant this')

print()
print('FAILURES: %d' % failures)
sys.exit(1 if failures else 0)
