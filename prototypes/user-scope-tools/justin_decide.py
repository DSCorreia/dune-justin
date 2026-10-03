#!/usr/bin/env python3
#
# justin_decide.py - predict whether justIN would let you write to a scope.
#
# Part of a prototype exploring interactive file management in per-user
# Rucio scopes. See README.md in this directory.
#
# This PREDICTS. justIN decides. The prediction can only be as good as the
# data justIN publishes, and that data is thinner than justIN's real rule
# - which is the whole point of the four outcomes below.
#
# justIN's rule, from the scope check in services/justin-wsgi-ui:
#
#     if not quotaName:
#         403  'Scope %s has no named quota defined and cannot yet be
#               used via justIN'
#
#     if wlcgGroupName:
#         if wlcgGroupName not in user['wlcg_groups']:
#             403  'You need to be in group %s to use scope %s'
#     elif principalName != user['user_name']:
#         403  'You need to be %s to use scope %s'
#
# So a scope is owned either by a WLCG GROUP or by a PERSON, and which it
# is depends on the named quota behind it. The published table
# (/api/info/scopes.csv) carries only scope_name and wlcg_group_name. It
# does not carry quota_name or principal_name. An empty group field
# therefore means one of two things that we cannot tell apart:
#
#     - the scope belongs to a person, or
#     - the scope has no quota and nobody can use it
#
# Hence LIKELY and UNDETERMINED. Publishing principal_name alongside the
# group would collapse both into certainty; see README.md.
#
# Standard library only, to match commands/justin.

import collections


# Certain: justIN publishes everything needed to know the answer.
ALLOWED = 'ALLOWED'
DENIED = 'DENIED'

# Inferred: the scope name follows the user.<name>.fnal.gov convention
# and matches your identity. Not published anywhere; see expectedUserScope.
LIKELY = 'LIKELY'

# Unknown: the group field is empty and the name tells us nothing useful.
UNDETERMINED = 'UNDETERMINED'


Decision = collections.namedtuple('Decision', ['outcome', 'certain', 'reason'])


def expectedUserScope(principalName):
  """The personal scope name implied by a principal name.

  'danielsc@fnal.gov' -> 'user.danielsc.fnal.gov'

  Derived forwards, from identity to scope, never backwards. Going the
  other way is ambiguous: 'user.danielsc.fnal.gov' could split at any dot,
  so there is no way to know that the principal was danielsc@fnal.gov
  rather than danielsc.fnal@gov. Deriving forwards has exactly one answer.

  NOTE this convention appears nowhere in justIN's source - it is a Rucio
  naming practice we are reading off the data. Every result that depends
  on it is reported as LIKELY, never as certain.
  """
  if not principalName or '@' not in principalName:
    return None

  return 'user.' + principalName.replace('@', '.')


def decide(scopeName, scopes, principalName, wlcgGroups):
  """Predict justIN's answer for writing to scopeName.

  scopes       {scope_name: wlcg_group_name} from justin_scopes
  principalName your identity, e.g. 'danielsc@fnal.gov'
  wlcgGroups   your groups, e.g. ['/dune', '/dune/users']

  Pure: no network, no files, no clock. Everything it knows arrives as an
  argument, so every branch below can be tested directly.
  """
  if scopeName not in scopes:
    # justIN would fail to find it and return 400 before any
    # authorisation check happens. We can be certain about this one.
    return Decision(DENIED, True,
                    'not in justIN\'s scope table')

  publishedGroup = scopes[scopeName]

  if publishedGroup:
    # Group-owned scope. The published table tells us everything the
    # rule needs, so the answer is certain either way.
    if publishedGroup in wlcgGroups:
      return Decision(ALLOWED, True,
                      'scope requires %s and you are in it' % publishedGroup)

    return Decision(DENIED, True,
                    'scope requires %s and you are not in it' % publishedGroup)

  # No group published. Either a person owns this scope, or it has no
  # quota and is unusable. The naming convention is the only signal left.
  expected = expectedUserScope(principalName)

  if expected is not None and scopeName == expected:
    return Decision(LIKELY, False,
                    'name matches your identity by the user.<name> '
                    'convention, but justIN does not publish scope owners')

  return Decision(UNDETERMINED, False,
                  'no group published, and the name does not match your '
                  'identity - this is either someone else\'s personal '
                  'scope or a scope with no quota, and justIN does not '
                  'publish which')
