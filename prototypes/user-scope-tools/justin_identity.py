#!/usr/bin/env python3
#
# justin_identity.py - who justIN thinks you are.
#
# Part of a prototype exploring interactive file management in per-user
# Rucio scopes. See README.md in this directory.
#
# WHY THIS EXISTS, AND WHY IT IS NOT READ FROM THE TOKEN
#
# The obvious place to look for your identity is the WLCG token justIN
# caches for you. It is not there. A real DUNE token, inspected 2026-10-02,
# carries:
#
#   "sub":         "a77d88e4-42d6-4ced-b69c-6e7f77669b09"
#   "wlcg.groups": ["/dune", "/dune/production"]
#   "wlcg.ver":    "1.0"
#
# and no principal name in any form - no eppn, no preferred_username, no
# email. The subject is an opaque CILogon UUID. This is not an oversight:
# the WLCG token profile is deliberately minimal, carrying authorisation
# rather than identity.
#
# But justIN's own rule for user-owned scopes compares principal names:
#
#   elif principalName != user['user_name']:
#       403  'You need to be %s to use scope %s'
#
# So the token can never answer that question, and asking it to is a dead
# end. justIN knows the answer because it holds the session, and exposes
# it through "justin whoami". That is what we use.
#
# Standard library only, to match commands/justin.

import shutil
import subprocess


class IdentityError(Exception):
  """Raised when justIN cannot tell us who you are."""


def parseWhoami(text):
  """Parse the output of "justin whoami".

  The format is right-aligned "Label : value" lines:

        User name : danielsc@fnal.gov
    Session expires : 2026-10-09 19:52:52 UTC
           Groups : /dune  /dune/production

  Split on the FIRST colon only - the expiry value contains colons of its
  own, and splitting on all of them silently truncates it.
  """
  principal = None
  groups = []

  for line in text.splitlines():
    label, separator, value = line.partition(':')

    if not separator:
      continue

    label = label.strip().lower()
    value = value.strip()

    if label == 'user name':
      principal = value
    elif label == 'groups':
      groups = value.split()

  if not principal:
    raise IdentityError('no user name in "justin whoami" output')

  return principal, groups


def whoami(timeout=30):
  """Ask justIN who you are. Returns (principal, groups).

  Shelling out to the justin command rather than reimplementing its
  session handling: the session file format and the UI API are justIN's
  internals and would be wrong to depend on, whereas whoami is a
  documented user-facing subcommand.
  """
  if shutil.which('justin') is None:
    raise IdentityError(
      'the "justin" command is not on your PATH.\n'
      'Set it up with:\n'
      '  source /cvmfs/dune.opensciencegrid.org/products/dune/setup_dune.sh\n'
      '  setup justin')

  try:
    completed = subprocess.run(['justin', 'whoami'],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               timeout=timeout)
  except subprocess.TimeoutExpired:
    raise IdentityError('"justin whoami" timed out after %ds' % timeout)

  if completed.returncode != 0:
    raise IdentityError(
      '"justin whoami" failed: %s\n'
      'You may need to re-authorise:  justin time'
      % completed.stderr.decode('utf-8', 'replace').strip())

  return parseWhoami(completed.stdout.decode('utf-8', 'replace'))
