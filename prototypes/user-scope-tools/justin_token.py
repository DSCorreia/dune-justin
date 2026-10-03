#!/usr/bin/env python3
#
# justin_token.py - locate and read the WLCG token that justIN caches for
#                   the current user.
#
# Part of a prototype exploring interactive file management in per-user
# Rucio scopes. See README.md in this directory.
#
# IMPORTANT - this module DECODES a token, it does not VERIFY one.
#
#   A WLCG token is a JWT: three base64url segments separated by dots, the
#   third being a signature from the issuer (CILogon). Checking that
#   signature requires the issuer's public keys and is what a *server*
#   does before trusting a caller.
#
#   This tool runs on your own machine and reads your own token in order to
#   tell you what it says. It makes no security decision and must never be
#   relied on for one. Real enforcement happens at justIN and at Rucio.
#   Everything here is a local prediction of what those services will say.
#
# Standard library only, to match commands/justin.

import os
import sys
import json
import time
import base64


def bearerTokenPath():
  """Where justIN keeps the current user's WLCG token.

  This mirrors the rule in the get-token section of commands/justin
  exactly. Do not change it independently: if justIN's rule moves, this
  must follow it, or the two tools will disagree about which file is
  current.
  """
  path = os.getenv('BEARER_TOKEN_FILE')
  if path:
    return path

  userUID = int(os.getuid())

  if os.path.isdir('/run/user/%d' % userUID):
    return '/run/user/%d/bt_u%d' % (userUID, userUID)

  return '/tmp/bt_u%d' % userUID


def readToken(path=None):
  """Return the raw token string, or None if there is no readable token.

  Returning None rather than raising keeps the "you have not logged in
  yet" case ordinary, because it is: it is what every user sees first.
  """
  if path is None:
    path = bearerTokenPath()

  try:
    with open(path, 'r') as f:
      token = f.read().strip()
  except IOError:
    return None

  return token if token else None


def decodeSegment(segment):
  """base64url-decode one JWT segment.

  JWT strips the '=' padding that base64 normally requires, so we add it
  back. The length must be a multiple of 4; -len(segment) % 4 gives how
  many characters are missing.
  """
  padding = '=' * (-len(segment) % 4)
  return base64.urlsafe_b64decode(segment + padding)


def tokenClaims(token):
  """Return the token's payload as a dict.

  Raises ValueError if this does not look like a JWT at all, so that a
  truncated or corrupted token file fails loudly instead of silently
  looking like an empty set of claims.
  """
  segments = token.split('.')

  if len(segments) != 3:
    raise ValueError('not a JWT: expected 3 dot-separated segments, got %d'
                     % len(segments))

  try:
    return json.loads(decodeSegment(segments[1]))
  except Exception as e:
    raise ValueError('could not decode token payload: %s' % str(e))


def tokenGroups(claims):
  """The DUNE WLCG groups this token carries.

  The claim name is the literal string 'wlcg.groups' - a dot inside the
  key, not a nested object. Reading it as claims['wlcg']['groups'] is the
  usual mistake and returns nothing.
  """
  return claims.get('wlcg.groups', [])


def secondsRemaining(claims):
  """Seconds until this token expires. Negative if it already has.

  Returns None if the token carries no 'exp' claim, which would be
  unusual and is worth surfacing rather than treating as valid forever.
  """
  expires = claims.get('exp')

  if expires is None:
    return None

  return int(expires) - int(time.time())


def describeRemaining(seconds):
  """Human-readable form of secondsRemaining(), for display only."""
  if seconds is None:
    return 'no expiry claim'

  if seconds <= 0:
    return 'EXPIRED %dm ago' % (-seconds // 60)

  return '%dh%02dm left' % (seconds // 3600, (seconds % 3600) // 60)


def main():
  path = bearerTokenPath()
  token = readToken(path)

  if token is None:
    print('No justIN token found at %s' % path, file=sys.stderr)
    print('Run "justin get-token" to fetch one.', file=sys.stderr)
    return 1

  try:
    claims = tokenClaims(token)
  except ValueError as e:
    print('Token at %s is unreadable: %s' % (path, str(e)), file=sys.stderr)
    return 1

  groups = tokenGroups(claims)

  print('token file   %s' % path)
  print('issuer       %s' % claims.get('iss', '<none>'))
  print('subject      %s' % claims.get('sub', '<none>'))
  print('expires      %s' % describeRemaining(secondsRemaining(claims)))
  print('groups       %s' % (', '.join(groups) if groups else '<none>'))

  # Until this has been run against a real justIN token we do not know
  # which claim carries the human username, so show everything on request
  # rather than guessing at one.
  if '--all-claims' in sys.argv:
    print()
    print(json.dumps(claims, indent=2, sort_keys=True))

  return 0


if __name__ == '__main__':
  sys.exit(main())
