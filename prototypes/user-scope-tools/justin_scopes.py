#!/usr/bin/env python3
#
# justin_scopes.py - fetch and cache justIN's published scope table.
#
# Part of a prototype exploring interactive file management in per-user
# Rucio scopes. See README.md in this directory.
#
# This module reports FACTS and makes no judgements. It answers "what does
# justIN publish about this scope?" and nothing else. Deciding whether you
# may write to a scope is justin_decide.py's job. Keeping the two apart
# matters, because the published data is thinner than the real rule and
# the seam between them is exactly where the prototype's limits live.
#
# Standard library only, to match commands/justin.

import os
import re
import csv
import ssl
import sys
import time
import urllib.request


# justIN's information API. Documented in docs/api.info.md as
# "a list of Rucio scopes and the DUNE WLCG Groups which have write
# access to them through justIN". Unauthenticated by design.
SCOPES_URL = 'https://justin-ui-fnal.dune.hep.ac.uk/api/info/scopes.csv'

# justIN's servers present IGTF (grid CA) certificates, which are not in
# the normal system trust store. These are installed by the
# ca-policy-igtf-classic package; see README.md.
GRID_CA_PATH = '/etc/grid-security/certificates'

# The table changes rarely - justin-info-collector refreshes it on its own
# cycle - so a long cache life is appropriate. Use --refresh to override.
CACHE_MAX_AGE_SECONDS = 6 * 3600


def stringIsScope(s):
  """Mirror of stringIsScope() in justIN's modules/__init__.py.

  Note this permits uppercase, even though the error message the UI
  service returns says 'a-z 0-9 - _ .'. We follow the code, not the
  message, so that we accept exactly what justIN accepts.
  """
  return re.search('[^A-Za-z0-9_.-]', s) is None


def cachePath():
  """Where the fetched table is kept between runs."""
  base = os.getenv('XDG_CACHE_HOME') or os.path.expanduser('~/.cache')
  return os.path.join(base, 'justin-user-scope-tools', 'scopes.csv')


def sslContext():
  """Trust both the system CAs and the grid CAs.

  Loading the system defaults as well as the grid path means this keeps
  working if justIN ever moves to a commercial certificate, and it does
  not weaken anything: adding trust anchors for this one connection is
  not the same as installing them system-wide.
  """
  context = ssl.create_default_context()

  if not os.path.isdir(GRID_CA_PATH):
    raise RuntimeError(
      'Grid CA directory %s not found.\n'
      'justIN uses IGTF certificates, which are not trusted by default.\n'
      'Install them with:  sudo apt install ca-policy-igtf-classic\n'
      '(see README.md in this directory)' % GRID_CA_PATH)

  context.load_verify_locations(capath=GRID_CA_PATH)
  return context


def fetchScopes(url=None, timeout=30):
  """Download the scope table. Returns the raw CSV text.

  url defaults to SCOPES_URL, but is resolved here rather than in the
  signature. A default argument is bound once when the function is
  defined, so writing url=SCOPES_URL would freeze the value and make the
  module constant impossible to override - including from a test.
  """
  if url is None:
    url = SCOPES_URL

  request = urllib.request.Request(
    url, headers={'User-Agent': 'justin-user-scope-tools prototype'})

  with urllib.request.urlopen(request,
                              timeout=timeout,
                              context=sslContext()) as response:
    return response.read().decode('utf-8')


def parseScopes(text):
  """Parse the CSV into {scope_name: wlcg_group_name}.

  The file has no header row and exactly two columns. An empty second
  field is preserved as an empty string and deliberately NOT interpreted
  here - see the module docstring. justIN writes the file with plain
  '%s,%s' formatting and validates scope names to a character set with no
  commas or quotes, so there is nothing to unquote, but the csv module
  costs nothing and is harder to get wrong.
  """
  scopes = {}

  for row in csv.reader(text.splitlines()):
    if not row:
      continue

    if len(row) != 2:
      raise ValueError('expected 2 columns per row, got %d: %r' % (len(row), row))

    scopes[row[0]] = row[1]

  if not scopes:
    raise ValueError('scope table is empty')

  return scopes


def writeCache(text):
  """Save the table, writing to a temporary file then renaming.

  The rename is atomic, so an interrupted write can never leave a
  truncated cache behind that would later parse as a short but valid
  table - which would silently produce wrong answers.
  """
  path = cachePath()
  os.makedirs(os.path.dirname(path), exist_ok=True)

  temporary = path + '.tmp'
  with open(temporary, 'w') as f:
    f.write(text)

  os.replace(temporary, path)


def readCache(maxAge=None):
  """Return cached CSV text if it exists and is fresh enough, else None.

  maxAge resolved here, not in the signature, for the same reason as in
  fetchScopes().
  """
  if maxAge is None:
    maxAge = CACHE_MAX_AGE_SECONDS

  path = cachePath()

  try:
    age = time.time() - os.path.getmtime(path)
  except OSError:
    return None

  if age > maxAge:
    return None

  try:
    with open(path, 'r') as f:
      return f.read()
  except IOError:
    return None


def loadScopes(refresh=False, maxAge=None):
  """The normal entry point: cached table if fresh, otherwise fetched.

  Returns (scopes, source) where source is 'cache' or 'network', so
  callers can tell the user which they got. If the network fetch fails
  but a stale cache exists, the stale cache is used rather than failing
  outright - being slightly out of date is far better than not working on
  a train, and the scope table moves slowly.
  """
  if not refresh:
    cached = readCache(maxAge)
    if cached is not None:
      return parseScopes(cached), 'cache'

  try:
    text = fetchScopes()
  except Exception as e:
    stale = readCache(maxAge=float('inf'))
    if stale is not None:
      print('Warning: fetch failed (%s); using stale cache' % str(e),
            file=sys.stderr)
      return parseScopes(stale), 'stale cache'
    raise

  writeCache(text)
  return parseScopes(text), 'network'


def main():
  refresh = '--refresh' in sys.argv
  arguments = [a for a in sys.argv[1:] if not a.startswith('-')]

  try:
    scopes, source = loadScopes(refresh=refresh)
  except Exception as e:
    print('Could not load scope table: %s' % str(e), file=sys.stderr)
    return 1

  if not arguments:
    withGroup = sum(1 for g in scopes.values() if g)
    print('%d scopes (from %s)' % (len(scopes), source))
    print('  %d with a published WLCG group' % withGroup)
    print('  %d with none published' % (len(scopes) - withGroup))
    print()
    print('Pass a scope name to look one up.')
    return 0

  status = 0

  for name in arguments:
    if not stringIsScope(name):
      print('%s: not a valid scope name' % name, file=sys.stderr)
      status = 1
      continue

    if name not in scopes:
      print('%s: not in justIN\'s scope table' % name)
      status = 1
      continue

    group = scopes[name]
    print('%s: %s' % (name, group if group else '<no group published>'))

  return status


if __name__ == '__main__':
  sys.exit(main())
