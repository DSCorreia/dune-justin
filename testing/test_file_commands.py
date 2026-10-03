#!/usr/bin/env python3
"""Exercise all four file commands without a justIN instance.

services/justin-wsgi-ui is imported with justin, rucio and M2Crypto
replaced by stubs. The justin stub keeps the REAL validator functions
from modules/__init__.py, because validation is part of what is tested;
only select() is faked, to answer the scope query.

Run from anywhere: python3 testing/test_file_commands.py

What this proves: every branch of rm-file, undo-rm-file, list-files and
mv-file returns the intended status; Rucio is reached only on authorised
paths; refusals never commit; and mv-file attaches before it detaches,
so a failure cannot leave a file in no dataset at all.

What it does not prove: that any of this works against a live justIN.
That needs database, CILogon, MetaCat and Rucio credentials. See README.
"""

import os
import re
import sys
import types
import contextlib
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
UI = os.path.join(HERE, '..', 'services', 'justin-wsgi-ui')


# ---------------------------------------------------------------- stubs

rucioCalls = []
failOn = set()          # method names that should raise
connectFails = False
scopeContents = {}      # scope -> list of file names, for list_dids
fileMetadata = {}       # what get_metadata returns


class FakeConnection:
  def __init__(self):
    self.actions = []

  def commit(self):
    self.actions.append('commit')

  def rollback(self):
    self.actions.append('rollback')


class FakeDIDClient:
  def __init__(self):
    if connectFails:
      raise RuntimeError('simulated Rucio connection failure')

  def _record(self, method, **kwargs):
    if method in failOn:
      raise RuntimeError('simulated %s failure' % method)
    rucioCalls.append(dict(method=method, **kwargs))

  def set_metadata(self, scope=None, name=None, key=None, value=None):
    self._record('set_metadata', scope=scope, name=name, key=key, value=value)

  def attach_dids(self, scope=None, name=None, dids=None, rse=None):
    self._record('attach_dids', scope=scope, name=name, dids=dids)

  def detach_dids(self, scope=None, name=None, dids=None):
    self._record('detach_dids', scope=scope, name=name, dids=dids)

  def get_metadata(self, scope=None, name=None, plugin='DID_COLUMN'):
    if 'get_metadata' in failOn:
      raise RuntimeError('simulated get_metadata failure')
    rucioCalls.append({'method': 'get_metadata', 'scope': scope,
                       'name': name})
    return dict(fileMetadata)

  def list_dids(self, scope=None, filters=None, did_type=None):
    if 'list_dids' in failOn:
      raise RuntimeError('simulated list_dids failure')
    rucioCalls.append({'method': 'list_dids', 'scope': scope,
                       'did_type': did_type})
    return iter(scopeContents.get(scope, []))


SCOPES = {
  'usertests':              {'scope_id': 1, 'quota_name': 'dune-general',
                             'wlcg_group_name': '/dune',
                             'principal_name': None},
  'dc4':                    {'scope_id': 2, 'quota_name': 'dune-production',
                             'wlcg_group_name': '/dune/production',
                             'principal_name': None},
  'user.danielsc.fnal.gov': {'scope_id': 3, 'quota_name': 'danielsc-quota',
                             'wlcg_group_name': None,
                             'principal_name': 'danielsc@fnal.gov'},
  'user.aahmad.fnal.gov':   {'scope_id': 4, 'quota_name': 'aahmad-quota',
                             'wlcg_group_name': None,
                             'principal_name': 'aahmad@fnal.gov'},
  'user.orphan.fnal.gov':   {'scope_id': 5, 'quota_name': None,
                             'wlcg_group_name': None,
                             'principal_name': None},
}


def fakeSelect(query, justOne=False, tries=10, showQuery=False):
  match = re.search(r'scope_name="([^"]*)"', query)
  if not match:
    raise RuntimeError('unexpected query: %s' % query[:80])
  row = SCOPES.get(match.group(1))
  if row is None:
    raise RuntimeError('no such scope')
  return row


def installStubs():
  rucioMod = types.ModuleType('rucio')
  clientMod = types.ModuleType('rucio.client')
  didMod = types.ModuleType('rucio.client.didclient')
  downloadMod = types.ModuleType('rucio.client.downloadclient')

  didMod.DIDClient = FakeDIDClient
  clientMod.didclient = didMod
  clientMod.downloadclient = downloadMod
  clientMod.Client = object
  rucioMod.client = clientMod

  for name, mod in [('rucio', rucioMod),
                    ('rucio.client', clientMod),
                    ('rucio.client.didclient', didMod),
                    ('rucio.client.downloadclient', downloadMod)]:
    sys.modules[name] = mod

  m2 = types.ModuleType('M2Crypto')
  for name in ['RSA', 'BIO', 'X509', 'ASN1', 'EVP']:
    setattr(m2, name, object)
  sys.modules['M2Crypto'] = m2

  justinMod = types.ModuleType('justin')
  justinMod.stringIsScope = lambda s: re.search('[^A-Za-z0-9_.-]', s) is None
  justinMod.stringIsFile = lambda s: re.search('[^A-Za-z0-9_.-]', s) is None
  justinMod.stringIsDID = lambda s: re.search('[^A-Za-z0-9_.:-]', s) is None
  justinMod.justinAdmins = []
  justinMod.select = fakeSelect
  justinMod.conn = FakeConnection()
  sys.modules['justin'] = justinMod


installStubs()

spec = importlib.util.spec_from_loader(
  'justin_wsgi_ui',
  importlib.machinery.SourceFileLoader('justin_wsgi_ui', UI))
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)

ME = {'user_id': 100,
      'user_name': 'danielsc@fnal.gov',
      'wlcg_groups': ['/dune', '/dune/production']}

MINE = 'user.danielsc.fnal.gov'


def call(handler, jsonDict, user=ME):
  """Invoke a handler and return (status, body). Swallows its stderr."""
  captured = {}
  ui.justin.conn.actions.clear()
  rucioCalls.clear()

  def startResponse(status, headers):
    captured['status'] = status

  with open(os.devnull, 'w') as quiet:
    with contextlib.redirect_stderr(quiet):
      body = handler(startResponse, jsonDict, user)

  text = b''.join(body).decode('utf-8', 'replace') if body else ''
  return captured.get('status', '<none>').split()[0], text.strip()


failures = 0


def check(label, got, want):
  global failures
  ok = got == want
  if not ok:
    failures += 1
  print('%-46s %-5s %-5s %s' % (label, want, got, 'yes' if ok else 'NO'))


# ------------------------------------------------------------ rm-file

print('=== rm-file ===')
print('%-46s %-5s %-5s %s' % ('CASE', 'WANT', 'GOT', 'OK'))
for label, did, want in [
    ('missing did',               None,                          '400'),
    ('no colon',                  'justafilename',               '400'),
    ('illegal chars',             MINE + ':a b.root',            '400'),
    ('unknown scope',             'no.such:x.root',              '400'),
    ('group scope, not a member', 'usertests:x.root',            '403'),
    ('group scope, IS a member',  'dc4:x.root',                  '403'),
    ('someone elses scope',       'user.aahmad.fnal.gov:x.root', '403'),
    ('no quota',                  'user.orphan.fnal.gov:x.root', '403'),
    ('own scope',                 MINE + ':t.root',              '200')]:
  jd = {} if did is None else {'file_did': did}
  check(label, call(ui.rmFileCmd, jd)[0], want)

# ------------------------------------------------------- undo-rm-file

print()
print('=== undo-rm-file ===')
for label, did, want in [
    ('missing did',         None,                          '400'),
    ('someone elses scope', 'user.aahmad.fnal.gov:x.root', '403'),
    ('group scope',         'dc4:x.root',                  '403'),
    ('own scope',           MINE + ':t.root',              '200')]:
  jd = {} if did is None else {'file_did': did}
  check(label, call(ui.undoRmFileCmd, jd)[0], want)

status, _ = call(ui.undoRmFileCmd, {'file_did': MINE + ':t.root'})
print('   clears lifetime: %s' % rucioCalls)
if rucioCalls != [{'method': 'set_metadata', 'scope': MINE,
                   'name': 't.root', 'key': 'lifetime', 'value': None}]:
  failures += 1
  print('   ^^ FAIL: undo must set lifetime to None')

# --------------------------------------------------------- list-files

print()
print('=== list-files ===')
scopeContents[MINE] = ['a.root', 'b.root', 'c.root']
for label, scope, want in [
    ('missing scope',       None,                     '400'),
    ('group scope',         'dc4',                    '403'),
    ('someone elses scope', 'user.aahmad.fnal.gov',   '403'),
    ('own scope',           MINE,                     '200')]:
  jd = {} if scope is None else {'scope': scope}
  check(label, call(ui.listFilesCmd, jd)[0], want)

status, body = call(ui.listFilesCmd, {'scope': MINE})
print('   body: %s' % body.replace('\n', ' | '))
if body.count(MINE + ':') != 3:
  failures += 1
  print('   ^^ FAIL: expected three files listed')

scopeContents[MINE] = []
status, body = call(ui.listFilesCmd, {'scope': MINE})
print('   empty scope: %s' % body)
if 'No files' not in body:
  failures += 1

scopeContents[MINE] = ['f%d.root' % i for i in range(ui.listFilesMaximum + 50)]
status, body = call(ui.listFilesCmd, {'scope': MINE})
print('   cap honoured: %d lines, truncation notice=%s'
      % (len(body.splitlines()), 'truncated' in body))
if 'truncated' not in body:
  failures += 1
  print('   ^^ FAIL: must truncate at listFilesMaximum')
scopeContents[MINE] = ['a.root']

# ---------------------------------------------------------- show-file

print()
print('=== show-file ===')
fileMetadata.clear()
fileMetadata.update({'bytes': 12345, 'adler32': 'deadbeef',
                     'created_at': '2026-10-01 12:00:00',
                     'expired_at': None, 'account': 'dunepro',
                     'nonsense_key': 'should not be shown'})

for label, did, want in [
    ('missing did',         None,                          '400'),
    ('group scope',         'dc4:x.root',                  '403'),
    ('someone elses scope', 'user.aahmad.fnal.gov:x.root', '403'),
    ('own scope',           MINE + ':t.root',              '200')]:
  jd = {} if did is None else {'file_did': did}
  check(label, call(ui.showFileCmd, jd)[0], want)

status, body = call(ui.showFileCmd, {'file_did': MINE + ':t.root'})
print('   body: %s' % body.replace('\n', ' | '))
if 'nonsense_key' in body:
  failures += 1
  print('   ^^ FAIL: must show only the curated keys')
if 'expired_at' in body:
  failures += 1
  print('   ^^ FAIL: a None value must be omitted, not printed')
if '12345' not in body:
  failures += 1
  print('   ^^ FAIL: expected the size')

print()
print('   --- and when a removal IS pending ---')
fileMetadata['expired_at'] = '2026-10-04 18:00:00'
status, body = call(ui.showFileCmd, {'file_did': MINE + ':t.root'})
print('   %s' % body.replace('\n', ' | '))
if 'scheduled for removal' not in body or 'undo-rm-file' not in body:
  failures += 1
  print('   ^^ FAIL: must say it is pending and how to cancel')

print()
print('   --- a missing key must not crash it ---')
fileMetadata.clear()
fileMetadata.update({'bytes': 1})
status, body = call(ui.showFileCmd, {'file_did': MINE + ':t.root'})
check('   sparse metadata', status, '200')

# ------------------------------------------------------------ mv-file

print()
print('=== mv-file ===')
DS1 = MINE + ':dataset_one'
DS2 = MINE + ':dataset_two'

for label, jd, want in [
    ('missing file',        {'from_dataset': DS1, 'to_dataset': DS2}, '400'),
    ('missing datasets',    {'file_did': MINE + ':a.root'},           '400'),
    ('same dataset twice',  {'file_did': MINE + ':a.root',
                             'from_dataset': DS1, 'to_dataset': DS1}, '400'),
    ('malformed dataset',   {'file_did': MINE + ':a.root',
                             'from_dataset': 'nocolon',
                             'to_dataset': DS2},                      '400'),
    ('target is group',     {'file_did': MINE + ':a.root',
                             'from_dataset': DS1,
                             'to_dataset': 'dc4:ds'},                 '403'),
    ('file is someone elses', {'file_did': 'user.aahmad.fnal.gov:a.root',
                             'from_dataset': DS1, 'to_dataset': DS2}, '403'),
    ('all mine',            {'file_did': MINE + ':a.root',
                             'from_dataset': DS1, 'to_dataset': DS2}, '200')]:
  check(label, call(ui.mvFileCmd, jd)[0], want)

# ------------------------------------- the ordering property for mv

print()
print('=== mv-file attaches BEFORE it detaches ===')
good = {'file_did': MINE + ':a.root', 'from_dataset': DS1, 'to_dataset': DS2}
call(ui.mvFileCmd, good)
order = [c['method'] for c in rucioCalls]
print('   call order: %s' % order)
if order != ['attach_dids', 'detach_dids']:
  failures += 1
  print('   ^^ FAIL: attach must come first')

failOn.add('attach_dids')
status, body = call(ui.mvFileCmd, good)
print('   attach fails -> %s, detach attempted: %s'
      % (status, any(c['method'] == 'detach_dids' for c in rucioCalls)))
if status != '500' or any(c['method'] == 'detach_dids' for c in rucioCalls):
  failures += 1
  print('   ^^ FAIL: a failed attach must stop before detaching')
print('   message: %s' % body[:70])
failOn.discard('attach_dids')

failOn.add('detach_dids')
status, body = call(ui.mvFileCmd, good)
print('   detach fails -> %s' % status)
print('   message: %s' % body[:90])
if status != '500' or 'both' not in body:
  failures += 1
  print('   ^^ FAIL: must say the file is now in both datasets')
failOn.discard('detach_dids')

# ------------------------------- Rucio reached only where authorised

print()
print('=== refusals never reach Rucio, and never commit ===')

refusals = [
  (ui.rmFileCmd,     {'file_did': 'dc4:x.root'}),
  (ui.rmFileCmd,     {'file_did': 'user.aahmad.fnal.gov:x.root'}),
  (ui.undoRmFileCmd, {'file_did': 'dc4:x.root'}),
  (ui.listFilesCmd,  {'scope': 'dc4'}),
  (ui.showFileCmd,   {'file_did': 'user.aahmad.fnal.gov:x.root'}),
  (ui.mvFileCmd,     {'file_did': MINE + ':a.root',
                      'from_dataset': DS1, 'to_dataset': 'dc4:ds'}),
]

for handler, jd in refusals:
  call(handler, jd)
  if rucioCalls:
    failures += 1
    print('   FAIL: %s reached Rucio on a refusal' % handler.__name__)
  if 'commit' in ui.justin.conn.actions:
    failures += 1
    print('   FAIL: %s committed on a refusal' % handler.__name__)
print('   %d refusal paths checked: no Rucio calls, no commits'
      % len(refusals))

# ------------------------------------------ connection failure is 500

print()
print('=== a Rucio outage is a 500, not a traceback ===')
connectFails = True
for name, handler, jd in [
    ('rm-file',      ui.rmFileCmd,     {'file_did': MINE + ':t.root'}),
    ('undo-rm-file', ui.undoRmFileCmd, {'file_did': MINE + ':t.root'}),
    ('list-files',   ui.listFilesCmd,  {'scope': MINE}),
    ('show-file',    ui.showFileCmd,   {'file_did': MINE + ':t.root'}),
    ('mv-file',      ui.mvFileCmd,     good)]:
  status, _ = call(handler, jd)
  check('   ' + name, status, '500')
connectFails = False

print()
print('FAILURES: %d' % failures)
sys.exit(1 if failures else 0)
