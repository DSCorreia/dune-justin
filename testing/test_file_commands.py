#!/usr/bin/env python3
"""Exercise the did-* and rule-update commands without a justIN instance.

services/justin-wsgi-ui is imported with justin, rucio and M2Crypto
replaced by stubs. The justin stub keeps the REAL validator functions from
modules/__init__.py, because validation is part of what is tested; only
select() is faked, to answer the scope query.

Run from anywhere: python3 testing/test_file_commands.py

What this proves: every branch of all seven handlers returns the intended
status; a collection DID is accepted wherever a file DID is, which is the
point of the did-* naming; Rucio is reached only on authorised paths;
refusals never commit; and a Rucio outage is a 500 rather than a traceback.

What it does not prove: that any of this works against a live justIN. That
needs database, CILogon, MetaCat and Rucio credentials.
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
failOn = set()
connectFails = False
scopeContents = {}
didMetadata = {}
ruleRecord = {}


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
    rucioCalls.append({'method': 'get_metadata', 'scope': scope, 'name': name})
    return dict(didMetadata)

  def list_dids(self, scope=None, filters=None, did_type=None):
    if 'list_dids' in failOn:
      raise RuntimeError('simulated list_dids failure')
    rucioCalls.append({'method': 'list_dids', 'scope': scope,
                       'did_type': did_type})
    return iter(scopeContents.get(scope, []))


class FakeRuleClient:
  def __init__(self):
    if connectFails:
      raise RuntimeError('simulated Rucio connection failure')

  def get_replication_rule(self, rule_id):
    if 'get_replication_rule' in failOn:
      raise RuntimeError('simulated get_replication_rule failure')
    rucioCalls.append({'method': 'get_replication_rule', 'rule_id': rule_id})
    return dict(ruleRecord)

  def update_replication_rule(self, rule_id, options):
    if 'update_replication_rule' in failOn:
      raise RuntimeError('simulated update_replication_rule failure')
    rucioCalls.append({'method': 'update_replication_rule',
                       'rule_id': rule_id, 'options': options})
    return True


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
  ruleMod = types.ModuleType('rucio.client.ruleclient')
  downloadMod = types.ModuleType('rucio.client.downloadclient')

  didMod.DIDClient = FakeDIDClient
  ruleMod.RuleClient = FakeRuleClient
  clientMod.didclient = didMod
  clientMod.ruleclient = ruleMod
  clientMod.downloadclient = downloadMod
  clientMod.Client = object
  rucioMod.client = clientMod

  for name, mod in [('rucio', rucioMod),
                    ('rucio.client', clientMod),
                    ('rucio.client.didclient', didMod),
                    ('rucio.client.ruleclient', ruleMod),
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
THEIRS = 'user.aahmad.fnal.gov'
RULEID = 'a1b2c3d4e5f6071829304a5b6c7d8e9f'
DS = MINE + ':dataset_one'


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
  print('%-50s %-5s %-5s %s' % (label, want, got, 'yes' if ok else 'NO'))


print('%-50s %-5s %-5s %s' % ('CASE', 'WANT', 'GOT', 'OK'))

# ------------------------------------------------------------ did-list

print()
print('=== did-list ===')
scopeContents[MINE] = ['a.root', 'b.root', 'c.root']
for label, jd, want in [
    ('missing scope',        {},                                     '400'),
    ('bad did-type',         {'scope': MINE, 'did_type': 'banana'},  '400'),
    ('group scope',          {'scope': 'dc4'},                       '403'),
    ('someone elses scope',  {'scope': THEIRS},                      '403'),
    ('own scope',            {'scope': MINE},                        '200'),
    ('own scope, datasets',  {'scope': MINE, 'did_type': 'dataset'}, '200')]:
  check(label, call(ui.didListCmd, jd)[0], want)

call(ui.didListCmd, {'scope': MINE, 'did_type': 'dataset'})
print('   did_type reaches Rucio as: %s' % rucioCalls[0]['did_type'])
if rucioCalls[0]['did_type'] != 'dataset':
  failures += 1
  print('   ^^ FAIL: did_type not passed through')

status, body = call(ui.didListCmd, {'scope': MINE})
if body.count(MINE + ':') != 3:
  failures += 1
  print('   ^^ FAIL: expected three DIDs listed')

scopeContents[MINE] = ['f%d.root' % i for i in range(ui.didListMaximum + 20)]
status, body = call(ui.didListCmd, {'scope': MINE})
print('   cap honoured: truncation notice = %s' % ('truncated' in body))
if 'truncated' not in body:
  failures += 1
scopeContents[MINE] = ['a.root']

# ------------------------------------------------------------ did-show

print()
print('=== did-show ===')
didMetadata.clear()
didMetadata.update({'did_type': 'FILE', 'bytes': 12345, 'adler32': 'deadbeef',
                    'expired_at': None, 'account': 'dunepro',
                    'nonsense_key': 'should not be shown'})
for label, did, want in [
    ('missing did',          None,                 '400'),
    ('group scope',          'dc4:x.root',         '403'),
    ('someone elses scope',  THEIRS + ':x.root',   '403'),
    ('own file',             MINE + ':t.root',     '200'),
    ('own DATASET',          MINE + ':my_dataset', '200')]:
  jd = {} if did is None else {'did': did}
  check(label, call(ui.didShowCmd, jd)[0], want)

status, body = call(ui.didShowCmd, {'did': MINE + ':t.root'})
if 'nonsense_key' in body or 'expired_at' in body:
  failures += 1
  print('   ^^ FAIL: only curated, non-None keys should show')

didMetadata['expired_at'] = '2026-10-28 18:00:00'
status, body = call(ui.didShowCmd, {'did': MINE + ':t.root'})
print('   pending removal surfaced: %s' % ('did-remove-undo' in body))
if 'did-remove-undo' not in body:
  failures += 1

# ---------------------------------------------------------- did-remove

print()
print('=== did-remove ===')
for label, did, want in [
    ('missing did',           None,                     '400'),
    ('no colon',              'justaname',              '400'),
    ('illegal characters',    MINE + ':a b.root',       '400'),
    ('unknown scope',         'no.such:x.root',         '400'),
    ('group scope',           'dc4:x.root',             '403'),
    ('someone elses scope',   THEIRS + ':x.root',       '403'),
    ('scope with no quota',   'user.orphan.fnal.gov:x', '403'),
    ('own file',              MINE + ':t.root',         '200'),
    ('own DATASET',           MINE + ':my_dataset',     '200')]:
  jd = {} if did is None else {'did': did}
  check(label, call(ui.didRemoveCmd, jd)[0], want)

print()
print('   --- a collection DID is accepted: the point of the rename ---')
call(ui.didRemoveCmd, {'did': MINE + ':my_dataset'})
print('   %s' % rucioCalls)
expected = {'method': 'set_metadata', 'scope': MINE, 'name': 'my_dataset',
            'key': 'lifetime', 'value': 86400}
if rucioCalls != [expected]:
  failures += 1
  print('   ^^ FAIL: expected %s' % expected)

# ----------------------------------------------------- did-remove-undo

print()
print('=== did-remove-undo ===')
for label, did, want in [
    ('missing did',          None,                 '400'),
    ('someone elses scope',  THEIRS + ':x.root',   '403'),
    ('own file',             MINE + ':t.root',     '200'),
    ('own DATASET',          MINE + ':my_dataset', '200')]:
  jd = {} if did is None else {'did': did}
  check(label, call(ui.didRemoveUndoCmd, jd)[0], want)

call(ui.didRemoveUndoCmd, {'did': MINE + ':t.root'})
if rucioCalls != [{'method': 'set_metadata', 'scope': MINE, 'name': 't.root',
                   'key': 'lifetime', 'value': None}]:
  failures += 1
  print('   ^^ FAIL: undo must clear the lifetime to None')

# ----------------------------------------------- did-content add/remove

print()
print('=== did-content-add ===')
for label, jd, want in [
    ('missing both',      {},                                          '400'),
    ('missing target',    {'did': MINE + ':a.root'},                   '400'),
    ('attach to itself',  {'did': DS, 'to_dataset': DS},               '400'),
    ('target is group',   {'did': MINE + ':a.root',
                           'to_dataset': 'dc4:ds'},                    '403'),
    ('did is theirs',     {'did': THEIRS + ':a.root',
                           'to_dataset': DS},                          '403'),
    ('both mine',         {'did': MINE + ':a.root', 'to_dataset': DS}, '200')]:
  check(label, call(ui.didContentAddCmd, jd)[0], want)

call(ui.didContentAddCmd, {'did': MINE + ':a.root', 'to_dataset': DS})
print('   call: %s' % rucioCalls)
if not rucioCalls or rucioCalls[0]['method'] != 'attach_dids':
  failures += 1
  print('   ^^ FAIL: expected attach_dids')

print()
print('=== did-content-remove ===')
for label, jd, want in [
    ('missing both',    {},                                              '400'),
    ('source is group', {'did': MINE + ':a.root',
                         'from_dataset': 'dc4:ds'},                      '403'),
    ('both mine',       {'did': MINE + ':a.root', 'from_dataset': DS},   '200')]:
  check(label, call(ui.didContentRemoveCmd, jd)[0], want)

call(ui.didContentRemoveCmd, {'did': MINE + ':a.root', 'from_dataset': DS})
if not rucioCalls or rucioCalls[0]['method'] != 'detach_dids':
  failures += 1
  print('   ^^ FAIL: expected detach_dids')

# --------------------------------------------------------- rule-update

print()
print('=== rule-update ===')
ruleRecord.clear()
ruleRecord.update({'id': RULEID, 'scope': MINE, 'name': 'my_dataset',
                   'rse_expression': 'DUNE_US_FNAL_DISK_STAGE'})

for label, jd, want in [
    ('missing rule id',   {'lifetime_days': 30},                      '400'),
    ('rule id too short', {'rule_id': 'abc', 'lifetime_days': 30},    '400'),
    ('rule id not hex',   {'rule_id': 'z' * 32, 'lifetime_days': 30}, '400'),
    ('missing lifetime',  {'rule_id': RULEID},                        '400'),
    ('negative lifetime', {'rule_id': RULEID, 'lifetime_days': -1},   '400'),
    ('extend to 30 days', {'rule_id': RULEID, 'lifetime_days': 30},   '200'),
    ('expire now',        {'rule_id': RULEID, 'lifetime_days': 0},    '200')]:
  check(label, call(ui.ruleUpdateCmd, jd)[0], want)

print()
print('   --- a rule on a scope that is not yours is refused ---')
ruleRecord['scope'] = THEIRS
check('   rule on their personal scope', call(ui.ruleUpdateCmd,
      {'rule_id': RULEID, 'lifetime_days': 30})[0], '403')
ruleRecord['scope'] = 'dc4'
check('   rule on a group scope', call(ui.ruleUpdateCmd,
      {'rule_id': RULEID, 'lifetime_days': 30})[0], '403')
ruleRecord['scope'] = MINE

print()
print('   --- the lifetime reaches Rucio in SECONDS ---')
call(ui.ruleUpdateCmd, {'rule_id': RULEID, 'lifetime_days': 30})
update = [c for c in rucioCalls if c['method'] == 'update_replication_rule']
print('   %s' % update)
if not update or update[0]['options'] != {'lifetime': 30 * 86400}:
  failures += 1
  print('   ^^ FAIL: expected lifetime 2592000 seconds')

call(ui.ruleUpdateCmd, {'rule_id': RULEID, 'lifetime_days': 0})
update = [c for c in rucioCalls if c['method'] == 'update_replication_rule']
if not update or update[0]['options'] != {'lifetime': 0}:
  failures += 1
  print('   ^^ FAIL: 0 days must send lifetime 0')

print()
print('   --- an unreadable rule is a 404, and nothing is updated ---')
failOn.add('get_replication_rule')
status, _ = call(ui.ruleUpdateCmd, {'rule_id': RULEID, 'lifetime_days': 30})
check('   unreadable rule', status, '404')
if any(c['method'] == 'update_replication_rule' for c in rucioCalls):
  failures += 1
  print('   ^^ FAIL: must not update a rule it could not read')
failOn.discard('get_replication_rule')

# --------------------------------- Rucio reached only where authorised

print()
print('=== refusals never reach Rucio, and never commit ===')

refusals = [
  (ui.didRemoveCmd,        {'did': 'dc4:x.root'}),
  (ui.didRemoveCmd,        {'did': THEIRS + ':x.root'}),
  (ui.didRemoveUndoCmd,    {'did': 'dc4:x.root'}),
  (ui.didListCmd,          {'scope': 'dc4'}),
  (ui.didShowCmd,          {'did': THEIRS + ':x.root'}),
  (ui.didContentAddCmd,    {'did': MINE + ':a.root', 'to_dataset': 'dc4:ds'}),
  (ui.didContentRemoveCmd, {'did': MINE + ':a.root', 'from_dataset': 'dc4:ds'}),
]

for handler, jd in refusals:
  call(handler, jd)
  if rucioCalls:
    failures += 1
    print('   FAIL: %s reached Rucio on a refusal' % handler.__name__)
  if 'commit' in ui.justin.conn.actions:
    failures += 1
    print('   FAIL: %s committed on a refusal' % handler.__name__)
print('   %d refusal paths checked: no Rucio calls, no commits' % len(refusals))

# ------------------------------- the restriction lives in ONE place

print()
print('=== lifting refuseGroupScope() frees ALL seven, not some ===')

# The point of this test. The guard used to be three separate copies, two
# of them in handlers that take no DID, so deleting the obvious one would
# have freed five commands and left did-list and rule-update refusing. If
# anyone reintroduces a second copy, this fails.
ruleRecord['scope'] = 'dc4'
scopeContents['dc4'] = ['a.root']
original = ui.refuseGroupScope
ui.refuseGroupScope = lambda scopeName, verb: None

GROUP_DS = 'dc4:dataset_one'
for name, handler, jd in [
    ('did-list',           ui.didListCmd,          {'scope': 'dc4'}),
    ('did-show',           ui.didShowCmd,          {'did': 'dc4:t.root'}),
    ('did-remove',         ui.didRemoveCmd,        {'did': 'dc4:t.root'}),
    ('did-remove-undo',    ui.didRemoveUndoCmd,    {'did': 'dc4:t.root'}),
    ('did-content-add',    ui.didContentAddCmd,    {'did': 'dc4:a.root',
                                                    'to_dataset': GROUP_DS}),
    ('did-content-remove', ui.didContentRemoveCmd, {'did': 'dc4:a.root',
                                                    'from_dataset': GROUP_DS}),
    ('rule-update',        ui.ruleUpdateCmd,       {'rule_id': RULEID,
                                                    'lifetime_days': 30})]:
  check('   ' + name + ' on a group scope', call(handler, jd)[0], '200')

ui.refuseGroupScope = original
ruleRecord['scope'] = MINE
scopeContents.pop('dc4', None)

print()
print('   --- and with it restored, all seven refuse again ---')
ruleRecord['scope'] = 'dc4'
for name, handler, jd in [
    ('did-list',           ui.didListCmd,          {'scope': 'dc4'}),
    ('did-show',           ui.didShowCmd,          {'did': 'dc4:t.root'}),
    ('did-remove',         ui.didRemoveCmd,        {'did': 'dc4:t.root'}),
    ('did-remove-undo',    ui.didRemoveUndoCmd,    {'did': 'dc4:t.root'}),
    ('did-content-add',    ui.didContentAddCmd,    {'did': 'dc4:a.root',
                                                    'to_dataset': GROUP_DS}),
    ('did-content-remove', ui.didContentRemoveCmd, {'did': 'dc4:a.root',
                                                    'from_dataset': GROUP_DS}),
    ('rule-update',        ui.ruleUpdateCmd,       {'rule_id': RULEID,
                                                    'lifetime_days': 30})]:
  check('   ' + name + ' on a group scope', call(handler, jd)[0], '403')
ruleRecord['scope'] = MINE

# ------------------------------------------ connection failure is 500

print()
print('=== a Rucio outage is a 500, not a traceback ===')
connectFails = True
for name, handler, jd in [
    ('did-list',           ui.didListCmd,          {'scope': MINE}),
    ('did-show',           ui.didShowCmd,          {'did': MINE + ':t.root'}),
    ('did-remove',         ui.didRemoveCmd,        {'did': MINE + ':t.root'}),
    ('did-remove-undo',    ui.didRemoveUndoCmd,    {'did': MINE + ':t.root'}),
    ('did-content-add',    ui.didContentAddCmd,    {'did': MINE + ':a.root',
                                                    'to_dataset': DS}),
    ('did-content-remove', ui.didContentRemoveCmd, {'did': MINE + ':a.root',
                                                    'from_dataset': DS}),
    ('rule-update',        ui.ruleUpdateCmd,       {'rule_id': RULEID,
                                                    'lifetime_days': 30})]:
  check('   ' + name, call(handler, jd)[0], '500')
connectFails = False

print()
print('FAILURES: %d' % failures)
sys.exit(1 if failures else 0)
