#!/usr/bin/env python3
#
# justin_rucio.py - the execution layer, and the guard rails around it.
#
# Part of a prototype exploring interactive file management in per-user
# Rucio scopes. See README.md in this directory.
#
# WHAT THIS CAN AND CANNOT DO
#
# Measured on dunegpvm07, 2026-10-02. The X.509 proxy that "justin
# get-token" writes to /tmp/x509up_uUID is NOT your identity:
#
#   identity  : /C=UK/O=eScience/OU=Manchester/L=HEP/
#               CN=justin-jobs-no-roles.dune.hep.ac.uk/CN=3351091619
#   attribute : /dune/Role=NULL/Capability=NULL
#
# It is justIN's own shared no-roles certificate, delegated for reading
# from storage. dune-rucio.fnal.gov rejects it outright:
#
#   SSLError(1, '[SSL: TLSV1_ALERT_UNKNOWN_CA] tlsv1 alert unknown ca')
#   Cannot authenticate to account dunepro with given credentials
#
# The server answers an anonymous GET /ping with 200, so the server is
# healthy - it is our client certificate it will not accept. Catalogue
# operations (erase, attach, detach) therefore cannot be performed with
# the credential an ordinary user is given.
#
# "justin get-token --production" issues a different proxy which, per the
# justin(1) man page, is "capable of writing directly to storage and
# issuing Rucio data management commands" - but only for members of
# /dune/production, and it authenticates AS dunepro. So even on that
# path, nothing you do is attributed to you.
#
# The preflight() below exists to detect all of this and refuse clearly,
# rather than discovering it halfway through a multi-call operation.
#
# Standard library only, to match commands/justin.

import os
import shutil
import subprocess


class RucioUnavailable(Exception):
  """The rucio client is missing, or cannot authenticate."""


class ExecutionRefused(Exception):
  """The guard rails stopped this before anything was attempted."""


def rucioPath():
  """Where the rucio client is, or None."""
  return shutil.which('rucio')


def rucioAccount():
  """Which Rucio account the client will act as.

  Worth surfacing prominently: the default rucio.cfg shipped on the gpvm
  at /cvmfs/.../rucio/v38_1_0/NULL/etc/rucio.cfg sets account = dunepro.
  So an unmodified client acts as the production account, not as you.
  """
  account = os.getenv('RUCIO_ACCOUNT')
  if account:
    return account, 'RUCIO_ACCOUNT'

  home = os.getenv('RUCIO_HOME')
  if home:
    config = os.path.join(home, 'etc', 'rucio.cfg')
    try:
      with open(config) as f:
        for line in f:
          if line.strip().startswith('account'):
            _, _, value = line.partition('=')
            return value.strip(), config
    except IOError:
      pass

  return None, None


def preflight(timeout=60):
  """Check the client exists and can authenticate. Read-only.

  Returns the account name on success. Raises RucioUnavailable with a
  message explaining what to do otherwise. Runs "rucio whoami", which
  reads and changes nothing.
  """
  if rucioPath() is None:
    raise RucioUnavailable(
      'the rucio client is not on your PATH.\n'
      'Set it up with:\n'
      '  source /cvmfs/dune.opensciencegrid.org/products/dune/setup_dune.sh\n'
      '  setup rucio')

  try:
    completed = subprocess.run(['rucio', 'whoami'],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,
                               timeout=timeout)
  except subprocess.TimeoutExpired:
    raise RucioUnavailable('"rucio whoami" timed out after %ds' % timeout)

  output = completed.stdout.decode('utf-8', 'replace')

  # rucio does not always exit non-zero on an auth failure, so check the
  # text as well as the return code.
  if completed.returncode != 0 or 'Cannot authenticate' in output:
    account, source = rucioAccount()

    raise RucioUnavailable(
      'the rucio client cannot authenticate.\n'
      '\n'
      '%s\n'
      'Configured account: %s%s\n'
      '\n'
      'The proxy from a plain "justin get-token" is justIN\'s own\n'
      'no-roles certificate, which dune-rucio.fnal.gov does not accept\n'
      'for catalogue operations. A credential that works here requires\n'
      '"justin get-token --production" and membership of /dune/production.'
      % (output.strip(),
         account or '<unknown>',
         ' (from %s)' % source if source else ''))

  return output.strip()


def execute(calls, permitted=False, dryRun=True):
  """Run the planned Rucio commands, or show what would run.

  permitted must be set explicitly by the caller after it has checked the
  decision. Defaulting it to False means a caller that forgets to check
  gets a refusal, not an execution: the safe direction to fail in.

  dryRun defaults to True for the same reason. Executing is something you
  must ask for twice - once by deciding it is permitted, once by turning
  off the dry run.
  """
  if not permitted:
    raise ExecutionRefused(
      'not permitted: the caller did not confirm this operation is allowed')

  if dryRun:
    return [(call, None, 'dry run - not executed') for call in calls]

  preflight()

  results = []

  for call in calls:
    completed = subprocess.run(call.split(),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    output = completed.stdout.decode('utf-8', 'replace').strip()

    results.append((call, completed.returncode, output))

    # Stop at the first failure. The 'mv' verb is attach followed by
    # detach, in that order deliberately: if the attach fails we stop
    # before detaching, and the file stays where it was. Doing it the
    # other way round would leave a half-finished move with the file in
    # no dataset at all.
    if completed.returncode != 0:
      break

  return results
