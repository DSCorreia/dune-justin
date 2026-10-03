# Interactive file management in per-user Rucio scopes

**Status: prototype and proposal. Nothing here acts on data.**

Prepared by Daniel Souza Correia (dsouzac@olemiss.edu), October 2026.
Measurements taken on `dunegpvm07.fnal.gov` against justIN 01.06.04 and the
production justIN instance at `justin-ui-fnal.dune.hep.ac.uk`.

**Branch base: `02.00` at `416d479` (02.00.rc4), fetched 2026-10-03.**
This work was first written against `main`, then rebased. `main` has not moved
since 2026-07-09 and is still `01.07.rc0`, while `02.00` has reached rc4 with
104 commits and was last touched the day before this was written. `02.00` is
where development is happening and is what this proposes against. All twelve
commits replayed onto it with no conflicts.

Two things survived the move unchanged, which matters:

- every column `checkScopeWritable()` reads - in `scopes`, `named_quotas`,
  `users`, `principal_names` and `wlcg_groups` - is identical on 02.00, so the
  authorisation query is correct on the new base
- `scopesInfo()` is untouched upstream, so the ambiguity in finding 1 below is
  still present in 02.00 and open question 3 is still live

02.00 does rename columns elsewhere, which dates some of the descriptions in
other notes but not this proposal: `files.state` became `file_state` and gained
a `processing` value, `workflows.state` became `workflow_state`, and
`replicas.wan_pfn` and `lan_pfn` were merged into a single `pfn` - so the
LAN/WAN distinction that `findBestFile()` used to make is gone.

---

## The problem

Every DUNE user now has a private Rucio scope — `user.<username>.fnal.gov`.
A justIN workflow can be told to write its outputs there and it will.

But justIN writes **all** output files with its own privileged credentials,
including files landing in user and group namespaces. The constant is in
`modules/__init__.py`:

```python
rucioProductionUser = 'dunepro'
```

So users can have justIN write their files, and can read them afterwards, but
there is no way to write further files outside a job, or to move, rename or
delete the ones that exist. Your name is on the scope; `dunepro` is the only
account that ever touches it.

This directory contains a working tool that establishes exactly where the
boundary sits, and a proposal for moving it.

---

## What was measured

Four things, none of which were obvious before testing against the running
system. They are the substance of this proposal.

### 1. The published scope table cannot distinguish "yours" from "unusable"

justIN's rule, from the scope check in `services/justin-wsgi-ui`:

```python
if not quotaName:
    403  'Scope %s has no named quota defined and cannot yet be used via justIN'

if wlcgGroupName:
    if wlcgGroupName not in user['wlcg_groups']:
        403  'You need to be in group %s to use scope %s'
elif principalName != user['user_name']:
    403  'You need to be %s to use scope %s'
```

A scope is owned either by a **WLCG group** or by a **person**, depending on the
named quota behind it. But the information API publishes only two columns:

```
GET /api/info/scopes.csv   →   scope_name,wlcg_group_name
```

`quota_name` and `principal_name` are not published anywhere. So an empty group
field conflates two situations with opposite consequences — *this belongs to a
person* and *this has no quota and nobody may use it*.

In the live table on 2026-10-02:

```
1173 scopes
  67 with a published WLCG group
1106 with none  ← includes all 1097 user.* scopes
```

Every per-user scope, including the ones this proposal is about, falls in the
ambiguous blank.

### 2. A DUNE WLCG token carries no identity

The obvious place to look for a principal name is the token justIN caches.
It is not there. A real token, read on dunegpvm07:

```json
{
  "sub":         "a77d88e4-42d6-4ced-b69c-6e7f77669b09",
  "wlcg.groups": ["/dune", "/dune/production"],
  "wlcg.ver":    "1.0",
  "scope":       "storage.read:/ storage.create:/scratch/users/danielsc ..."
}
```

No `eppn`, no `preferred_username`, no `email`. The subject is an opaque CILogon
UUID. This is by design — the WLCG profile carries authorisation, not identity.

Since justIN's rule for user-owned scopes compares **principal names**, the token
can never answer that question. `justin whoami` can, and does.

### 3. The user's X.509 proxy is justIN's identity, not the user's

`justin get-token` writes a proxy to `/tmp/x509up_uUID`. Inspecting it:

```
identity  : /C=UK/O=eScience/OU=Manchester/L=HEP/
            CN=justin-jobs-no-roles.dune.hep.ac.uk/CN=3351091619
attribute : /dune/Role=NULL/Capability=NULL
```

That is justIN's own shared no-roles certificate — the one described in
`docs/security_model.md` as being delegated into the container that runs a user's
jobscript. It is not a credential belonging to the user at all.

`dune-rucio.fnal.gov` refuses it:

```
SSLError(1, '[SSL: TLSV1_ALERT_UNKNOWN_CA] tlsv1 alert unknown ca')
Cannot authenticate to account dunepro with given credentials
```

The server answers an anonymous `GET /ping` with 200, so the service is healthy —
it is the client certificate it will not accept. The proxy is for reading from
**storage**; the Rucio **catalogue** is a different door, and this key does not
open it.

### 4. Even the privileged path is not attributable

`justin get-token --production` issues a proxy that, per the `justin(1)` man page,
is "capable of writing directly to storage and issuing Rucio data management
commands" — for members of `/dune/production` only.

But the Rucio client on the gpvm is configured as:

```
# /cvmfs/dune.opensciencegrid.org/products/dune/rucio/v38_1_0/NULL/etc/rucio.cfg
account = dunepro
auth_type = x509_proxy
```

So even on that path, every operation is attributed to `dunepro`. Nothing records
*which person* deleted a file. For an experiment that will run for decades, that
is a problem independent of access control.

---

## What is in this directory

A tool that predicts whether justIN would permit an operation, prints the Rucio
calls it would require, and stops.

| File | Role |
|---|---|
| `justin_token.py` | Finds and decodes the cached WLCG token. Decodes only — never verifies. |
| `justin_identity.py` | Asks `justin whoami` who you are. See finding 2. |
| `justin_scopes.py` | Fetches and caches `/api/info/scopes.csv`. Reports facts, interprets nothing. |
| `justin_decide.py` | The prediction. Pure — no network, no files, no clock. |
| `justin_rucio.py` | The execution layer and its guard rails. **Not wired in.** |
| `justin-files` | The command. |

### Four outcomes, not a yes/no

Because the published data is thinner than justIN's rule, a binary answer would
have to lie. So:

```
ALLOWED       group-owned scope, you are in the group        certain
DENIED        group-owned scope and you are not; or the
              scope is absent from justIN's table            certain
LIKELY        name matches your identity by the
              user.<name>.fnal.gov convention                inferred
UNDETERMINED  no group published, name does not match you    unknown
```

`LIKELY` exists because the `user.<name>.fnal.gov` convention appears **nowhere in
justIN's source**. It is a Rucio naming practice read off the data. Anything
resting on it is reported as an inference and never as certainty.

Exit codes are distinct per outcome — 0, 2, 3, 4, and 1 for errors — so that
collapsing `LIKELY` into `ALLOWED` is impossible by accident.

### Verified behaviour

On dunegpvm07, against a live session and token:

```
usertests                  exit=0  ALLOWED
dc4                        exit=0  ALLOWED
dc4-output                 exit=0  ALLOWED
user.danielsc.fnal.gov     exit=3  LIKELY   (inferred)
user.aahmad.fnal.gov       exit=4  UNDETERMINED   (unknown)
no.such.scope              exit=2  DENIED
```

```
  identity   danielsc@fnal.gov   (token 1h17m left)
  groups     /dune, /dune/production
  scope      user.danielsc.fnal.gov
  decision   LIKELY   (inferred)
             name matches your identity by the user.<name> convention,
             but justIN does not publish scope owners

  would run  rucio erase user.danielsc.fnal.gov:test_00123.root

  NOT EXECUTED.
```

### Requirements

Python 3.6 or later, standard library only, matching `commands/justin`. The only
external dependency is the IGTF trust anchors, because justIN's endpoints present
grid certificates that are not in a normal system trust store:

```bash
sudo apt install ca-policy-igtf-classic      # Debian/Ubuntu
# anchors land in /etc/grid-security/certificates, NOT the system store
```

On the gpvm these are already present (1299 anchors). `justin_scopes.py` loads the
system CAs *and* that directory, so it works in both places unchanged.

---

## Path A — what a user could build today, and why it is not enough

A member of `/dune/production` could close the loop themselves: take a production
proxy, set up the Rucio client, check the operation against justIN's rules with
`justin_decide.py`, and execute only if permitted.

`justin_rucio.py` implements that execution layer, including:

- `preflight()` — runs the read-only `rucio whoami` and refuses with a specific
  explanation if the credential cannot authenticate, rather than discovering it
  halfway through a two-call `mv`
- `execute(calls, permitted=False, dryRun=True)` — both guards default to the safe
  value, so a caller that forgets to check gets a refusal rather than an execution
- stops at the first failing call, because a `mv` is detach-then-attach and running
  the attach after a failed detach leaves the file in neither dataset

**It is deliberately not wired into `justin-files`.** Connecting it is a short,
obvious change, and it is left for a human to make knowingly. Three reasons:

1. **The enforcement would be advisory.** A client holding a write-everything
   credential and policing itself is only as safe as its own logic. Server-side
   refusal is the only kind that means anything.
2. **It works only for `/dune/production` members.** That is a small fraction of
   users, and not the ones the problem describes.
3. **Everything it did would be attributed to `dunepro`** — see finding 4.

Path A is worth having as a demonstration. It is not worth deploying.

---

## Path B — the proposal

**justIN already holds every hard part of the solution.** It has the user's
identity and groups, the authorisation rule, the `dunepro` credential, and a CLI
that users already have installed. It writes files into these very scopes, every
day, at scale.

What it lacks is verbs. There is no `justin rm-file`. The complete command list,
unchanged from 01.06.04 through 02.00.rc4:

```
create-workflow  submit-workflow  restart-workflow  pause-workflow
finish-workflow  create-stage     create-campaign   simple-workflow
show-workflows   show-stages      show-jobscript    show-stage-outputs
show-files       fail-files       show-replicas     show-jobs
fetch-logs       get-token        whoami            time      version
```

`show-files` and `show-replicas` read justIN's own database; they are not Rucio
operations.

So the proposal is not "build a tool that borrows justIN's authentication". It is:

### Add the operations to justIN, where the authorisation already lives

New subcommands, backed by endpoints in `justin-wsgi-ui` that perform the Rucio
call after the scope check the service **already runs today** for workflow
creation. The user never holds a privileged credential; justIN acts on their
behalf, within bounds it already knows how to compute.

Suggested, smallest first:

| Command | Rucio operation | Notes |
|---|---|---|
| `justin rm-file DID` | `erase` | The most requested, and the most dangerous |
| `justin attach-file DID DATASET` | `attach` | |
| `justin detach-file DID DATASET` | `detach` | Together these are "move between datasets" |
| `justin put-file PATH SCOPE` | `upload` | Largest; needs RSE selection and quota checks |

Rucio has **no rename primitive** for files — a DID is an identifier, not a path —
so renaming means uploading under a new DID and erasing the old. Worth stating in
any user documentation, since "rename" is what people will ask for.

### What this branch actually changes

One piece of the patch is applied: `checkScopeWritable()` in
`services/justin-wsgi-ui`, 57 lines, which lifts justIN's existing scope rule
out into a function so a second caller cannot drift away from it. It adds no
capability and changes no behaviour — the two existing call sites are untouched
and could adopt it.

Its SQL was verified against a database seeded with one row of every shape that
occurs in the real scope table (`prototypes/user-scope-tools/` has the harness):

```
usertests               as danielsc  groups /dune                    ALLOWED
usertests               as danielsc  groups -                        denied
dc4                     as danielsc  groups /dune,/dune/production   ALLOWED
dc4                     as danielsc  groups /dune                    denied
user.danielsc.fnal.gov  as danielsc  groups -                        ALLOWED
user.aahmad.fnal.gov    as danielsc  groups /dune/production         denied
orphan_scope            as danielsc  groups /dune,/dune/production   denied
no_such_scope           as danielsc  groups /dune                    denied
user.aahmad.fnal.gov    as aahmad    groups -                        ALLOWED
```

The property worth checking twice: **membership of `/dune/production` does not
open another person's scope.** That branch compares identity, not groups, so a
production member asking to remove `user.aahmad.fnal.gov:x` is told *"You need to
be aahmad@fnal.gov"*. Any implementation must preserve that.

The handler itself (`rmFileCmd`) is **described below but not applied**, and so is
the `scopes.csv` column. Both are decisions for the maintainers rather than
changes to make unilaterally: one performs an irreversible-ish deletion, the other
publishes every user's principal name on an unauthenticated endpoint.

### The proposed handler

Validate, authorise, act — reusing the function above:

1. Require `file_did` as `scope:name`; reject anything failing
   `justin.stringIsDID()` / `stringIsFile()`.
2. `refusal = checkScopeWritable(scopeName, user)` — return it if not `None`.
3. `rucio.client.didclient.DIDClient().set_metadata(scope, name,
   'lifetime', 86400)`.
4. Return 200 saying when Rucio will remove the file.

Then one line in the dispatcher next to `fail-files`, and `"rm-file"` added to the
`commands` list in `commands/justin`. No client-side response handling is needed —
the CLI already has a default branch that prints the body.

Three things a reviewer should weigh:

- **Deletion is deferred, not immediate.** `set_metadata(... 'lifetime', 86400)` is
  exactly what `rucio erase` does (`rucio/cli/bin_legacy/rucio.py:833`). Rucio
  removes the file after 24 hours and clearing the lifetime cancels it. Deleting
  outright would be easier and much worse.
- **This would be justIN's first Rucio write.** The UI service already calls Rucio
  synchronously, but only `list_replicas` and `download_dids` — both reads. If a
  write belongs in an agent instead of a request handler, it should move. The
  authorisation is unaffected either way.
- **There is nowhere to record who asked.** `justin.logEvent()` accepts campaign,
  workflow, stage, file, job, site, entry and rse — but no user, and the `events`
  table has no `user_id`. See the scoping note immediately below, which is what
  this implies.

### Start with user-owned scopes only

`checkScopeWritable()` permits two kinds of scope, and they have very different
risk profiles:

| | Who may write | Attribution | Blast radius |
|---|---|---|---|
| `user.<name>.fnal.gov` | exactly one person | **implicit in the scope name** | your own files |
| `dc4`, 53 others | everyone in a WLCG group | none — all operations run as `dunepro` | shared production data |

For a personal scope, a `user_id` column would record something the scope name
already states: only `danielsc@fnal.gov` can write to
`user.danielsc.fnal.gov`, so if a file there was removed through justIN, it was
them. Attribution is near-redundant.

For a group scope it is the opposite. Dozens of people share `/dune/production`,
every operation is attributed to `dunepro`, and a deleted production file leaves
no trace of who asked. That is also where a mistake costs the most.

**So the first version should accept user-owned scopes only** — refuse when
`wlcg_group_name` is set, with a message saying group scopes are not yet
supported. That gives:

- the use case the original request actually describes
- a blast radius limited to the requester's own files
- no dependency on an `events.user_id` column
- a materially smaller change to review

Group scopes can follow once attribution exists. Splitting it this way turns one
contested change into an uncontroversial one plus a later conversation, and the
authorisation function already written needs no modification — only the handler
decides which kinds of scope it will accept.

### Two smaller changes that would help immediately

**(a) Publish `principal_name` in the scopes API.** A one-column addition to
`scopesInfo()` in `services/justin-wsgi-ui`:

```python
rows = justin.select('SELECT scope_name,wlcg_group_name,principal_name '
                     'FROM scopes '
                     'LEFT JOIN named_quotas '
                     'ON named_quotas.quota_id=scopes.quota_id '
                     'LEFT JOIN users ON users.user_id=named_quotas.user_id '
                     'LEFT JOIN principal_names '
                     'ON principal_names.pn_id=users.main_pn_id '
                     'LEFT JOIN wlcg_groups '
                     'ON named_quotas.wlcg_group_id=wlcg_groups.wlcg_group_id '
                     'ORDER BY scope_name')
```

This collapses `LIKELY` and `UNDETERMINED` into certainty and makes correct
client-side tooling possible at all. It exposes the mapping from scope to owner,
which is a judgement for the maintainers — though scope names already encode
usernames in plain text.

**(b) Attribute operations to the person.** Whatever performs these operations
should record *who asked*. justIN already has an `events` table built for exactly
this kind of audit trail.

---

## Open questions

1. **Should per-user scopes be writable interactively at all**, or is write-once
   output from workflows the intended model? This proposal assumes the former
   because the original request did, but it is the maintainers' call.
2. **Quota enforcement.** `named_quotas` and `storages_quotas` exist. Interactive
   uploads would need to respect them; workflow outputs already do.
3. **Whether the `user.<name>.fnal.gov` convention is guaranteed.** Nothing in
   justIN constructs or parses it. If it is a stable Rucio-side rule, that is worth
   writing down somewhere; if it is not, finding 1 matters more than it appears.
4. **Rucio-side scoped credentials.** The token already carries
   `storage.create:/scratch/users/danielsc` — a path-scoped write capability. If
   Rucio could issue the catalogue equivalent per scope, users could act as
   themselves and Path B's server-side mediation would become optional rather than
   essential. That is a much larger change, and a question for the Rucio team
   rather than for justIN.

---

## Where to send this

Issues for justIN go to **`DUNE/dune-dist-comp`**, not to the `dune-justin` repo —
its own issue template says so. The maintainers are Andrew McNab (Manchester) and
Christopher Brew (STFC).

This directory is a prototype and is **not proposed for merge into
`DUNE/dune-justin`**. That repository runs DUNE's production computing under a
strict release policy, and a `prototypes/` tree does not belong in it. It lives on
a branch as a working demonstration to accompany the discussion.

---

## Reproducing the measurements

```bash
source /cvmfs/dune.opensciencegrid.org/products/dune/setup_dune.sh
setup justin
justin whoami                      # establishes identity; needs a live session
justin get-token                   # read-only token and proxy

cd user-scope-tools
python3 justin_token.py --all-claims     # finding 2
python3 justin_scopes.py                 # finding 1
./justin-files rm user.<you>.fnal.gov:anything.root

voms-proxy-info -file /tmp/x509up_u$(id -u) -identity -fqan   # finding 3
setup rucio && rucio whoami                                    # finding 3, 4
```

`justin get-token --production` was deliberately **not** run while preparing this,
since it writes a privileged credential to disk.
