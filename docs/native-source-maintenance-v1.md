# Native source maintenance v1 — narrow candidate

2026-11-17. Source/filesystem/command checks and the same-fixture installed
upgrade/native Main subset below pass. Full mode/platform/GUI acceptance remains pending.
This is code-only maintenance for the proven empty, unbound native profile, not
legacy migration, general state recovery, or completed R017 GUI delivery.

The first installed native candidate retains its original failed pre-start in
case E. systemd's `+` executes a Root helper but leaves TemporaryFileSystem mounts
in effect. A separate readonly diagnostic passed with fixed
`nsenter --mount=/proc/1/ns/mnt --root=/proc/1/root --wd=/` around the existing
Root inspector. The candidate unit now applies this context to that one command.
Main keeps its dedicated identity, empty capability sets, NNP and filesystem masks.
All paths/commands are fixed; no caller-chosen PID, namespace or command is used.

`prepare-source-update --request-id ORIGINAL_UUID --package ROOT_PRIVATE_DEB
--sha256 REVIEWED_SHA256` is a Root backend operation. It first requires current
exact code/unit/source pairing, inactive original profiles, initial disabled
configuration, exactly the original three state files, the original generation
and zero rows in the seven business tables. Only observed empty Root0755 legacy
mountpoints are recognized; real legacy data, credentials/grants and other state
require their separate maintenance flow. The DB/plan key/init receipt/continuity
fingerprints are captured without resetting or adopting anything.

Incoming archives must have exactly the 23 code/doc/metadata payloads and four
paired maintainer scripts, Root ancestors/files and exact modes. Configuration,
state, symlinks, extra control hooks or data paths are refused before dpkg.
Native/public/publisher metadata and every mapped source are checked; the Java
adapter and Core loader metadata must retain their exact existing pair. Each
maintainer body and lifecycle is authenticated against its source manifest.
Embedding uses the actual top-level AST main guard; a matching string inside a
source literal does not truncate privileged code.

The controller takes the package-manager frontend/backend locks, rechecks current
source/data, then publishes the original global intent before per-operation
records. A fixed runtime mask blocks agent starts. The exact previous installed
prerm is authenticated and retained privately before an atomic replacement with
the incoming paired guard. This explicit bootstrap is needed because the first
unreleased native candidate refused every initialized profile in its old prerm.
It does not hide data or bypass an UNKNOWN business guard. A controller verified
from the incoming cohort is required to bootstrap that first candidate; its old
installed wrapper does not provide the new action. This backend is not the
finished graphical maintenance workflow.

Native prerm/preinst accept only the pending original source pair, matching target
version and exact unchanged state. Postinst verifies all installed incoming code
and data again, then publishes new public code pins plus a separate immutable
source-pair result/current pointer. Only the three code pins may change; UID/GIDs,
paths and authority stay exact. The historical initialization receipt is never
rewritten. Every later startup validates the entire bounded source-pair chain
back to that original receipt. Interrupted publication preserves the original
intent and only missing, independently proven local publication steps can resume;
it does not resend tasks, initialize again or start units. Missing history or a
lost pending marker with incomplete records blocks startup and another ID.

The narrow operation refuses bound/running/business-bearing profiles and leaves
full native/legacy upgrades, UNKNOWN migrations, credential continuity, general
backup/restore, removal/purge and GUI authorization/activation internal pending.
It does not repair the unchanged Root-agent isolation defect in older live scenes.
The complete six-component/provider/launcher/platform matrix and twelve frozen
parents remain open; only the original three external deferred groups apply.

Current checks: expanded Python158 total,156 pass and2 explicitly excluded old
export fixtures. Eleven source-maintenance methods cover previous/incoming
maintainer authenticity, code/data boundaries, original admission/publication,
interruption/resume, lost marker/history, wrong pair/version/mask and a real busy
package-manager lock. Counts overlap earlier selections. Actual first native
Main and its namespace subset subsequently passed in the retained case E.

## Same original case E acceptance

Code `e06139b` produced package `0.1.0~native20261117.e06139b-1`, SHA256
`a478cb78f8ddf795467b5847e37c72942c419c14eda4297d719a8e24ccb2fea1`.
231 exported source files were checked; all201 Rust build inputs were unchanged,
and an actual fresh release build reproduced ELF `f6d0920f…72a1`.
The four generated maintainer scripts compile.

Original source operation `26ea376c-81ff-4cdd-b8b9-3ebfcc7c4105` prepared once in
the existing `a60111a6…44414` environment. The new Root controller was copied from
and checked against the incoming package before bootstrapping its old installed
prerm. Readonly preflight authenticated both complete script cohorts, Java/loader
pair and six original inputs. Preparation masked the inactive unit; the one dpkg
dispatch admitted that same pair, upgraded in place and published the immutable
history. Original status is APPLIED/unitStarted=false; mask/pending are gone.
DB, key, marker, original init receipt, env and continuity fingerprints remain
exact. Initialization `24560864-f974-46aa-940a-0a97ad926118` is still APPLIED/READY;
it was not replayed or rewritten. The original pre-start failure stays recorded.

The original first-start purpose then continued after the paired fix. Main795/
ticks18465663 is active, NRestarts0, UID/GID997 with groups996/997, all five
capability sets zero and NNP1. Local `agent.status` reports available; Kura is
absent and no identity/channel is bound. This started before Java was installed,
so Java/Core were not dependencies of standalone agent startup.

Public synthetic probes in the actual Main mount namespace, using its exact
UID/GID, cap0/NNP1 and legitimate reader group, cannot read a Root0600 public file
directly (hidden), through a UID0/cap0/NNP1 peer's process root (EACCES), or connect
to a Root0600 public-only socket (EACCES). Private env/admin paths stay hidden.
The Root public positive control succeeds; owned workers/files are removed. No
real Core key/HMAC, business CSR or old command is opened/sent. Core itself is
not installed here, so this is not actual Core key/provider or OSGi acceptance.

OpenJDK21.0.13 was installed only afterward in this new fixture for the actual
packaged Java policy probe. A freshly compiled Java21 test probe loads the
installed adapter JAR as UID65534/cap0 with the control group: it accepts the real
UID997/native-group server and rejects a conflicting Root property. No business
frame or Kura registration is sent. A Docker archive-copy attempt into /run failed
before execution; the same test intent used checked public file bytes via exec,
with the failure preserved. Main PID/ticks/capabilities remain unchanged.

Runtime creates its own disabled remote record, empty network/firewall/recovery
directories and zero-byte locks; all seven business tables remain zero and the
original native generation remains1. These observed runtime assets need a typed
continuity/maintenance inventory before general upgrades. This first operation
was deliberately limited to the pre-run empty state; do not relax it or delete
runtime files to pass another source update. Complete retained upgrade, Root
authorization/delegation, Core/OSGi, provider/launcher/resource/platform and GUI
rows remain internal pending.

## Initial runtime inventory increment

The source controller now recognizes the exact owned assets traced to native
`Remote::open`, `Network::open`, recovery/firewall constructors and system-change
guard. It permits the original disabled `installation` remote decision with its
canonical revision, known empty directories, zero-byte original locks, empty WAL
and bounded original SHM. All files/directories require the exact native UID/GID,
private modes, regular/single-link files and no unreviewed paths. Directory and
file byte/metadata fingerprints are retained across source publication. Existing
runtime writer locks must be independently available; no lock is recreated.

A missing remote decision alongside runtime evidence is a recovery condition.
Nonempty WAL is refused before the immutable main-database read; empty main DB
must never conceal a WAL containing unknown work. Existing recovery receipts,
network journals, changed/enabled decisions, bound credentials or other state
stay outside this narrow inventory. Nothing is deleted, adopted, chmod/chowned
or regenerated to obtain admission. This is not general running/bound maintenance
or a complete state-loss/recovery guarantee.

Expanded Python163 total:161 pass,2 historical export fixtures excluded. Five new
methods cover unchanged initial-runtime source publication, nonempty WAL refusal,
missing original decision, real recovery/changed decision refusal and an actual
orphan writer flock. These overlap earlier checks. This increment is not yet
installed in case E at the time of its source commit; the already running E
retains package e06139b/Main795 while the next paired cohort is prepared.
