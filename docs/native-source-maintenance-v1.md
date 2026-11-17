# Native source maintenance v1 — narrow candidate

2026-11-17. Source/filesystem/command checks pass; same-fixture installed upgrade
and native Main acceptance have not yet been performed at this source checkpoint.
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
Main and its namespace proof remain required in the retained case E.
