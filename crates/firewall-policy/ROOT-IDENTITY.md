# Firewall publication Root domains

The native worker has two Root domain schemes. With no `.root-domain-v2`
directory, it computes the original `legacy-v1` Scope from machine-id and the
Root/publication device and inode tuple, without modification. Existing intents
are never converted, rebound, re-signed or dispatched by initialization.

## Explicit initialization before the first publication

`kura-firewall-publish --initialize-persistent-root` accepts no Root, Scope,
operation ID, filesystem ID or file handle arguments. It requires effective
Root UID/GID and inherited FD3 matching Core's fixed Root-owned, mode 0600,
empty, single-link `/run/kura-key-service/writers/lease.lock`. The descriptor
must acquire the exclusive nonblocking writer lock; a Main holding its shared
lease prevents initialization. The worker does not create the coordinator.

The caller must provision an empty Root-owned mode 0700 publication directory.
Initialization refuses any existing publication entry and any nonempty rules or
boot-restore directory. An already valid v2 binding returns `EXISTS` without
rewriting metadata or inspecting operation files, including when that domain
now has pending operations. Existing legacy history cannot acquire a binding.

For each held Root and publication FD, Linux `fstatfs` and `name_to_handle_at`
with `AT_EMPTY_PATH` provide filesystem type, raw filesystem ID bytes and an
opaque kernel handle. Device numbers and mount IDs are absent from this
identity. The canonical binding has these fields:

```text
schema: 2
purpose: "kura-firewall-persistent-root-v2"
machineSha256: SHA256(trimmed /etc/machine-id)
identity:
  root: {filesystemType, filesystemId, handleType, handle}
  journal: {filesystemType, filesystemId, handleType, handle}
```

All JSON object keys are sorted recursively, without whitespace. The Scope is
the lowercase SHA256 of `kura-firewall-publication-v2` followed by a NUL byte
and the canonical binding bytes. The normal scope/outcome requests and existing
intent/receipt schemas are unchanged; the Scope remains an opaque 64-hex value.

## Publication, interruption and refusal

The worker holds the publication directory lock. It first persists a mode 0700
`.root-domain-v2` directory, then writes/fsyncs `binding.staged`, changes it to
0400, and publishes it with `renameat2(RENAME_NOREPLACE)` as `binding.json`.
Directory syncs and exact readback complete initialization. Bindings are bounded
to 8192 bytes, Root-owned and single-link. Intermediate directories and files
are not accepted as an ordinary domain.

Every ordinary journal constructor validates the final binding against the
current kernel objects before reading any operation path. Missing final bytes,
extra entries, unsafe metadata, unsupported kernel identity or a foreign binding
refuse access. Explicit initialization may finish an empty marker or a complete
staged binding only when the actual current kernel-derived bytes match exactly;
it never replaces incomplete, conflicting or foreign staged bytes. No success
receipt for a firewall operation is created by this command.

The self-contained Python package-maintenance gate independently recomputes the
same kernel identity and Scope. It checks the marker even when no intents exist,
and refuses incomplete/foreign bindings and pending operations without needing
the installed worker. Thus removing the executable does not bypass the gate.

The worker never calls `open_by_handle_at` and needs no additional capability.
Unsupported filesystems, missing filesystem IDs and handles exceeding 128 bytes
fail explicitly. There is no substitute identity. Ordinary legacy mode remains
legacy; requesting persistent mode on an unsupported OverlayFS fails.

## Observation and validation boundary

`--inspect-root-identity` holds the same directory lock and reports the selected
`rootScopeScheme` (`legacy-v1` or `kernel-fh-v2`) and current kernel objects. It
does not read operation files, dispatch Netlink or create a binding, and always
sets `authorizesMigration:false`. Observation cannot authorize an old ID on a
different Root. Removing a marker cannot authorize v2 IDs under the different
legacy Scope, and is not a supported recovery operation.

Run `tests/root_domain_linux.py --worker /absolute/worker --test-parent
/var/lib/NEW-test-directory` explicitly in an isolated, no-Kura ARM64 Linux
fixture with Python 3, util-linux and strace. It retains all synthetic cases,
uses private mount namespaces, and tests FD3 fences, unchanged legacy history,
incomplete/conflicting bindings, actual rename EINTR, workerless remove/purge
gates and object replacement without dispatching business operations. It is
separate from the normal crate regressions and is not a real receipt test.

The earlier independent C/Rust observation proved that the tested OrbStack
btrfs clone retained machine-id and inode numbers but had different kernel
filesystem objects. This does not establish rejection of every storage clone
implementation, particularly ones duplicating filesystem IDs and handles.
Normal restarts did not reproduce device-number reassignment; that boundary
remains pending. Persistent format support alone does not retrofit old domains
or complete the paired Core/Networking package and launcher matrix.

API reference: [Linux name_to_handle_at](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html).
