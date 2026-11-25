# Root identity observations

`kura-firewall-publish --inspect-root-identity` observes the current Root and the
held publication directory. It does not read operation files, dispatch Netlink,
create a binding, or change the legacy Scope. The normal publication-directory
ownership, mode and descriptor checks remain in force, and its lock is held for
the observation.

The response labels the Scope as `legacy-v1` and sets `authorizesMigration` to
`false`. A filesystem observation is not authority to rebind an existing intent
or query an old operation against another Root.

On Linux the observation combines the filesystem type, filesystem ID and opaque
`name_to_handle_at` handle for each held directory. Mount IDs and `st_dev` are
not included in this observation. The legacy Scope still uses its original
machine-id and device/inode tuple without modification. No caller-supplied Root,
filesystem ID, handle or accepted Scope is supported by the command.

The command never calls `open_by_handle_at` and requires no additional
capabilities. Kernel refusal, an unavailable filesystem ID or a handle larger
than the bounded buffer returns `UNSUPPORTED_ROOT_IDENTITY`; it does not return
a substitute identity. In particular, an unsupported OverlayFS is not treated
as a successful persistent Root observation.

The isolated ARM64 check uses two btrfs Roots, including a clone with the same
machine-id and inode numbers. Independent C and Rust observations agree, and
the clone has different filesystem-object identities. The observed identities
remain equal over normal shutdown/start cycles. Device-number reassignment was
not reproduced in those cycles. These observations do not establish support on
other filesystems or enable a new persistent publication protocol.

API reference: [Linux name_to_handle_at](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html).
