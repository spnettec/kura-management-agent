"""Fresh native payload only. Retained profiles require original maintenance.

Embedded with Setup and RuntimeSetup in all four dpkg scripts, including postrm.
No package script adopts data, switches a legacy process or starts Core.
"""


def native_retained(setup):
    return any(os.path.lexists(setup.path(name)) for name in [V2_CONFIG, V2_ADMIN, V2_PUBLIC, V2_STATE])


def native_admission(setup):
    profile = RuntimeSetup(setup)
    profile.stopped('kura-management-agent.service')
    profile.stopped(V2_UNIT)
    for name in [CONFIG, STATE]:
        if os.path.lexists(setup.path(name)):
            raise RuntimeError('Retained legacy profile requires explicit original migration before package replacement')
    if native_retained(setup):
        raise RuntimeError('Retained native profile requires original upgrade/removal maintenance; preserve all data')


def native_accounts(setup):
    for name in ['kura-management', V2_USER]:
        try:
            group = grp.getgrnam(name)
        except KeyError:
            setup.run(['/usr/sbin/groupadd', '--system', name], check=True)
            group = grp.getgrnam(name)
        if group.gr_gid == 0:
            raise RuntimeError('Dedicated native groups must be non-Root')
    try:
        pwd.getpwnam(V2_USER)
    except KeyError:
        setup.run(['/usr/sbin/useradd', '--system', '--gid', V2_USER, '--home-dir', '/nonexistent',
                   '--no-create-home', '--shell', '/usr/sbin/nologin', V2_USER], check=True)
    RuntimeSetup(setup).account()


def lifecycle(script, action):
    setup = Setup()
    if script == 'preinst' and action in ['install', 'upgrade']:
        native_admission(setup)
        setup.guard_core_loader(PACKAGE_CORE_LOADER_SHA256)
    elif script == 'postinst' and action == 'configure':
        # A repeated configure does not initialize, start, overwrite or repair
        # an existing profile. Its original Root controller owns that intent.
        native_accounts(setup)
        RuntimeSetup(setup).profile_pair()
        setup.systemctl('daemon-reload')
        print('Native payload configured. Initialize with the original request ID; remote management remains disabled.')
    elif script == 'prerm' and action in ['remove', 'upgrade', 'deconfigure']:
        native_admission(setup)
        # Initialized data is refused above before any process/endpoint change.
        setup.systemctl('stop', 'kura-management-agent-enrollment.socket', READER_SOCKET_UNIT, V2_UNIT)
        if action == 'remove':
            setup.systemctl('disable', 'kura-management-agent-enrollment.socket', READER_SOCKET_UNIT, V2_UNIT)
    elif script == 'postrm':
        if action == 'purge' and native_retained(setup):
            raise RuntimeError('Preserve native profile and original receipts; verified archive/recovery is required before purge')
        if action in ['remove', 'purge']:
            setup.systemctl('daemon-reload')


if __name__ == '__main__':
    lifecycle(SCRIPT_NAME, sys.argv[1] if len(sys.argv) > 1 else '')
