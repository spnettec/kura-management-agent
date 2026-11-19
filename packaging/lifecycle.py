"""Embedded in all deb maintainer scripts, including postrm after payload removal."""
import grp


def lifecycle(script, action):
    setup = Setup()
    if script == 'preinst' and action in ('install', 'upgrade'):
        setup.preflight()
        loader = setup.guard_core_loader(PACKAGE_CORE_LOADER_SHA256)
        if (action == 'upgrade' and len(sys.argv) == 4
                and setup.path(setup.nm_package_path(PACKAGE_LEGACY_NM_PAIR, 'observed.json')).exists()):
            if loader is None:
                raise RuntimeError('An installed paired Core is required for observed firewall upgrade')
            setup.observed_firewall_upgrade(sys.argv[2], sys.argv[3], PACKAGE_LEGACY_NM_PAIR, 'before-unpack')
        elif (action == 'upgrade' and len(sys.argv) == 4
                and setup.path(setup.nm_package_path(PACKAGE_LEGACY_NM_PAIR, 'json')).exists()):
            if loader is None:
                raise RuntimeError('An installed paired Core is required for original NM upgrade')
            setup.nm_package_upgrade(sys.argv[2], sys.argv[3], PACKAGE_LEGACY_NM_PAIR, 'before-unpack')
        else:
            setup.guard_writer()
    elif script == 'prerm' and action == 'failed-upgrade':
        if len(sys.argv) != 4:
            raise RuntimeError('Original NM upgrade requires old and new package versions')
        setup.preflight()
        if setup.guard_core_loader(PACKAGE_CORE_LOADER_SHA256) is None:
            raise RuntimeError('An installed paired Core is required for original NM upgrade')
        if setup.path(setup.nm_package_path(PACKAGE_LEGACY_NM_PAIR, 'observed.json')).exists():
            setup.observed_firewall_upgrade(sys.argv[2], sys.argv[3], PACKAGE_LEGACY_NM_PAIR, 'before-stop')
        else:
            setup.nm_package_upgrade(sys.argv[2], sys.argv[3], PACKAGE_LEGACY_NM_PAIR, 'before-stop')
    elif script == 'postinst' and action == 'configure':
        setup.preflight()
        try:
            grp.getgrnam('kura-management')
        except KeyError:
            setup.run(['/usr/sbin/groupadd', '--system', 'kura-management'], check=True)
        if grp.getgrnam('kura-management').gr_gid == 0:
            raise RuntimeError('Agent socket group must not be root')
        for name in [CONFIG, STATE, '/var/log/kura-management-agent']:
            path = setup.path(name)
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            if path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
                raise RuntimeError('Agent retained directories must remain root-owned and private')
        marker = setup.path(STATE + '/.package-v1')
        if not marker.exists():
            setup.put(marker, 'kura-management-agent-v1\n')
        fresh = setup.init_local()
        setup.systemctl('daemon-reload')
        setup.guard_firewall_boot_unit()
        if fresh:
            setup.systemctl('enable', '--now', UNIT)
            print('Local agent started without identity; remote management remains disabled.')
        else:
            print('Retained settings and remote decision; use explicit activate after maintenance.')
    elif script == 'prerm' and action in ('remove', 'upgrade', 'deconfigure'):
        setup.guard_writer()
        setup.stop_packaged_fence_reader(action == 'remove')
        if setup.path('/usr/lib/systemd/system/' + READER_SOCKET_UNIT).exists():
            setup.systemctl('stop', READER_SOCKET_UNIT)
            loaded = setup.systemctl('list-units', '--all', '--no-legend', '--plain', '--no-pager',
                                     'kura-management-enrollment-reader@*.service')
            if loaded is not None:
                units = [line.split()[0] for line in loaded.stdout.splitlines() if line.split()]
                if any(not name.startswith('kura-management-enrollment-reader@') or not name.endswith('.service')
                       or len(name) > 256 or any(c.isspace() for c in name) for name in units):
                    raise RuntimeError('Unexpected enrollment reader instance; preserve the original units')
                if units:
                    setup.systemctl('stop', *units)
            if action == 'remove':
                setup.systemctl('disable', READER_SOCKET_UNIT)
        setup.systemctl('stop', UNIT)
        if action == 'remove':
            # Never interrupt a pending restore. After the guard only retire this package's boot link.
            if setup.guard_firewall_boot_unit() == 'enabled':
                setup.systemctl('disable', FIREWALL_BOOT_UNIT)
            setup.systemctl('disable', UNIT)
    elif script == 'postrm':
        if action == 'purge':
            setup.purge()
        if action in ('remove', 'purge'):
            setup.systemctl('daemon-reload')


if __name__ == '__main__':
    lifecycle(SCRIPT_NAME, sys.argv[1] if len(sys.argv) > 1 else '')
