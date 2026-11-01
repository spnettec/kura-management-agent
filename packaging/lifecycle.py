"""Embedded in all deb maintainer scripts, including postrm after payload removal."""
import grp


def lifecycle(script, action):
    setup = Setup()
    if script == 'preinst' and action in ('install', 'upgrade'):
        setup.preflight()
        setup.guard_writer()
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
        setup.systemctl('daemon-reload')
        print('Installed without starting. Import registered identity, authorize Kura if needed, then explicitly activate.')
    elif script == 'prerm' and action in ('remove', 'upgrade', 'deconfigure'):
        setup.guard_writer()
        setup.systemctl('stop', UNIT)
        if action == 'remove':
            setup.systemctl('disable', UNIT)
    elif script == 'postrm':
        if action == 'purge':
            setup.purge()
        if action in ('remove', 'purge'):
            setup.systemctl('daemon-reload')


if __name__ == '__main__':
    lifecycle(SCRIPT_NAME, sys.argv[1] if len(sys.argv) > 1 else '')
