import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from fence_reader import observe


@unittest.skipUnless(os.geteuid() == 0 and hasattr(os, 'O_NOATIME'), 'Linux Root reader fixture')
class FenceReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.network = self.root / 'network-owner-agent'
        self.firewall = self.root / 'firewall-owner-agent'

    @staticmethod
    def publish(path, data):
        with path.open('xb') as stream:
            stream.write(data)
        path.chmod(0o600)

    def test_two_fixed_files_are_observed_without_opening_unrelated_material(self):
        self.assertEqual(observe(self.root, os.getegid()), dict(schemaVersion=1, network=None, firewall=None))
        self.publish(self.network, b'original network fence')
        self.publish(self.firewall, b'original firewall fence')
        (self.root / 'unrelated-secret').symlink_to('/dev/zero')
        observed = observe(self.root, os.getegid())
        for file, key in ((self.network, 'network'), (self.firewall, 'firewall')):
            info = file.stat()
            self.assertEqual(observed[key], dict(device=info.st_dev, inode=info.st_ino,
                                                 sha256=hashlib.sha256(file.read_bytes()).hexdigest()))

    def test_backing_metadata_is_checked_and_identical_bytes_cannot_hide_replacement(self):
        self.publish(self.network, b'original')
        first = observe(self.root, os.getegid())
        self.network.rename(self.root / 'original-retained')
        self.publish(self.network, b'original')
        after = observe(self.root, os.getegid())
        self.assertEqual(first['network']['sha256'], after['network']['sha256'])
        self.assertNotEqual(first['network']['inode'], after['network']['inode'])
        self.network.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe original fence file'):
            observe(self.root, os.getegid())

    def test_symlinks_and_hardlinks_are_never_treated_as_absence(self):
        self.publish(self.network, b'original')
        os.link(self.network, self.firewall)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe original fence file'):
            observe(self.root, os.getegid())
        self.firewall.unlink()
        self.firewall.symlink_to(self.network)
        with self.assertRaises(OSError):
            observe(self.root, os.getegid())
