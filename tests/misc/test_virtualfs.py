import os
import unittest

from impacket.virtualfs import (
    VirtualFS,
    add_virtual_share,
    remove_virtual_share,
    vfs_close,
    vfs_exists,
    vfs_listdir,
    vfs_lseek,
    vfs_open,
    vfs_read,
)


class VirtualFSUnitTests(unittest.TestCase):
    def setUp(self):
        self.vfs = VirtualFS()
        self.vfs.add_dir('test')
        self.vfs.add_file('test/test.txt', b'hello world')

    def test_add_dir_and_listdir(self):
        entries = self.vfs.listdir('test')
        self.assertIn('test.txt', entries)

    def test_stat_reports_size(self):
        stat_result = self.vfs.stat('test/test.txt')
        self.assertEqual(stat_result.st_size, len(b'hello world'))

    def test_open_read_close(self):
        handle = self.vfs.open('test/test.txt')
        self.assertEqual(vfs_read(handle, 5), b'hello')
        self.assertEqual(vfs_read(handle, 1024), b' world')
        vfs_close(handle)

    def test_seek(self):
        handle = self.vfs.open('test/test.txt')
        vfs_lseek(handle, 6, os.SEEK_SET)
        self.assertEqual(vfs_read(handle, 5), b'world')
        vfs_close(handle)

    def test_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.vfs.stat('does/not/exist')


class VFSWrapperTests(unittest.TestCase):
    def setUp(self):
        self.share_path = 'virtual_unit_share'
        self.vfs = VirtualFS()
        self.vfs.add_file('hello.txt', 'hi')
        add_virtual_share(self.share_path, self.vfs)

    def tearDown(self):
        remove_virtual_share(self.share_path)

    def test_wrappers_route_to_virtual_fs(self):
        path = os.path.join(self.share_path, 'hello.txt')
        self.assertTrue(vfs_exists(path))
        self.assertIn('hello.txt', vfs_listdir(self.share_path))
        handle = vfs_open(path, os.O_RDONLY)
        self.assertEqual(vfs_read(handle, 2), b'hi')
        vfs_close(handle)


if __name__ == '__main__':
    unittest.main()