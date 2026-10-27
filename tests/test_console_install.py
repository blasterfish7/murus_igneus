"""Console installer must require a real terminal and exact confirmation before writes."""
import fcntl
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src/murus_igneus'))
import installer


class ConsoleInstallTests(unittest.TestCase):
    def setUp(self):
        self.disk={'path':'/dev/vda','bytes':16*1024**3,'model':'Test disk','identity':'lab'}
        self.data={'live':True,'message':'Live test','disks':[self.disk]}

    def test_wrong_confirmation_never_calls_install(self):
        with patch.object(installer.os,'geteuid',return_value=0),patch.object(installer,'inventory',return_value=self.data),patch.object(installer.sys.stdin,'isatty',return_value=True),patch.object(installer,'install') as install:
            self.assertEqual(installer.console_main(['--disk','/dev/vda'],read=lambda _: 'yes',log=io.StringIO()),2)
            install.assert_not_called()

    def test_exact_confirmation_uses_selected_identity(self):
        out=io.StringIO()
        with patch.object(installer.os,'geteuid',return_value=0),patch.object(installer,'inventory',return_value=self.data),patch.object(installer.sys.stdin,'isatty',return_value=True),patch.object(installer,'install') as install:
            self.assertEqual(installer.console_main(['--disk','/dev/vda'],read=lambda _:'CANCELLA /dev/vda',log=out),0)
            install.assert_called_once_with(self.disk,out)

    def test_noninteractive_install_is_refused_but_listing_is_allowed(self):
        with patch.object(installer.os,'geteuid',return_value=0),patch.object(installer,'inventory',return_value=self.data),patch.object(installer.sys.stdin,'isatty',return_value=False),patch.object(installer,'install') as install:
            self.assertEqual(installer.console_main(['--disk','/dev/vda'],log=io.StringIO()),1)
            self.assertEqual(installer.console_main(['--list'],log=io.StringIO()),0)
            install.assert_not_called()

    def test_process_lock_blocks_another_install_before_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'install.lock';fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with patch.object(installer,'INSTALL_LOCK',path),patch.object(installer,'_install') as install:
                    with self.assertRaisesRegex(ValueError,'già in corso'):installer.install(self.disk,io.StringIO())
                    install.assert_not_called()
            finally:os.close(fd)

if __name__=='__main__':unittest.main()
