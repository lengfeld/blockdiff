#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#   blockdiff - block based binary patch tool
#
#   Copyright (C) 2017 Stefan Lengfeld <contact@stefanchrist.eu>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) version 3 of the License. See also README.md.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import hashlib
import binascii
import unittest
from os.path import join, realpath, dirname
from subprocess import Popen, PIPE

path = realpath(__file__)
sys.path.append(join(dirname(path), "../"))

from helpers import TestCaseTempFolder, BytesStreamReader, BytesStreamWriter

BLOCKDIFF = join(dirname(path), "..", "blockdiff")


from blockdiff import (readPatch, EarlyEOFReached, readContainer,
                       NonZeroPadding, InvalidCRC, InvalidMagic,
                       packContainer, readTargetAndGenPatchCommands, Header,
                       Footer, __FILE_MAGIC_FOOTER__, writePatch,
                       FileFormatError, parseExtSuperblock, DataCorruption,
                       readSource, UnsupportedFileVersion)


class TestReadContainer(unittest.TestCase):
    def testNoPayload(self):
        __MAGIC__ = b"BDIF"
        fd = BytesStreamReader(__MAGIC__ + b"\x00\x00\x00\x00" + b"\0\0\0\0" + b"\x8a\xd3;\x0e")
        payload, bytes_read = readContainer(fd, __MAGIC__)
        self.assertEqual(payload, b"")
        self.assertEqual(bytes_read, 16)

    def testNonZeroPadding(self):
        __MAGIC__ = b"BDIF"
        # Note: The zero padding bytes are checked after the CRC32 of the wohle
        # container is checked. Therfore the following container has a valid
        # CRC32, but invalid padding bytes.
        fd = BytesStreamReader(__MAGIC__ + b"\x00\x00\x00\x00" + b"\0\0\xff\0" + b"\xf8.\x1f\x9d")
        self.assertRaises(NonZeroPadding, readContainer, fd, __MAGIC__)

    def testOneBytePayload(self):
        __MAGIC__ = b"BDIF"
        fd = BytesStreamReader(__MAGIC__ + b"\x01\x00\x00\x00" + b"\x42" + b"\0\0\0" + b"\xa2C\x8c\xf3")
        payload, bytes_read = readContainer(fd, __MAGIC__)
        self.assertEqual(payload, b"\x42")
        self.assertEqual(bytes_read, 16)

    def testZeroPadding(self):
        __MAGIC__ = b"BDIF"
        # Using 12 bytes of payload results in zero padding added.
        fd = BytesStreamReader(__MAGIC__ + b"\x0C\x00\x00\x00" + b"123456789012" + b"\x9d\xe8\xbcm")
        payload, bytes_read = readContainer(fd, __MAGIC__)
        self.assertEqual(payload, b"123456789012")
        self.assertEqual(bytes_read, 24)

    def testInvalidCRC(self):
        __MAGIC__ = b"BDIF"
        # Note: The InvalidCRC execption is raised, before the zero padding is
        # checked. So hence the following container as a non-zero padding, the
        # first failure mode is the invalid CRC32.
        fd = BytesStreamReader(__MAGIC__ + b"\x01\x00\x00\x00" + b"\x42" + b"\0\xff\0" + b"\xff\xff\xff\xff")
        self.assertRaises(InvalidCRC, readContainer, fd, __MAGIC__)

    def testInvalidMagic(self):
        __MAGIC__ = b"BDIF"
        # The InvalidMagic exceptions is raised very early. Providing a full
        # container not needed, just the first four bytes are sufficient.
        fd = BytesStreamReader(b"aabb" + b"...")
        self.assertRaises(InvalidMagic, readContainer, fd, __MAGIC__)


class TestPackContainer(unittest.TestCase):
    def testZeroLengthPayload(self):
        __MAGIC__ = b"BDIF"
        container = packContainer(__MAGIC__, b"")
        self.assertEqual(len(container), 16)
        self.assertEqual(container,
                         __MAGIC__ + b"\x00\x00\x00\x00" + b"\0\0\0\0" + b"\x8a\xd3;\x0e")

    def testOneBytePayload(self):
        __MAGIC__ = b"BDIF"
        container = packContainer(__MAGIC__, b"\x42")
        self.assertEqual(len(container), 16)
        self.assertEqual(container,
                         __MAGIC__ + b"\x01\x00\x00\x00" + b"\x42" + b"\0\0\0" + b"\xa2C\x8c\xf3")

    def testZeroPadding(self):
        # Using 4 + 8 = 12 bytes of payload. In that case no padding is needed.
        __MAGIC__ = b"BDIF"
        container = packContainer(__MAGIC__, b"123456789012")
        self.assertEqual(len(container), 24)
        self.assertEqual(container,
                         __MAGIC__ + b"\x0C\x00\x00\x00" + b"123456789012" + b"\x9d\xe8\xbcm")


class TestReadSource(TestCaseTempFolder):
    def testSimple(self):
        dir = join(self.tmpdir, "testSimple")
        os.makedirs(dir, exist_ok=True)

        source = b"aabbaaaaaa"
        source_filepath = join(dir, "source")
        with open(source_filepath, "bw") as f:
            f.write(source)

        x = readSource(source_filepath, 2, "MD5", stdoutAllowed=False)
        source_hashtable, source_blockcount, source_checksum = x

        # NOTE: Only a maximum of three block indices are saved in the
        # hashtable.
        self.assertEqual(source_hashtable,
                         {hashlib.md5(b"aa").hexdigest(): ([0, 2, 3], binascii.crc32(b"aa")),
                          hashlib.md5(b"bb").hexdigest(): ([1], binascii.crc32(b"bb"))})
        self.assertEqual(source_blockcount, 5)
        self.assertEqual(source_checksum, hashlib.md5(source).digest())


class TestReadTargetAndGenPatchCommands(unittest.TestCase):
    def testCopyWriteAndZeroEntry(self):
        # Create dummy dictionary for source file
        blocksize = 2
        source_fd = BytesStreamReader(b"aabb")
        source_hashtable = {hashlib.md5(b"aa").hexdigest(): ([0], binascii.crc32(b"aa")),
                            hashlib.md5(b"bb").hexdigest(): ([1], binascii.crc32(b"bb"))}
        checksum_type = "SHA1"
        source_blockcount = 2
        source_checksum = hashlib.sha1(b"aabb").digest()
        target_filepath = "some-filename"
        target = b"bbcc\0\0\xff\xff"
        target_fd = BytesStreamReader(target)
        commands = readTargetAndGenPatchCommands(blocksize, checksum_type, source_fd, source_hashtable, source_blockcount, source_checksum, target_filepath, target_fd)

        target_checksum = hashlib.sha1(target).digest()
        self.assertEqual(list(commands),
                         [Header(blocksize, source_blockcount, checksum_type, source_checksum),
                          ('c', binascii.crc32(b"bb"), 1),
                          ('w', b'cc'),  # entry type, target block
                          ('z',),
                          ('o',),
                          ('s',),
                          Footer(target_checksum)])

    def testZeroLengthTarget(self):
        # Create dummy dictionary for source file
        blocksize = 2
        source_fd = BytesStreamReader(b"aabb")
        source_hashtable = {}   # can be empty for tests
        checksum_type = "SHA1"
        source_blockcount = 2
        source_checksum = hashlib.sha1(b"aabb").digest()
        target_filepath = "some-filename"
        target = b""
        target_fd = BytesStreamReader(target)
        commands = readTargetAndGenPatchCommands(blocksize, checksum_type, source_fd, source_hashtable, source_blockcount, source_checksum, target_filepath, target_fd)

        target_checksum = hashlib.sha1(target).digest()
        self.assertEqual(list(commands),
                         [Header(blocksize, source_blockcount, checksum_type, source_checksum),
                          ('s',),
                          Footer(target_checksum)])


class TestWritePatch(unittest.TestCase):
    def testSimple(self):
        # Create command stream for patch file
        entry_stream = [Header(2, 3, "SHA1", b"A" * 20),
                        ('c', 0xAABBCCDD, 1),
                        ('w', b"cc"),
                        ('z',),
                        ('o',),
                        ('s',),
                        Footer(b"B" * 20)]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch_generated = patch_fd.getBuffer()

        # The binary format of the patch looks like
        # Header:
        #         Magic+length                   version   blocksize         source-blockcount   checksum-type
        patch = b"BDIF\x4a\x00\x00\x00" + b"\x01" + b"\x02\x00\x00\x00\x03\x00\x00\x00" + b"\x03"
        #         source checksum + checksum padding
        patch += b"A" * 20 + b"\0" * 44
        #         Container Zero padding
        patch += b"\x00\x00"
        #         Container CRC32 checksum
        patch += b"\x97\xe2\xdc\xc8"
        # Entries:
        #        block-copy                                 block-write zero-write ones-write stop
        patch += b"\x03\xdd\xcc\xbb\xaa\x01\x00\x00\x00" + b"\x04cc" + b"\x02" + b"\x01" + b"\x00"
        # Footer:
        #         Magic           Length
        patch += b"BDIE" + b"\x44\x00\x00\x00"
        #         Commands CRC32 checksum
        patch += b"\xac\xb6\x12\xdd"
        #         Checksum                 Padding
        patch += b"BBBBBBBBBBBBBBBBBBBB" + b"\0" * 44
        #         Container CRC32 checksum
        patch += b"\x06>\xb16"

        self.assertEqual(patch_generated, patch)

    def testSHA512(self):
        # Create command stream for patch file
        entry_stream = [Header(2, 3, "SHA512", b"A" * 64),
                        ('c', 0xAABBCCDD, 1),
                        ('w', b"cc"),
                        ('z',),
                        ('o',),
                        ('s',),
                        Footer(b"B" * 64)]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch_generated = patch_fd.getBuffer()

        # The binary format of the patch looks like
        # Header:
        #         Magic+length                   version   blocksize         source-blockcount   checksum-type
        patch = b"BDIF\x4A\x00\x00\x00" + b"\x01" + b"\x02\x00\x00\x00\x03\x00\x00\x00" + b"\x05"
        #         source checksum
        patch += b"A" * 64
        #         Container Zero padding
        patch += b"\x00\x00"
        #         Container CRC32 checksum
        patch += b"\xa8\xf9\xa1\xfe"
        # Entries:
        #        block-copy                                 block-write zero-write ones-write stop
        patch += b"\x03\xdd\xcc\xbb\xaa\x01\x00\x00\x00" + b"\x04cc" + b"\x02" + b"\x01" + b"\x00"
        # Footer:
        #         Magic           Length
        patch += b"BDIE" + b"\x44\x00\x00\x00"
        #         Commands CRC32 checksum
        patch += b"\xac\xb6\x12\xdd"
        #         Checksum
        patch += b"B" * 64
        #         Container CRC32 checksum
        patch += b"\xd8n\xe5\xb4"

        self.assertEqual(patch_generated, patch)


class TestReadPatch(unittest.TestCase):
    def testInvalidHeaderMagic(self):
        # Create binary Patch file
        # Header:
        #         Magic
        patch = b"BD\xFF\xFF"
        # The rest of the file can be ignored, because the function readPatch  aborts after
        # reading the magci number.

        patch_fd = BytesStreamReader(patch)
        self.assertRaises(InvalidMagic, list, readPatch(patch_fd))

    def testInvalidFooterMagic(self):
        # Create binary Patch file
        # Header:
        #         Magic+length                   version   blocksize         source-blockcount   checksum-type
        patch = b"BDIF\x4a\x00\x00\x00" + b"\x01" + b"\x02\x00\x00\x00\x03\x00\x00\x00" + b"\x03"
        #         source checksum + padding
        patch += b"A" * 20 + b"\0" * 44
        #         Container Zero padding
        patch += b"\x00\x00"
        #         Container CRC32 checksum
        patch += b"\x97\xe2\xdc\xc8"
        # Entries:
        #         stop
        patch += b"\x00"
        # Footer:
        patch += b'BD\xFF\xFF'
        # Function `readPatch` aborts after reading a invalid footer magic. No
        # further bytes are needed.

        patch_fd = BytesStreamReader(patch)
        self.assertRaises(DataCorruption, list, readPatch(patch_fd))

    def testNormal(self):
        # Create binary patch file
        # Header:
        #         Magic+length                   version   blocksize         source-blockcount   checksum-type
        patch = b"BDIF\x4a\x00\x00\x00" + b"\x01" + b"\x02\x00\x00\x00\x03\x00\x00\x00" + b"\x03"
        #         source checksum + padding
        patch += b"A" * 20 + b"\0" * 44
        #         Container Zero padding
        patch += b"\x00\x00"
        #         Container CRC32 checksum
        patch += b"\x97\xe2\xdc\xc8"
        # Entries:
        #        block-copy                                 block-write zero-write ones-write stop
        patch += b"\x03\xdd\xcc\xbb\xaa\x01\x00\x00\x00" + b"\x04cc" + b"\x02" + b"\x01" + b"\x00"
        # Footer:
        #         Magic           Length
        patch += b"BDIE" + b"\x44\x00\x00\x00"
        #         Commands CRC32 checksum
        patch += b"\xac\xb6\x12\xdd"
        #         Checksum
        patch += b"B" * 20 + b"\0" * 44
        #         Container CRC32 checksum
        patch += b"\x06>\xb16"

        patch_fd = BytesStreamReader(patch)

        entries = list(readPatch(patch_fd))
        self.assertEqual(entries, [Header(2, 3, "SHA1", b"A" * 20),
                                   ('c', 0xAABBCCDD, 1),
                                   ('w', b'cc'),
                                   ('z',),
                                   ('o',),
                                   ('s',),
                                   Footer(b"B" * 20)])

    def testInvalidHeaderFormat(self):
        # Create binary Patch file, with correct patch file format version, but
        # incorrect header length for patch file version '1'.
        patch = packContainer(b"BDIF", b"\x01" + b"invalid")

        patch_fd = BytesStreamReader(patch)
        self.assertRaises(FileFormatError, list, readPatch(patch_fd))

    def testInvalidFooterFormat(self):
        # Create binary Patch file
        # Header:
        #         Magic+length                   version   blocksize         source-blockcount   checksum-type
        patch = b"BDIF\x4a\x00\x00\x00" + b"\x01" + b"\x02\x00\x00\x00\x03\x00\x00\x00" + b"\x03"
        #         source checksum + padding
        patch += b"A" * 20 + b"\0" * 44
        #         Container Zero padding
        patch += b"\x00\x00"
        #         Container CRC32 checksum
        patch += b"\x97\xe2\xdc\xc8"
        # Entries:
        #        stop
        patch += b"\x00"
        # Footer:
        #         Magic           Length
        patch += b"BDIE" + b"\x10\x00\x00\x00"
        #         Some payload that triggers the error
        patch += b"not-enough-bytes"
        #         Container Zero padding
        patch += b"\x00\x00\x00\x00"
        #         Container CRC32 checksum
        patch += b"V\xedu\x83"

        patch_fd = BytesStreamReader(patch)
        self.assertRaises(FileFormatError, list, readPatch(patch_fd))

    def testEarlyEOFReached(self):
        # Header:
        #               Magic+length                   version   blocksize         source-blockcount   checksum-type
        patch_header = b"BDIF\x4a\x00\x00\x00" + b"\x01" + b"\x02\x00\x00\x00\x03\x00\x00\x00" + b"\x03"
        #               source checksum + padding
        patch_header += b"A" * 20 + b"\0" * 44
        #               Container Zero padding
        patch_header += b"\x00\x00"
        #               Container CRC32 checksum
        patch_header += b"\x97\xe2\xdc\xc8"

        # Test early EOF in copy entry
        patch = patch_header
        patch += b"\x02" + b"\x03\x02\x00"
        patch_fd = BytesStreamReader(patch)
        self.assertRaises(EarlyEOFReached, list, readPatch(patch_fd))

        # Test early EOF in block-write entry
        patch = patch_header
        patch += b"\x02" + b"\x04"
        patch_fd = BytesStreamReader(patch)
        self.assertRaises(EarlyEOFReached, list, readPatch(patch_fd))

        # Test missing stop entry at the end of the stream
        patch = patch_header
        patch += b"\x02"
        patch_fd = BytesStreamReader(patch)
        self.assertRaises(EarlyEOFReached, list, readPatch(patch_fd))

    def testDataCorruptionExhaustive(self):
        # Create binary patch. Target file will be b"\0\0".
        entry_stream = [Header(2, 0, "SHA1", b"A" * 20),
                        ('z',),
                        ('s',),
                        Footer(b"B" * 20)]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        # Avoid invalidating the first 4 bytes of the patch file. It's the
        # magic number.  A wrong magic number provokes a different exception
        # and exit code.
        for i in range(4, len(patch)):
            # Skipt over length field in header structure. This raises the
            # EarlyEOFReached exception instead of a DataCorruption.
            if i in (4, 5, 6, 7):
                continue

            # Skipt over length field in footer structure. This raises the
            # EarlyEOFReached exception instead of a DataCorruption.
            if i in (94, 95, 96, 97):
                continue

            # Invalidate a single byte in the patch file
            with self.subTest(i=i):
                patch_corrupted = bytearray(patch)
                patch_corrupted[i] = ~patch_corrupted[i] & 0xff  # Just inverse every bit
                patch_corrupted = bytes(patch_corrupted)

                patch_fd = BytesStreamReader(patch_corrupted)
                self.assertRaises(DataCorruption, list, readPatch(patch_fd))

    def testEarlyEOFReachedExhaustive(self):
        # Create binary patch. Target file will be b"\0\0".
        entry_stream = [Header(2, 0, "SHA1", b"A" * 20),
                        ('z',),
                        ('s',),
                        Footer(b"B" * 20)]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        for i in range(len(patch)):
            # Cut the valid patch file in <patch>
            with self.subTest(i=i):
                patch_too_short = patch[:i]

                patch_fd = BytesStreamReader(patch_too_short)
                self.assertRaises(EarlyEOFReached, list, readPatch(patch_fd))

    def testDataCorruptionExhaustive(self):
        # Create binary patch.
        entry_stream = [Header(2, 0, "SHA1", b"A" * 20),
                        ('s',),
                        Footer(b"B" * 20)]

        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        # Add some additional bytes at the end of the binary patch
        patch += b"abc"

        patch_fd = BytesStreamReader(patch)
        self.assertRaises(DataCorruption, list, readPatch(patch_fd, error_on_no_eof=True))

    def testUnsupportedPatchFileVersion(self):
        # Create binary patch file that has the blockdiff magic b"BDIF"
        # but has a different internal version number. The length field does
        # not matter as long it's not zero.
        patch = packContainer(b"BDIF", b"\x02xxxx")

        patch_fd = BytesStreamReader(patch)
        self.assertRaises(UnsupportedFileVersion, list, readPatch(patch_fd))

    def testHeaderEntryOfZeroLength(self):
        # Create binary patch file that has the blockdiff magic b"BDIF"
        # but a header entry of zero length. That's a special case, because
        # the patch file format needs a least a single byte of payload in the header
        # entry containing the version number.
        patch = packContainer(b"BDIF", b"")

        patch_fd = BytesStreamReader(patch)
        self.assertRaises(FileFormatError, list, readPatch(patch_fd))


class TestPatch(TestCaseTempFolder):
    def testNonPatchFile(self):
        dir = join(self.tmpdir, "testNonPatchFile")
        os.makedirs(dir, exist_ok=True)

        with open(join(dir, "source"), "bw") as f:
            f.write(b"")

        # Feed non-patch file (invalid magic) to command `info`.  Function
        # `readPatch` aborts after reading the four bytes to check the magic
        # number.
        patch = b"\0\0\0\0"

        p = Popen([BLOCKDIFF, "patch", "-q", "source", "-", "target"], stdin=PIPE, stderr=PIPE, cwd=dir)
        _, stderr = p.communicate(patch)
        self.assertEqual(p.returncode, 1)
        self.assertIn(b"ERROR: File `-` is not a valid patch file:", stderr)

    def testApplySmallPatch(self):
        dir = join(self.tmpdir, "testApplySmallPatch")
        os.makedirs(dir, exist_ok=True)

        source = b"\0\0aabb"
        with open(join(dir, "source"), "bw") as f:
            f.write(source)

        target = b"\0\0\xff\xffbbcc"

        # Create binary patch file for comparision
        entry_stream = [Header(2, 3, "SHA1", hashlib.sha1(source).digest()),
                        ('z',),
                        ('o',),
                        ('c', binascii.crc32(b"bb"), 2),
                        ('w', b"cc"),
                        ('s',),
                        Footer(hashlib.sha1(target).digest())]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        with open(join(dir, "patch"), "bw") as f:
            f.write(patch)

        p = Popen([BLOCKDIFF, "patch", "-q", "source", "patch", "target"], cwd=dir)
        p.communicate()
        self.assertEqual(p.returncode, 0)

        with open(join(dir, "target"), "br") as f:
            self.assertEqual(f.read(), target)

    def testSHA256Patch(self):
        dir = join(self.tmpdir, "testSHA256Patch")
        os.makedirs(dir, exist_ok=True)

        source = b"\0\0aabb"
        with open(join(dir, "source"), "bw") as f:
            f.write(source)

        target = b"\0\0\xff\xffbbcc"

        # Create binary patch file for comparision
        entry_stream = [Header(2, 3, "SHA256", hashlib.sha256(source).digest()),
                        ('z',),
                        ('o',),
                        ('c', binascii.crc32(b"bb"), 2),
                        ('w', b"cc"),
                        ('s',),
                        Footer(hashlib.sha256(target).digest())]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        with open(join(dir, "patch"), "bw") as f:
            f.write(patch)

        p = Popen([BLOCKDIFF, "patch", "-q", "source", "patch", "target"], cwd=dir)
        p.communicate()
        self.assertEqual(p.returncode, 0)

        with open(join(dir, "target"), "br") as f:
            self.assertEqual(f.read(), target)

    def testPatchIsStdinAndTargetIsStdout(self):
        dir = join(self.tmpdir, "testPatchIsStdinAndTargetIsStdout")
        os.makedirs(dir, exist_ok=True)

        source = b"\0\0aabb"
        with open(join(dir, "source"), "bw") as f:
            f.write(source)
        target = b"\0\0bbcc"

        # Create binary patch file for comparision
        entry_stream = [Header(2, 3, "SHA1", hashlib.sha1(source).digest()),
                        ('z',),
                        ('c', binascii.crc32(b"bb"), 2),
                        ('w', b"cc"),
                        ('s',),
                        Footer(hashlib.sha1(target).digest())]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        p = Popen([BLOCKDIFF, "patch", "-q", "source", "-", "-"], stdin=PIPE, stdout=PIPE, cwd=dir)
        stdout, _ = p.communicate(patch)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(stdout, target)

    def testTargetHasLengthZero(self):
        dir = join(self.tmpdir, "testTargetHasLengthZero")
        os.makedirs(dir, exist_ok=True)

        # Create dummy source file. It's only opened, not read.
        source = b""
        with open(join(dir, "source"), "bw") as f:
            f.write(source)

        target = b""

        # Create binary patch file for comparision
        entry_stream = [Header(2, 3, "SHA1", hashlib.sha1(source).digest()),
                        ('s',),
                        Footer(hashlib.sha1(target).digest())]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        # Before executing `blockdiff` the target file does not exists.
        target_filepath = join(dir, "target")
        self.assertFalse(os.path.exists(target_filepath))

        p = Popen([BLOCKDIFF, "patch", "-q", "source", "-", "target"], stdin=PIPE, cwd=dir)
        stdout, _ = p.communicate(patch)
        self.assertEqual(p.returncode, 0)
        with open(target_filepath, "br") as f:
            self.assertEqual(f.read(), target)  # Target has zero length

    def testTargetChecksumMismatch(self):
        dir = join(self.tmpdir, "testTargetChecksumMismatch")
        os.makedirs(dir, exist_ok=True)

        # Create dummy source file. It's only opened, not read.
        with open(join(dir, "source"), "bw") as f:
            f.write(b"")

        # Create binary patch. Target file will be b"\0\0".
        entry_stream = [Header(2, 0, "SHA1", b"\0" * 20),
                        ('z',),
                        ('s',),
                        Footer(b"\0" * 20)]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        # Execute `blockdiff` with source and patch file. Checksum in footer
        # <b"\0" * 20> does not match the target file.
        p = Popen([BLOCKDIFF, "patch", "source", "-", "-"],
                  stdout=PIPE, stdin=PIPE, stderr=PIPE, cwd=dir)
        _, stderr = p.communicate(patch)
        # Special exit code __EXIT_CODE_TARGET_CHECKSUM_MISMATCH__:
        self.assertEqual(p.returncode, 5)
        self.assertEqual(stderr,
                         b"ERROR: Checksum of generated target file (SHA1: 1489f923c4dca729178b3e3233458550d8dddf29) does not match the original checksum of the target file (SHA1: 0000000000000000000000000000000000000000)!\n")

    def testDataCorruptionInPatchfile(self):
        dir = join(self.tmpdir, "testDataCorruptionInPatchfile")
        os.makedirs(dir, exist_ok=True)

        # Create dummy source file. It's only opened, not read.
        with open(join(dir, "source"), "bw") as f:
            f.write(b"")

        # Create binary patch. Target file will be b"\0\0".
        entry_stream = [Header(2, 0, "SHA1", b"A" * 20),
                        ('z',),
                        ('s',),
                        Footer(b"B" * 20)]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        # Invalidate header CRC32 checksum to force a DataCorruption exception.
        patch = bytearray(patch)
        patch[20] = 0xff

        # Execute `blockdiff` with corrupted patch file.
        p = Popen([BLOCKDIFF, "patch", "source", "-", "-"],
                  stdin=PIPE, stderr=PIPE, cwd=dir)
        _, stderr = p.communicate(patch)
        # Special exit code __EXIT_CODE_PATCH_FILE_DATA_CORRUPTION__:
        self.assertEqual(p.returncode, 6)
        self.assertEqual(stderr,
                         b"ERROR: Invalid CRC32 in header: Expected CRC32 2112325614 (bytes b'\\xee\\x87\\xe7}'). Computed CRC32 447524916 (bytes b'4\\xb0\\xac\\x1a')!\n")

    def testSourceBlockHasInvalidCRC32(self):
        dir = join(self.tmpdir, "testSourceBlockHasInvalidCRC32")
        os.makedirs(dir, exist_ok=True)

        # Create source file. The first and third block in the source file is
        # corrupted, but only the third source block will cause the failure of
        # the patch command.
        with open(join(dir, "source"), "bw") as f:
            f.write(b"axbbcx")

        target = b"bbcc"

        # Create binary patch. Target file will be b"bbcc".
        entry_stream = [Header(2, 3, "SHA1", b"A" * 20),
                        ('c', binascii.crc32(b"bb"), 1),
                        ('c', binascii.crc32(b"cc"), 2),
                        ('s',),
                        Footer(hashlib.sha1(target).digest())]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        # Execute `blockdiff` with source and patch file.
        p = Popen([BLOCKDIFF, "patch", "source", "-", "-"],
                  stdout=PIPE, stdin=PIPE, stderr=PIPE, cwd=dir)
        stdout, stderr = p.communicate(patch)
        # Special exit code __EXIT_CODE_SOURCE_FILE_DATA_CORRUPTION__:
        self.assertEqual(p.returncode, 7)
        self.assertEqual(stderr,
                         b"ERROR: Cannot copy source block 3 to block 2 in target file. Source block CRC32 is 1373098901, expected 3685882489!\n")

    def testNewerPatchFileFormat(self):
        dir = join(self.tmpdir, "testNewerPatchFileFormat")
        os.makedirs(dir, exist_ok=True)

        # Create binary patch file that has the blockdiff magic b"BDIF"
        # but has a different internal version number. The length field does
        # not matter as long it's not zero.
        patch = packContainer(b"BDIF", b"\x03xxxx")

        with open(join(dir, "source"), "bw") as f:
            f.write(b"")

        p = Popen([BLOCKDIFF, "patch", "source", "-", "-"],
                  stdin=PIPE, stderr=PIPE, cwd=dir)
        _, stderr = p.communicate(patch)

        self.assertEqual(p.returncode, 1)
        self.assertEqual(stderr,
                         b"ERROR: Unsupported file format version '3'. Only file version '1' is supported!\n")


class TestInfo(TestCaseTempFolder):
    def testNonPatchFile(self):
        # Feed non-patch file (invalid magic) to command `info`.  Function
        # `readPatch` aborts after reading the four bytes to check the magic
        # number.
        patch = b"\0\0\0\0"

        p = Popen([BLOCKDIFF, "info", "-"], stdin=PIPE, stderr=PIPE)
        _, stderr = p.communicate(patch)
        self.assertEqual(p.returncode, 1)
        self.assertIn(b"ERROR: File `-` is not a valid patch file:", stderr)

    def testMinimal(self):
        # Create binary patch file
        entry_stream = [Header(2, 3, "SHA1", b"\0" * 20),
                        ('z',),
                        ('o',),
                        ('c', binascii.crc32(b"bb"), 2),
                        ('w', b"cc"),
                        ('s',),
                        Footer(b"\0" * 20)]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        # Feed patch file into `blockdiff info`
        p = Popen([BLOCKDIFF, "info", "-"], stdout=PIPE, stdin=PIPE)
        stdout, _ = p.communicate(patch)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(stdout,
b"""blocksize 2 B
source-blocks      3
checksum-type SHA1
source-checksum 0000000000000000000000000000000000000000
target-blocks      4
target-checksum 0000000000000000000000000000000000000000
blocks-zero        1 ( 25.00 %)
blocks-ones        1 ( 25.00 %)
blocks-copy        1 ( 25.00 %)
blocks-new         1 ( 25.00 %)
source-filesize          6 B (    0.0 MiB)
patch-filesize         183 B (    0.0 MiB)
target-filesize          8 B (    0.0 MiB)
Saving -175 B (-2187.50 %) compared to sending the target file.
""")

    def testSHA512(self):
        # Create binary patch file
        entry_stream = [Header(2, 3, "SHA512", b"\x01" * 64),
                        ('z',),
                        ('o',),
                        ('c', binascii.crc32(b"bb"), 2),
                        ('w', b"cc"),
                        ('s',),
                        Footer(b"\x02" * 64)]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        # Feed patch file into `blockdiff info`
        p = Popen([BLOCKDIFF, "info", "-"], stdout=PIPE, stdin=PIPE)
        stdout, _ = p.communicate(patch)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(stdout,
b"""blocksize 2 B
source-blocks      3
checksum-type SHA512
source-checksum 01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101
target-blocks      4
target-checksum 02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202
blocks-zero        1 ( 25.00 %)
blocks-ones        1 ( 25.00 %)
blocks-copy        1 ( 25.00 %)
blocks-new         1 ( 25.00 %)
source-filesize          6 B (    0.0 MiB)
patch-filesize         183 B (    0.0 MiB)
target-filesize          8 B (    0.0 MiB)
Saving -175 B (-2187.50 %) compared to sending the target file.
""")

    def testPatchWithZeroLengthedSource(self):
        # Create binary patch file
        entry_stream = [Header(2, 0, "SHA1", b"\0" * 20),
                        ('z',),
                        ('w', b"aa"),
                        ('s',),
                        Footer(b"\0" * 20)]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        # Feed patch file into `blockdiff info`
        p = Popen([BLOCKDIFF, "info", "-"], stdout=PIPE, stdin=PIPE)
        stdout, _ = p.communicate(patch)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(stdout,
b"""blocksize 2 B
source-blocks      0
checksum-type SHA1
source-checksum 0000000000000000000000000000000000000000
target-blocks      2
target-checksum 0000000000000000000000000000000000000000
blocks-zero        1 ( 50.00 %)
blocks-ones        0 (  0.00 %)
blocks-copy        0 (  0.00 %)
blocks-new         1 ( 50.00 %)
source-filesize          0 B (    0.0 MiB)
patch-filesize         173 B (    0.0 MiB)
target-filesize          4 B (    0.0 MiB)
Saving -169 B (-4225.00 %) compared to sending the target file.
""")

    def testTargetBlockCountIsZero(self):
        dir = join(self.tmpdir, "testTargetBlockCountIsZero")
        os.makedirs(dir, exist_ok=True)

        # Create binary patch file
        patch_filepath = join(dir, "patch")
        with open(patch_filepath, "bw") as patch_fd:
            entry_stream = [Header(2, 3, "SHA1", b"\0" * 20),
                            ('s',),
                            Footer(b"\0" * 20)]
            writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)

        self.assertEqual(os.stat(patch_filepath).st_size, 169)

        # Feed patch file into `blockdiff info`
        p = Popen([BLOCKDIFF, "info", "patch"], stdout=PIPE, cwd=dir)
        stdout, _ = p.communicate()
        self.assertEqual(p.returncode, 0)
        self.assertEqual(stdout,
b"""blocksize 2 B
source-blocks      3
checksum-type SHA1
source-checksum 0000000000000000000000000000000000000000
target-blocks      0
target-checksum 0000000000000000000000000000000000000000
blocks-zero        0 (  0.00 %)
blocks-ones        0 (  0.00 %)
blocks-copy        0 (  0.00 %)
blocks-new         0 (  0.00 %)
source-filesize          6 B (    0.0 MiB)
patch-filesize         169 B (    0.0 MiB)
target-filesize          0 B (    0.0 MiB)
Target file is 0 bytes in size. Not saving anything.
""")

    def testDataCorruptionInPatchfile(self):
        # Create binary patch. Target file will be b"\0\0".
        entry_stream = [Header(2, 0, "SHA1", b"A" * 20),
                        ('z',),
                        ('s',),
                        Footer(b"B" * 20)]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        # Invalidate header CRC32 checksum to force a DataCorruption exception.
        patch = bytearray(patch)
        patch[20] = 0xff

        # Execute `blockdiff` with corrupted patch file.
        p = Popen([BLOCKDIFF, "info", "-"], stdin=PIPE, stderr=PIPE)
        _, stderr = p.communicate(patch)

        # Special exit code __EXIT_CODE_PATCH_FILE_DATA_CORRUPTION__:
        self.assertEqual(p.returncode, 6)
        self.assertEqual(stderr,
                         b"ERROR: Invalid CRC32 in header: Expected CRC32 2112325614 (bytes b'\\xee\\x87\\xe7}'). Computed CRC32 447524916 (bytes b'4\\xb0\\xac\\x1a')!\n")

    def testNoEOFAtEndOfPatchFile(self):
        # Create binary patch. Target file will be b"\0\0".
        entry_stream = [Header(2, 0, "SHA1", b"A" * 20),
                        ('z',),
                        ('s',),
                        Footer(b"B" * 20)]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        # Add additional bytes at end of patch
        patch += b"abc"

        # Execute `blockdiff` with corrupted patch file.
        p = Popen([BLOCKDIFF, "info", "-"], stdin=PIPE, stderr=PIPE)
        _, stderr = p.communicate(patch)

        # Special exit code __EXIT_CODE_PATCH_FILE_DATA_CORRUPTION__:
        self.assertEqual(p.returncode, 6)
        self.assertEqual(stderr,
                         b"ERROR: No EOF after footer entry. Additional bytes at end of patch file!\n")

    def testNewerPatchFileFormat(self):
        # Create binary patch file that has the blockdiff magic b"BDIF"
        # but has a different internal version number. The length field does
        # not matter as long it's not zero.
        patch = packContainer(b"BDIF", b"\x03xxxx")

        # Execute `blockdiff` with corrupted patch file.
        p = Popen([BLOCKDIFF, "info", "-"], stdin=PIPE, stderr=PIPE)
        _, stderr = p.communicate(patch)

        self.assertEqual(p.returncode, 1)
        self.assertEqual(stderr,
                         b"ERROR: Unsupported file format version '3'. Only file version '1' is supported!\n")


class TestDiffAndPatch(TestCaseTempFolder):
    def testCreatePatchAndApplyPatch(self):
        dir = join(self.tmpdir, "testCreatePatchAndApplyPatch")
        os.makedirs(dir, exist_ok=True)

        source = b"\0\0aabb"
        with open(join(dir, "source"), "bw") as f:
            f.write(source)

        target = b"\0\0\xff\xffbbcc"
        with open(join(dir, "target"), "bw") as f:
            f.write(target)

        p = Popen([BLOCKDIFF, "diff", "-q", "--blocksize", "2", "source", "target", "patch"], cwd=dir)
        p.communicate()
        self.assertEqual(p.returncode, 0)

        # Check patch file
        source_checksum = hashlib.sha1(source).digest()
        target_checksum = hashlib.sha1(target).digest()
        entry_stream = [Header(2, 3, "SHA1", source_checksum),
                        ('z',),
                        ('o',),
                        ('c', binascii.crc32(b"bb"), 2),
                        ('w', b"cc"),
                        ('s',),
                        Footer(target_checksum)]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        with open(join(dir, "patch"), "br") as f:
            self.assertEqual(f.read(), patch)

        # Apply patch to file
        p = Popen([BLOCKDIFF, "patch", "-q", "source", "patch", "target.2"], cwd=dir)
        p.communicate()
        self.assertEqual(p.returncode, 0)

        with open(join(dir, "target.2"), "br") as f:
            self.assertEqual(f.read(), b"\0\0\xff\xffbbcc")


class TestDiff(TestCaseTempFolder):
    def testSimpleDiff(self):
        dir = join(self.tmpdir, "testSimpleDiff")
        os.makedirs(dir, exist_ok=True)

        source = b"\0\0aabb"
        with open(join(dir, "source"), "bw") as f:
            f.write(source)
        target = b"\0\0\xff\xffbbcc"
        with open(join(dir, "target"), "bw") as f:
            f.write(target)

        p = Popen([BLOCKDIFF, "diff", "--blocksize=2", "source", "target", "-"], stdout=PIPE, cwd=dir)
        stdout, _ = p.communicate()
        self.assertEqual(p.returncode, 0)

        # Create binary patch file for comparision
        entry_stream = [Header(2, 3, "SHA1", hashlib.sha1(source).digest()),
                        ('z',),
                        ('o',),
                        ('c', binascii.crc32(b"bb"), 2),
                        ('w', b"cc"),
                        ('s',),
                        Footer(hashlib.sha1(target).digest())]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        self.assertEqual(stdout, patch)

    def testCreatePatchForZeroLengthTarget(self):
        dir = join(self.tmpdir, "testCreatePatchForZeroLengthTarget")
        os.makedirs(dir, exist_ok=True)

        source = b"aa"
        with open(join(dir, "source"), "bw") as f:
            f.write(source)
        target = b""
        with open(join(dir, "target"), "bw") as f:
            f.write(target)

        p = Popen([BLOCKDIFF, "diff", "--blocksize=2", "source", "target", "-"],
                  stdout=PIPE, cwd=dir)
        stdout, _ = p.communicate()
        self.assertEqual(p.returncode, 0)

        # Patch for zero length target file should look like
        entry_stream = [Header(2, 1, "SHA1", hashlib.sha1(source).digest()),
                        ('s',),
                        Footer(hashlib.sha1(target).digest())]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        self.assertEqual(stdout, patch)

    def testTargetIsStdinAndPatchIsStdout(self):
        dir = join(self.tmpdir, "testTargetIsStdinAndPatchIsStdout")
        os.makedirs(dir, exist_ok=True)

        source = b"\0\0aabb"
        with open(join(dir, "source"), "bw") as f:
            f.write(source)

        target = b"\0\0bbcc"

        p = Popen([BLOCKDIFF, "diff", "--blocksize=2", "source", "-", "-"], stdin=PIPE, stdout=PIPE, cwd=dir)
        stdout, _ = p.communicate(target)
        self.assertEqual(p.returncode, 0)

        # Create binary patch for comparision
        entry_stream = [Header(2, 3, "SHA1", hashlib.sha1(source).digest()),
                        ('z',),
                        ('c', binascii.crc32(b"bb"), 2),
                        ('w', b"cc"),
                        ('s',),
                        Footer(hashlib.sha1(target).digest())]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        self.assertEqual(stdout, patch)

    def testZeroLengthSource(self):
        dir = join(self.tmpdir, "testZeroLengthSource")
        os.makedirs(dir, exist_ok=True)

        source = b""
        with open(join(dir, "source"), "bw") as f:
            f.write(source)

        target = b"\0\0aa"

        p = Popen([BLOCKDIFF, "diff", "--blocksize=2", "source", "-", "-"], stdin=PIPE, stdout=PIPE, cwd=dir)
        stdout, _ = p.communicate(target)
        self.assertEqual(p.returncode, 0)

        # Create binary patch for comparision
        entry_stream = [Header(2, 0, "SHA1", hashlib.sha1(source).digest()),
                        ('z',),
                        ('w', b"aa"),
                        ('s',),
                        Footer(hashlib.sha1(target).digest())]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        self.assertEqual(stdout, patch)

    def testSourceIsNotBlocksizeAligned(self):
        dir = join(self.tmpdir, "testSourceIsNotBlocksizeAligned")
        os.makedirs(dir, exist_ok=True)

        with open(join(dir, "source"), "bw") as f:
            f.write(b"aab")
        with open(join(dir, "target"), "bw") as f:
            f.write(b"aa")

        p = Popen([BLOCKDIFF, "diff", "--blocksize=2", "source", "target", "-"], stdout=PIPE, stderr=PIPE, cwd=dir)
        _, stderr = p.communicate()
        self.assertEqual(p.returncode, 1)  # Returns '1' for aligment errors. See manpage.
        self.assertIn(b"not block aligned", stderr)
        self.assertIn(b"1 byte(s) left and blocksize is 2 byte", stderr)

    def testInvalidChecksumType(self):
        p = Popen([BLOCKDIFF, "diff", "--checksum-type=INVALID", "source", "-", "-"],
                  stderr=PIPE)
        _, stderr = p.communicate()
        self.assertEqual(p.returncode, 64)  # 64 == EX_USAGE. See /usr/include/sysexits.h
        self.assertIn(b"Value 'INVALID' is not a valid checksum type!", stderr)

    def testChecksumSHA512(self):
        dir = join(self.tmpdir, "testChecksumSHA512")
        os.makedirs(dir, exist_ok=True)

        source = b"bb"
        with open(join(dir, "source"), "bw") as f:
            f.write(source)

        target = b"aabb"

        # Check also short options '-b' and '-c' here.
        p = Popen([BLOCKDIFF, "diff", "-b", "2", "-c", "SHA512", "source", "-", "-"],
                  stdin=PIPE, stdout=PIPE, cwd=dir)
        stdout, _ = p.communicate(target)
        self.assertEqual(p.returncode, 0)

        # Create binary patch for comparision
        entry_stream = [Header(2, 1, "SHA512", hashlib.sha512(source).digest()),
                        ('w', b"aa"),
                        ('c', binascii.crc32(b"bb"), 0),
                        ('s',),
                        Footer(hashlib.sha512(target).digest())]
        patch_fd = BytesStreamWriter()
        writePatch(iter(entry_stream), patch_fd, stdoutAllowed=False)
        patch = patch_fd.getBuffer()

        self.assertEqual(stdout, patch)


class TestStandardArguments(unittest.TestCase):
    def testVersion(self):
        p = Popen([BLOCKDIFF, "--version"], stdout=PIPE)
        stdout, _ = p.communicate()
        self.assertEqual(p.returncode, 0)
        # FIXME add regex to match version number
        self.assertTrue(stdout.startswith(b"blockdiff "))

    def testNoCommand(self):
        p = Popen([BLOCKDIFF], stdout=PIPE)
        stdout, _ = p.communicate()
        self.assertEqual(p.returncode, 64)   # 64 == EX_USAGE. See /usr/include/sysexits.h
        self.assertIn(b"usage: blockdiff", stdout)
        self.assertIn(b"optional arguments:", stdout)
        self.assertIn(b"positional arguments:", stdout)

    def testHelp(self):
        p = Popen([BLOCKDIFF, "--help"], stdout=PIPE)
        stdout, _ = p.communicate()
        # Should be the same behavior 'blockdiff' without a command. See above.
        self.assertEqual(p.returncode, 0)
        self.assertIn(b"usage: blockdiff", stdout)
        self.assertIn(b"optional arguments:", stdout)
        self.assertIn(b"positional arguments:", stdout)


class TestExtInfo(TestCaseTempFolder):
    def _testExtInfo(self, ext_type, s_feature_compat, s_feature_incompat, dir):
        assert ext_type in ("ext2", "ext3", "ext4")

        # Blocksizes greater than 4096 are *evil*:
        #   mke2fs 1.42.13 (17-May-2015)
        #   mkfs.ext4: 8192-byte blocks too big for system (max 4096)
        #   Proceed anyway? (y,n) y
        # FIXME use unittest subtests
        for blocksize in (1024, 2048, 4096):
            # Create sparse file
            # NOTE: Using 'stderr=PIPE' to avoid console output.
            p = Popen(["dd", "if=/dev/zero", "of=img", "conv=sparse", "bs=1M", "count=50"],
                      stderr=PIPE, cwd=dir)
            p.communicate()
            self.assertEqual(p.returncode, 0)

            # Create ext filesystem
            # NOTE: Hardcoding path /sbin/mkfs.ext4, because on my debian
            # system a normal user has the binary not in their 'mkfs.ext4'
            # PATH.
            p = Popen(["/sbin/mkfs.ext4", "-q", "-t", ext_type, "-b%d" % (blocksize,), "img"],
                      cwd=dir)
            p.communicate()
            self.assertEqual(p.returncode, 0)

            # Check s_feature_incompat and s_feature_compat for ext2,3,4
            # filesystems.
            # FIXME This maybe depends on the default system 'mkfs.ext4'
            # settings in '/etc/mke2fs.conf'. The future will show whether this
            # check fails on other systems and distros. Waiting for bug reports
            # :-).
            with open(join(dir, "img"), "br") as f:
                f.seek(1024)
                superblock = f.read(1024)
            ext_superblock = parseExtSuperblock(superblock)
            self.assertEqual(ext_superblock.s_feature_compat, s_feature_compat)
            self.assertEqual(ext_superblock.s_feature_incompat, s_feature_incompat)

            p = Popen([BLOCKDIFF, "extinfo", "img"], stdout=PIPE, cwd=dir)
            stdout, _ = p.communicate()
            self.assertEqual(p.returncode, 0)
            output_correct = "blocksize\t%d\n" % (blocksize,)
            output_correct += "total size\t%d\n" % (50 * 1024 * 1024,)
            self.assertEqual(stdout, output_correct.encode("ascii"))

    def testExt2(self):
        dir = join(self.tmpdir, "testExt2")
        os.makedirs(dir, exist_ok=True)
        self._testExtInfo("ext2", 56, 2, dir)

    def testExt3(self):
        dir = join(self.tmpdir, "testExt3")
        os.makedirs(dir, exist_ok=True)
        self._testExtInfo("ext3", 60, 2, dir)

    def testExt4(self):
        dir = join(self.tmpdir, "testExt4")
        os.makedirs(dir, exist_ok=True)
        self._testExtInfo("ext4", 60, 578, dir)

    def testMagicNotFound(self):
        dir = join(self.tmpdir, "testMagicNotFound")
        os.makedirs(dir, exist_ok=True)

        # Create sparse file
        # NOTE: Using 'stderr=PIPE' to avoid console output.
        p = Popen(["dd", "if=/dev/zero", "of=img", "conv=sparse", "bs=2M", "count=1"],
                  stderr=PIPE, cwd=dir)
        p.communicate()

        p = Popen([BLOCKDIFF, "extinfo", "img"], stderr=PIPE, cwd=dir)
        _, stderr = p.communicate()
        self.assertEqual(p.returncode, 1)
        self.assertIn(b"Magic number", stderr)

    def testUsage(self):
        p = Popen([BLOCKDIFF, "extinfo"], stderr=PIPE)
        _, stderr = p.communicate()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"usage: blockdiff extinfo", stderr)


if __name__ == '__main__':
    unittest.main()
