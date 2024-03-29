#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#   blockdiff - block based binary patch tool
#
#   Copyright (C) 2017 Stefan Lengfeld <stefan@lengfeld.xyz>
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
import struct
import hashlib
import binascii
from argparse import ArgumentParser
from itertools import count
from collections import namedtuple


__VERSION__ = "0.1.y"


__FILE_MAGIC_HEADER__ = b"BDIF"
__FILE_MAGIC_FOOTER__ = b"BDIE"
__FILE_FORMAT_VERSION__ = 1
__FILE_HEADER_PAYLOAD_LENGTH__ = 74
__FILE_FOOTER_PAYLOAD_LENGTH__ = 72


__EXIT_CODE_TARGET_CHECKSUM_MISMATCH__ = 5     # See also `blockdiff.md`
__EXIT_CODE_PATCH_FILE_DATA_CORRUPTION__ = 6   # See also `blockdiff.md`
__EXIT_CODE_SOURCE_FILE_DATA_CORRUPTION__ = 7  # See also `blockdiff.md`


# Nomenclature: The term 'hash-alg' stands for 'hash algorithm' and describes
# the cryptographic one-way hash function. Examples are SHA1 or MD5. The term
# 'digest' is the short form of 'message digest' and is the output of the hash
# function for a given input. It's also called the checksum.

# value 0 is reserved in __hash_algs__
__hash_algs__ = {"MD5": 2,
                 "SHA1": 3,
                 "SHA256": 4,
                 "SHA512": 5}


# Values are in bytes, not bits.
__digest_lenghts__ = {"MD5": 16,
                      "SHA1": 20,
                      "SHA256": 32,
                      "SHA512": 64}


def toHex(b):
    # Note: using binascii.hexlify(), because bytes.hex() is only available
    # since python 3.5.
    return binascii.hexlify(b).decode("ascii")


class NonZeroPadding(Exception):
    pass


class DataCorruption(Exception):
    pass


class InvalidMagic(Exception):
    pass


def readContainer(fd, magic):
    """
     Container format:
          4 bytes          magic  ['B', 'D', '\xdb', '\xf7']
          4 bytes uint32le length of payload. Up to (2^32 - 8 - 4) bytes allowed
          n bytes          payload
        0-7 bytes          of zero padding. End of container must be 8 bytes aligned.
          4 bytes uint32le CRC32

     * Container format can store up to (2^32 - 8 - 4) bytes of payload. Minus
       magic, length and CRC field.
     * Automatic internal padding at end of payload to story the whole container 8
       bytes/64 bits aligned.
     * CRC32 checksum is calculate over all fields (magic, length, payload,
       padding) except the checksum itself.
     * There is no user defined version number in the container format. The
       version schema should be defined by your application.
     * All numbers in the fields (length and CRC32) are stored little endian.
    """
    if not isinstance(magic, bytes):
        raise ValueError("Magic must be of type bytes")
    if len(magic) != 4:
        raise ValueError("Magic must be exactly four bytes long")

    bytes_read = 0

    # Read and check magic number
    magic_in_file = fd.read(4)
    bytes_read += len(magic_in_file)
    if len(magic_in_file) != 4:
        raise EarlyEOFReached("Cannot read four bytes for magic number in file. EOF reached!")

    if magic_in_file != magic:
        raise InvalidMagic("Invalid magic number %s. Expected magic %s!" % (magic_in_file, magic))

    # Read and parse length field
    length_payload_uint32le = fd.read(4)
    bytes_read += len(length_payload_uint32le)
    if len(length_payload_uint32le) != 4:
        raise EarlyEOFReached("Cannot read four bytes for length. EOF reached!")

    length_payload = struct.unpack("<I", length_payload_uint32le)[0]
    assert 0 <= length_payload < 2**32
    # if length_payload:
    #     raise Exception("here")
    # FIXME Add upper bound check

    # Read payload
    payload = fd.read(length_payload)
    bytes_read += len(payload)
    if len(payload) != length_payload:
        raise EarlyEOFReached("tbd")

    # Calculate size of padding
    length_padding = 8 - (length_payload + 4) % 8  # add four bytes to payload length for CRC32 field
    if length_padding == 8:
        length_padding = 0
    assert 0 <= length_padding < 8
    assert (length_payload + length_padding + 4) % 8 == 0

    # Read padding
    if length_padding != 0:
        padding = fd.read(length_padding)
        bytes_read += len(padding)
        if len(padding) != length_padding:
            raise EarlyEOFReached("Cannot read %d byte(s) of padding" % (length_padding,))
    else:
        padding = b""

    # Read CRC32
    crc32_in_file_uint32le = fd.read(4)
    bytes_read += len(crc32_in_file_uint32le)
    if len(crc32_in_file_uint32le) != 4:
        raise EarlyEOFReached("tbd")

    crc32_in_file = struct.unpack("<I", crc32_in_file_uint32le)[0]
    assert 0 <= crc32_in_file < 2**32

    magic_legnth_payload_padding_in_file = magic_in_file + length_payload_uint32le + payload + padding
    assert len(magic_legnth_payload_padding_in_file) == 8 + length_payload + length_padding

    crc32 = binascii.crc32(magic_legnth_payload_padding_in_file)
    assert isinstance(crc32, int)
    assert 0 <= crc32 < 2**32

    if crc32 != crc32_in_file:
        raise DataCorruption("Expected CRC32 %d (bytes %s). Computed CRC32 %d (bytes %s)!" %
                             (crc32_in_file,
                              struct.pack("<I", crc32_in_file),
                              crc32,
                              struct.pack("<I", crc32)))

    # The padding bytes are checked after the CRC32 of the whole container is
    # checked.
    if any(byte != 0 for byte in padding):
        raise NonZeroPadding("Non zero padding bytes in padding: %s" % (padding,))

    return payload, bytes_read


def packContainer(magic, payload):
    if not isinstance(magic, bytes):
        raise ValueError("Magic must be of type bytes")
    if len(magic) != 4:
        raise ValueError("Magic must be exactly four bytes long")

    length_payload = len(payload)
    if length_payload > (2**32 - 8 - 4):
        raise ValueError("Payload is too long. %d bytes cannot be stored in the container format!" % (length_payload,))

    # Create length field as bytes
    length_payload_uint32le = struct.pack("<I", length_payload)
    assert len(length_payload_uint32le) == 4

    # Calculate size of padding
    length_padding = 8 - ((length_payload + 4) % 8)  # add four bytes to payload length for CRC32 field
    if length_padding == 8:
        length_padding = 0
    assert 0 <= length_padding < 8
    assert (length_payload + length_padding + 4) % 8 == 0
    padding = b"\0" * length_padding

    # Calculate CRC32 of magic, length, payload and padding
    magic_length_payload_padding = magic + length_payload_uint32le + payload + padding
    crc32 = binascii.crc32(magic_length_payload_padding)
    crc32_uint32le = struct.pack("<I", crc32)

    container = magic + length_payload_uint32le + payload + padding + crc32_uint32le

    return container


class AligmentError(Exception):
    pass


def readSource(filename, blocksize, hash_alg, quiet=True):
    block_zero = bytes([0] * blocksize)
    assert len(block_zero) == blocksize

    block_ones = bytes([0xff] * blocksize)
    assert len(block_ones) == blocksize

    source_hashtable = {}

    if not quiet:
        print("Reading source '%s':" % (filename,), file=sys.stderr)

    # Using 's.stat(filename).st_size' does not work for block devices.
    with open(filename, "br") as f:
        source_filesize = f.seek(0, 2)

    if source_filesize % blocksize != 0:
        raise AligmentError("Source file '%s' is not block aligned. %d byte(s) left and blocksize is %d byte(s)!" % (filename, source_filesize % blocksize, blocksize))

    source_checksum_m = getChecksumGenerator(hash_alg)

    percent_lasttime = None   # Speed optimization for statusbar

    with open(filename, "br") as f:
        for i in count():
            block = f.read(blocksize)
            if len(block) == 0:
                break  # EOF reached

            # Feed block to hashlib checksum generator
            source_checksum_m.update(block)

            if len(block) != blocksize:
                # Should be already catched above, when the size of the source
                # file has not changed in the meantime.
                raise AligmentError("Source file is not block aligned")

            if block == block_zero or block == block_ones:
                # Ignore zero blocks and all one blocks in the source file. Do
                # not store them in the hashtable. The patch file format has an
                # extra command_type to write a zero/ones block into the target
                # file.
                #
                # Since zero blocks (and ones blocks) are so common, this also
                # saves memory in the hashtable.
                pass
            else:
                block_md5sum = hashlib.md5(block).hexdigest()

                try:
                    block_indices, source_block_crc32 = source_hashtable[block_md5sum]
                    if len(block_indices) >= 3:
                        # Don't save multiple blocks, because the patch file
                        # generator uses at most one to three different copies.
                        # For now it uses only one copy.
                        pass
                    else:
                        block_indices.append(i)  # Updates list *in-place*
                except KeyError:
                    source_block_crc32 = binascii.crc32(block)
                    source_hashtable[block_md5sum] = ([i], source_block_crc32)

            # Only show progress bar when stderr is a tty.
            if not quiet and sys.stderr.isatty():
                LENGTH = 50
                # Using (i + 1), so the last iteration is 100%.
                percent = (100 * blocksize * (i + 1)) // source_filesize

                # Speed optimization. Only update the statusbar when the
                # percent value has really hanged. Doing a write operation to
                # stdout every iteration slows done the program by a couple of
                # seconds.
                if percent != percent_lasttime:
                    print("|" + "-" * (percent // 2) + " " * (LENGTH - percent // 2) + "| (%3d %%)\r" % (percent,),
                          end="",
                          file=sys.stderr)
                    percent_lasttime = percent

        source_blockcount = i

    if not quiet and sys.stderr.isatty():
        print("", file=sys.stderr)

    source_checksum = source_checksum_m.digest()

    return source_hashtable, source_blockcount, source_checksum


def getChecksumGenerator(hash_alg):
    if hash_alg == "MD5":
        checksum_m = hashlib.md5()
    elif hash_alg == "SHA1":
        checksum_m = hashlib.sha1()
    elif hash_alg == "SHA256":
        checksum_m = hashlib.sha256()
    elif hash_alg == "SHA512":
        checksum_m = hashlib.sha512()
    else:
        raise ValueError("Checksum-type '%s' unknown!" % (hash_alg,))

    return checksum_m


def readTargetAndGenPatchCommands(blocksize, hash_alg, source_fd, source_hashtable, source_blockcount, source_checksum, target, target_fd, quiet=True):
    """ returns a entry generator object. First, last element and the element
        before the last element are special:
           [Header, command(type=!stop)*, command(type=stop), Footer]
    """
    block_zero = bytes([0] * blocksize)
    assert len(block_zero) == blocksize

    block_ones = bytes([0xff] * blocksize)
    assert len(block_ones) == blocksize

    blocks_zero = 0
    blocks_ones = 0
    blocks_copy = 0
    blocks_new = 0
    blocks_count = 0

    target_checksum_m = getChecksumGenerator(hash_alg)

    yield Header(blocksize, source_blockcount, hash_alg, source_checksum)

    if not quiet:
        print("Reading target '%s' and writing patch. Block statistics:" %
              (target,),
              file=sys.stderr)

    def printStat(blocks_count, blocks_zero, blocks_ones, blocks_copy, blocks_new):
        assert blocks_count != 0
        # NOTE: Percentage values and output format should be the nearly
        # the same as for command "info".
        print("%10d (%6.02f %%) zero   %10d (%6.02f %%) ones  %10d (%6.02f %%) copyable  %10d (%6.02f %%) new\r" %
              (blocks_zero, blocks_zero * 100 / blocks_count,
               blocks_ones, blocks_ones * 100 / blocks_count,
               blocks_copy, blocks_copy * 100 / blocks_count,
               blocks_new, blocks_new * 100 / blocks_count),
              end="",
              file=sys.stderr)

    for i in count():
        # FIXME Add code to read exactly a byte buffer of size 'blocksize'. Not
        # less.
        block = target_fd.read(blocksize)
        if len(block) == 0:
            break  # EOF reached

        if len(block) != blocksize:
            raise Exception("Target file is not block aligned. Some bytes left at the end")

        # Feed block to hashlib checksum generator for checksum in footer
        target_checksum_m.update(block)

        md5sum = hashlib.md5(block).hexdigest()

        # Decided with patch command to emit
        if block == block_zero:
            yield ("z",)
            blocks_zero += 1
        elif block == block_ones:
            yield ("o",)
            blocks_ones += 1
        elif md5sum in source_hashtable:
            # NOTE: Selection of source block should be deterministic
            block_indices, source_block_crc32 = source_hashtable[md5sum]
            source_block_index = block_indices[0]  # just take the first element

            # FIXME read source block <source_block_index> and verify that it's identical
            # to the target block in <block>. Paranoid guy: don't rely on the checksum.

            yield ("c", source_block_crc32, source_block_index)
            blocks_copy += 1
        else:
            yield ("w", block)
            blocks_new += 1

        blocks_count = i + 1

        # Only update states when stderr is a tty.
        if not quiet and sys.stderr.isatty():
            # Update the statistic every 1000 iteration to avoid stderr write
            # calls.  A 2 GiB ext4 disk images has 524288 blocks by a blocksize
            # of 4KiB, so there are 524 statistic updates while reading the
            # target file.
            if (i + 1) % 1000 == 0:
                printStat(blocks_count, blocks_zero, blocks_ones, blocks_copy, blocks_new)

    # After the loop print the statistics a last time, because the loop does
    # not update the statistic every iteration. Also update the stats when
    # stderr is not a tty. This way it appears in a log file.
    if not quiet:
        if blocks_count >= 1:
            printStat(blocks_count, blocks_zero, blocks_ones, blocks_copy, blocks_new)
            # Print a newline character, because printStat() does not do it.
            print("", file=sys.stderr)

    yield ("s",)  # Emit command(type=stop)

    target_checksum = target_checksum_m.digest()

    if not quiet:
        print("%s checksum of target file: %s" %
              (hash_alg, toHex(target_checksum)),
              file=sys.stderr)

    yield Footer(target_checksum)


class Header():
    def __init__(self, blocksize, source_blockcount, hash_alg, source_checksum):
        assert isinstance(source_checksum, bytes)
        assert isinstance(hash_alg, str)
        # FIXME add file size limitations
        self._blocksize = blocksize
        self._source_blockcount = source_blockcount

        if hash_alg not in __digest_lenghts__.keys():
            raise ValueError("Hash algorithm '%s' not supported!." % (hash_alg,))
        self._hash_alg = hash_alg

        digest_length = __digest_lenghts__[hash_alg]
        if len(source_checksum) != digest_length:
            raise ValueError("Checksum '%s' is not %d bytes long!" % (source_checksum, digest_length))
        self._source_checksum = source_checksum

    def getBlocksize(self):
        return self._blocksize

    def getSourceBlockCount(self):
        return self._source_blockcount

    def getHashAlgorithm(self):
        return self._hash_alg

    def getSourceChecksum(self):
        return self._source_checksum

    # Only used in unittests
    def __eq__(self, y):
        if not isinstance(y, self.__class__):
            return False

        return self._blocksize == y._blocksize and \
            self._source_blockcount == y._source_blockcount and \
            self._hash_alg == y._hash_alg and \
            self._source_checksum == y._source_checksum

    # Only used in unittests
    def __repr__(self):
        return "Header(%s, %s, %s, %s)" % (self._blocksize,
                                           self._source_blockcount,
                                           self._hash_alg,
                                           self._source_checksum)


# NOTE: This class has no 1to1 relation to the on disk footer structure.  The
# footer structure contains additional fields like the target block count and
# the command entries CRC32. The class is a program internal structure to carry
# only non redundant information and without any data corruptions checksums,
# because it's already verified while reading.
class Footer():
    def __init__(self, target_checksum):
        assert isinstance(target_checksum, bytes)
        self._target_checksum = target_checksum

    def getTargetChecksum(self):
        return self._target_checksum

    # Only used in unittests
    def __eq__(self, y):
        if not isinstance(y, self.__class__):
            return False

        return self._target_checksum == y._target_checksum

    # Only used in unittests
    def __repr__(self):
        return "Footer(%s)" % (self._target_checksum,)


def writePatch(entry_stream, patch_fd):
    """
    Consumes an entry generator object (e.g. by function
    readTargetAndGenPatchCommands()), encodes it, add writes it to the patch
    file in <patch_fd>.

    The binary patch format consists of different types of entries placed into
    the file behind each other:

         [header(magic=BDIF), command(type=!stop)*, command(type=stop), footer(magic=BDIE)]

    Every entry exists exactly once except the entries command(type=!stop). For
    every block in the target file there is an entry containing the patch
    instruction. Whether it should be copied from the source file, written from
    patch payload or is a full zero or one block.

    The internal fields of header, command and footer are described here:

    Header (wrapped in a container, magic='BDIF'):
      - u8 version (1: standard)
      - u8 hash algorithm (see above)
      - u32le blocksize
      - u32le source block count (not all inputs are really required)
           Putting the target block count in the header is impossible, because
           the 'target' file in the command 'patch' is written as a stream.
      - u8[64] checksum of source file by hash algorithm
            For MD5 only the first 16 bytes are used. The rest is set to zero.
            ...
            For SHA512 the full 64 bytes are used.

    Commands:
      - u8 type (0: stop, 1: ones, 2: zero, 3: copy, 4: new)
      payload:
         for 0=stop: no payload
         for 1=ones: no payload
         for 2=zero: no payload
         for 3=copy:
             - u32le CRC32 of source block
             - u32le source block index
         for 4=new:
             - u8[<BLOCKSIZE>] bytes of target block

    Footer (wrapped in a container, magic='BDIE'):
      - u32le target block count
         Infact this is redundant information. In the patch file format the
         count of command entries (without the special entry(type=stop) is equal
         to the target block count. But storing the target block count
         information in the footer explicitly, allows 'blockdiff info --fast' to
         print more information without traverse the whole patch file.
      - u32le CRC32 of command entries
      - u8[64] checksum[T] of target file
            For MD5 only the first 16 bytes are used. The rest is set to zero.
            ....
            For SHA512 the full 64 bytes are used.
         (This is located at the end of the file. This way the patch-file must
         only be traversed once. No seeking to the start of the file required)
    """

    header = next(entry_stream)
    assert isinstance(header, Header)

    blocksize = header.getBlocksize()
    source_blockcount = header.getSourceBlockCount()
    hash_alg = header.getHashAlgorithm()
    source_checksum = header.getSourceChecksum()

    patch_file_version = __FILE_FORMAT_VERSION__
    hash_alg_number = __hash_algs__[hash_alg]

    assert 0 <= patch_file_version < 256
    assert 0 <= blocksize < 2 ** 32
    assert 0 <= source_blockcount < 2 ** 32
    assert 0 <= hash_alg_number < 256
    header_payload = struct.pack("<BIIB",
                                 patch_file_version,
                                 blocksize,
                                 source_blockcount,
                                 hash_alg_number)
    header_payload += source_checksum
    source_checksum_padding = b"\0" * (64 - len(source_checksum))
    header_payload += source_checksum_padding

    # Header payload is always 74 bytes long
    assert len(header_payload) == __FILE_HEADER_PAYLOAD_LENGTH__

    container_header = packContainer(__FILE_MAGIC_HEADER__, header_payload)
    patch_fd.write(container_header)

    commands_crc32 = 0  # Initial value for CRC32

    for i, command in enumerate(entry_stream, 1):
        if command[0] == "z":
            entry = b"\x02"
        elif command[0] == "o":
            entry = b"\x01"
        elif command[0] == "c":
            _, source_block_crc32, source_block_index = command

            if not (0 <= source_block_index < 2**32):
                raise Exception("Block number %d does not fit in 16 bits" % (source_block_index,))

            # Using '<' enforces little endian and standard sizes
            entry = b"\x03"
            entry += struct.pack("<II", source_block_crc32, source_block_index)
        elif command[0] == "w":
            _, block = command

            entry = b"\x04" + block
        elif command[0] == "s":
            # Read stop command. End of command stream reached.
            entry = b"\x00"  # Write Command(type=stop)
        else:
            raise Exception("Never reached")

        patch_fd.write(entry)
        commands_crc32 = binascii.crc32(entry, commands_crc32)

        if entry == b"\x00":
            assert command[0] == "s"
            break  # Stop Command reached and stop command written

    target_blockcount = i - 1  # Reduce block count because stop entry becomes no target block!

    footer = next(entry_stream)
    assert isinstance(footer, Footer)

    target_checksum = footer.getTargetChecksum()

    assert 0 <= target_blockcount < 2**64

    footer_payload = struct.pack("<II",
                                 target_blockcount,
                                 commands_crc32)
    footer_payload += target_checksum
    target_checksum_padding = b"\0" * (64 - len(target_checksum))
    footer_payload += target_checksum_padding

    # Footer payload is always 72 bytes long.
    assert len(footer_payload) == __FILE_FOOTER_PAYLOAD_LENGTH__

    container_footer = packContainer(__FILE_MAGIC_FOOTER__, footer_payload)
    patch_fd.write(container_footer)

    return 0


def diff(args, parser):
    source = args.source
    target = args.target
    patch = args.patch  # FIXME rename, because it has the same name as the function
    blocksize = args.blocksize
    hash_alg = args.hash_alg
    quiet = args.quiet

    # Sanitize hash_alg value from user
    hash_alg = hash_alg.upper()
    if hash_alg not in __hash_algs__.keys():
        print("ERROR: Value '%s' is not a valid hash algorithm!" %
              (hash_alg,),
              file=sys.stderr)
        return 64   # EX_USAGE. See /usr/include/sysexits.h

    # Phase One: Read source file and generate checksum hashtable
    try:
        source_hashtable, source_blockcount, source_checksum = readSource(source, blocksize, hash_alg, quiet=quiet)
    except AligmentError as e:
        print("ERROR:", e, file=sys.stderr)
        return 1

    if not quiet:
        print("%s checksum of source file: %s" %
              (hash_alg, toHex(source_checksum)),
              file=sys.stderr)

    # Phase Two: Generate and write patch
    if target != "-":
        # FIXME Catch exceptions
        target_fd = open(target, "br")
    else:
        target_fd = sys.stdin.buffer

    if patch != "-":
        # FIXME Catch exceptions
        patch_fd = open(patch, "bw")  # Truncates existing files
    else:
        patch_fd = sys.stdout.buffer

    # Start writing patch file
    with open(source, "br") as source_fd:
        entry_stream = readTargetAndGenPatchCommands(blocksize, hash_alg, source_fd, source_hashtable, source_blockcount, source_checksum, target, target_fd, quiet=quiet)

        # File `source` still needs to be opened while generating the patch
        # file. Some blocks are reread.
        writePatch(entry_stream, patch_fd)

    if target != "-":
        target_fd.close()

    if patch != "-":
        patch_fd.close()

    return 0


class EarlyEOFReached(Exception):
    pass


class FileFormatError(Exception):
    pass


class NotSeekable(Exception):
    pass


class UnsupportedFileVersion(Exception):
    pass


def readPatch(patch_fd, additional_return_values=[], error_on_no_eof=False, skip_command_entries=False):
    """Returns an entry generator. The argument <patch_fd> can be a file or stream.

    If flag <skip_command_entries> is false, which is the default, the generator
    returns the entries:

        [header, command(type=!stop)*, command(type=stop), footer]

    If flag <skip_command_entries> is true, the function skips the command
    entries and only returns the header and footer. The <patch_fd> must be
    seekable in that case. The entries in the generator look like

        [header, footer]

    Raises exceptions:
        - InvalidMagic when file <patch_fd> is not a patch file
        - DataCorruption when the patch file is corrupted
        - DataCorruption when <error_on_no_eof> is true and file/stream in
          <patch_fd> contains bytes after the footer entry.
        - UnsupportedFileVersion if the patch file format in <patch_fd> is
          not equal to '1'. Other and newer formats are not supported.
        - NotSeekable when skip_command_entries is true, but the file
          descriptor in <patch_fd> is not seekable.
    """

    # Accumulate every bytes that this function reads from <patch_fd>.
    patch_bytes_read = 0

    # Function readContainer() raises InvalidMagic when the magic numbers was
    # not found.
    try:
        header_payload, bytes_read = readContainer(patch_fd, __FILE_MAGIC_HEADER__)
        patch_bytes_read += bytes_read
    except DataCorruption as e:
        raise DataCorruption("Invalid CRC32 in header: %s" % (e,))

    if not len(header_payload) >= 1:
        raise FileFormatError("Header entry does not contain patch format version information. Invalid patch file!")

    patch_file_version = header_payload[0]   # :: int
    if patch_file_version != __FILE_FORMAT_VERSION__:
        raise UnsupportedFileVersion("Unsupported file format version '%d'. Only file version '%d' is supported!" %
                                     (patch_file_version, __FILE_FORMAT_VERSION__))

    # After checking the patch file format version, check the length to match
    # format expectation.
    if len(header_payload) != __FILE_HEADER_PAYLOAD_LENGTH__:
        raise FileFormatError("Header payload must be %d bytes long!" % (__FILE_HEADER_PAYLOAD_LENGTH__,))

    header_payload_fixed_entries = header_payload[:10]
    header_payload_checksum = header_payload[10:]

    x = struct.unpack("<BIIB", header_payload_fixed_entries)
    # Ignore the file version number here, because it's already checked above.
    blocksize = x[1]
    source_blockcount = x[2]
    hash_alg_number = x[3]

    if hash_alg_number not in __hash_algs__.values():
        raise FileFormatError("tbd")
    else:
        # HACKY
        hash_alg = None
        for key, value in __hash_algs__.items():
            if value == hash_alg_number:
                hash_alg = key
        assert hash_alg in __digest_lenghts__

    digest_length = __digest_lenghts__[hash_alg]
    source_checksum = header_payload_checksum[:digest_length]

    source_checksum_padding = header_payload_checksum[digest_length:]
    if not all(i == 0 for i in source_checksum_padding):
        raise FileFormatError("Source checksums padding is not zero: %s!" % (source_checksum_padding,))

    yield Header(blocksize, source_blockcount, hash_alg, source_checksum)

    if skip_command_entries is False:
        commands_crc32 = 0  # Initial value for CRC32
        target_blockcount_from_commands = 0
        while True:
            # Reading commands entries until the stop command is reached. A priori
            # the code/format does not know how many commands the patch file
            # contains.
            command_type = patch_fd.read(1)
            patch_bytes_read += len(command_type)
            commands_crc32 = binascii.crc32(command_type, commands_crc32)

            if len(command_type) == 0:
                raise EarlyEOFReached("Cannot read next command. No stop command found.")

            if command_type == b"\x00":
                yield ('s',)  # emit command(type=stop)
                break  # Stop reading command entries
            elif command_type == b"\x02":
                yield ('z',)  # write zero block
            elif command_type == b"\x01":
                yield ('o',)  # write ones block
            elif command_type == b"\x03":
                # Copy block
                source_block_encoded = patch_fd.read(8)
                patch_bytes_read += len(source_block_encoded)
                commands_crc32 = binascii.crc32(source_block_encoded, commands_crc32)

                if len(source_block_encoded) != 8:
                    raise EarlyEOFReached("Cannot read source block information in command(type=copy).")

                source_block_crc32, source_block_index = struct.unpack("<II",
                                                                       source_block_encoded)

                if not 0 <= source_block_index < source_blockcount:
                    raise DataCorruption("Source block index %d in command(type=copy) corrupted. Source file has only %d block(s)!" %
                                         (source_block_index, source_blockcount))

                yield ('c', source_block_crc32, source_block_index)
            elif command_type == b"\x04":
                # New block
                block = patch_fd.read(blocksize)
                patch_bytes_read += len(block)
                commands_crc32 = binascii.crc32(block, commands_crc32)
                if len(block) != blocksize:
                    raise EarlyEOFReached("Cannot block data in command(type=write).")

                yield ('w', block)
            else:
                # An unknown command type is also some sort of data corruption.
                # Maybe caused by a single bitflip in the patch file.
                # Nevertheless an invalid command type byte is detected by the
                # command CRC32 checksum stored in the footer structure, too.
                raise DataCorruption("Unkown command type: %s" % (command_type,))

            target_blockcount_from_commands += 1
    else:
        # Skip command entries in the patch file format after reading the
        # header structure. File in <patch_fd> must be seekable. Otherwise it's
        # impossible to know at which location the footer structure is located
        # in the patch file format, because the command entries are of variable
        # byte lengths.
        #
        # This code uses the external information source, the file's length, to
        # avoid traverse the command entries in the patch file.

        # NOTE: Violating the 'It's better to ask for forgiveness than for
        # permission'-Rule here.
        if patch_fd.seekable():
            # 16 bytes of container metadata, 72 bytes of footer structure payload.
            #
            # FIXME add function to calculate the size of the containter for a
            # given payload length and replace the magic constant '16' here.
            pos = patch_fd.seek(-(16 + __FILE_FOOTER_PAYLOAD_LENGTH__), 2)
        else:
            raise NotSeekable("The patch file is not seekable!")

        # Adapt the counter <bytes_read>. For files it's equal to the absolute
        # file position. Since we skip reading bytes here, advance the
        # bytes_read counter virtually, so the patch file size calculation does
        # not become out of sync. It must return the same value as in the
        # <skip_command_entries> is false case.
        #
        # FIXME This only works reliable, when the file position of <patch_fd>
        # was zero at the start of the function call.
        assert pos > bytes_read
        patch_bytes_read = pos

    # Read footer structure
    try:
        footer_payload, bytes_read = readContainer(patch_fd, __FILE_MAGIC_FOOTER__)
        patch_bytes_read += bytes_read
    except InvalidMagic:
        # Do not raise InvalidMagic magic for the footer structure. The
        # function should only raises InvalidMagic for the header structure. A invalid
        # footer structure is just a normal data corruption error in the file.
        # FIXME add read and expected bytes in message
        raise DataCorruption("Invalid magic number in footer. Corrupted file?")
    except DataCorruption as e:
        raise DataCorruption("Invalid CRC32 in footer: %s" % (e,))

    if len(footer_payload) != __FILE_FOOTER_PAYLOAD_LENGTH__:
        raise FileFormatError("Footer payload must be %d bytes long!" % (__FILE_FOOTER_PAYLOAD_LENGTH__,))

    digest_length = __digest_lenghts__[hash_alg]

    target_blockcount_in_file, commands_crc32_in_file = struct.unpack("<II", footer_payload[:8])
    target_checksum = footer_payload[8:8 + digest_length]
    target_checksum_padding = footer_payload[8 + digest_length:]

    if not all(i == 0 for i in target_checksum_padding):
        raise FileFormatError("Target checkums padding is not zero: %s!" % (target_checksum_padding,))

    if not skip_command_entries:
        # Check CRC32 of command entries, when the above code as read them.
        if commands_crc32_in_file != commands_crc32:
            raise DataCorruption("Corrupted bytes in the command stream. Computed CRC32 is %d (bytes %s). Expected CRC32 is %d (bytes %s)!" %
                                 (commands_crc32,
                                  struct.pack("<I", commands_crc32),
                                  commands_crc32_in_file,
                                  struct.pack("<I", commands_crc32_in_file)))

        # Verify redundant information: Compare the count of commands - without
        # the command(type=stop) - in the patch file with the stored 'target
        # block count' in the footer structure.
        if target_blockcount_in_file != target_blockcount_from_commands:
            # Note: Using the exception DataCorruption would be wrong here. If
            # the block count in the footer structure is wrong, it cannot be
            # caused by a bitflip error, because the command entries and the
            # footer structure is already checked by CRC32. A evil user has
            # created a patch file with a wrong target block count.
            raise FileFormatError("Target block count in footer (=%d blocks) is not equal to count of commands(type!=stop) (=%d blocks)!" %
                                  (target_blockcount_in_file,
                                   target_blockcount_from_commands))

    target_blockcount = target_blockcount_in_file

    # Must be before the last yield statement. Otherwise consumer never reaches
    # the code.
    if error_on_no_eof:
        after_footer = patch_fd.read(1)
        if len(after_footer) != 0:
            raise DataCorruption("No EOF after footer entry. Additional bytes at end of patch file!")

    # HACKY HACK: Using mutable list object for by-reference  semantics to
    # return additional information after the generator has finished.
    additional_return_values.clear()
    #
    # At the end of the function the count of bytes, which are read,
    # correspond to the patch file.
    additional_return_values.append(patch_bytes_read)
    additional_return_values.append(target_blockcount)

    yield Footer(target_checksum)


def applyPatch(source_fd, patch_fd, target_fd, quiet=True):
    entry_stream = readPatch(patch_fd)

    header = next(entry_stream)
    assert isinstance(header, Header)
    blocksize = header.getBlocksize()
    source_blockcount = header.getSourceBlockCount()
    hash_alg = header.getHashAlgorithm()

    target_checksum_m = getChecksumGenerator(hash_alg)

    block_zero = b"\0" * blocksize
    assert len(block_zero) == blocksize

    block_ones = b"\xff" * blocksize
    assert len(block_ones) == blocksize

    for i, command in enumerate(entry_stream):
        if command[0] == 's':
            # Read command(type=stop)
            break
        elif command[0] == 'z':
            block = block_zero  # write zero block
        elif command[0] == 'o':
            block = block_ones  # write ones block
        elif command[0] == 'c':
            # Copy block from source
            _, source_block_crc32, source_block_index = command

            source_fd.seek(source_block_index * blocksize)
            block = source_fd.read(blocksize)
            # FIXME Check read size

            block_crc32_from_file = binascii.crc32(block)
            if block_crc32_from_file != source_block_crc32:
                print("ERROR: Cannot copy source block %d to block %d in target file. Source block CRC32 is %d, expected %d!" %
                      (source_block_index + 1,
                       i + 1,
                       block_crc32_from_file,
                       source_block_crc32),
                      file=sys.stderr)

                ret = __EXIT_CODE_SOURCE_FILE_DATA_CORRUPTION__
                return ret
        elif command[0] == 'w':
            # New block in target file. Write data from patch file.
            _, block = command
            assert len(block) == blocksize
        else:
            raise Exception("Unknown command: %s" % (command[0],))

        # Feed block to hashlib checksum generator
        target_checksum_m.update(block)

        target_fd.write(block)

    footer = next(entry_stream)
    assert isinstance(footer, Footer)

    # Verify that Footer structure is really the last element in the entry
    # stream generator.
    try:
        next(entry_stream)
        raise ValueError("Entry stream generator does not end after footer entry!")
    except StopIteration:
        pass

    # Get checksum of target file
    target_checksum = target_checksum_m.digest()

    if target_checksum != footer.getTargetChecksum():
        print("ERROR: Checksum of generated target file (%s: %s) does not match the original checksum of the target file (%s: %s)!" %
              (hash_alg,
               toHex(target_checksum),
               hash_alg,
               toHex(footer.getTargetChecksum())),
              file=sys.stderr)
        ret = __EXIT_CODE_TARGET_CHECKSUM_MISMATCH__
    else:
        ret = 0

    if not quiet:
        print("%s Checksum of target file: %s" %
              (hash_alg, toHex(target_checksum)),
              file=sys.stderr)

    return ret


def patch(args, parser):
    source = args.source
    patch = args.patch  # FIXME rename, because it has the same name as the function
    target = args.target
    quiet = args.quiet

    if patch != "-":
        patch_fd = open(patch, "br")
    else:
        patch_fd = sys.stdin.buffer

    if target != "-":
        target_fd = open(target, "bw")
    else:
        target_fd = sys.stdout.buffer

    if not quiet:
        print("Writing target '%s':" % (target,), file=sys.stderr)

    # Source opened and must be seekable, but maybe not used at all.
    try:
        with open(source, "br") as source_fd:
            ret = applyPatch(source_fd, patch_fd, target_fd, quiet=quiet)
    except InvalidMagic as e:
        print("ERROR: File `%s` is not a valid patch file: %s"
              % (patch, e),
              file=sys.stderr)
        ret = 1
    except DataCorruption as e:
        print("ERROR: %s" % (e,), file=sys.stderr)
        ret = __EXIT_CODE_PATCH_FILE_DATA_CORRUPTION__
    except UnsupportedFileVersion as e:
        print("ERROR: %s" % (e,), file=sys.stderr)
        ret = 1

    if patch != "-":
        patch_fd.close()

    if target != "-":
        target_fd.close()

    return ret


def printInfo(patch_fd, skip_command_entries=False):
    # Phase I): Reading the patch file
    additional_return_values = []
    entry_stream = readPatch(patch_fd,
                             additional_return_values=additional_return_values,
                             error_on_no_eof=True,
                             skip_command_entries=skip_command_entries)

    header = next(entry_stream)
    assert isinstance(header, Header)
    blocksize = header.getBlocksize()
    source_blockcount = header.getSourceBlockCount()
    hash_alg = header.getHashAlgorithm()
    source_checksum = header.getSourceChecksum()

    if not skip_command_entries:
        blocks_zero = 0
        blocks_ones = 0
        blocks_copy = 0
        blocks_new = 0
        for command in entry_stream:
            assert isinstance(command, tuple)
            if command[0] == 's':
                # Exit loop and do not count as a target_block. End of commands
                # reached.
                break  # Command(type=stop)

            if command[0] == 'z':
                blocks_zero += 1
            elif command[0] == 'o':
                blocks_ones += 1
            elif command[0] == 'c':
                blocks_copy += 1
            elif command[0] == 'w':
                blocks_new += 1
            else:
                raise Exception("Unknown command: %s" % (command[0],))

    footer = next(entry_stream)
    assert isinstance(footer, Footer)
    target_checksum = footer.getTargetChecksum()

    # Verify that Footer structure is really the last element in the entry
    # stream generator.
    try:
        next(entry_stream)
        raise ValueError("Entry stream generator does not end after footer entry!")
    except StopIteration:
        pass

    # FIXME The readPatch() generator should return additional return values
    # patch filesize(= count of read bytes) and the target_blockcount another
    # way.  Using the mutable list as passed-by-ref workaround is HACKY.
    patch_filesize = additional_return_values[0]
    target_blockcount = additional_return_values[1]

    if patch != "-":
        patch_fd.close()

    # Phase II): Writing information and statistics
    source_filesize = source_blockcount * blocksize
    target_filesize = target_blockcount * blocksize

    print("blocksize", blocksize, "B"),
    print("source-blocks %6i" % (source_blockcount,))
    print("hash-algorithm", hash_alg)
    print("source-checksum", toHex(source_checksum))
    print("target-blocks %6i" % (target_blockcount,))

    print("target-checksum", toHex(target_checksum))

    if not skip_command_entries:
        # NOTE: target_blockcount can be zero, when the target file is zero bytes
        # in the size.
        if target_blockcount == 0:
            assert blocks_zero == 0
            assert blocks_ones == 0
            assert blocks_copy == 0
            assert blocks_new == 0
            blocks_zero_percentage = 0.0
            blocks_ones_percentage = 0.0
            blocks_copy_percentage = 0.0
            blocks_new_percentage = 0.0
        else:
            blocks_zero_percentage = blocks_zero * 100 / target_blockcount
            blocks_ones_percentage = blocks_ones * 100 / target_blockcount
            blocks_copy_percentage = blocks_copy * 100 / target_blockcount
            blocks_new_percentage = blocks_new * 100 / target_blockcount

        print("blocks-zero   %6i (%6.02f %%)" % (blocks_zero, blocks_zero_percentage))
        print("blocks-ones   %6i (%6.02f %%)" % (blocks_ones, blocks_ones_percentage))
        print("blocks-copy   %6i (%6.02f %%)" % (blocks_copy, blocks_copy_percentage))
        print("blocks-new    %6i (%6.02f %%)" % (blocks_new, blocks_new_percentage))

    print("source-filesize %10i B (%7.01f MiB)" % (source_filesize, source_filesize // 1024**2))
    print("patch-filesize  %10i B (%7.01f MiB)" % (patch_filesize, patch_filesize // 1024**2))

    print("target-filesize %10i B (%7.01f MiB)" % (target_filesize, target_filesize // 1024**2))

    if target_filesize != 0:
        saved_bytes = target_filesize - patch_filesize
        percentage = 100 * saved_bytes / target_filesize
        print("Saving %i B (%6.02f %%) compared to sending the target file." % (saved_bytes, percentage))
    else:
        print("Target file is 0 bytes in size. Not saving anything.")

    return 0


def info(args, parser):
    patch = args.patch  # FIXME rename, because it has the same name as the function
    fast = args.fast

    if patch != "-":
        patch_fd = open(patch, "br")
    else:
        patch_fd = sys.stdin.buffer

    try:
        ret = printInfo(patch_fd, skip_command_entries=fast)
    except InvalidMagic as e:
        print("ERROR: File `%s` is not a valid patch file: %s"
              % (patch, e),
              file=sys.stderr)
        ret = 1
    except DataCorruption as e:
        print("ERROR: %s" % (e,), file=sys.stderr)
        ret = __EXIT_CODE_PATCH_FILE_DATA_CORRUPTION__
    except UnsupportedFileVersion as e:
        print("ERROR: %s" % (e,), file=sys.stderr)
        ret = 1
    except NotSeekable:
        print("ERROR: Option '--fast' requires the patch argument to be seekable, e.g. a file!",
              file=sys.stderr)
        ret = 1

    return ret


ExtSuperblock = namedtuple("ExtSuperblock", ["s_blocks_count_lo",
                                             "s_feature_compat",
                                             "s_feature_incompat",
                                             "s_log_block_size"])


class ExtMagicNotFound(Exception):
    pass


# Documentation:
#
def parseExtSuperblock(superblock):
    """Parse 1024 byte ext superblock and return a fields
          s_blocks_count,
          s_feature_compat,
          s_feature_incompat and
          s_log_block_size
    as a namedtuple.

    The ext superblock format is documented here:
        https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout#The_Super_Block

    Function raises exceptions:
        - ExtMagicNotFound() when the superblock is not a ext superblock.
    """
    assert isinstance(superblock, bytes)
    assert len(superblock) == 1024

    s_magic_le16 = superblock[0x38:0x38 + 2]
    s_magic = struct.unpack("<H", s_magic_le16)[0]

    if s_magic != 0xEF53:
        raise ExtMagicNotFound("Magic number in file 0x%04x does not match ext magic number 0xEF53!" % (s_magic,))

    # NOTE: It seems that the filed s_checksum is always zero.
    #  s_checksum_le32 = superblock[1020:1024]
    #  s_checksum = struct.unpack("<I", s_checksum_le32)[0]
    #  print(s_checksum)

    s_blocks_count_lo_le32 = superblock[0x4:0x4 + 4]
    s_blocks_count_lo = struct.unpack("<I", s_blocks_count_lo_le32)[0]

    s_feature_compat_le32 = superblock[0x5C:0x5C + 4]
    s_feature_compat = struct.unpack("<I", s_feature_compat_le32)[0]

    s_feature_incompat_le32 = superblock[0x60:0x60 + 4]
    s_feature_incompat = struct.unpack("<I", s_feature_incompat_le32)[0]

    # Documentation:
    #      blocks are in the range of 1KiB and 64KiB
    #      (See https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout#Blocks)
    #
    # But infact only 1, 2 and 4 KiB are allowed.
    #
    # Formula Block size is 2 ^ (10 + s_log_block_size)
    s_log_block_size_le32 = superblock[0x18:0x18 + 4]
    s_log_block_size = struct.unpack("<I", s_log_block_size_le32)[0]

    ext_superblock = ExtSuperblock(s_blocks_count_lo=s_blocks_count_lo,
                                   s_feature_compat=s_feature_compat,
                                   s_feature_incompat=s_feature_incompat,
                                   s_log_block_size=s_log_block_size)

    return ext_superblock


def extinfo(args, parser):
    filepath = args.filepath

    with open(filepath, "br") as f:
        f.seek(1024)
        superblock = f.read(1024)
        if len(superblock) != 1024:
            print("ERROR: Cannot read 1024 bytes for superblock!",
                  file=sys.stderr)
            return 1

    try:
        ext_superblock = parseExtSuperblock(superblock)
    except ExtMagicNotFound as e:
        print("ERROR: %s" % (e,), file=sys.stderr)
        return 1

    # Documentation:
    #       Block size is 2 ^ (10 + s_log_block_size)
    blocksize = 2 ** (10 + ext_superblock.s_log_block_size)
    print("blocksize", blocksize, sep="\t")

    size = ext_superblock.s_blocks_count_lo * blocksize
    print("total size", size, sep="\t")

    return 0


def version():
    print("blockdiff", __VERSION__)
    return 0


def nocommand(args, parser):
    parser.print_help(file=sys.stdout)
    return 64   # EX_USAGE. See /usr/include/sysexits.h


def main():
    parser = ArgumentParser(description="Generate and apply patch files for block based file or disk formats.",
                            epilog="""Licensed under *GPLv2* and *GPLv3*. See https://www.gnu.org/licenses/.
Homepage: https://stefan.lengfeld.xyz/projects/blockdiff
""")
    parser.add_argument("--version", dest="version",
                        action="store_true", default=False,
                        help="print program's version")
    subparsers = parser.add_subparsers()

    parser_diff = subparsers.add_parser("diff", help="generate patch file from a source and target file.")
    parser_diff.set_defaults(func=diff)
    parser_diff.add_argument(dest="source", type=str,
                             help="path to source file.")
    parser_diff.add_argument(dest="target", type=str,
                             help="path to target file or '-' to read from stdin.")
    parser_diff.add_argument(dest="patch", type=str,
                             help="file to write the patch or '-' to write to stdout. Existing files will be overwritten.")
    parser_diff.add_argument("-b", "--blocksize", dest="blocksize", type=int,
                             default=4 * 1024,
                             help="blocksize in bytes (default: 4096 B = 4 KiB)")
    parser_diff.add_argument("-a", "--hash-alg", dest="hash_alg", type=str,
                             default="SHA1",
                             help="hash algorithm (default: 'SHA1', values: 'MD5', 'SHA1', 'SHA256', 'SHA512')")
    parser_diff.add_argument("-q", "--quiet", dest="quiet", action='store_true',
                             default=False,
                             help="don't print verbose output on stdout")

    parser_patch = subparsers.add_parser("patch", help="apply patch to source file and write out the target file.")
    parser_patch.set_defaults(func=patch)
    parser_patch.add_argument(dest="source", type=str,
                              help="path to source file")
    parser_patch.add_argument(dest="patch", type=str,
                              help="path to patch or '-' to read from stdin.")
    parser_patch.add_argument(dest="target", type=str,
                              help="file to write the output or '-' to write to stdout. Existing files will be overwritten.")
    parser_patch.add_argument("-q", "--quiet", dest="quiet", action='store_true',
                              default=False,
                              help="don't print verbose output on stdout")

    parser_info = subparsers.add_parser("info", help="extract informations from patch file. ")
    parser_info.set_defaults(func=info)
    parser_info.add_argument(dest="patch", type=str,
                             help="path to patch or '-' to read from stdin.")
    parser_info.add_argument("--fast", dest="fast", action='store_true',
                             default=False,
                             help="don't read the whole patch file. Only print the available information in the header and footer. Patch file must be seekable.")

    parser_extinfo = subparsers.add_parser("extinfo", help="print blocksize and size of a ext2,3,4 filesystem image (Or just use 'dumpe2fs')")
    parser_extinfo.set_defaults(func=extinfo)
    parser_extinfo.add_argument(dest="filepath", type=str,
                                help="path to ext2,3,4 filesystem image (device path or file).")

    args = parser.parse_args()

    if args.version:
        ret = version()
    else:
        # Workaround for help
        if hasattr(args, "func"):
            ret = args.func(args, parser)
        else:
            ret = nocommand(args, parser)
    return ret


if __name__ == "__main__":
    sys.exit(main())
