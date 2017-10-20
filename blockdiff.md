% BLOCKDIFF(1)
% Stefan Lengfeld
% September 2017


NAME
====
blockdiff - block based binary patch tool


SYNOPSIS
========

    blockdiff diff [-b/--blocksize=<uint>] [-c/--checksum-type=<name>] [-q/--quiet] <source> <target> <patch>
    blockdiff patch [-q/--quiet] <source> <patch> <target>
    blockdiff info [--fast] <patch>
    blockdiff extinfo <filepath>


DESCRIPTION
===========

blockdiff is a binary patch tool for block base file and disk formats (like
ext2,3,4 and btrfs). It's similar to *bsdiff* but not as general, because
blockdiff is built on a more stricter assumption about the internal file
format.  The diff algorithm only considers very long byte sequences, blocks of
around ~4 KiB, not single bytes. That's why the runtime and memory usage of
blockdiff is minimal compared to *bsdiff*. Of course at the cost of not being
as general applicable as *bsdiff*.  The main usage area of `blockdiff` should
be filesystem based A/B Updates of embedded devices.


COMMANDS
========

## diff

Generate a patch by computing the block based differences between 'source' and
'target'.

You should use the `--blocksize` parameter to match the blocksize used in your
source/target file/disk format. For ext2,3,4 disk images the default blocksize
`4 KiB` is mostly correct.  You can verify the used ext blocksize with the
command `blockdiff extinfo` or the program `dumpe2fs`. You can also experiment
with smaller blocksizes to reduce the patch file size further.

You can specify the checksum algorithm with argument `--checksum-type` (default
`SHA1`) which is stored in the patch file. It's used to verify the target file
while writing the target file in the patch operation.

Command returns exit code `1` if source file is not block aligned (size of file
is not a multiple of the blocksize).


## patch

Argument 'patch' is the path to the patch file or '-' to read the patch
directly from stdin. Argument 'target' is the path to the target file that will
be written (overwriting any existing file) or '-' to write the target file to
stdout.

If the generated target file does not match the checksum stored in the patch
file, the command returns the exit code `5` and prints an error message to
stderr. Note: In that case the target file is still completely written to the
given path, block device or stdout. You should not trust the target file and
invalidate it at once.

If the consumed patch file is corrupted, e.g. contains a bitflip, the patch
operation is aborted. The command prints an error message on stderr and returns
the exit code `6`. Note: In that case any number of blocks of the target file,
even the whole file, is written out already. You should not trusted the target
file and invalidate it at once.

If a needed block in the source file is corrupted, checked by CRC32, the patch
operation is aborted.  The command prints an error message on stderr and
returns the exit code `7`. Note: In that case any number of blocks of the
target file is written out already. You should not trusted the target file and
invalidate it at once.

Additional bytes at the end of the patch file are tolerated. No EOF needed.


## info

Argument 'patch' is the patch to read the patch file or '-' to read the patch
directly from stdin.

Pass the argument '--fast' to only read and print the information from the
header and footer structure in the patch file. This speeds up the execution
time considerably, because the program must not traverse the whole patch file.
Note: Not all information can be printed, the 'patch' argument must be
seekable, e.g.  reading from stdin fails, and not every data corruption of the
patch file can be detected.

If the consumed patch file is corrupted, e.g. contains a bitflip, the command
aborts, prints an error message on stderr and returns the exit code `6`.

If the consumed patch file contains additional bytes after the footer entry in
the patch file (no EOF reached), the command aborts, prints an error message on
stderr and returns the exit code `6`.


## extinfo

The command `extinfo` reads the superblock of ext2,3,4 disk images and prints
some useful information. For now it calculates the blocksize and the total
length of the filessystem. It's a strip down version of the real tool
`dumpe2fs`.


OPTIONS
=======

General options for some commands:

-q/--quiet::
    Disable informational output on stdout


EXAMPLES
========

## Simple example


## Piping patch file over SSH

The patch file format is streamable and the commands `blockdiff diff` and
`blockdiff patch` allow to write the patch file to stdout and read the patch
file from stdin. The following example use that feature over SSH.

    $ blockdiff diff --blocksize 512 old-file new-file - | \
	ssh server "blockdiff patch old-file - output-file"

In the above command the patch file is never written to the disk. It's directly
streamed over the network.


## A/B Update scheme on block devices

The primary use case for **blockdiff** is A/B update scheme in embedded
devices.

On the Sender/build machine/host/server:

    host$ blockdiff diff rootfs.v1.0.0.ext4 rootfs.v1.1.0.ext4 rootfs.v1.0.0-v1.1.0.patch
    host$ blockdiff info rootfs.v1.0.0-v1.1.0.patch

Transfer file `rootfs.v1.0.0-v1.1.0.patch` onto receiver/device, mostly by
uploading the file to a server which is polled by the devices/clients
regularly.

On Receiver/device/target/client:

    # With p2 and p3 are the Slot A and Slot B partitions
    target$ blockdiff patch /dev/mmcblk0p2 /tmp/rootfs.v1.0.0-v1.1.0.patch /dev/mmcblk0p3

More sophisticated example with streaming in the patch file from the server:

    target$ wget -O - https://example.org/rootfs.v1.0.0-v1.1.0.patch | \
                blockdiff patch /dev/mmcblk0p2 - /dev/mmcblk0p3


SEE ALSO
========

**bsdiff**(1), **bspatch**(1), **dumpe2fs**(8)


BLOCKDIFF
=========
The source code of **blockdiff** is licensed under *GLPv2* and *GPLv3*.  The
project hompage is

    https://www.stefanchrist.eu/projects/blockdiff

and the github repository is

    https://github.com/lengfeld/blockdiff
