# TODOs

Implement exact properties of supported file sizes. 2^32 or 2^64. Check
boundary checks with generic implementation that also supports smaller and
testable sizes 2^16 and 2^8.

Fix file format to support 2^64 file lengths.

Add tool and built-in feature for `blockdiff patch`. Read target blocks before
writing them. Maybe they are already written by a previous interrupted patch
operation. Minimize write operations.

IDEA: Allow *in-place* patching for (system/rescue update concepts). Think
about interrupts/power-cuts.

Some infos about exit codes http://www.tldp.org/LDP/abs/html/exitcodes.html

IDEA: `block diff` should produce file format for `bspatch`. So the patch can
be applied with the normal bspatch tool.

test ubifs: #

    $ mkfs.ubifs -r xx  -m 1024 -e 15360 -c 2000 ubifs.img
    NAND Chip 8GiB (MX60LF8G18AC): 2K page size, 128K blocksize
    # for two gibs of ubifs space
    $ sudo mkfs.ubifs --max-leb-cnt 16384 -m 2048 -e 131072 ubifs.0.10.0.img -x none -r mnt/

    $ blockdiff  diff ubifs.0.9.0.img ubifs.0.10.0.img t.patch

    $ time bsdiff  ubifs.0.9.0.img ubifs.0.9.0.img bsdiff.0.10.0.patch
    real	3m20.795s
    user	3m19.308s
    sys	0m1.484s
    -> corrupted patch

    # TODO are these commands here compelete?

Add a `--dry-run` option to `blockdiff patch`. Don't write the target file.
Just check whether the patch file is not corrupted and all copied blocks are
available in the source file.

Add multiple source blocks in the command copy. Detect data corruption in the
source file and fallback to another block. This should make the patch operation
more resilient against bit errors on the storage media.

The command `blockdiff info` should be able to read "gz" files. A user
of blockdiff is going to compress the patch files.

Support interrupted patch operations. No need to download the whole patch file
again. Just continue the download and patch operation in the middle of the
patch file.

Use asciidoc instead of pandoc to generate the manpage and the html for the
homepage. Pandoc is a haskell programm and requires the haskell toolchain
installed on the build system.

Add argument "auto" for option "--blocksize" in command 'blockdiff diff'. The
program should try to detect the suitable blocksize from the file, e.g. header
of ext2,3,4 images or perdefined for tar.

Add some sort or progress stderr output in 'blockdiff patch'. Currently there
is no indication that the patch operation is running.

Follow the recommendation of the REUSE documenation by FSF for software
licenses.
