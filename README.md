
blockdiff
=========

**blockdiff** is a binary patch tool for block based file and disk formats (like
ext2,3,4 and btrfs). It's similar to [bsdiff] but not as general, because
`blockdiff` is built on a more stricter assumption about the internal file
format.  The diff algorithm only considers very long byte sequences, blocks of
around ~4 KiB, not single bytes. That's why the runtime and memory usage of
`blockdiff` is minimal compared to *bsdiff*. Of course at the cost of not being
as general applicable as *bsdiff*.  The main usage area of `blockdiff` should
be filesystem based A/B Updates of embedded devices.

For the commandline interface and examples see [blockdiff's
manpage](blockdiff.md).

For more information about binary patch tools see [bsdiff's homepage][bsdiff],
the Wikipedia article [Delta Update][wikipedia-delta-update] and [Google's
Chrome Updater Courgette][google-chrome-courgette].

**NOTE:** The commandline interface and the patch file format of `blockdiff` is
**not** considered stable yet. Wait for the *1.0.0* release.

[bsdiff]: http://www.daemonology.net/bsdiff/
[wikipedia-delta-update]: https://en.wikipedia.org/wiki/Delta_update
[google-chrome-courgette]: https://www.chromium.org/developers/design-documents/software-updates-courgette


Features and Limitations
------------------------

Features:

* The operation `blockdiff diff` runs in *O(n + m)* time and memory usage is
  limited by *O(n)* with *n := 'blocks in the source file'* and *m := 'blocks
  in the target file'*.
* The operation `blockdiff patch` runs in *O(m)* time and the memory usage is
  constant with *m := 'blocks in target file'*.
* Patch file format is streamable. You can pipe out the patch file in
  `blockdiff diff` and pipe in the patch file in `blockdiff patch`. No need to
  download the whole patch file before processing it.
* Every byte in the patch file format is protected by CRC32. Any data
  corruption in the patch file is detected by `blockdiff patch` or `blockdiff
  info`.
* The target file is checked against a cryptographic checksum while it's
  written in `blockdiff patch`. When `blockdiff patch` has finished successfully
  you can be totally sure that the patch operation has produced the identical
  file as it has existed while doing `blockdiff diff` on the sender machine.
* You can choose the cryptographic checksum that is stored in the patch file.
  Available options are (MD5, SHA1, SHA256 and SHA512). You can select the same
  checksum in the patch file as you use for your cryptographic signatures.
  Note: That's only for convenience, not for security, since if you cannot
  trust the patch file, you can also not trust the cryptographic checksum in
  the patch file. Another external tool must verify the final target file or
  patch input file.
* Special cases, source or target file has zero length, are handled.
* Using the wrong source file/device in `blockdiff patch` is handled
  gracefully. Every source block is checked by CRC32. This catches simple human
  errors.
* Using a block device as the source file and target file in `blockdiff patch`
  is supported.  You can write the produced disk image directly to the device.

Limitations (Or *Keep in mind*):

* **Does not work** on arbitrary binary files (like executables, images, audio or
  video files). It only works on file/disk formats that are block based like
  ext2,3,4 and btrfs.
* Works best with disk images up to ~10GB. The limiting factor is time to read
  the source and target file.  Using `blockdiff` for 3 TB disk images is not
  feasable, because the time to read a 3TB disk images is just too long.
* `blockdiff` does not use compression internally.  You should *gzip* the patch
  file yourself to reduce the transferred bytes further.
* *In-place* patching is **not** supported.


Homepage, Code and Contribution
-------------------------------

There is a [project's wobsite](https://stefan.lengfeld.xyz/projects/blockdiff/),
but it contains the same information as the
[github repo](https://github.com/lengfeld/blockdiff/).

The source code can be found in the git repositories:

    $ git clone https://github.com/lengfeld/blockdiff
    $ git clone https://git.stefanchrist.eu/blockdiff.git

If you found a bug or want to brainstrom about additional features, open a
issue on github. To contribute code, open a pull request on github or just send
patches to [stefan+blockdiff@lengfeld.xyz](mailto:stefan+blockdiff@lengfeld.xyz).


Documentation and Installation
------------------------------

To generate the manpage and documentation just execute:

    $ make

Then to view the manpage execute:

    $ man ./blockdiff.1

To install the program in `$HOME/bin` execute:

    $ make install

To install the program and the manpage system-wide in `/usr` execute:

    $ make prefix=/usr install install-doc

For an overview of all Makefile targets execute

    $ make help
    all             Generate documentation
    tests           Runs the python unit tests
    check           Runs the pep8 source code checker
    install         Installs program to $(prefix)/
    help            Show the help prompt


Usage Example
-------------

See file `blockdiff.md` for examples.


License
-------

The source code of `blockdiff` is licensed under *GPLv2* and *GPLv3*. For the
license text see files `LICENSE.GPLv2.txt` and `LICENSE.GPLv3.txt` or visit
[GNU.org Licenses](https://www.gnu.org/licenses/).

I chose not to license the program as *GPLv3 only*, because the normal company
lawyer freaks out when she/he hears the license name *GPLv3*. So she/he can
calm down and only have to acknowledge the *GPLv2* license text.


Algorithm
---------

Compared to `bsdiff` the diff algorithm in `blockdiff` is braindead simple.
It's the natural implementation that you would come up yourself if you
restricted the binary diff algorithm to equally sized blocks and not bother
with arbitrary byte movements of data. The presented algorithm works for
blockbased file formats and filesystems that allows movement of data only at
block length offsets.

The diff algorithm defined in functions `readSource` and
`readTargetAndGenPatchCommands` is based on the user defined blocksize argument
in command `blockdiff patch`.

The function `readSource` splits the source file into equally sized chunks
(here named *blocks*) of *blocksize* bytes. This implies that the source file's
length is a multiple of the *blocksize*.

    Source file:
    0                                                              EOF
    |-- 0 --|-- 1 --|-- 2 --|-- 3 --|--    ...    --|-(n-1)-|-- n --|
        |       |       |                               |       |
        |       |       \- block 2                      |       |
        |       \- block 1                 block (n-1) -/       |
        \- block 0                        block n [last block] -/

For each block in the source file a checksum is calculated. `blockdiff` uses
MD5 internally. The block's checksums are used to build a big hashtable for the
source file. The hashtable key is the checksum of a block and the hashtable's
value is the block index. Since multiple blocks in the source file can be
identical and map to the same checksum, multiple indices are saved as a list as
the hashtable's value. The hashtable looks like:

    hashtable = {checksum_a: [4, 3],
                 checksum_b: [1],
                 checksum_c: [0],
                 checksum_d: [2, n, n-1],
                 ...}

As an optimization blocks of all zeros or ones bits are ignored and not saved
in the hashtable. For filesystem zero blocks are quite common, because it's the
default for non-used space.

The hashtable makes it easy and fast to look up whether a given block can be
found in the source file and get the index of it.


After the hashtable of the source file is generated the target file is
processed. The goal is to produce a sequence of commands, the patch file. The
patch file can rebuild the target file, based on the available data in the
source and patch file itself.

The function `readTargetAndGenPatchCommands` splits the target file into
equally sized blocks of *blocksize* bytes and processes one block at a time.
The block's checksum is calculated and looked up in the hashtable of the source
file. If the same block is available in the source file, it emits a
'copy-from-block-index-n-in-source' command. If the block is not available in
the source file, it emits and writes the whole target block content into the
patch command. For all zero or ones blocks a special patch command is emitted.
The sequence of patch commands may look like:

    commands:
      target block 0: copy from source file block 2
      target block 1: copy from source file block (n-1)
      target block 2: write block of all ones
      target block 3: write block content b"a3f1deadbeaf..."
      target block 4: write block of all zeros
      ...
      target block n: copy from source file block 0

Apart from the sequence of patch commands the patch file formats contains an
additional header and footer including extra information like the count of
source and target blocks and extra checksums to verify the integrity of the
generated target file in the command `blockdiff patch`.


Patch File Format
-----------------

Goals and spec:

* Streamable. Consumer and produce don't need to seek in the patch file.
* File format knows it's filesize and has a magic number in the header. It can
  be embedded into other byte streams.
* Every byte is protected by CRC32 against data corruption.
* Values are encoded little endian, because that's the processor default on x86
  and most ARM systems.
* First four bytes contain the magic number: b"BDIF" (0x42 0x44 0x49 0x46)

Contents/entries:

    [header(magic="BDIF"), command(type=!stop)*, command(type=stop), footer(magic="BDIE")]

Command entries:

* 0x00: command(type=stop): end of commands
* 0x01: command(type=ones): write ones block
* 0x02: command(type=zero): write zero block
* 0x03: command(type=copy): copy block from source file
* 0x04: command(type=new): write new block with contents from patch file

For more details see function `writePatch`.


Todos
-----

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
mkfs.ubifs -r xx  -m 1024 -e 15360 -c 2000 ubifs.img
NAND Chip 8GiB (MX60LF8G18AC): 2K page size, 128K blocksize
# for two gibs of ubifs space
sudo mkfs.ubifs --max-leb-cnt 16384 -m 2048 -e 131072 ubifs.0.10.0.img -x none -r mnt/

$  blockdiff  diff ubifs.0.9.0.img ubifs.0.10.0.img t.patch

$ time bsdiff  ubifs.0.9.0.img ubifs.0.9.0.img bsdiff.0.10.0.patch
real	3m20.795s
user	3m19.308s
sys	0m1.484s
-> corrupted patch

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
