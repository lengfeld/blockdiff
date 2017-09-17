
blockdiff
=========

**blockdiff** is a binary patch tool for block base file and disk formats (like
ext2,3,4 and btrfs). It's similar to [bsdiff] but not as general, because
blockdiff is built on a more stricter assumption about the internal file
format.  The diff algorithm only considers very long byte sequences, blocks of
around ~4 KiB, not single bytes. That's why the runtime and memory usage of
*blockdiff* is minimal compared to *bsdiff*. Of course at the cost of not being
as general applicable as *bsdiff*.  The main usage area of *blockdiff* should
be filesystem based A/B Updates of embedded devices.

For the commandline interface and examples see [blockdiff's
manpage](blockdiff.md).

For more information about binary patch tools see [bsdiff's homepage][bsdiff],
the Wikipedia article [Delta Update][wikipedia-delta-update] and [Google's
Chrome Updater Courgette][google-chrome-courgette].

**NOTE:** The commandline interface and the patch file format of blockdiff is
**not** considered stable yet. Wait for the *1.0.0* release :-)

[bsdiff]: http://www.daemonology.net/bsdiff/
[wikipedia-delta-update]: https://en.wikipedia.org/wiki/Delta_update
[google-chrome-courgette]: https://www.chromium.org/developers/design-documents/software-updates-courgette


Features and Limitations
------------------------

Features:

* The operation `blockdiff diff` runs in *O(n + m)* time and memory usage is limited
  by *O(n)* with *n := 'blocks in the source file'* and *m := 'blocks in the target file'*.
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
  file as it has existed on while doing `blockdiff diff` on the sender machine.
* You can choose the cryptographic checksum that is stored in the patch file.
  Available options are (MD5, SHA1, SHA256 and SHA512). You can select the same
  checksum in the patch file as you used for your cryptographic signatures. Note:
  That's only for convenience, for not security, since if you cannot trust the
  patch file, you can also not trust the cryptographic checksum in the patch
  file. The final target file must be verified another external tool.
* Special cases, source or target file has zero length, are handled.
* Using the wrong source file in *blockdiff patch* is handled gracefully. Every
  source block is checked by CRC32. That catches simple human errors.


Limitations (Or *Keep in mind*):

* **Does not work** on arbitrary binary files (like executables, images, audio or
  video files). It only works on file/disk formats that are block based like
  ext2,3,4 and btrfs.
* Works best with disk images up to ~10GB. The limiting factor is time to read
  the source and target file.  Using `blockdiff` for 3 TB disk images is not
  feasable, because the time to read a 3TB disk images is just too long.
* 'blockdiff' does not use compression internally.  You should *gzip* the patch
  file yourself to reduce the transferred bytes further.
* *In-place* patching is **not** supported.


Homepage and Code
-----------------

The project's wobsite is:

    https://www.stefanchrist.eu/projects/blockdiff

The source code can be found in the git repositories:

    $ git clone https://github.com/lengfeld/blockdiff
    $ git clone https://git.stefanchrist.eu/blockdiff.git


Documentation and Install
-------------------------

To generate the manpage and documentation just execute:

    $ make

Then to view the manpage execute:

    $ man ./blockdiff.1

To install the program in `$HOME/bin` execute:

    $ make install

To install the programm and the manpage system-wide in `/usr` execute:

    $ make prefix=/usr install install-doc

For an overview of all Makefile targets execute

    $ make help



Usage Example
-------------

See file `blockdiff.md` for examples.


License
-------

The source code of `blockdiff` is licensed under *GPLv2* and *GPLv3*. For the
license text see files `LICENSE.GPLv2.txt` and `LICENSE.GPLv3.txt` or visit
[GNU.org Licenses](https://www.gnu.org/licenses/).

I chose not to license the program as *GPLv3 only*, because the normal company
lawyer freaks out when they hear the license name *GPLv3*. So they can calm
down and only have to acknowledge the *GPLv2* license text.


Algorithm
---------

FIXME


Patch File Format
-----------------

Goals:

* Streamable. Consumer and produce don't neet to seek in the patch file.
* File format knows it's filesize and has a magic number in the header. It can
  be embedded into other byte streams.
* Every byte is protected by CRC32 against data corruption
* Values are encoded little endian, because that's the processor default on x86
  and most ARM systems.

Contents/entries:

    [header, command(type=!stop)*, command(type=stop), footer]

Supported commands

* 0x00: command(type=stop): End of command stream reached.
* 0x01: command(type=ones): write ones block
* 0x02: command(type=copy): write zero block
* 0x03: command(type=copy): copy block from source file
* 0x04: command(type=new): write new block with contents from patch file


Todos
-----

Implement exact properties of supported file sizes. 2^32 or 2^64. Check
boundary checks with generic implementation that also supports smaller and
testable sizes 2^16 and 2^8.

Fix file format to support 2^64 file lengths.

Add tool and built-in feature for `blockdiff patch`. Read target blocks before
writing them. Maybe they are already wirtten by a previous interrupted patch
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

slengfeld@marvin:~/git/blockdiff$ time bsdiff  ubifs.0.9.0.img ubifs.0.9.0.img bsdiff.0.10.0.patch
real	3m20.795s
user	3m19.308s
sys	0m1.484s
-> corrupted patch


Add a `--dry-run` option to `blockdiff patch`. Don't write the target file.
Just check whether the patch file is not corrupted and all copied blocks are
available in the source file.

Add multiple source blocks in the command copy. Detect data corruption in the
source file and fallback to another block. This should make the patch operation
more resitents against bit errors on the storage media.

Test EOFs in `blockdiff patch` for the source file. Too short

Test EOF in `blockdiff patch/info` for patch file. It should not have extra
padding bytes after the footer structure. Warn the user about that.