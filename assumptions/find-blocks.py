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
from os.path import join
from itertools import count


def main():
    if len(sys.argv) != 4:
        print("Usage: tbd", file=sys.stderr)
        return 1

    blocksize = int(sys.argv[1])
    assert blocksize in (1024, 2048, 4096)
    dirname = sys.argv[2]
    image = sys.argv[3]

    block_md5sums = set()

    with open(image, "br") as f:
        while True:
            block = f.read(blocksize)
            if len(block) == 0:
                break  # EOF reached

            assert len(block) == blocksize

            block_md5sum = hashlib.md5(block).hexdigest()
            block_md5sums.add(block_md5sum)

    errors = 0
    for folder, folders, files in os.walk(dirname):
        for filename in files:
            filepath = join(folder, filename)

            with open(filepath, "br") as f:
                for block_i in count():
                    block = f.read(blocksize)
                    if len(block) == 0:
                        break  # EOF reached

                    if len(block) < blocksize:
                        # Filesize is not a multiple of the blocksize. Pad with
                        # zeros.
                        block = block + b"\0" * (blocksize - len(block))
                        assert len(block) == blocksize

                    block_md5sum = hashlib.md5(block).hexdigest()

                    if block_md5sum in block_md5sums:
                        print("OK   ", block_i, block_md5sum, filepath)
                    else:
                        print("ERROR", block_i, block_md5sum, filepath)
                        errors += 1

    sys.stdout.flush()
    if errors > 0:
        print("Assumption failure. Not all file blocks found in filesystem image!",
              file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
