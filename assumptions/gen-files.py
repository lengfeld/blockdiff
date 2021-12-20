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
import random
from os.path import join


def main():
    if len(sys.argv) != 3:
        print("Usage: tbd", file=sys.stderr)
        return 1

    blocksize = int(sys.argv[1])
    assert blocksize in (1024, 2048, 4096)
    dirname = sys.argv[2]

    count_of_files = 100
    # NOTE: don't start with 0, because there will always be a null block in a
    # ext4/btrfs filesystem.
    data_byte = 1

    random.seed(42)

    for i in range(count_of_files):
        levels = random.randint(1, 5)
        assert 0 <= levels < 25  # only A-Z

        folder = '/'.join([chr(ord("a") + i) * 3 for i in range(levels)])
        filename = "file%04d" % (i,)

        os.makedirs(join(dirname, folder), exist_ok=True)

        blocks = random.randint(0, 9)
        with open(join(dirname, folder, filename), "bw") as f:
            # Write <blocks> number of full blocks
            for x in range(blocks):
                f.write(bytes([data_byte]) * blocksize)
                data_byte = (data_byte + 1) % 256

            # Write a non full last block
            size = random.randint(0, blocksize)
            f.write(bytes([data_byte]) * size)
            data_byte = (data_byte + 1) % 256

    return 0


if __name__ == "__main__":
    sys.exit(main())
