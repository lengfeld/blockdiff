
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

# Use bash for 'set -o pipefail'
SHELL = bash

TARGETS = files image.ext4 image.btrfs report.ext4 report.btrfs

# Filesytem blocksize. Valid values are 1024, 2048 or 4096.
BLOCKSIZE = 2048


all: $(TARGETS)


files:
	./gen-files.py $(BLOCKSIZE) $@


image.ext4: files
	dd if=/dev/zero of=$@ count=100 bs=1M conv=sparse
	mkfs.ext4 -b $(BLOCKSIZE) $@
	mkdir -p mnt-ext4
	sudo mount  $@ mnt-ext4
	sudo cp -rv $</* mnt-ext4/
	sudo umount mnt-ext4
	rmdir mnt-ext4

image.btrfs: files
	dd if=/dev/zero of=$@ count=100 bs=1M conv=sparse
	mkfs.btrfs -s  $(BLOCKSIZE) $@
	mkdir -p mnt-btrfs
	sudo mount  $@ mnt-btrfs
	sudo cp -rv $</* mnt-btrfs/
	sudo umount mnt-btrfs
	rmdir mnt-btrfs


report.ext4: files image.ext4
	set -o pipefail ; ./find-blocks.py $(BLOCKSIZE) $^ | tee $@


# NOTE: btrfs stores files up to 2048 bytes in the directory tree, not in
# separate blocks. For files smaller or equal to 2048 the assumption does not
# hold.
report.btrfs: files image.btrfs
	set -o pipefail ; ./find-blocks.py $(BLOCKSIZE) $^ | tee $@


.PHONY: clean
clean:
	rm -rf $(TARGETS)
