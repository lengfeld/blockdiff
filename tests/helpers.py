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

import tempfile
import unittest
import shutil
from os.path import dirname


class TestCaseTempFolder(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir)

    # Setup stuff is only called once before execution of all unittests in this
    # class, because it's setUpClass() and not setUp().
    @classmethod
    def setUpClass(cls):
        # cls.__name__ will be the name of the lower class.
        cls.tmpdir = tempfile.mkdtemp(prefix=cls.__name__,
                                      dir=dirname(__file__))


# Providing function read() and seek() to emulate a file object for the unit
# tests.
class BytesStreamReader():
    def __init__(self, b):
        self._b = b
        self._pos = 0

    def read(self, size):
        """ If all bytes are read the function returns b''."""
        tmp = self._b[self._pos: self._pos + size]
        self._pos += size
        return tmp

    def seek(self, pos):
        self._pos = pos


class BytesStreamWriter():
    def __init__(self):
        self._b = b""

    def write(self, x):
        self._b += x
        return len(x)

    def getBuffer(self):
        return self._b
