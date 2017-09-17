
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


prefix = $(HOME)
mandir ?= $(prefix)/share/man
man1dir = $(mandir)/man1
DESTDIR ?= ""


TARGETS = blockdiff.html blockdiff.1 README.html

all: $(TARGETS)               ### Generate documentation

%.html: %.md
	pandoc -f markdown -t html -s --toc $< -o $@

%.1: %.md
	pandoc -f markdown -t man -s $< -o $@


.PHONY: tests
tests:                        ### Runs the python unit tests
	python3 -m unittest discover -s tests


# Ignore
#   E501 line too long (83 > 79 characters)
.PHONY: check
check:                        ### Runs the pep8 source code checker
	@pep8 --ignore E501 blockdiff tests/*.py|| true


.PHONY: install
install:                      ### Installs program to $(prefix)/
	@#FIXME: Install manpage
	install -Dm 755 blockdiff.py $(DESTDIR)/$(prefix)/bin/blockdiff

.PHONY:
install-doc: blockdiff.1
	install -Dm 644 blockdiff.1 $(DESTDIR)/$(man1dir)/blockdiff.1


.PHONY: clean
clean:
	rm -rf $(TARGETS)
	find tests -maxdepth 1 -name "Test*" -exec rm "-rf" "{}" ";"


# See http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help
help: ## Show the help prompt
	  @grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
