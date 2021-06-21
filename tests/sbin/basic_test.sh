# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 Daniel O'Connor <darius@dons.net.au>. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

atf_test_case basic cleanup
basic_body() {
  kldstat -qm pefs
  if [ $? -ne 0 ]; then
      atf_skip "PEFS kernel module not loaded"
  fi
  mkdir mnt
  echo test123 >keyfile
  atf_check -s exit:0 -o empty -e empty pefs addchain -fZj keyfile mnt
  atf_check -s exit:0 -o empty -e empty pefs mount mnt mnt
  atf_check -s exit:0 -o empty -e empty pefs addkey -cj keyfile mnt
  orig=$(dd if=/dev/random count=100 | tee mnt/testfile | sha256 -q)
  atf_check -s exit:0 -o empty -e empty pefs umount mnt
  if [ -e mnt/testfile ]; then
      aft_fail "Test filename was present after umount"
  fi
  atf_check -s exit:0 -o empty -e empty pefs mount mnt mnt
  atf_check -s exit:0 -o empty -e empty pefs addkey -cj keyfile mnt
  new=$(sha256 -q mnt/testfile)
  atf_check_equal $orig ${new}
}

basic_cleanup() {
  if [ -e mnt ]; then
      umount -f mnt
  fi
}

atf_init_test_cases() {
  atf_add_test_case basic
}
