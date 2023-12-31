# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *


class TestDfilterScanner:
    trace_file = "http.pcap"

    def test_dquote_1(self, checkDFilterCount):
        dfilter = 'http.request.method == "HEAD"'
        checkDFilterCount(dfilter, 1)

    def test_dquote_2(self, checkDFilterCount):
        dfilter = 'http.request.method == "\\x48EAD"'
        checkDFilterCount(dfilter, 1)

    def test_dquote_3(self, checkDFilterCount):
        dfilter = 'http.request.method == "\\x58EAD"'
        checkDFilterCount(dfilter, 0)

    def test_dquote_4(self, checkDFilterCount):
        dfilter = 'http.request.method == "\\110EAD"'
        checkDFilterCount(dfilter, 1)

    def test_dquote_5(self, checkDFilterCount):
        dfilter = 'http.request.method == "\\111EAD"'
        checkDFilterCount(dfilter, 0)

    def test_dquote_6(self, checkDFilterFail):
        dfilter = r'http.request.method == "\HEAD"'
        checkDFilterFail(dfilter, 'not a valid character escape sequence')
