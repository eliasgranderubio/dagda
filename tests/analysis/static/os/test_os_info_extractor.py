import unittest

from dagda.analysis.static.os.os_info_extractor import get_os_name
from dagda.analysis.static.os.os_info_extractor import parse_apk_output_list
from dagda.analysis.static.os.os_info_extractor import parse_dpkg_output_list
from dagda.analysis.static.os.os_info_extractor import parse_rpm_output_list


# -- Test suite

class OSInfoExtractorTestSuite(unittest.TestCase):

    def test_get_os_name(self):
        self.assertEqual(get_os_name(mock_os_release_file), "NAME=Fedora")

    def test_parse_rpm_output_list(self):
        product_list = parse_rpm_output_list(mock_rpm_output_list)
        self.assertEqual(len(product_list), 2)
        self.assertEqual(product_list[0]['product'], "libdrm")
        self.assertEqual(product_list[0]['version'], "2.4.60")
        self.assertEqual(product_list[1]['product'], "plymouth")
        self.assertEqual(product_list[1]['version'], "0.8.9")

    def test_parse_dpkg_output_list(self):
        product_list = parse_dpkg_output_list(mock_dpkg_output_list)
        self.assertEqual(len(product_list), 2)
        self.assertEqual(product_list[0]['product'], "apt")
        self.assertEqual(product_list[0]['version'], "1.0.9.8.3")
        self.assertEqual(product_list[1]['product'], "bash")
        self.assertEqual(product_list[1]['version'], "4.3")

    def test_parse_apk_output_list(self):
        product_list = parse_apk_output_list(mock_apk_output_list)
        self.assertEqual(len(product_list), 2)
        self.assertEqual(product_list[0]['product'], "glibc")
        self.assertEqual(product_list[0]['version'], "2.23")
        self.assertEqual(product_list[1]['product'], "libgcc")
        self.assertEqual(product_list[1]['version'], "5.3.0")

# -- Mock Constants

mock_os_release_file = """
VERSION="17 (Beefy Miracle)"
ID=fedora
NAME=Fedora
VERSION_ID=17
PRETTY_NAME="Fedora 17 (Beefy Miracle)"
ANSI_COLOR="0;34"
CPE_NAME="cpe:/o:fedoraproject:fedora:17"
HOME_URL="https://fedoraproject.org/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"
"""

mock_rpm_output_list = """"
Name        : libdrm
Version     : 2.4.60
Release     : 3.el7
Architecture: x86_64
Install Date: Tue 15 Nov 2016 07:32:08 PM CET
Group       : System Environment/Libraries
Size        : 299131
License     : MIT
Signature   : RSA/SHA256, Wed 25 Nov 2015 03:54:08 PM CET, Key ID 24c6a8a7f4a80eb5
Source RPM  : libdrm-2.4.60-3.el7.src.rpm
Build Date  : Fri 20 Nov 2015 03:23:16 PM CET
Build Host  : worker1.bsys.centos.org
Relocations : (not relocatable)
Packager    : CentOS BuildSystem <http://bugs.centos.org>
Vendor      : CentOS
URL         : http://dri.sourceforge.net
Summary     : Direct Rendering Manager runtime library
Description :
Direct Rendering Manager runtime library
Name        : plymouth
Version     : 0.8.9
Release     : 0.24.20140113.el7.centos
Architecture: x86_64
Install Date: Tue 15 Nov 2016 07:32:08 PM CET
Group       : System Environment/Base
Size        : 232723
License     : GPLv2+
Signature   : RSA/SHA256, Wed 25 Nov 2015 04:29:53 PM CET, Key ID 24c6a8a7f4a80eb5
Source RPM  : plymouth-0.8.9-0.24.20140113.el7.centos.src.rpm
Build Date  : Thu 19 Nov 2015 11:00:34 PM CET
Build Host  : worker1.bsys.centos.org
Relocations : (not relocatable)
Packager    : CentOS BuildSystem <http://bugs.centos.org>
Vendor      : CentOS
URL         : http://www.freedesktop.org/wiki/Software/Plymouth
Summary     : Graphical Boot Animation and Logger
Description :
Plymouth provides an attractive graphical boot animation in
place of the text messages that normally get shown.  Text
messages are instead redirected to a log file for viewing
after boot.
"""

mock_dpkg_output_list = """
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                     Version                  Architecture Description
+++-========================-========================-============-========================================================================
ii  apt                      1.0.9.8.3                amd64        commandline package manager
ii  bash                     4.3-11+b1                amd64        GNU Bourne Again SHell
"""

mock_apk_output_list = """
WARNING: Ignoring APKINDEX.167438ca.tar.gz: No such file or directory
WARNING: Ignoring APKINDEX.a2e6dac0.tar.gz: No such file or directory
glibc-2.23-r3
libgcc-5.3.0-r0
"""

if __name__ == '__main__':
    unittest.main()
