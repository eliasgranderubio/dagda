import unittest
import json
import requests_mock
from dagda.vulnDB.bid_downloader import get_bid


# -- Test suite

class BidDownloaderTestCase(unittest.TestCase):

    @requests_mock.mock()
    def test_get_bid(self, m):
        m.get('http://www.securityfocus.com/bid/12', text=mock_bid_12_page)
        parsed_bid = json.loads(get_bid(12))
        self.assertEqual(parsed_bid['bugtraq_id'], 12)
        self.assertEqual(parsed_bid['title'], "VMS ANALYZE/PROCESS_DUMP Vulnerability")
        self.assertEqual(len(parsed_bid['vuln_products']), 17)
        self.assertTrue("Digital VMS 5.4.3" in parsed_bid['vuln_products'])
        self.assertTrue("Digital VMS 5.2" in parsed_bid['vuln_products'])
        self.assertTrue("Digital VMS 5.1" in parsed_bid['vuln_products'])
        self.assertTrue("Digital VMS 4.0" in parsed_bid['vuln_products'])


# -- Mock Constants

mock_bid_12_page = '''
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
<meta name="description" content="SecurityFocus is designed to facilitate discussion on computer security related topics, create computer security awareness, and to provide the Internet&apos;s largest and most comprehensive database of computer security knowledge and resources to the public. It also hosts the BUGTRAQ mailing list.">
<meta name="keywords" content="securityfocus, security focus, computer security, information security, security, hack, full disclosure, bugtraq, bugtrack, bugtrac, bugtrag, vulnerability, vulnerabilities, vulnerability database, auditing, spoofing, sniffer, sniffing, exploit, advisory, antivirus, virus, firewall, buffer overflow, overflow, password, windows, windows nt, solaris, linux, crack, cracker, cracking, IDS, intrusion detection, backdoor, backdoors, trojan, cryptography, encryption, authentication, DoS, DDoS, denial of service, syn flooding, smurf, internet security, web security, security tools, security products, vuln-dev, security incidents, incident responce, bugtraq-jp, bugtraq-es, security jobs, sf-news, focus-ms, focus-sun, focus-linux, focus-ids, focus-ih, infowar, information warfare, VPN, virtual private network">
<script language="JavaScript">
var pathname='/home';
var OAS_listpos = 'Top,Middle,Bottom1,Right1,x29,x30,x28';
</script>
<SCRIPT LANGUAGE="JavaScript1.2" SRC="/js/standard.js"></SCRIPT>
<script src="/__utm.js" type="text/javascript"></script>
<link rel="stylesheet" type="text/css" href="/new_SFPS_style.css" />
<title>VMS ANALYZE/PROCESS_DUMP Vulnerability</title>

</head>

<body bgcolor="#ffffff">
<map name="ButtonMap">
  <area shape="rect" coords="139,25,190,45" href="/about">
  <area shape="rect" coords="191,25,249,45" href="/contact">
</map>
<!-- start header -->

<a href="/"><div id="logo_new">
		<div class="headerButtonBar"><img src="/images/site/header_button_bar.gif" width="258" height="45" alt="" usemap="#ButtonMap" border="0"></div>
</div></a>
<div id="bannerAd">
<table width="890" cellpadding="0" border="0" cellspacing="0">
<tr><td width="728">
<a href="http://www.symantec.com/connect/" target="_blank"><img src="/images/site/sf-symc-connect-banner.jpg" width="728" height="90" alt="" border="0"/></a>
</td>
<td width="12">&nbsp;</td>
<td width="150" align="right">
&nbsp;
<td>
</tr>
</table>

</div>

<!-- end header -->

<table width="900" cellpadding="0" cellspacing="4" border="0">
	<tr valign="top">

		<td>
			<!-- Start Content -->
<br/>
 <div id="tabs">
  <ul>
  	<li class="here"><a href="/bid/12/info">info</a></li>
	<li><a href="/bid/12/discuss">discussion</a></li>
	<li><a href="/bid/12/exploit">exploit</a></li>
	<li><a href="/bid/12/solution">solution</a></li>
	<li><a href="/bid/12/references">references</a></li>
	</ul>
</div>
<div id="vulnerability">
	<span class="title">VMS ANALYZE/PROCESS_DUMP Vulnerability</span><br/><br/>
	<table cellpadding="4" cellspacing="0" border="0">
		<tr>
			<td>
				<span class="label">Bugtraq ID:</span>
			</td>
			<td>
				12
			</td>
		</tr>
		<tr>
			<td>
				<span class="label">Class:</span>
			</td>
			<td>
				Unknown
			</td>
		</tr>
		<tr valign="top">
			<td>
				<span class="label">CVE:</span>
			</td>
			<td>

			</td>
		</tr>
		<tr>
			<td>
				<span class="label">Remote:</span>
			</td>
			<td>
				Unknown
			</td>
		</tr>
		<tr>
			<td>
				<span class="label">Local:</span>
			</td>
			<td>
				Unknown
			</td>
		</tr>
		<tr>
			<td>
				<span class="label">Published:</span>
			</td>
			<td>
				Oct 25 1990 12:00AM
			</td>
		</tr>
		<tr>
			<td>
				<span class="label">Updated:</span>
			</td>
			<td>
				Oct 25 1990 12:00AM
			</td>
		</tr>
		<tr>
			<td>
				<span class="label">Credit:</span>
			</td>
			<td>

			</td>
		</tr>
		<tr valign="top">
			<td>
				<span class="label">Vulnerable:</span>
			</td>
			<td>

					Digital VMS 5.4.3 <br/>


					Digital VMS 5.4.2 <br/>


					Digital VMS 5.4.1 <br/>


					Digital VMS 5.4 <br/>


					Digital VMS 5.3.2 <br/>


					Digital VMS 5.3.1 <br/>


					Digital VMS 5.3 <br/>


					Digital VMS 5.2.1 <br/>


					Digital VMS 5.2 <br/>


					Digital VMS 5.1.2 <br/>


					Digital VMS 5.1.1 <br/>


					Digital VMS 5.1 B<br/>


					Digital VMS 5.1 <br/>


					Digital VMS 5.0.2 <br/>


					Digital VMS 5.0.1 <br/>


					Digital VMS 5.0 <br/>


					Digital VMS 4.0 <br/>


			</td>
		</tr>
		<tr>
			<td colspan="2">
				<div class="breakline"></div>
			</td>
		</tr>
		<tr valign="top">
			<td>
				<span class="label">Not Vulnerable:</span>
			</td>
			<td>

			</td>
		</tr>
	</table>

</div>

<br/><br/>


			<!-- End Content -->
		</td>
	</tr>
</table>
<!-- start footer -->
<table width="900" cellpadding="0" cellspacing="4" border="0">
	<tr valign="top">
		<td width="120">
		&nbsp;
		</td>
		<td>

<br/>
<p align="center" style="color: #666; font-size: 8pt;"><a href="/privacy">Privacy Statement</a><br>Copyright 2010, SecurityFocus</p>

		</td>
		<td width="160">
		&nbsp;
		</td>
	</tr>
</table>
</body>
</html>
'''


if __name__ == '__main__':
    unittest.main()
