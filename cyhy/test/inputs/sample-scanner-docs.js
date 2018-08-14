Nmap Port Doc
{
	"_id" : ObjectId("50db48cf0697f719ad10a298"),
	"protocol" : "tcp",
	"service" : {
		"name" : "minecraft",
		"conf" : "3",
		"method" : "table"
	},
	"ip" : "173.66.73.61",
	"time" : ISODate("2012-09-14T16:22:00Z"),
	"state" : "open",
	"source" : "nmap",
	"reason" : "syn-ack",
	"ip_int" : NumberLong("2906802493"),
	"owner" : "TEST",
	"port" : 25565,
	"latest" : true
}

Nmap Host Doc
{
	"_id" : ObjectId("50db48cf0697f719ad10a299"),
	"accuracy" : "88",
	"ip" : "173.66.73.61",
	"name" : "Apple iPad tablet computer (iPhone OS 3.2)",
	"source" : "nmap",
	"classes" : [
		{
			"osfamily" : "iPhone OS",
			"vendor" : "Apple",
			"cpe" : [
				"cpe:/o:apple:iphone_os:3"
			],
			"type" : "general purpose",
			"osgen" : "3.X",
			"accuracy" : "88"
		}
	],
	"time" : ISODate("2012-09-14T16:22:00Z"),
	"owner" : "TEST",
	"line" : "3634",
	"latest" : true
}

Nessus Host Doc
{
	"_id" : ObjectId("50db9b550697f7076586f6b6"),
	"host_fqdn" : "mail.geekpad.com",
	"operating_system" : "Mac OS X 10.8",
	"name" : "173.66.73.61",
	"ip" : "173.66.73.61",
	"start_time" : ISODate("2012-09-26T12:48:38Z"),
	"source" : "nessus",
	"system_type" : "general-purpose",
	"ip_int" : NumberLong("2906802493"),
	"owner" : "TEST",
	"latest" : true,
	"end_time" : ISODate("2012-09-26T13:08:53Z")
}

Nessus Port Doc
{
	"_id" : ObjectId("50db9b550697f7076586f636"),
	"cvss_temporal_vector" : "CVSS2#E:F/RL:OF/RC:C",
	"protocol" : "tcp",
	"cvss_base_score" : 7.8,
	"exploitability_ease" : "Exploits are available",
	"edb-id" : "18221",
	"cvss_temporal_score" : 6.4,
	"plugin_output" : "\nNessus determined the server is unpatched and is not using any\nof the suggested workarounds by making the following requests :\n\n-------------------- Testing for workarounds --------------------\nHEAD /images/contact.html HTTP/1.1\nHost: web1.nidhog.com\nAccept-Language: en\nAccept-Charset: iso-8859-1,utf-8;q=0.9,*;q=0.1\nRange: bytes=5-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9,10-10\nRequest-Range: bytes=5-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9,10-10\nConnection: Close\nPragma: no-cache\nUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\n\nHTTP/1.1 206 Partial Content\nDate: Wed, 26 Sep 2012 17:18:10 GMT\nServer: Apache/2.2.3 (FreeBSD) mod_ssl/2.2.3 OpenSSL/0.9.7e-p1 DAV/2 PHP/4.4.4 with Suhosin-Patch\nLast-Modified: Mon, 25 Apr 2005 04:02:35 GMT\nETag: \"e6cddf-2251-e0be6cc0\"\nAccept-Ranges: bytes\nContent-Length: 858\nConnection: close\nContent-Type: multipart/x-byteranges; boundary=4ca9e01c3c6df151c2\n-------------------- Testing for workarounds --------------------\n\n-------------------- Testing for patch --------------------\nHEAD /images/contact.html HTTP/1.1\nHost: web1.nidhog.com\nAccept-Language: en\nAccept-Charset: iso-8859-1,utf-8;q=0.9,*;q=0.1\nRange: bytes=0-,1-\nRequest-Range: bytes=0-,1-\nConnection: Close\nPragma: no-cache\nUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\n\nHTTP/1.0 206 Partial Content\nDate: Wed, 26 Sep 2012 17:18:10 GMT\nServer: Apache/2.2.3 (FreeBSD) mod_ssl/2.2.3 OpenSSL/0.9.7e-p1 DAV/2 PHP/4.4.4 with Suhosin-Patch\nLast-Modified: Mon, 25 Apr 2005 04:02:35 GMT\nETag: \"e6cddf-2251-e0be6cc0\"\nAccept-Ranges: bytes\nContent-Length: 17765\nConnection: close\nContent-Type: multipart/x-byteranges; boundary=4ca9e01c62c1615148\n-------------------- Testing for patch --------------------\n",
	"owner" : "TEST",
	"port" : 443,
	"xref" : "EDB-ID:18221",
	"severity" : 3,
	"service" : "www",
	"osvdb" : "74721",
	"plugin_family" : "Web Servers",
	"patch_publication_date" : ISODate("2011-08-25T00:00:00Z"),
	"synopsis" : "The web server running on the remote host is affected by a denial of service vulnerability.",
	"risk_factor" : "High",
	"source" : "nessus",
	"fname" : "apache_range_dos.nasl",
	"ip" : "66.207.132.2",
	"plugin_id" : 55976,
	"vuln_publication_date" : ISODate("2011-08-19T00:00:00Z"),
	"latest" : true,
	"description" : "The version of Apache HTTP Server running on the remote host is affected by a denial of service vulnerability.  Making a series of HTTP requests with overlapping ranges in the Range or Request-Range request headers can result in memory and CPU exhaustion.  A remote, unauthenticated attacker could exploit this to make the system unresponsive.\n\nExploit code is publicly available and attacks have reportedly been observed in the wild.",
	"see_also" : "http://archives.neohapsis.com/archives/fulldisclosure/2011-08/0203.html\nhttp://www.gossamer-threads.com/lists/apache/dev/401638\nhttp://www.nessus.org/u?404627ec\nhttp://httpd.apache.org/security/CVE-2011-3192.txt\nhttp://www.nessus.org/u?1538124a\nhttp://www-01.ibm.com/support/docview.wss?uid=swg24030863",
	"bid" : "49303",
	"plugin_modification_date" : ISODate("2012-09-06T00:00:00Z"),
	"plugin_name" : "Apache HTTP Server Byte Range DoS",
	"solution" : "Upgrade to Apache httpd 2.2.21 or later, or use one of the workarounds in Apache's advisories for CVE-2011-3192.  Version 2.2.20 fixed the issue, but also introduced a regression.\n\nIf the host is running a web server based on Apache httpd, contact the vendor for a fix.",
	"exploit_framework_metasploit" : "true",
	"metasploit_name" : "Apache Range header DoS (Apache Killer)",
	"plugin_publication_date" : ISODate("2011-08-25T00:00:00Z"),
	"cvss_vector" : "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C",
	"ip_int" : 1120896002,
	"cpe" : "cpe:/a:apache:http_server",
	"cert" : "405811",
	"exploit_available" : "true",
	"cve" : "CVE-2011-3192",
	"exploit_framework_core" : "true",
	"plugin_type" : "remote"
}

