#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2025 Jozef Sudolsky (jozef@sudolsky.sk)
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <jozef@sudolsky.sk> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Jozef Sudolsky
################################################################################
import sys
import urllib.request
import urllib.error

tests = [
	{"version": "4.16.0 or newer", "payloads": [{"get": "/.deployment-secrets.txt", "trigger": 1}]},
	{"version": "4.15.0", "payloads": [{"get": "/database.yaml", "trigger": 1}]},
	{"version": "4.14.0", "payloads": [{"get": "/console.dir(", "trigger": 1}]},
	{"version": "4.13.0", "payloads": [{"get": "/.travis.yaml", "trigger": 1}]},
	{"version": "4.12.0", "payloads": [{"get": "/user_secrets.yml", "trigger": 1}]},
	{"version": "4.11.0", "payloads": [{"get": "/ldap-authentication-report.csv", "trigger": 1}, {"headers": {"Cookie": "a=&if"}, "trigger": 0}]},
	{"version": "4.10.0", "payloads": [{"get": "/ldap-authentication-report.csv", "trigger": 1}]},
	{"version": "4.9.0", "payloads": [{"get": "/fish_variables", "trigger": 1}]},
	{"version": "4.8.0", "payloads": [{"get": "/?a=memory_limit=", "trigger": 0}, {"headers": {"User-Agent": "TsunamiSecurityScanner"}, "trigger": 1}]},
	{"version": "4.7.0", "payloads": [{"headers": {"Cookie": "a=~+"}, "trigger": 1}, {"headers": {"Content-Type": "multipart/related;     boundary=a"}, "trigger": 0}]},
	{"version": "4.6.0", "payloads": [{"headers": {"Cookie": "a=~+"}, "trigger": 1}]},
	{"version": "4.5.0", "payloads": [{"headers": {"Cookie": "a=a alias +m a=b"}, "trigger": 1}]},
	{"version": "4.3.0 / 4.4.0", "payloads": [{"headers": {"User-Agent": "Mozlila"}, "trigger": 1}]},
	{"version": "4.2.0", "payloads": [{"headers": {"Cookie": "a=bin/cscli"}, "trigger": 1}]},
	{"version": "4.1.0", "payloads": [{"headers": {"Cookie": "a=bin/ansible"}, "trigger": 1}]},
	{"version": "4.0.0", "payloads": [{"headers": {"User-Agent": "TsunamiSecurityScanner"}, "trigger": 1}]},
	{"version": "3.3.7", "payloads": [{"headers": {"Content-Type": "multipart/related"}, "trigger": 1}, {"headers": {"Content-Type": "application/x-amf"}, "trigger": 1}]},
	{"version": "3.3.6", "payloads": [{"post": b"--d277996c4e7f403cae647d06227502b3\r\nContent-Disposition: form-data; name=\"cv.p\\f\"; filename=\"cv.pdf\"\r\nContent-Type: application/octet-stream\r\n\r\nhelloworld\r\n--d277996c4e7f403cae647d06227502b3--\r\n", "headers": {"Content-Type": "multipart/form-data; boundary=d277996c4e7f403cae647d06227502b3"}, "trigger": 1}]},
	{"version": "3.3.3 / 3.3.4 / 3.3.5", "payloads": [{"headers": {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8; charset=utf-7"}, "trigger": 1}, {"get": "/%0A", "trigger": 1}, {"headers": {"User-Agent": "SemrushBot"}, "trigger": 1}]},
	{"version": "3.3.2", "payloads": [{"headers": {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8; charset=utf-7"}, "trigger": 0}, {"get": "/admin/content/assets/add/a", "post": b"a=/etc/passwd", "headers": {"Cookie": "SESSa=a"}, "trigger": 1}]},
	{"version": "3.3.0", "payloads": [{"headers": {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8; charset=utf-7"}, "trigger": 0}, {"get": "/?a=%22ontransitioncancel%3D", "trigger": 1}, {"headers": {"User-Agent": "Detectify"}, "trigger": 1}]},
	{"version": "3.2.2 / 3.2.3", "payloads": [{"post": b"--boundary\r\nContent-disposition: form-data; name=\"_charset_\"\r\n\r\nutf-8\r\n--boundary\r\nContent-disposition: form-data; name=\"922110\"\r\nContent-Type: text/plain; charset=utf-7\r\n\r\nKnockknock.\r\n--boundary--\r\n", "headers": {"Content-Type": "multipart/form-data; boundary=boundary"}, "trigger": 1}]},
	{"version": "3.2.1", "payloads": [{"get": "/admin/content/assets/add/a", "post": b"a=/etc/passwd", "headers": {"Cookie": "SESSa=a"}, "trigger": 1}, {"headers": {"Cookie": "a=org.apache.struts2"}, "trigger": 1}]},
	{"version": "3.2.0", "payloads": [{"headers": {"Cookie": "a=org.apache.struts2"}, "trigger": 1}]},
	{"version": "3.1.2", "payloads": [{"get": "/admin/content/assets/add/a", "post": b"a=/etc/passwd", "headers": {"Cookie": "SESSa=a"}, "trigger": 1}]},
	{"version": "3.1.1", "payloads": [{"get": "/?asp.net_sessionid=a", "trigger": 1}, {"get": "/?aspXnet_sessionid=a", "trigger": 0}]},
	{"version": "3.1.0", "payloads": [{"headers": {"User-Agent": "Detectify"}, "trigger": 1}]},
	{"version": "3.0.1 / 3.0.2", "payloads": [{"headers": {"Cookie": "a=[/php]"}, "trigger": 1}]},
	{"version": "3.0.0", "payloads": [{"headers": {"Cookie": "a=<?php"}, "trigger": 1}, {"headers": {"Cookie": "a=[/php]"}, "trigger": 0}]}
]

tests_pl = [
	{"pl": "4", "payload": {"headers": {"X-test-pl": "test'"}}},
	{"pl": "3", "payload": {"headers": {"X-test-pl": "test%"}}},
	{"pl": "2", "payload": {"get": "/?a=https://example.com"}}
]

def test_target(target):
	try:
		req = urllib.request.Request("%s/?a=/etc/passwd" % target)
		# to lower the noise from WAF
		req.add_header("Accept", "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5")
		req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
		response = urllib.request.urlopen(req, timeout=2)
	except urllib.error.HTTPError as e:
		crs_blocking_code = e.code
	except urllib.error.URLError:
		return "timeout"
	else:
		return "off"
	detected_version = None
	for t in tests:
		ok = True
		for p in t["payloads"]:
			try:
				req = urllib.request.Request("%s%s" % (target, p["get"] if "get" in p else ""), headers=p["headers"] if "headers" in p else {}, data=p["post"] if "post" in p else None)
				# to lower the noise from WAF
				req.add_header("Accept", "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5")
				if "headers" not in p or ("headers" in p and "User-Agent" not in p["headers"]):
					req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
				response = urllib.request.urlopen(req, timeout=2)
			except urllib.error.HTTPError as e:
				code = e.code
			except urllib.error.URLError:
				break
			else:
				code = response.status
			if (p["trigger"] == 1 and code != crs_blocking_code) or (p["trigger"] == 0 and code == crs_blocking_code):
				ok = False
				break
		if ok:
			detected_version = t["version"]
			break
	if detected_version:
		detected_pl = "1"
		for t in tests_pl:
			try:
				req = urllib.request.Request("%s%s" % (target, t["payload"]["get"] if "get" in t["payload"] else ""), headers=t["payload"]["headers"] if "headers" in t["payload"] else {})
				# to lower the noise from WAF
				req.add_header("Accept", "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5")
				if "headers" not in p or ("headers" in p and "User-Agent" not in p["headers"]):
					req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
				response = urllib.request.urlopen(req, timeout=2)
			except urllib.error.HTTPError as e:
				code = e.code
			except urllib.error.URLError:
				break
			else:
				code = response.status
			if code == crs_blocking_code:
				detected_pl = t["pl"]
				break
	return {"version": detected_version, "pl": detected_pl}

if __name__ == "__main__":
	if len(sys.argv) != 2 or not (sys.argv[1].lower().startswith("http://") or sys.argv[1].lower().startswith("https://")):
		print("You must specify one target in format http://example.com .")
		sys.exit(1)
	target = sys.argv[1]
	while target[-1] == "/":
		target = target[:-1]
	v = test_target(target)
	if not v:
		print("Unknown version.")
	elif v in ("off", "timeout"):
		print("CRS doesn't seems to be installed on the target.")
	else:
		print("Detected version: %(version)s (PL%(pl)s)" % v)
