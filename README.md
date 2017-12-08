# XSSSonar
Little tool to look for XSS vulnerabilities in a web page.

![XSS Sonar Screenshot](xsssonar.png)

# Info
This code is just a draft. There are some errors still to be corrected, and sometimes false positives occur.<br/>
Test with Python 2.7.9 on Debian Jessie. I'll write it for Python 3.x maybe.<br/>

# ChangeLog
<strong>0.1.5</strong><br/>
[-] Added scan on POST parameters<br/>
[-] Changed name<br/>
<br/>
<strong>0.1.4a</strong><br/>
[-] Added stopwatch to know the time spent to check each URL<br/>
[-] Same features with 1500 lines of code missing<br/>
<br/>
<strong>0.1.4</strong><br/>
[-] Check a single URL or a list.txt of sites

# To start
pip install fake-useragent<br/>
python xsssonar.py
