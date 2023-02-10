import paramiko
import re
import time
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO


ospf_info={}

def execute_cmd(ctx,cmd):

	ctx.send(f'{cmd}\n')
	time.sleep(.5)
	output = ctx.recv(65535)

	if cmd == 'write':
		output = ctx.recv(65535)

	output =  str(output,'utf-8')

	return output


def interface_inspection (connection,next = False ):

	stdout =  execute_cmd(connection,' ') if next else execute_cmd(connection,'sh ip int br')
	#stdin, stdout, stderr = ssh.exec_command('sh ip int br')

	ip_int = stdout.split('\n')
	#print(stdout.split('\n'))
	#return
	ip_int = ip_int[2:len(ip_int)]
	interfaces_brief = []

	for int in ip_int:

		f_int = {}

		#remove unuse information
		int_line = re.sub(r'\s+','_',int)
		int_line = int_line.replace('YES_NVRAM','')
		int_line = int_line.replace('YES_unset','')

		#check if interface is administratively down or not
		if 'administratively_down' in int_line:
			int_line = int_line.replace('administratively_down','')
			f_int["enable"] = 0
		elif 'up' in int_line:
			int_line = int_line.replace('up','',1)
			f_int["enable"] = 1
		else:
			f_int["enable"] = 'no set'
		#check if interface is connected or not
		if 'down' in int_line:
			int_line = int_line.replace('down','')
			f_int["connected"] = 0
		elif 'up' in int_line:
			int_line = int_line.replace('up','')
			f_int["connected"] = 1
		else:
			pass

		#check if ip address was assign
		ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',int_line)
		if  ip:
			int_line = int_line.replace(ip[0],'')
			f_int["ip"] = ip[0]
		else:
			int_line = int_line.replace('unassigned','')
			f_int["ip"] = 'unassigned'

		f_int["name"] = re.sub(r'_','',int_line)
		interfaces_brief.append(f_int)

		if f_int['name'] == '--More--' :
			t = interface_inspection(connection,True)
			interfaces_brief.extend(t)
	return [ i for i in interfaces_brief if i['enable'] != 'no set' ]

def shut_down_unused_interfaces(connection,interfaces):
	print('shut down unused interfaces ...')

	execute_cmd(connection,'conf t')
	for interface in interfaces:
		execute_cmd(connection,f'interface {interface}')
		execute_cmd(connection,'switchport mode access')
		execute_cmd(connection,'shutdown')

	execute_cmd(connection,'end')

#Check bpdu guard security

def bpdu_guard_inspection(connection) :

	print('checking bpduguard status...')
	spanning_tree_brief = {}

	output = execute_cmd(connection,'sh spanning-tree summary')
	output = output.split('\n')[2]

	if 'BPDU Guard' in output:
		if 'disabled' in output:
			spanning_tree_brief['bpdu_guard'] = 0
		elif 'enabled' in output:
			spanning_tree_brief['bpdu_guard'] = 1
	print('bpduguard status check done.')
	print(spanning_tree_brief)


def enable_bpdu_guard(connection):

	print('Enabling bpduguard...')

	execute_cmd(connection,'conf t')
	execute_cmd(connection,'spanning-tree portfast bpduguard')
	execute_cmd(connection,'end')
	execute_cmd(connection,'write')

	print('Bpduguard enabled.')



def check_ospf(connection,interface):
	print('Checking ospf status ...\n')

	ospf_info[interface] = {}
	output = execute_cmd(connection,f'sh ip ospf interface {interface}')
	output = output.split('\n')

	if 'not enabled' in output[1]:

		ospf_info[interface]['enable'] = 0
	else:
		ospf_info[interface]['enable'] = 1
		ospf_info[interface]['authentication'] = {}

		for line in output:

			if 'authentication enabled' in line:
				ospf_info[interface]['authentication']['enable'] = 1

			if 'Youngest key id is' in line:
				ospf_info[interface]['authentication']['key_is_set'] = 1
				print(f'key is configured {interface}')
				print(ospf_info[interface]['authentication']['key_is_set'])

def secure_ospf(connection,ospf_id,ospf_area,interfaces,ospf_pass):

	execute_cmd(connection,'conf t')
	execute_cmd(connection,f'router ospf {ospf_id}')
	execute_cmd(connection,f'area {ospf_area} authentication message-digest')
	execute_cmd(connection,'exit')

	for interface in interfaces:
		execute_cmd(connection,f'int {interface}')
		execute_cmd(connection,f'ip ospf message-digest-key 1 md5 {ospf_pass}')

	execute_cmd(connection,'end')

#interfaces = interface_inspection()
#interfaces = [ el['name'] for el in interfaces ]
#secure_ospf(1,0,interfaces,123456)
#ospf_info = {}
#for interface in interfaces:
#	check_ospf_status(interface['name'])
#print(ospf_info)

#enable_bpdu_guard()
#bpdu_guard_inspection()

#check_ospf_status('g4/0')

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

	def do_GET(self):
		self.send_response(200)
		self.end_headers()
		self.wfile.write(b'Hello, world!')

	def do_POST(self):
		print(self.path)

		content_length = int(self.headers['Content-Length'])
		body = self.rfile.read(content_length)
		payload = json.loads(str(body,'utf-8'))
		print(payload)
		host = payload['host']

		if host and payload['enable_password']:

			print(f"connection to host {host}....")
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
			ssh.connect(hostname=host, username=payload['user'], password=payload['secret'], port=22)
			print(f'connection to {host} done\n')

			print('Entering enable mode...')
			connection = ssh.invoke_shell()
			connection.recv(65535)
			connection.send('enable\n')
			time.sleep(.5)
			connection.recv(65535)
			connection.send(payload['enable_password'])
			time.sleep(.5)
			connection.recv(65535)
			print("Entering enable mode successfully\n")
		#else:
		#	self.send_response(400)
		#	self.end_headers()
		#	self.wfile.write(b'Required argument missing')
		#	return

		if self.path == '/inspect-interface' :
			print('interface inspection...')
			res = interface_inspection(connection=connection)
			res = str(res)
			self.send_response(200)
			self.end_headers()
			response = BytesIO()
			response.write(str.encode(res))
			self.wfile.write(response.getvalue())
			print('interface inspection done.')

		elif self.path == '/shutdown-unused-interfaces' :
			print('shutdown unused interfaces ...')
			res = shut_down_unused_interfaces(connection,payload['interfaces'])
			res = str(res)
			self.send_response(200)
			self.end_headers()
			response = BytesIO()
			response.write(str.encode(res))
			self.wfile.write(response.getvalue())
			print('shutdown unused interfaces done.')

		elif self.path == '/check-bpdu-guard' :
			print('checking bpdu guard ...')
			res = bpdu_guard_inspection(connection)
			res = str(res)
			self.send_response(200)
			self.end_headers()
			response = BytesIO()
			response.write(str.encode(res))
			self.wfile.write(response.getvalue())
			print('check for bpdu guard done.')

		elif self.path == '/enable-bpdu-guard' :
			print('enabling bpdu guard ...')
			res = enable_bpdu_guard(connection)
			res = str(res)
			self.send_response(200)
			self.end_headers()
			response = BytesIO()
			response.write(str.encode(res))
			self.wfile.write(response.getvalue())
			print('enabling bpdu guard done.')

		elif self.path == '/check-ospf':
			print('checking ospf ...')
			for interface in payload['interfaces']:
				check_ospf(connection,interface)
			res = str(ospf_info)
			self.send_response(200)
			self.end_headers()
			response = BytesIO()
			response.write(str.encode(res))
			self.wfile.write(response.getvalue())
			print('ospf check done.')

		elif self.path == '/secure-ospf':
			print('start to setup ospf cypher ...')
			secure_ospf(connection,payload['ospf_id'],payload['ospf_area'],payload['interfaces'],payload['ospf_pass'])
			self.send_response(200)
			self.end_headers()
			response = BytesIO()
			response.write(b'done')
			self.wfile.write(response.getvalue())
			print('ospf cypher done.')

		else:
			self.send_response(200)
			self.end_headers()
			response = BytesIO()
			response.write(b'This is POST request. ')
			response.write(b'Received: ')
			response.write(body)
			self.wfile.write(response.getvalue())


httpd = HTTPServer(('localhost', 8000), SimpleHTTPRequestHandler)
print('Serving at 8000')
httpd.serve_forever()

