#!/usr/bin/env python

import json
import requests
from datetime import datetime
import os

#####
class PrintColor:
	BLUE 	= '\033[94m'
	GREEN 	= '\033[92m'
	YELLO 	= '\033[93m'
	RED 	= '\033[91m'
	ENDC 	= '\033[0m'

#####
class ProxmoxAPI:
	def __init__(self, ip, port, user, passwd):
		self.ip = ip
		self.port = port
		self.user = user
		self.passwd = passwd
		self.uri = "https://" + self.ip + ":" + self.port + "/api2/json/"
		self.cookie = ''
		self.token = ''
		self.nodes = []
	#
	def write_log(self, prefix, content):
		logPath = '/var/log/proxmoxapi.log'
		try:
			fo = open(logPath, 'a')
			now = datetime.now()
			nowFormat = now.strftime('%Y/%m/%d %H:%M:%S')
			fo.writelines(nowFormat + "\t" + prefix + content + "\n")
		except Exception, e:
			pass
		finally:
			fo.close()
	#
	def send_post_request(self, uri, data, headers):
		return requests.post(uri, data, headers=headers, verify=False)
	#
	def send_get_request(self, uri, headers):
		return requests.get(uri, headers=headers, verify=False)
	#
	def create_headers(self):
		headers = {
			"Accept" : "application/json",
			"Content-type": "application/x-www-form-urlencoded",
			"Host" : self.ip+":"+self.port,
			"Connection" : "keep-alive",
			"Cookie" : self.cookie,
			"CSRFPreventionToken" : self.token
		}
		return headers
	#
	def login(self):
		payload = {'username':self.user, 'password':self.passwd, 'realm':'pam'}
		size = len(payload)
		headers = {
			"Accept" : "application/json",
			"Content-type": "application/x-www-form-urlencoded",
			"Host" : self.ip+":"+self.port,
			"Content-Length" : size,
			"Connection" : "keep-alive"
		}
		uri = "https://" + self.ip + ":" + self.port + "/api2/extjs/access/ticket"
		#r = self.send_post_request(uri, payload, headers)
		r = requests.post(uri, payload, headers=headers, verify=False)
		isOK = False
		if r:
			self.cookie = "PVEAuthCookie=" + r.json()['data']['ticket']
			self.token = r.json()['data']['CSRFPreventionToken']
			isOK = True
		else:
			#print 'Cannot login proxmox server, plz check !'
			print r.status_code
			self.write_log("INFO: ", "Cannot login proxmox server")
			self.write_log("DEBUG: ", r.status_code)
		#	
		return isOK
	#
	def get_resources(self):
		uri = self.uri + "cluster/resources"
		#r = self.send_get_request(uri, self.create_headers())
		r = requests.get(uri, headers = self.create_headers(), verify=False)
		if r:
			num_of_host = len(r.json()['data'])
			prox1 = []
			prox2 = []
			for host in range (0, num_of_host):
				if r.json()['data'][host].get('vmid'):
					if r.json()['data'][host]['node'] == "proxmox1":
						prox1.append(r.json()['data'][host].get('vmid'))
					else:
						prox2.append(r.json()['data'][host].get('vmid'))
			#
			print PrintColor.GREEN + "\t\t\t >>>>> NODE: Proxmox1 <<<<<" + PrintColor.ENDC
			for host in sorted(prox1):
				print PrintColor.RED + ">>>>> VMID: " + str(host) + PrintColor.ENDC
				self.get_qemu_detail(host, "proxmox1")
			#
			print PrintColor.GREEN + "\t\t\t >>>>> NODE: Proxmox2 <<<<<" + PrintColor.ENDC
			for host in sorted(prox2):
				print PrintColor.RED + ">>>>> VMID: " + str(host) + PrintColor.ENDC
				self.get_qemu_detail(host, "proxmox2")
		else:
			print 'Cannot send request to api'
			print r.status_code
			self.write_log("INFO: ", "Cannot send request to api")
			self.write_log("DEBUG: ", r.status_code)
	#
	def get_api_version(self):
		uri = self.uri + "version"
		r = self.send_get_request(uri, self.create_headers())
		if r:
			print "Version : " + r.json()['data']['version']
		else:
			print 'Cannot send request to api'
			print r.status_code
			self.write_log("INFO: ", "Cannot send request to api")
			self.write_log("DEBUG: ", r.status_code)
	#
	def get_qemu_detail(self, vmid, node):
		uri = self.uri + "nodes/" + node + "/qemu/" + str(vmid) + "/status/current"
		r = self.send_get_request(uri, self.create_headers())
		if r:
			print "Name: " + r.json()['data']['name']
			print "Status: " + r.json()['data']['status']
			cpu = r.json()['data']['cpu']
			cpu = cpu * 100
			cpus = r.json()['data']['cpus']
			print "CPU usage: " + str(cpu) + "% of " + str(cpus) + " CPUs"
			mem = r.json()['data']['mem']
			mem = mem / 1048576
			maxmem = r.json()['data']['maxmem']
			maxmem = maxmem / 1048576
			print "Memory usage: " + "Used: " + str(mem) + "MB / Total: " + str(maxmem) + "MB"
			print "Uptime: " + convert_to_date(r.json()['data']['uptime'])
		else:
			print 'Cannot send request to api'
			print r.status_code
			self.write_log("INFO: ", "Cannot send request to api")
			self.write_log("DEBUG: ", r.status_code)
		#
	#
	def get_qemu_status(self, vmid, node, out):
		uri = self.uri + "nodes/" + node + "/qemu/" + str(vmid) + "/status/current"
		r = requests.get(uri, headers=self.create_headers(), verify=False)
		st = -1
		if r:
			status = r.json()['data']['status']
			qmpstatus = r.json()['data']['qmpstatus']
			if status == "running":
				if out == True:
					print "status: running"
				#
				if qmpstatus == "running":
					st = 0
				elif qmpstatus == "paused":
					st = 2
			elif status == "stopped":
				if out == True:
					print "status: stopped"
				#
				st = 1
		else:
			print 'Cannot send request to api'
			print r.status_code
			self.write_log("INFO: ", "Cannot send request to api")
			self.write_log("DEBUG: ", r.status_code)
		#
		return st
	#
	def start_qemu_vm(self, vmid, node):
		st = self.get_qemu_status(vmid, node, False)
		isOK = False
		if st == 0 or st == 2:
			print "VM %s already running" %(vmid)
		else:
			uri = self.uri + "nodes/" + node + "/qemu/" + str(vmid) + "/status/start"
			r = requests.post(uri, headers=self.create_headers(), verify=False)
			if r:
				isOK = True
			else:
				print 'Cannot send request to api'
				print r.status_code
				self.write_log("INFO: ", "Cannot send request to api")
				self.write_log("DEBUG: ", r.status_code)
		#
		return isOK
	#
	def stop_qemu_vm(self, vmid, node):
		st = self.get_qemu_status(vmid, node, False)
		isOK = False
		if st == 1:
			print "VM %s already stopped" %(vmid)
		else:
			uri = self.uri + "nodes/" + node + "/qemu/" + str(vmid) + "/status/stop"
			r = requests.post(uri, headers=self.create_headers(), verify=False)
			if r:
				isOK = True
			else:
				print 'Cannot send request to api'
				print r.status_code
				self.write_log("INFO: ", "Cannot send request to api")
				self.write_log("DEBUG: ", r.status_code)
		#
		return isOK
	#
	def reset_qemu_vm(self, vmid, node):
		st = self.get_qemu_status(vmid, node, False)
		isOK = False
		if st == 1:
			print "VM %s not running" %(vmid)
		else:
			uri = self.uri + "nodes/" + node + "/qemu/" + str(vmid) + "/status/reset"
			r = requests.post(uri, headers=self.create_headers(), verify=False)
			if r:
				isOK = True
			else:
				print 'Cannot send request to api'
				print r.status_code
				self.write_log("INFO: ", "Cannot send request to api")
				self.write_log("DEBUG: ", r.status_code)
		#
		return isOK
	#
	def suspend_qemu_vm(self, vmid, node):
		st = self.get_qemu_status(vmid, node, False)
		isOK = False
		if st == 1:
			print "VM %s not running" %(vmid)
		else:
			uri = self.uri + "nodes/" + node + "/qemu/" + str(vmid) + "/status/suspend"
			r = requests.post(uri, headers=self.create_headers(), verify=False)
			if r:
				isOK = True
			else:
				print 'Cannot send request to api'
				print r.status_code
				self.write_log("INFO: ", "Cannot send request to api")
				self.write_log("DEBUG: ", r.status_code)
		#
		return isOK
	#
	def resume_qemu_vm(self, vmid, node):
		st = self.get_qemu_status(vmid, node, False)
		isOK = False
		if st == 1:
			print "VM %s not running" %(vmid)
		else:
			uri = self.uri + "nodes/" + node + "/qemu/" + str(vmid) + "/status/resume"
			r = requests.post(uri, headers=self.create_headers(), verify=False)
			if r:
				isOK = True
			else:
				print 'Cannot send request to api'
				print r.status_code
				self.write_log("INFO: ", "Cannot send request to api")
				self.write_log("DEBUG: ", r.status_code)
		#
		return isOK
	#
	def get_next_vmid(self):
		uri = self.uri + "cluster/nextid"
		r = requests.get(uri, headers=self.create_headers(), verify=False)
		vmid = -1
		if r:
			vmid = r.json()['data']
		else:
			print 'Cannot send request to api'
			print r.status_code
			self.write_log("INFO: ", "Cannot send request to api")
			self.write_log("DEBUG: ", r.status_code)
		#
		return vmid
	#
	def get_node(self):
		uri = self.uri + "nodes"
		r = requests.get(uri, headers=self.create_headers(), verify=False)
		del self.nodes[:]
		if r:
			num_of_node = len(r.json()['data'])
			for node in range (0, num_of_node):
				self.nodes.append(r.json()['data'][node]['node'])
		else:
			print 'Cannot send request to api'
			print r.status_code
			self.write_log("INFO: ", "Cannot send request to api")
			self.write_log("DEBUG: ", r.status_code)
		#
	#
	def create_qemu_vm(self, node, name):
		isOK = False
		#
		self.get_node()
		if node in self.nodes:
			uri = self.uri + "nodes/" + node + "/qemu"
			vmid = self.get_next_vmid()
			payload = {'vmid':vmid, 'name':name, 'ostype':'l26', 'ide2':'iso:iso/CentOS-6.5-x86_64-netinstall.iso,media=cdrom', 'virtio0':'local:20,format=qcow2,cache=writeback', 'sockets':'1', 'cores':'4', 'memory':'512', 'net0':'virtio,bridge=vmbr0'}
			size = len(payload)
			#
			headers = {
				"Accept" : "application/json",
				"Content-type": "application/x-www-form-urlencoded",
				"Host" : self.ip+":"+self.port,
				"Content-Length" : size,
				"Connection" : "keep-alive",
				"Cookie" : self.cookie,
				"CSRFPreventionToken" : self.token
			}
			#
			r = requests.post(uri, payload, headers=headers, verify=False)
			if r:
				isOK = True
			else:
				print 'Cannot send request to api'
				print r.status_code
				self.write_log("INFO: ", "Cannot send request to api")
				self.write_log("DEBUG: ", r.status_code)
		else:
			print "Node %s don't exist" %(node)
			
		#
		return isOK
	#
	def check_qemu_vmid(self, vmid, node):
		#
		uri = self.uri + "nodes/" + node + "/qemu/" + str(vmid) + "/status"
		r = requests.get(uri, headers=self.create_headers(), verify=False)
		if r:
			isOK = True
		else:
			isOK = False
		#
		return isOK
		
	#
	def delete_qemu_vm(self, vmid, node):
		isOK = False
		#
		self.get_node()
		if node in self.nodes:
			if self.check_qemu_vmid(vmid, node):
				uri = self.uri + "nodes/" + node + "/qemu/" + str(vmid)
				r = requests.delete(uri, headers=self.create_headers(), verify=False)
				if r:
					isOK = True
				else:
					print 'Cannot send request to api'
					print r.status_code
					self.write_log("INFO: ", "Cannot send request to api")
					self.write_log("DEBUG: ", r.status_code)
			else:
				print "VM %s don't exits" %(str(vmid))
		else:
			print "Node %s don't exist" %(node)
		#
		return isOK
	#
	def write_virt_viewer(self, f_path, content):
		try:
			fo = open(f_path, 'a')
			fo.writelines(content+"\n")
		except Exception, e:
			pass
		finally:
			fo.close()
	#
	def create_qemu_spiceproxy(self, vmid, node):
		isOK = False
		#
		self.get_node()
		if node in self.nodes:
			if self.check_qemu_vmid(vmid, node):
				uri = self.uri + "nodes/" + node + "/qemu/" + str(vmid) + "/spiceproxy"
				r = requests.post(uri, headers=self.create_headers(), verify=False)
				if r:
					isOK = True
					f_path="/usr/local/src/tmp.vv"
					os.remove(f_path)
					
					self.write_virt_viewer(f_path, "[virt-viewer]")
					
					content = "secure-attention=" + r.json()['data']['secure-attention']
					self.write_virt_viewer(f_path, content)
					
					content = "ca=" + r.json()['data']['ca']
					self.write_virt_viewer(f_path, content)
					
					content = "delete-this-file=" + str(r.json()['data']['delete-this-file'])
					self.write_virt_viewer(f_path, content)
					
					content = "host-subject=" + r.json()['data']['host-subject']
					self.write_virt_viewer(f_path, content)
					
					content = "host=" + r.json()['data']['host']
					self.write_virt_viewer(f_path, content)
					
					content = "password=" + r.json()['data']['password']
					self.write_virt_viewer(f_path, content)
					
					content = "release-cursor=" + r.json()['data']['release-cursor']
					self.write_virt_viewer(f_path, content)
					
					content = "type=" + r.json()['data']['type']
					self.write_virt_viewer(f_path, content)
					
					content = "title=" + r.json()['data']['title']
					self.write_virt_viewer(f_path, content)
					
					content = "proxy=" + r.json()['data']['proxy']
					self.write_virt_viewer(f_path, content)
					
					content = "tls-port=" + str(r.json()['data']['tls-port'])
					self.write_virt_viewer(f_path, content)
					
					content = "toggle-fullscreen=" + r.json()['data']['toggle-fullscreen']
					self.write_virt_viewer(f_path, content)
					
				else:
					print 'Cannot send request to api'
					print r.status_code
					self.write_log("INFO: ", "Cannot send request to api")
					self.write_log("DEBUG: ", r.status_code)
			else:
				print "VM %s don't exits" %(str(vmid))
		else:
			print "Node %s don't exist" %(node)
		#
		return isOK
	#
	
###
def convert_to_date(secs):
	h = (secs / 3600)
	m = ((secs % 3600) / 60)
	s = (secs % 60)
	if h > 24:
		d = (h / 24)
		h = h - (d * 24)
		return "%s days, %s:%s:%s" %(d, h, m, s)
	else:
		return "%s:%s:%s" %(h, m, s)
#