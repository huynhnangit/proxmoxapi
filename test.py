#!/usr/bin/env python

import proxmoxapi

connectAPI = proxmoxapi.ProxmoxAPI("x.x.x.x", "8006", "root", "xxxxxxx")
if connectAPI.login():
	#connectAPI.get_resources()
	#connectAPI.get_api_version()
	#connectAPI.get_qemu_status(131, "proxmox2", True)
	#connectAPI.start_qemu_vm(131, "proxmox2")
	#connectAPI.get_next_vmid()
	#connectAPI.create_qemu_vm("proxmox2", "test2")
	#connectAPI.create_qemu_spiceproxy(131, "proxmox2")
