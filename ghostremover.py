import pydivert
import threading
import requests
import json
import socket

blockedips = set()
playerips = set()

playerips.add(socket.gethostbyname(socket.gethostname()))

def block(ip):
	if not type(ip) is str:
		print("IP must be in string format. An example block would be: block('69.168.1.30')")
		return

	blockedips.add(ip)

	print("Successfully added " + ip + " to the block list.")
	
	try:
		f = open("C:/eu4_blocked_ips.log", "a")
		f.write(ip + "\n")
		f.close()
	except:
		print("Failed to write to C:/eu4_blocked_ips.log. (unnecessary for script to function)")

def unblock(ip):
	if not type(ip) is str:
		print("IP must be in string format. An example block would be: unblock('69.168.1.30')")
		return

	blockedips.remove(ip)
	playerips.remove(ip)	

	print("Successfully removed " + ip + " from the block list.")
	

def loadlogfile():
	try:
		f2 = open("C:/eu4_blocked_ips.log", "r")
		ips = f2.read().split("\n")
		for x in ips:
			print("Blocking " + x)
			blockedips.add(x)
		f2.close()
	except:
		print("Failed to load log file. Is the file empty?")

def getinfo(ip):
	if not type(ip) is str:
		print("IP must be in string format. An example block would be: getinfo('69.168.1.30')")
		return
	try:
		r = requests.get("http://ipinfo.io/" + ip + "/json", verify=False)
	except:
		print("\nConnection refused by ipinfo for " + ip + ", check if this is a Valve server manually.")
		return	
	
	data = r.json()
	
	if "Valve Corporation" in data["org"]:
		blockedips.add(ip)
		print("Blocked NAT attmept from " + ip)
	else:
		print("\nNew connection from " + ip + " from " + data["region"] + ", " + data["country"] + ".")

def networking():
	with pydivert.WinDivert("udp.PayloadLength > 0") as w:
		for packet in w:
			if "6e2801004b28" in packet.payload.hex() and packet.src_addr not in playerips:
				if not packet.src_addr in playerips:
					playerips.add(packet.src_addr)
					try:			
						getinfo(packet.src_addr)
					except:
						print("\nNew connection from " + packet.src_addr)
			if packet.src_addr in blockedips or packet.dst_addr in blockedips:
				packet.payload = "\x00\x01\x02".encode()
			w.send(packet)

threading.Thread(name='networking', target=networking).start() # required multithreading to allow user input without pausing windivert

print("\nEU4 Ghost Remover by Mastoid & KLS loaded.\n")
print("Type loadlogfile() to load previously blocked IP addresses into the current session. (recommended)")
print("Type block('ip here') to block an IP address.")
print("Type unblock('ip here') to unblock an IP address.")
