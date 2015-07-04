#!/usr/bin/env python
#@author: Prahlad Yeri
#@description: Small daemon to create a wifi hotspot on linux
#@license: MIT
import sys
import os
import argparse
import cli
import json
import socket
import platform
import time

class Proto:
	pass

const = Proto()

#global const = Proto() #struct to hold startup parameters
#const.debug = False
#const.verbose = False
#const.command = 'start'
#const.argv = None

stores = Proto() #struct to dump misc variables
stores.running  = False

def validate_ip(addr):
	try:
		socket.inet_aton(addr)
		return True # legal
	except socket.error:
		return False # Not legal

def configure():
	dc = json.load(open('hotspotd.json'))
	Netmask = dc["netmask"]
	SSID = dc["SSID"]
	password = dc["password"]
	IP = dc["ip"]
	wlan = dc["wlan"]
	ppp = dc["inet"]

	f = open('run.dat','r')
	lout=[]
	global driver
	driver = "nl80211"
	if os.path.exists("/etc/rpi-isssue"):
		driver = "rtl871xdrv"
	for line in f.readlines():
		lout.append(line.replace('<SSID>',SSID).replace('<PASS>',password).replace('<INTERFACE>',wlan).replace('<DRIVER>',driver))

	f.close()
	f = open('run.conf','w')
	f.writelines(lout)
	f.close()

	print 'created hostapd configuration: run.conf'

	dc = {'wlan': wlan, 'inet':ppp, 'ip':IP, 'netmask':Netmask, 'SSID':SSID, 'password':password}
	json.dump(dc, open('hotspotd.json','wb'))

def check_dependencies():
	#CHECK FOR DEPENDENCIES
	if len(cli.check_sysfile('hostapd'))==0:
		print 'hostapd executable not found. Make sure you have installed hostapd.'
		return False
	elif len(cli.check_sysfile('dnsmasq'))==0:
		print 'dnsmasq executable not found. Make sure you have installed dnsmasq.'
		return False
	else:
		return True

def check_interfaces():
	global wlan, ppp
	print 'Verifying interfaces'
	s=cli.execute_shell('ifconfig')
	lines = s.splitlines()
	bwlan = False
	bppp  = False

	for line in lines:
		if not line.startswith(' ') and len(line)>0:
			text=line.split(' ')[0]
			if text.startswith(wlan):
				bwlan = True
			elif text.startswith(ppp):
				bppp = True

	if not bwlan:
		print wlan + ' interface was not found. Make sure your wifi is on.'
		return False
	elif not bppp:
		print ppp + ' interface was not found. Make sure you are connected to the internet.'
		return False
	else:
		print 'done.'
		return True

def pre_start():
	try:
		# oper = platform.linux_distribution()
		# if oper[0].lower()=='ubuntu' and oper[2].lower()=='trusty':
			# trusty patch
		# print 'applying hostapd workaround for ubuntu trusty.'
		#29-12-2014: Rather than patching individual distros, lets make it a default.
		result = cli.execute_shell('nmcli radio wifi off')
		if "error" in result.lower():
			cli.execute_shell('nmcli nm wifi off')
		cli.execute_shell('rfkill unblock wlan')
		cli.execute_shell('sleep 1')
		print 'done.'
	except:
		pass

def start_router():
	if not check_dependencies():
		return
	elif not check_interfaces():
		return
	pre_start()
	s = 'ifconfig ' + wlan + ' up ' + IP + ' netmask ' + Netmask
	print 'created interface: mon.' + wlan + ' on IP: ' + IP
	r = cli.execute_shell(s)
	cli.writelog(r)
	#cli.writelog('sleeping for 2 seconds.')
	print 'wait..'
	cli.execute_shell('sleep 2')
	i = IP.rindex('.')
	ipparts=IP[0:i]

	#stop dnsmasq if already running.
	if cli.is_process_running('dnsmasq')>0:
		print 'stopping dnsmasq'
		cli.execute_shell('killall dnsmasq')


	#stop hostapd if already running.
	if cli.is_process_running('hostapd')>0:
		print 'stopping hostapd'
		cli.execute_shell('killall hostapd')

	#enable forwarding in sysctl.
	print 'enabling forward in sysctl.'
	r=cli.set_sysctl('net.ipv4.ip_forward','1')
	print r.strip()

	#enable forwarding in iptables.
	print 'creating NAT using iptables: ' + wlan + '<->' + ppp
	cli.execute_shell('iptables -P FORWARD ACCEPT')

	#add iptables rules to create the NAT.
	cli.execute_shell('iptables --table nat --delete-chain')
	cli.execute_shell('iptables --table nat -F')
	r=cli.execute_shell('iptables --table nat -X')
	if len(r.strip())>0: print r.strip()
	cli.execute_shell('iptables -t nat -A POSTROUTING -o ' + ppp +  ' -j MASQUERADE')
	cli.execute_shell('iptables -A FORWARD -i ' + ppp + ' -o ' + wlan + ' -j ACCEPT -m state --state RELATED,ESTABLISHED')
	cli.execute_shell('iptables -A FORWARD -i ' + wlan + ' -o ' + ppp + ' -j ACCEPT')

	#allow traffic to/from wlan
	cli.execute_shell('iptables -A OUTPUT --out-interface ' + wlan + ' -j ACCEPT')
	cli.execute_shell('iptables -A INPUT --in-interface ' + wlan +  ' -j ACCEPT')


	#start dnsmasq
	s = 'dnsmasq --dhcp-authoritative --interface=' + wlan + ' --dhcp-range=' + ipparts + '.20,' + ipparts +'.100,' + Netmask + ',4h'
	print 'running dnsmasq'
	r = cli.execute_shell(s)
	cli.writelog(r)

	#~ f = open(os.getcwd() + '/hostapd.tem','r')
	#~ lout=[]
	#~ for line in f.readlines():
		#~ lout.append(line.replace('<SSID>',SSID).replace('<PASS>',password))
		#~
	#~ f.close()
	#~ f = open(os.getcwd() + '/hostapd.conf','w')
	#~ f.writelines(lout)
	#~ f.close()

	#writelog('created: ' + os.getcwd() + '/hostapd.conf')
	#start hostapd
	#s = 'hostapd -B ' + os.path.abspath('run.conf')
	s = 'hostapd -B ' + os.getcwd() + '/run.conf'
	cli.writelog('running hostapd')
	#cli.writelog('sleeping for 2 seconds.')
	cli.writelog('wait..')
	cli.execute_shell('sleep 2')
	r = cli.execute_shell(s)
	cli.writelog(r)
	print 'hotspot is running.'
	return

def stop_router():
	#bring down the interface
	cli.execute_shell('ifconfig mon.' + wlan + ' down')

	#TODO: Find some workaround. killing hostapd brings down the wlan0 interface in ifconfig.
	#~ #stop hostapd
	#~ if cli.is_process_running('hostapd')>0:
		#~ cli.writelog('stopping hostapd')
		#~ cli.execute_shell('pkill hostapd')

	#stop dnsmasq
	if cli.is_process_running('dnsmasq')>0:
		cli.writelog('stopping dnsmasq')
		cli.execute_shell('killall dnsmasq')

	#disable forwarding in iptables.
	cli.writelog('disabling forward rules in iptables.')
	cli.execute_shell('iptables -P FORWARD DROP')

	#delete iptables rules that were added for wlan traffic.
	if wlan != None:
		cli.execute_shell('iptables -D OUTPUT --out-interface ' + wlan + ' -j ACCEPT')
		cli.execute_shell('iptables -D INPUT --in-interface ' + wlan +  ' -j ACCEPT')
	cli.execute_shell('iptables --table nat --delete-chain')
	cli.execute_shell('iptables --table nat -F')
	cli.execute_shell('iptables --table nat -X')
	#disable forwarding in sysctl.
	cli.writelog('disabling forward in sysctl.')
	r = cli.set_sysctl('net.ipv4.ip_forward','0')
	print r.strip()
	#cli.execute_shell('ifconfig ' + wlan + ' down'  + IP + ' netmask ' + Netmask)
	#cli.execute_shell('ip addr flush ' + wlan)
	print 'hotspot has stopped.'
	return

def main(args):
	global wlan, ppp, IP, Netmask


	scpath = os.path.realpath(__file__)
	realdir = os.path.dirname(scpath)
	os.chdir(realdir)
	#print 'changed directory to ' + os.path.dirname(scpath)
	#if an instance is already running, then quit
	#const.verbose = args.verbose
	#const.command = args.command
	#const.blocking = args.blocking
	#const.argv = [os.getcwd() + '/server.py'] + sys.argv[1:]
	cli.arguments = args #initialize

	newconfig = False
	configure()
	if not os.path.exists('hotspotd.json'):
		newconfig=True
	if len(cli.check_sysfile('hostapd'))==0:
		print "hostapd is not installed on your system. This package will not work without it. To install it, try 'sudo apt-get install hostapd' or http://wireless.kernel.org/en/users/Documentation/hostapd after this installation is over."
		time.sleep(2)
	dc =json.load(open('hotspotd.json'))
	wlan = dc['wlan']
	ppp = dc['inet']
	IP=dc['ip']
	Netmask=dc['netmask']
	SSID = dc['SSID']
	password = dc['password']

	if args.command == 'configure':
		if not newconfig: configure()
	elif args.command == 'stop':
		stop_router()
	elif args.command == 'start':
		if (cli.is_process_running('hostapd') != 0 and cli.is_process_running('dnsmasq') != 0):
			print 'hotspot is already running.'
		else:
			start_router()
