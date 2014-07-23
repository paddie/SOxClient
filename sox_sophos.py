#!/usr/bin/env python
# encoding: utf-8

import os, plistlib, time, sys, socket
from datetime import datetime, date
from uuid import getnode as get_mac
import platform
import subprocess
import tempfile
import httplib
import json

# sophos antivirus log is in binary format => convert to xml1
def plistFromPath(plist_path):
    # convertPlist(plist_path, 'xml1')
    if os.system('plutil -convert xml1 '+ plist_path) != 0:
        print 'failed to convert plist from path: ', plist_path
        sys.exit(1)
    try:
    	return plistlib.plistFromPath(plist_path)
    except AttributeError: # there was an AttributeError, we may need to use the older method for reading the plist
    	try:
    		return plistlib.Plist.fromFile(plist_path)
    	except:
    		print 'failed to read plist'
    		sys.exit(5)

def convertToXML(path):
    # convertPlist(plist_path, 'xml1')
	tmp_path = os.path.join("/var/tmp", "com.application_walking_tmp.plist")
    # tmp_path = "/Library/AdPeople/com.application_walking_tmp.plist"
	subprocess.call(['cp', path, tmp_path])
	if os.system('plutil -convert xml1 '+ tmp_path) != 0:
		raise Exception("Could not convert binary plist to xml1")
	
	plist = plistlib.readPlist(tmp_path)
	subprocess.call(['rm', tmp_path])
	return plist

def runProcess(exe):    
    p = subprocess.Popen(exe, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while(True):
        retcode = p.poll() #returns None while subprocess is running
        line = p.stdout.readline()
        yield line
        if(retcode is not None):
            break

# """
# Software Update Tool
# Copyright 2002-2009 Apple

# Software Update found the following new or updated software:
#    * iTunesX-11.0.1
#     iTunes (11.0.1), 193391K [recommended]
# """
# lists all pending sopftware updates
def softwareupdate(doc):
    # subprocess.check_output(*popenargs, **kwargs)
    collect_info = False
    pending_updates = ""
    for l in runProcess(["softwareupdate", "-l"]):
        print l
        if "No new software available" in l:
            doc.update({"softwareupdate":False})
            return

        if collect_info is False and "Software Update found" in l:
            collect_info = True

        if collect_info:
            pending_updates += l

    print "pending updates: ", pending_updates

    doc.update({
        "softwareupdate":True,
        "softwareoutput":pending_updates
        })
     # = subprocess.Popen(["softwareupdate", "-l"],).split("\n")

# returns the CFBundleShortVersionString of any application. Effectively the version
# ID of any application (if the programmers have been kind enough to set it)
def plist_version(path):
	plist = "N/A"
	try:
		plist = plistlib.readPlist(path)
	except:
	    try:
			plist = convertToXML(path)
	    except:
	        return "N/A"
	try:
		return plist["CFBundleShortVersionString"]
	except:
		return "N/A"

# List all installed applications
# - we no longer report this list, to speed up the reporting.
def installed_apps(doc):
	# apps = walk()
    # tf = tempfile.TemporaryFile("w+b")
    apps = subprocess.Popen(["/usr/sbin/system_profiler","-xml","SPApplicationsDataType"],stdout=subprocess.PIPE).communicate()[0]
    # tf.write(apps)
    # tf.seek(0)
    plist = plistlib.readPlistFromString(apps)
    apps = plist[0]["_items"]
    for i in xrange(0,len(apps)):
        date = apps[i].get('lastModified', None)
        if date is not None:
            apps[i]['lastModified'] = date.isoformat()
        else:
            apps[i]['lastModified'] = None

    doc.update( {"apps":apps} )

# Updates the dict with all the sophos antivirus related information
# - SAV, Engine and the time of last update.
def sophos_dict(doc):
    if not os.path.isfile('/Applications/Sophos Anti-Virus.app/Contents/Info.plist'):
        return doc.update({
            'virus_version':"N/A",
            'virus_def':"N/A",
            'virus_last_run':"N/A"})    

    version = plist_version('/Applications/Sophos Anti-Virus.app/Contents/Info.plist')
    v_def, mtime = log_information()
    return doc.update({
        'virus_version':version,
        'virus_def':v_def,
        'virus_last_run':mtime,
    })

# parse the log for information pertaining to the most recent 
# sophos update. Returns the version of the virus definitions and the time of last update.
# - using the modified time of the latest update migth not be the best approach
#   but it has served decently so far.
def log_information(path='/Library/Logs/Sophos Anti-Virus.log'):
    if os.path.isfile(path):
        log = open(path, 'r')
        for lines in log:
            if 'com.sophos.intercheck: Version' in lines:
                vers = lines
        mtime = time.strftime("%d/%m/%y",time.localtime(os.path.getmtime(path)))
        log.close()
        
        return vers.split(": ")[1].split(",")[0][7:], mtime
        # return vers[31:-15], mtime
    else:
        # if no log is at this position
        return "N/A", "N/A"

# In /usr/libexec/ApplicationFirewall is the Firewall command, the binary of the actual application layer firewall and socketfilterfw,
# which configures the firewall. To configure the firewall to block all incoming traffic:
# /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on

# A couple of global options that can be set. Stealth Mode:
# /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# Firewall logging:
# /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on

# To start the firewall:
# /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

def char_int_to_bool(char):
    if char == "0":
        return False

    return True

# Get firewall: stealth, logging and globalstate settings
def firewall(doc):
    # /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
    fw_plist = "/Library/Preferences/com.apple.alf"

    fw_globalstate = subprocess.Popen(["/usr/bin/defaults", "read", fw_plist, "globalstate"],stdout=subprocess.PIPE).communicate()[0][:-1]
    fw_mode = int(fw_globalstate)
    fw_globalstate = char_int_to_bool(fw_globalstate)

    fw_logging = subprocess.Popen(["/usr/bin/defaults", "read", fw_plist, "loggingenabled"],stdout=subprocess.PIPE).communicate()[0][:-1]
    fw_logging = char_int_to_bool(fw_logging)

    fw_stealth = subprocess.Popen(["/usr/bin/defaults", "read", fw_plist, "stealthenabled"],stdout=subprocess.PIPE).communicate()[0][:-1]
    fw_stealth = char_int_to_bool(fw_stealth)
    # print "firewall", fw_globalstate,"fw_stealth: ", fw_stealth, "fw_logging:",fw_logging

    doc.update({
        "firewall":fw_globalstate,
        "fw_mode":fw_mode,
        "fw_stealth":fw_stealth,
        "fw_logging":fw_logging,
    })

# Check for the existence of the recon agent along with the installed version etc.
def recon_dict(doc):
    # old = "/Library/Application Support/JAMF/scripts/submitInventory.sh"
    new = "/Library/Application Support/WPP/Inventory/scripts/submitInventory.sh"

    recon_conf = "/Library/Application Support/WPP/Inventory/conf/com.wpp.recon"

    recon_version = "N/A"
    if os.path.isfile(recon_conf + ".plist"):
        # print "file exists"
        # recon_version = subprocess.call(["/usr/bin/defaults", "read", recon_conf, "version"])
        recon_version = subprocess.Popen(["/usr/bin/defaults", "read", recon_conf, "version"],stdout=subprocess.PIPE).communicate()[0][:-1]


    doc.update({
        'recon':os.path.isfile(new),
        'recon_version':recon_version}
    )

# Run through every network interface and return only if one of the ips
 # are prefixed by 152.146..
def getIP():
    ips = []
    for i in xrange(5):
        interface = "en" + str(i)
        ip = subprocess.Popen(["/usr/sbin/ipconfig", "getifaddr", interface], stdout=subprocess.PIPE).communicate()[0][0:-1]
        if len(ip) > 0:
            ips.append(ip)

    ip = ""
    if len(ips) > 0:
        for i in ips:
            if "152.146." in i:
                ip = i
                break

    return ip

# Read machine specific information
# - ip, hostname, serial, cpu, cores, memory..
def machine_dict(doc):
    # machine specific info
    profile = subprocess.Popen(["/usr/sbin/system_profiler","-xml","SPHardwareDataType"], stdout=subprocess.PIPE).communicate()[0]
    # read xml into plit-file, and ignore irrelevant data..
    machine = plistlib.readPlistFromString(profile)[0]["_items"][0]

    # *******************
    # OSX version and build
    # *******************
    l = subprocess.Popen(["sw_vers"],
        stdout=subprocess.PIPE).communicate()[0].split("\n")
    osx_vers = "OSX %s (%s)" % (l[1].split(":\t")[-1],l[2].split(":\t")[-1])

    ip = getIP()

    # *****************************
    # HOSTNAME - use scutil to read computer names etc.
    # *****************************
    computername = subprocess.Popen(["/usr/sbin/scutil","--get", "ComputerName"],stdout=subprocess.PIPE).communicate()[0].split("\n")[0]
    localhostname = subprocess.Popen(["/usr/sbin/scutil","--get", "LocalHostName"],stdout=subprocess.PIPE).communicate()[0].split("\n")[0]
    hostname = subprocess.Popen(["/usr/sbin/scutil","--get", "HostName"],stdout=subprocess.PIPE).communicate()[0].split("\n")[0]
    # defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server NetBIOSName
    netbios_name = subprocess.Popen(["/usr/bin/defaults", "read", "/Library/Preferences/SystemConfiguration/com.apple.smb.server", "NetBIOSName"],stdout=subprocess.PIPE).communicate()[0].split("\n")[0]

    doc.update({
        '_id':machine["serial_number"],
        # 'Old_serial':old_serial,
        'osx':str(osx_vers),
        'model':machine["machine_model"],
        'hostname':computername.split(".")[0],
        'device_names': {
            'computername':computername.split(".")[0],
            'hostname':hostname.split(".")[0],
            'localhostname':localhostname.split(".")[0],
            'netbiosname':netbios_name.lower(),    
        },        
        'cpu':"%s %s" % (machine["cpu_type"], machine["current_processor_speed"]),
        'cores':machine["number_processors"],
        'memory':machine["physical_memory"][0:-3],
        'ip':ip,
    })

# get a list of users in the '/Users' folder.
# Ignores any files that are not folders, along with the 'Shared' folder.
def users():
    # lists all folders '/Users'
    # - discards: Shared and any files in that folder
    users = []
    for folder in os.listdir('/Users'):
        # ignore files
		if not folder == 'Shared' and os.path.isdir('/Users/'+folder):
		    users.append(folder)
    if os.path.isdir("/Domain/PeopleGroup.Internal/Users"):
        for folder in os.listdir('/Domain/PeopleGroup.Internal/Users'):
            # ignore files
    		if os.path.isdir('/Domain/PeopleGroup.Internal/Users/'+folder):
    		    users.append(folder)

    return users

def postMachineSpecs(ip, doc):
    params = json.dumps(doc)
    # print params
    try:
        headers = {"Content-Type": "application/json"}
        conn = httplib.HTTPConnection(ip)
        conn.request("POST", "/updateMachine/", params, headers)
        print "SOX script: Success!"
    except Exception:
        print "Couldn't connect to webserver on ip: ", ip
        print "Retrying in an hour.."
    # urllib2.urlopen("localhost:6060/updateMachine", jdata)

# Class for storing a single access point
class Network():
    """using url: http://osxdaily.com/2007/01/18/airport-the-little-known-command-line-wireless-utility/"""
    def __init__(self, ssid="N/A", bssid="N/A", sec=[], rssi=0, ip="", hostname=""):
        self.ssid = ssid
        self.bssid = bssid
        self.rssi = rssi
        # self.noise = noise
        self.sec = sec
        self.ip = ip
        self.hostname = hostname
        # self.hostname

def scan_w(ip, hostname):
    if ip == "":
        print "Device not on local network. IP not in '152.146' range.",
        return

    airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

    ssids = []
    if os.path.isfile(airport_path):
        plist_str = subprocess.Popen([airport_path, "-s", "-x"],stdout=subprocess.PIPE).communicate()[0]
        if len(plist_str) == 0:
            return
        plist_dict = plistlib.readPlistFromString(plist_str)

        for d in plist_dict:

            ssid = d.get("SSID_STR")
            bssid = d.get("BSSID")
            rssi = d.get("RSSI")
            # noise = d.get("NOISE")

            # Decode security fields
            sec = []
            # RSN (Robust Security Network) = WPA2
            if "RSN_IE" in d:
                sec.append("WPA2")

            # WPA... = WPA
            if "WPA_IE" in d:
                sec.append("WPA")
            
            n = Network(ssid, bssid, sec, rssi, ip, hostname)
            ssids.append(n.__dict__)
        print "posting wireless data.."
        postWirelessScan("152.146.38.56:6060", ssids)
    else:
        print "No 'airport' utility located in " + airport_path

# def postWirelessScan(ip, ssids):
#     params = json.dumps(ssids)
#     try:
#         headers = {"Content-type": "application/x-www-form-urlencoded",
#                 "Accept": "text/plain"}
#         conn = httplib.HTTPConnection(ip)
#         conn.request("POST", "/reportWirelessScan/", params, headers)
#         print "Wireless scan completed."
#     except Exception:
#         print "Couldn't connect to webserver on ip: ", ip

def main():
    # server_ip = "localhost:6060" # localhost
    
    doc = {
        'users':users(),
        "script_v" : subprocess.Popen(["/usr/local/git/bin/git","describe"],stdout=subprocess.PIPE).communicate()[0][:-1],
    }
    # get ip, hostname etc.
    machine_dict(doc)
    # sophos related info
    sophos_dict(doc)
    # firewall setting etc.
    firewall(doc)
    # check for recon, version etc.
    recon_dict(doc)
    # check if there are any critical security updates
    softwareupdate(doc)

    ip = doc["ip"]
    hostname = doc["hostname"]
    # scan for wireless networks to help with diagnostics
    # print "scanning for wireless networks: ip = ", ip
    # scan_w(ip, hostname)

    server_ip = "152.146.38.56:6060" # static IP for the mini-server 
    postMachineSpecs(server_ip, doc)
    
if __name__ == '__main__':
	main()