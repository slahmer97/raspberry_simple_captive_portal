import threading
import atexit
import datetime
import ipaddress
import hashlib
import argparse
import sqlite3
import subprocess
from flask import Flask, request
from flask import jsonify,render_template
class CaptivePortal:
	def __init__(self, interface="wlan0", server_ip_addr = "10.3.141.1", server_port=9999):
		# Disable Forwarding for @interface
		self.conn = sqlite3.connect('database.db')
		self.init_db()
		self.interface = interface
		self.server_ip_addr = server_ip_addr
		self.server_port = server_port
		self.max_connections = 1
		tmp = ipaddress.ip_address(server_ip_addr)
		if isinstance(tmp, ipaddress.IPv4Address):
			self.iptables = "iptables"
		elif isinstance(tmp, ipaddress.IPv6Address):
			self.iptables = "ip6tables"
		else:
			print ("[!] no ip type found, default ipv4")
			self.iptables = "iptables"
		subprocess.call([self.iptables, "-A", "FORWARD", "-i", interface, "-p", "tcp", "--dport", "53", "-j" ,"ACCEPT"])
		subprocess.call([self.iptables, "-A", "FORWARD", "-i", interface, "-p", "udp", "--dport", "53", "-j" ,"ACCEPT"])
		subprocess.call([self.iptables, "-A", "FORWARD", "-i", interface, "-p", "tcp", "--dport", 
				 str(server_port),"-d", server_ip_addr, "-j" ,"ACCEPT"])
		subprocess.call([self.iptables, "-A", "FORWARD", "-i", interface, "-j" ,"DROP"])
	def exit(self):
		subprocess.call([self.iptables, "-D", "FORWARD", "-i", interface, "-p", "tcp", "--dport", "53", "-j" ,"ACCEPT"])
		subprocess.call([self.iptables, "-D", "FORWARD", "-i", interface, "-p", "udp", "--dport", "53", "-j" ,"ACCEPT"])
		subprocess.call([self.iptables, "-D", "FORWARD", "-i", interface, "-p", "tcp", "--dport",
				str(self.server_port),"-d", self.server_ip_addr, "-j" ,"ACCEPT"])
		subprocess.call([self.iptables, "-D", "FORWARD", "-i", interface, "-j" ,"DROP"])
	def init_db(self):
		query = """CREATE TABLE users (
			user_id INTEGER PRIMARY KEY,
			first_name TEXT NOT NULL,
			last_name TEXT NOT NULL,
			email TEXT NOT NULL UNIQUE,
			username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL
			);"""
		query2 = """
			CREATE TABLE users_connections(
   			connection_id INTEGER,
   			connection_time timestamp,
			connection_ip TEXT NOT NULL,
			connection_ip_version INTEGER,
			user_id INTEGER NOT NULL,
   			FOREIGN KEY (user_id)
				REFERENCES users(user_id)
			);
			"""
		try:
			self.conn.execute(query)
			self.conn.execute(query2)
		except Exception as inst:
			print("E : {}".format(inst))
	def authenticate(self, username, password):
		con = sqlite3.connect("database.db")
		con.row_factory = sqlite3.Row
		cur = con.cursor()
		cur.execute("select * from users WHERE username=? AND password=?",(username, password))
		rows = cur.fetchall();
		if len(rows):
			return rows[0]["user_id"]
		return None
	def add_new_connection(self, user_id, remote_ip):
		subprocess.call([self.iptables,"-t", "nat", "-I", "PREROUTING","-s", remote_ip, "-j" ,"ACCEPT"])
		subprocess.call([self.iptables, "-I", "FORWARD", "-s", remote_ip, "-j" ,"ACCEPT"])
		#self.wfile.write("You are now authorized. Navigate to any URL")
		con = sqlite3.connect('database.db')
		cur = con.cursor()
		tmp = ipaddress.ip_address(remote_ip)
		if isinstance(tmp, ipaddress.IPv4Address):
			ver = 4
		elif isinstance(tmp, ipaddress.IPv6Address):
			ver = 6
		else:
			print("[!] add_new_connection() ip version is unknown")
			ver = 4
		try:
			cur.execute(
                	"""INSERT INTO users_connections (connection_time,connection_ip, connection_ip_version, user_id)
		   	VALUES (?,?,?,?)"""
		   	,(datetime.datetime.now(), remote_ip, ver, user_id) )
			con.commit()
		except Exception as inst:
			con.rollback()
			print("[!] E : {}".format(inst))
	def get_user_connections_count(self, user_id):
		return 1
	def authorize(self, user_id, ip):
		print( "user_id : {} -- ip : {}".format(user_id, ip))
		if self.get_user_connections_count(user_id) <= self.max_connections:
			self.add_new_connection(user_id, ip)
			return "You are authorize now to start surfing the internet ^^ ;)"
		errors = {}
		errors["error"] = "Your account allow you to have only 5 simultanuous connections ^^"
		return render_template("error.html",errors = errors)
	def run_captive_portal_server(self):
		pass


#a = CaptivePortal()

import atexit

captive_portal = None

def exit_handler():
    global captive_portal
    captive_portal.exit()
    print ('aMy application is wending!')

atexit.register(exit_handler)

app = Flask(__name__)

@app.route("/list_connections")
def list_connections():
	con = sqlite3.connect("database.db")
	con.row_factory = sqlite3.Row
	cur = con.cursor()
	cur.execute("""
		select users.username, users.email,
		       users_connections.connection_time,
		       users_connections.connection_ip,
                       users_connections.connection_ip_version
		from users, users_connections
		WHERE users.user_id = users_connections.user_id
		""")
	rows = cur.fetchall();
	return render_template("list_connections.html",rows = rows)

@app.route('/')
def cp_home():
    return 'ip addr = {}'.format(request.remote_addr)
@app.route("/list_users", methods=["GET", "POST"])
def list_users():
  con = sqlite3.connect("database.db")
  con.row_factory = sqlite3.Row
  cur = con.cursor()
  cur.execute("select * from users")
  rows = cur.fetchall();
  return render_template("list_users.html",rows = rows)
@app.route('/add_user', methods=["POST"])
def add_user():
  try:
    first_name = request.form["first_name"]
    last_name = request.form["last_name"]
    password = request.form["password"]
    password = hashlib.sha224(password.encode()).hexdigest()
    email = request.form["email"]
    username = request.form["username"]
    print("fn : {} -- ln : {} -- password : {} -- email : {} -- username : {}".format(first_name,last_name,password,email,username))
    con = sqlite3.connect('database.db')
    cur = con.cursor()
    cur.execute(
		"""INSERT INTO users (first_name,last_name,username, password, email)
               VALUES (?,?,?,?,?)"""
		,(first_name, last_name, username, password, email) )
    con.commit()
    return "added"
  except Exception as inst:
    return "E : {}".format(inst)

@app.route('/add_new_user', methods = ['POST', 'GET'])
def add_user_template():
  return render_template("add_new_user.html")

@app.route('/user_auth', methods = ['POST', 'GET'])
def user_auth():
  if request.method == 'POST':
    username = request.form["username"]
    password = request.form["password"]
    password = hashlib.sha224(password.encode()).hexdigest()
    print("username : {} -- password : {}".format(username, password))
    user_id = captive_portal.authenticate(username, password)
    if user_id:
      ret = captive_portal.authorize(user_id, "{}".format(request.remote_addr))
      return ret
    else:
      return "Bad password"
@app.route('/welcome_new_user', methods = ['POST', 'GET'])
def welcome_new_user():
   return render_template('user_auth.html')

def my_func(ipversion):
  import time
  con = sqlite3.connect("database.db")
  while True:  
    try:
      con.row_factory = sqlite3.Row
      cur = con.cursor()
      cur.execute("""
                	select users_connections.connection_ip
                	from users_connections
               		WHERE users_connections.connection_ip_version = {}
                	""".format(ipversion))
      rows = cur.fetchall();
      for record in rows:
          print(record[0])

      for record in rows:
        address = record[0]
        if ipversion == 4:
            res = subprocess.call(['ping', '-c', '1', address])
        else:
            res = subprocess.call(['ping6', '-c', '1', address])
        if res != 0:
            print("USER {} has disconnected".format(address))
            cur.execute("delete from users_connections where users_connections.connection_ip LIKE '%{}%'".format(str(address)))
            con.commit()
            subprocess.call(["iptables", "-D", "FORWARD", "-s", "{}/32".format(address), "-j", "ACCEPT"])
            subprocess.call(["iptables", "-D", "FORWARD", "-s", "{}/32".format(address), "-j", "ACCEPT"])
      time.sleep(5)
    except Exception as inst:
        print("E : {}".format(inst))
if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument("--port", help="port")
  parser.add_argument("--host")
  parser.add_argument("--interface")
  args = parser.parse_args()
  print(args)
  host = "10.3.141.1"
  port = 9999
  interface = "wlan0"
  if args.port:
    port = args.port
  if args.host:
    host = args.host
  if args.interface:
    interface = args.interface
  print("host:port : {}:{}".format(host, port))
  captive_portal = CaptivePortal( interface=interface, server_ip_addr = host, server_port=port)
  from threading import Thread
  thread = Thread(target=my_func, args=(4,))
  thread.daemon = True
  thread.start()
  app.run(ssl_context='adhoc', host=host, port=port)
