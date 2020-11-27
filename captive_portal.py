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
		subprocess.call(["iptables", "-A", "FORWARD", "-i", interface, "-p", "tcp", "--dport", "53", "-j" ,"ACCEPT"])
		subprocess.call(["iptables", "-A", "FORWARD", "-i", interface, "-p", "udp", "--dport", "53", "-j" ,"ACCEPT"])
		subprocess.call(["iptables", "-A", "FORWARD", "-i", interface, "-p", "tcp", "--dport", str(server_port),"-d", server_ip_addr, "-j" ,"ACCEPT"])
		subprocess.call(["iptables", "-A", "FORWARD", "-i", interface, "-j" ,"DROP"])
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
   			FOREIGN KEY (user_id) 
      				REFERENCES users (user_id) 
         				ON DELETE CASCADE 
         				ON UPDATE NO ACTION
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
	def authorize(self, user_id, ip):
		print( "user_id : {} -- ip : {}".format(user_id, ip))
	def run_captive_portal_server(self):
		pass


#a = CaptivePortal()

app = Flask(__name__)
captive_portal = None

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
      captive_portal.authorize(user_id, "{}".format(request.remote_addr))
      return "good"
    else:
      return "not good"
@app.route('/welcome_new_user', methods = ['POST', 'GET'])
def welcome_new_user():
   return render_template('user_auth.html')


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
  app.run(host=host, port=port)
