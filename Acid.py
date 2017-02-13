
import re
import ssl
import json
import urllib
import inspect
import webbrowser

try:
	# Python3 URL Libraries
	from urllib.request import urlopen
	from urllib.parse import quote_plus
	from urllib.parse import urlencode
	from http.cookiejar import CookieJar
	from urllib.request import build_opener
	from urllib.request import Request
	from urllib.request import HTTPCookieProcessor
	from urllib.request import HTTPSHandler
	# Python3 GUI Libraries
	#from tkinter import *
	import tkinter as tk
	from tkinter import ttk
except ImportError:
	# Python2 URL Libraries
	from urllib2 import urlopen
	from urllib import quote_plus
	from urllib import urlencode
	from cookielib import CookieJar
	from urllib2 import build_opener
	from urllib2 import Request
	from urllib2 import HTTPCookieProcessor
	from urllib2 import HTTPSHandler
	# Python2 GUI Libraries
	#from Tkinter import *
	import Tkinter as tk
	from tkinter import ttk

version = "0.3.0"

class topwindow:
	def __init__(self, master):
		self.currentoutput = ""
		self.master = master
		master.title("Acid")
		self.viewpasswordstate = False
		####################
		self.logo = tk.PhotoImage(data=logodata)
		self.logolabel = tk.Label(master, image=self.logo)
		master.tk.call('wm','iconphoto',root._w,self.logo)
		self.logolabel.grid(row=0, column=0, rowspan=4, sticky=tk.W+tk.N)
		####################
		self.ipaddresslabel = tk.Label(master, text="Hostname or IP Address")
		self.ipaddresslabel.grid(row=0, column=1, sticky=tk.E)
		#########
		self.ipaddressentry = tk.Entry(master, bd=5, width=35)
		self.ipaddressentry.grid(row=0, column=2)
		####################
		#self.ipoutput = ""
		self.ipoutputtext = tk.StringVar()
		self.ipoutputtext.set(self.currentoutput)
		self.ipoutputlabel = tk.Label(master, textvariable=self.ipoutputtext)
		self.ipoutputlabel.grid(row=1, column=2)
		####################
		####################
		self.usernamelabel = tk.Label(master, text="Username")
		self.usernamelabel.grid(row=2, column=1, sticky=tk.E)
		#########
		self.usernameentry = tk.Entry(master, bd=5, width=35)
		self.usernameentry.grid(row=2, column=2)
		####################
		####################
		self.passwordlabel = tk.Label(master, text="Password")
		self.passwordlabel.grid(row=3, column=1, sticky=tk.E)
		#########
		self.passwordentry = tk.Entry(master, show="*", bd=5, width=35)
		self.passwordentry.grid(row=3, column=2)
		#########
		#self.passint = tk.IntVar()
		#self.passcheck = tk.Checkbutton(master, text="View Password", variable=self.passint).grid(row=3, column=3, sticky=tk.W)
		self.viewpassbutton = tk.Button(master, text='View Password', command=self.view_password)
		self.viewpassbutton.grid(row=3, column=3)
		####################
		self.clearlogbutton = tk.Button(master, text='Clear Log Window', command=self.clear_output)
		self.clearlogbutton.grid(row=4, column=0, sticky=tk.W)
		####################
		self.currentoutput = ""
		self.outputtext = tk.StringVar()
		self.outputtext.set(self.currentoutput)
		self.outputlabel = tk.Label(master, textvariable=self.outputtext, wraplength=400)
		self.outputlabel.grid(row=4, column=1, columnspan=2, rowspan=2)
		####################
		self.testbutton = tk.Button(master, text='Test Credentials', command=self._login)
		self.testbutton.grid(row=0, column=3)
		####################
		self.basicbutton = tk.Button(master, text='Basic Settings', command=self.start_basicwindow)
		self.basicbutton.grid(row=1, column=3)
		####################
		self.closebutton = tk.Button(master, text='Close', command=self.close)
		self.closebutton.grid(row=4, column=3)
		####################
		self.scrollbar = tk.Scrollbar(master)
		self.textbox = tk.Text(master, height=30, width=150, bg="white smoke", yscrollcommand=self.scrollbar.set)
		self.scrollbar.config(command=self.textbox.yview)
		self.textbox.grid(row=6, column=0, columnspan=5)
		self.scrollbar.grid(row=6, column=6,sticky=tk.N+tk.S+tk.W+tk.E)
		master.grid_columnconfigure(0, weight=1)
		master.grid_columnconfigure(1, weight=1)
		master.grid_rowconfigure(6, weight=1)
		self.write_output("Logs and API calls will be listed here")
		####################
		self.webframe = tk.Frame(master)
		self.webframe.grid(row=7, column=0, columnspan=4)
		self.webname = tk.Label(self.webframe, text=r"Created by John W Kerns      -     ",)
		self.webname.pack(side="left")
		self.weblink = tk.Label(self.webframe, text=r"https://github.com/packetsar/acid", fg="blue", cursor="hand2")
		self.weblink.pack(side="right")
		self.weblink.bind("<Button-1>", self.open_web)
		####################
		self.versionlabel = tk.Label(master, text=r"Version "+version,)
		self.versionlabel.grid(row=7, column=4)
		####################
	def _login(self):
		self.outputtext.set("")
		########### Check Inputs ##########
		self.emptyip = not check_ipdns_entry(self.ipaddressentry, self.ipoutputlabel, self.ipoutputtext)
		self.emptyuname = entry_is_empty(self.usernameentry)
		self.emptypass = entry_is_empty(self.passwordentry)
		if self.emptyip or self.emptyuname or self.emptypass:
			self.master.lift()
		else:
			########## Make Call to ACI ##########
			self.write_output(self.header(35, "Logging into ACI", 2))
			self.call = acicalls(username=self.usernameentry.get(), password=self.passwordentry.get(), hostname=self.ipaddressentry.get())
			########## Parse output from the login ##########
			if self.call.loginresponse['status'] == 'failed':
				self.master.lift()
				self.outputtext.set(self.call.loginresponse['description'])
				self.outputlabel.configure(fg="red")
				if self.call.loginresponse['reason'] == "badip":
					self.ipaddressentry.configure(bg="red")
				elif self.call.loginresponse['reason'] == "badcreds":
					self.usernameentry.configure(bg="red")
					self.passwordentry.configure(bg="red")
					self.write_send_header_body(self.call.url, self.call.data)
					self.write_response_header_body(self.call.loginresponse['response'])
			elif self.call.loginresponse['status'] == 'success':
				self.outputtext.set("HTTP Response 200, OK: Login Successful")
				self.write_send_header_body(self.call.url, self.call.data)
				self.write_response_header_body(self.call.loginresponse['response'])
				self.outputlabel.configure(fg="green4")
				self.ipaddressentry.configure(bg="green4")
				self.usernameentry.configure(bg="green4")
				self.passwordentry.configure(bg="green4")
			return self.call.loginresponse
	def write_send_header_body(self, url, data):
		self.write_output("\nURL: "+url+"\n")
		self.write_output("\n\n"+self.header(35, "Sending Body", 0))
		if type(data) == type(b"") or type(data) == type(""):
			if data == "<No Body>":
				self.write_output("<No Body>")
				return None
			else:
				data = json.loads(data)
		self.json = json.dumps(data, indent=4, sort_keys=True)
		self.writedata = str(self.json)
		if self.viewpasswordstate == False:
			self.json = self.writedata.replace(self.passwordentry.get(), "*"*len(self.passwordentry.get()))
		self.write_output(str(self.json))
	def write_response_header_body(self, responseobject):
		if "http" in str(type(responseobject)).lower():
			self.write_output("\n\n"+self.header(35, "Returned Header", 0))
			self.write_output(str(responseobject.info()))
			self.write_output("\n\n"+self.header(35, "Returned Body", 0))
			self.json = json.loads(responseobject.read())
			self.json = json.dumps(self.json, indent=4, sort_keys=True)
			self.write_output(str(self.json))
		elif "instance" in str(type(responseobject)).lower():
			self.write_output("\n\n"+self.header(35, "Returned Header", 0))
			self.write_output(str(responseobject.info()))
			self.write_output("\n\n"+self.header(35, "Returned Body", 0))
			self.json = json.loads(responseobject.read())
			self.json = json.dumps(self.json, indent=4, sort_keys=True)
			self.write_output(str(self.json))
		elif type(responseobject) == type(()):
			self.write_output("\n\n"+self.header(35, "Returned Header", 0))
			self.write_output(responseobject[0])
			self.write_output("\n\n"+self.header(35, "Returned Body", 0))
			self.json = json.loads(responseobject[1])
			self.json = json.dumps(self.json, indent=4, sort_keys=True)
			self.write_output(str(self.json))
	def start_basicwindow(self):
		try:
			if self.bwopen == False:
				self.bw = basicwindow(root)
				self.bwopen = True
			elif self.bwopen == True:
				self.bw.close()
				self.bwopen = False
		except AttributeError:
			self.bwopen = False
			self.start_basicwindow()
	def write_output(self, text):
		self.textbox.config(state=tk.NORMAL)
		self.textbox.insert(tk.END, ("\n"+str(text)))
		self.textbox.config(state=tk.DISABLED)
		self.textbox.see(tk.END)
	def clear_output(self):
		self.textbox.config(state=tk.NORMAL)
		self.textbox.delete(1.0, tk.END)
		self.textbox.config(state=tk.DISABLED)
		self.textbox.see(tk.END)
	def header(self, indent, message, rows):
		result = ("#"*indent) + " " + message.upper() + " " + ("#"*indent)
		length = len(result)
		for each in range(rows):
			result = result + "\n" + ("#"*length)
		return result
	def login_check(self, recursed=False):
		try:
			if self.call.loginresponse['status'] == 'success': return True
			else:
				if recursed:
					return False
				elif not recursed:
					self._login()
					return self.login_check(recursed=True)
		except AttributeError:
			if self._login() == None:
				return False
			else:
				return self.login_check(recursed=True)
	def post(self, url="https://192.168.1.1/api", data={"somedata": "in JSON format"}):
		self.result = self.call.post(url, data)
		if self.result.getcode() == 403:
			self.write_output("\n\n\n\n>>>>>>>>>> Detected token timeout. \
			Reprocessing login and resending POST... <<<<<<<<<\n\n\n\n")
			self._login()
			return self.call.post(url, data)
		else:
			return self.result
	def get(self, url="https://192.168.1.1/api"):
		self.result = self.call.get(url)
		if self.result.getcode() == 403:
			self.write_output("\n\n\n\n>>>>>>>>>> Detected token timeout. \
			Reprocessing login and resending POST... <<<<<<<<<\n\n\n\n")
			self._login()
			return self.call.get(url)
		else:
			return self.result
	def view_password(self):
		if self.viewpasswordstate == False:
			self.passwordentry.configure(show="")
			self.viewpassbutton.configure(text='Hide Password')
			self.viewpasswordstate = True
		elif self.viewpasswordstate == True:
			self.passwordentry.configure(show="*")
			self.viewpassbutton.configure(text='Show Password')
			self.viewpasswordstate = False
	def open_web(self, url):
		print(url.widget.cget("text"))
		webbrowser.open_new(url.widget.cget("text"))
	def close(self):
		self.master.destroy()


class basicwindow:
	def __init__(self, master):
		self.bw = tk.Toplevel(master)
		self.bw.title("Acid Basic Settings")
		######## NTP ########
		self.ntpheader = tk.Label(self.bw, text="Step 1: Add NTP Servers", font=("Helvetica", 12, "bold"))
		self.ntpheader.grid(row=0, column=0, columnspan=4)
		self.ntplabel = tk.Label(self.bw, text="NTP Server Hostname or IP Address")
		self.ntplabel.grid(row=1, column=0, sticky=tk.E)
		self.ntpentry = tk.Entry(self.bw, bd=5, width=35)
		self.ntpentry.grid(row=1, column=1)
		self.ntpsubmit = tk.Button(self.bw, text='Post NTP', command=self.submit_ntp)
		self.ntpsubmit.grid(row=1, column=3)
		self.ntpchecktext = tk.StringVar()
		self.ntpchecktext.set("")
		self.ntpchecklabel = tk.Label(self.bw, textvariable=self.ntpchecktext)
		self.ntpchecklabel.grid(row=2, column=1)
		self.ntpprefvar = tk.IntVar()
		self.ntpprefbox = tk.Checkbutton(self.bw, text="Preferred", variable=self.ntpprefvar)
		self.ntpprefbox.grid(row=1, column=2)
		self.ntpstatustext = tk.StringVar()
		self.ntpstatustext.set("")
		self.ntpstatuslabel = tk.Label(self.bw, textvariable=self.ntpstatustext)
		self.ntpstatuslabel.grid(row=1, column=4)
		self.onetwosep = tk.Frame(self.bw, height=1, bg="gray50")
		self.onetwosep.grid(row=10, column=0, columnspan=100, sticky=tk.N+tk.S+tk.W+tk.E)
		#####################
		######## DNS ########
		self.dnsheader = tk.Label(self.bw, text="Step 2: Add DNS Settings", font=("Helvetica", 12, "bold"))
		self.dnsheader.grid(row=11, column=0, columnspan=4)
		self.dnssvrlabel = tk.Label(self.bw, text="DNS Server IP Address")
		self.dnssvrlabel.grid(row=12, column=0, sticky=tk.E)
		self.dnssvrentry = tk.Entry(self.bw, bd=5, width=35)
		self.dnssvrentry.grid(row=12, column=1)
		self.dnssvrsubmit = tk.Button(self.bw, text='Post DNS Server', command=self.submit_dns_server)
		self.dnssvrsubmit.grid(row=12, column=3)
		self.dnssvrchecktext = tk.StringVar()
		self.dnssvrchecktext.set("")
		self.dnssvrchecklabel = tk.Label(self.bw, textvariable=self.dnssvrchecktext)
		self.dnssvrchecklabel.grid(row=13, column=1)
		self.dnssvrprefvar = tk.IntVar()
		self.dnssvrprefbox = tk.Checkbutton(self.bw, text="Preferred", variable=self.dnssvrprefvar)
		self.dnssvrprefbox.grid(row=12, column=2)
		self.dnssvrstatustext = tk.StringVar()
		self.dnssvrstatustext.set("")
		self.dnssvrstatuslabel = tk.Label(self.bw, textvariable=self.dnssvrstatustext)
		self.dnssvrstatuslabel.grid(row=12, column=4)
		######
		self.dnsdmnlabel = tk.Label(self.bw, text="DNS Search Domain")
		self.dnsdmnlabel.grid(row=14, column=0, sticky=tk.E)
		self.dnsdmnentry = tk.Entry(self.bw, bd=5, width=35)
		self.dnsdmnentry.grid(row=14, column=1)
		self.dnsdmnsubmit = tk.Button(self.bw, text='Post DNS Domain', command=self.submit_dns_domain)
		self.dnsdmnsubmit.grid(row=14, column=3)
		self.dnsdmnchecktext = tk.StringVar()
		self.dnsdmnchecktext.set("")
		self.dnsdmnchecklabel = tk.Label(self.bw, textvariable=self.dnsdmnchecktext)
		self.dnsdmnchecklabel.grid(row=15, column=1)
		self.dnsdmnprefvar = tk.IntVar()
		self.dnsdmnprefbox = tk.Checkbutton(self.bw, text="Default", variable=self.dnsdmnprefvar)
		self.dnsdmnprefbox.grid(row=14, column=2)
		self.dnsdmnstatustext = tk.StringVar()
		self.dnsdmnstatustext.set("")
		self.dnsdmnstatuslabel = tk.Label(self.bw, textvariable=self.dnsdmnstatustext)
		self.dnsdmnstatuslabel.grid(row=14, column=4)
		######
		self.dnsassignsubmit = tk.Button(self.bw, text='Assign DNS to OOB EPG', command=self.submit_assign_dns)
		self.dnsassignsubmit.grid(row=15, column=2, columnspan=2, sticky=tk.E)
		self.dnsassignstatustext = tk.StringVar()
		self.dnsassignstatustext.set("")
		self.dnsassignstatuslabel = tk.Label(self.bw, textvariable=self.dnsassignstatustext)
		self.dnsassignstatuslabel.grid(row=15, column=4)
		######
		self.twothreesep = tk.Frame(self.bw, height=1, bg="gray50")
		self.twothreesep.grid(row=20, column=0, columnspan=100, sticky=tk.N+tk.S+tk.W+tk.E)
		#####################
		######## POD ########
		self.podframe = tk.Frame(self.bw, borderwidth=4, relief=tk.RAISED)
		self.podframe.grid(row=22, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.podlabel = tk.Label(self.podframe, text="Select an ACI Pod     ")
		self.podlabel.grid(row=0, column=0, sticky="en")
		self.podvar = tk.StringVar(self.podframe)
		self.podvar.set("Select a Pod")
		self.podmenu = ttk.Combobox(self.podframe, textvariable=self.podvar, width=15)
		self.podmenu.state(['readonly'])
		self.podmenu.grid(row=0, column=1)
		self.podupdate = tk.Button(self.podframe, text='Update Pod List', command=self.update_pod_list)
		self.podupdate.grid(row=0, column=2)
		self.podupdatetext = tk.StringVar()
		self.podupdatetext.set("")
		self.podupdatelabel = tk.Label(self.podframe, textvariable=self.podupdatetext)
		self.podupdatelabel.grid(row=1, column=1)
		#####################
		######## BGP ########
		self.bgpframe = tk.Frame(self.bw, borderwidth=4, relief=tk.RAISED)
		self.bgpframe.grid(row=23, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.bgpheader = tk.Label(self.bgpframe, text="Step 3: Setup BGP", font=("Helvetica", 12, "bold"))
		self.bgpheader.grid(row=0, column=0, columnspan=101, sticky="en")
		self.bgpasnlabel = tk.Label(self.bgpframe, text="BGP Autonomous System Number (ASN)       ")
		self.bgpasnlabel.grid(row=1, column=0, sticky="en")
		self.bgpasnentry = tk.Entry(self.bgpframe, bd=5, width=15)
		self.bgpasnentry.grid(row=1, column=1)
		self.bgpasnsubmit = tk.Button(self.bgpframe, text='Post BGP ASN', command=self.submit_assign_bgpasn)
		self.bgpasnsubmit.grid(row=1, column=2)
		self.bgpasnchecktext = tk.StringVar()
		self.bgpasnchecktext.set("")
		self.bgpasnchecklabel = tk.Label(self.bgpframe, textvariable=self.bgpasnchecktext)
		self.bgpasnchecklabel.grid(row=2, column=1, columnspan=101)
		self.bgpasnstatustext = tk.StringVar()
		self.bgpasnstatustext.set("")
		self.bgpasnstatuslabel = tk.Label(self.bgpframe, textvariable=self.bgpasnstatustext)
		self.bgpasnstatuslabel.grid(row=1, column=3)
		######
		self.bgprrframe = tk.Frame(self.bgpframe)
		self.bgprrframe.grid(row=3, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.bgpasnlabel = tk.Label(self.bgprrframe, text="Add BGP Route Reflector Nodes  ")
		self.bgpasnlabel.grid(row=0, column=0, sticky="en")
		self.bgprrvar = tk.StringVar(self.bgprrframe)
		self.bgprrvar.set("Select Route Reflector (RR) Node")
		self.bgprrmenu = ttk.Combobox(self.bgprrframe, textvariable=self.bgprrvar, width=35)
		self.bgprrmenu.state(['readonly'])
		self.bgprrmenu.grid(row=0, column=1)
		self.bgprrupdate = tk.Button(self.bgprrframe, text='Update List', command=self.update_bgp_rr_nodes)
		self.bgprrupdate.grid(row=0, column=2)
		self.bgprrsubmit = tk.Button(self.bgprrframe, text='Add RR Node', command=self.submit_rr_node)
		self.bgprrsubmit.grid(row=0, column=3)
		self.bgprrstatustext = tk.StringVar()
		self.bgprrstatustext.set("")
		self.bgprrstatuslabel = tk.Label(self.bgprrframe, textvariable=self.bgprrstatustext)
		self.bgprrstatuslabel.grid(row=0, column=4)
		self.bgprrupdatetext = tk.StringVar()
		self.bgprrupdatetext.set("")
		self.bgprrupdatelabel = tk.Label(self.bgprrframe, textvariable=self.bgprrupdatetext)
		self.bgprrupdatelabel.grid(row=1, column=1)
		#######################
		######## CLOSE ########
		self.closebutton = tk.Button(self.bw, text='Close', command=self.close)
		self.closebutton.grid(row=100, column=100)
		#######################
	def submit_ntp(self):
		if check_ipdns_entry(self.ntpentry, self.ntpchecklabel, self.ntpchecktext):
			if gui.login_check():
				self.ntpstatustext.set("Attempting Post...")
				gui.write_output("\n\n\n"+gui.header(35, "Pushing NTP Server", 2))
				self.pushdatatup = add_ntp(self.ntpentry.get(), self.ntpprefvar.get())
				self.pushurl = gui.call.baseurl+self.pushdatatup[0]
				self.pushdata = self.pushdatatup[1]
				gui.write_send_header_body(self.pushurl, self.pushdata)
				self.response = gui.post(url=self.pushurl, data=self.pushdata)
				gui.write_response_header_body(self.response)
				if self.response.getcode() == 200:
					self.ntpstatustext.set("Success: HTTP 200")
					self.ntpstatuslabel.configure(fg="green4")
				else:
					self.ntpstatustext.set("Post Failed")
					self.ntpstatuslabel.configure(fg="red")
				gui.write_output(gui.header(35, "NTP Push Complete", 2))
	def submit_dns_server(self):
		if check_ip_entry(self.dnssvrentry, self.dnssvrchecklabel, self.dnssvrchecktext):
			if gui.login_check():
				self.dnssvrstatustext.set("Attempting Post...")
				gui.write_output("\n\n\n"+gui.header(35, "Pushing DNS Server", 2))
				self.pushdatatup = add_dns_server(self.dnssvrentry.get(), self.dnssvrprefvar.get())
				self.pushurl = gui.call.baseurl+self.pushdatatup[0]
				self.pushdata = self.pushdatatup[1]
				gui.write_send_header_body(self.pushurl, self.pushdata)
				self.response = gui.post(url=self.pushurl, data=self.pushdata)
				gui.write_response_header_body(self.response)
				if self.response.getcode() == 200:
					self.dnssvrstatustext.set("Success: HTTP 200")
					self.dnssvrstatuslabel.configure(fg="green4")
				else:
					self.dnssvrstatustext.set("Post Failed")
					self.dnssvrstatuslabel.configure(fg="red")
				gui.write_output(gui.header(35, "DNS Server Push Complete", 2))
	def submit_dns_domain(self):
		if check_dns_entry(self.dnsdmnentry, self.dnsdmnchecklabel, self.dnsdmnchecktext):
			if gui.login_check():
				self.dnsdmnstatustext.set("Attempting Post...")
				gui.write_output("\n\n\n"+gui.header(35, "Pushing DNS Domain", 2))
				self.pushdatatup = add_dns_domain(self.dnsdmnentry.get(), self.dnsdmnprefvar.get())
				self.pushurl = gui.call.baseurl+self.pushdatatup[0]
				self.pushdata = self.pushdatatup[1]
				gui.write_send_header_body(self.pushurl, self.pushdata)
				self.response = gui.post(url=self.pushurl, data=self.pushdata)
				gui.write_response_header_body(self.response)
				if self.response.getcode() == 200:
					self.dnsdmnstatustext.set("Success: HTTP 200")
					self.dnsdmnstatuslabel.configure(fg="green4")
				else:
					self.dnsdmnstatustext.set("Post Failed")
					self.dnsdmnstatuslabel.configure(fg="red")
				gui.write_output(gui.header(35, "DNS Server Push Complete", 2))
	def submit_assign_dns(self):
		if gui.login_check():
			self.dnsassignstatustext.set("Attempting Post...")
			gui.write_output("\n\n\n"+gui.header(35, "Pushing DNS Assignment", 2))
			self.pushdatatup = assign_dns_to_oob()
			self.pushurl = gui.call.baseurl+self.pushdatatup[0]
			self.pushdata = self.pushdatatup[1]
			gui.write_send_header_body(self.pushurl, self.pushdata)
			self.response = gui.post(url=self.pushurl, data=self.pushdata)
			gui.write_response_header_body(self.response)
			if self.response.getcode() == 200:
				self.dnsassignstatustext.set("Success: HTTP 200")
				self.dnsassignstatuslabel.configure(fg="green4")
			else:
				self.dnsassignstatustext.set("Post Failed")
				self.dnsassignstatuslabel.configure(fg="red")
			gui.write_output(gui.header(35, "DNS Server Push Complete", 2))
	def submit_assign_bgpasn(self):
		if check_bgpasn_entry(self.bgpasnentry, self.bgpasnchecklabel, self.bgpasnchecktext):
			if gui.login_check():
				self.bgpasnstatustext.set("Attempting Post...")
				gui.write_output("\n\n\n"+gui.header(35, "Pushing BGP ASN", 2))
				self.pushdatatup = assign_bgp_asn(self.bgpasnentry.get())
				self.pushurl = gui.call.baseurl+self.pushdatatup[0]
				self.pushdata = self.pushdatatup[1]
				gui.write_send_header_body(self.pushurl, self.pushdata)
				self.response = gui.post(url=self.pushurl, data=self.pushdata)
				gui.write_response_header_body(self.response)
				if self.response.getcode() == 200:
					self.bgpasnstatustext.set("Success: HTTP 200")
					self.bgpasnstatuslabel.configure(fg="green4")
				else:
					self.bgpasnstatustext.set("Post Failed")
					self.bgpasnstatuslabel.configure(fg="red")
				gui.write_output(gui.header(35, "DNS Server Push Complete", 2))
	def update_pod_list(self):
		if gui.login_check():
			self.podupdatetext.set("Updating Pod List...")
			gui.write_output("\n\n\n"+gui.header(35, "Updating Pod List", 2))
			self.pushurl = gui.call.baseurl+"/api/node/class/fabricPod.json"
			gui.write_send_header_body(self.pushurl, "<No Body>")
			self.response = gui.get(url=self.pushurl)
			rawdata = self.response.read()
			rawheader = self.response.info()
			gui.write_response_header_body((rawheader, rawdata))
			data = json.loads(rawdata)
			index = 0
			self.pods = {}
			podlist = []
			if self.response.getcode() == 200:
				for each in range(int(data['totalCount'])):
					podid = data['imdata'][index]['fabricPod']['attributes']['id']
					podname = "Pod "+podid
					self.pods.update({podname:{"id": podid}})
					podlist.append(podname)
					index += 1
				self.podmenu['values'] = podlist
				self.podupdatetext.set("List Updated")
				self.podupdatelabel.configure(fg="green4")
			else:
				self.podupdatetext.set("Update Failed")
				self.podupdatelabel.configure(fg="red")
			gui.write_output(gui.header(35, "Pod List Update Complete", 2))
	def update_bgp_rr_nodes(self):
		if gui.login_check():
			podname = self.podmenu.get()
			if "select" in podname.lower():
				self.bgprrupdatetext.set("Select a Pod First")
				self.bgprrupdatelabel.configure(fg="red")
				return None
			else:
				poddata = self.get_pod_info(podname)
				self.pods[podname].update({"nodes": poddata})
				nodelist = []
				for node in poddata:
					nodefriendlyname = ""
					nodefriendlyname += "Node: "+poddata[node]['id']
					nodefriendlyname += " | "+poddata[node]['name']
					nodelist.append(nodefriendlyname)
					self.pods[podname]['nodes'][node].update({"nodefriendlyname": nodefriendlyname})
				self.bgprrmenu['values'] = nodelist
				self.bgprrupdatetext.set("List Updated")
				self.bgprrupdatelabel.configure(fg="green4")
	def get_pod_info(self, podname="Pod 1"):
		if gui.login_check():
			podid = self.pods[podname]["id"]
			gui.write_output("\n\n\n"+gui.header(35, "Getting Pod "+podid+" Info", 2))
			decoquery = 'query-target=children&target-subtree-class=fabricNode&query-target-filter=and(ne(fabricNode.role,"controller"))'
			query = quote_plus(decoquery)
			self.pushurl = gui.call.baseurl+"/api/node/mo/topology/pod-"+podid+".json?"+query
			gui.write_send_header_body(self.pushurl, "<No Body>")
			self.response = gui.get(url=self.pushurl)
			rawdata = self.response.read()
			rawheader = self.response.info()
			gui.write_response_header_body((rawheader, rawdata))
			data = json.loads(rawdata)
			index = 0
			nodes = {}
			for each in range(int(data['totalCount'])):
				atts = data['imdata'][index]['fabricNode']['attributes']
				nodes.update({atts['id']: atts})
				index += 1
			return nodes
	def submit_rr_node(self):
		if "select" not in self.bgprrmenu.get().lower():
			if gui.login_check():
				self.bgprrstatustext.set("Attempting Post...")
				gui.write_output("\n\n\n"+gui.header(35, "Pushing BGP Route Reflector Node", 2))
				self.pushdatatup = assign_bgp_asn(self.bgpasnentry.get())
				nodeid = ""
				for node in self.pods[self.podmenu.get()]["nodes"]:
					if self.pods[self.podmenu.get()]["nodes"][node]["nodefriendlyname"] == self.bgprrmenu.get():
						nodeid = self.pods[self.podmenu.get()]["nodes"][node]["id"]
				self.pushdatatup = assign_bgp_rr(nodeid)
				self.pushurl = gui.call.baseurl+self.pushdatatup[0]
				self.pushdata = self.pushdatatup[1]
				gui.write_send_header_body(self.pushurl, self.pushdata)
				self.response = gui.post(url=self.pushurl, data=self.pushdata)
				gui.write_response_header_body(self.response)
				if self.response.getcode() == 200:
					self.bgprrstatustext.set("Success: HTTP 200")
					self.bgprrstatuslabel.configure(fg="green4")
				else:
					self.bgprrstatustext.set("Post Failed")
					self.bgprrstatuslabel.configure(fg="red")
				gui.write_output(gui.header(35, "DNS Server Push Complete", 2))
		else:
			self.bgprrstatustext.set("Bad Selection")
			self.bgprrstatuslabel.configure(fg="red")
	def close(self):
		gui.bwopen = False
		self.bw.destroy()




#####################################3
def check_ipdns_entry(entryobj, labelobj, textobj):
	textobj.set("")
	if entry_is_empty(entryobj):
		return False
	else:
		checkhostname = check_domainname(entryobj.get())
		checkaddress = check_ipv4("address", entryobj.get())
		if checkaddress['status'] == 'fail' and checkhostname['status'] == 'fail':
			entryobj.configure(bg="red")
			textobj.set("Unrecognized IP Address or Hostname")
			labelobj.configure(fg="red")
			return False
		elif checkaddress['status'] == 'pass':
			textobj.set("Legal IPv4 Address")
			labelobj.configure(fg="green4")
			return True
		elif checkhostname['status'] == 'pass':
			textobj.set("Legal Domain/Hostname")
			labelobj.configure(fg="green4")
			return True

def check_ip_entry(entryobj, labelobj, textobj):
	textobj.set("")
	if entry_is_empty(entryobj):
		return False
	else:
		checkaddress = check_ipv4("address", entryobj.get())
		if checkaddress['status'] == 'fail':
			entryobj.configure(bg="red")
			textobj.set("Unrecognized IP Address")
			labelobj.configure(fg="red")
			return False
		elif checkaddress['status'] == 'pass':
			textobj.set("Legal IPv4 Address")
			labelobj.configure(fg="green4")
			return True

def check_dns_entry(entryobj, labelobj, textobj):
	textobj.set("")
	if entry_is_empty(entryobj):
		return False
	else:
		checkhostname = check_domainname(entryobj.get())
		if checkhostname['status'] == 'fail':
			entryobj.configure(bg="red")
			textobj.set("Unrecognized Domain Name")
			labelobj.configure(fg="red")
			return False
		elif checkhostname['status'] == 'pass':
			textobj.set("Legal Domain/Hostname")
			labelobj.configure(fg="green4")
			return True

def check_bgpasn_entry(entryobj, labelobj, textobj):
	textobj.set("")
	if entry_is_empty(entryobj):
		return False
	else:
		try:
			asn = int(entryobj.get())
			if asn > 4294967295:
				entryobj.configure(bg="red")
				textobj.set("Must be a number between 1 and 4294967295")
				labelobj.configure(fg="red")
				return False
			else:
				return True
		except ValueError:
			entryobj.configure(bg="red")
			textobj.set("Must be a number between 1 and 4294967295")
			labelobj.configure(fg="red")
			return False

def entry_is_empty(entryobj):
	entryobj.configure(bg="white")
	if entryobj.get() == "":
		entryobj.configure(bg="yellow")
		return True
	else:
		return False

########################################################
class acicalls:
	def __init__(self, username="admin", password="admin", hostname="192.168.1.1"):
		self.username = username
		self.password = password
		self.hostname = hostname
		self.baseurl = "https://" + self.hostname
		self.gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
		self.cj = CookieJar()
		self.opener = build_opener(HTTPCookieProcessor(self.cj), HTTPSHandler(context=self.gcontext))
		self.loginresponse = self._login()
	def _login(self):
		self.url = self.baseurl + "/api/aaaLogin.json"
		self.data = json.dumps({"aaaUser":{"attributes":{"name":self.username,"pwd":self.password}}})
		self.data = self.data.encode('utf8')
		try:
			self.response = self.opener.open(self.url, self.data)
			return {"status": "success", "response": self.response, "code": self.response.getcode()}
		except Exception as exception:
			if "time" in str(exception).lower():
				return {"status": "failed", "response": exception, "code": 0, "description": "A timeout has occured. Please check that the hostname or IP address is reachable", "reason": "badip"}
			if "getaddrinfo" in str(exception).lower():
				return {"status": "failed", "response": exception, "code": 0, "description": "Hostname lookup failed. Please recheck hostname or DNS lookup capability.", "reason": "badip"}
			elif "http error" in str(exception).lower():
				return {"status": "failed", "response": exception, "code": exception.getcode(), "description": "A login error occured. Please recheck credentials: " + str(exception), "reason": "badcreds"}
	def json_convert(self, data={"somedata": "in JSON format"}):
		self.data = data
		self.data = json.dumps(self.data)
		return self.data.encode('utf8')
	def post(self, url="https://192.168.1.1/api", data={"somedata": "in JSON format"}):
		self.url = url
		self.data = self.json_convert(data)
		try:
			return self.opener.open(self.url, self.data)
		except Exception as exception:
			return exception
	def get(self, url="https://192.168.1.1/api"):
		self.url = url
		try:
			return self.opener.open(self.url)
		except Exception as exception:
			return exception




################################## C H E C K   D O M A I N   N A M E ##################################
#######################################################################################################

##### Check a domain or FQDN host name for legitimacy and proper formatting #####
##### Input "domainname" is a string of the domain name #####
##### Output will be a pass/fail with status messages formatted in the standard messaging format (see "status_reporter" method for more info) #####

def check_domainname(domainname):
	result = {"status": "pass", "messages": []} # Start with a passing result
	##### 1. Check that only legal characters are in name (RFC883 and RFC952) #####
	characterregex = "^[a-zA-Z0-9\-\.]+$" # A list of the valid domain-name characters in a domain name
	for entry in re.findall(characterregex, domainname): # For each string in the list returned by re.findall
		if entry == domainname: # If one of the strings in the returned list equals the full domainname string
			charactercheck = "pass" # Then all its characters are legal and it passes the check
			result["messages"].append({"OK": "No illegal characters found"}) # Append a message to the result
	if charactercheck == "fail": # If the check failed
		result["messages"].append({"FATAL": "Illegal character found. Only a-z, A-Z, 0-9, period (.), and hyphen (-) allowed."})
	##### 2. Check the Length Restrictions: 63 max char per label, 253 max total (RFC1035) #####
	if len(domainname) <= 253: # If total length of domain name is 253 char or less
		result["messages"].append({"OK": "Domain total length is good"})
		labelcheck = {'passlength': 0, 'faillength': 0} # Start a tally of passed and failed labels
		for label in domainname.split("."): # Split the domain into its labels and for each label
			if len(label) <= 63: # If the individual label is less than or equal to 63 characters...
				labelcheck['passlength'] = labelcheck['passlength'] + 1 # Add it as a passed label in the tally
			else: # If it is longer than 63 characters
				labelcheck['faillength'] = labelcheck['faillength'] + 1 # Add it as a failed label in the tally
				result["messages"].append({"FATAL": "Label: " + label + " exceeds max label length of 63 characters"})
		if labelcheck['faillength'] == 0: # If there are NOT any failed labels in the tally
			maxlengthcheck = "pass" # Then all labels are passed and the check passes
	##### 3. Check that first and last character are not a hyphen or period #####
	firstcharregex = "^[a-zA-Z0-9]" # Match a first character of upper or lower A-Z and any digit (no hyphens or periods)
	lastcharregex = "[a-zA-Z0-9]$" # Match a last character of upper or lower A-Z and any digit (no hyphens or periods)
	if len(re.findall(firstcharregex, domainname)) > 0: # If the first characters produces a match
		result["messages"].append({"OK": "Domain first character is legal"})
		if len(re.findall(lastcharregex, domainname)) > 0: # And the last characters produces a match
			result["messages"].append({"OK": "Domain last character is legal"})
			firstlastcheck = "pass" # Then first and last characters are legal and the check passes
		else:
			result["messages"].append({"FATAL": "First and last character in domain must be alphanumeric"})
	else:
		result["messages"].append({"FATAL": "First and last character in domain must be alphanumeric"})
	##### 4. Check that no labels begin or end with hyphens (https://www.icann.org/news/announcement-2000-01-07-en) #####
	beginendhyphenregex = "\.\-|\-\." # Match any instance where a hyphen follows a period or vice-versa
	if len(re.findall(beginendhyphenregex, domainname)) == 0: # If the regex does NOT make a match anywhere
		result["messages"].append({"OK": "No labels begin or end with hyphens"})
		beginendhyphencheck = "pass" # Then no names begin with a hyphen and the check passes
	else:
		result["messages"].append({"FATAL": "Each label in the domain name must begin and end with an alphanumeric character. No hyphens"})
	##### 5. No double periods or triple-hyphens exist (RFC5891 for double-hyphens) #####
	nomultiplesregex = "\.\.|\-\-\-" # Match any instance where a double period (..) or a triple hyphen (---) exist
	if len(re.findall(nomultiplesregex, domainname)) == 0: # If the regex does NOT make a match anywhere
		result["messages"].append({"OK": "No double periods or triple hyphens found"})
		nomultiplescheck = "pass" # Then no double periods or triple hyphens exist and the check passes
	else:
		result["messages"].append({"FATAL": "No double-periods (..) or triple-hyphens (---) allowed in domain name"})
	##### 6. There is at least one period in the domain name #####
	periodinnameregex = "\." # Match any instance of a period
	if len(re.findall(periodinnameregex, domainname)) > 0: # If there is at least one period in the domain name...
		periodinnamecheck = "pass"
		result["messages"].append({"OK": "At least one period found in the domain name"})
	else:
		result["messages"].append({"WARNING": "No period (.) found in domain name. FQDNs are preferred but not required."})
	##### Make sure all checks are passed #####
	for listentry in result["messages"]:
		for key in listentry:
			if key == "FATAL":
				result["status"] = "fail"
	return result

########################################## USAGE AND EXAMPLES #########################################
#
#>>> check_domainname("host.domain.com") # Should pass
#>>> print(status_reporter(check_domainname("host.domain.com"), "all")) # Use reporting method to report on checks
#
#>>> check_domainname("host.dom-ain.com") # Should pass
#>>> print(status_reporter(check_domainname("host.dom-ain.com"), "all")) # Use reporting method to report on checks
#
#>>> check_domainname("host.dom-ain.com-") # Should fail
#>>> print(status_reporter(check_domainname("host.dom-ain.com-"), "all")) # Use reporting method to report on checks
#
#######################################################################################################
#######################################################################################################



################################# C H E C K   I P v 4   A D D R E S S #################################
#######################################################################################################

##### Check that legit IP address or CIDR block was entered #####
##### Input argument "iptype" (str) can be (address | cidr) and argument "ipdata" (str) should be the IP address #####
##### Output will be a pass/fail with status messages formatted in the standard messaging format (see "status_reporter" method for more info) #####

def check_ipv4(iptype, ipdata):
	result = {"status": "", "messages": []} # Initialize result
	if iptype == "address":
		ipregex = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
		result["messages"].append({"OK": "IP parsed as type: Address"})
	elif iptype == "cidr":
		ipregex = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|1[0-9]|2[0-9]|3[0-2]?)$"
		result["messages"].append({"OK": "IP parsed as type: CIDR"})
	check = re.search(ipregex, ipdata)
	if check is None:
		result["status"] = "fail"
		result["messages"].append({"FATAL": "Address failed parsing"})
	else:
		result["status"] = "pass"
		result["messages"].append({"OK": "Address passed parsing"})
	return result

########################################## USAGE AND EXAMPLES #########################################
#
#>>> check_ipv4("address", "1.1.1.100") # Should pass
#>>> print(status_reporter(check_ipv4("address", "1.1.1.100"), "all")) # Use reporting method to report on checks
#
#>>> check_ipv4("address", "1.1.1.256") # Should fail
#>>> print(status_reporter(check_ipv4("address", "1.1.1.256"), "all")) # Use reporting method to report on checks
#
#######################################################################################################
#######################################################################################################






def add_ntp(ntp_hostname, ntp_preferred):
	if ntp_preferred == 1:
		ntp_preferred_value = "true"
	elif ntp_preferred == 0:
		ntp_preferred_value = "false"
	###NTP JSON Data###
	data = {
  "datetimeNtpProv": {
    "attributes": {
      "dn": "uni/fabric/time-default/ntpprov-"+ntp_hostname,
      "name": ntp_hostname,
      "preferred": ntp_preferred_value,
      "rn": "ntpprov-"+ntp_hostname,
      "status": "created,modified"
    },
    "children": [
      {
        "datetimeRsNtpProvToEpg": {
          "attributes": {
            "tDn": "uni/tn-mgmt/mgmtp-default/oob-default",
            "status": "created,modified"
          },
          "children": []
        }
      }
    ]
  }
}
	###################
	uri = "/api/node/mo/uni/fabric/time-default/ntpprov-"+ntp_hostname+".json"
	return (uri, data)


def add_dns_server(dns_address, dns_preferred):
	if dns_preferred == 1:
		dns_preferred_value = "true"
	elif dns_preferred == 0:
		dns_preferred_value = "false"
	###NTP JSON Data###
	data = {
  "dnsProv": {
    "attributes": {
      "dn": "uni/fabric/dnsp-default/prov-["+dns_address+"]",
      "addr": dns_address,
      "status": "created,modified",
	  "preferred": dns_preferred_value,
      "rn": "prov-["+dns_address+"]"
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/fabric/dnsp-default/prov-["+dns_address+"].json"
	return (uri, data)

def add_dns_domain(dns_domain, default_domain):
	if default_domain == 1:
		default_domain_value = "true"
	elif default_domain == 0:
		default_domain_value = "false"
	###NTP JSON Data###
	data = {
  "dnsDomain": {
    "attributes": {
      "dn": "uni/fabric/dnsp-default/dom-"+dns_domain,
      "name": dns_domain,
      "status": "created,modified",
	  "isDefault":default_domain_value,
      "rn": "dom-"+dns_domain
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/fabric/dnsp-default/dom-"+dns_domain+".json"
	return (uri, data)


def assign_dns_to_oob():
	###NTP JSON Data###
	data = {
  "dnsRsProfileToEpg": {
    "attributes": {
      "tDn": "uni/tn-mgmt/mgmtp-default/oob-default",
      "status": "created,modified"
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/fabric/dnsp-default/rsProfileToEpg.json"
	return (uri, data)


def assign_bgp_asn(bgp_asn):
	###NTP JSON Data###
	data = {
  "bgpAsP": {
    "attributes": {
      "dn": "uni/fabric/bgpInstP-default/as",
      "asn": bgp_asn,
      "rn": "as",
      "status": "created,modified"
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/fabric/bgpInstP-default/as.json"
	return (uri, data)


def assign_bgp_rr(bgp_rr_nodeid):
	###NTP JSON Data###
	data = {
  "bgpRRNodePEp": {
    "attributes": {
      "dn": "uni/fabric/bgpInstP-default/rr/node-"+bgp_rr_nodeid,
      "id": bgp_rr_nodeid,
      "rn": "node-"+bgp_rr_nodeid,
      "status": "created,modified"
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/fabric/bgpInstP-default/rr/node-"+bgp_rr_nodeid+".json"
	return (uri, data)





logodata = '''R0lGODlhlgCWAPcAAAAAAEBAQEFBQUJCQkREREVFRUZGRkdHR0hISElJSUpKSkt
LS0xMTE1NTU5OTk9PT1BQUFFRUVNTU1ZWVldXV1lZWVpaWltbW1xcXF1dXV9fX2FhYWJiYmVlZWZmZm
dnZ2hoaGpqam5ubnFxcXV1dXd3d3l5eXp6eoCAgIODg4SEhIaGhomJiYuLi4+Pj5OTk5aWlpmZmZ+fn
6CgoKWlpaenp6ioqKqqqqysrK+vr7GxsbS0tLW1tba2tre3t7q6ur+/v5W61pW615a72Ja72Ze82Je8
2Ze82pi82Ji82Zm82pm+2pq+25y+2py+25y/3J2/3Z7A257A3J7A3aDB3KHB3aPC3KHC3aLD3qLD36P
E3qPE36TD3aTD3qXE3aXE3qXE36bG36jG3qjG363J36XF4KfG4KnH4KjH4arI4KrI4azI4K3I4azJ4q
/K4K7K4a7K4q7L47DK4LDK4bDL4rHL47LM4rLM47PO47LN5LPO5LTN4rbO4rfP47TN5LbO5LXO5bjP4
7bQ5bjQ47rQ5LjQ5bjQ5rvS5LvS5rzS5L3S5b3S5rzT573U5r3U57/V6MPDw8jIyMnJydDQ0NHR0dLS
0tTU1NbW1tnZ2dra2tvb29zc3N3d3d7e3t/f38HU5MDU5cDU5sDV58LW5sHW58TW5sTX58DV6MLW6MT
X6MXX6cbY58PY6MXY6MXY6cfa6cfa6sjY58jZ6Mna6Mra6crb6szb6c3c6c3c6s3d68/e6c/e6s7e68
/e7NDe6tHe69Hf7NPg69Lg7Nbh6tXg69Th7NTh7dbi7Nbi7dni69ji7Njj7drk7Nrk7drl7tzk7Nzl7
d7m7N7m7d3m7uHh4eXl5eDn7eDn7uLo7uLo7+Pq7+Xq7uXq7+fs7+js7+Do8OPq8OXq8Ofs8Ojs8Ont
8eru8Ovu8ezu8O3u8e7w8e7w8vDw8PDw8fDx8vHy8gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAP8ALAAAAACWAJYAAAj/AP8JHChwBQgOCBMqXMiwoc
OHECNKnEixIkQQKghqJDiDQYCPIEOKHEmypMmTKFOqXMmyZYIYGwduaEmzps2bOHOSvBAzAkgPNChpG
kq0qNGjSJMqXcq0qdOnUJdWshECpAONMwMs2LHOndevYMOKHUu2rNmzaNOqXauW3Y8HHy0MlPFxwSS2
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
AA7'''



root = tk.Tk()
gui = topwindow(root)
root.mainloop()
