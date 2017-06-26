#!/usr/bin/python

#####       Acid (Quick ACI Editor)        #####
#####       Written by John W Kerns        #####
#####      http://blog.packetsar.com       #####
#####  https://github.com/PackeTsar/acid   #####

#### All code will work with Python 2.7.13+ and 3.6.X+ on Windows and OS X ####
#### All imported libraries are native to (included in) Python 2.7.13+ and 3.6.X+ ####

# Set some global variables here
version = "1.0.0"


# Import libraries with names common to Python2 and Python3
import re
import ssl
import sys
import json
import time
import urllib
import inspect
import webbrowser


# Import libraries with names unique to Python2 and Python3
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
	import tkinter as tk
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
	import Tkinter as tk

# Import ttk seperately due to unique OS X paths
try:
	from tkinter import ttk
except ImportError:
	import ttk


# Auto-Populate Hostname, Username, Password fields for faster QA and testing (reset before commiting!)
autologin = False
hostname = "192.168.1.1"
username = "admin"
password = "admin"


#### Initial GUI Window with Credentials, Log Output, and buttons for child windows ####
class topwindow:
	def __init__(self, master):
		self.master = master
		master.title("Acid")
		self.viewpasswordstate = False
		####################
		self.logo = tk.PhotoImage(data=logodata)
		self.logolabel = tk.Label(master, image=self.logo)
		master.tk.call('wm','iconphoto',self.master._w,self.logo)
		self.logolabel.grid(row=0, column=0, rowspan=4, sticky=tk.W+tk.N)
		####################
		master.grid_columnconfigure(1, weight=1)
		master.grid_columnconfigure(2, weight=1)
		master.grid_rowconfigure(6, weight=1)
		####################
		self.entriesframe = tk.Frame(master, padx=20, borderwidth=1, relief=tk.SUNKEN)
		self.entriesframe.grid(row=0, column=1, sticky=tk.N+tk.S+tk.W+tk.E)
		self.entriesframe.grid_columnconfigure(0, weight=1)
		####
		self.ipaddressframe = tk.Frame(self.entriesframe)
		self.ipaddressframe.grid(row=0, column=0, columnspan=3)
		self.ipaddressframe.grid_columnconfigure(0, weight=1)
		self.ipaddresslabel = tk.Label(self.ipaddressframe, text="Hostname or IP Address")
		self.ipaddresslabel.grid(row=0, column=0)
		self.ipaddressentry = tk.Entry(self.ipaddressframe, bd=5, width=35)
		self.ipaddressentry.grid(row=0, column=1)
		####
		####
		self.ipoutputtext = tk.StringVar()
		self.ipoutputtext.set("")
		self.ipoutputlabel = tk.Label(self.entriesframe, textvariable=self.ipoutputtext)
		self.ipoutputlabel.grid(row=1, column=1)
		####
		self.usernamelabel = tk.Label(self.entriesframe, text="Username")
		self.usernamelabel.grid(row=2, column=0, sticky=tk.E)
		self.usernameentry = tk.Entry(self.entriesframe, bd=5, width=35)
		self.usernameentry.grid(row=2, column=1)
		####
		self.passwordlabel = tk.Label(self.entriesframe, text="Password")
		self.passwordlabel.grid(row=3, column=0, sticky=tk.E)
		self.passwordentry = tk.Entry(self.entriesframe, show="*", bd=5, width=35)
		self.passwordentry.grid(row=3, column=1)
		self.viewpassbutton = tk.Button(self.entriesframe, text='Show Password', command=self.view_password)
		self.viewpassbutton.grid(row=3, column=2, sticky=tk.W)
		self.viewpassbutton.config(height=1, width=12)
		####
		self.testbuttonframe = tk.Frame(self.entriesframe)
		self.testbuttonframe.grid(row=4, column=0, columnspan=3, sticky=tk.N+tk.S+tk.W+tk.E)
		self.testbuttonframe.grid_columnconfigure(0, weight=1)
		self.testbutton = tk.Button(self.testbuttonframe, text='Test Credentials', command=self._login)
		self.testbutton.grid(row=4, column=1, sticky=tk.W)
		self.outputtext = tk.StringVar()
		self.outputtext.set("")
		self.outputlabel = tk.Label(self.testbuttonframe, textvariable=self.outputtext, wraplength=300)
		self.outputlabel.grid(row=4, column=0)
		####################
		self.buttonsframe = tk.Frame(master, padx=10, borderwidth=1, relief=tk.SUNKEN)
		self.buttonsframe.grid(row=0, column=2, sticky=tk.N+tk.S+tk.W+tk.E)
		self.buttonsframe.grid_columnconfigure(0, weight=1)
		####
		self.safemodeframe = tk.Frame(self.buttonsframe, borderwidth=1, relief=tk.SUNKEN, padx=10)
		self.safemodeframe.grid(row=0, column=0, rowspan=5)
		self.safemodeframe.grid_columnconfigure(0, weight=1)
		self.safemodedesc = tk.Label(self.safemodeframe, 
		text="Safe Mode will prevent Acid from overwriting/modifying already existing policies which have the same name as new ones", 
		font=("Helvetica", 8), wraplength=150)
		self.safemodedesc.grid(row=1, column=0)
		self.safemodevar = tk.IntVar(value=1)
		self.safemodebox = tk.Checkbutton(self.safemodeframe, text="Safe Mode", variable=self.safemodevar, font=("Helvetica", 8, "bold"))
		self.safemodebox.grid(row=0, column=0)
		####
		self.sysinfobutton = tk.Button(self.buttonsframe, text='System Info', command=self.start_sysinfowindow)
		self.sysinfobutton.grid(row=0, column=1)
		self.sysinfoopen = False
		####
		self.basicbutton = tk.Button(self.buttonsframe, text='Basic Settings', command=self.start_basicwindow)
		self.basicbutton.grid(row=1, column=1)
		self.bwopen = False
		####
		self.portsbutton = tk.Button(self.buttonsframe, text='Configure Ports', command=self.start_ports)
		self.portsbutton.grid(row=2, column=1)
		self.portsopen = False
		####
		self.clearlogbutton = tk.Button(self.buttonsframe, text='Clear Log Window', command=self.clear_output)
		self.clearlogbutton.grid(row=3, column=1)
		####
		self.closebutton = tk.Button(self.buttonsframe, text='Close', command=self.close)
		self.closebutton.grid(row=4, column=1)
		####################
		self.textboxframe = tk.Frame(master, borderwidth=4, relief=tk.RAISED)
		self.textboxframe.grid(row=6, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.textboxframe.grid_columnconfigure(0, weight=1)
		self.textboxframe.grid_rowconfigure(0, weight=1)
		self.scrollbar = tk.Scrollbar(self.textboxframe)
		self.textbox = tk.Text(self.textboxframe, height=10, width=75, bg="white smoke", yscrollcommand=self.scrollbar.set)
		self.scrollbar.config(command=self.textbox.yview)
		self.textbox.grid(row=0, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.scrollbar.grid(row=0, column=1,sticky=tk.N+tk.S+tk.W+tk.E)
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
		self.versionlabel = tk.Label(master, text=r"Version "+version+" (Python %s.%s.%s" % sys.version_info[:3]+")",)
		self.versionlabel.grid(row=7, column=2)
		####################
		if autologin:
			self.ipaddressentry.insert(0, hostname)
			self.usernameentry.insert(0, username)
			self.passwordentry.insert(0, password)
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
		if self.bwopen == False:
			self.bw = basicwindow(root)
			self.bwopen = True
		elif self.bwopen == True:
			self.bw.close()
			self.bwopen = False
	def start_sysinfowindow(self):
		if self.sysinfoopen == False:
			self.sysinfo = systeminfo(root)
			self.sysinfoopen = True
		elif self.sysinfoopen == True:
			self.sysinfo.close()
			self.sysinfoopen = False
	def start_ports(self):
		if self.portsopen == False:
			self.ports = ports(root)
			self.portsopen = True
		elif self.portsopen == True:
			self.ports.close()
			self.portsopen = False
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
		webbrowser.open_new(url.widget.cget("text"))
	def close(self):
		self.master.destroy()


#### GUI window used for doing initial, basic, one-time setup ####
class basicwindow:
	def __init__(self, master):
		self.basicwindow = tk.Toplevel(master)
		self.basicwindow.title("Acid Basic Settings")
		self.basicwindow.geometry('900x450')
		self.basicwindow.tk.call('wm','iconphoto',self.basicwindow._w,gui.logo)
		self.bwcanvas = tk.Canvas(self.basicwindow)
		self.bwcanvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
		self.bw = tk.Frame(self.bwcanvas)
		self.bw.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
		self.bwscroll = tk.Scrollbar(self.basicwindow)
		self.bwscroll.pack(side=tk.RIGHT, fill='y')
		self.bwcanvas.configure(yscrollcommand = self.bwscroll.set)
		self.bwscroll.config(command=self.bwcanvas.yview)
		self.interior_id = self.bwcanvas.create_window(0, 0, window=self.bw, anchor=tk.N+tk.W)
		self.bwcanvas.bind('<Configure>', lambda event, a=self.bwcanvas, b=self.interior_id:self.on_configure(event, a, b))
		self.bwcanvas.bind_all("<MouseWheel>", self.on_mousewheel)
		self.bwcanvas.configure(scrollregion=self.bwcanvas.bbox("all"))
		self.bwcanvas.itemconfig(self.interior_id, height=1080)
		self.basicwindow.wm_protocol("WM_DELETE_WINDOW", self.close)
		#####################
		######## NTP ########
		self.ntpframe = tk.Frame(self.bw, borderwidth=4, relief=tk.RAISED)
		self.ntpframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.ntpframe.grid_columnconfigure(0, weight=1)
		self.ntpframe.grid_columnconfigure(1, weight=1)
		self.ntpframe.grid_columnconfigure(2, weight=1)
		self.ntpframe.grid_columnconfigure(3, weight=1)
		self.ntpheadframe = tk.Frame(self.ntpframe)
		self.ntpheadframe.grid(row=0, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.ntpheadframe.grid_columnconfigure(0, weight=1)
		self.ntpheader = tk.Label(self.ntpheadframe, text="Step 1: Add NTP Servers", font=("Helvetica", 12, "bold"))
		self.ntpheader.grid(row=0, column=0)
		self.ntplabel = tk.Label(self.ntpframe, text="NTP Server Hostname or IP Address")
		self.ntplabel.grid(row=1, column=0, sticky=tk.E)
		self.ntpentry = tk.Entry(self.ntpframe, bd=5, width=35)
		self.ntpentry.grid(row=1, column=1)
		self.ntpsubmit = tk.Button(self.ntpframe, text='Add NTP Server', command=self.submit_ntp)
		self.ntpsubmit.grid(row=1, column=3)
		self.ntpchecktext = tk.StringVar()
		self.ntpchecktext.set("")
		self.ntpchecklabel = tk.Label(self.ntpframe, textvariable=self.ntpchecktext)
		self.ntpchecklabel.grid(row=2, column=1)
		self.ntpprefvar = tk.IntVar()
		self.ntpprefbox = tk.Checkbutton(self.ntpframe, text="Preferred", variable=self.ntpprefvar)
		self.ntpprefbox.grid(row=1, column=2)
		self.ntpstatustext = tk.StringVar()
		self.ntpstatustext.set("")
		self.ntpstatuslabel = tk.Label(self.ntpframe, textvariable=self.ntpstatustext)
		self.ntpstatuslabel.grid(row=2, column=3)
		#####################
		######## DNS ########
		self.dnsframe = tk.Frame(self.bw, borderwidth=4, relief=tk.RAISED)
		self.dnsframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.dnsframe.grid_columnconfigure(0, weight=1)
		self.dnsframe.grid_columnconfigure(1, weight=1)
		self.dnsframe.grid_columnconfigure(2, weight=1)
		self.dnsheadframe = tk.Frame(self.dnsframe)
		self.dnsheadframe.grid(row=0, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.dnsheadframe.grid_columnconfigure(0, weight=1)
		self.dnsheader = tk.Label(self.dnsheadframe, text="Step 2: Add DNS Settings", font=("Helvetica", 12, "bold"))
		self.dnsheader.grid(row=0, column=0)
		######
		self.dnssvrframe = tk.Frame(self.dnsframe, borderwidth=1, relief=tk.SUNKEN)
		self.dnssvrframe.grid(row=1, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.dnssvrframe.grid_columnconfigure(0, weight=3)
		self.dnssvrframe.grid_columnconfigure(1, weight=1)
		self.dnssvrheader = tk.Label(self.dnssvrframe, text="Add DNS Server", font=("Helvetica", 8, "bold"))
		self.dnssvrheader.grid(row=0, column=0, columnspan=2)
		self.dnssvrlabel = tk.Label(self.dnssvrframe, text="DNS Server IP Address")
		self.dnssvrlabel.grid(row=1, column=0)
		self.dnssvrentry = tk.Entry(self.dnssvrframe, bd=5, width=30)
		self.dnssvrentry.grid(row=2, column=0)
		self.dnssvrprefvar = tk.IntVar()
		self.dnssvrprefbox = tk.Checkbutton(self.dnssvrframe, text="Preferred", variable=self.dnssvrprefvar)
		self.dnssvrprefbox.grid(row=2, column=1)
		self.dnssvrchecktext = tk.StringVar()
		self.dnssvrchecktext.set("")
		self.dnssvrchecklabel = tk.Label(self.dnssvrframe, textvariable=self.dnssvrchecktext)
		self.dnssvrchecklabel.grid(row=3, column=0)
		self.dnssvrsubmitframe = tk.Frame(self.dnssvrframe)
		self.dnssvrsubmitframe.grid(row=4, column=0, columnspan=2, sticky=tk.N+tk.S+tk.W+tk.E)
		self.dnssvrsubmit = tk.Button(self.dnssvrsubmitframe, text='Add DNS Server', command=self.submit_dns_server)
		self.dnssvrsubmit.grid(row=0, column=0)
		self.dnssvrstatustext = tk.StringVar()
		self.dnssvrstatustext.set("")
		self.dnssvrstatuslabel = tk.Label(self.dnssvrsubmitframe, textvariable=self.dnssvrstatustext)
		self.dnssvrstatuslabel.grid(row=0, column=1)
		######
		self.dnsdmnframe = tk.Frame(self.dnsframe, borderwidth=1, relief=tk.SUNKEN)
		self.dnsdmnframe.grid(row=1, column=1, sticky=tk.N+tk.S+tk.W+tk.E)
		self.dnsdmnframe.grid_columnconfigure(0, weight=3)
		self.dnsdmnframe.grid_columnconfigure(1, weight=1)
		self.dnsdmnframe.grid_columnconfigure(2, weight=1)
		self.dnsdmnheader = tk.Label(self.dnsdmnframe, text="Add DNS Search Domain", font=("Helvetica", 8, "bold"))
		self.dnsdmnheader.grid(row=0, column=0, columnspan=3)
		self.dnsdmnlabel = tk.Label(self.dnsdmnframe, text="DNS Search Domain")
		self.dnsdmnlabel.grid(row=1, column=0)
		self.dnsdmnentry = tk.Entry(self.dnsdmnframe, bd=5, width=30)
		self.dnsdmnentry.grid(row=2, column=0)
		self.dnsdmnprefvar = tk.IntVar()
		self.dnsdmnprefbox = tk.Checkbutton(self.dnsdmnframe, text="Default", variable=self.dnsdmnprefvar)
		self.dnsdmnprefbox.grid(row=2, column=1)
		self.dnsdmnchecktext = tk.StringVar()
		self.dnsdmnchecktext.set("")
		self.dnsdmnchecklabel = tk.Label(self.dnsdmnframe, textvariable=self.dnsdmnchecktext)
		self.dnsdmnchecklabel.grid(row=3, column=0)
		self.dnsdmnsubmitframe = tk.Frame(self.dnsdmnframe)
		self.dnsdmnsubmitframe.grid(row=4, column=0, columnspan=2, sticky=tk.N+tk.S+tk.W+tk.E)
		self.dnsdmnsubmit = tk.Button(self.dnsdmnsubmitframe, text='Add DNS Search Domain', command=self.submit_dns_domain)
		self.dnsdmnsubmit.grid(row=0, column=0)
		self.dnsdmnstatustext = tk.StringVar()
		self.dnsdmnstatustext.set("")
		self.dnsdmnstatuslabel = tk.Label(self.dnsdmnsubmitframe, textvariable=self.dnsdmnstatustext)
		self.dnsdmnstatuslabel.grid(row=0, column=1)
		######
		self.dnsassignframe = tk.Frame(self.dnsframe, borderwidth=1, relief=tk.SUNKEN)
		self.dnsassignframe.grid(row=1, column=2, sticky=tk.N+tk.S+tk.W+tk.E)
		self.dnsassignframe.grid_columnconfigure(0, weight=1)
		self.dnsassignheader = tk.Label(self.dnsassignframe, text="Assign DNS Settings to EPG", font=("Helvetica", 8, "bold"))
		self.dnsassignheader.grid(row=0, column=0)
		self.dnsassigndesc = tk.Label(self.dnsassignframe, text="  ", font=("Helvetica", 8))
		self.dnsassigndesc.grid(row=1, column=0)
		self.dnsassignsubmit = tk.Button(self.dnsassignframe, text='Assign DNS to OOB EPG', command=self.submit_assign_dns)
		self.dnsassignsubmit.grid(row=5, column=0)
		self.dnsassignstatustext = tk.StringVar()
		self.dnsassignstatustext.set("")
		self.dnsassignstatuslabel = tk.Label(self.dnsassignframe, textvariable=self.dnsassignstatustext)
		self.dnsassignstatuslabel.grid(row=6, column=0)
		#####################
		######## POD ########
		self.podframe = tk.Frame(self.bw, borderwidth=4, relief=tk.RAISED)
		self.podframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.podframe.grid_columnconfigure(0, weight=2)
		self.podframe.grid_columnconfigure(1, weight=1)
		self.podheadframe = tk.Frame(self.podframe)
		self.podheadframe.grid(row=0, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.podheadframe.grid_columnconfigure(0, weight=1)
		self.podheader = tk.Label(self.podheadframe, text="Step 3: ACI Pod Setup", font=("Helvetica", 12, "bold"))
		self.podheader.grid(row=0, column=0)
		######
		self.podselectframe = tk.Frame(self.podframe, borderwidth=1, relief=tk.SUNKEN)
		self.podselectframe.grid(row=1, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.podselectframe.grid_columnconfigure(0, weight=1)
		self.podselectframe.grid_columnconfigure(2, weight=1)
		self.podlabel = tk.Label(self.podselectframe, text="Select an ACI Pod")
		self.podlabel.grid(row=1, column=0, sticky="e")
		self.podvar = tk.StringVar(self.podselectframe)
		self.podvar.set("Select a Pod")
		self.podmenu = ttk.Combobox(self.podselectframe, textvariable=self.podvar, width=15)
		self.podmenu.state(['readonly'])
		self.podmenu.grid(row=1, column=1)
		self.podupdate = tk.Button(self.podselectframe, text='Update Pod List', command=self.update_pod_list)
		self.podupdate.grid(row=1, column=2, sticky="w")
		self.podupdatetext = tk.StringVar()
		self.podupdatetext.set("")
		self.podupdatelabel = tk.Label(self.podselectframe, textvariable=self.podupdatetext)
		self.podupdatelabel.grid(row=2, column=1)
		######
		self.podprofframe = tk.Frame(self.podframe, borderwidth=1, relief=tk.SUNKEN)
		self.podprofframe.grid(row=1, column=1, sticky=tk.N+tk.S+tk.W+tk.E)
		self.podprofframe.grid_columnconfigure(0, weight=1)
		self.podprofassign = tk.Button(self.podprofframe, text='Assign Default Pod Policy Group to Pod Profile', command=self.submit_pod_prof)
		self.podprofassign.grid(row=0, column=0)
		self.podproftext = tk.StringVar()
		self.podproftext.set("")
		self.podproflabel = tk.Label(self.podprofframe, textvariable=self.podproftext)
		self.podproflabel.grid(row=1, column=0)
		#####################
		######## BGP ########
		self.bgpframe = tk.Frame(self.bw, borderwidth=4, relief=tk.RAISED)
		self.bgpframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.bgpframe.grid_columnconfigure(0, weight=1)
		self.bgpheadframe = tk.Frame(self.bgpframe)
		self.bgpheadframe.grid(row=0, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.bgpheadframe.grid_columnconfigure(0, weight=1)
		self.bgpheader = tk.Label(self.bgpheadframe, text="Step 4: Setup BGP", font=("Helvetica", 12, "bold"))
		self.bgpheader.grid(row=0, column=0)
		######
		self.bgpasnframe = tk.Frame(self.bgpframe, borderwidth=1, relief=tk.SUNKEN)
		self.bgpasnframe.grid(row=1, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.bgpasnframe.grid_columnconfigure(0, weight=1)
		self.bgpasnframe.grid_columnconfigure(2, weight=1)
		self.bgpasnlabel = tk.Label(self.bgpasnframe, text="BGP Autonomous System Number (ASN)       ")
		self.bgpasnlabel.grid(row=1, column=0, sticky="en")
		self.bgpasnentry = tk.Entry(self.bgpasnframe, bd=5, width=15)
		self.bgpasnentry.grid(row=1, column=1)
		self.bgpasnsubmit = tk.Button(self.bgpasnframe, text='Assign BGP ASN', command=self.submit_assign_bgpasn)
		self.bgpasnsubmit.grid(row=1, column=2)
		self.bgpasnchecktext = tk.StringVar()
		self.bgpasnchecktext.set("")
		self.bgpasnchecklabel = tk.Label(self.bgpasnframe, textvariable=self.bgpasnchecktext)
		self.bgpasnchecklabel.grid(row=2, column=1)
		self.bgpasnstatustext = tk.StringVar()
		self.bgpasnstatustext.set("")
		self.bgpasnstatuslabel = tk.Label(self.bgpasnframe, textvariable=self.bgpasnstatustext)
		self.bgpasnstatuslabel.grid(row=2, column=2)
		######
		self.bgprrframe = tk.Frame(self.bgpframe, borderwidth=1, relief=tk.SUNKEN)
		self.bgprrframe.grid(row=3, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.bgprrframe.grid_columnconfigure(0, weight=1)
		self.bgprrframe.grid_columnconfigure(3, weight=1)
		self.bgpasnlabel = tk.Label(self.bgprrframe, text="Add BGP Route Reflector Nodes  ")
		self.bgpasnlabel.grid(row=0, column=0, sticky="en")
		self.bgprrvar = tk.StringVar(self.bgprrframe)
		self.bgprrvar.set("Select Route Reflector (RR) Node")
		self.bgprrmenu = ttk.Combobox(self.bgprrframe, textvariable=self.bgprrvar, width=45)
		self.bgprrmenu.state(['readonly'])
		self.bgprrmenu.grid(row=0, column=1)
		self.bgprrupdate = tk.Button(self.bgprrframe, text='Update List', 
		command= lambda: self.update_switch_list(self.bgprrupdatetext, self.bgprrupdatelabel, self.bgprrmenu))
		self.bgprrupdate.grid(row=0, column=2)
		self.bgprrsubmit = tk.Button(self.bgprrframe, text='Add RR Node', command=self.submit_rr_node)
		self.bgprrsubmit.grid(row=0, column=3)
		self.bgprrstatustext = tk.StringVar()
		self.bgprrstatustext.set("")
		self.bgprrstatuslabel = tk.Label(self.bgprrframe, textvariable=self.bgprrstatustext)
		self.bgprrstatuslabel.grid(row=1, column=3)
		self.bgprrupdatetext = tk.StringVar()
		self.bgprrupdatetext.set("")
		self.bgprrupdatelabel = tk.Label(self.bgprrframe, textvariable=self.bgprrupdatetext)
		self.bgprrupdatelabel.grid(row=1, column=1)
		##########################
		######## IF-PROFs ########
		self.ifprofframe = tk.Frame(self.bw, borderwidth=4, relief=tk.RAISED)
		self.ifprofframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.ifprofframe.grid_columnconfigure(0, weight=1)
		self.ifprofframe.grid_columnconfigure(1, weight=1)
		self.ifprofframe.grid_columnconfigure(2, weight=1)
		self.ifprofheadframe = tk.Frame(self.ifprofframe)
		self.ifprofheadframe.grid(row=0, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.ifprofheadframe.grid_columnconfigure(0, weight=1)
		self.ifprofheader = tk.Label(self.ifprofheadframe, text="Step 5: Create Interface Policies", font=("Helvetica", 12, "bold"))
		self.ifprofheader.grid(row=0, column=0)
		######
		self.ifprofdisframe = tk.Frame(self.ifprofframe, borderwidth=1, relief=tk.SUNKEN)
		self.ifprofdisframe.grid(row=1, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.ifprofdisframe.grid_columnconfigure(0, weight=1)
		self.ifprofdisframe.grid_columnconfigure(1, weight=1)
		self.ifprofdisheader = tk.Label(self.ifprofdisframe, text="Discovery Protocols", font=("Helvetica", 8, "bold"))
		self.ifprofdisheader.grid(row=0, column=0, columnspan=2)
		self.ifprofcdpenvar = tk.IntVar(value=1)
		self.ifprofcdpen = tk.Checkbutton(self.ifprofdisframe, text="CDP Enabled", 
		variable=self.ifprofcdpenvar, command= lambda: self.disable_entry(self.ifprofcdpenentry, self.ifprofcdpenvar))
		self.ifprofcdpen.grid(row=1, column=0)
		self.ifprofcdpenentry = tk.Entry(self.ifprofdisframe, bd=1, width=15)
		self.ifprofcdpenentry.grid(row=2, column=0)
		self.ifprofcdpenentry.insert(tk.END, 'Enabled')
		self.ifprofcdpdisvar = tk.IntVar(value=1)
		self.ifprofcdpdis = tk.Checkbutton(self.ifprofdisframe, text="CDP Disabled", 
		variable=self.ifprofcdpdisvar, command= lambda: self.disable_entry(self.ifprofcdpdisentry, self.ifprofcdpdisvar))
		self.ifprofcdpdis.grid(row=1, column=1)
		self.ifprofcdpdisentry = tk.Entry(self.ifprofdisframe, bd=1, width=15)
		self.ifprofcdpdisentry.insert(tk.END, 'Disabled')
		self.ifprofcdpdisentry.grid(row=2, column=1)
		self.ifproflldpenvar = tk.IntVar(value=1)
		self.ifproflldpen = tk.Checkbutton(self.ifprofdisframe, text="LLDP Enabled", 
		variable=self.ifproflldpenvar, command= lambda: self.disable_entry(self.ifproflldpenentry, self.ifproflldpenvar))
		self.ifproflldpen.grid(row=3, column=0)
		self.ifproflldpenentry = tk.Entry(self.ifprofdisframe, bd=1, width=15)
		self.ifproflldpenentry.grid(row=4, column=0)
		self.ifproflldpenentry.insert(tk.END, 'Enabled')
		self.ifproflldpdisvar = tk.IntVar(value=1)
		self.ifproflldpdis = tk.Checkbutton(self.ifprofdisframe, text="LLDP Disabled", 
		variable=self.ifproflldpdisvar, command= lambda: self.disable_entry(self.ifproflldpdisentry, self.ifproflldpdisvar))
		self.ifproflldpdis.grid(row=3, column=1)
		self.ifproflldpdisentry = tk.Entry(self.ifprofdisframe, bd=1, width=15)
		self.ifproflldpdisentry.grid(row=4, column=1)
		self.ifproflldpdisentry.insert(tk.END, 'Disabled')
		######
		self.ifprofllframe = tk.Frame(self.ifprofframe, borderwidth=1, relief=tk.SUNKEN)
		self.ifprofllframe.grid(row=1, column=1, sticky=tk.N+tk.S+tk.W+tk.E)
		self.ifprofllframe.grid_columnconfigure(0, weight=1)
		self.ifprofllframe.grid_columnconfigure(1, weight=1)
		self.ifprofllheader = tk.Label(self.ifprofllframe, text="Link-Layer Settings", font=("Helvetica", 8, "bold"))
		self.ifprofllheader.grid(row=0, column=0, columnspan=2)
		self.ifprof1gvar = tk.IntVar(value=1)
		self.ifprof1g = tk.Checkbutton(self.ifprofllframe, text="1 Gigabit Auto", 
		variable=self.ifprof1gvar, command= lambda: self.disable_entry(self.ifprof1gentry, self.ifprof1gvar))
		self.ifprof1g.grid(row=1, column=0)
		self.ifprof1gentry = tk.Entry(self.ifprofllframe, bd=1, width=15)
		self.ifprof1gentry.grid(row=2, column=0)
		self.ifprof1gentry.insert(tk.END, '1G-Auto')
		self.ifprof10gvar = tk.IntVar(value=1)
		self.ifprof10g = tk.Checkbutton(self.ifprofllframe, text="10 Gigabit", 
		variable=self.ifprof10gvar, command= lambda: self.disable_entry(self.ifprof10gentry, self.ifprof10gvar))
		self.ifprof10g.grid(row=1, column=1)
		self.ifprof10gentry = tk.Entry(self.ifprofllframe, bd=1, width=15)
		self.ifprof10gentry.grid(row=2, column=1)
		self.ifprof10gentry.insert(tk.END, '10G')
		######
		self.ifprofpcframe = tk.Frame(self.ifprofframe, borderwidth=1, relief=tk.SUNKEN)
		self.ifprofpcframe.grid(row=1, column=2, sticky=tk.N+tk.S+tk.W+tk.E)
		self.ifprofpcframe.grid_columnconfigure(0, weight=1)
		self.ifprofpcframe.grid_columnconfigure(1, weight=1)
		self.ifprofpcheader = tk.Label(self.ifprofpcframe, text="Port-Channel Policies", font=("Helvetica", 8, "bold"))
		self.ifprofpcheader.grid(row=0, column=0, columnspan=2)
		self.ifproflacpvar = tk.IntVar(value=1)
		self.ifproflacp = tk.Checkbutton(self.ifprofpcframe, text="LACP Active", 
		variable=self.ifproflacpvar, command= lambda: self.disable_entry(self.ifproflacpentry, self.ifproflacpvar))
		self.ifproflacp.grid(row=1, column=0)
		self.ifproflacpentry = tk.Entry(self.ifprofpcframe, bd=1, width=15)
		self.ifproflacpentry.grid(row=2, column=0)
		self.ifproflacpentry.insert(tk.END, 'LACP-Active')
		self.ifprofstatvar = tk.IntVar(value=1)
		self.ifprofstat = tk.Checkbutton(self.ifprofpcframe, text="Static On", 
		variable=self.ifprofstatvar, command= lambda: self.disable_entry(self.ifprofstatentry, self.ifprofstatvar))
		self.ifprofstat.grid(row=1, column=1)
		self.ifprofstatentry = tk.Entry(self.ifprofpcframe, bd=1, width=15)
		self.ifprofstatentry.grid(row=2, column=1)
		self.ifprofstatentry.insert(tk.END, 'Static-On')
		self.ifprofmacvar = tk.IntVar(value=1)
		self.ifprofmac = tk.Checkbutton(self.ifprofpcframe, text="MAC Pinning", 
		variable=self.ifprofmacvar, command= lambda: self.disable_entry(self.ifprofmacentry, self.ifprofmacvar))
		self.ifprofmac.grid(row=3, column=0, columnspan=2)
		self.ifprofmacentry = tk.Entry(self.ifprofpcframe, bd=1, width=15)
		self.ifprofmacentry.grid(row=4, column=0, columnspan=2)
		self.ifprofmacentry.insert(tk.END, 'MAC-Pinning')
		######
		self.ifprofsubframe = tk.Frame(self.ifprofframe)
		self.ifprofsubframe.grid(row=2, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.ifprofsubframe.grid_columnconfigure(0, weight=1)
		self.ifprofsubframe.grid_columnconfigure(1, weight=1)
		self.ifprofsubmit = tk.Button(self.ifprofsubframe, text='Add Selected Interface Policies', command=self.submit_if_policies)
		self.ifprofsubmit.grid(row=0, column=0, sticky=tk.E)
		self.ifprofchecktext = tk.StringVar()
		self.ifprofchecktext.set("")
		self.ifprofchecklabel = tk.Label(self.ifprofsubframe, textvariable=self.ifprofchecktext)
		self.ifprofchecklabel.grid(row=0, column=1, sticky=tk.W)
		##########################
		######## AAEPs ########
		self.aaepframe = tk.Frame(self.bw, borderwidth=4, relief=tk.RAISED)
		self.aaepframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.aaepframe.grid_columnconfigure(0, weight=1)
		self.aaepframe.grid_columnconfigure(1, weight=1)
		self.aaepframe.grid_columnconfigure(2, weight=1)
		self.aaepheadframe = tk.Frame(self.aaepframe)
		self.aaepheadframe.grid(row=0, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.aaepheadframe.grid_columnconfigure(0, weight=1)
		self.aaepheader = tk.Label(self.aaepheadframe, text="Step 6: Create Attachable Access Entity Profiles (AAEPs)", font=("Helvetica", 12, "bold"))
		self.aaepheader.grid(row=0, column=0)
		######
		self.aaepvlanframe = tk.Frame(self.aaepframe, borderwidth=1, relief=tk.SUNKEN)
		self.aaepvlanframe.grid(row=1, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.aaepvlanframe.grid_columnconfigure(0, weight=1)
		self.aaepvlanframe.grid_columnconfigure(1, weight=1)
		self.aaepvlanframe.grid_columnconfigure(2, weight=1)
		self.aaepvlanframe.grid_columnconfigure(3, weight=1)
		self.aaepvlanheadervar = tk.IntVar(value=1)
		self.aaepvlanheader = tk.Checkbutton(self.aaepvlanframe, text="VLAN Pool (Static)", variable=self.aaepvlanheadervar, font=("Helvetica", 8, "bold"), command= lambda: self.aaep_frame_control())
		self.aaepvlanheader.grid(row=0, column=0, columnspan=4)
		self.aaepvlanpoollabel = tk.Label(self.aaepvlanframe, text="VLAN Pool Name")
		self.aaepvlanpoollabel.grid(row=1, column=0, sticky=tk.E)
		self.aaepvlanpoolentry = tk.Entry(self.aaepvlanframe, bd=1, width=15)
		self.aaepvlanpoolentry.grid(row=1, column=1, sticky=tk.W)
		self.aaepvlanpoolentry.insert(tk.END, 'phys-static')
		self.aaepvlanrangeframe = tk.Frame(self.aaepvlanframe)
		self.aaepvlanrangeframe.grid(row=2, column=0, columnspan=4, sticky=tk.N+tk.S+tk.W+tk.E)
		self.aaepvlanrangeframe.grid_columnconfigure(0, weight=1)
		self.aaepvlanrangeframe.grid_columnconfigure(3, weight=1)
		self.aaepvlanrangelabel = tk.Label(self.aaepvlanrangeframe, text="VLAN Range  ")
		self.aaepvlanrangelabel.grid(row=0, column=0, sticky=tk.E)
		self.aaepvlanstartentry = tk.Entry(self.aaepvlanrangeframe, bd=1, width=7)
		self.aaepvlanstartentry.grid(row=0, column=1)
		self.aaepvlanstartentry.insert(tk.END, '1')
		self.aaepvlanrangedashlabel = tk.Label(self.aaepvlanrangeframe, text=" - ")
		self.aaepvlanrangedashlabel.grid(row=0, column=2)
		self.aaepvlanendentry = tk.Entry(self.aaepvlanrangeframe, bd=1, width=7)
		self.aaepvlanendentry.grid(row=0, column=3, sticky=tk.W)
		self.aaepvlanendentry.insert(tk.END, '2000')
		self.aaepvlanrangedstatusvar = tk.StringVar()
		self.aaepvlanrangedstatusvar.set("")
		self.aaepvlanrangedstatus = tk.Label(self.aaepvlanrangeframe, textvariable=self.aaepvlanrangedstatusvar)
		self.aaepvlanrangedstatus.grid(row=1, column=0, columnspan=4)
		######
		self.aaepaaepframe = tk.Frame(self.aaepframe, borderwidth=1, relief=tk.SUNKEN)
		self.aaepaaepframe.grid(row=1, column=1, sticky=tk.N+tk.S+tk.W+tk.E)
		self.aaepaaepframe.grid_columnconfigure(0, weight=1)
		self.aaepaaepframe.grid_columnconfigure(1, weight=1)
		self.aaepaaepheadervar = tk.IntVar(value=1)
		self.aaepaaepheader = tk.Checkbutton(self.aaepaaepframe, text="AAEP Profile", variable=self.aaepaaepheadervar, font=("Helvetica", 8, "bold"), command= lambda: self.aaep_frame_control())
		self.aaepaaepheader.grid(row=0, column=0, columnspan=2)
		self.aaepaaeplabel = tk.Label(self.aaepaaepframe, text="Profile Name")
		self.aaepaaeplabel.grid(row=1, column=0, sticky=tk.E)
		self.aaepaaepentry = tk.Entry(self.aaepaaepframe, bd=1, width=15)
		self.aaepaaepentry.grid(row=1, column=1, sticky=tk.W)
		self.aaepaaepentry.insert(tk.END, 'phys')
		self.aaepaaepinfravar = tk.IntVar()
		self.aaepaaepinfrabox = tk.Checkbutton(self.aaepaaepframe, text="Enable Infrastructure VLAN", variable=self.aaepaaepinfravar)
		self.aaepaaepinfrabox.grid(row=2, column=0, columnspan=2)
		######
		self.aaepphysdomframe = tk.Frame(self.aaepframe, borderwidth=1, relief=tk.SUNKEN)
		self.aaepphysdomframe.grid(row=1, column=2, sticky=tk.N+tk.S+tk.W+tk.E)
		self.aaepphysdomframe.grid_columnconfigure(0, weight=1)
		self.aaepphysdomframe.grid_columnconfigure(1, weight=1)
		self.aaepphysdomheadervar = tk.IntVar(value=1)
		self.aaepphysdomheader = tk.Checkbutton(self.aaepphysdomframe, text="Physical Domain", variable=self.aaepphysdomheadervar, font=("Helvetica", 8, "bold"), command= lambda: self.aaep_frame_control())
		self.aaepphysdomheader.grid(row=0, column=0, columnspan=2)
		self.aaepphysdomlabel = tk.Label(self.aaepphysdomframe, text="Physical Domain Name")
		self.aaepphysdomlabel.grid(row=1, column=0, sticky=tk.E)
		self.aaepphysdomentry = tk.Entry(self.aaepphysdomframe, bd=1, width=15)
		self.aaepphysdomentry.grid(row=1, column=1, sticky=tk.W)
		self.aaepphysdomentry.insert(tk.END, 'phys')
		self.aaepphysdomassvar = tk.IntVar(value=1)
		self.aaepphysdomassbox = tk.Checkbutton(self.aaepphysdomframe, text="Associate VLAN Pool and AAEP to Physical Domain", variable=self.aaepphysdomassvar, command= lambda: self.aaep_frame_control())
		self.aaepphysdomassbox.grid(row=2, column=0, columnspan=2)
		######
		self.aaepsubframe = tk.Frame(self.aaepframe, borderwidth=1, relief=tk.SUNKEN)
		self.aaepsubframe.grid(row=2, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.aaepsubframe.grid_columnconfigure(0, weight=1)
		self.aaepsubframe.grid_columnconfigure(1, weight=1)
		self.aaepsubmit = tk.Button(self.aaepsubframe, text='Submit AAEP Settings', command=self.submit_aaep)
		self.aaepsubmit.grid(row=0, column=0, sticky=tk.E)
		self.aaepchecktext = tk.StringVar()
		self.aaepchecktext.set("")
		self.aaepchecklabel = tk.Label(self.aaepsubframe, textvariable=self.aaepchecktext)
		self.aaepchecklabel.grid(row=0, column=1, sticky=tk.W)
		##########################
		######## Mgmt IPs ########
		self.mgmtipframe = tk.Frame(self.bw, borderwidth=4, relief=tk.RAISED)
		self.mgmtipframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.mgmtipframe.grid_columnconfigure(1, weight=1)
		self.mgmtipheadframe = tk.Frame(self.mgmtipframe)
		self.mgmtipheadframe.grid(row=0, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.mgmtipheadframe.grid_columnconfigure(0, weight=1)
		self.mgmtipheader = tk.Label(self.mgmtipheadframe, 
		text="Step 7: Set Out of Band (OOB) Management IPs", font=("Helvetica", 12, "bold"))
		self.mgmtipheader.grid(row=0, column=0)
		######
		self.mgmtipselframe = tk.Frame(self.mgmtipframe)
		self.mgmtipselframe.grid(row=1, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		self.mgmtipselframe.grid_columnconfigure(0, weight=2)
		self.mgmtipselframe.grid_columnconfigure(1, weight=1)
		self.mgmtipselframe.grid_columnconfigure(2, weight=1)
		self.mgmtipselframe.grid_columnconfigure(3, weight=1)
		self.mgmtipnodevar = tk.StringVar(self.mgmtipselframe)
		self.mgmtipnodelabel = tk.Label(self.mgmtipselframe, text="Leaf/Spine Switch")
		self.mgmtipnodelabel.grid(row=0, column=0)
		self.mgmtipnodevar.set("Select Switch")
		self.mgmtipmenu = ttk.Combobox(self.mgmtipselframe, textvariable=self.mgmtipnodevar, width=45)
		self.mgmtipmenu.state(['readonly'])
		self.mgmtipmenu.grid(row=1, column=0)
		######
		self.mgmtipupdateframe = tk.Frame(self.mgmtipselframe)
		self.mgmtipupdateframe.grid(row=2, column=0)
		self.mgmtipupdateframe.grid_columnconfigure(0, weight=1)
		self.mgmtipupdate = tk.Button(self.mgmtipupdateframe, text='Update List', 
		command= lambda: self.update_switch_list(self.mgmtipupdatetext, self.mgmtipupdatelabel, self.mgmtipmenu))
		self.mgmtipupdate.grid(row=0, column=0, sticky=tk.E)
		self.mgmtipupdatetext = tk.StringVar()
		self.mgmtipupdatetext.set("")
		self.mgmtipupdatelabel = tk.Label(self.mgmtipupdateframe, textvariable=self.mgmtipupdatetext)
		self.mgmtipupdatelabel.grid(row=0, column=1)
		######
		self.mgmtipipentrylabel = tk.Label(self.mgmtipselframe, text="OOB IP Address (CIDR)")
		self.mgmtipipentrylabel.grid(row=0, column=1)
		self.mgmtipipentry = tk.Entry(self.mgmtipselframe, bd=5, width=20)
		self.mgmtipipentry.grid(row=1, column=1)
		self.mgmtipipstatustext = tk.StringVar()
		self.mgmtipipstatustext.set("")
		self.mgmtipipstatuslabel = tk.Label(self.mgmtipselframe, textvariable=self.mgmtipipstatustext)
		self.mgmtipipstatuslabel.grid(row=2, column=1)
		######
		self.mgmtipgwentrylabel = tk.Label(self.mgmtipselframe, text="Default Gateway")
		self.mgmtipgwentrylabel.grid(row=0, column=2)
		self.mgmtipgwentry = tk.Entry(self.mgmtipselframe, bd=5, width=20)
		self.mgmtipgwentry.grid(row=1, column=2)
		self.mgmtipgwstatustext = tk.StringVar()
		self.mgmtipgwstatustext.set("")
		self.mgmtipgwstatuslabel = tk.Label(self.mgmtipselframe, textvariable=self.mgmtipgwstatustext)
		self.mgmtipgwstatuslabel.grid(row=2, column=2)
		######
		self.mgmtipsubmit = tk.Button(self.mgmtipselframe, text='Submit OOB IP Settings', command=self.submit_mgmtip)
		self.mgmtipsubmit.grid(row=1, column=3)
		self.mgmtipsubmittext = tk.StringVar()
		self.mgmtipsubmittext.set("")
		self.mgmtipsubmitlabel = tk.Label(self.mgmtipselframe, textvariable=self.mgmtipsubmittext)
		self.mgmtipsubmitlabel.grid(row=2, column=3)
		#######################
		######## CLOSE ########
		self.closebutton = tk.Button(self.bw, text='Close', command=self.close)
		self.closebutton.pack()
		#######################
		#######################
	def on_configure(self, event, canvasobject, window):
		canvasobject.itemconfig(window, width=event.width)
		canvasobject.configure(scrollregion=canvasobject.bbox('all'))
	def on_mousewheel(self, event):
		if abs(event.delta) > 100:  # If we are on a Windows system which uses values of 120
			self.bwcanvas.yview_scroll(int(-1*(event.delta/120)), "units")
		else:  # If we are on a Mac which uses values of 1
			self.bwcanvas.yview_scroll(int(event.delta * -1), "units")
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
				gui.write_output(gui.header(35, "Push Complete", 2))
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
				gui.write_output(gui.header(35, "Push Complete", 2))
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
				gui.write_output(gui.header(35, "Push Complete", 2))
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
			gui.write_output(gui.header(35, "Push Complete", 2))
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
				gui.write_output(gui.header(35, "Push Complete", 2))
	def update_pod_list(self):
		if gui.login_check():
			response = get_pod_list()
			self.pods = response
			podlist = list(self.pods)
			self.podmenu['values'] = podlist
			self.podupdatetext.set("List Updated")
			self.podupdatelabel.configure(fg="green4")
	def update_switch_list(self, updatetextobj, updatelabelobj, updatemenuobj):
		if gui.login_check():
			podname = self.podmenu.get()
			if "select" in podname.lower():
				updatetextobj.set("Select a Pod First")
				updatelabelobj.configure(fg="red")
				return None
			else:
				podid = self.pods[podname]["id"]
				poddata = get_pod_info(podid)
				self.pods[podname].update({"nodes": poddata})
				nodelist = []
				for node in poddata:
					nodefriendlyname = ""
					nodefriendlyname += "Node: "+poddata[node]['id']
					nodefriendlyname += " | "+poddata[node]['name']
					nodefriendlyname += " ("+poddata[node]['role']+")"
					nodelist.append(nodefriendlyname)
					self.pods[podname]['nodes'][node].update({"nodefriendlyname": nodefriendlyname})
				updatemenuobj['values'] = nodelist
				updatetextobj.set("List Updated")
				updatelabelobj.configure(fg="green4")
	def submit_pod_prof(self):
		if gui.login_check():
			self.podproftext.set("Attempting Post...")
			gui.write_output("\n\n\n"+gui.header(35, "Pushing Pod Policy Assignment", 2))
			self.pushdatatup = assign_pod_profile()
			self.pushurl = gui.call.baseurl+self.pushdatatup[0]
			self.pushdata = self.pushdatatup[1]
			gui.write_send_header_body(self.pushurl, self.pushdata)
			self.response = gui.post(url=self.pushurl, data=self.pushdata)
			gui.write_response_header_body(self.response)
			if self.response.getcode() == 200:
				self.podproftext.set("Success: HTTP 200")
				self.podproflabel.configure(fg="green4")
			else:
				self.podproftext.set("Post Failed")
				self.podproflabel.configure(fg="red")
			gui.write_output(gui.header(35, "Push Complete", 2))
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
				gui.write_output(gui.header(35, "Push Complete", 2))
		else:
			self.bgprrstatustext.set("Bad Selection")
			self.bgprrstatuslabel.configure(fg="red")
	def disable_entry(self, entryobj, checkboxobj):
		if checkboxobj.get() == 0:
			entryobj.config(state='disabled')
		elif checkboxobj.get() == 1:
			entryobj.config(state='normal')
	def compile_if_policies(self):
		checkobjlist = [self.ifprofcdpenvar, self.ifprofcdpdisvar, 
		self.ifproflldpenvar, self.ifproflldpdisvar, self.ifprof1gvar, 
		self.ifprof10gvar, self.ifproflacpvar, self.ifprofstatvar, self.ifprofmacvar]
		####
		nameobjlist = [self.ifprofcdpenentry, self.ifprofcdpdisentry, 
		self.ifproflldpenentry, self.ifproflldpdisentry, self.ifprof1gentry, 
		self.ifprof10gentry, self.ifproflacpentry, self.ifprofstatentry, self.ifprofmacentry]
		####
		methlist = [ifprof_cdp_enabled(self.ifprofcdpenentry.get()), 
		ifprof_cdp_disabled(self.ifprofcdpdisentry.get()), 
		ifprof_lldp_enabled(self.ifproflldpenentry.get()), 
		ifprof_lldp_disabled(self.ifproflldpdisentry.get()), 
		ifprof_1g(self.ifprof1gentry.get()), 
		ifprof_10g(self.ifprof10gentry.get()), 
		ifprof_lacp(self.ifproflacpentry.get()), 
		ifprof_static(self.ifprofstatentry.get()), 
		ifprof_mac(self.ifprofmacentry.get())]
		####
		self.ifprofreportobjlist = [self.ifprofcdpen, self.ifprofcdpdis, 
		self.ifproflldpen, self.ifproflldpdis, self.ifprof1g, 
		self.ifprof10g, self.ifproflacp, self.ifprofstat, self.ifprofmac]
		index = 0
		postlist = []
		status = "good"
		for obj in checkobjlist:
			if obj.get() == 1:
				if nameobjlist[index].get() == "":
					nameobjlist[index].configure(bg="yellow")
					status = "empty"
				elif check_aciobjname_entry(nameobjlist[index]) == False:
					nameobjlist[index].configure(bg="red")
					status = "badinput"
				postlist.append([methlist[index], self.ifprofreportobjlist[index]])
			index += 1
		if status == "good":
			return postlist
		else:
			return status
	def submit_if_policies(self):
		plist = self.compile_if_policies()
		for entry in self.ifprofreportobjlist:
			entry.configure(fg="black")
		if plist == "empty":
			self.ifprofchecktext.set("Policy Names Cannot be Empty")
			self.ifprofchecklabel.configure(fg="red")
		elif plist == "badinput":
			self.ifprofchecktext.set("Illegal Policy Name. Allowed Characters are a-z A-Z 0-9 - _ :")
			self.ifprofchecklabel.configure(fg="red")
		elif plist != []:
			if gui.login_check():
				self.ifprofchecktext.set("Attempting Post...")
				gui.write_output("\n\n\n"+gui.header(35, "Pushing Interface Policies", 2))
				resultlist = []
				for push in plist:
					gui.write_output("\n"+gui.header(35, push[0][2], 1))
					pushurl = gui.call.baseurl+push[0][0]
					gui.write_send_header_body(pushurl, push[0][1])
					response = gui.post(url=pushurl, data=push[0][1])
					resultlist.append([response.getcode(), push[1]])
					gui.write_response_header_body(response)
				goodpush = True
				for code in resultlist:
					if code[0] != 200:
						goodpush = False
						code[1].configure(fg="red")
					elif code[0] == 200:
						code[1].configure(fg="green4")
				if goodpush:
					self.ifprofchecktext.set("Success: HTTP 200")
					self.ifprofchecklabel.configure(fg="green4")
				else:
					self.ifprofchecktext.set("Issues Encountered, See Logs")
					self.ifprofchecklabel.configure(fg="red")
		else:
			self.ifprofchecktext.set("Must Select at Least One Policy")
			self.ifprofchecklabel.configure(fg="red")
	def aaep_frame_control(self):
		calling = inspect.stack()[1][4][0].replace("\t", "")
		calling = calling.split(" ")[0]
		if calling == "self.aaepphysdomassbox":
			if self.aaepphysdomassvar.get() == 1:
				self.aaepvlanheadervar.set(value=1)
				self.aaepaaepheadervar.set(value=1)
		####
		if self.aaepvlanheadervar.get() == 0:
			self.aaepvlanpoolentry.config(state='disabled')
			self.aaepvlanstartentry.config(state='disabled')
			self.aaepvlanendentry.config(state='disabled')
			if calling == "self.aaepvlanheader":
				self.aaepphysdomassvar.set(value=0)
		elif self.aaepvlanheadervar.get() == 1:
			self.aaepvlanpoolentry.config(state='normal')
			self.aaepvlanstartentry.config(state='normal')
			self.aaepvlanendentry.config(state='normal')
		####
		if self.aaepaaepheadervar.get() == 0:
			self.aaepaaepentry.config(state='disabled')
			self.aaepaaepinfrabox.config(state='disabled')
			if calling == "self.aaepaaepheader":
				self.aaepphysdomassvar.set(value=0)
		elif self.aaepaaepheadervar.get() == 1:
			self.aaepaaepentry.config(state='normal')
			self.aaepaaepinfrabox.config(state='normal')
		####
		if self.aaepphysdomheadervar.get() == 0:
			self.aaepphysdomentry.config(state='disabled')
			self.aaepphysdomassbox.config(state='disabled')
		elif self.aaepphysdomheadervar.get() == 1:
			self.aaepphysdomentry.config(state='normal')
			self.aaepphysdomassbox.config(state='normal')
	def check_aaep_frame(self):
		checkobjlist = [self.aaepvlanheadervar, self.aaepaaepheadervar, 
		self.aaepphysdomheadervar]
		####
		nameobjlist = [self.aaepvlanpoolentry, self.aaepaaepentry, 
		self.aaepphysdomentry]
		####
		methlist = [create_vlan_pool(self.aaepvlanpoolentry.get(), self.aaepvlanstartentry.get(), self.aaepvlanendentry.get()), create_aaep(self.aaepaaepentry.get(), self.aaepaaepinfravar.get()), create_physical_domain(self.aaepphysdomentry.get())]
		####
		self.aaepreportobjlist = [self.aaepvlanheader, 
		self.aaepaaepheader, self.aaepphysdomheader]
		index = 0
		postlist = []
		status = "good"
		for obj in checkobjlist:
			if obj.get() == 1:
				if nameobjlist[index].get() == "":
					nameobjlist[index].configure(bg="orange")
					status = "empty"
				elif check_aciobjname_entry(nameobjlist[index]) == False:
					nameobjlist[index].configure(bg="red")
					status = "badinput"
				postlist.append([methlist[index], self.aaepreportobjlist[index]])
			index += 1
		if check_vlan_id(self.aaepvlanstartentry, 
		self.aaepvlanrangedstatus, self.aaepvlanrangedstatusvar) == False:
			status = "badvlan"
		if check_vlan_id(self.aaepvlanendentry, 
		self.aaepvlanrangedstatus, self.aaepvlanrangedstatusvar) == False:
			status = "badvlan"
		###############
		if self.aaepvlanheadervar.get() == 1 and self.aaepaaepheadervar.get() == 1 and self.aaepphysdomheadervar.get() == 1:
			if self.aaepphysdomassvar.get()==1:
				assopost1 = associate_pd_aaep(self.aaepaaepentry.get(), 
				self.aaepphysdomentry.get())
				assopost2 = associate_pd_vlanp(self.aaepvlanpoolentry.get(), 
				self.aaepphysdomentry.get())
				postlist.append([assopost1, self.aaepphysdomassbox])
				postlist.append([assopost2, self.aaepphysdomassbox])
		###############
		if status == "good":
			return postlist
		else:
			return status
	def submit_aaep(self):
		self.aaepchecktext.set("")
		self.aaepchecklabel.configure(fg="black")
		plist = self.check_aaep_frame()
		for entry in self.aaepreportobjlist:
			entry.configure(fg="black")
		if plist == "empty":
			self.aaepchecktext.set("Profile Names Cannot be Empty")
			self.aaepchecklabel.configure(fg="red")
		elif plist == "badinput":
			self.aaepchecktext.set("Illegal Profile Name. Allowed Characters are a-z A-Z 0-9 - _ :")
			self.aaepchecklabel.configure(fg="red")
		elif plist == "badvlan":
			self.aaepchecktext.set("Bad VLAN ID")
			self.aaepchecklabel.configure(fg="red")
		elif plist == []:
			self.aaepchecktext.set("Nothing To Do")
			self.aaepchecklabel.configure(fg="orange")
		else:
			if gui.login_check():
				self.aaepchecktext.set("Attempting Post...")
				gui.write_output("\n\n\n"+gui.header(35, "Pushing AAEP Settings", 2))
				resultlist = []
				for push in plist:
					gui.write_output("\n"+gui.header(35, push[0][2], 1))
					pushurl = gui.call.baseurl+push[0][0]
					gui.write_send_header_body(pushurl, push[0][1])
					response = gui.post(url=pushurl, data=push[0][1])
					resultlist.append([response.getcode(), push[1]])
					gui.write_response_header_body(response)
				goodpush = True
				for code in resultlist:
					if code[0] != 200:
						goodpush = False
						code[1].configure(fg="red")
					elif code[0] == 200:
						code[1].configure(fg="green4")
				#########
				if goodpush:
					self.aaepchecktext.set("Success: HTTP 200")
					self.aaepchecklabel.configure(fg="green4")
				else:
					self.aaepchecktext.set("Issues Encountered, See Logs")
					self.aaepchecklabel.configure(fg="red")
	def submit_mgmtip(self):
		checkip = check_cidr_entry(self.mgmtipipentry, self.mgmtipipstatuslabel, self.mgmtipipstatustext)
		checkgw = check_ip_entry(self.mgmtipgwentry, self.mgmtipgwstatuslabel, self.mgmtipgwstatustext)
		if "select" in self.mgmtipmenu.get().lower():
			self.mgmtipupdatetext.set("Bad Selection")
			self.mgmtipupdatelabel.configure(fg="red")
			return None
		if checkip and checkgw:
			if gui.login_check():
				self.mgmtipsubmittext.set("Attempting Post...")
				podid =  self.pods[self.podmenu.get()]['id']
				nodeid = ""
				for node in self.pods[self.podmenu.get()]["nodes"]:
					if self.pods[self.podmenu.get()]["nodes"][node]["nodefriendlyname"] == self.mgmtipmenu.get():
						nodeid = self.pods[self.podmenu.get()]["nodes"][node]["id"]
				self.pushdatatup = assign_mgmt_ip(podid, nodeid, self.mgmtipipentry.get(), self.mgmtipgwentry.get())
				self.pushurl = gui.call.baseurl+self.pushdatatup[0]
				self.pushdata = self.pushdatatup[1]
				gui.write_output("\n\n\n"+gui.header(35, "Pushing Switch OOB Settings", 2))
				gui.write_send_header_body(self.pushurl, self.pushdata)
				self.response = gui.post(url=self.pushurl, data=self.pushdata)
				gui.write_response_header_body(self.response)
				if self.response.getcode() == 200:
					self.mgmtipsubmittext.set("Success: HTTP 200")
					self.mgmtipsubmitlabel.configure(fg="green4")
				else:
					self.mgmtipsubmittext.set("Post Failed")
					self.mgmtipsubmitlabel.configure(fg="red")
				gui.write_output(gui.header(35, "Switch OOB IP Push Complete", 2))
	def close(self):
		gui.bwopen = False
		self.basicwindow.destroy()



class systeminfo:
	def __init__(self, master):
		self.basicwindow = tk.Toplevel(master)
		self.basicwindow.title("Acid ACI System Info")
		self.basicwindow.geometry('750x200')
		self.basicwindow.tk.call('wm','iconphoto',self.basicwindow._w,gui.logo)
		self.bwcanvas = tk.Canvas(self.basicwindow)
		self.bwcanvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
		self.bw = tk.Frame(self.bwcanvas)
		self.bw.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
		self.bwscroll = tk.Scrollbar(self.basicwindow)
		self.bwscroll.pack(side=tk.RIGHT, fill='y')
		self.bwcanvas.configure(yscrollcommand = self.bwscroll.set)
		self.bwscroll.config(command=self.bwcanvas.yview)
		self.interior_id = self.bwcanvas.create_window(0, 0, window=self.bw, anchor=tk.N+tk.W)
		self.bwcanvas.bind('<Configure>', self.on_configure)
		self.bwcanvas.bind_all("<MouseWheel>", self.on_mousewheel)
		self.bwcanvas.configure(scrollregion=self.bwcanvas.bbox("all"))
		self.basicwindow.wm_protocol("WM_DELETE_WINDOW", self.close)
		######## UPDATE ########
		self.updateframe = tk.Frame(self.bw)
		self.updateframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.updateframe.grid_columnconfigure(0, weight=1)
		self.updatebutton = tk.Button(self.updateframe, text='Update', command=self.update)
		self.updatebutton.grid(row=0, column=0)
		########################
		######## CONTROLLERS ########
		self.controllersframe = tk.Frame(self.bw, borderwidth=1, relief=tk.SUNKEN)
		self.controllersframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.controllersframe.grid_columnconfigure(0, weight=1)
		self.controllersheadframe = tk.Frame(self.controllersframe)
		self.controllersheadframe.grid(row=0, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.controllersheadframe.grid_columnconfigure(0, weight=1)
		self.controllershead = tk.Label(self.controllersheadframe, text="ACI Controllers", font=("Helvetica", 12, "bold"))
		self.controllershead.grid(row=0, column=0)
		self.controllersdataframe = tk.Frame(self.controllersframe)
		self.controllersdataframe.grid(row=1, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.controllersdataframe.grid_columnconfigure(0, weight=1)
		self.controllersmappings = {
			0: {"attributename": "name","headname": "Name"},
			1: {"attributename": "id","headname": "Node ID"},
			2: {"attributename": "model","headname": "Model #"},
			3: {"attributename": "serial","headname": "Serial #"},
			4: {"attributename": "oobMgmtAddr","headname": "OOB IP Address"},
			5: {"attributename": "version","headname": "Software Version"},
			}
		self.create_headers(self.controllersdataframe, self.controllersmappings)
		#############################
		######## SPINES ########
		self.spinesframe = tk.Frame(self.bw, borderwidth=1, relief=tk.SUNKEN)
		self.spinesframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.spinesframe.grid_columnconfigure(0, weight=1)
		self.spinesheadframe = tk.Frame(self.spinesframe)
		self.spinesheadframe.grid(row=0, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.spinesheadframe.grid_columnconfigure(0, weight=1)
		self.spineshead = tk.Label(self.spinesheadframe, text="ACI Spine Switches", font=("Helvetica", 12, "bold"))
		self.spineshead.grid(row=0, column=0)
		self.spinesdataframe = tk.Frame(self.spinesframe)
		self.spinesdataframe.grid(row=1, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.spinesdataframe.grid_columnconfigure(0, weight=1)
		self.spinesmappings = {
			0: {"attributename": "name","headname": "Name"},
			1: {"attributename": "id","headname": "Node ID"},
			2: {"attributename": "model","headname": "Model #"},
			3: {"attributename": "serial","headname": "Serial #"},
			4: {"attributename": "oobMgmtAddr","headname": "OOB IP Address"},
			5: {"attributename": "version","headname": "Software Version"},
			}
		self.create_headers(self.spinesdataframe, self.spinesmappings)
		########################
		######## LEAVES ########
		self.leavesframe = tk.Frame(self.bw, borderwidth=1, relief=tk.SUNKEN)
		self.leavesframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.leavesframe.grid_columnconfigure(0, weight=1)
		self.leavesheadframe = tk.Frame(self.leavesframe)
		self.leavesheadframe.grid(row=0, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.leavesheadframe.grid_columnconfigure(0, weight=1)
		self.leaveshead = tk.Label(self.leavesheadframe, text="ACI Leaf Switches", font=("Helvetica", 12, "bold"))
		self.leaveshead.grid(row=0, column=0)
		self.leavesdataframe = tk.Frame(self.leavesframe)
		self.leavesdataframe.grid(row=1, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.leavesdataframe.grid_columnconfigure(0, weight=1)
		self.leavesmappings = {
			0: {"attributename": "name","headname": "Name"},
			1: {"attributename": "id","headname": "Node ID"},
			2: {"attributename": "model","headname": "Model #"},
			3: {"attributename": "serial","headname": "Serial #"},
			4: {"attributename": "oobMgmtAddr","headname": "OOB IP Address"},
			5: {"attributename": "version","headname": "Software Version"},
			}
		self.create_headers(self.leavesdataframe, self.leavesmappings)
		########################
		######## CLOSE ########
		self.closeframe = tk.Frame(self.bw)
		self.closeframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.closeframe.grid_columnconfigure(0, weight=1)
		self.closebutton = tk.Button(self.closeframe, text='Close', command=self.close)
		self.closebutton.grid(row=0, column=0)
		#######################
	def on_configure(self, event):
		self.bwcanvas.itemconfig(self.interior_id, width=event.width)
		self.bwcanvas.configure(scrollregion=self.bwcanvas.bbox('all'))
	def on_mousewheel(self, event):
		if abs(event.delta) > 100:  # If we are on a Windows system which uses values of 120
			self.bwcanvas.yview_scroll(int(-1*(event.delta/120)), "units")
		else:  # If we are on a Mac which uses values of 1
			self.bwcanvas.yview_scroll(int(event.delta * -1), "units")
	def create_headers(self, frame, mappings):
		for header in mappings:
			text = mappings[header]["headname"]
			columnid = header
			newhead = tk.Label(frame, text=text, font=("Helvetica", 8, "bold"))
			newhead.grid(row=0, column=columnid)
			frame.grid_columnconfigure(columnid, weight=1)
	def update(self):
		start_time = time.time()
		if gui.login_check():
			data = pull_aci_info()
			columnorder = ["name", "id", "model", "serial", "oobMgmtAddr", "version"]
			gui.write_output("\n\n\n"+gui.header(35, "System Info", 2))
			gui.write_output("\n"+make_table(columnorder, data))
			timetaken = time.time() - start_time
			##############
			datamappings = {
				"controller": {"frame": self.controllersdataframe,"fieldmappings": self.controllersmappings, "index": 1},
				"spine": {"frame": self.spinesdataframe,"fieldmappings": self.spinesmappings, "index": 1},
				"leaf": {"frame": self.leavesdataframe,"fieldmappings": self.leavesmappings, "index": 1}
				}
			##############
			for node in data:
				frame = datamappings[node["role"]]["frame"]
				fieldmappings = datamappings[node["role"]]["fieldmappings"]
				for field in fieldmappings:
					path = fieldmappings[field]["attributename"]
					text = node[path]
					columnid = field
					rowid = datamappings[node["role"]]["index"]
					#newnodelabel = tk.Label(frame, text=text)
					#newnodelabel.grid(row=rowid, column=columnid)
					newhead = tk.Text(frame, height=1, borderwidth=0)
					newhead.insert(1.0, text)
					newhead.grid(row=rowid, column=columnid)
					newhead.configure(state="disabled")
					newhead.tag_configure("center", justify='center')
					newhead.tag_add("center", 1.0, "end")
				datamappings[node["role"]]["index"] += 1
			self.update_height()
	def update_height(self):
		self.bwcanvas.update()
		self.bwcanvas.configure(scrollregion=self.bwcanvas.bbox("all"))
		if self.bwcanvas.bbox("all")[3] < root.winfo_screenheight():
			width = str(self.basicwindow.winfo_width())
			height = str(self.bwcanvas.bbox("all")[3] + 10)
			self.basicwindow.geometry(width+'x'+height)
	def close(self):
		gui.sysinfoopen = False
		self.basicwindow.destroy()


class ports:
	def __init__(self, master):
		self.basicwindow = tk.Toplevel(master)
		self.basicwindow.title("Acid Configure Ports")
		self.basicwindow.geometry('750x200')
		self.basicwindow.tk.call('wm','iconphoto',self.basicwindow._w,gui.logo)
		self.bwcanvas = tk.Canvas(self.basicwindow)
		self.bwcanvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
		self.bw = tk.Frame(self.bwcanvas)
		self.bw.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
		self.bwscroll = tk.Scrollbar(self.basicwindow)
		self.bwscroll.pack(side=tk.RIGHT, fill='y')
		self.bwcanvas.configure(yscrollcommand = self.bwscroll.set)
		self.bwscroll.config(command=self.bwcanvas.yview)
		self.interior_id = self.bwcanvas.create_window(0, 0, window=self.bw, anchor=tk.N+tk.W)
		self.bwcanvas.bind('<Configure>', lambda event, a=self.bwcanvas, b=self.interior_id:self.on_configure(event, a, b))
		self.bwcanvas.bind_all("<MouseWheel>", self.on_mousewheel)
		self.bwcanvas.configure(scrollregion=self.bwcanvas.bbox("all"))
		self.basicwindow.wm_protocol("WM_DELETE_WINDOW", self.close)
		self.publishedswitches = []
		self.tickedinterfaces = []
		self.publishedinterfaces = []
		######## LEAF PROFILES ########
		self.leafprofframe = tk.Frame(self.bw, borderwidth=4, relief=tk.RAISED)
		self.leafprofframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.leafprofframe.grid_columnconfigure(0, weight=1)
		self.leafprofframe.grid_columnconfigure(1, weight=2)
		self.leafprofheadframe = tk.Frame(self.leafprofframe)
		self.leafprofheadframe.grid(row=0, column=0, columnspan=2, sticky=tk.N+tk.S+tk.W+tk.E)
		self.leafprofheadframe.grid_columnconfigure(0, weight=1)
		self.leafprofhead = tk.Label(self.leafprofheadframe, text="Create Leaf Profiles (Switch Selectors)", font=("Helvetica", 12, "bold"))
		self.leafprofhead.grid(row=0, column=0)
		####
		self.leafprofnameframe = tk.Frame(self.leafprofframe, borderwidth=1, relief=tk.SUNKEN)
		self.leafprofnameframe.grid(row=1, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.leafprofnameframe.grid_columnconfigure(0, weight=1)
		self.leafprofnamelabel = tk.Label(self.leafprofnameframe, text="Leaf Profile Name")
		self.leafprofnamelabel.grid(row=0, column=0)
		self.leafprofnameentry = tk.Entry(self.leafprofnameframe, bd=5, width=35)
		self.leafprofnameentry.grid(row=1, column=0)
		self.leafprofnameentry.config(state='disabled')
		self.leafprofnameautovar = tk.IntVar(value=1)
		self.leafprofnameauto = tk.Checkbutton(self.leafprofnameframe, text="Auto Name", variable=self.leafprofnameautovar, 
		command=self.tick_leafprofnameauto)
		self.leafprofnameauto.grid(row=2, column=0)
		self.leafprofsubmit = tk.Button(self.leafprofnameframe, text='Submit Leaf Profile', command=self.submit_leaf_profile)
		self.leafprofsubmit.grid(row=3, column=0)
		self.leafprofsubmitchecktext = tk.StringVar()
		self.leafprofsubmitchecktext.set("")
		self.leafprofsubmitchecklabel = tk.Label(self.leafprofnameframe, textvariable=self.leafprofsubmitchecktext)
		self.leafprofsubmitchecklabel.grid(row=4, column=0)
		#####################
		self.leafprofswframe = tk.Frame(self.leafprofframe, borderwidth=1, relief=tk.SUNKEN, padx=10)
		self.leafprofswframe.grid(row=1, column=1, sticky=tk.N+tk.S+tk.W+tk.E)
		self.leafprofswframe.grid_columnconfigure(0, weight=1)
		self.leafprofswupdatebutton = tk.Button(self.leafprofswframe, text='Update Switch List', command=self.update_leaf_list)
		self.leafprofswupdatebutton.grid(row=0, column=0)
		####
		self.leafprofswitchtopframe = tk.Frame(self.leafprofswframe, borderwidth=1, relief=tk.SUNKEN)
		self.leafprofswitchtopframe.grid(row=1, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.leafprofswitchcanvas = tk.Canvas(self.leafprofswitchtopframe, width=100, height=100)
		self.leafprofswitchcanvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
		self.leafprofswleavesframe = tk.Frame(self.leafprofswitchcanvas)
		self.leafprofswleavesframe.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
		self.leafprofswleavesframe.grid_columnconfigure(0, weight=1)
		self.leafprofswitchscroll = tk.Scrollbar(self.leafprofswitchtopframe)
		self.leafprofswitchscroll.pack(side=tk.RIGHT, fill='y')
		self.leafprofswitchcanvas.configure(yscrollcommand = self.leafprofswitchscroll.set)
		self.leafprofswitchscroll.config(command=self.leafprofswitchcanvas.yview)
		self.interior_id = self.leafprofswitchcanvas.create_window(0, 0, window=self.leafprofswleavesframe, anchor=tk.N+tk.W)
		self.leafprofswitchcanvas.bind('<Configure>', lambda event, a=self.leafprofswitchcanvas, b=self.interior_id:self.on_configure(event, a, b))
		self.leafprofswitchcanvas.bind_all("<MouseWheel>", self.on_mousewheel)
		self.leafprofswitchcanvas.configure(scrollregion=self.leafprofswitchcanvas.bbox("all"))
		######## VPC ########
		self.vpcframe = tk.Frame(self.bw, borderwidth=4, relief=tk.RAISED)
		self.vpcframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.vpcframe.grid_columnconfigure(0, weight=1)
		self.vpcframe.grid_columnconfigure(1, weight=1)
		self.vpcheadframe = tk.Frame(self.vpcframe)
		self.vpcheadframe.grid(row=0, column=0, columnspan=2, sticky=tk.N+tk.S+tk.W+tk.E)
		self.vpcheadframe.grid_columnconfigure(0, weight=1)
		self.vpchead = tk.Label(self.vpcheadframe, text="Create Virtual Port-Channel (vPC)", font=("Helvetica", 12, "bold"))
		self.vpchead.grid(row=0, column=0)
		#########
		self.vpclistsupdatebutton = tk.Button(self.vpcframe, text='Update Lists', command=self.update_policy_lists)
		self.vpclistsupdatebutton.grid(row=1, column=0, columnspan=2)
		self.vpcupdatechecktext = tk.StringVar()
		self.vpcupdatechecktext.set("")
		self.vpcupdatechecklabel = tk.Label(self.vpcframe, textvariable=self.vpcupdatechecktext)
		self.vpcupdatechecklabel.grid(row=2, column=0, columnspan=2)
		#########
		self.vpcpolgrpframe = tk.Frame(self.vpcframe, borderwidth=1, relief=tk.SUNKEN)
		self.vpcpolgrpframe.grid(row=3, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		self.vpcpolgrpframe.grid_columnconfigure(1, weight=1)
		self.vpcpolgrpfrmheader = tk.Label(self.vpcpolgrpframe, text="Policy Group Settings", font=("Helvetica", 8, "bold"))
		self.vpcpolgrpfrmheader.grid(row=0, column=0, columnspan=2)
		####
		self.vpcpolgrpheader = tk.Label(self.vpcpolgrpframe, text="Policy Group Name")
		self.vpcpolgrpheader.grid(row=1, column=0, columnspan=2)
		self.vpcpolgrpentry = tk.Entry(self.vpcpolgrpframe, bd=5, width=45)
		self.vpcpolgrpentry.grid(row=2, column=0, columnspan=2)
		self.vpcpolgrpentry.config(state='disabled')
		self.vpcpolgrpautovar = tk.IntVar(value=1)
		self.vpcpolgrpauto = tk.Checkbutton(self.vpcpolgrpframe, text="Auto Name", variable=self.vpcpolgrpautovar, 
		command=self.tick_vpcpolgrpnameauto)
		self.vpcpolgrpauto.grid(row=3, column=0, columnspan=2)
		####
		self.vpcaaeplabel = tk.Label(self.vpcpolgrpframe, text="Attachable Entity Profile", pady=14)
		self.vpcaaeplabel.grid(row=4, column=0, sticky=tk.E)
		self.vpcaaepdefault = "Select an AAEP"
		self.vpcaaepvar = tk.StringVar(self.vpcpolgrpframe)
		self.vpcaaepvar.set(self.vpcaaepdefault)
		self.vpcaaep = ttk.Combobox(self.vpcpolgrpframe, textvariable=self.vpcaaepvar, width=30)
		self.vpcaaep.state(['readonly'])
		self.vpcaaep.grid(row=4, column=1)
		####
		self.vpclaglabel = tk.Label(self.vpcpolgrpframe, text="Port-Channel Policy", pady=14)
		self.vpclaglabel.grid(row=5, column=0, sticky=tk.E)
		self.vpclagdefault = "Select a Port-Channel Policy"
		self.vpclagvar = tk.StringVar(self.vpcpolgrpframe)
		self.vpclagvar.set(self.vpclagdefault)
		self.vpclag = ttk.Combobox(self.vpcpolgrpframe, textvariable=self.vpclagvar, width=30)
		self.vpclag.state(['readonly'])
		self.vpclag.grid(row=5, column=1)
		####
		self.vpccdpcheckbuttonvar = tk.IntVar(value=1)
		self.vpccdpcheckbutton = tk.Checkbutton(self.vpcpolgrpframe, text="CDP Policy", variable=self.vpccdpcheckbuttonvar, 
		command=lambda: self.disable_combobox(self.vpccdp, self.vpccdpcheckbuttonvar), pady=12)
		self.vpccdpcheckbutton.grid(row=6, column=0, sticky=tk.E)
		self.vpccdpdefault = "Select a CDP Policy"
		self.vpccdpvar = tk.StringVar(self.vpcpolgrpframe)
		self.vpccdpvar.set(self.vpccdpdefault)
		self.vpccdp = ttk.Combobox(self.vpcpolgrpframe, textvariable=self.vpccdpvar, width=30)
		self.vpccdp.state(['readonly'])
		self.vpccdp.grid(row=6, column=1)
		####
		self.vpclldpcheckbuttonvar = tk.IntVar(value=1)
		self.vpclldpcheckbutton = tk.Checkbutton(self.vpcpolgrpframe, text="LLDP Policy", variable=self.vpclldpcheckbuttonvar, 
		command=lambda: self.disable_combobox(self.vpclldp, self.vpclldpcheckbuttonvar), pady=12)
		self.vpclldpcheckbutton.grid(row=7, column=0, sticky=tk.E)
		self.vpclldpdefault = "Select a LLDP Policy"
		self.vpclldpvar = tk.StringVar(self.vpcpolgrpframe)
		self.vpclldpvar.set(self.vpclldpdefault)
		self.vpclldp = ttk.Combobox(self.vpcpolgrpframe, textvariable=self.vpclldpvar, width=30)
		self.vpclldp.state(['readonly'])
		self.vpclldp.grid(row=7, column=1)
		####
		self.vpclinkcheckbuttonvar = tk.IntVar(value=1)
		self.vpclinkcheckbutton = tk.Checkbutton(self.vpcpolgrpframe, text="Link Policy", variable=self.vpclinkcheckbuttonvar, 
		command=lambda: self.disable_combobox(self.vpclink, self.vpclinkcheckbuttonvar), pady=12)
		self.vpclinkcheckbutton.grid(row=8, column=0, sticky=tk.E)
		self.vpclinkdefault = "Select a Link Policy"
		self.vpclinkvar = tk.StringVar(self.vpcpolgrpframe)
		self.vpclinkvar.set(self.vpclinkdefault)
		self.vpclink = ttk.Combobox(self.vpcpolgrpframe, textvariable=self.vpclinkvar, width=30)
		self.vpclink.state(['readonly'])
		self.vpclink.grid(row=8, column=1)
		##################################
		self.vpcintprofframe = tk.Frame(self.vpcframe, borderwidth=1, relief=tk.SUNKEN)
		self.vpcintprofframe.grid(row=3, column=1, sticky=tk.N+tk.S+tk.W+tk.E)
		self.vpcintprofframe.grid_columnconfigure(0, weight=1)
		self.vpcintprofframe.grid_columnconfigure(1, weight=1)
		self.vpcintproffrmheader = tk.Label(self.vpcintprofframe, text="Interface Profile Settings", font=("Helvetica", 8, "bold"))
		self.vpcintproffrmheader.grid(row=0, column=0, columnspan=3)
		####
		self.vpcintprofheader = tk.Label(self.vpcintprofframe, text="Interface Profile Name")
		self.vpcintprofheader.grid(row=1, column=0, columnspan=3)
		self.vpcintprofentrystr = tk.StringVar()
		self.vpcintprofentrystr.trace("w", lambda *args: self.policy_group_auto_name())
		self.vpcintprofentry = tk.Entry(self.vpcintprofframe, textvariable=self.vpcintprofentrystr, bd=5, width=45)
		self.vpcintprofentry.grid(row=2, column=0, columnspan=3)
		####
		self.vpcleafproflabel = tk.Label(self.vpcintprofframe, text="Switch Selector Profile", pady=15)
		self.vpcleafproflabel.grid(row=3, column=0, sticky=tk.E)
		self.vpcleafprofdefault = "Select a Switch Selector Profile"
		self.vpcleafprofvar = tk.StringVar(self.vpcintprofframe)
		self.vpcleafprofvar.set(self.vpcleafprofdefault)
		self.vpcleafprof = ttk.Combobox(self.vpcintprofframe, textvariable=self.vpcleafprofvar, width=30)
		self.vpcleafprof.state(['readonly'])
		self.vpcleafprof.grid(row=3, column=1)
		####
		self.vpcselframe = tk.Frame(self.vpcintprofframe, borderwidth=1, relief=tk.SUNKEN, padx=10)
		self.vpcselframe.grid(row=4, column=0, columnspan=2)
		self.vpcselframe.grid_columnconfigure(0, weight=1)
		####
		self.vpcportsellabel = tk.Label(self.vpcselframe, text="Port Selector Name")
		self.vpcportsellabel.grid(row=0, column=0)
		self.vpcportselentry = tk.Entry(self.vpcselframe, bd=5, width=35)
		self.vpcportselentry.grid(row=1, column=0)
		self.vpcportselentry.config(state='disabled')
		self.vpcportselautovar = tk.IntVar(value=1)
		self.vpcportselauto = tk.Checkbutton(self.vpcselframe, text="Auto Name", variable=self.vpcportselautovar, 
		command=self.tick_vpcportselnameauto)
		self.vpcportselauto.grid(row=1, column=1)
		####
		self.vpcintupdateframe = tk.Frame(self.vpcselframe)
		self.vpcintupdateframe.grid(row=2, column=0, columnspan=2)
		self.vpcupdateintbutton = tk.Button(self.vpcintupdateframe, text='Update Interface List', command=self.update_switch_interfaces)
		self.vpcupdateintbutton.grid(row=0, column=0)
		self.vpcupdateintchecktext = tk.StringVar()
		self.vpcupdateintchecktext.set("")
		self.vpcupdateintchecklabel = tk.Label(self.vpcintupdateframe, textvariable=self.vpcupdateintchecktext)
		self.vpcupdateintchecklabel.grid(row=1, column=0)
		####
		self.vpcinttopframe = tk.Frame(self.vpcselframe, borderwidth=1, relief=tk.SUNKEN)
		self.vpcinttopframe.grid(row=3, column=0, sticky=tk.N+tk.S+tk.W+tk.E, columnspan=2)
		self.vpcintcanvas = tk.Canvas(self.vpcinttopframe, width=100, height=100)
		self.vpcintcanvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
		self.vpcintframe = tk.Frame(self.vpcintcanvas)
		self.vpcintframe.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
		self.vpcintframe.grid_columnconfigure(0, weight=1)
		self.vpcintscroll = tk.Scrollbar(self.vpcinttopframe)
		self.vpcintscroll.pack(side=tk.RIGHT, fill='y')
		self.vpcintcanvas.configure(yscrollcommand = self.vpcintscroll.set)
		self.vpcintscroll.config(command=self.vpcintcanvas.yview)
		self.interior_id = self.vpcintcanvas.create_window(0, 0, window=self.vpcintframe, anchor=tk.N+tk.W)
		self.vpcintcanvas.bind('<Configure>', lambda event, a=self.vpcintcanvas, b=self.interior_id:self.on_configure(event, a, b))
		self.vpcintcanvas.bind_all("<MouseWheel>", self.on_mousewheel)
		self.vpcintcanvas.configure(scrollregion=self.vpcintcanvas.bbox("all"))
		####
		self.vpcsubmitframe = tk.Frame(self.vpcframe, borderwidth=1, relief=tk.SUNKEN)
		self.vpcsubmitframe.grid(row=4, column=0, sticky=tk.N+tk.S+tk.W+tk.E, columnspan=2)
		self.vpcsubmitframe.grid_columnconfigure(0, weight=1)
		self.vpcsubmitframe.grid_columnconfigure(1, weight=1)
		self.vpcsubmitframe.grid_columnconfigure(2, weight=1)
		self.vpcsubmitbutton = tk.Button(self.vpcsubmitframe, text='Submit vPC Configuration', command=self.submit_vpc)
		self.vpcsubmitbutton.grid(row=0, column=0, columnspan=3)
		####
		self.vpcsubmitpolgrpchecktext = tk.StringVar()
		self.vpcsubmitpolgrpchecktext.set("")
		self.vpcsubmitpolgrpchecklabel = tk.Label(self.vpcsubmitframe, textvariable=self.vpcsubmitpolgrpchecktext)
		self.vpcsubmitpolgrpchecklabel.grid(row=1, column=0)
		####
		self.vpcsubmitintprofchecktext = tk.StringVar()
		self.vpcsubmitintprofchecktext.set("")
		self.vpcsubmitintprofchecklabel = tk.Label(self.vpcsubmitframe, textvariable=self.vpcsubmitintprofchecktext)
		self.vpcsubmitintprofchecklabel.grid(row=1, column=1)
		####
		self.vpcsubmitassochecktext = tk.StringVar()
		self.vpcsubmitassochecktext.set("")
		self.vpcsubmitassochecklabel = tk.Label(self.vpcsubmitframe, textvariable=self.vpcsubmitassochecktext)
		self.vpcsubmitassochecklabel.grid(row=1, column=2)
		######## CLOSE ########
		self.closeframe = tk.Frame(self.bw)
		self.closeframe.pack(fill=tk.BOTH, expand=tk.YES)
		self.closeframe.grid_columnconfigure(0, weight=1)
		self.closebutton = tk.Button(self.closeframe, text='Close', command=self.close)
		self.closebutton.grid(row=0, column=0)
		self.update_height()
		#######################
	def on_configure(self, event, canvasobject, window):
		canvasobject.itemconfig(window, width=event.width)
		canvasobject.configure(scrollregion=canvasobject.bbox('all'))
	def on_mousewheel(self, event):
		if abs(event.delta) > 100:  # If we are on a Windows system which uses values of 120
			self.bwcanvas.yview_scroll(int(-1*(event.delta/120)), "units")
		else:  # If we are on a Mac which uses values of 1
			self.bwcanvas.yview_scroll(int(event.delta * -1), "units")
	def update_height(self):
		self.bwcanvas.update()
		self.bwcanvas.configure(scrollregion=self.bwcanvas.bbox("all"))
		if self.bwcanvas.bbox("all")[3] < root.winfo_screenheight():
			width = str(self.basicwindow.winfo_width())
			height = str(self.bwcanvas.bbox("all")[3] + 10)
			self.basicwindow.geometry(width+'x'+height)
	def disable_entry_inverted(self, entryobj, checkboxobj):
		if checkboxobj.get() == 1:
			entryobj.config(state='disabled')
		elif checkboxobj.get() == 0:
			entryobj.config(state='normal')
	def disable_combobox(self, entryobj, checkboxobj):
		if checkboxobj.get() == 0:
			entryobj.config(state='disabled')
		elif checkboxobj.get() == 1:
			entryobj.config(state='readonly')
	def tick_leafprofnameauto(self):
		self.disable_entry_inverted(self.leafprofnameentry, self.leafprofnameautovar)
		self.update_leaf_profile_name()
	def tick_vpcpolgrpnameauto(self):
		self.disable_entry_inverted(self.vpcpolgrpentry, self.vpcpolgrpautovar)
		self.policy_group_auto_name()
	def tick_vpcportselnameauto(self):
		self.disable_entry_inverted(self.vpcportselentry, self.vpcportselautovar)
		self.interface_selector_auto_name()
	def update_leaf_list(self):
		if gui.login_check():
			data = get_leaves()
			rowindex = 0
			self.publishedswitches = []
			for leaf in data:
				text = leaf["name"]+" ("+leaf["id"]+")"
				switchobjvar = tk.IntVar(value=0)
				switchobj = tk.Checkbutton(self.leafprofswleavesframe, text=text, variable=switchobjvar,
				command= lambda: self.update_leaf_profile_name())
				switchobj.grid(row=rowindex, column=0)
				self.publishedswitches.append({"id": leaf["id"], "intvar": switchobjvar, "checkbutton": switchobj})
				rowindex += 1
			self.leafprofswitchcanvas.update()
			self.leafprofswitchcanvas.configure(scrollregion=self.leafprofswitchcanvas.bbox("all"))
	def get_leaf_profile_autoname(self):
		self.tickedswitches = []
		for switch in self.publishedswitches:
			if switch['intvar'].get() == 1:
				self.tickedswitches.append(switch['id'])
		if len(self.tickedswitches) == 0:
			return ""
		else:
			return named_range(self.tickedswitches, prepend="L")[0]
	def update_leaf_profile_name(self):
		self.get_leaf_profile_autoname()
		if self.leafprofnameautovar.get() == 1:
			self.leafprofnameentry.config(state='normal')
			self.leafprofnameentry.delete(0, 'end')
			text = self.get_leaf_profile_autoname()
			self.leafprofnameentry.insert(tk.END, text)
			self.leafprofnameentry.config(state='disabled')
	def submit_leaf_profile(self):
		self.leafprofsubmitchecklabel.configure(fg="black")
		self.leafprofsubmitchecktext.set("")
		if not check_aciobjname_entry(self.leafprofnameentry):
			self.leafprofsubmitchecklabel.configure(fg="red")
			self.leafprofsubmitchecktext.set("Bad Profile Name")
		else:
			if self.get_leaf_profile_autoname() == "":
				self.leafprofsubmitchecklabel.configure(fg="red")
				self.leafprofsubmitchecktext.set("Need to Select At Least One Switch")
			else:
				if gui.login_check():
					self.leafprofsubmitchecktext.set("Attempting Post...")
					ranges = named_range(self.tickedswitches, prepend="")[1]
					self.pushdatatup = create_leaf_profile(self.leafprofnameentry.get(), self.leafprofnameentry.get(), ranges)
					self.pushurl = gui.call.baseurl+self.pushdatatup[0]
					self.pushdata = self.pushdatatup[1]
					gui.write_output("\n\n\n"+gui.header(35, "Pushing Leaf Profile", 2))
					gui.write_send_header_body(self.pushurl, self.pushdata)
					self.response = gui.post(url=self.pushurl, data=self.pushdata)
					gui.write_response_header_body(self.response)
					if self.response.getcode() == 200:
						self.leafprofsubmitchecktext.set("Success: HTTP 200")
						self.leafprofsubmitchecklabel.configure(fg="green4")
					else:
						self.leafprofsubmitchecktext.set("Post Failed")
						self.leafprofsubmitchecklabel.configure(fg="red")
					gui.write_output(gui.header(35, "Leaf Profile Push Complete", 2))
	def update_policy_lists(self):
		if gui.login_check():
			self.vpcupdatechecktext.set("Updating...")
			self.vpcupdatechecklabel.configure(fg="black")
			data = get_infra_policies()
			mappings = {"infraAttEntityP": self.vpcaaep, "lacpLagPol": self.vpclag, "cdpIfPol": self.vpccdp,
			"lldpIfPol": self.vpclldp, "fabricHIfPol": self.vpclink, "infraNodeP": self.vpcleafprof}
			for policyset in data:
				comboboxobj = mappings[policyset]
				policylist = []
				for policy in data[policyset]:
					policylist.append(policy["name"])
				comboboxobj['values'] = policylist
			self.vpcupdatechecktext.set("Updated")
			self.vpcupdatechecklabel.configure(fg="green4")
	def update_switch_interfaces(self):
		if gui.login_check():
			self.vpcupdateintchecktext.set("Updating...")
			self.vpcupdateintchecklabel.configure(fg="black")
			self.vpcleafproflabel.configure(fg="black")
			if self.vpcleafprof.get() == self.vpcleafprofdefault:
				self.vpcupdateintchecktext.set("Select a Switch Selector First")
				self.vpcupdateintchecklabel.configure(fg="red")
				self.vpcleafproflabel.configure(fg="red")
			else:
				checkswitchids = get_leaf_profile_switchids(self.vpcleafprof.get())
				switches = get_leaves()
				interfacedict = {}
				for switchid in checkswitchids:
					for switch in switches:
						if switch["id"] == switchid:
							podid = switch["podid"]
							interfaces = get_switch_interfaces(podid, switchid)
							interfacelist = []
							for interface in interfaces:
								interfacelist.append(interface["id"])
							interfacedict.update({switchid: interfacelist})
				if interfacedict == {}:
					self.vpcupdateintchecktext.set("No Switches in Switch Selector")
					self.vpcupdateintchecklabel.configure(fg="yellow3")
				else:
					#### List only common interfaces ####
					dictcounter = {}
					for switch in interfacedict:
						for interface in interfacedict[switch]:
							if interface not in dictcounter:
								dictcounter.update({interface: 1})
							else:
								dictcounter[interface] += 1
					finalinterfacelist = []
					for interface in dictcounter:
						if dictcounter[interface] == len(interfacedict):
							finalinterfacelist.append(interface)
					if finalinterfacelist == []:
						self.vpcupdateintchecktext.set("No Common Interfaces in Switches")
						self.vpcupdateintchecklabel.configure(fg="yellow3")
					else:
						finalinterfacelist = sort_interfaces(finalinterfacelist)
						rowindex = 0
						self.publishedinterfaces = []
						for interface in finalinterfacelist:
							interfaceobjvar = tk.IntVar(value=0)
							interfaceobj = tk.Checkbutton(self.vpcintframe, text=interface, variable=interfaceobjvar, 
							command= lambda: self.interface_selector_auto_name())
							interfaceobj.grid(row=rowindex, column=0)
							shortname = re.findall("[0-9]+$", interface)[0]
							self.publishedinterfaces.append({"id": interface, "shortname": shortname, "intvar": interfaceobjvar, "checkbutton": interfaceobj})
							rowindex += 1
						self.vpcintcanvas.update()
						self.vpcintcanvas.configure(scrollregion=self.vpcintcanvas.bbox("all"))
						self.vpcupdateintchecktext.set("Updated")
						self.vpcupdateintchecklabel.configure(fg="green4")
	def get_port_selector_autoname(self):
		self.tickedinterfaces = []
		for interface in self.publishedinterfaces:
			if interface['intvar'].get() == 1:
				self.tickedinterfaces.append(interface['shortname'])
		if len(self.tickedinterfaces) == 0:
			return ""
		else:
			return named_range(self.tickedinterfaces, prepend="Port")[0]
	def interface_selector_auto_name(self):
		text = self.get_port_selector_autoname()
		if self.vpcportselautovar.get() == 1:
			self.vpcportselentry.config(state='normal')
			self.vpcportselentry.delete(0, 'end')
			self.vpcportselentry.insert(tk.END, text)
			self.vpcportselentry.config(state='disabled')
	def policy_group_auto_name(self, *args):
		if self.vpcpolgrpautovar.get() == 1:
			self.vpcpolgrpentry.config(state='normal')
			self.vpcpolgrpentry.delete(0, 'end')
			text = self.vpcintprofentrystr.get()
			self.vpcpolgrpentry.insert(tk.END, text)
			self.vpcpolgrpentry.config(state='disabled')
	def submit_vpc(self):
		if gui.login_check():
			dropdownoptions = [
				{"name": "aaep", "entry": self.vpcaaep, "default": self.vpcaaepdefault, "label": self.vpcaaeplabel, "ticked": 1},
				{"name": "lag", "entry": self.vpclag, "default": self.vpclagdefault, "label": self.vpclaglabel, "ticked": 1},
				{"name": "leafprof", "entry": self.vpcleafprof, "default": self.vpcleafprofdefault, "label": self.vpcleafproflabel, "ticked": 1},
				{"name": "cdp", "entry": self.vpccdp, "default": self.vpccdpdefault, "label": self.vpccdpcheckbutton, "ticked": self.vpccdpcheckbuttonvar.get()},
				{"name": "lldp", "entry": self.vpclldp, "default": self.vpclldpdefault, "label": self.vpclldpcheckbutton, "ticked": self.vpclldpcheckbuttonvar.get()},
				{"name": "link", "entry": self.vpclink, "default": self.vpclinkdefault, "label": self.vpclinkcheckbutton, "ticked": self.vpclinkcheckbuttonvar.get()}]
			entryboxes = [
				{"entry": self.vpcintprofentry, "label": self.vpcintprofheader, "autoticked": 0},
				{"entry": self.vpcpolgrpentry, "label": self.vpcpolgrpheader, "autoticked": self.vpcpolgrpautovar.get()},
				{"entry": self.vpcportselentry, "label": self.vpcportsellabel, "autoticked": self.vpcportselautovar.get()},]
			############ Check Inputs ############
			### Check Drop Down Options ###
			checksout = True
			errormessages = {}
			for box in dropdownoptions:
				box["label"].configure(fg="black")
				if box["ticked"] == 1:
					if box["entry"].get() == box["default"]:
						box["label"].configure(fg="red")
						checksout = False
						errormessages.update({1: " (Drop Down Unselected)"})
			### Check Entry Boxes ###
			for box in entryboxes:
				box["entry"].configure(bg="white")
				box["label"].configure(fg="black")
				if not check_aciobjname_entry(box["entry"]):
					box["label"].configure(fg="red")
					checksout = False
					errormessages.update({2: " (Entry Box Incorrect)"})
			### Check Ticked Interfaces ###
			if self.tickedinterfaces == []:
				errormessages.update({3: " (No Interfaces Selected)"})
				checksout = False
			############ Report Errors ############
			error = ""
			for message in errormessages:
				error += errormessages[message]
			self.vpcsubmitpolgrpchecktext.set("")
			self.vpcsubmitpolgrpchecklabel.configure(fg="black")
			self.vpcsubmitintprofchecktext.set("")
			self.vpcsubmitintprofchecklabel.configure(fg="black")
			self.vpcsubmitassochecktext.set("")
			self.vpcsubmitassochecklabel.configure(fg="black")
			if not checksout:
				self.vpcsubmitintprofchecktext.set(error)
				self.vpcsubmitintprofchecklabel.configure(fg="red")
			else:
				############ Process Inputs ############
				policygroupname = self.vpcpolgrpentry.get()
				valuedict = {"aaep": False, "lag": False, "cdp": False , "lldp": False, "link": False}
				for box in dropdownoptions:
					if box["ticked"] == 1:
						valuedict[box["name"]] = box["entry"].get()
				####
				profilename = self.vpcintprofentry.get()
				selectorname = self.vpcportselentry.get()
				interfacerange = named_range(self.tickedinterfaces)[1]  # Range of interfaces for profile selector
				############ Execute Policy Group ############
				self.vpcsubmitpolgrpchecktext.set("Attempting Post...")
				self.pushdatatup = create_vpc_interface_policy_group(policygroupname, valuedict)
				self.pushurl = gui.call.baseurl+self.pushdatatup[0]
				self.pushdata = self.pushdatatup[1]
				gui.write_output("\n\n\n"+gui.header(35, "Pushing Interface Policy Group", 2))
				gui.write_send_header_body(self.pushurl, self.pushdata)
				self.response = gui.post(url=self.pushurl, data=self.pushdata)
				gui.write_response_header_body(self.response)
				if self.response.getcode() == 200:
					self.vpcsubmitpolgrpchecktext.set("(Policy Group: Success)")
					self.vpcsubmitpolgrpchecklabel.configure(fg="green4")
				else:
					self.vpcsubmitpolgrpchecktext.set("(Policy Group: Failed)")
					self.vpcsubmitpolgrpchecklabel.configure(fg="red")
				gui.write_output(gui.header(35, "Interface Policy Group Push Complete", 2))
				############ Execute Interface Profile ############
				self.vpcsubmitintprofchecktext.set("Attempting Post...")
				self.pushdatatup = create_vpc_interface_profile(profilename, selectorname, policygroupname, interfacerange)
				self.pushurl = gui.call.baseurl+self.pushdatatup[0]
				self.pushdata = self.pushdatatup[1]
				gui.write_output("\n\n\n"+gui.header(35, "Pushing Interface Profile", 2))
				gui.write_send_header_body(self.pushurl, self.pushdata)
				self.response = gui.post(url=self.pushurl, data=self.pushdata)
				gui.write_response_header_body(self.response)
				if self.response.getcode() == 200:
					self.vpcsubmitintprofchecktext.set("(Interface Profile: Success)")
					self.vpcsubmitintprofchecklabel.configure(fg="green4")
				else:
					self.vpcsubmitintprofchecktext.set("(Interface Profile: Failed)")
					self.vpcsubmitintprofchecklabel.configure(fg="red")
				gui.write_output(gui.header(35, "Interface Profile Push Complete", 2))
				############ Execute Profile Association ############
				self.vpcsubmitassochecktext.set("Attempting Post...")
				self.pushdatatup = associate_intprofile_leafprofile(profilename, self.vpcleafprof.get())
				self.pushurl = gui.call.baseurl+self.pushdatatup[0]
				self.pushdata = self.pushdatatup[1]
				gui.write_output("\n\n\n"+gui.header(35, "Pushing Profile Association", 2))
				gui.write_send_header_body(self.pushurl, self.pushdata)
				self.response = gui.post(url=self.pushurl, data=self.pushdata)
				gui.write_response_header_body(self.response)
				if self.response.getcode() == 200:
					self.vpcsubmitassochecktext.set("(Leaf Association: Success)")
					self.vpcsubmitassochecklabel.configure(fg="green4")
				else:
					self.vpcsubmitassochecktext.set("(Leaf Association: Failed)")
					self.vpcsubmitassochecklabel.configure(fg="red")
				gui.write_output(gui.header(35, "Profile Association Push Complete", 2))
	def close(self):
		gui.portsopen = False
		self.basicwindow.destroy()






#####################################
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

def check_cidr_entry(entryobj, labelobj, textobj):
	textobj.set("")
	if entry_is_empty(entryobj):
		return False
	else:
		checkaddress = check_ipv4("cidr", entryobj.get())
		if checkaddress['status'] == 'fail':
			entryobj.configure(bg="red")
			textobj.set("Unrecognized IP CIDR Address")
			labelobj.configure(fg="red")
			return False
		elif checkaddress['status'] == 'pass':
			textobj.set("Legal IP CIDR Address")
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

def check_aciobjname_entry(entryobj):
	entrystate = entryobj.cget("state")
	entryobj.configure(state="normal")
	entryobj.configure(bg="white")
	if entry_is_empty(entryobj):
		entryobj.configure(state=entrystate)
		return False
	else:
		characterregex = "^[a-zA-Z0-9\-\.\_\:]+$"
		result = False
		for entry in re.findall(characterregex, entryobj.get()):
			if entry == entryobj.get():
				result = True
		if result == False:
			entryobj.configure(bg="red")
		entryobj.configure(state=entrystate)
		return result

def entry_is_empty(entryobj):
	entryobj.configure(bg="white")
	if entryobj.get() == "":
		entryobj.configure(bg="yellow")
		return True
	else:
		return False

def check_vlan_id(entryobj, labelobj, textobj):
	textobj.set("")
	if entry_is_empty(entryobj):
		return False
	else:
		try:
			vlanid = int(entryobj.get())
			if vlanid > 0 and vlanid < 4095:
				return True
			else:
				entryobj.configure(bg="red")
				textobj.set("Must be Between 1 and 4094")
				labelobj.configure(fg="red")
				return False
		except ValueError:
			entryobj.configure(bg="red")
			textobj.set("Must be Between 1 and 4094")
			labelobj.configure(fg="red")
			return False

########################################################

class acicalls:
	def __init__(self, username="admin", password="admin", hostname="192.168.1.1"):
		self.username = username
		self.password = password
		self.hostname = hostname
		self.baseurl = "https://" + self.hostname
		try:
			self.gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
		except AttributeError:
			try:
				self.gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
			except AttributeError:
				self.gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
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
			else:
				return {"status": "failed", "response": exception, "code": 0, "description": exception, "reason": "unknown"}
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

########################################################

def get_calls(pushurl, message):
	gui.write_output("\n\n\n"+gui.header(35, message, 2))
	gui.write_send_header_body(pushurl, "<No Body>")
	response = gui.get(url=pushurl)
	rawdata = response.read()
	rawheader = response.info()
	gui.write_response_header_body((rawheader, rawdata))
	return json.loads(rawdata)

def pull_aci_info():
	preresult = []
	poddict = get_pod_list()
	for pod in poddict:
		podid = poddict[pod]['id']
		nodes = get_all_nodes(podid=podid)
		nodeorder = []
		for node in nodes:
			nodedata = node
			nodedata.update(get_node_info(podid, node['id']))
			if nodedata['role'] == 'controller':
				nodedata.update(get_controller_fw(podid, node['id']))
			else:
				nodedata.update(get_switch_fw(podid, node['id']))
			nodeorder.append(int(node['id']))
			preresult.append(node)
		#### Order Nodes ####
		result = []
		nodeorder.sort()
		for nodeid in nodeorder:
			for node in preresult:
				if node['id'] == str(nodeid):result.append(node); break
		#####################
	return result

####################################### Messing with threading #########################################
################ Comment out pull_aci_info() and uncomment this to continue testing ####################
####import queue
####import threading
####
####def pull_aci_info():
####	result = []
####	start_time = time.time()
####	poddict = get_pod_list()
####	for pod in poddict:
####		podid = poddict[pod]['id']
####		nodes = get_all_nodes(podid=podid)
####		########
####		queuedata = queue.Queue()
####		#######
####		print(len(nodes))
####		for node in nodes:
####			thread = threading.Thread(target=dontthreadonme, args=(queuedata, get_node_info, podid, node['id']))
####			thread.start()
####		wthread = threading.Thread(target=watcher, args=(queuedata, start_time))
####		wthread.start()
####		#while threading.activeCount():
####		#	time.sleep(0.5)
####		#	print(threading.activeCount())
####		#	print(queuedata.qsize())
####			#if exc_info:
####			#	raise exc_info[1]
####		#for node in range(queuedata.qsize()):
####		#	print(queuedata.get())
####		#	
####		#	
####		#	
####		#	nodedata = node
####		#	nodedata.update(get_node_info(podid, node['id']))
####		#	if nodedata['role'] == 'controller':
####		#		nodedata.update(get_controller_fw(podid, node['id']))
####		#	else:
####		#		nodedata.update(get_switch_fw(podid, node['id']))
####		#	result.append(node)
####		########
####		#columnorder = ["name", "id", "model", "serial", "oobMgmtAddr"]
####		#gui.write_output("\n\n\n"+gui.header(35, "System Info", 2))
####		#gui.write_output("\n\n\n"+make_table(columnorder, result))
####		#gui.write_output(time.time() - start_time)
####
####def dontthreadonme(queuedata, method, *args):
####	result = method(*args)
####	queuedata.put(result)
####
####def watcher(queuedata, start_time):
####	while threading.activeCount() > 2:
####		time.sleep(0.5)
####		print(threading.activeCount())
####		print(queuedata.qsize())
####	print("\n\n\n\n\n\n done!")
####	for node in range(queuedata.qsize()):
####		print(queuedata.get())
####	gui.write_output(time.time() - start_time)
#########################################################################################################

def get_pod_list():
	pushurl = gui.call.baseurl+"/api/node/class/fabricPod.json"
	message = "Updating Pod List"
	data = get_calls(pushurl, message)
	index = 0
	result = {}
	for each in range(int(data['totalCount'])):
		podid = data['imdata'][index]['fabricPod']['attributes']['id']
		podname = "Pod "+podid
		result.update({podname:{"id": podid}})
		index += 1
	return result

def get_all_nodes(podid="1"):
	pushurl = gui.call.baseurl+"/api/node/mo/topology/pod-"+podid+".json?query-target=children&target-subtree-class=fabricNode"
	message = "Getting Node Info"
	data = get_calls(pushurl, message)
	result = []
	for node in data["imdata"]:
		result.append(node["fabricNode"]["attributes"])
	columnorder = ['name', 'model', 'serial', 'role']
	return result

def get_pod_info(podid="1"):
	decoquery = 'query-target=children&target-subtree-class=fabricNode&query-target-filter=and(ne(fabricNode.role,"controller"))'
	query = quote_plus(decoquery)
	pushurl = gui.call.baseurl+"/api/node/mo/topology/pod-"+podid+".json?"+query
	message = "Getting Pod "+podid+" Info"
	data = get_calls(pushurl, message)
	index = 0
	nodes = {}
	for each in range(int(data['totalCount'])):
		atts = data['imdata'][index]['fabricNode']['attributes']
		nodes.update({atts['id']: atts})
		index += 1
	return nodes

def get_node_info(podid, nodeid):
	pushurl = gui.call.baseurl+"/api/node/mo/topology/pod-"+podid+"/node-"+nodeid+".json?query-target=children&target-subtree-class=topSystem"
	message = "Getting More Info on Node "+nodeid
	data = get_calls(pushurl, message)
	return data["imdata"][0]["topSystem"]["attributes"]

def get_switch_fw(podid, nodeid):
	pushurl = gui.call.baseurl+"/api/node/class/topology/pod-"+podid+"/node-"+nodeid+"/firmwareRunning.json"
	message = "Getting Firmware for Node "+nodeid
	data = get_calls(pushurl, message)
	result = {}
	attlist = ["version", "peVer", "ksFile"]
	for att in attlist:
		result.update({att: data["imdata"][0]["firmwareRunning"]["attributes"][att]})
	return result

def get_controller_fw(podid, nodeid):
	pushurl = gui.call.baseurl+"/api/node/class/topology/pod-"+podid+"/node-"+nodeid+"/firmwareCtrlrRunning.json"
	message = "Getting Firmware for Node "+nodeid
	data = get_calls(pushurl, message)
	result = {}
	attlist = ["version"]
	for att in attlist:
		result.update({att: data["imdata"][0]["firmwareCtrlrRunning"]["attributes"][att]})
	return result

def get_lag_policies():
	pushurl = gui.call.baseurl+"/api/node/class/lacpLagPol.json?rsp-subtree=full&rsp-subtree-class=tagAliasInst"
	message = "Getting List of LAG Policies"
	data = get_calls(pushurl, message)
	result = []
	for policy in data["imdata"]:
		result.append(policy["lacpLagPol"]["attributes"]["name"])
	return result

def get_infra_policies():
	pushurl = gui.call.baseurl+"/api/node/mo/uni/infra.json?query-target=children"
	message = "Getting List of Interface Policies"
	data = get_calls(pushurl, message)
	result = {"lacpLagPol": [], "cdpIfPol": [], "lldpIfPol": [], "infraAttEntityP": [], "fabricHIfPol": [], "infraNodeP": []}
	for policy in data["imdata"]:
		policytype = list(policy)[0]
		if policytype in result:
			result[policytype].append(policy[policytype]["attributes"])
	return result

def get_leaf_profile_switchids(profilename):
	pushurl = gui.call.baseurl+"/api/node/mo/uni/infra/nprof-"+profilename+".json?query-target=subtree&target-subtree-class=infraLeafS&target-subtree-class=infraNodeBlk,infraRsAccNodePGrp&query-target=subtree"
	message = "Getting Leaf Profile "+ profilename
	data = get_calls(pushurl, message)
	blockgroups = []
	for block in data["imdata"]:
		for blockcode in block:
			if blockcode == "infraNodeBlk":
				fromval = block[blockcode]["attributes"]["from_"]
				toval = block[blockcode]["attributes"]["to_"]
				blockgroups.append([fromval, toval])
	result = expand_ranges(blockgroups)
	return result

def get_leaves():
	pushurl = gui.call.baseurl+'/api/node/class/fabricNode.json?query-target-filter=and(eq(fabricNode.role,"leaf"))'
	message = "Getting List of Leaf Switches"
	data = get_calls(pushurl, message)
	preresult = {}
	for node in data["imdata"]:
		leafid = node["fabricNode"]["attributes"]["id"]
		preresult.update({leafid: node["fabricNode"]["attributes"]})
		preresult[leafid].update({"podid": get_switch_pod_id(node["fabricNode"]["attributes"])})
	nodelist = list(preresult)
	nodelist.sort()
	result = []
	for node in nodelist:
		result.append(preresult[node])
	return result

def get_switch_interfaces(podid, switchid):
	pushurl = gui.call.baseurl+"/api/node/class/topology/pod-"+podid+"/node-"+switchid+"/l1PhysIf.json"
	message = "Getting List Switch Interfaces"
	data = get_calls(pushurl, message)
	preresult = {}
	iflist = []
	for interface in data['imdata']:
		preresult.update({interface["l1PhysIf"]["attributes"]["id"]: interface["l1PhysIf"]["attributes"]})
		iflist.append(interface["l1PhysIf"]["attributes"]["id"])
	iflist = sort_interfaces(iflist)
	result = []
	for interface in iflist:
		result.append(preresult[interface])
	return result

"/api/node/mo/uni/infra.json?query-target=subtree&target-subtree-class=infraNodeP&target-subtree-class=infraLeafS,infraNodeBlk,infraRsAccNodePGrp&query-target=subtree"

################################## C H E C K   D O M A I N   N A M E ##################################
#######################################################################################################

##### Check a domain or FQDN host name for legitimacy and proper formatting #####
##### Input "domainname" is a string of the domain name #####
##### Output will be a pass/fail with status messages formatted in the standard messaging format (see "status_reporter" method for more info) #####

def check_domainname(domainname):
	result = {"status": "pass", "messages": []} # Start with a passing result
	##### 1. Check that only legal characters are in name (RFC883 and RFC952) #####
	characterregex = "^[a-zA-Z0-9\-\.]+$" # A list of the valid domain-name characters in a domain name
	charactercheck = "fail" # Set initial charactercheck result to fail. Pass only if check clears
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




######################################### M A K E   T A B L E #########################################
#######################################################################################################

##### Create a table of data from a list of dictionaries where the key in each dict is the header and the val is the column value #####
##### The tabledata input is the list of dictionaries and the column order is an ordered list of how the columns should be displayed #####
##### The output is a printable table with automatically spaced columns, centered headers and values #####

def make_table(columnorder, tabledata):
	##### Check and fix input type #####
	if type(tabledata) != type([]): # If tabledata is not a list
		tabledata = [tabledata] # Nest it in a list
	##### Set seperators and spacers #####
	tablewrap = "#" # The character used to wrap the table
	headsep = "=" # The character used to seperate the headers from the table values
	columnsep = "|" # The character used to seperate each value in the table
	columnspace = "  " # The amount of space between the largest value and its column seperator
	##### Generate a dictionary which contains the length of the longest value or head in each column #####
	datalengthdict = {} # Create the dictionary for storing the longest values
	for columnhead in columnorder: # For each column in the columnorder input
		datalengthdict.update({columnhead: len(columnhead)}) # Create a key in the length dict with a value which is the length of the header
	for row in tabledata: # For each row entry in the tabledata list of dicts
		for item in columnorder: # For column entry in that row
			if len(re.sub(r'\x1b[^m]*m', "",  row[item])) > datalengthdict[item]: # If the length of this column entry is longer than the current longest entry
				datalengthdict[item] = len(row[item]) # Then change the value of entry
	##### Calculate total table width #####
	totalwidth = 0 # Initialize at 0
	for columnwidth in datalengthdict: # For each of the longest column values
		totalwidth += datalengthdict[columnwidth] # Add them all up into the totalwidth variable
	totalwidth += len(columnorder) * len(columnspace) * 2 # Account for double spaces on each side of each column value
	totalwidth += len(columnorder) - 1 # Account for seperators for each row entry minus 1
	totalwidth += 2 # Account for start and end characters for each row
	##### Build Header #####
	result = tablewrap * totalwidth + "\n" + tablewrap # Initialize the result with the top header, line break, and beginning of header line
	columnqty = len(columnorder) # Count number of columns
	for columnhead in columnorder: # For each column header value
		spacing = {"before": 0, "after": 0} # Initialize the before and after spacing for that header value before the columnsep
		spacing["before"] = int((datalengthdict[columnhead] - len(columnhead)) / 2) # Calculate the before spacing
		spacing["after"] = int((datalengthdict[columnhead] - len(columnhead)) - spacing["before"]) # Calculate the after spacing
		result += columnspace + spacing["before"] * " " + columnhead + spacing["after"] * " " + columnspace # Add the header entry with spacing
		if columnqty > 1: # If this is not the last entry
			result += columnsep # Append a column seperator
		del spacing # Remove the spacing variable so it can be used again
		columnqty -= 1 # Remove 1 from the counter to keep track of when we hit the last column
	del columnqty # Remove the column spacing variable so it can be used again
	result += tablewrap + "\n" + tablewrap + headsep * (totalwidth - 2) + tablewrap + "\n" # Add bottom wrapper to header
	##### Build table contents #####
	result += tablewrap # Add the first wrapper of the value table
	for row in tabledata: # For each row (dict) in the tabledata input
		columnqty = len(columnorder) # Set a column counter so we can detect the last entry in this row
		for column in columnorder: # For each value in this row, but using the correct order from column order
			spacing = {"before": 0, "after": 0} # Initialize the before and after spacing for that header value before the columnsep
			spacing["before"] = int((datalengthdict[column] - len(re.sub(r'\x1b[^m]*m', "",  row[column]))) / 2) # Calculate the before spacing
			spacing["after"] = int((datalengthdict[column] - len(re.sub(r'\x1b[^m]*m', "",  row[column]))) - spacing["before"]) # Calculate the after spacing
			result += columnspace + spacing["before"] * " " + row[column] + spacing["after"] * " " + columnspace # Add the entry to the row with spacing
			if columnqty == 1: # If this is the last entry in this row
				result += tablewrap + "\n" + tablewrap # Add the wrapper, a line break, and start the next row
			else: # If this is not the last entry in the row
				result += columnsep # Add a column seperator
			del spacing # Remove the spacing settings for this entry 
			columnqty -= 1 # Keep count of how many row values are left so we know when we hit the last one
	result += tablewrap * (totalwidth - 1) # When all rows are complete, wrap the table with a trailer
	return result

########################################## USAGE AND EXAMPLES #########################################
#
#>>> tabledataindict = [{"key1": "val111111111", "key2": "val123", "key3": "v"}, {"key1": "val21", "key2": "val22", "key3": "v"}, {"key1": "val31", "key2": "val32", "key3": "va"}, {"key1": "val41", "key2": "val4233", "key3": "va"}, {"key1": "val51", "key2": "val52", "key3": "vasomething longer"}]
#
#>>> ordercolumnslike = ["key1", "key2", "key3"]
#
#>>> print(make_table(ordercolumnslike, tabledataindict))
#
#######################################################################################################
#######################################################################################################


######################################### N A M E D  R A N G E #########################################
########################################################################################################
'''
- Create a shorthand name for a list of integers; shortening the consecutive integers into 
    range statements, ie: [1, 2, 3, 4, 6] becomes "1-4_6"
- The inputlist input is a list of integers or strings of integers (or a mix), prepend adds a
    string to the beginning of each number, divider is used to separate statements
- The output is string which contains the shorthand name with prepends and dividers
'''
def named_range(inputlist, prepend="", divider="_"):
	#### Convert to integers and sort ####
	sorted = []
	for num in inputlist:
		sorted.append(int(num))
	sorted.sort()
	###################################################
	#### Set some variables to be used in ranging ####
	statements = []  # Statements are put in a list for assembly later
	prevnumber = None  # The previously processed number
	firstnumber = None  # The first number in a range (ie: 1, 2, 3, 4...)
	range = False
	##########################
	#### Ranging Process #####
	for currentnumber in sorted:
		if prevnumber == None:  # If this is the first iteration of the for loop
			currentstatement = str(currentnumber)
			firstnumber = currentnumber
		elif currentnumber == prevnumber + 1:  # If this number is 1 more than the last
			currentstatement = [str(firstnumber), str(currentnumber)]
			range = True
		else:
			if range:  # We just exited a range of numbers
				statements.append(currentstatement)
				firstnumber = currentnumber
				currentstatement = str(currentnumber)
				range = False
			elif not range:
				statements.append(currentstatement)
				firstnumber = currentnumber
				currentstatement = str(currentnumber)
		prevnumber = currentnumber
	statements.append(currentstatement)  # Append last updated statement after for loop ends
	############################################
	#### Assemble the Statements into name and return ####
	name = ""
	for statement in statements:
		if type(statement) == type(""):
			name += divider + prepend + statement
		elif type(statement) == type([]):
			name += divider + prepend + statement[0] + "-" + prepend + statement[1]
	result = (name[1:], statements)
	return result

########################################## USAGE AND EXAMPLES #########################################
#
#>>> inputlist = ["2", 100, 101, 102, 103, 105]
#
#>>> named_range(inputlist, prepend="L")
#
#######################################################################################################
#######################################################################################################

def expand_ranges(rangeslist):
	result = []
	for rangevar in rangeslist:
		fromint = int(rangevar[0])
		toint = int(rangevar[1])
		if fromint == toint:
			result.append(str(fromint))
		else:
			idlist = list(range(fromint,toint+1))
			for id in idlist:
				result.append(str(id))
	return result

def generate_hex():
	time.clock()  # Return first value to discard it
	curtime = str(time.clock()).replace(".", "")
	return "ac1d"+curtime[len(curtime)-12:len(curtime)]


def sort_interfaces(interfacelist):
	result = []
	tempintlist = []
	tempmapdict = {}
	for interface in interfacelist:
		intid = int(re.findall("[0-9]+$", str(interface))[0])
		tempintlist.append(intid)
		tempmapdict.update({intid: interface})
	tempintlist.sort()
	for interface in tempintlist:
		result.append(str(tempmapdict[interface]))
	return result


def get_switch_pod_id(switchattributes):
	dn = switchattributes["dn"]
	podname = re.findall("pod-[0-9]+", dn)[0]
	podid = re.findall("[0-9]+", podname)[0]
	return podid


#######################################################################################################

def modify_pref_setting():
	if gui.safemodevar.get() == 1:
		return "created"
	elif gui.safemodevar.get() == 0:
		return "created,modified"



def add_ntp(ntp_hostname, ntp_preferred):
	if ntp_preferred == 1:
		ntp_preferred_value = "true"
	elif ntp_preferred == 0:
		ntp_preferred_value = "false"
	###JSON Data###
	data = {
  "datetimeNtpProv": {
    "attributes": {
      "dn": "uni/fabric/time-default/ntpprov-"+ntp_hostname,
      "name": ntp_hostname,
      "preferred": ntp_preferred_value,
      "rn": "ntpprov-"+ntp_hostname,
      "status": modify_pref_setting()
    },
    "children": [
      {
        "datetimeRsNtpProvToEpg": {
          "attributes": {
            "tDn": "uni/tn-mgmt/mgmtp-default/oob-default",
            "status": modify_pref_setting()
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
	###JSON Data###
	data = {
  "dnsProv": {
    "attributes": {
      "dn": "uni/fabric/dnsp-default/prov-["+dns_address+"]",
      "addr": dns_address,
      "status": modify_pref_setting(),
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
	###JSON Data###
	data = {
  "dnsDomain": {
    "attributes": {
      "dn": "uni/fabric/dnsp-default/dom-"+dns_domain,
      "name": dns_domain,
      "status": modify_pref_setting(),
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
	###JSON Data###
	data = {
  "dnsRsProfileToEpg": {
    "attributes": {
      "tDn": "uni/tn-mgmt/mgmtp-default/oob-default",
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/fabric/dnsp-default/rsProfileToEpg.json"
	return (uri, data)


def assign_pod_profile():
	###JSON Data###
	data = {
  "fabricRsPodPGrp": {
    "attributes": {
      "tDn": "uni/fabric/funcprof/podpgrp-default",
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/fabric/podprof-default/pods-default-typ-ALL/rspodPGrp.json"
	return (uri, data)


def assign_bgp_asn(bgp_asn):
	###JSON Data###
	data = {
  "bgpAsP": {
    "attributes": {
      "dn": "uni/fabric/bgpInstP-default/as",
      "asn": bgp_asn,
      "rn": "as",
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/fabric/bgpInstP-default/as.json"
	return (uri, data)


def assign_bgp_rr(bgp_rr_nodeid):
	###JSON Data###
	data = {
  "bgpRRNodePEp": {
    "attributes": {
      "dn": "uni/fabric/bgpInstP-default/rr/node-"+bgp_rr_nodeid,
      "id": bgp_rr_nodeid,
      "rn": "node-"+bgp_rr_nodeid,
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/fabric/bgpInstP-default/rr/node-"+bgp_rr_nodeid+".json"
	return (uri, data)


########################## Interface Policies ##########################
def ifprof_cdp_enabled(name):
	###JSON Data###
	data = {
  "cdpIfPol": {
    "attributes": {
      "dn": "uni/infra/cdpIfP-"+name,
      "name": name,
      "adminSt": "enabled",
      "rn": "cdpIfP-"+name,
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/infra/cdpIfP-"+name+".json"
	desc = "CDP Enabled"
	return (uri, data, desc)

def ifprof_cdp_disabled(name):
	###JSON Data###
	data = {
  "cdpIfPol": {
    "attributes": {
      "dn": "uni/infra/cdpIfP-"+name,
      "name": name,
      "adminSt": "disabled",
      "rn": "cdpIfP-"+name,
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/infra/cdpIfP-"+name+".json"
	desc = "CDP Disabled"
	return (uri, data, desc)

def ifprof_lldp_enabled(name):
	###JSON Data###
	data = {
  "lldpIfPol": {
    "attributes": {
      "dn": "uni/infra/lldpIfP-"+name,
      "name": name,
      "adminRxSt": "enabled",
      "adminTxSt": "enabled",
      "rn": "lldpIfP-"+name,
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/infra/lldpIfP-"+name+".json"
	desc = "LLDP Enabled"
	return (uri, data, desc)

def ifprof_lldp_disabled(name):
	###JSON Data###
	data = {
  "lldpIfPol": {
    "attributes": {
      "dn": "uni/infra/lldpIfP-"+name,
      "name": name,
      "adminRxSt": "disabled",
      "adminTxSt": "disabled",
      "rn": "lldpIfP-"+name,
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/infra/lldpIfP-"+name+".json"
	desc = "LLDP Disabled"
	return (uri, data, desc)

def ifprof_1g(name):
	###JSON Data###
	data = {
  "fabricHIfPol": {
    "attributes": {
      "dn": "uni/infra/hintfpol-"+name,
      "name": name,
      "rn": "hintfpol-"+name,
      "speed": "1G",
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/infra/hintfpol-"+name+".json"
	desc = "1 Gigabit Auto"
	return (uri, data, desc)

def ifprof_10g(name):
	###JSON Data###
	data = {
  "fabricHIfPol": {
    "attributes": {
      "dn": "uni/infra/hintfpol-"+name,
      "name": name,
      "rn": "hintfpol-"+name,
      "speed": "10G",
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/infra/hintfpol-"+name+".json"
	desc = "10 Gigabit"
	return (uri, data, desc)

def ifprof_lacp(name):
	###JSON Data###
	data = {
  "lacpLagPol": {
    "attributes": {
      "dn": "uni/infra/lacplagp-"+name,
      "ctrl": "fast-sel-hot-stdby,graceful-conv,susp-individual",
      "name": name,
      "mode": "active",
      "rn": "lacplagp-"+name,
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/infra/lacplagp-"+name+".json"
	desc = "LACP Active"
	return (uri, data, desc)

def ifprof_static(name):
	###JSON Data###
	data = {
  "lacpLagPol": {
    "attributes": {
      "dn": "uni/infra/lacplagp-"+name,
      "ctrl": "fast-sel-hot-stdby,graceful-conv,susp-individual",
      "name": name,
      "rn": "lacplagp-"+name,
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/infra/lacplagp-"+name+".json"
	desc = "Static On"
	return (uri, data, desc)

def ifprof_mac(name):
	###JSON Data###
	data = {
  "lacpLagPol": {
    "attributes": {
      "dn": "uni/infra/lacplagp-"+name,
      "ctrl": "fast-sel-hot-stdby,graceful-conv,susp-individual",
      "name": name,
      "mode": "mac-pin",
      "rn": "lacplagp-"+name,
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/infra/lacplagp-"+name+".json"
	desc = "MAC Pinning"
	return (uri, data, desc)


def create_vlan_pool(name, vlanstart, vlanstop):
	###JSON Data###
	data = {
  "fvnsVlanInstP": {
    "attributes": {
      "allocMode": "static",
      "dn": "uni/infra/vlanns-["+name+"]-static",
      "name": name,
      "rn": "vlanns-["+name+"]-static",
      "status": modify_pref_setting()
    },
    "children": [
      {
        "fvnsEncapBlk": {
          "attributes": {
            "dn": "uni/infra/vlanns-["+name+"]-static/from-[vlan-"+vlanstart+"]-to-[vlan-"+vlanstop+"]",
            "from": "vlan-"+vlanstart+"",
            "rn": "from-[vlan-"+vlanstart+"]-to-[vlan-"+vlanstop+"]",
            "status": modify_pref_setting(),
            "to": "vlan-"+vlanstop+""
          },
          "children": []
        }
      }
    ]
  }
}
	###################
	uri = "/api/node/mo/uni/infra/vlanns-["+name+"]-static.json"
	desc = "VLAN Pool"
	return (uri, data, desc)


def create_aaep(name, infravlanenabled):
	###JSON Data###
	infradata = {
  "infraInfra": {
    "attributes": {
      "dn": "uni/infra",
      "status": modify_pref_setting()
    },
    "children": [
      {
        "infraAttEntityP": {
          "attributes": {
            "dn": "uni/infra/attentp-"+name,
            "name": name,
            "rn": "attentp-"+name,
            "status": modify_pref_setting()
          },
          "children": [
            {
              "infraProvAcc": {
                "attributes": {
                  "dn": "uni/infra/attentp-"+name+"/provacc",
                  "status": modify_pref_setting()
                },
                "children": []
              }
            }
          ]
        }
      },
      {
        "infraFuncP": {
          "attributes": {
            "dn": "uni/infra/funcprof",
            "status": modify_pref_setting()
          },
          "children": []
        }
      }
    ]
  }
}
	###################
	noinfradata = {
  "infraInfra": {
    "attributes": {
      "dn": "uni/infra",
      "status": modify_pref_setting()
    },
    "children": [
      {
        "infraAttEntityP": {
          "attributes": {
            "dn": "uni/infra/attentp-"+name,
            "name": name,
            "rn": "attentp-"+name,
            "status": modify_pref_setting()
          },
          "children": []
        }
      },
      {
        "infraFuncP": {
          "attributes": {
            "dn": "uni/infra/funcprof",
            "status": modify_pref_setting()
          },
          "children": []
        }
      }
    ]
  }
}
	###################
	uri = "/api/node/mo/uni/infra.json"
	desc = "AAEP"
	if infravlanenabled == 1:
		return (uri, infradata, desc)
	else:
		return (uri, noinfradata, desc)


def create_physical_domain(name):
	###JSON Data###
	data = {
  "physDomP": {
    "attributes": {
      "dn": "uni/phys-"+name,
      "name": name,
      "rn": "phys-"+name,
      "status": modify_pref_setting()
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/phys-"+name+".json"
	desc = "Physical Domain"
	return (uri, data, desc)


def associate_pd_aaep(aaepname, pdname):
	###JSON Data###
	data = {
  "infraRsDomP": {
    "attributes": {
      "status": modify_pref_setting(),
      "tDn": "uni/phys-"+pdname
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/infra/attentp-"+aaepname+".json"
	desc = "Physical Domain \\ AAEP Association"
	return (uri, data, desc)


def associate_pd_vlanp(vlanpname, pdname):
	###JSON Data###
	data = {
  "infraRsVlanNs": {
    "attributes": {
      "status": modify_pref_setting(),
      "tDn": "uni/infra/vlanns-["+vlanpname+"]-static"
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/phys-"+pdname+"/rsvlanNs.json"
	desc = "Physical Domain \\ VLAN Pool Association"
	return (uri, data, desc)


def assign_mgmt_ip(podid, nodeid, cidr, gateway):
	###JSON Data###
	data = {
  "mgmtRsOoBStNode": {
    "attributes": {
      "addr": cidr,
      "gw": gateway,
      "status": modify_pref_setting(),
      "tDn": "topology/pod-"+podid+"/node-"+nodeid+""
    },
    "children": []
  }
}
	###################
	uri = "/api/node/mo/uni/tn-mgmt/mgmtp-default/oob-default/rsooBStNode-[topology/pod-"+podid+"/node-"+nodeid+"].json"
	desc = "Assign Leaf/Spine OOB IP Assignment"
	return (uri, data, desc)


#rangelist = [["202", "203"], "205"]
#profilename = "TEST_PROF"
#selecname = "TEST_SELEC"
def create_leaf_profile(profilename, selecname, rangelist):
	###Range Creation###
	blockselections = []
	for range in rangelist:
		blockhex = generate_hex()
		if type(range) == type([]):
			from_id = range[0]
			to_id = range[1]
		else:
			from_id = range
			to_id = range
		rangetemplate = {
    "infraNodeBlk": {
        "attributes": {
            "dn": "uni/infra/nprof-"+profilename+"/leaves-"+selecname+"-typ-range/nodeblk-"+blockhex,
            "from_": from_id,
            "name": blockhex,
            "rn": "nodeblk-"+blockhex,
            "status": "created",
            "to_": to_id
        },
        "children": []
    }
}
		blockselections.append(rangetemplate)
	###JSON Data###
	data = {
    "infraNodeP": {
        "attributes": {
            "dn": "uni/infra/nprof-"+profilename,
            "name": profilename,
            "rn": "nprof-"+profilename,
            "status": modify_pref_setting()
        },
        "children": [
            {
                "infraLeafS": {
                    "attributes": {
                        "dn": "uni/infra/nprof-"+profilename+"/leaves-"+selecname+"-typ-range",
                        "name": selecname,
                        "rn": "leaves-"+selecname+"-typ-range",
                        "status": "created",
                        "type": "range"
                    },
                    "children": blockselections
                }
            }
        ]
    }
}
	###################
	uri = "/api/node/mo/uni/infra/nprof-"+profilename+".json"
	desc = "Create Leaf Profile"
	return (uri, data, desc)


def create_vpc_interface_policy_group(name, valuedict):
	mappings = [
	{"policy": "infraRsAttEntP", "name": "tDn", "value": "uni/infra/attentp-"+str(valuedict["aaep"]), "create": valuedict["aaep"]},
	{"policy": "infraRsLacpPol", "name": "tnLacpLagPolName", "value": valuedict["lag"], "create": valuedict["lag"]},
	{"policy": "infraRsCdpIfPol", "name": "tnCdpIfPolName", "value": valuedict["cdp"], "create": valuedict["cdp"]},
	{"policy": "infraRsLldpIfPol", "name": "tnLldpIfPolName", "value": valuedict["lldp"], "create": valuedict["lldp"]},
	{"policy": "infraRsHIfPol", "name": "tnFabricHIfPolName", "value": valuedict["link"], "create": valuedict["link"]}]
	###############
	children = []
	for child in mappings:
		if child["create"]:
			polgrpchild = {
                child["policy"]: {
                    "attributes": {
                        "status": modify_pref_setting(),
                        child["name"]: child["value"]
                    },
                    "children": []
                }
            }
			children.append(polgrpchild)
	###JSON Data###
	data = {
    "infraAccBndlGrp": {
        "attributes": {
            "dn": "uni/infra/funcprof/accbundle-"+name,
            "lagT": "node",
            "name": name,
            "rn": "accbundle-"+name,
            "status": modify_pref_setting()
        },
        "children": children
    }
}
	###################
	uri = "/api/node/mo/uni/infra/funcprof/accbundle-"+name+".json"
	desc = "Create Interface Policy Group"
	return (uri, data, desc)



def create_vpc_interface_profile(profilename, selectorname, policygroupname, interfacerange):
	###Range Creation###
	blockselections = []
	blocknumber = 2
	for range in interfacerange:
		if type(range) == type([]):
			from_id = range[0]
			to_id = range[1]
		else:
			from_id = range
			to_id = range
		rangetemplate = {
                            "infraPortBlk": {
                                "attributes": {
                                    "dn": "uni/infra/accportprof-"+profilename+"/hports-"+selectorname+"-typ-range/portblk-block"+str(blocknumber),
                                    "fromPort": from_id,
                                    "name": "block"+str(blocknumber),
                                    "rn": "portblk-block"+str(blocknumber),
                                    "status": modify_pref_setting(),
                                    "toPort": to_id
                                },
                                "children": []
                            }
                        }
		blockselections.append(rangetemplate)
		blocknumber += 1
	associatepolgroup = {
                            "infraRsAccBaseGrp": {
                                "attributes": {
                                    "status": modify_pref_setting(),
                                    "tDn": "uni/infra/funcprof/accbundle-"+policygroupname
                                },
                                "children": []
                            }
                        }
	blockselections.append(associatepolgroup)
	###JSON Data###
	data = {
    "infraAccPortP": {
        "attributes": {
            "dn": "uni/infra/accportprof-"+profilename,
            "name": profilename,
            "rn": "accportprof-"+profilename,
            "status": modify_pref_setting()
        },
        "children": [
            {
                "infraHPortS": {
                    "attributes": {
                        "dn": "uni/infra/accportprof-"+profilename+"/hports-"+selectorname+"-typ-range",
                        "name": selectorname,
                        "rn": "hports-"+selectorname+"-typ-range",
                        "status": modify_pref_setting()
                    },
                    "children": blockselections
                }
            }
        ]
    }
}
	###################
	uri = "/api/node/mo/uni/infra/accportprof-"+profilename+".json"
	desc = "Create Interface Profile"
	return (uri, data, desc)


def associate_intprofile_leafprofile(intprofilename, leafprofname):
	###JSON Data###
	data = {
    "infraRsAccPortP": {
        "attributes": {
            "status": "created,modified",
            "tDn": "uni/infra/accportprof-"+intprofilename
        },
        "children": []
    }
}
	###################
	uri = "/api/node/mo/uni/infra/nprof-"+leafprofname+".json"
	desc = "Associate Interface Profile to Leaf Profile"
	return (uri, data, desc)



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
ePPq3cu3b9hLED6+ELjgIw+/iBMrXrwWiIAABwR+/MCOseXLmPuyG/ExR4qPNTKLHk2arI6PJz58rFS
6tWvMmT5qyPDR0+vbuPtW+ygBw0dquce2Q3euuPHjyJMrX34cXfCxuwNE8B0A+HOv6WR1YcK9u/fv4M
OL//8+pRC261+jT/+NPl0eIUHiy59Pv779+/edSEPvTj11688tAh9+BBZooHxPjIOef+w9d44UB0YoI
X1C/LLgR+tVdx03S0zooYSmXCjdf9d50+GHKBIY4nUMavhcOlikKGN9QhwjYoYABocLETP2GEQa6dxI
Inq0JOEjikKcwQ1/Leb4HDR9kCHllFRWaeWVWFb5Bi3OMYnhkPyFyeKXDYppJm5Nnqnma2mu6eZobb4
pp2VxzmknYnWGuUwrfPL5Sjl9/dInn7VUdmae/BFCnxHn8bUGfU90aSai6Ck6H6N9PTpfpGpSep2l8m
HqKKSSiunpc6DGJ+pemiJYapinBv+XahCr6tVqfJweSqaLZs5a61ntpCPssLcGkeukuzqZ6KKNpgVLF
NBGOwSpnSarpq/NooWKgceaau2Z2K7FyhDkljugq9WOWKaY4arFDTHwxusFtbqqyyu7zGZKL7L2Kltp
vqNu+qqX/V4LMKv7elswuAfbmjCs3/bacF7FdgvxwhJfmi3FDxOMo8Ea6ytwuh8zHHLA6NZbcsahbmw
WOdjELLMYHQu5bpjtpuXKETz3fC6uA9t8L84Tm7VtgRZ7DCa+J6eFihBQR11f0kL7+2nRZYETr7w1j4
kx0y2LnDK/K4OtqstsVRy012UT3bTDI6u8tNthoww0yXMv+zbHcZP/nfe/e+OlNt436103wn0r3LbhZ
4t9t9yFA344Wt/0YvnlXHT9XKy55awtt2tvHrHZtKJN1tEEUs3231cHXtbOPfP8s7GhB8c5bp6fhc44
vPc+OORD82cHfVMAypcpi+4HvNXBpVMFfWC009ctPwuBC+HBX5cNj/P94Rc0RtD3BvbM5+ZIfbT4hQ6
E8xFhuu2jozfOFPS5j9jw9CmyvJmL1PeF9H7JxeyS0A2/RS430lAChVaRmHLQjz6EMGD2cNOOYgVBCu
dQzCnqowRnKI51t7HF7IZwPcWQ4wr1UYOhqsafcbBvPmoAoGJiMcJbXGxxuGFEfZIwDcukg2b0uYKCT
lh4nWkwoT6OEM4jvsDEJjrxiVD8ghPskwilHbA17WhDfaQwxLA0w0hHat/7WnM70VBvgWNBxxfCmMIV
5qaMmPHGC+UzhiCJxRSzY+MQeP+xuiuSRkD0UYIyxsINBbKxPljoIpri55psGHI+hhCOHg55n0WI7mu
uaQcdtrgksRwjfJTcofIWicnWCIN78hFC+sQyDi2E8j5ikCGbGEmac4DBf3YMiyjy+MogWO+NtBzNKE
Y4SLFg45G9pE8iSYlD0VgDjN0TjgULJIQkUGENaaBCEnhJIFEwE4SXaccbODmWM0ZICFygRSe9wo1VX
IGb9mHCGC8Dx8QUY1rzEUItxuJACSVhFmtDByqgaaA6yJI09VTfLemDhlyCRYcRcsIy0FIMghJoCL6Y
ZSkzgzr5DKEZY5kGMglUhGKoZRbwpE8UaseYhPLlmPXZw1jSEQb/CfFhLewYZ4QsScZgMqYdbKiPE9Y
JFlmkdD5JuAZbmgFKAy0hGz3dqGWIgc9UtoKQU4zQGPCCji1IKA9uzIxL84KOzNHnDGF1RzsCMaEI4u
UPEipCMEozVry0YnZGAKknq3qgVbKlFRO6Akvx5NPEhGOO8RFEGs3gIb+uBbASEoL+4FRYv7RDEFMLx
1hccdT6TJYtfvCQEubpl7qqRRmojI8QGGjMrE7oC3hJx0IndAfKShUx6EAhfeooFqCiaAjMYIsymiqh
ISBDNKZFSykGWMyw6IKvtD1oWdoBhxSZIYOYSa5ZuOFa+RRiLOaIUYqSAIyTQjeyV81uZfXSDrhC/4q
oX+koipKwC7TY4rwTGqp6b8uXZUBXCKoI6UhRZIRSOBQs6SAFfj1kh/02ky/omK18vjCwdAT1SEL4Ai
/EAcB2cOMWWOjsgYZADHquFy+rGOFcxXKLBadICEwAAxvYAAYmiFhCZRgsXrQrFm90Nz504OePk8lGI
biCTideyx6ECl+v9IHIyZRCk3WT5LR8kULpDYszXAxlH/mhpVXWnRrqc12xpAMN9yGCFKaghBt3eYcl
VgyPvyJA+gzBpGKhRR6dgIpmnAMd2fjFF9z8ZvlwQcdpmbM7xgGF+jTYmEfM5xs0G5bsIKHQExJCLOQ
c5rK4F6nb6C3+5rOGA4OlFv9cxjR9mKBIvsxZGRYVworCQtVVj5EdeVC1hCJJWP6m5Yf1AQN2EbxG+i
ACLddIta7jowS9UtnXaNGznfGsSxod9yzssMIhh5CEJCi7QEAqbafD4sL64GEs2Yj0fJQwZbEU20dSA
MUz1CGOYbihCDISwizEDW2zGKI+TKB0WOJgnyO0OyxA7BEcBO6VdvwCsfk9eKLH/ZVmjFQIqRiLLxYs
DLSgY8AfAoM5yIIMi04oEM9+MFrSUB8uDPsr5dCtfeCAFmIQ2j7Ane6oP/RRV1PcHdKeTxHiHJZBwJM
IRE9jTXvkhbPYXEZqMLVa6joOKtSntmKZhsnpU4V2p+PfPnL/w1m4sfVz7lMvdW3E1JqcjupySxgHxQ
Ybbn4fsW+37BGSMtrHDVP6ZPnUNx5CGD7hi2Ss4g14/1DTzZIMuudv7/0GSxaDPTBuPOFDQvi2h3JOl
nY8uUdGiEZeXIoL6A5hxWEpxLIJ9IWRj6XkRxpDWs+SUG/IXD5zGEsyLr16/MSh1e04xu1ntMcdh/kQ
AA91WNTY+wJdIRTPSIc5iDEHfLNRiGyppzRM3oixQLb5BRqCErb5yiSupZ6qp08WXu4Vbagb/L2fgjf
On+R2iDeVxhgLIOAPfyFkdOpJpg5NYGdrIAcGeIBroHn8l0yfhRZwJIALGIEF0oC0F4ADKIEY/1gfPD
VxkdcO75aBGWgENgKAkecOv5B4ILh6QgAI2RdmvvAEjpeClFRNqSB1ZeFS5cALfXAGPNiDPviDQBiEQ
jiERFiERniEQ6gGiuAL7MeBKncnUOiEtBEAnRCFVgh5EtABH2EJV9iFa7EJH5EBKPAROOCFZngWPfAR
JZCGASACs3eGZ1gCH3ED/4AAASAAQACHevgVkfAYBSAQMIAhmLCHcNgJE/ARLTAQFYAhkECIXigJhxg
AEqARCvARAkACPMAJ1bCJnNiJnviJoBiKojiKpFiKpniKqDiKnuADJjAAH4EAMUEBOjGLtFiLtsgSkx
gT/+ACBnCLvviLwFgTBCzAArpIEDhQAhYAAQywjMzYjM74jNAYjdI4jdRYjdZ4jdgYjQ1gASRgAzERE
AA7'''



root = tk.Tk()
gui = topwindow(root)
root.mainloop()