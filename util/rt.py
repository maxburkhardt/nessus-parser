#!/usr/bin/env python
import httplib
import urllib
import getpass
import readline
import sys
import re
import os
import stat
import warnings
import subprocess
import ssl
import socket

class RTConnect:
    
    SHOW_REPLIES = 0
    SESSION_SAVE = 1
    USER_AGENT = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.24    ) Gecko/20111109 CentOS/3.6-3.el5.centos Firefox/3.6.24"
    PS1 = "\033[1;34mrt\033[0m \033[1m$ \033[0m" # blue bold "rt" with a white bold "$" 
    AUTH_URL = "auth.berkeley.edu"
    RT_URL = "rt.rescomp.berkeley.edu"
    CERT_FILE = "cacerts.txt"

    def __init__(self):
        self.token = self.cache_authenticate()


    def cert_check(self, host, port):
        
        sock = socket.socket()
        sock.connect((host,port))

        sock = ssl.wrap_socket(sock,cert_reqs=ssl.CERT_REQUIRED,ca_certs=RTConnect.CERT_FILE)

        cert = sock.getpeercert()

        for field in cert['subject']:
            if field[0][0] == 'commonName':
                certhost = field[0][1]
                if certhost != host:
                    raise ssl.SSLError("Host name '%s' doesn't match certificate host '%s'" % (host, certhost))
                else:
                    return True
        return False

    # Logs a user in to calnet with the given username and password. Returns the cookie that RT gives for access.
    def authenticate(self, user, password): 
        if not(self.cert_check(RTConnect.AUTH_URL,443)):
            print "SSL Failed! Something is wrong!"
            return 0
        auth_agent = httplib.HTTPSConnection(RTConnect.AUTH_URL, 443, timeout=10)
        auth_agent.request("GET", "/cas/login?service=https://rt.rescomp.berkeley.edu/")
        initial_response = auth_agent.getresponse()
        if initial_response.status != 200:
            return None
        jsessionid = initial_response.getheader("set-cookie")
        jsessionid = jsessionid[0:jsessionid.find(";")]
        lt = initial_response.read()
        lt = lt[lt.find("_cNoOpConversation"):]
        lt = lt[0:lt.find("\"")]
        auth_agent.close()
        
        auth_params = urllib.urlencode({"username": user, "password": password, "lt": lt, "warn": "false", "_eventId": "submit" })
        auth_headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Encoding": "gzip,deflate", "Language": "en-us,en;q=0.5", "Content-type": "application/x-www-form-urlencoded", "Connection": "keep-alive", "Referer": "https://auth.berkeley.edu/cas/login?service=https://rt.rescomp.berkeley.edu/index.html", "User-Agent": RTConnect.USER_AGENT, "Cookie": jsessionid}
        auth_agent.request("POST", "/cas/login?service=https://rt.rescomp.berkeley.edu/", auth_params, auth_headers)
        response = auth_agent.getresponse()
        if response.status != 302:
            return None
        next_url =  response.getheader("location")
        next_url = next_url[next_url.find("?"):]
        auth_agent.close()
        
        if not(self.cert_check(RTConnect.RT_URL,443)):
            print "SSL Failed! Something is wrong!"
            return 0
        cookie_agent = httplib.HTTPSConnection(RTConnect.RT_URL, 443, timeout=10)
        cookie_headers = {"Referer": "https://auth.berkeley.edu/cas/login?service=https://rt.rescomp.berkeley.edu/index.html", "User-Agent": RTConnect.USER_AGENT, "Connection": "keep-alive"}
        cookie_agent.request("GET", "/" + next_url, "", cookie_headers)
        cookie_response = cookie_agent.getresponse()
        if cookie_response.status != 301:
            return "ERROR: Could not load RT. Might be the sysadmins' fault."
        auth_cookie = cookie_response.getheader("set-cookie")
        auth_cookie = auth_cookie[0:auth_cookie.find(";")]
        cookie_agent.close()

        # save the cookie if session saving is on
        # first touch the file, then chmod it so it's 600
        if RTConnect.SESSION_SAVE == 1: 
            with file(".rt_cache", "w"):
                os.utime(".rt_cache", None)
                os.chmod(".rt_cache", stat.S_IRUSR | stat.S_IWUSR)
            f = open(".rt_cache", "w")
            f.write(auth_cookie)
            f.close()
        self.token = auth_cookie
    
    # attempts to authenticate using a saved cookie. if it works, return that cookie like authenticate()
    def cache_authenticate(self):
        cookie = ""
        try:
            f = open(".rt_cache", "r")
            cookie = f.read().strip()
        except IOError:
            return None
        if not(self.cert_check(RTConnect.RT_URL,443)):
            print "SSL Failed! Something is wrong!"
            return 0
        test_agent = httplib.HTTPSConnection("rt.rescomp.berkeley.edu", 443, timeout=30)
        test_headers = {"User-Agent": RTConnect.USER_AGENT, "Connection": "keep-alive", "Cookie": cookie}
        test_agent.request("GET", "/REST/1.0/index.html", "", test_headers)
        test_response = test_agent.getresponse()
        if test_response.status == 200:
            return cookie
        else:
            return None
    
    # RT's default format for emails delivered via REST is pretty messy, so this cleans it up.
    @staticmethod
    def parse_email(email):
        email = re.sub("id:.+?\n", "", email)
        email = re.sub("Creator:.+?\n", "", email)
        email = re.sub("Transaction:.+?\n", "", email)
        email = re.sub("Parent:.+?\n", "", email)
        email = re.sub("MessageId:.+?\n", "", email)
        email = re.sub("Filename:.+?\n", "", email)
        email = re.sub("ContentType:.+?\n", "", email)
        email = re.sub("ContentEncoding:.+?\n", "", email)
        email = re.sub("\nHeaders:.*\n", "", email)
        email = email[0:email.find("\n         Reply-To:")]+email[email.find("\n         To:"):email.find("\n         MIME")]+"\n\n"+email[email.find("Content:"):]
        if RTConnect.SHOW_REPLIES == 0:
            email = re.sub("\s+>.*?\n", "", email)
        return email.strip()

####### HERE BEGIN THE OPERATION FUNCTIONS

    def create_ticket(self, requestor, subject, text, queue):
        data = self.request("/ticket/new", [("id", "ticket/new"), ("Requestor", requestor), ("Subject", subject), ("Text", text), ("Queue", queue)], "POST")
        if "created" in data:
            m = re.search('\d+', data)
            try:
                return int(m.group(0))
            except:
                return None
        else:
            return None

    def nop(self):
        return ""

    def ticket_details(self, identifier):
        path = "/ticket/" + str(identifier) + "/show"
        return self.request(path)

    def get_attachments(self, identifier):
        path = "/ticket/" + str(identifier) + "/attachments"
        return self.request(path)

    def list_queue(self, queue):
        path = "/search/ticket?query=Queue='" + str(queue) + "'+AND+(+Status='new'+OR+Status='open'+)&orderby=%2BCreated&format=s"
        data = self.request(path).strip().split("\n")
        queue = []
        for line in data:
            key = int(line[0:line.find(":")])
            value = line[line.find(":") + 2:len(line)]
            queue.append((key, value))
        return queue
    
    def get_message(self, message_id):
        path = "/ticket/" + str(message_id) + "/attachments"
        attachments = self.request(path)
        attachments = attachments[attachments.find("Attach"):]
        ids = re.findall("\d+?:", attachments)
        i = 0
        message_data = []
        for attachment in ids:
            if i % 2 != 0:
                path = "/ticket/" + str(message_id) + "/attachments/" + attachment[0:len(attachment)-1]
                message_data.append(RTConnect.parse_email(self.request(path)) + "\n\n========================================\n\n")
            i = i + 1
        return message_data

    def reply_to(self, message_id):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            compose = os.tempnam()
            subprocess.call(["vim", compose])
            composed_msg = open(compose, "r")
            message = composed_msg.read()
            composed_msg.close()
            os.remove(compose)
            return message
        
    def get_help(self):
        helpdocs = "================================\n||maxb's RT CLI interface help||\n================================\n\ndetails <id>\t\tShows the details on ticket <id>.\nattachments <id>\tShows the attachments for ticket <id>\nmessage <id>\t\tShows the full message history for ticket <id>\nqueue <name>\t\tShows the open and new tickets in queue <name>\nreply <id>\t\tReplies to the ticket <id>. Uses the editor defined by $EDITOR"
        print helpdocs


####### HERE END THE OPERATION FUNCTIONS
    
    # takes an instruction given by the user and does the appropriate action.
    def controller(self, instr, token):
        if instr.find(" ") == -1:
            command = instr
        else:
            command = instr[0:instr.find(" ")]
        args = instr[instr.find(" "):].split(" ")[1:]
        if command == "nop":
            print self.nop()
        elif command == "details" or command == "d":
            print self.ticket_details(args[0])
        elif command == "attachments" or command == "a":
            print self.get_attachments(args[0])
        elif command == "message" or command == "m":
            for message in self.get_message(args[0]):
                print message
        elif command == "queue" or command == "q":
            data = self.list_queue(args[0])
            print "Tickets are listed from oldest to newest."
            for ticket in data:
                print str(ticket[0]) + ":", ticket[1]
        elif command == "reply" or command == "r":
            print self.reply_to(args[0])
        elif command == "help" or command == "h":
            self.get_help()
        else:
            print "Sorry, that command wasn't recognized. Type 'help' to see a list of valid commands."
                    
                    
    # handles the network request necessary for a query. path is the REST path to request, params is a list of key-value tuples that will be submitted, token is the auth token
    def request(self, path, params=None, method="GET"):

        if not(self.cert_check(RTConnect.RT_URL,443)):
            print "SSL Failed, something is wrong!"
            return 0
        req_agent = httplib.HTTPSConnection(RTConnect.RT_URL, 443, timeout=30)
        req_headers = {"User-Agent": RTConnect.USER_AGENT, "Connection": "keep-alive", "Cookie": self.token}
        body = ""
        if params:
            body = "content="
            for (key,value) in params:
                value = value.replace("\n", "\n\t")
                body += key + ": " + value + "\n"
        req_agent.request(method, "/REST/1.0" + path, body, req_headers)
        req_response = req_agent.getresponse()
        result = req_response.read()
        result = result[result.find("\n")+1:]
        req_agent.close()
        return result

if __name__ == "__main__":
    print "Welcome to maxb's RT client!"
    authed = 0
    rtc = RTConnect()
    if rtc.token == None:
        user = raw_input("Username: ")
        password = getpass.getpass()
        rtc.authenticate(user, password)
    if rtc.token == None:
        print "ERROR: could not log in to CalNet. Bad username/password?"
        sys.exit()
    else:
        print "Successfully logged in."

    # main console loop
    while True:
        try:
            instruction = raw_input(RTConnect.PS1)
        except EOFError:
            print ""
            sys.exit()
        except KeyboardInterrupt:
            instruction = "nop"
        if instruction == "exit":
            sys.exit()
        else:
            rtc.controller(instruction, rtc.token)
