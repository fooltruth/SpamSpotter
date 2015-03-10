#!/usr/bin/python

import os,random,subprocess,re,time,datetime,platform,sys,socket
#from collections import defaultdict
import fileinput, urllib
#spam_keywords=['sex','Vigara','Viigara' ,'aDult','Debt','already approved', 'already wealthy', 'amazing new discovery', 'amazing pranks', 'an excite game', 'and you save','nasty','babe','fuck']

try:
    defaultdict
except (NameError,ImportError):
    class defaultdict(dict):
        """
        A backport of `defaultdict` to Python 2.4
        See http://docs.python.org/library/collections.html
        """
        def __new__(cls, default_factory=None):
            return dict.__new__(cls)
        def __init__(self, default_factory):
            self.default_factory = default_factory
        def __missing__(self, key):
            try:
                return self.default_factory()
            except:
                raise KeyError("Key '%s' not in dictionary" % key)
        def __getitem__(self, key):
            if not dict.__contains__(self, key):
                dict.__setitem__(self, key, self.__missing__(key))
            return dict.__getitem__(self, key)


urllib.urlretrieve("http://7ea64f9d972b911b7d5a-d87343827908bf30b98b24c2e965bc85.r25.cf1.rackcdn.com/mail.txt", filename="spamList.txt")
#urllib.urlretrieve("http://7ea64f9d972b911b7d5a-d87343827908bf30b98b24c2e965bc85.r25.cf1.rackcdn.com/mail.txt", filename="spamList.txt")
spam_keywords = [line.strip() for line in open("spamList.txt", 'r')]

def black_list_checker(myIP):
        bls = ["zen.spamhaus.org", "spam.abuse.ch", "cbl.abuseat.org", "virbl.dnsbl.bit.nl", "dnsbl.inps.de",
                "ix.dnsbl.manitu.net", "dnsbl.sorbs.net", "bl.spamcannibal.org", "bl.spamcop.net",
                "xbl.spamhaus.org", "pbl.spamhaus.org", "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
                "dnsbl-3.uceprotect.net", "db.wpbl.info","b.barracudacentral.org","ubl.unsubscore.com","hostkarma.junkemailfilter.com"]
        pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"

        if re.match(pattern, myIP):
                ip = str(myIP).split('.')
                rev = '%s.%s.%s.%s' % (ip[3],ip[2],ip[1],ip[0])

                print "\n"
                print bcolors.OKBLUE + "*************************"
                print "Checking Blacklists"
                print "*************************" + bcolors.ENDC
                for bl in bls:
                        cmd = "dig +short " + rev + "." + bl
                        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                        output, err = p.communicate()
                        if len(output)>0:
                                #print 'IP: %s IS listed in %s' %(myIP, bl)
                                print bl + bcolors.FAIL + "[LISTED]" + bcolors.ENDC
                        else:
                                #print 'IP: %s is NOT listed in %s' %(myIP, bl)
                                print bl + bcolors.OKGREEN + "[OK]" + bcolors.ENDC
        else:
                print "IP format is not right"


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    UNDERLINE = '\033[4m'

# This class discovers all required feature of environement
# * OS distribution
# * PLesk or Non Plesk
# * MTA Type
# * PHP version
class EnvironmentDiscovery:
        # Empty constructor
        def __init__(self):
                pass

        def is_old_python(self):
                 if sys.version_info[1]<=4:
                        return True
                 else:
                        return False
        # identify PHP version
        def php_version(self):
                php_ver = "php -v | egrep PHP.\s*[0-9]\.[0-9] | awk '{print $2}'"
                p = subprocess.Popen(php_ver, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                output, err = p.communicate()
                #print output
                #print err
                return output

        # Is it a plesk server?
        def is_plesk(self):
                plesk_process = "netstat -ntpl | grep 'sw-cp-server' | wc -l"
                p = subprocess.Popen(plesk_process, stdout=subprocess.PIPE, shell=True)
                output, err = p.communicate()
                if int(output) >= 1:
                        return True
                else:
                        return False

        # matches keyword again MTAs
        def mta_f(self,x):
                return {
                        'master': 'Postfix',
                        'smtpd': 'Postfix',
                        'xinetd': 'Qmail',
                        'sendmail': 'Sendmail',
                        'exim': 'Exim',
                }.get(x,'Unknown')


        # Discover MTA using netstat output.
        def mta_type(self):
                mta_process_id = "netstat -ntpl | grep :25 | awk -F/ '{print $2}' | uniq"
                mta_processes = "netstat -ntpl | grep :25 | awk -F/ '{print $2}' | uniq | wc -l"
                p1 = subprocess.Popen(mta_process_id, stdout=subprocess.PIPE, shell=True)
                outputp1, err = p1.communicate()

                p2 = subprocess.Popen(mta_processes, stdout=subprocess.PIPE, shell=True)
                outputp2, err = p2.communicate()

                if int(outputp2) == 1:
                        outputp1 = outputp1.rstrip()
                        mta = self.mta_f(outputp1)
                        #print mta
                        return mta
                elif int(outputp2) == 0:
			rpm_cmd = "ls -l  /etc/alternatives/mta | awk -F/ '{print $NF}' | awk -F. '{print $2}'"
			p3 = subprocess.Popen(rpm_cmd, stdout=subprocess.PIPE, shell=True)
			outputp3, err = p3.communicate()
			print "Hello", outputp3
			if outputp3.rstrip()=="postfix":
				return "Postfix"
			else:
                        	print "No mail service is currently running. Please start mail service and run the script again."
                else:
                        print "There are multiple MTA's running and this script is not compatiable"

        # Find Linux Distribution and version
        def linux_dist(self):
                if self.is_old_python()==False:
                        return platform.linux_distribution()
                else:
                        return platform.dist()
        # Determine mail log path based on environment
        def mail_log_path(self,distro,plesk):
                Redhat = set(['Redhat','CentOS','redhat','centos','Red Hat Enterprise Linux Server'])
                Debian = set(['Ubuntu','Debian'])

                if plesk:
                        return "/usr/local/psa/var/log/maillog"
                elif distro in Redhat:
                        return "/var/log/maillog"
                elif distro in Debian:
                        return "/var/log/mail.log"
                else:
                        return "Unknown"

        def mail_queue_loc(self,mta):
                if mta=="Postfix":
                        return "/var/spool/postfix/"
                elif mta=="Qmail":
                        return "/var/qmail/queue/"
                else:
                        return "Not Supported"

#e = EnvironmentDiscovery()
#MTA=e.mta_type()
#print "Mail Service is: ", MTA
#print "Plesk server? ", e.is_plesk()
#print e.mail_log_path(e.linux_dist()[0],e.is_plesk())
#MAILLOG_PATH=e.mail_log_path(e.linux_dist()[0],e.is_plesk())
#print MAILLOG_PATH

#MAIL_QUEUE_LOC=e.mail_queue_loc(MTA)
#print MAIL_QUEUE_LOC


class MailParser:
        def maillog_size(self,path):
                return os.path.getsize(path)
        # Read X number of lines of maillog file from bottom. "tail" like function
        def tail(self,f, lines=2000000):
                total_lines_wanted = lines

                BLOCK_SIZE = 1024
                f.seek(0, 2)
                block_end_byte = f.tell()
                lines_to_go = total_lines_wanted
                block_number = -1
                blocks = [] # blocks of size BLOCK_SIZE, in reverse order starting
                # from the end of the file
                while lines_to_go > 0 and block_end_byte > 0:
                        if (block_end_byte - BLOCK_SIZE > 0):
                                # read the last block we haven't yet read
                                f.seek(block_number*BLOCK_SIZE, 2)
                                blocks.append(f.read(BLOCK_SIZE))
                        else:
                                # file too small, start from begining
                                f.seek(0,0)
                                # only read what was not read
                                blocks.append(f.read(block_end_byte))
                        lines_found = blocks[-1].count('\n')
                        lines_to_go -= lines_found
                        block_end_byte -= BLOCK_SIZE
                        block_number -= 1
                all_read_text = ''.join(reversed(blocks))
                return '\n'.join(all_read_text.splitlines()[-total_lines_wanted:])



        # Get list of email address authenticated with IPs
        def auth_email_list(self,maillog_loc,pattern,pos1,pos2):
                fo = open(maillog_loc, "r")
                #If maillog is bigger than 50MB, tail logs
                if (self.maillog_size(maillog_loc) > 52428800):
                        file = self.tail(fo)
                else:
                        file=fo.read()
                auth_emails=defaultdict(list)
                for i in file.split('\n'):
                        if re.search(pattern,i):
                                l = []
                                for w in i.split(" "):
                                        l.append(w)
                                if  re.search("cmd5checkpw",i):
                                        auth_emails[l[pos1]].append(l[pos2-1])
                                else:
                                        auth_emails[l[pos1]].append(l[pos2])
                fo.close()
                return auth_emails


# Find Mail queue size

#print number of folders in directory
####
## We do need to count number of files not number of folders???
####

#def fcount(path):
#  map ={}
#  count = 0
#  for f in os.listdir(path):
#    child = os.path.join(path, f)
#    if os.path.isdir(child):
#      child_count = fcount(child)
#      count += child_count + 1 # unless include self
#  map[path] = count
#  return count


def fcount(path):
        c=0
        for dirpath, dirnames, files in os.walk(path):
                for name in files:
                        c=c+1
        return c

def intersection(iterableA, iterableB, key=lambda x: x):
    """Return the intersection of two iterables with respect to `key` function.

    """
    def unify(iterable):
        d = {}
        for item in iterable:
            d.setdefault(key(item), []).append(item)
        return d

    A, B = unify(iterableA), unify(iterableB)

    return [(A[k], B[k]) for k in A if k in B]


# Mail Queue size
def queue_size(queue_loc,mta):
        if mta=="Postfix":
                m_queue = ["deferred", "active", "bounce", "corrupt"]
                mail_queue_num = {}
                for i in m_queue:
                        mail_queue_num[i] = fcount(queue_loc+i)
                print "Total Messages: ", mail_queue_num['bounce']+ mail_queue_num['deferred']+mail_queue_num['active']+mail_queue_num['corrupt']
                print "Bounced Mail Queue :", mail_queue_num['bounce']
                print "Deffered Mail Queue :", mail_queue_num['deferred']
                print "Active Mail Queue :", mail_queue_num['active']
                print "Corrupt Mail Queue:", mail_queue_num['corrupt']
                print "\n"
        elif mta=="Qmail":
                m_queue = ["remote", "local", "bounce","todo"]
                mail_queue_num = {}
                for i in m_queue:
                        mail_queue_num[i] = fcount(queue_loc+i)
                print "Total Messages: ", mail_queue_num['remote']+ mail_queue_num['local']+mail_queue_num['bounce']+mail_queue_num['todo']
                print "Bounced Mail Queue :", mail_queue_num['bounce']
                print "Remote Mail Queue :", mail_queue_num['remote']
                print "Local Mail Queue :", mail_queue_num['local']
                print "Preprocess Queue :", mail_queue_num['todo']
                print "\n"
        else:
                print "MTA running on this server is not supported by this script"


#queue_size(MAIL_QUEUE_LOC,MTA)

# Get a specified number mail headers from specififed queue
def getRandMailHeaders(queue,n):
        f_list = []
        for dirpath, dirnames, files in os.walk(queue):
                for name in files:
                        f_list.append(name)
        if len(f_list)>=n:
                return random.sample(f_list,n)
        else:
                return f_list

# Read a mail
def viewMail(mid,mta):
        if mta=="Postfix":
                read_mail = "postcat -q " + mid
        elif mta=="Qmail":
                read_mail = "find /var/qmail/queue/mess/ -name " + mid + " -exec cat {} \;"
        p = subprocess.Popen(read_mail, stdout=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        return output

#print viewMail("3B77413C1B3")

#Get a list of line of lines contains a specific word
def grepfunc(text,pattern):
        l = []
        for i in text.split('\n'):
                if re.search(pattern,i):
                        for w in i.split(" "):
                                l.append(w)
                        l.append('\n')
        return l


# Idetify if the mail was sent via PHP script or from Mail authentication
def mailOrigin(mail,mta):
        """
         Postfix: Examine the last "Recived: by" line. Bounced emails with have more than one "Received: by" lines.
         Last entry on the line indicates the userid. If userid is 110, mail is generated from Auth users.
         This is only true for Plesk servers.
        """
        if mta=="Postfix":
                if len(grepfunc(mail,"Received: by"))>0:
                        if grepfunc(mail,"Received: by")[-2:-1][0][:-1]==110:
                                return "Auth"
                        else:
                                return "PHP"
                elif grepfunc(mail,"ESMTPA"):
                        return "Auth"
                elif grepfunc(mail,"SMTPA"):
                        return "Auth"
                else:
                        return "Incoming"
        # Qmail: Examine the last "Recived:" line. Bounced emails with have more than one "Received:" lines.
        # If the received line contains an entry "network", mail is generated from Auth users; Otherwise from PHP script
        elif mta=="Qmail":
                qmail_list=grepfunc(mail,"Received: \(qmail")
                if len(qmail_list)>0:
                        for i in qmail_list:
                                if re.search("network",i):
                                        return "Auth"
                                else:
                                        return "PHP"



#def isSpamMail(mid,mta):
#       mail = viewMail(mid,mta)
#       #print mail
#       #f = open('/var/spool/postfix/deferred/3/3A77414C1B3','r')
#        #mail = f.read()
#        #f.close()
#
#       if mailOrigin(mail,mta)=="PHP":
#               if len(grepfunc(mail,"X-PHP-Originating-Script"))>0:
#                       if (len(intersection(spam_keywords, grepfunc(mail,"Subject:"), key=str.lower)) > 0):
#                               return "spam",grepfunc(mail,"X-PHP-Originating-Script")[1].split(':')[1]
#                       else:
#                               return "possible",grepfunc(mail,"X-PHP-Originating-Script")[1].split(':')[1]
#               else:
#                       return "enable","Enable PHP add_x_header"
#       elif mailOrigin(mail,mta)=="Auth":
#               return "auth","Auth"
#
#       else:
#               return "incoming","Incoming"

#print isSpam("3A77414C1B3","Postfix")

def isSpam(queue,mta):
        def_spam = []
        pos_spam = []
        enable_spam = []
        auth_spam = []
        incoming_mail = []
	mail_header_list=getRandMailHeaders(queue,5)
	if len(mail_header_list)==0:
		print "No mails in the queue. Mail header check is ignored"
        for i in mail_header_list:
		print "\tInspecting Mail Header "+i
                mail = viewMail(i,mta)
                if mailOrigin(mail,mta)=="PHP":
                        if len(grepfunc(mail,"X-PHP-Originating-Script"))>0:
                                if (len(intersection(spam_keywords, grepfunc(mail,"Subject:"), key=str.lower)) > 0):
                                        def_spam.append(grepfunc(mail,"X-PHP-Originating-Script")[1].split(':')[1])	
					print "\t\tEmail generated using script: ",grepfunc(mail,"X-PHP-Originating-Script")[1].split(':')[1]
					#print "\t\tSubject of mail header "+ i + " contain spam keywords and the Subject is: "
					#subject="Subject is "
					#for i in grepfunc(mail,"Subject:"):
					#	subject = subject + i
					#print subject
					
                                else:
                                        pos_spam.append(grepfunc(mail,"X-PHP-Originating-Script")[1].split(':')[1])
					#print "\t\t'X-PHP-Originating-Script' exist on mail header"
					print "\t\tEmail generated using script: ", grepfunc(mail,"X-PHP-Originating-Script")[1].split(':')[1]
					#print "\t\tSubject of mail header "+ i + " does not contain spam keywords"
					
                        else:
                                enable_spam.append("Enable PHP add_x_header")
				print "\t\t No 'X-PHP-Originating-Script' listed on mail header"
                elif mailOrigin(mail,mta)=="Auth":
                        auth_spam.append("Auth")
			print "\t\tEmail is sent using authentication"

                else:
                        incoming_mail.append("incoming")
			print "\t\tIncoming mail header"

        if len(def_spam) > 2:
                return "Spam", def_spam
        elif len(pos_spam) > 2:
                return "possible", pos_spam
        elif len(enable_spam) > 2:
                return "enable", enable_spam
        elif len(auth_spam) > 2:
                return "Auth", auth_spam
        else:
                return "Incoming",incoming_mail

def find_php_file(path,fname):
	#fname=fname.split(".php")[0]
	#fname=fname+".php"
        cmd= "locate /" +fname
        #print cmd
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        if len(err)>0:
                cmd = "find " +path+ " -name " +fname+ " -type f"
                print "Locating the compromised file can take a while....."
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                output, err = p.communicate()
        return output


## if 0 return then file is infected; 1 file is not infected; 2 - file is not there
def isInfected(fname):
	print "\t\t\tInspecting file "+fname+" for any malcious contnet........."
        cmd = "egrep 'passthru|shell_exec|base64_decode|edoced_46esab|eval(' "  + fname
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, stderr=subprocess.STDOUT)
        output, err = p.communicate()
        return p.returncode


def verifySpam(mta):
        if mta=="Postfix":
                queue = "/var/spool/postfix/deferred"
        elif mta=="Qmail":
                queue = "/var/qmail/queue/mess"
        else:
                "Unsupported Mail Service"

        path = "/var/www/"

        n = 5
        d_file = []
        spam=isSpam(queue,mta)
        if spam[0]=="Spam":
                f_list = set(spam[1])
                for i in f_list:
                        for j in find_php_file(path,i).split('\n'):
                                d_file.append(j)
        elif spam[0]=="possible":
                f_list = set(spam[1])
                for i in f_list:
                        for j in find_php_file(path,i).split('\n'):
                                d_file.append(j)
        else:
                n=1
        #print d_file
        inf_d=defaultdict(list)
        for key in d_file:
                #print key
		#value = isInfected(key)
                if key!='':
			value = isInfected(key)
                        if value==0:
                                inf_d['infected'].append(key)
                        elif value==1:
                                f_timestamp=datetime.datetime.fromtimestamp(os.path.getmtime(key))
                                if (datetime.datetime.now() - f_timestamp) < datetime.timedelta(days=2):
                                        inf_d['manual'].append(key)
                                else:
                                        inf_d['manual_notime'].append(key)
                        else:
                                inf_d['none']='none'

        return inf_d

e = EnvironmentDiscovery()
MTA=e.mta_type()
PHP_VERSION=e.php_version()
def mail_queue():
	if (MTA=="Postfix") or (MTA=="Qmail"):
		print "\n"
        	print bcolors.OKBLUE + "*************************"
        	print  "Mail Service is: ", MTA, ""
        	print "*************************" +bcolors.ENDC
		#MAILLOG_PATH=e.mail_log_path(e.linux_dist()[0],e.is_plesk())
		MAIL_QUEUE_LOC=e.mail_queue_loc(MTA)
		queue_size(MAIL_QUEUE_LOC,MTA)

def mail_auth_discovery():
	print "\n"
        print bcolors.OKBLUE + "*********************************"
        print "Checking Mail Account Compromise"
        print "*********************************" + bcolors.ENDC
	if (MTA=="Postfix") or (MTA=="Qmail"):
		MAILLOG_PATH=e.mail_log_path(e.linux_dist()[0],e.is_plesk())
		if MTA=="Postfix":
                	PATTERN="sasl_method=LOGIN"
                	POS1=8
                	POS2=6
        	elif MTA=="Qmail":
                	PATTERN="logged in"
                	POS1=7
                	POS2=13

		m=MailParser()
        	email_list=m.auth_email_list(MAILLOG_PATH,PATTERN,POS1,POS2)

		found=0
		for i in email_list:
                	if len(email_list[i]) > 100:
                        	print bcolors.FAIL + "Compromised Email is: ", i, " " +bcolors.ENDC
				found=1
		if found==0:
			print bcolors.OKGREEN + "No compromised mail account found\n" +bcolors.ENDC
			
def mail_php_discovery():
	print "\n"
        print bcolors.OKBLUE + "********************************"
        print "Checking PHP Script Compromise"
        print "********************************" + bcolors.ENDC
	if (MTA=="Postfix") or (MTA=="Qmail"):
		if float(PHP_VERSION[0:3]) >= 5.3:
                        for i in range(3):
				if i==0:
					print "Picking 5 random mail headers for PHP/CGI compromise....." 
				elif i==1:
					print "\nInsufficient evidence on previous 5 random mail headers, therefore picking another 5 random mail headers....."
				else:
					print "\nInsufficient evidence on previous 10 random mail headers, therefore picking another 5 random mail headers....."
                                outcome=verifySpam(MTA)
                                #print outcome
                                if len(outcome)>0:
                                        if outcome.has_key('infected')==True:
						print "Infected files are: "
						for x in range (0,len(outcome['infected'])):
                                                        print bcolors.FAIL +outcome['infected'][x]+bcolors.ENDC
                                                #print bcolors.OKGREEN + "Infected file is: ", outcome['infected'], +bcolors.ENDC
                                                break
                                        elif outcome.has_key('manual')==True:
                                                print "Verify files manually: "
                                                for x in range (0,len(outcome['manual'])):
                                                        print outcome['manual'][x]
                                                break
                                        else:
						if i==2:
                                                	print bcolors.OKGREEN + "Mail compromise is not detected. Please do manual checks" +bcolors.ENDC
                                else:
                                        if i==2:
                                                print bcolors.OKGREEN +  "No PHP compromise detected!!! Manually verify!!! " +bcolors.ENDC
        	else:
                	print bcolors.FAIL + "PHP version is:", PHP_VERSION, "PHP 5.3 and above is required to identify the spam file. Please refere to the following article to identify the script manaually. " +bcolors.ENDC	



        #yIP=socket.gethostbyname(socket.gethostname())
def black_list():
	ip_cmd = "curl -s -4 icanhazip.com"
        ip_p = subprocess.Popen(ip_cmd, stdout=subprocess.PIPE, shell=True)
        output_ip, err_ip = ip_p.communicate()
        myIP=output_ip.strip()

        black_list_checker(socket.gethostbyname(myIP))

def deliverability():
	print "\n"
        print bcolors.OKBLUE + "*************************"
        print "Checking 3-way MailCheck"
        print "*************************" + bcolors.ENDC

	rdns=0
	myIPLocal=socket.gethostbyname(socket.gethostname())
	ip_cmd = "curl -s -4 icanhazip.com"
	ip_p = subprocess.Popen(ip_cmd, stdout=subprocess.PIPE, shell=True)
        output_ip, err_ip = ip_p.communicate()
	myIP=output_ip.strip()
	#print myIP    

	cmd = "dig +short -x " + myIP
	#print cmd
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        output, err = p.communicate()
	if len(output)>0:
		print "Reverse Record Check" 
		print "-----------------------"
		print "Reverse Record present:" + output

	else:
		rdns=0

	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	l=[]
	good=1
	try:
		#print "Connecting to SMTP....."
		connect=s.connect((myIPLocal,25))
		b=s.recv(1024)
		for w in b.split(" "):
                	l.append(w)
		if len(output)>0 and output.strip()[:-1]==l[1]:
			rdns=1
		else: 
			rdns=0
		
		print  "SMTP port check" 
		print "-------------------"
		print "Connected to " + myIP +" on port 25, mail banner says: " + l[1]
		
		cmd_a = "dig +short " + l[1]
                p1 = subprocess.Popen(cmd_a, stdout=subprocess.PIPE, shell=True)
                output_a, err_a = p1.communicate()
		output_a=output_a.strip()
		if myIPLocal==output_a:
			output_a=myIP
 		if len(output_a)>0:
			print "Found 'A' record for " +l[1]+": "+output_a
		else:
			print "No 'A' record found for: " +output_a
			good=0
		if myIP==output_a:
			print "DNS 'A' record for "+ l[1] + "matches the given IP " +output_a
		else: 
			print "DNS 'A' record for "+ l[1] + "does NOT matches the given IP " +output_a
			good=0

        except socket.timeout:
		print "SMTP port check" 
                print "-------------------"
		print "SMTP server timed out"
		good=0
	except socket.error:
		print "SMTP port check" 
                print "-------------------"
		print "Not able to connect to SMTP server"
		good=0	
	s.close()
	
        print "\nResults"
	print "-----------------"	
	if rdns==1 and good==1:
		print bcolors.OKGREEN + "GOOD: " +bcolors.ENDC + "Reverse record matches SMTP banner, 3-way mailcheck PASS."
	elif rdns==1 and good==0:
		print bcolors.WARNING + "BAD: " +bcolors.ENDC + "Reverse record matches SMTP banner but 3-way mail check FAIL."
	elif rdns==0 and good==1:
		print bcolors.WARNING+ "BAD: " +bcolors.ENDC +"Reverse record does NOT matches SMTP banner but 3-way mail check PASS."
	elif rdns==0 and good==0:
		print bcolors.WARNING +"BAD: " +bcolors.ENDC +"Reverse record does NOT matches SMTP banner but 3-way mail check FAIL."

def version():
	print "MailSpamDiscovery v1.0"

def usage():
	print ("Usage: %s [option]" % sys.argv[0])
	print ("Example: %s -v" % sys.argv[0])
	print "\n"
        print "Available options:"
        print "-s               display mail queue statistics"
        print "-m               disover compromised mail account"
        print "-p               discover PHP compromised script"
	print "-a               discover mail size, compromised mail account and PHP, and blacklist"
        print "-b               check blacklist"
        print "-c               3-way mail check"
        print "-v               version"
	print "-h               help"

def all_func():
	mail_queue()
        mail_auth_discovery()
        mail_php_discovery()
	deliverability()
        black_list()

def delete_file(myfile):
	try:
        	os.remove(myfile)
	except OSError, e:  ## if failed, report it back to the user ##
        	print ("Not able to delete the %s file. Please delete manually.  %s - %s." % (e.filename,e.strerror))

def main():
	myCommandDict = {"-s": mail_queue, "-m": mail_auth_discovery, "-p": mail_php_discovery, "-b": black_list,"-v": version, "-h":usage, "-a": all_func,"-c":deliverability}
	commandline_args = sys.argv[1:]
	if len(commandline_args)>0:
    		for argument in commandline_args:
        		if argument in myCommandDict:
            			myCommandDict[argument]()
        		else:
				usage()
	else:
		usage()
	delete_file("spamList.txt")

if __name__ == "__main__":
    main()
