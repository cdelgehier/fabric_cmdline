from fabric.api import env, local, run, require, cd
from fabric.operations import _prefix_commands, _prefix_env_vars
from fabric.contrib.files import *
from fabric.colors import *
from fabric.state import *

import inspect
import util
import sys
import time
import socket

class system(object):

    # Turn to 'True' to enable current module
    enabled = True
    # Dict for functions calling
    first = {}

    # run options
    needSudo = False


    def __init__(self):
        puts("Init <"+__name__+">")

    def _fabrun(self,*args):
        puts("FABRUN SUDO ="+str(self.needSudo))
        if self.needSudo:
            puts("Using sudo for "+str(args))
            return util._sudo(*args)
        else:
            puts("Using run for "+str(args))
            return util._run(*args)


    def check_ntp(self,sudo=False):
            """
            Display and colorize ntp status via ntpq -p, in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())
            ntpq = self._fabrun("ntpq -p")
            if not re.search('timed out',ntpq):
                ntp_list = ntpq.splitlines()
                cpt = 0
                for ntp in ntp_list:
                    if cpt > 1:	# Permet de virer les dux premieres lignes d'entete
                        space_start = ntp.startswith(" ",0,1)		# Gestion de l'espace comme premier caratere de la ligne
                        ntp_fields = ntp.split()
                        sys.stdout.write(env.host)
                        first = True	# Initialisation de la variable permettant de savoir si nous sommes sur le premier champs
                        for ntp_field in ntp_fields:
                            sys.stdout.write("|")
                            if first:
                                if ntp_field.startswith(("+","*","o"),0,1):	# Affichage en vert des peers OK
                                    sys.stdout.write(green(ntp_field))
                                else:
                                    if ntp_field.startswith(("#"),0,1):	# Affichage en jaune des peers backup
                                        sys.stdout.write(yellow(ntp_field))
                                    else:
                                        if space_start:
                                            sys.stdout.write(" ")
                                        sys.stdout.write(red(ntp_field,True))	# Affichage en rouge des peers KO
                            else:
                                sys.stdout.write(ntp_field)
                            first = False
                        sys.stdout.write("\n")
                    cpt += 1
            else:
                sys.stderr.write(env.host+' | '+red('KO')+' | Timeout during ntpq -p\n')

    def put_file(self,*args, **kwargs):
            """
            <put> task alias
            """
            self.put(*args, **kwargs)

    def put(self,local_path,remote_path,fmode,sudo=False):
            """
            Put <local_path> set in parameter into <remote_path> with mode <fmode> on remote host, in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            try:
                result = put(local_path=local_path,remote_path=remote_path,mode=int(fmode,base=0),use_sudo=eval(str(sudo).capitalize()))
                if result.succeeded:
                     print env.host+"|<"+yellow(local_path)+"> "+green("successfully")+" uploaded on "+env.host+":"+remote_path
                else:
                     print env.host+"|"+yellow(",".join(str(item) for item in result.failed))+" "+red("failed")+" uploaded on "+env.host+":"+remote_path
            except Exception as e:
                puts(env.host+"|"+red("ERROR:")+" During upload (Bad value for some parameter(s) ?)",e)



    def df(self,sudo=False):
            """
            Show df Output, in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())
            fs = self._fabrun("df -h | grep -v \"Filesystem\"")
            fs_list = fs.split()
            cpt = 0
            line = ""
            util._print_task_header("Hostname|Filesystem|Size|Used|Avail|Use%|Mounted")
            for fs in fs_list:
                line += "|" + fs
                cpt += 1
                if cpt == 6:
                        print env.host + line
                        cpt = 0
                        line = ""

    def ls_dir(self,fd,sudo=False):
            """
            List dir <fd> set in parameter, in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())
            fd = self._fabrun("ls -dl " + fd + " | grep -vi \"^total\" | awk '{print $9 $10 $11}'")
            fd_list = fd.split("\r\n")
            for fd in fd_list:
                    print env.host + "|" + fd


    def exec_cmd(self,cmd,sudo=False,pty=True):
            """
            Exec <cmd> set in sudo mode if <sudo> is set to True
            with a [pty] (default: True )
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())
            fd = self._fabrun(cmd,pty)
            if fd.succeeded:
                fd_list = fd.split("\r\n")
                for result in fd_list:
                    print env.host + "|" + result
            else:
                print env.host + "|Error during command execution: " +fd
            return fd.succeeded


    def arch(self):
            """
            Show architecture x86_64, i386 ...
            """
            if not util._is_host_up(env.host, int(env.port)):
                return False
            print env.host + "|" + util._run("uname --hardware-platform")

    def uptime(self):
            """
            Show uptime of the host
            """
            if not util._is_host_up(env.host, int(env.port)):
                return False
            print env.host + "|" + util._run('uptime')


    def date(self):
            """
            Show date of the host
            """
            if not util._is_host_up(env.host, int(env.port)):
                return False
            result = util._run('date')
            if result.succeeded:
                print env.host + "|" + result
            return result.succeeded

    def hostname(self):
            """
            Return configured hostname
            """
            if not util._is_host_up(env.host, int(env.port)):
                return False
            result = util._run('hostname -f')
            if result.succeeded:
                print env.host + "|" + result
            return result.succeeded


    def cat(self,filename,sudo=False,display=True):
            """
            Cat <filename> set in parameter, in sudo mode is [sudo] is set to True,
            and [display] le filename default True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())
            output = self._fabrun("cat "+filename)
            if output.failed:
                print env.host +"|"+red("FAILED:")+" to read file <"+yellow(filename)+">"
                return False
            if eval(str(display).capitalize()):
                print env.host+"|"+filename+"|"+output
            else:
                return output

    def os_short(self):
            """
            Show truncated OS version ( LFS, RedHat CentOS ... )
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            OS = util._run("bash -c 'head -n 1 /etc/{{system,redhat,centos}-release,release} 2>/dev/null' | sort -u | grep -v '^==>'")
            if re.match("LC",OS,flags=re.IGNORECASE):
                print env.host + "|LFS " + OS
            if re.match("Red Hat",OS,flags=re.IGNORECASE):
                print env.host  + "|" + OS
            if re.match("Centos",OS,flags=re.IGNORECASE):
                print env.host  + "|" + OS
            if re.match("Solaris",OS,flags=re.IGNORECASE):
                print env.host  + "|" + OS
            else:
                print env.host  + "|UNKNOW_OS" + OS

    def os_release(self,display=True):
            """
            Show complete OS release ( LFS, RedHat ... )
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            OS = util._run("bash -c 'head -n 1 /etc/{{system,redhat,centos}-release,release} 2>/dev/null' | sort -u | grep -v '^==>'")
            OS_list = OS.splitlines()
            OS_hash = {}
            for entry in OS_list:
                OS_hash[entry]=1
            OS = ""
            for os in OS_hash.iterkeys():
                OS+=os+' '
            if display:
                print env.host + "|" + OS
            else:
                return OS


    def os_type(self,display=True):
        """
        Show OS type ( LFS, RedHat CentOS ... ) [display] True by default
        """
        if util._is_host_up(env.host, int(env.port)) is False:
            return False
        OS = util._run("bash -c 'head -n 1 /etc/{{system,redhat,centos}-release,release} 2>/dev/null' | sort -u | grep -v '^==>'")
        if re.match("LC",OS,flags=re.IGNORECASE):
            if display:
                print env.host + "| LFS"
            return "lfs"
        if re.match("Red Hat",OS,flags=re.IGNORECASE):
            if display:
                print env.host  + "| redhat"
            return "redhat"
        if re.match("Centos",OS,flags=re.IGNORECASE):
            if display:
                print env.host  + "| centos"
            return "centos"
        if re.match("Solaris",OS,flags=re.IGNORECASE):
            if display:
                print env.host  + "| solaris"
            return "solaris"
        else:
            if display:
                print env.host  + "| UNKNOWN_OS"
            return "UNKNOWN_OS"

    def kernel_version(self):
            """
            Display the kernel version running on the host
            """
            if util._is_host_up(env.host, int(env.port)) is False:
             return False
            k_version =  util._run('uname -r')
            print env.host + "|" + k_version

    def version_rpm(self,name):
            """
            Display rpm package <name> version
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            #rpms =  util._run('rpm -qa | egrep \"'+name+'\"')
            os_version = self.os_release(display=False)
            rpms =  util._run('rpm -q '+name+' --queryformat "%{NAME}|%{VERSION}-%{RELEASE}.%{ARCH}|%{INSTALLTIME:date}\n"')
            rpms_list = rpms.splitlines()
            if not self.first.has_key(util._func_name()):
                self.first[util._func_name()] = True
                util._print_task_header("HOSTNAME|OS_RELEASE|PACKAGE_NAME|VERSION|INSTALL_DATE")
            for rpm in rpms_list:
                    print env.host + "|"  + os_version + "|" + rpm



    def yum_install(self,pkg,sudo=False,disablerepo=None,disableplugin=None,enablerepo=None):
            """
            Install package from <pkg> named argument through Yum, in sudo mode is [sudo] is set to True
            with [disablerepo] as a list of separated by ' ' spaces yum repo to disable
            with [enablerepo] as a list of separated by ' ' spaces yum repo to enable
            with [disableplugin] as a list of separated by ' ' spaces yum plugin to disable
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())

            disablerepo_list = ""
            if not disablerepo is None:
                disablerepo_list = disablerepo.split()
                disablerepo_list = map(lambda x: ' --disablerepo="'+x+'"', disablerepo_list)
                disablerepo_list = ''.join(disablerepo_list)

            enablerepo_list = ""
            if not enablerepo is None:
                enablerepo_list = enablerepo.split()
                enablerepo_list = map(lambda x: ' --enablerepo="'+x+'"', enablerepo_list)
                enablerepo_list = ''.join(enablerepo_list)

            disableplugin_list = ""
            if not disableplugin is None:
                disableplugin_list = disableplugin.split()
                disableplugin_list = map(lambda x: ' --disableplugin="'+x+'"', disableplugin_list)
                disableplugin_list = ''.join(disableplugin_list)

            result = self._fabrun("yum -y "+disableplugin_list+" "+disablerepo_list+" "+enablerepo_list+" install "+pkg)
            if not result.failed:
                print env.host + "|" + green("OK") + "|<"+pkg+"> successfully installed"
            else:
                print env.host + "|" + red("FAILED",True) + "|<"+pkg+"> not successfully installed"
            return result.succeeded

    def yum_update(self,pkg,sudo=False,disablerepo=None,disableplugin=None,enablerepo=None):
            """
            Update package from <pkg> named argument through Yum, in sudo mode is [sudo] is set to True
            with [disablerepo] as a list of separated by ' ' spaces yum repo to disable
            with [enablerepo] as a list of separated by ' ' spaces yum repo to enable
            with [disableplugin] as a list of separated by ' ' spaces yum plugin to disable
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())

            disablerepo_list = ""
            if not disablerepo is None:
                disablerepo_list = disablerepo.split()
                disablerepo_list = map(lambda x: ' --disablerepo="'+x+'"', disablerepo_list)
                disablerepo_list = ''.join(disablerepo_list)

            enablerepo_list = ""
            if not enablerepo is None:
                enablerepo_list = enablerepo.split()
                enablerepo_list = map(lambda x: ' --enablerepo="'+x+'"', enablerepo_list)
                enablerepo_list = ''.join(enablerepo_list)

            disableplugin_list = ""
            if not disableplugin is None:
                disableplugin_list = disableplugin.split()
                disableplugin_list = map(lambda x: ' --disableplugin="'+x+'"', disableplugin_list)
                disableplugin_list = ''.join(disableplugin_list)



            result = self._fabrun("yum -y "+disableplugin_list+" "+disablerepo_list+" "+enablerepo_list+" update "+pkg)
            if result.succeeded:
             print env.host + "|" + green("OK") + "|<"+pkg+"> successfully updated"
            else:
             print env.host + "|" + red("FAILED",True) + "|<"+pkg+"> not successfully updated: <"+result+">"
             return result.succeeded


    def yum_search(self,pkg,sudo=False):
            """
            Search package from <pkg> named argument through Yum, in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())
            result = self._fabrun("yum search "+pkg)
            if result.succeeded:
                result_list = result.split("\r\n")
                next = False
                pkgs = ""
                matches = []
                for line in result_list:
                    if re.match("^==",line):
                        next = True
                        continue
                    if next and not re.match("^[\s\t]+.*",line) and re.search("\w",line):
                        matches.append(line)
                for pkgs in matches:
                    print env.host + "|Found|" + pkgs
                if len(matches) == 0:
                    print env.host + "|NotFound|"+pkg
            return result.succeeded


    def process(self,process_pattern,sudo=False,kill=False):
            """
            Show <process_pattern> running processes, in sudo mode is [sudo] is set to True, and [kill] if set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())
            process_list = self._fabrun('ps aux | grep ' + process_pattern + ' | grep -v grep')
            for p in process_list.splitlines():
                print env.host+"|"+process_list
                if eval(str(kill).capitalize()):
                    plist = process_list.split()
                    result = self._fabrun('kill '+plist[1])

    def ip(self,sudo=False):
            """
            Show all mounted ip, in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())
            ips = self._fabrun("export PATH=$PATH:/sbin:/usr/sbin && ifconfig -a| awk '/^wlan|^eth|^lo|^bond/ {;a=$1;FS=\":\"; nextline=NR+1; next}{ if (NR==nextline) { split($2,b,\" \")}{ if ($2 ~ /[0-9]\./) {print a\",\"b[1]}; FS=\" \"}}'")
            ips_list = ips.split()
            #print ips_list
            ips_dict = dict((key, value) for key, value in (line.split(',') for line in ips_list))
            #print ips_dict
            for eth in ips_dict.iterkeys():
                try:
                        reverse_name = socket.gethostbyaddr(ips_dict[eth])[0]
                except:
                        reverse_name = self._fabrun("nslookup "+ ips_dict[eth]+ " 2>/dev/null | grep '.in-addr.arpa' | awk '{print $NF}'")
                        if reverse_name == "NXDOMAIN" :
                            reverse_name = "No DNS resolution found"
                print env.host + "|" + eth + "|" + ips_dict[eth] + "|" + reverse_name

    def listen(self,sudo=False):
            """
            Show all listen port/processes, in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())
            listen = self._fabrun("netstat -lntp 2>/dev/null | awk '{print $4,$7}' | awk -F/ '{print $1,$2}' | awk '{if ($1 ~ /[0-9]+/) {print $1\",\"$3}}' | sort -n")
            listen_list = listen.split()
            #print listen_list
            listen_dict = dict((key, value) for key, value in (line.split(',') for line in listen_list))
            #print listen_dict
            if not self.first.has_key(util._func_name()):
                self.first[util._func_name()] = True
                util._print_task_header("HOSTNAME|IP|PORT|PROCESS_NAME")
            for port in listen_dict.iterkeys():
                print env.host + "|" + re.sub(':(\d+)$','|\\1',port) + "|" + listen_dict[port]


    def ipvsadm(self,sudo=False):
        """
        Show all lvs rules configured on dispatcher host, in sudo mode is [sudo] is set to True
        """
        if util._is_host_up(env.host, int(env.port)) is False:
            return False
        self.needSudo = eval(str(sudo).capitalize())
        rules = self._fabrun("ipvsadm -ln --sort  | grep -E \"(TCP|->)\" | grep -v \"Remote\" | awk '{print $1\"|\"$2\"|\"$3\"|\"$4\"|\"$5\"|\"$6}'")
        rules_list = rules.split()
        lvs_rules = {}
        last_entry = ""
        list = []
        puts(rules_list)
        for entry in rules_list:
            if re.match("^->.*",entry):
                s = re.sub(r"^\->\|(.*)$","\\1",entry)
                ip = re.sub(r"^\->\|([^\:]+)\:.*$","\\1",entry)
                end = re.sub(r"^\->\|([^\:]+)(\:.*)$","\\2",entry)
                reverse = util._nslookup(ip)
                if reverse is not False:
                    puts("Found real server "+ util._nslookup(ip))
                    s = reverse+end
                else:
                    puts("Non reversed server "+ip)
                lvs_rules[last_entry].append(s)
            else:
                s = re.sub(r"^([^\|]+)\|([^\|]+)\|([^\|]+)\|.*$","\\1|\\2|\\3",entry)
                ip = re.sub(r"^([^\|]+)\|([^\:]+)\:.*$","\\2",entry)
                end = re.sub(r"^([^\|]+)\|([^\:]+)(\:.*)$","\\3",entry)
                end = re.sub(r'\|+','|',end)
                reverse = util._nslookup(ip)
                if reverse is not False:
                    puts("Found VIP "+ util._nslookup(ip))
                    s = reverse+end
                else:
                    puts("Non reversed VIP "+ip)
                last_entry = s
            if not lvs_rules.has_key(last_entry):
                lvs_rules[last_entry] = []
        puts(lvs_rules)
        if not self.first.has_key(util._func_name()):
            self.first[util._func_name()] = True
            util._print_task_header("HOSTNAME|VIP:VPORT|VMETHOD|REALIP:REALPORT|FORWARD_METHOD|WEIGHT|ACTIVECONN|INACTCONN")
        for rule in lvs_rules.iterkeys():
            for node in lvs_rules[rule]:
                print env.host + "|" + rule + node


    def route(self,sudo=False):
            """
            Show all configured routes, in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())
            routes = self._fabrun("netstat -nr | grep -E -v \"(Destination|Kernel)\" | awk '{print $1\"|\"$2\"|\"$3\"|\"$NF}'")
            routes_list = routes.split()
            for route in routes_list:
                print env.host + "|" + route

    def lvdisplay(self,sudo=False):
            """
            List logical volumes, in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())
            result = self._fabrun("lvdisplay -C | grep -v 'LV' | awk '{print $1\"|\"$2}'")
            if result.failed:
                print env.host+"|Failed: cannot execute lvdisplay: "+result
            lv_list = result.split()
            for lv in lv_list:
                print env.host + "|" + lv



    def lvcreate(self,lvname,vgname,size,fstype,sudo=False):
            """
            Create <lvname> into <vgname> of <size> and format into <fstype>, in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            self.needSudo = eval(str(sudo).capitalize())
            if not re.match("^\d+[kKmMgGtT]$",size):
                print env.host+"|Failed: Size must match with /^\d+[kKmMgGtT]$/"
                sys.exit()
            result = self._fabrun("vgdisplay /dev/"+vgname)
            if result.failed:
                print env.host+"|Failed: Cannot found Volume Group <"+vgname+">"
                sys.exit()
            result = self._fabrun("lvdisplay /dev/"+vgname+"/"+lvname)
            if  result.failed:
                    result = self._fabrun("lvcreate -L"+size+" -n"+lvname+" "+vgname)
                    if result.failed:
                        print env.host+"|Failed: Cannot create <"+lvname+"> on <"+vgname+"> Because of: "
                        print result
                        sys.exit()
                    else:
                        print env.host+"|OK: <"+lvname+"> on <"+vgname+"> Created"
                        result = self._fabrun("mkfs."+fstype+" -V")
                        if not result.failed:
                            result = self._fabrun("mkfs."+fstype+" /dev/"+vgname+"/"+lvname)
                            if not result.failed:
                                print env.host+"|OK: <"+lvname+"> on <"+vgname+"> Created on "+fstype+ " filesystem"
                            else:
                                print env.host+"|Failed: Cannot format /dev/"+vgname+"/"+vgname+" on "+fstype+" Because of: "
                                print result
                                sys.exit()
                        else:
                                print env.host+"|Failed: Cannot found mkfs."+fstype+" executable"
                                sys.exit()
            else:
                    print env.host+"|Failed: <"+lvname+"> on <"+vgname+"> Already exists"

            return True


    def last_line(self,file_l,nb_line,sudo=False):
            """
            Show the last <nb_line> of the <file_l>, in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                                return False
            self.needSudo = eval(str(sudo).capitalize())
            lines = self._fabrun('tail -n ' + nb_line + ' ' + file_l)
            if lines.failed:
                sys.stdout.write(env.host)
                sys.stdout.write("|" + red("Fichier introuvable"))
            else:
                real_nb_line = lines.count("\n")
                if real_nb_line == 0:
                    print env.host + '|' + yellow("Fichier vide")
                else:
                    line_list = lines.splitlines()
                    i = 0
                    for line in line_list:
                        if i != real_nb_line:
                            print env.host + '|' + white(line)
                        else:
                            print env.host + '|' + white(line,True)
                        i += 1

    def system_service_runlevel_info(self,service,sudo=False):
            """
            Show runlevel information of <service>
            in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                                return False
            self.needSudo = eval(str(sudo).capitalize())
            redhatRelease = self._fabrun('cat /etc/{redhat,centos}-release')
            if redhatRelease.failed:
                print env.host + '|' + yellow("{redhat,centos}-release file missing. Probably not a CentOs, Redhat distribution.")
            else:
                service_state = self._fabrun('chkconfig --list ' + service)
                service_state_col = service_state.split()
                sys.stdout.write(env.host)
                for col in service_state_col:
                    if col.split(":")[0] == "3":
                        if col.split(":")[1] == "off":
                            sys.stdout.write("|" + white(col,True))
                        else:
                            sys.stdout.write("|" + green(col))
                    else:
                        sys.stdout.write("|" + 	col)
                sys.stdout.write("\n")


    def system_service_onstartup(self,service,sudo=False):
            """
            Set a <service> to run on server startup
            in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                                return False
            self.needSudo = eval(str(sudo).capitalize())
            redhatRelease = self._fabrun('cat /etc/{redhat,centos}-release')
            if redhatRelease.failed:
                print env.host + '|' + yellow("{redhat,centos}-release file missing. Probably not a CentOs, Redhat distribution.")
            else:
                chk_result = self._fabrun('chkconfig --level 3 ' + service + ' on')
                if chk_result.failed:
                    print env.host + '|' + red("Failed to add the service on startup. Check the service name.")
                else:

                    print env.host + '|' + green("OK")

    def system_service_notonstartup(self,service,sudo=False):
            """
            Set a <service> to run on server startup
            in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                        return False
            self.needSudo = eval(str(sudo).capitalize())
            redhatRelease = self._fabrun('cat /etc/{redhat,centos}-release')
            if redhatRelease.failed:
                   print env.host + '|' + yellow("{redhat,centos}-release file missing. Probably not a CentOs, Redhat distribution.")
            else:
                   chk_result = self._fabrun('chkconfig --level 3 ' + service + ' off')
                   if chk_result.failed:
                          print env.host + '|' + red("Failed to remove the service on startup. Check the service name.")
                   else:
                          print env.host + '|' + green("OK")

    def system_service_action(self,service,action,sudo=False,display=False):
            """
            For a <service> in init
            Launch <action> : value are [re]start,stop,status,reload
            Red Hat like os compatible
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                   return False
            self.needSudo = eval(str(sudo).capitalize())
            redhatRelease = self._fabrun('cat /etc/{redhat,centos}-release')
            if redhatRelease.failed:
                print env.host + '|' + yellow("{redhat,centos}-release file missing. Probably not a CentOs, Redhat distribution.")
                return False
            else:
                svc_result = self._fabrun('/sbin/service ' + service + ' ' + action)
                if eval(str(display).capitalize()):
                    print svc_result
                    if svc_result.failed:
                         print env.host + '|' + red("Failed to "+action+" "+service+". Check the service name or the action.")
                         return False
                    else:
                         print env.host + '|' + green("SUCCESS:")+" launching <"+action+"> action for this init script: <"+service+">"
                         return True

    def reboot(self,confirm=True):
        """
        Reboot server
        """
        if confirm:
            prompt("Do you confirm that you want to reboot this server <"+env.host_string+"> (Y/N) ?",key='answer', default='N',validate='Y|N')
            if env.answer == 'Y':
                print env.host_string+"|rebooting"
                reboot(120)
            else:
                sys.exit(0)
        reboot(120)

    def mkdir(self,path,user=None,group=None,mode=None,sudo=False):
        """
        Create <path> recursively and chown [user] or/and [group], and set unix [mode]
        """
        if util._is_host_up(env.host, int(env.port)) is False:
            return False
        self.needSudo = eval(str(sudo).capitalize())
        msg = ""
        ret = self._fabrun("mkdir -p "+path)
        if not ret.failed:
            ret = self.chown(path,user,group,self.needSudo)
            if ret:
                ret = self.chmod(path,mode,self.needSudo)
                if ret:
                    print env.host+"|"+path+"|"+"Successfully created"
                else:
                    return False
        else:
            print(red("Error: ")+"Cannot mkdir "+path)
            return False
        return True

    def chown(self,path,user=None,group=None,sudo=False):
        """
        Chown <path> with <user>/<group>, in sudo mode is [sudo] is set to True
        """
        self.needSudo = eval(str(sudo).capitalize())
        if user is not None:
            ret = self._fabrun("chown "+user+" "+path)
            if ret.failed:
                print(red("Error: ")+"Cannot chown "+user+" into path "+path)
                return False
        if group is not None:
            ret = self._fabrun("chgrp "+group+" "+path)
            if ret.failed:
                print(red("Error: ")+"Cannot chgrp "+group+" into path "+path)
                return False
        return True


    def chmod(self,path,mode,sudo=False):
        """
        Chmod <path> with unix <mode>, in sudo mode is [sudo] is set to True
        """
        self.needSudo = eval(str(sudo).capitalize())
        ret = self._fabrun("chmod "+mode+" "+path)
        if ret.failed:
            print(red("Error: ")+"Cannot chmod "+mode+" into path "+path)
            return False
        return True


    def mount(self,mount_point,dev,muser=None,mgroup=None,mode=None,fstype=None,mount_opts=None,sudo=False):
        """
        Mount device <dev> into <mount_point> and create it with [muser]/[mgroup] rights
        """
        if util._is_host_up(env.host, int(env.port)) is False:
            return False
        self.needSudo = eval(str(sudo).capitalize())
        mtab = "/etc/mtab"
        if not util._contains(mtab,mount_point):
            if not util._exists(mount_point):
                ret = self.mkdir(path=mount_point,user=muser,group=mgroup,mode=mode)
                if not ret:
                    print(red("Error: ")+"Cannot create directory <"+mount_point+">. Abording")
                    return False
            if util._exists(dev):
                fstab = "/etc/fstab"
                if not util._contains(fstab,mount_point):
                        util._append(fstab,dev+"\t"+mount_point+"\t"+fstype+"\t"+mount_opts)
                ret = self._fabrun("mount "+mount_point)
                if ret.failed:
                    print(red("Error: ")+"Cannot mount <"+mount_point+"> partition. Abording")
                    return False
                ret = self.chown(mount_point,muser,mgroup,self.needSudo)
                if ret:
                    ret = self.chmod(mount_point,mode,self.needSudo)
            else:
                print(red("Error: ")+"Device <"+dev+"> cannot exists. Abording")
                return False
        return True


    def piped_tar(self,src_host,src_path,dst_path,src_user=env.user):
        """
        Copy object from [src_user]@<src_host>:<src_path> to host into <dst_path>
        src_user is the default ssh client user
        """
        import paramiko
        if util._is_host_up(env.host, int(env.port)) is False:
            return False
        if util._is_host_up(src_host, int(env.port)) is False:
            return False
        if src_path.endswith('/'):
            src_path = re.sub("/$","",src_path)
        src_path_last_dir = re.sub(r"^(.*)/([^\/]+)$","\\1",src_path)
        src_path_end = re.sub(r"^"+src_path_last_dir+"/([^\/]+)$","\\1",src_path)
        save_host = env.host
        save_user = env.user
        save_host_string = env.host_string
        env.host = src_host
        env.host_string = src_host
        env.user= src_user
        check_src = run("ls "+src_path)
        if check_src.failed:
            print(red("FAILURE")+" cannot found <"+src_path+"> on <"+env.host+">")
            return False
        env.host = save_host
        env.user = save_user
        env.host_string = save_host_string
        check_src = run("ls "+dst_path)
        if check_src.failed:
            print(red("FAILURE")+" cannot found <"+dst_path+"> on <"+env.host+">")
            return False
        if not dst_path.endswith('/'):
            dst_path += '/'
        command = "ssh "+src_user+'@'+src_host+" \"cd "+src_path_last_dir+" && tar zcvf - "+src_path_end+"\" | ssh "+env.user+"@"+env.host+" \"cd "+dst_path+" && tar zxvf -\""
        puts(command)
        save_host = env.host
        save_host_string = env.host_string
        env.host_string = src_host
        env.host = src_host
        orig_size_file = self._fabrun("stat -c %s "+src_path)
        orig_size_file_list = orig_size_file.splitlines()
        orig_size_file = 0
        for f in orig_size_file_list:
            try:
                int(f)
                orig_size_file+=int(f)
            except:
                orig_size_file+=0
        if int(orig_size_file) == 0:
            print red("Error: ")+"<"+src_path+"> file size is null"
            return False
        puts("Orig file size = "+str(orig_size_file))
        env.host = save_host
        env.host_string = save_host_string

        newpid = os.fork()

        if newpid == 0:
            # child

            puts("child "+str(os.getpid()))

            Bar = util.ProgressBar(int(orig_size_file), 60, src_host+'->'+env.host)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(env.host, username=env.user)
            while True:
                _, stdout, _ = client.exec_command("stat -c %s "+dst_path+src_path_end+" 2>/dev/null")
                size_file = stdout.read()
                puts("found size = "+size_file)
                size_file_list = size_file.splitlines()
                size_file = 0
                for s in size_file_list:
                    try:
                        int(s)
                        size_file+=int(s)
                    except:
                        size_file+=0
                puts("Dst file size = "+str(size_file))

                Bar.update(int(size_file))

                if int(size_file) >= int(orig_size_file):
                    print " copy terminated"
                    os._exit(0)

        else:
            # parent
            result = local(command,capture=True)
            os.waitpid(newpid, 0)

            if not result.failed:
                print(green("SUCCESS")+" during piped tar through ssh copy")
                puts(result.stderr)
            else:
                print(red("FAILURE")+" during piped tar through ssh copy")
                print result.stderr


    def sed(self,filename, before, after, limit='', sudo=False, backup='.bak', flags=''):
        """
        sed <filename> replace <before> with <after> with [limit] default '' , in [sudo] mode default False, [backup] old file with extension default .bak and add some [flags] for sed flags
        """
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        result = util._sed(filename, before, after, limit, sudo, backup, flags)
        if not result.succeeded:
                print(env.host+"|"+red("FAILURE")+" during sed on <"+filename+">")
                puts(result.stderr)
                return False
        else:
                print(env.host+"|"+green("SUCCESS")+" during sed on <"+filename+">")
                return True


    def grep(self,filename,pattern,lines=0,show_lines=False,sudo=False,display=True):
        """
        grep <pattern> into <filename> and return [lines] lines
        default 0 for all matching lines, and [show_lines] False by default , whith [sudo] False by default
        """
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        self.needSudo = eval(str(sudo).capitalize())
        l_opt = ""
        n_opt = ""
        if int(lines) > 0:
            l_opt = "| head -n "+str(int(lines))+" "
        try:
            if eval(str(show_lines)):
                n_opt = "-n "
        except:
            util._print_stack_error(str(show_lines)+" is not a valid boolean value. Ignoring")
        result = self._fabrun("grep -E \""+pattern+"\" "+n_opt+filename+l_opt)
        if result.failed:
            print(env.host+"|"+red("FAILURE")+" during grep on <"+filename+">")
            puts(result.stderr)
            return False
        else:
            if eval(str(display).capitalize()):
                for l in result.splitlines():
                    print env.host+"|"+l
            return True

    def free(self,sudo=False):
        """
        display memory usage through 'free -m' , whith [sudo] False by default
        """
        self.needSudo = eval(str(sudo).capitalize())
        result = self._fabrun("free -m")
        if result.failed:
                print(env.host+"|"+red("FAILURE")+" during free command")
                puts(result.stderr)
                return False
        else:
                print env.host+"|"+result
                return True


    def append(self,filename, text, use_sudo=False, partial=False, escape=False,shell=False,force=False,create=False):
        """
        Append string (or list of strings) <text> to <filename>.
        When a list is given, each string inside is handled independently (but in the order given.)
        If text is already found in filename, the append is not run, and None is returned immediately.
        Because text is single-quoted, single quotes will be transparently backslash-escaped.
        This can be disabled with [escape] default False.
        [force] can be used to add <text> if it is already set into file, (default: False) so doing nothing
        The [shell] argument will be eventually passed to run/sudo, (default: False)
        If [use_sudo] is True, will use sudo instead of run.
        create file if not found if [create] is set to True ( default : False )
        """
        self.needSudo = eval(str(use_sudo).capitalize())
        if not util._exists(filename) and eval(str(create).capitalize()):
            result = self._fabrun("touch "+filename)
            if result.failed:
                print env.host+"|"+red("Failed")+" to create file <"+filename+"> "
                return False
        ret = util._append(filename, text, use_sudo, partial, escape, shell, force)
        if ret:
            print env.host+"|File <"+filename+"> has been "+green("correctly")+" modified"
        else:
            print env.host+"|"+red("Failed")+" to modify file <"+filename+"> "


    def find(self,directory,type=None,maxdepth=None,name=None,display=True,sudo=False,error=True):
        """
        list all entries into <directory>, or just [type], [name] entries, into [maxdepth] (cf man find for type argument) and [display] default True,  If [sudo] is True, will use sudo instead of run
        """
        if util._is_host_up(env.host, int(env.port)) is False:
            return False
        self.needSudo = eval(str(sudo).capitalize())
        type_opt = ""
        if not type is None:
            type_opt = " -type "+type+" "
        maxdepth_opt = ""
        if not maxdepth is None:
            maxdepth_opt = " -maxdepth "+str(maxdepth)+" "
        name_opt = ""
        if not name is None:
            name_opt = " -name \'"+name+"\' "
        error_opt = ""
        if not error:
            error_opt = " 2>/dev/null"
        else:
            error_opt = ""
        result = self._fabrun("find "+directory+maxdepth_opt+name_opt+type_opt+error_opt)
        if result.failed:
            if error:
                print env.host+"|"+red("Failed")+" search into <"+directory+"> "
                print result
            return False
        else:
            if display:
                for entry in result.splitlines():
                    print env.host+"|"+entry
            return result.splitlines()


    def stat(self,fd,display=True,sudo=False):
            """
            stat <fd> and [display] unix mode, default true, in [sudo] mode default False
            """
            self._fabrun = eval(str(sudo).capitalize()) and util._sudo or util._run
            result = self._fabrun("stat --format='%a|%U|%G' "+fd)
            if not result.failed:
                    modes = result.split('|')
                    modes[0] = "%04d" % (int(modes[0]))
                    if eval(str(display).capitalize()):
                            if not self.first.has_key(util._func_name()):
                                    self.first[util._func_name()] = True
                                    util._print_task_header("HOSTNAME|ENTRY|UNIX_MODE|USER|GROUP")
                            print env.host+"|"+fd+"|"+'|'.join(modes)
                    else:
                            return '|'.join(modes)
            else:
                    if eval(str(display).capitalize()):
                            print env.host+"|"+fd+"|"+result
                    else:
                            puts(env.host+"|"+fd+"|"+result)
                    return False

    def uid_exists(self,uid,user_name):
        """
        Use getent tool to check if uid exists
        <uid> must be a numreric value
        <user_name> must be the label expected
        """
        ruid = self._fabrun("getent user "+str(uid)+"|grep "+user_name)
        if ruid.succeeded:
            return True
        else:
            return False

    def gid_exists(self,gid,group_name):
        """
        Use getent tool to check if gid exists
        <gid must> be a numreric value
        <group_name> must be the label expected
        """
        rgid = self._fabrun("getent group "+str(gid)+"|grep "+group_name)
        if rgid.succeeded:
            return True
        else:
            return False


    def id(self):
        """
        Get the current id of the user on remote host
        """
        id = util._run("id")
        print env.host+"|"+id
        return id

    def yum_disable_repo(self,reponame,entry,backup='bak',sudo=False):
        """
        Disable <entry> (ie main, testing etc .. ) into <reponame>.repo file into /etc/yum.conf.d/
        and create backup file with [backup] extension (default: 'bak')
        in [sudo] mode (default: False)
        """
        if util._is_host_up(env.host, int(env.port)) is False:
            return False
        self.needSudo = eval(str(sudo).capitalize())
        filename = "/etc/yum.repos.d/"+reponame+".repo"
        if util._exists(filename+"."+backup):
            print(env.host+"|"+yellow("Warning: ")+"<"+cyan(filename+"."+backup)+"> file already exists, doing nothing. Please delete first if you want to change it")
            return False
        result = self._fabrun("sed -i."+backup+" -e 'N; s#/"+entry+"/$basearch\\nenabled = 1#/"+entry+"/$basearch\\nenabled = 0#' "+filename)
        if not result.succeeded:
            print(env.host+"|"+red("FAILURE")+" during sed on <"+filename+">")
            puts(result.stderr)
            return False
        else:
            print(env.host+"|"+green("SUCCESS")+" during sed on <"+filename+">")
            return True

    def get_file(self,*args, **kwargs):
            """
            <get> task alias
            """
            self.get(*args, **kwargs)

    def get(self,remote_path,local_path,sudo=False):
            """
            Get <remote_path> set in parameter on remote host into <local_path> , in sudo mode is [sudo] is set to True
            """
            if util._is_host_up(env.host, int(env.port)) is False:
                return False
            if len(remote_path) == 0:
                print(red('ERROR:')+' '+remote_path+' cannot be an empty path')
                return False
            if len(local_path) == 0:
                print(red('ERROR:')+' '+local_path+' cannot be an empty path')
                return False
            try:
                last_level_remote_path = remote_path.split('/')
                local_path = local_path.rstrip('/')
                local_unique_path = local_path.rstrip('/')+'/'+last_level_remote_path[-1]+'.'+env.host
                result = get(remote_path=remote_path,local_path=local_unique_path,use_sudo=eval(str(sudo).capitalize()))
                if result.succeeded:
                    print env.host+"|<"+yellow(remote_path)+"> "+green("successfully")+" get from "+env.host+" and put into <"+yellow("\n".join(result))+">"
                else:
                    print env.host+"|<"+yellow(remote_path)+"> "+red("failed")+" to get some objects <"+red(",".join(str(item) for item in result.failed))+">"
            except Exception as e:
                puts(env.host+"|Exception during task execution (Bad value for some parameter(s) ? ) : ",e)

