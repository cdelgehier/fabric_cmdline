from __future__ import division

from fabric.api import *
from fabric.context_managers import *
from fabric.contrib.files import *
from fabric.contrib.files import _escape_for_regex
from fabric.colors import *

import inspect
import sys
import traceback
import paramiko
import socket
import os.path
import re

from socket import gethostbyaddr

def add_class_methods_as_module_level_functions_for_fabric(instance, module_name):
    '''
    Utility to take the methods of the instance of a class, instance,
    and add them as functions to a module, module_name, so that Fabric
    can find and call them. Call this at the bottom of a module after
    the class definition.
    '''
    # get the module as an object
    module_obj = sys.modules[module_name]

    # Iterate over the methods of the class and dynamically create a function
    # for each method that calls the method and add it to the current module
    for method in inspect.getmembers(instance, predicate=inspect.ismethod):
        method_name, method_obj = method

        if not method_name.startswith('_'):
            # get the bound method
            func = getattr(instance, method_name)

            # add the function to the current module
            setattr(module_obj, method_name, func)

def _is_host_ping(host):
    import subprocess
    with open(os.devnull, 'wb') as devnull:
        return subprocess.call(['ping', '-c','1', host], stdout=devnull, stderr=subprocess.STDOUT) == 0

def _is_host_ip_defined (host):
    try:
        socket.gethostbyname(host)
    except Exception:
        return False
    else:
        return True
    
def _is_host_up(host, port,timeout=3,ssh_compatibility=True,display_warn=True):
    import sys
    if socket.gethostname().lower() == host or host == 'localhost' or not env.gateway is None:
        return True
    # its win32, maybe there is win64 too?
    if sys.platform.startswith('win'):
        port = 5985 # winrm default port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((env.host, port))
            s.shutdown(2)
        except:
            if display_warn:
                sys.stderr.write('***Warning*** Host {host} on port {port} is down\n'.format(host=host, port=port))
            return False
    # linux platforms
    elif sys.platform.startswith('linux'):
        # Set the timeout
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            transport = paramiko.Transport((host, port))
        except:
            if display_warn:
                sys.stderr.write('***Warning*** Host {host} on port {port} is down\n'.format(host=host, port=port))
            return False
        socket.setdefaulttimeout(original_timeout)
        if eval(str(ssh_compatibility).capitalize()):
            # check SSH protocol
            if not _is_host_compatible(host,display_warn):
                if display_warn:
                    sys.stderr.write('***Warning*** Host {host} on port {port} is not SSH reachable\n'.format(host=host, port=port))
                return False
        return True


def _is_host_compatible(host=env.host,display_warn=True,timeout=None):
    """
    Check if host is compatible with SSHv2
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=env.user,allow_agent=env.forward_agent,timeout=timeout)
    except paramiko.transport.SSHException as e:
        if display_warn:
            print host + "|" + red("SSHException",True) + "|%s " % e
        return False
    return True


def _humanize_bytes(bytes, precision=2):
    """
    Return a humanized string representation of a number of bytes.
    Assumes `from __future__ import division`.
    >>> humanize_bytes(1)
    '1 byte'
    >>> humanize_bytes(1024)
    '1.0 kB'
    >>> humanize_bytes(1024*123)
    '123.0 kB'
    >>> humanize_bytes(1024*12342)
    '12.1 MB'
    >>> humanize_bytes(1024*12342,2)
    '12.05 MB'
    >>> humanize_bytes(1024*1234,2)
    '1.21 MB'
    >>> humanize_bytes(1024*1234*1111,2)
    '1.31 GB'
    >>> humanize_bytes(1024*1234*1111,1)
    '1.3 GB'
    """
    import math
    bytes = long(bytes)
    abbrevs = (
        (1<<50L, 'PB'),
        (1<<40L, 'TB'),
        (1<<30L, 'GB'),
        (1<<20L, 'MB'),
        (1<<10L, 'kB'),
        (1, 'bytes')
    )
    if bytes == 1:
        return '1 byte'
    for factor, suffix in abbrevs:
        if bytes >= factor:
            break
    return '%.*f %s' % (precision, bytes / factor, suffix)


def _func_name():
    return inspect.stack()[1][3]


def _nslookup(ip):
    try:
        output = gethostbyaddr(ip)
        return output[0]
    except:
        return False

def _print_stack_error(msg_error=""):
    """
    Print stacktrace and an error message first
    """
    puts("ERROR: "+msg_error)
    exc_type, exc_value, exc_traceback = sys.exc_info()
    trace = traceback.format_exception(exc_type, exc_value, exc_traceback,limit=0)
    puts("".join(trace))


def _values_list_to_dict(list,sep):
    """
    Return dict from list with string separated values
    """
    _dict = {}
    #print list
    for param in sorted(list):
        val = param.split(str(sep))
        if len(val) == 2:
            _dict[val[0]] = val[1]
        else:
            _dict[val[0]] = True
    return _dict

def _run(command,pty=True):
    result = ''
    if socket.gethostname() == env.host or env.host == 'localhost':
        puts("Executing local command <"+command+">")
        result = local(command,capture=True)
    else:
        puts("Executing remote command <"+command+">")
        result = run(command,pty)
    puts("result _run = <"+str(result)+">")
    return result

def _exists(filedir,use_sudo=False,verbose=False):
    if socket.gethostname() == env.host or env.host == 'localhost':
        if not re.match("^/",filedir):
            filedir = env.cwd + '/'+ filedir
        puts("Executing local exists <"+filedir+">")
        result = os.path.exists(filedir)
    else:
        puts("Executing remote exists <"+filedir+">")
        result = exists(filedir,use_sudo,verbose)
    puts("result _exists = "+str(result))
    return result

def _cd(path):
    if socket.gethostname() == env.host or env.host == 'localhost':
        puts("Executing local cd <"+path+">")
        while path.endswith('/'):
            path = path[0:-1]
        env.cwd = path
        puts("Executing local cd <"+path+">")
        return lcd(path)
    else:
        puts("Executing remote cd <"+path+">")
        return cd(path)


def _contains(file,pattern,exact=True,use_sudo=False,escape=False):
    if socket.gethostname() == env.host or env.host == 'localhost':
        puts("Executing local contains <"+file+">")
        if not re.match("^/",file):
            file = env.cwd + '/' + file
        if os.path.exists(file):
            if eval(str(use_sudo).capitalize()):
                from cStringIO import StringIO
                f = StringIO(_sudo("cat "+file))
            else:
                f = open(file, 'r')
            search = re.compile(pattern)
            flag = ""
            if eval(str(exact).capitalize()):
                flag = re.I
            result = search.search(f.read(),flag)
            if result:
                return result
            else:
                return False
        else:
            return False
    else:
        puts("Executing remote contains <"+file+">")
        return contains(file,pattern,exact,use_sudo,escape)


def _sudo(command,shell=True,pty=True, combine_stderr=True, user=None):
    if socket.gethostname() == env.host or env.host == 'localhost':
        puts("Executing local sudo <"+command+">")
        result = local("sudo -S -p 'sudo password:' "+command,capture=True)
    else:
        puts("Executing remote sudo <"+command+">")
        result = sudo(command,shell,pty,combine_stderr,user)
    return result


def _sed(filename,before, after, limit='', use_sudo=False, backup='.bak', flags=''):
    if socket.gethostname() == env.host or env.host == 'localhost':
        if not re.match("^/",filename):
            filename = env.cwd + '/' + filename
        puts("Executing local sed on <"+filename+">")
        result = _run("sed -i."+backup+" -r -e 's/"+before+"/"+after+"/g"+flags+"' "+filename)
    else:
        puts("Executing remote sed on <"+filename+">")
        result = sed(filename,before, after, limit, use_sudo, backup, flags)
    return result


def _append(filename, text, use_sudo=False, partial=False, escape=True,shell=False, force=True):
    env.warn_only = False
    if type(text) != type(list()) and type(text) == type(str()):
        text = text.split("\\n")
    # local mode
    if socket.gethostname() == env.host or env.host == 'localhost':
        if not re.match("^/",filename):
            filename = env.cwd + '/' + filename
        if not os.path.exists(filename):
            print(env.host+"|"+red("Error: ")+" file <"+magenta(filename)+"> doesn't exists")
            return False
        puts("Executing local append on <"+filename+">")
        result = True
        for t in text:
            # default not writing
            write = False
            contains =  _contains(filename,t,exact=True,use_sudo=eval(str(use_sudo).capitalize()))
            if not contains:
                write = True
            elif contains and eval(str(force).capitalize()):
                write = True
            elif contains and not eval(str(force).capitalize()):
                print(env.host+"|"+yellow("Warning: ")+" text <"+cyan(t)+"> already into <"+magenta(filename)+">, not added")
                result = True
                continue
            if write:
                if eval(str(use_sudo).capitalize()):
                    result = local("sudo -S -p 'sudo password: ' "+env.shell+" 'echo \""+t+"\" >> "+filename+"'",capture=True)
                else:
                    result = local("echo \""+t+"\" >> "+filename,capture=True)
                if result.failed:
                    print(env.host+"|"+red("Error: ")+" during text <"+cyan(t)+"> append into <"+magenta(filename)+">")
                    return False
                result = result.succeeded
        return result

    # remote mode
    else:
        if not _exists(filename):
            print(env.host+"|"+red("Error: ")+" file <"+magenta(filename)+"> doesn't exists")
            return False
        puts("Executing remote append on <"+filename+">")
        result = True
        for t in text:
            # default not writing
            write = False
            contains =  _contains(filename,t,exact=True,use_sudo=eval(str(use_sudo).capitalize()))
            if not contains:
                write = True
            elif contains and eval(str(force).capitalize()):
                write = True
            elif contains and not eval(str(force).capitalize()):
                print(env.host+"|"+yellow("Warning: ")+" text <"+cyan(t)+"> already into <"+magenta(filename)+">, not added")
                result = True
                continue
            if write:
                #result = append(filename, text, eval(str(use_sudo).capitalize()), eval(str(partial).capitalize()), eval(str(escape).capitalize()),shell)
                if eval(str(use_sudo).capitalize()):
                    result = sudo(env.shell+" 'echo \""+t+"\" >> "+filename+"'")
                else:
                    result = run("echo \""+t+"\" >> "+filename)
                if result.failed:
                    print(env.host+"|"+red("Error: ")+" during text <"+cyan(t)+"> append into <"+magenta(filename)+">")
                    return False
                result = result.succeeded
        return result


def _check_sudo(requires_cmds=None,user='root'):
    """
    Check sudo rights from <requires_cmds> for <user>
    """
    if user == 'root':
        return True
    if requires_cmds is None:
        requires_cmds = []
    line = _run("sudo -l")
    for match in requires_cmds:
        if re.search(match,line,re.M):
                item = requires_cmds.remove(match)
    if len(requires_cmds) != 0:
        print(red("Error: ")+"some sudo commands <"+str(requires_cmds)+"> are missing")
        return False
    else:
        return True



def _kazan_retrieve(GAV,ArtifactClassifier,ArtifactPackaging):
    """
    Retrieve kazan from <GAV>,<ArtifactClassifier> and <ArtifactPackaging>
    <GAV> separated params groupID:artifactID:version
    <artifactClass> class of files LIB, CONF-dev ( separated by ':' field ) etc ...
    <ArtifactPackaging> type of package tar.gz , war ...
    """
    import urlgrabber

    # NEXUS_BASE = "http://ganesh-code.mpht.priv.atos.fr/nexus"
    NEXUS_BASE = "https://kazan.priv.atos.fr/nexus"
    REST_PATH = "/service/local"
    ART_REDIR = "/artifact/maven/redirect"
    if sys.platform.startswith('win'):
        output_dir = "D:\\Temp\\software\\kazan"
    if sys.platform.startswith('linux'):
        output_dir = "/DATA/software/kazan"


    if not re.match("(war|tar.gz|jar)",ArtifactPackaging):
        print "ArtifactPackaging mus be <war|tar.gz>"
        sys.exit()

    GAV_list = GAV.split(":")
    CLASSIFIER_list = ArtifactClassifier.split(":")
    params_url = {  'g' : GAV_list[0] ,
            'a' : GAV_list[1],
            'v' : GAV_list[2],
            'p' : ArtifactPackaging,
    }

    if re.match(".*SNAPSHOT",params_url["v"]):
        #params_url["r"] = "ganeshrepository-snapshot"
        params_url["r"] = "snapshots"
    else:
        #params_url["r"] = "ganeshrepository"
        params_url["r"] = "releases"

    url = NEXUS_BASE + REST_PATH + ART_REDIR + '?'
    uri = ""
    for param in params_url.iterkeys():
        url+=param+'='+params_url[param]+'&'
    url=re.sub("&$","",url)

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    saved_files = []
    # save on local file
    for classifier in CLASSIFIER_list:
        if not re.match("(war|jar)",ArtifactPackaging,flags=re.IGNORECASE):
            cl="&c="+classifier
            classifier="-"+classifier
        else:
            cl=""
            classifier=""
        cl_url = url+cl
        print "\nTrying to fetch url <"+cl_url+">\n"
        try:
            if sys.platform.startswith('win'):
                #filename = urlgrabber.urlgrab(cl_url,filename=output_dir+"\\"+params_url["a"]+"-"+params_url["v"]+classifier+"."+params_url["p"])
                filename = output_dir+"\\"+params_url["a"]+"-"+params_url["v"]+classifier+"."+params_url["p"]
            if sys.platform.startswith('linux'):
                #filename = urlgrabber.urlgrab(cl_url,filename=output_dir+"/"+params_url["a"]+"-"+params_url["v"]+classifier+"."+params_url["p"])
                filename = output_dir+"/"+params_url["a"]+"-"+params_url["v"]+classifier+"."+params_url["p"]
            distantfile = cl_url
            import urllib2
            #import M2Crypto

            proxy = urllib2.ProxyHandler({})
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)

            dfile = urllib2.urlopen(distantfile)
            output = open(filename,'wb')
            output.write(dfile.read())
            output.close()

            print "File <"+filename+"> successfully uploaded"
            saved_files.append(filename)
        except:
            print "Unexpected error:", sys.exc_info()[0]
            raise
    return saved_files


def _mysqldb_query(host,user,password,query,db,port=3306):
    """
    Execute mysql <query> on <host>:[port] authenticated with <user>/<password> on <db>
    """
    if _check_python_library('MySQLdb'):
        import MySQLdb
    else:
        return False
    database = None
    resultset = False
    port = int(port)
    try:
            puts("Executing query <"+query+"> on <"+host+":"+str(port)+"/"+db)
            database = MySQLdb.connect(host=host,
                            port=port,
                            user=user,
                            passwd=password,
                            db=db)
            cursor = database.cursor()
            result = cursor.execute(query)
            resultset = []
            for line in cursor.fetchall():
                resultset.append(line)
    except Exception as e:
        print str(type(e))+str(e)

    finally:
            if database:
                cursor.close()
                database.close()
    return resultset


def _cmdbdump(hosts,name="HOSTS_DUMP",remote_user="root",enable=True,display=True,file=False):
    """
    Dump cmdb from a <hosts> dict on stdout if [display] is True (default)
    [name] the output family
    """
    import pprint
    name = re.sub("[\.\-\s%]","_",name)
    cmdb_str = "enable = True\nremote_user = \""+str(remote_user)+"\"\ncmdb = " + str(pprint.PrettyPrinter(indent=1,width=80,depth=None).pformat(hosts))+"\n"
    if eval(str(display).capitalize()):
        print cmdb_str
    if eval(str(file).capitalize()):
        if sys.platform.startswith('win'):
            dumpfile = open(env.config_dict['Fabcmdb']+'\\'+name+".py","w")
        if sys.platform.startswith('linux'):
            dumpfile = open(env.config_dict['Fabcmdb']+'/'+name+".py","w")
        dumpfile.write(cmdb_str)
        dumpfile.close()
    return cmdb_str



class ProgressBar:
    """
    Progress bar
    """
    def __init__ (self, valmax, maxbar, title):
        if valmax == 0:  valmax = 1
        if maxbar > 200: maxbar = 200
        self.valmax = max(1, valmax)
        self.maxbar = min(maxbar, 200)
        self.title  = title
    
    def update(self, val):
        import sys
        # process
        perc  = round((float(val) / float(self.valmax)) * 100)
        scale = 100.0 / float(self.maxbar)
        bar   = int(perc / scale)
  
        # render 
        out = '\r %20s [%s%s] %3d %%' % (self.title, '=' * bar, ' ' * (self.maxbar - bar), perc)
        sys.stdout.write(out)
        sys.stdout.flush()


def _check_python_library(python_library):
    if not env.installed_library.has_key(python_library) or not env.installed_library[python_library]:
        env.installed_library[python_library] = False
        from pkgutil import iter_modules
        a=iter_modules()
        while True:
            try: x=a.next()
            except: break
            if python_library in x[1]:
                env.installed_library[python_library] = True
                return True
        if not env.installed_library[python_library]:
            print(yellow("Warning:")+"<"+python_library+"> library is not installed, please install it first before using this module or task)")
            return False
    else:
        return True

def _print_task_header(msg):
    if not env.parallel:
        print msg

