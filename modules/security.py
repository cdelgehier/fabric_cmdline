from fabric.api import env, local, run, require, cd
from fabric.operations import _prefix_commands, _prefix_env_vars
from fabric.contrib.files import *
from fabric.colors import *

import inspect
import util
import sys

class security(object):

    # Turn to 'True' to enable current module
    enabled = True
    # Dict for functions calling
    first = {}

    # run options
    needSudo = False

    def __init__(self):
            puts("Init <" + __name__ + ">")


    def _fabrun(self,*args):
        if self.needSudo:
            return util._sudo(*args)
        else:
            return util._run(*args)



    def changeUnixPassword(self,user,password=None,sudo=False):
        """
        Change Unix password for <user>
        with [password] (default: None) , prompted for the user ( Warning: this method is unsecure with shell history)
        in [sudo] mode (default False)
        """
        from crypt import crypt
        from getpass import getpass
        self.needSudo = eval(str(sudo).capitalize())
        if not env.has_key('changeUnixPassword'):
            env.changeUnixPassword = {}
        if not env.changeUnixPassword.has_key(user):
            if not password is None:
                env.changeUnixPassword[user] = crypt(password, 'salt')
            else:
                password = getpass('Enter a new password for user %s:' % user)
                password2 = getpass('Please re-enter the password for user %s:' % user)
                if password != password2:
                    print(red("ERROR:")+" the two passwords you've entered does not matched")
                    return False
                env.changeUnixPassword[user] = crypt(password, 'salt')
        result = self._fabrun('usermod --password %s %s' % (env.changeUnixPassword[user], user), False)
        if result.succeeded:
            print(env.host+"|password "+green("SUCCESSFULLY")+" updated for <"+blue(user)+"> user")
            return True
        else:
            print(env.host+"|"+red("FAILED")+" to update password for <"+blue(user)+"> user. Reason: <"+yellow(result)+">")
            return False


    def secu_check_ssl_version(self,version='ssl2|ssl3',port='443',excluded_ip=None,excluded_ports=None,timestamp=False):
        '''
        Check the availability of SSL protocol on port

        :param version: network protocols to check 'ssl2|ssl3' by default
        :param port: port to check on host (mutually exclusive with 'excluded_ports')
        :param excluded_ip : To exclude specify ip scan (ex: '127.0.0.0.1|0.0.0.0')
        :param excluded_ports : To scan all ports except these ones (mutually exclusive with 'port'). No default value but '22|2106|2205|5666|4000|510|123' is a good start
        :param timestamp: Display an additional stamp
        :return:
        '''
        
        if timestamp:
            import datetime, time
            output = env.host + '|' + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + '| '
        else:
            output = env.host + '| '

        vers = version.split("|") 

        if excluded_ports is not None:
            port = None
            black_list_port = excluded_ports.split("|")

        if excluded_ip is not None:
            black_list_ip = excluded_ip.split("|")

        if not util._is_host_ip_defined(env.host):
            print output + 'Could ' + red('not be resolved', True) + ' to an IP address'
            return
    
        if not util._is_host_ping(env.host):
            print output + 'Machine ' + red('does not respond', True) + ' to ping request'
            return

        if not util._is_host_compatible(env.host, display_warn=False,timeout=5):
            print output + yellow('This server may not be compatible with Fabric')
            
        if not util._is_host_up(env.host, 22, display_warn=False):
            print output + 'SSH server may be ' + red('down', True) + " or you don't have access with the " + blue(env.user, True) + " user. Please check your ~/.ssh/config."
            return

        if port:
            if excluded_ip is not None:
                result = run('netstat -lnt | grep LISTEN | awk \'{{print $4}}\' | grep -v -E "{ip}"| grep {port}'.format(port=port, ip="|".join(black_list_ip)), timeout=7)
            else:
                result = run('netstat -lnt | grep LISTEN | awk \'{{print $4}}\' | grep {port}'.format(port=port), timeout=7)
        elif excluded_ports:
            if excluded_ip is not None:
                result = run('netstat -lnt | grep LISTEN | awk \'{{print $4}}\' | grep -v -E "{ip}" | grep -v -E "{port}"'.format(port="|".join([':{0}$'.format(e) for e in black_list_port]), ip="|".join(black_list_ip)), timeout=7)
            else:
                result = run('netstat -lnt | grep LISTEN | awk \'{{print $4}}\' | grep -v -E "{port}"'.format(port="|".join([':{0}$'.format(e) for e in black_list_port])), timeout=7)
        else :
            print output + magenta('You have to specify a port OR some excluded ports', True)
            return False

        if result.succeeded:
            result3 = self._fabrun('rpm -q openssl --queryformat "%{NAME}-%{VERSION}-%{RELEASE}\n" | sort -n | tail -1 | xargs rpm -ql | grep -E "bin/openssl$"')

            if result3.succeeded:
                binopenssl = result3
            else:
                print output + yellow("OpenSSL not found on this server")
                return False
                
            for line in result.splitlines():
                ip = line.split(':')[0]
                port = line.split(':')[1]
                
                for prot in vers:
                    enable = True
                    result2 = self._fabrun('echo "QUIT" | '+ binopenssl +' s_client -connect '+ ip + ':' + port + ' -' + prot, False)

                    if any(message in result2 for message in ('SSL routines:SSL3_GET_RECORD:wrong version number','ssl handshake failure','errno=104', 'SSL routines:SSL2_READ_INTERNAL:illegal padding')):
                        print output + ip + ':' + port + ' ' + yellow(prot) + ' is ' + green('disable')
                    else:
                        print output + ip + ':' + port + ' ' + yellow(prot) + ' is ' + red('enable')

        else: 
            print output + "no ip is listening on port : " + yellow(port)
