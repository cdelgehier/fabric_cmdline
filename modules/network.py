from fabric.api import env, local, run, require, cd
from fabric.operations import _prefix_commands, _prefix_env_vars
from fabric.contrib.files import *
from fabric.colors import *

import inspect
import util
import sys

class network(object):

        # Turn to 'True' to enable current module
        enabled = True
        # Dict for functions calling
        first = {}
    
        def __init__(self):
            puts("Init <"+__name__+">")

        def netcat(self,rhost,rport,timeout=10):
                """
                Test <rhost> <rport> tcp connectivity from host using nc with  [timeout] default 10s
                """
                if util._is_host_up(env.host, int(env.port)) is False:
                    return
                HOSTNAME = env.host
                nc = run("nc -v -z -w "+str(timeout)+ " " + rhost + " " + rport + " 2>&1")
                if nc.succeeded:
                    nc_fields = nc.split()
                    nc_result = nc_fields[len(nc_fields)-1]
                    print HOSTNAME + "|" + rhost + "|" + rport + "|" + green(nc_result.title())
                else:
                    #print "Debug nc : " + nc
                    m = re.search('(?<=failed..).+', nc)
                    if m is None:
                        nc_result = "Failed: "+nc
                    else:
                        nc_result = m.group(0)
                    print HOSTNAME + "|" + rhost + "|" + rport + "|" + red(nc_result,True)
                return nc.succeeded


        def check_tcp(self,rhost,rport,timeout=5):
                """
                Test <rhost> <rport> tcp connectivity from host using python
                with [timeout] (default: 5s)
                """
                if util._is_host_up(env.host, int(env.port)) is False:
                        return False
                HOSTNAME = env.host
                puts("Proxy %s port %s " % (rhost,rport))
                tcp_check = util._run("python -c \"import socket;sock=socket.socket();sock.settimeout("+str(timeout)+");sock.connect(('"+rhost+"',"+rport+"));sock.close()\"")
                if tcp_check.succeeded:
                        print HOSTNAME + "|" + rhost + "|" + rport + "|" + green("Success")
                else:
                        print HOSTNAME + "|" + rhost + "|" + rport + "|" + red("Failed",True)
                return tcp_check.succeeded

        def vco_priv_ip_reservation(self,vco_uri='vco.local',workflow='7874513b-8dac-44f3-a325-f61affeb171e', oc=None, domain='sys', label=None):
            '''
            Ask a private ip to Infoblox via VCO , the response is asyncron
            :param vco_uri: VCO URI (otvmi162s.priv.atos.fr for sandbox)
            :param workflow: the workflow vco for reserve a private ip
            :param oc: object code in VCO
            :param domain: sys (default) or data
            :param label: network : ip/cidr or ip/cidr|comment in VCO
            :return: REST status
            '''

            from getpass import getuser, getpass
            from json import dumps
            import urllib2, base64, ssl

            headers = {
                'content-type': 'application/json; charset=utf8',
                'accept': 'application/json; charset=utf8',
                'X-Requested-With': 'urllib2'
            }
            uri = 'https://{0}:8281/vco/api/workflows/{1}/executions/'.format(vco_uri,workflow)

            backup_pool_size = env.pool_size

            #preserve VCO's server
            if env.pool_size > 10 :
                env.pool_size = 10

            if oc is not None and label is not None :
                user = getuser()
                if env.password is None :
                    env.password = getpass('VCO server {0} asked you:\nPlease enter the VCO password for user {1}: '.format(blue(vco_uri), yellow(user)))

                #the form
                form_1click = {u'parameters': [
                    {u'name': u'objectCode1', u'value': {u'string': {u'value': oc}}, u'type': u'string', u'description': u'object code of network : extensible attribute on infoblox'},
                    {u'name': u'ipType', u'value': {u'string': {u'value': u'Server'}}, u'type': u'string', u'description': u'Service Server'},
                    {u'name': u'domain', u'value': {u'string': {u'value': domain}}, u'type': u'string', u'description': u'sys svc data'},
                    {u'name': u'hostname', u'value': {u'string': {u'value': env.host}}, u'type': u'string', u'description': u'Name of the host'},
                    {u'name': u'zone1', u'value': {u'string': {u'value': label}}, u'type': u'string', u'description': u'network : ip/cidr or ip/cidr|comment'},
                    {u'name': u'needDataIP', u'value': {u'boolean': {u'value': False}}, u'type': u'boolean', u'description': u'yes or no if you want ip data'},
                    {u'name': u'_comment', u'value': {u'string': {u'value': u'reserved by {0} @ via REST API'.format(user)}}, u'type': u'string', u'description': u'Comment about the host'}
                ]}

                payload = dumps(form_1click, sort_keys=True, indent=4, separators=(',', ': '))
                request = urllib2.Request(uri,data=payload,headers=headers)
                base64string = base64.encodestring('{0}:{1}'.format(user, env.password)).replace('\n', '')
                request.add_header('Authorization', 'Basic {0}'.format(base64string))

                try:
                    response = urllib2.urlopen(request)
                except urllib2.HTTPError as e:
                    print '{0} in {1} : Exception {2} => {3}'.format(env.host, label, type(e).__name__, e)
                else:
                    if 'response' in locals():
                        result = 'In progress' if response.code == 202 else 'Error {0}'.format(response.code)
                        print '{0}|status : {1}'.format(env.host, result)
                        response.close()

            env.pool_size = backup_pool_size

