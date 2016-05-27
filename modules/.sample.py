from fabric.api import *
from fabric.contrib.files import *
from fabric.colors import *
from fabric.state import *

import util
import sys
import os
import re

# class must be named like the file module without suffix
class sample(object):

    # Turn to 'True' to enable current module
    enabled = True
    # Dict for functions calling
    first = {}

    # run options
    needSudo = False

    def __init__(self):
        puts("Init <"+__name__+">")

    def _fabrun(self,*args):
        if self.needSudo:
            return util._sudo(*args)
        else:
            return util._run(*args)


    def sampleTask(self,param1,param2=None,param3='value'):
        """
        Sample Task with :
            - mandatory <param1>
            - non mandatory [param2] , [param3]
        """
        print red("Sample red output")
        return self._fabrun("hostname").succeeded
