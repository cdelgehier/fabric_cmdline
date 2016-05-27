from fabric.api import env, local, run, require, cd
from fabric.operations import _prefix_commands, _prefix_env_vars
from fabric.contrib.files import *
from fabric.colors import *

import inspect
import util
import sys


class filer(object):

    # Turn to 'True' to enable current module
    enabled = True
    # Dict for functions calling
    first = {}

    def __init__(self):
        puts("Init <"+__name__+">")

    def _setup(self):
        env.shell = "sh -c"
        env.use_shell = False
        env.always_use_pty = False
        env.parallel = False

    def netapp_filer_uptime(self):
        """
        Show uptime of the host
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        HOSTNAME = run('hostname',False,False)
        disconnect_all()
        uptime = run('uptime').split(", ")

        i = 0
        sys.stdout.write(HOSTNAME)
        for col in uptime:
            if i != 1:
                sys.stdout.write("|" + col)
            else:
                j = 0
                col_s = col.split()
                for col_ in col_s:
                    if j != 1:
                        sys.stdout.write(" " + col_)
                    else:
                        sys.stdout.write("|" + col_)
                    j += 1
            i += 1
        sys.stdout.write("\n")
        disconnect_all()


    def netapp_filer_version(self):
        """
        Show the OS filer version
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
                 return False
        HOSTNAME = run('hostname')
        disconnect_all()
        if not self.first.has_key(util._func_name()):
            self.first[util._func_name()] = True
            print "HOSTNAME|OS_VERSION"
        print HOSTNAME + '|' + run('version')
        disconnect_all()

    def netapp_filer_model(self):
        """
        show the filer model
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
             return False
        HOSTNAME = run('hostname')
        disconnect_all()
        sysconfig = run('sysconfig -v')
        disconnect_all()
        sysconfig_lines = sysconfig.splitlines()

        model_line = False

        for sysconfig_line in sysconfig_lines:
            if not self.first.has_key(util._func_name()):
                self.first[util._func_name()] = True
                print "HOSTNAME|MODEL"
            if model_line:
                print HOSTNAME + '|' + sysconfig_line.split(":")[1].strip()
                model_line = False
            if sysconfig_line.count("System Board"):
                model_line = True


    def netapp_filer_disk_show(self,output=True):
        """
        show disk information on the filer
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        HOSTNAME = run('hostname')
        disconnect_all()
        disks = run('disk show')
        disconnect_all()
        disks_dict = {}
        disk_list= []
        for disk in disks.splitlines():
            if re.match(".*\-\-.*",disk):
                continue
            #   DISK       OWNER                    POOL   SERIAL NUMBER         HOME                    DR HOME
            if re.match(".*SERIAL NUMBER.*",disk):
                header_list= []
                disk = re.sub("(\w)\s(\w)","\\1_\\2",disk)
                disk = re.sub("\s+","|",disk)
                disk = re.sub("\|$","",disk)
                if not self.first.has_key(util._func_name()):
                    self.first[util._func_name()] = True
                    if eval(str(output).capitalize()):
                        print "HOSTNAME|"+disk
                header_list = disk.split("|")
            else:
                disk = re.sub("\s+","|",disk)
                disk = re.sub("\|\("," (",disk)
                disk = re.sub("\|$","",disk)
                if eval(str(output).capitalize()):
                    print HOSTNAME+"|"+disk
                else:
                    disk_list = disk.split("|")
                    if not disks_dict.has_key(disk_list[0]):
                        disks_dict[disk_list[0]]={}
                    for index, value in enumerate(disk_list):
                        disks_dict[disk_list[0]][header_list[index]]=value
        return disks_dict


    def netapp_filer_aggregate_size(self,aggr=None,unit='h',color=True):
        """
        show aggregates information on the filer
        on a specific aggregate [aggr] with [unit] option (default -h)
        with [color] ioutput default True
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        HOSTNAME = run('hostname')
        HOST_HEADER = HOSTNAME
        disconnect_all()
        if aggr is None:
            df = run('df -A'+unit)
        else:
            df = run('df -A'+unit+' '+aggr)
        disconnect_all()
        for l in df.splitlines():
            # Aggregate                total       used      avail capacity
            if re.match("^Aggregate.*",l):
                if not self.first.has_key(util._func_name()):
                    self.first[util._func_name()] = True
                    #l = re.sub("(\w)\s(\w)","\\1_\\2",l)
                    HOST_HEADER = "HOSTNAME"

                else:
                    continue
            else:
                HOST_HEADER = HOSTNAME
            l = re.sub("\s+","|",l)
            l = re.sub("\|$","",l)
            if eval(str(color).capitalize()):
                l_list = l.split("|")
                print HOST_HEADER+"|"+magenta(l_list[0])+"|"+blue(l_list[1])+"|"+red(l_list[2])+"|"+green(l_list[3])+"|"+yellow(l_list[4])
            else:
                print HOST_HEADER+"|"+l


    def netapp_filer_volume_size(self,vol=None,unit='h',color=True):
        """
        show volumes space information on the filer
        on a specific volume [vol],with [unit] option (default -h)
        with [color] ioutput default True
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        HOSTNAME = run('hostname')
        disconnect_all()
        if vol is None:
            df = run('df -'+unit)
        else:
            df = run('df -'+unit+' '+vol)
        disconnect_all()
        for l in df.splitlines():
            # Filesystem               total       used      avail capacity  Mounted on
            if re.match("^Filesystem.*",l):
                if not self.first.has_key(util._func_name()):
                    self.first[util._func_name()] = True
                    l = re.sub("(Mounted) (on)","\\1_\\2",l)
                    l = re.sub("[\t\s]+","|",l)
                    HOST_HEADER = "HOSTNAME"
                else:
                    continue
            else:
                HOST_HEADER = HOSTNAME

                l = re.sub("%[\t\s]+/","%|/",l)
                l = re.sub("%[\t\s]+","%|/",l)
                l = re.sub("([\w/])[\s\t]+([\d\-])","\\1|\\2",l)
            l = re.sub("\|$","",l)
            if eval(str(color).capitalize()):
                l_list = l.split("|")
                print HOST_HEADER+"|"+magenta(l_list[0])+"|"+blue(l_list[1])+"|"+red(l_list[2])+"|"+green(l_list[3])+"|"+yellow(l_list[4])+"|"+cyan(l_list[5])
            else:
                print HOST_HEADER+"|"+l


    def netapp_filer_check_zeroing(self):
        """
        check if disks are being zeroed or must be zeroed on the filer
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        HOSTNAME = run('hostname')
        disconnect_all()
        sysconfig = run('sysconfig -r')
        disconnect_all()
        for l in sysconfig.splitlines():
            #print l
            if re.match("^(.*)\s+\(creating\,.*",l):
                pool_name = re.sub("^(.*)\s+\(creating\,.*","\\1",l)
            if re.match("^(.*)\s+disks($|\s+\(.*)",l):
                pool_name = re.sub("^(.*)\s+disks($|\s+\(.*)","\\1",l)
            if re.match("^\s*RAID\s+Disk\s+Device\s+.*",l):
                header = l
                header = re.sub("(\w)\s+([^\s])","\\1|\\2",l)
            if re.match("^.*\((not\s+zeroed\)|zeroing\,).*",l):
                l = re.sub("([\w/])\s+(\d)","\\1|\\2",l)
                if not self.first.has_key(util._func_name()):
                    self.first[util._func_name()] = True
                    print "HOSTNAME|Pool|"+header
                print HOSTNAME+"|"+pool_name+"|"+l


    def netapp_filer_disk_repartition(self):
        """
        display the disks repartition by aggregat
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        HOSTNAME = run('hostname')
        disconnect_all()
        sysconfig = run('sysconfig -r')
        disconnect_all()
        disks = self.netapp_filer_disk_show(output=False)
        volumes = self.netapp_filer_volume_status(output=False)
        aggr_disk = {}
        aggr = None
        disks_output = False
        for l in sysconfig.splitlines():
            """
            Aggregate aggr2 (online, raid_dp) (block checksums)
            Plex /aggr2/plex0 (online, normal, active)
            RAID group /aggr2/plex0/rg0 (normal, block checksums)

                  RAID Disk Device          HA  SHELF BAY CHAN Pool Type  RPM  Used (MB/blks)    Phys (MB/blks)
                  --------- ------          ------------- ---- ---- ---- ----- --------------    --------------
                  dparity   3d.04.0         3d    4   0   SA:A   0  BSAS  7200 1695466/3472315904 1695759/3472914816
                  parity    3d.04.1         3d    4   1   SA:A   0  BSAS  7200 1695466/3472315904 1695759/3472914816

            Broken disks

            RAID Disk       Device          HA  SHELF BAY CHAN Pool Type  RPM  Used (MB/blks)    Phys (MB/blks)
            ---------       ------          ------------- ---- ---- ---- ----- --------------    --------------
            bad label       0a.03.6         0a    3   6   SA:B   0  BSAS  7200 847555/1735794176 847884/1736466816
            bad label       0a.03.7         0a    3   7   SA:B   0  BSAS  7200 847555/1735794176 847884/1736466816
            bad label       0a.03.8         0a    3   8   SA:B   0  BSAS  7200 847555/1735794176 847884/1736466816
            bad label       0a.03.12        0a    3   12  SA:B   0  BSAS  7200 847555/1735794176 847884/1736466816
            bad label       0a.03.13        0a    3   13  SA:B   0  BSAS  7200 847555/1735794176 847884/1736466816
            bad label       0a.03.14        0a    3   14  SA:B   0  BSAS  7200 847555/1735794176 847884/1736466816
            bad label       0a.03.15        0a    3   15  SA:B   0  BSAS  7200 847555/1735794176 847884/1736466816
            bad label       0a.03.16        0a    3   16  SA:B   0  BSAS  7200 847555/1735794176 847884/1736466816

            Partner disks

            RAID Disk       Device          HA  SHELF BAY CHAN Pool Type  RPM  Used (MB/blks)    Phys (MB/blks)
            ---------       ------          ------------- ---- ---- ---- ----- --------------    --------------
            partner         0b.05.2         0b    5   2   SA:A   0   SAS 15000 0/0               560208/1147307688
            partner         0b.05.7         0b    5   7   SA:A   0   SAS 15000 0/0               560208/1147307688
            """
            if re.match("^\s+RAID\s+group\s+([^\s]+)\s+",l):
                disks_output = False
                aggr = re.sub("^\s+RAID\s+group\s+([^\s]+)\s+","\\1",l)
                aggr = re.sub("\(.*$","",aggr)
                continue
            if re.match("^(Pool\d+)\s+spare\s+disks",l):
                aggr = "Spare"+re.sub("^(Pool\d+)\s+spare\s+disks","\\1",l)
                continue
            if re.match("^Spare\s+disks\s+for\s+block\s+checksum",l):
                disks_output = True
                continue
            if re.match("^([^\s]+)\s+disks",l):
                aggr = re.sub("^([^\s]+)\s+disks","\\1",l)
                continue
            if re.match("^(\s+)?\-\-\-.*",l):
                disks_output = True
                continue
            if len(l) == 0:
                disks_output = False
                continue
            if disks_output:
                if re.search("bad\s+label",l):
                    l = re.sub("bad\s+label","bad_label",l)
                if re.search("\(not zeroed\)",l):
                    l = re.sub("\(not[\s\t]+zeroed\)","not_zeroed",l)
                if re.search("\(zeroing\,",l):
                    l = re.sub("\(zeroing\,","zeroing",l)
                disk_info = l.split()
                puts(disk_info)
                if not aggr_disk.has_key(disk_info[1]):
                    aggr_disk[disk_info[1]] = {}
                if not aggr_disk[disk_info[1]].has_key(aggr):
                    if disks.has_key(disk_info[1]):
                        aggr_disk[disk_info[1]][aggr] = disks[disk_info[1]]['SERIAL_NUMBER']+"|"+disk_info[7]+"|"+disk_info[8]+"|"+disk_info[10]
                        if len(disk_info) >= 12:
                            aggr_disk[disk_info[1]][aggr]+="|"+disk_info[11]
                    else:
                        aggr_disk[disk_info[1]][aggr] = re.sub("\s+","|",l)
        puts(aggr_disk)
        for d in sorted(aggr_disk, key=aggr_disk.get, reverse=True):
            aggrs = []
            vols =  []
            for aggr in sorted(aggr_disk[d].keys()):
                for v in volumes.keys():
                    if aggr in volumes[v]['aggregate']:
                        vols.append(v)
                aggrs.append(aggr)
            if not self.first.has_key(util._func_name()):
                self.first[util._func_name()] = True
                print "HOSTNAME|disk_id|disk_serial|disk_type|disk_rpm|disk_size Phys (MB/blks)|aggregate_name/pool_name|attached_volumes"
            if re.search("\|(not_zeroed|zeroing)$",aggr_disk[d][aggr]):
                zero_type = re.sub(".*\|(not_zeroed|zeroing)$","\\1",aggr_disk[d][aggr])
                aggr_disk[d][aggr] = re.sub("\|(not_zeroed|zeroing)$","",aggr_disk[d][aggr])
                print HOSTNAME+"|"+d+"|"+aggr_disk[d][aggr]+"|"+",".join(aggrs)+"|"+",".join(sorted(vols))+zero_type
            else:
                print HOSTNAME+"|"+d+"|"+aggr_disk[d][aggr]+"|"+",".join(aggrs)+"|"+",".join(sorted(vols))


    def netapp_filer_volume_status(self,vol=None,output=True):
        """
        display or not with [output] default True, filer volumes informations
        on a specific volume [vol]
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        HOSTNAME = run('hostname')
        disconnect_all()
        if vol is None:
            vol_status = run('vol status -v')
        else:
            vol_status = run('vol status -v '+vol)
        disconnect_all()

        volumes = {}
        volume_output = False
        volume_info = []

        raid_group = False
        """
        Volume State           Status                Options
            worm_temp online          raid_dp, flex         nosnap=off, nosnapdir=off, minra=off,
                                64-bit                no_atime_update=off, nvfail=off, 
                                                      ignore_inconsistent=off, snapmirrored=off, 
                                                      create_ucode=on, convert_ucode=off, 
                                                      maxdirsize=73400, schedsnapname=ordinal, 
                                                      fs_size_fixed=off, guarantee=none, 
                                                      svo_enable=off, svo_checksum=off, 
                                                      svo_allow_rman=off, svo_reject_errors=off, 
                                                      no_i2p=off, fractional_reserve=0, extent=off, 
                                                      try_first=volume_grow, read_realloc=off, 
                                                      snapshot_clone_dependency=off, 
                                                      dlog_hole_reserve=off, nbu_archival_snap=off
                         Volume UUID: f6428f28-7523-11e2-84d0-123478563412
                Containing aggregate: 'aggr0'

                Plex /aggr0/plex0: online, normal, active
                    RAID group /aggr0/plex0/rg0: normal, block checksums

            Snapshot autodelete settings for worm_temp:
                                        state=off
                                        commitment=try
                                        trigger=volume
                                        target_free_space=20%
                                        delete_order=oldest_first
                                        defer_delete=user_created
                                        prefix=(not specified)
                                        destroy_list=none 
            Volume autosize settings:
                                mode=off
            Hybrid Cache:
                    Eligibility=read-write
        """

        for l in vol_status.splitlines():
            if re.match("^\s*(Volume[\t\s]+State[\t\s]+.*|[\t\s]+Eligibility=|state=.*)",l,re.MULTILINE):
                volume_info = []
                volume_output = True
                raid_group=False
                volume_name=""
                continue
            if re.match("^[\t\s]+Volume\s+UUID:\s+",l):
                volume_output = False
                continue
            if volume_output:
                volume_info=volume_info+l.split()
            if re.match("^\s+RAID\s+group\s+([^\:]+):\s+",l):
                #print volume_info
                if not raid_group:
                    volume_name = volume_info.pop(0) # volume name
                    volumes[volume_name] = {}
                    volumes[volume_name]['options'] = volume_info # volume options
                    volumes[volume_name]['status'] = volume_info.pop(0) # status online / offline
                    volumes[volume_name]['aggregate'] = re.sub("^\s+RAID\s+group\s+([^\:]+):\s+.*","\\1",l)
                    volumes[volume_name]['aggregate'] = []
                    volumes[volume_name]['aggregate'].append(re.sub("^\s+RAID\s+group\s+([^\:]+):\s+.*","\\1",l))
                else:
                    volumes[volume_name]['aggregate'].append(re.sub("^\s+RAID\s+group\s+([^\:]+):\s+.*","\\1",l))
                raid_group=True
            if re.match("(^[\s\t]+$|^$)",l):
                raid_group=False

        if eval(str(output).capitalize()):
            if not self.first.has_key(util._func_name()):
                self.first[util._func_name()] = True
                print "HOSTNAME|Volume_name|Aggregate(s)/RAID_Group(s)|Volume_status|Provisionning_Type|RAID_Type|Volume_Type|Volume_Arch"
            for vol in sorted(volumes.keys()):
                regex=re.compile(r"^guarantee\=(.*)$")
                guarantee_type = [m.group(1) for l in volumes[vol]['options'] for m in [regex.search(l)] if m]
                # 64-bit
                regex=re.compile(r"^(\d{2}\-bit).*$")
                bits = [m.group(0) for l in volumes[vol]['options'] for m in [regex.search(l)] if m]
                if len(bits) == 0:
                    bits="not_detected"
                print HOSTNAME+"|"+vol+"|"+",".join(sorted(volumes[vol]['aggregate']))+"|"+volumes[vol]['status']+"|"+re.sub(',$','',''.join(guarantee_type))+"|"+re.sub(',$','',volumes[vol]['options'][0])+"|"+re.sub(',$','',volumes[vol]['options'][1])+"|"+''.join(bits)
                #print volumes[vol]['options']
        else:
            return volumes


    def netapp_filer_snapmirror_status(self):
        """
        Show status of the snapmirror process on the filer process
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        HOSTNAME = run('hostname')
        disconnect_all()
        if not self.first.has_key(util._func_name()):
            self.first[util._func_name()] = True
            print "HOSTNAME|Status|Source|Destination|State|Lag|Status"
        snapmirror = run('snapmirror status')
        disconnect_all()
        status = ""
        lines = []
        for l in snapmirror.splitlines():
            if re.match("Snapmirror\s+is\s+(.*)$",l):
                status = re.sub("Snapmirror\s+is\s+(.*)$","\\1",l)
            elif not re.match("^Source\s+",l):
                lines.append(l)
        status=re.sub("\.","",status)
        if re.match("^on$",status):
            for l in lines:
                print HOSTNAME+"|"+status+"|"+re.sub("\s+","|",l)


    def netapp_filer_cluster_status(self):
        """
        Show status of the cluster on the filer
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        HOSTNAME = run('hostname')
        disconnect_all()
        if not self.first.has_key(util._func_name()):
            self.first[util._func_name()] = True
            print "HOSTNAME|Status|Source|Destination|State|Lag|Status"
        cf = run('cf status')
        disconnect_all()
        for l in cf.splitlines():
            print HOSTNAME+"|"+l


    def netapp_filer_exec_cmd(self,cmd):
        """
        Execute <cmd> command on the filer
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        HOSTNAME = run('hostname')
        disconnect_all()
        if not self.first.has_key(util._func_name()):
            self.first[util._func_name()] = True
            print "HOSTNAME|Command_Result"
        cf = run(cmd)
        disconnect_all()
        for l in cf.splitlines():
            print HOSTNAME+"|"+l

    def netapp_filer_storage_show_fault(self):
        """
        Display result of 'storage show fault' command on the filer
        """
        self._setup()
        if util._is_host_up(env.host, int(env.port)) is False:
                return False
        HOSTNAME = run('hostname')
        disconnect_all()
        if not self.first.has_key(util._func_name()):
            self.first[util._func_name()] = True
            print "HOSTNAME|FAULTS"
        cf = run('storage show fault')
        disconnect_all()
        for l in cf.splitlines():
            print HOSTNAME+"|"+l

