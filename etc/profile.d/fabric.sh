if [ ! -e ~/.fabricrc ]
then
	export FABFILE_PATH="/usr/lib/fabric/fabfile.py"
	alias fab='/usr/bin/fab --hide=everything --show=stdout --linewise -f $FABFILE_PATH'
	alias fabdebug='/usr/bin/fab --show=everything,debug,status --linewise -f $FABFILE_PATH'
	export PATH=$PATH:/usr/lib/fabric:/usr/lib/fabric/bin
fi

