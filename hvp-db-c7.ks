# Kickstart file for virtual database server
# Note: minimum amount of RAM successfully tested for installation: 2048 MiB from network - 1024 MiB from local media

# Install with commandline (see below for comments):
# TODO: check each and every custom "hvp_" parameter below for overlap with default dracut/anaconda parameters and convert to using those instead
# nomodeset elevator=deadline inst.ks=https://dangerous.ovirt.life/hvp-repos/el7/ks/hvp-db-c7.ks
# Note: DHCP is assumed to be available on one and only one network (the mgmt one, which will be autodetected, albeit with a noticeable delay) otherwise the ip=nicname:dhcp option must be added, where nicname is the name of the network interface to be used for installation (eg: ens32)
# Note: to force custom/fixed nic names add ifname=netN:AA:BB:CC:DD:EE:FF where netN is the desired nic name and AA:BB:CC:DD:EE:FF is the MAC address of the corresponding network interface
# Note: alternatively, to force legacy nic names (ethN), add biosdevname=0 net.ifnames=0
# Note: alternatively burn this kickstart into your DVD image and append to default commandline:
# elevator=deadline inst.ks=cdrom:/dev/cdrom:/ks/ks.cfg
# Note: to access the running installation by SSH (beware of publishing the access informations specified with the sshpw directive below) add the option inst.sshd
# Note: to force static nic name-to-MAC mapping add the option hvp_nicmacfix
# Note: to force custom host naming add hvp_myname=myhostname where myhostname is the unqualified (ie without domain name part) hostname
# Note: to force custom addressing add hvp_{mgmt,lan}=x.x.x.x/yy where x.x.x.x may either be the machine IP or the network address on the given network and yy is the prefix on the given network
# Note: to force custom IPs add hvp_{mgmt,lan}_my_ip=t.t.t.t where t.t.t.t is the chosen IP on the given network
# Note: to force custom network MTU add hvp_{mgmt,lan}_mtu=zzzz where zzzz is the MTU value
# Note: to force custom network domain naming add hvp_{mgmt,lan}_domainname=mynet.name where mynet.name is the domain name
# Note: to force custom AD subdomain naming add hvp_ad_subdomainname=myprefix where myprefix is the subdomain name
# Note: to force custom domain action add hvp_joindomain=bool where bool is either "true" (join an AD domain) or "false" (do not join an AD domain)
# Note: to force custom database type add hvp_dbtype=dddd where dddd is the database type (either postgresql, mysql, firebird or sqlserver)
# Note: to force custom nameserver IP add hvp_nameserver=w.w.w.w where w.w.w.w is the nameserver IP
# Note: to force custom gateway IP add hvp_gateway=n.n.n.n where n.n.n.n is the gateway IP
# Note: to force custom root password add hvp_rootpwd=mysecret where mysecret is the root user password
# Note: to force custom admin username add hvp_adminname=myadmin where myadmin is the admin username
# Note: to force custom admin password add hvp_adminpwd=myothersecret where myothersecret is the admin user password
# Note: to force custom AD further admin username add hvp_winadminname=mywinadmin where mywinadmin is the further AD admin username
# Note: to force custom AD further admin password add hvp_winadminpwd=mywinothersecret where mywinothersecret is the further AD admin user password
# Note: to force custom keyboard layout add hvp_kblayout=cc where cc is the country code
# Note: to force custom local timezone add hvp_timezone=VV where VV is the timezone specification
# Note: the default behaviour does not register fixed nic name-to-MAC mapping
# Note: the default host naming uses the "My Little Pony" character name bigmcintosh
# Note: the default addressing on connected networks is assumed to be 172.20.{10,12}.0/24 on {mgmt,lan}
# Note: the default MTU is assumed to be 1500 on {mgmt,lan}
# Note: the default machine IPs are assumed to be the 230th IPs available (network address + 230) on each connected network
# Note: the default domain names are assumed to be {mgmt,lan}.private
# Note: the default AD subdomain name is assumed to be ad
# Note: the default domain action is "false" (do not join an AD domain)
# Note: the default database type is postgresql
# Note: the default nameserver IP is assumed to be 8.8.8.8
# Note: the default gateway IP is assumed to be equal to the test IP on the mgmt network
# Note: the default root user password is HVP_dem0
# Note: the default admin username is hvpadmin
# Note: the default admin user password is HVP_dem0
# Note: the default AD further admin username is the same as the admin username with the string "ad" prefixed
# Note: the default AD further admin user password is HVP_dem0
# Note: the default keyboard layout is us
# Note: the default local timezone is UTC
# Note: to work around a known kernel commandline length limitation, all hvp_* parameters above can be omitted and proper default values (overriding the hardcoded ones) can be placed in Bash-syntax variables-definition files placed alongside the kickstart file - the name of the files retrieved and sourced (in the exact order) is: hvp_parameters.sh hvp_parameters_db.sh hvp_parameters_hh:hh:hh:hh:hh:hh.sh (where hh:hh:hh:hh:hh:hh is the MAC address of the nic used to retrieve the kickstart file)

# Perform an installation (as opposed to an "upgrade")
install
# Avoid asking interactive confirmation for unsupported hardware
unsupported_hardware
# Uncomment the line below to receive debug messages on a syslog server
# logging --host=192.168.229.1 --level=info
# Use text mode (as opposed to "cmdline", "graphical" or "vnc")
text
# Uncomment the line below to automatically reboot at the end of installation
# (must be sure that system does not try to loop-install again and again)
# Note: this is needed for proper installation automation by means of virt-install
reboot

# Installation source configuration dynamically generated in pre section below
%include /tmp/full-installsource

# System localization configuration dynamically generated in pre section below
%include /tmp/full-localization

# Network interface configuration dynamically generated in pre section below
%include /tmp/full-network

# Control "First Boot" interactive tool execution
# TODO: the following seems to be started anyway even if disabled manually in post section below - see https://bugzilla.redhat.com/show_bug.cgi?id=1213114
firstboot --disable
# EULA is implicitly accepted
eula --agreed

# Do not configure X Windows (as opposed to an "xconfig" line)
skipx
# Fail safe X Windows configuration
#xconfig --defaultdesktop=GNOME --startxonboot
# Control automatically enabled/disabled services for OS-supplied packages
services --disabled="mdmonitor,multipathd,lm_sensors,iscsid,iscsiuio,fcoe,fcoe-target,lldpad,iptables,ip6tables,ksm,ksmtuned,tuned,libvirtd,libvirt-guests,qpidd,tog-pegasus,cups,portreserve,postfix,nfs,nfs-lock,rpcbind,rpc-idmapd,rpc-gssd,rpc-svcgssd,pcscd,avahi-daemon,network,bluetooth,gpm,vsftpd,vncserver,slapd,dnsmasq,ipmi,ipmievd,nscd,psacct,rdisc,rwhod,saslauthd,smb,nmb,snmptrapd,svnserve,winbind,oddjobd,autofs,wpa_supplicant,kdump,iprdump,iprinit,iprupdate,snmpd" --enabled="firewalld,NetworkManager,NetworkManager-wait-online,ntpdate,ntpd"

# Users configuration dynamically generated in pre section below
%include /tmp/full-users

# Firewall (firewalld) enabled
# Note: further configuration performed in post section below
firewall --enabled --ssh
# Configure authentication mode
authconfig --enableshadow --passalgo=sha512
# Leave SELinux on (default will be "targeted" mode)
selinux --enforcing
# Disable kdump
%addon com_redhat_kdump --disable
%end

# Disk configuration dynamically generated in pre section below
%include /tmp/full-disk

# Explicitly list provided repositories
# Note: no additional repos setup - further packages/updates installed manually in post section
#repo --name="CentOS"  --baseurl=cdrom:sr0 --cost=100
#repo --name="HVP-mirror" --baseurl=https://dangerous.ovirt.life/hvp-repos/el7/centos

# Packages list - package groups are preceded by an "@" sign - excluded packages by an "-" sign
# Note: some virtualization technologies (Parallels, VirtualBox) require gcc, kernel-devel and dkms (from external repo) packages
%packages
@system-admin-tools
@console-internet
@core
@base
@large-systems
@performance
-perl-homedir
# Note: the following is needed since ifconfig/route is still required by some software
net-tools
policycoreutils-python
policycoreutils-newrole
mcstrans
stunnel
-xinetd
-ntp
# Note: the following seems to be missing by default and we explicitly include it to allow efficient updates
deltarpm
rdate
symlinks
dos2unix
unix2dos
screen
minicom
telnet
tree
audit
iptraf
iptstate
device-mapper-multipath
lm_sensors
OpenIPMI
ipmitool
hdparm
sdparm
lsscsi
xfsprogs
xfsdump
nss-tools
patch
expect
ksh
ncompress
libnl
redhat-lsb
-zsh
-nmap
-xdelta
-bluez
-bluez-libs
-fetchmail
-mutt
-pam_pkcs11
-coolkey
-finger
-conman
%end

# Pre-installation script (run with bash from stage2.img immediately after parsing this kickstart file)
%pre
( # Run the entire pre section as a subshell for logging.

# Discover exact pre-stage environment
echo "PRE env" >> /tmp/pre.out
env >> /tmp/pre.out
echo "PRE devs" >> /tmp/pre.out
ls -l /dev/* >> /tmp/pre.out
echo "PRE block" >> /tmp/pre.out
ls -l /sys/block/* >> /tmp/pre.out
echo "PRE mounts" >> /tmp/pre.out
df -h >> /tmp/pre.out
echo "PRE progs" >> /tmp/pre.out
for pathdir in $(echo "${PATH}" | sed -e 's/:/ /'); do
	if [ -d "${pathdir}" ]; then
		ls "${pathdir}"/* >> /tmp/pre.out
	fi
done

# A simple regex matching IP addresses
IPregex='[0-9]*[.][0-9]*[.][0-9]*[.][0-9]*'

# A general IP add/subtract function to allow classless subnets +/- offsets
# Note: derived from https://stackoverflow.com/questions/33056385/increment-ip-address-in-a-shell-script
# TODO: add support for IPv6
ipmat() {
	local given_ip=$1
	local given_diff=$2
	local given_op=$3
	# TODO: perform better checking on parameters
	if [ -z "${given_ip}" -o -z "${given_diff}" -o -z "${given_op}" ]; then
		echo ""
		return 255
	fi
	local given_ip_hex=$(printf '%.2X%.2X%.2X%.2X' $(echo "${given_ip}" | sed -e 's/\./ /g'))
	local given_diff_hex=$(printf '%.8X' "${given_diff}")
	local result_ip_hex=$(printf '%.8X' $(echo $(( 0x${given_ip_hex} ${given_op} 0x${given_diff_hex} ))))
	local result_ip=$(printf '%d.%d.%d.%d' $(echo "${result_ip_hex}" | sed -r 's/(..)/0x\1 /g'))
	echo "${result_ip}"
	return 0
}

# Define all default network data
unset nicmacfix
unset network
unset netmask
unset network_base
unset mtu
unset domain_name
unset ad_subdomain_prefix
unset domain_join
unset dbtype
unset reverse_domain_name
unset test_ip
unset test_ip_offset
unset my_ip_offset
unset my_name
unset my_nameserver
unset my_gateway
unset root_password
unset admin_username
unset admin_password
unset winadmin_username
unset winadmin_password
unset keyboard_layout
unset local_timezone

# Hardcoded defaults

nicmacfix="false"

dbtype="postgresql"

# Note: IP offsets below get used to automatically derive IP addresses
# Note: no need to allow offset overriding from commandline if the IP address itself can be specified

# Note: the following can be overridden from commandline
test_ip_offset="1"

my_ip_offset="230"

declare -A network netmask network_base mtu
network['mgmt']="172.20.10.0"
netmask['mgmt']="255.255.255.0"
network_base['mgmt']="172.20.10"
mtu['mgmt']="1500"
network['lan']="172.20.12.0"
netmask['lan']="255.255.255.0"
network_base['lan']="172.20.12"
mtu['lan']="1500"

declare -A domain_name
domain_name['mgmt']="mgmt.private"
domain_name['lan']="lan.private"

ad_subdomain_prefix="ad"

domain_join="false"

declare -A reverse_domain_name
reverse_domain_name['mgmt']="10.20.172.in-addr.arpa"
reverse_domain_name['lan']="12.20.172.in-addr.arpa"

declare -A test_ip
# Note: default values for test_ip derived below - defined here to allow loading as configuration parameters

my_nameserver="8.8.8.8"

my_name="bigmcintosh"

# Note: passwords must meet the DB complexity requirements
root_password="HVP_dem0"
admin_username="hvpadmin"
admin_password="HVP_dem0"
winadmin_password="HVP_dem0"
keyboard_layout="us"
local_timezone="UTC"

# Detect any configuration fragments and load them into the pre environment
# Note: BIOS based devices, file and DHCP methods are unsupported
mkdir /tmp/kscfg-pre
mkdir /tmp/kscfg-pre/mnt
ks_source="$(cat /proc/cmdline | sed -e 's/^.*\s*inst\.ks=\(\S*\)\s*.*$/\1/')"
if [ -z "${ks_source}" ]; then
	echo "Unable to determine Kickstart source - skipping configuration fragments retrieval" 1>&2
else
	ks_dev=""
	if echo "${ks_source}" | grep -q '^floppy' ; then
		# Note: hardcoded device name for floppy disk
		# Note: hardcoded filesystem type on floppy disk - assuming VFAT
		ks_dev="/dev/fd0"
		ks_fstype="vfat"
		ks_fsopt="ro"
		ks_path="$(echo ${ks_source} | awk -F: '{print $2}')"
		if [ -z "${ks_path}" ]; then
			ks_path="/ks.cfg"
		fi
		ks_dir="$(echo ${ks_path} | sed 's%/[^/]*$%%')"
	elif echo "${ks_source}" | grep -q '^cdrom:' ; then
		# Note: cdrom gets accessed as real device name which must be detected - assuming it is the first removable device
		# Note: hardcoded possible device names for CD/DVD - should cover all reasonable cases
		# Note: on RHEL>=6 even IDE/ATAPI devices have SCSI device names
		for dev in /dev/sd[a-z] /dev/sr[0-9]; do
			ks_dev=""
			if [ -b "${dev}" ]; then
				is_removable="$(cat /sys/block/$(basename ${dev})/removable 2>/dev/null)"
				if [ "${is_removable}" = "1" ]; then
					ks_dev="${dev}"
					ks_fstype="iso9660"
					ks_fsopt="ro"
					ks_path="$(echo ${ks_source} | awk -F: '{print $2}')"
					if [ -z "${ks_path}" ]; then
						echo "Unable to determine Kickstart source path" 1>&2
						ks_dev=""
					else
						ks_dir="$(echo ${ks_path} | sed 's%/[^/]*$%%')"
					fi
					break
				fi
			fi
		done
	elif echo "${ks_source}" | grep -q '^hd:' ; then
		# Note: blindly extracting device name from Kickstart commandline
		ks_dev="/dev/$(echo ${ks_source} | awk -F: '{print $2}')"
		# TODO: Detect actual filesystem type on local drive - assuming VFAT
		ks_fstype="vfat"
		ks_fsopt="ro"
		ks_path="$(echo ${ks_source} | awk -F: '{print $3}')"
		if [ -z "${ks_path}" ]; then
			echo "Unable to determine Kickstart source path" 1>&2
			ks_dev=""
		else
			ks_dir="$(echo ${ks_path} | sed 's%/[^/]*$%%')"
		fi
	elif echo "${ks_source}" | grep -q '^nfs:' ; then
		# Note: blindly extracting NFS server from Kickstart commandline
		ks_host="$(echo ${ks_source} | awk -F: '{print $2}')"
		ks_fstype="nfs"
		ks_fsopt="ro,nolock"
		ks_path="$(echo ${ks_source} | awk -F: '{print $3}')"
		if [ -z "${ks_path}" ]; then
			echo "Unable to determine Kickstart source path" 1>&2
			ks_dev=""
		else
			ks_dev="${ks_host}:$(echo ${ks_path} | sed 's%/[^/]*$%%')}"
			ks_dir="/"
		fi
	elif echo "${ks_source}" | egrep -q '^(http|https|ftp):' ; then
		# Note: blindly extracting URL from Kickstart commandline
		ks_host="$(echo ${ks_source} | sed -e 's%^.*//%%' -e 's%/.*$%%')"
		ks_dev="$(echo ${ks_source} | sed 's%/[^/]*$%%')"
		ks_fstype="url"
	else
		echo "Unsupported Kickstart source detected" 1>&2
	fi
	if [ -z "${ks_dev}" ]; then
		echo "Unable to extract Kickstart source - skipping configuration fragments retrieval" 1>&2
	else
		ks_custom_frags="hvp_parameters.sh hvp_parameters_db.sh"
		# Note: for network-based kickstart retrieval methods we extract the relevant nic MAC address to get the machine-specific fragment
		if [ "${ks_fstype}" = "url" -o "${ks_fstype}" = "nfs" ]; then
			# Note: we detect the nic device name as the one detaining the route towards the host holding the kickstart script
			# Note: regarding the kickstart host: we assume that if it is not already been given as an IP address then it is a DNS fqdn
			if ! echo "${ks_host}" | grep -q "${IPregex}" ; then
				ks_host_ip=$(nslookup "${ks_host}" | tail -n +3 | awk '/^Address/ {print $2}' | head -1)
			else
				ks_host_ip="${ks_host}"
			fi
			ks_nic=$(ip route get "${ks_host_ip}" | sed -n -e 's/^.*\s\+dev\s\+\(\S\+\)\s\+.*$/\1/p')
			if [ -f "/sys/class/net/${ks_nic}/address" ]; then
				ks_custom_frags="${ks_custom_frags} hvp_parameters_$(cat /sys/class/net/${ks_nic}/address).sh"
			fi
		fi
		if [ "${ks_fstype}" = "url" ]; then
			for custom_frag in ${ks_custom_frags} ; do
				echo "Attempting network retrieval of ${ks_dev}/${custom_frag}" 1>&2
				wget -P /tmp/kscfg-pre "${ks_dev}/${custom_frag}" 
			done
		else
			mount -t ${ks_fstype} -o ${ks_fsopt} ${ks_dev} /tmp/kscfg-pre/mnt
			for custom_frag in ${ks_custom_frags} ; do
				echo "Attempting filesystem retrieval of ${custom_frag}" 1>&2
				if [ -f "/tmp/kscfg-pre/mnt${ks_dir}/${custom_frag}" ]; then
					cp "/tmp/kscfg-pre/mnt${ks_dir}/${custom_frag}" /tmp/kscfg-pre
				fi
			done
			umount /tmp/kscfg-pre/mnt
		fi
	fi
fi
# Load any configuration fragment found, in the proper order
# Note: configuration-fragment defaults will override hardcoded defaults
# Note: commandline parameters will override configuration-fragment and hardcoded defaults
# Note: configuration fragments get executed with full privileges and no further controls beside a bare syntax check: obvious security implications must be taken care of (use HTTPS for network-retrieved kickstart and fragments)
pushd /tmp/kscfg-pre
for custom_frag in ${ks_custom_frags} ; do
	if [ -f "${custom_frag}" ]; then
		# Perform a configuration fragment sanity check before loading
		bash -n "${custom_frag}" > /dev/null 2>&1
		res=$?
		if [ ${res} -ne 0 ]; then
			# Report invalid configuration fragment and skip it
			logger -s -p "local7.err" -t "kickstart-pre" "Skipping invalid remote configuration fragment ${custom_frag}"
			continue
		fi
		source "./${custom_frag}"
	fi
done
popd

# TODO: perform better consistency check on all commandline-given parameters

# Determine choice of nic MAC fixed assignment
if grep -w -q 'hvp_nicmacfix' /proc/cmdline ; then
	nicmacfix="true"
fi

# Determine root password
given_root_password=$(sed -n -e "s/^.*hvp_rootpwd=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
if [ -n "${given_root_password}" ]; then
	root_password="${given_root_password}"
fi

# Determine admin username
given_admin_username=$(sed -n -e "s/^.*hvp_adminname=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
if [ -n "${given_admin_username}" ]; then
	admin_username="${given_admin_username}"
fi

# Determine admin password
given_admin_password=$(sed -n -e "s/^.*hvp_adminpwd=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
if [ -n "${given_admin_password}" ]; then
	admin_password="${given_admin_password}"
fi

# Determine AD further admin username
given_winadmin_username=$(sed -n -e "s/^.*hvp_winadminname=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
if [ -n "${given_winadmin_username}" ]; then
	winadmin_username="${given_winadmin_username}"
fi
if [ -z "${winadmin_username}" ]; then
	winadmin_username="ad${admin_username}"
fi

# Determine AD further admin password
given_winadmin_password=$(sed -n -e "s/^.*hvp_winadminpwd=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
if [ -n "${given_winadmin_password}" ]; then
	winadmin_password="${given_winadmin_password}"
fi

# Determine keyboard layout
given_keyboard_layout=$(sed -n -e "s/^.*hvp_kblayout=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
if [ -n "${given_keyboard_layout}" ]; then
	keyboard_layout="${given_keyboard_layout}"
fi

# Determine local timezone
given_local_timezone=$(sed -n -e "s/^.*hvp_timezone=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
if [ -n "${given_local_timezone}" ]; then
	local_timezone="${given_local_timezone}"
fi

# Determine hostname
given_hostname=$(sed -n -e 's/^.*hvp_myname=\(\S*\).*$/\1/p' /proc/cmdline)
if echo "${given_hostname}" | grep -q '^[[:alnum:]]\+$' ; then
	my_name="${given_hostname}"
fi

# Determine AD subdomain name
given_ad_subdomainname=$(sed -n -e "s/^.*hvp_ad_subdomainname=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
if [ -n "${given_ad_subdomainname}" ]; then
	ad_subdomain_prefix="${given_ad_subdomainname}"
fi

# Determine domain action
given_joindomain=$(sed -n -e 's/^.*hvp_joindomain=\(\S*\).*$/\1/p' /proc/cmdline)
if echo "${given_joindomain}" | egrep -q '^(true|false)$' ; then
	domain_join="${given_joindomain}"
fi

# Determine database type
given_dbtype=$(sed -n -e 's/^.*hvp_dbtype=\(\S*\).*$/\1/p' /proc/cmdline)
case "${given_dbtype}" in
	postgresql|mysql|firebird|sqlserver)
		dbtype="${given_dbtype}"
		;;
esac

# Determine nameserver address
given_nameserver=$(sed -n -e "s/^.*hvp_nameserver=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
if [ -n "${given_nameserver}" ]; then
	my_nameserver="${given_nameserver}"
fi

# Determine gateway address
given_gateway=$(sed -n -e "s/^.*hvp_gateway=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
if [ -n "${given_gateway}" ]; then
	my_gateway="${given_gateway}"
fi

# Determine network segments parameters
unset my_ip
declare -A my_ip
for zone in "${!network[@]}" ; do
	given_network_domain_name=$(sed -n -e "s/^.*hvp_${zone}_domainname=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
	if [ -n "${given_network_domain_name}" ]; then
		domain_name["${zone}"]="${given_network_domain_name}"
	fi
	given_network_mtu=$(sed -n -e "s/^.*hvp_${zone}_mtu=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
	if [ -n "${given_network_mtu}" ]; then
		mtu["${zone}"]="${given_network_mtu}"
	fi
	given_network=$(sed -n -e "s/^.*hvp_${zone}=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
	unset NETWORK NETMASK
	eval $(ipcalc -s -n "${given_network}")
	eval $(ipcalc -s -m "${given_network}")
	if [ -n "${NETWORK}" -a -n "${NETMASK}" ]; then
		network["${zone}"]="${NETWORK}"
		netmask["${zone}"]="${NETMASK}"
	fi
	NETWORK=${network["${zone}"]}
	NETMASK=${netmask["${zone}"]}
	given_network_my_ip=$(sed -n -e "s/^.*hvp_${zone}_my_ip=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
	if [ -n "${given_network_my_ip}" ]; then
		my_ip["${zone}"]="${given_network_my_ip}"
	else
		unset IPADDR
		IPADDR=$(echo "${given_network}" | sed -n -e 's>^\([^/]*\)/.*$>\1>p')
		if [ -n "${IPADDR}" -a "${IPADDR}" != "${NETWORK}" ]; then
			my_ip["${zone}"]="${IPADDR}"
		else
			my_ip["${zone}"]=$(ipmat ${NETWORK} ${my_ip_offset} +)
		fi
	fi
	given_network_test_ip=$(sed -n -e "s/^.*hvp_${zone}_test_ip=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
	if [ -n "${given_network_test_ip}" ]; then
		test_ip["${zone}"]="${given_network_test_ip}"
	fi
	if [ -z "${test_ip[${zone}]}" ]; then
		test_ip["${zone}"]=$(ipmat ${NETWORK} ${test_ip_offset} +)
	fi
	unset PREFIX
	eval $(ipcalc -s -p "${NETWORK}" "${NETMASK}")
	if [ "${PREFIX}" -ge 24 ]; then
		reverse_domain_name["${zone}"]=$(echo ${NETWORK} | awk -F. 'BEGIN {OFS="."}; {print $3,$2,$1}').in-addr.arpa
		network_base["${zone}"]=$(echo ${NETWORK} | awk -F. 'BEGIN {OFS="."}; {print $1,$2,$3}')
	elif [ "${PREFIX}" -ge 16 ]; then
		reverse_domain_name["${zone}"]=$(echo ${NETWORK} | awk -F. 'BEGIN {OFS="."}; {print $2,$1}').in-addr.arpa
		network_base["${zone}"]=$(echo ${NETWORK} | awk -F. 'BEGIN {OFS="."}; {print $1,$2}')
	elif [ "${PREFIX}" -ge 8 ]; then
		reverse_domain_name["${zone}"]=$(echo ${NETWORK} | awk -F. 'BEGIN {OFS="."}; {print $1}').in-addr.arpa
		network_base["${zone}"]=$(echo ${NETWORK} | awk -F. 'BEGIN {OFS="."}; {print $1}')
	fi
done
if [ -z "${my_gateway}" ]; then
	my_gateway="${test_ip['mgmt']}"
fi

# Disable any interface configured by NetworkManager
# Note: NetworkManager may interfer with interface assignment autodetection logic below
# Note: interfaces will be explicitly activated again by our dynamically created network configuration fragment
for nic_name in $(ls /sys/class/net/ 2>/dev/null | egrep -v '^(bonding_masters|lo|sit[0-9])$' | sort); do
	if nmcli device show "${nic_name}" | grep -q '^GENERAL.STATE:.*(connected)' ; then
		nmcli device disconnect "${nic_name}"
		nmcli connection delete "${nic_name}"
		ip addr flush dev "${nic_name}"
		ip link set mtu 1500 dev "${nic_name}"
	fi
done

# Determine network interface assignment
# Note: unconnected nics will be disabled
unset nics
declare -A nics
for nic_name in $(ls /sys/class/net/ 2>/dev/null | egrep -v '^(bonding_masters|lo|sit[0-9])$' | sort); do
	# Note: the file below will contain 1 for link up, 0 for link down or will result inaccessible for interface disabled
	if [ "$(cat /sys/class/net/${nic_name}/carrier 2>/dev/null)" = "1" ]; then
		ip addr flush dev "${nic_name}"
		nic_assigned='false'
		for zone in "${!network[@]}" ; do
			# Note: check whether the desired MTU setting can be obtained or not - skip if it fails
			ip link set mtu "${mtu[${zone}]}" dev "${nic_name}"
			res=$?
			effective_mtu=$(cat /sys/class/net/${nic_name}/mtu 2>/dev/null)
			if [ ${res} -ne 0 -o "${effective_mtu}" != "${mtu[${zone}]}" ] ; then
				ip addr flush dev "${nic_name}"
				ip link set mtu 1500 dev "${nic_name}"
				continue
			fi
			unset PREFIX
			eval $(ipcalc -s -p "${network[${zone}]}" "${netmask[${zone}]}")
			ip addr add "${my_ip[${zone}]}/${PREFIX}" dev "${nic_name}"
			res=$?
			if [ ${res} -ne 0 ] ; then
				ip addr flush dev "${nic_name}"
				ip link set mtu 1500 dev "${nic_name}"
				continue
			fi
			# Note: adding extra sleep and ping to work around possible hardware delays
			sleep 2
			ping -c 3 -w 8 -i 2 "${test_ip[${zone}]}" > /dev/null 2>&1
			if ping -c 3 -w 8 -i 2 "${test_ip[${zone}]}" > /dev/null 2>&1 ; then
				nics["${zone}"]="${nics[${zone}]} ${nic_name}"
				nic_assigned='true'
				ip addr flush dev "${nic_name}"
				ip link set mtu 1500 dev "${nic_name}"
				break
			fi
			ip addr flush dev "${nic_name}"
			ip link set mtu 1500 dev "${nic_name}"
		done
		if [ "${nic_assigned}" = "false" ]; then
			nics['unused']="${nics['unused']} ${nic_name}"
		fi
	else
		nics['unused']="${nics['unused']} ${nic_name}"
	fi
done

# TODO: Perform nic connections consistency check
# Note: with one network it must be mgmt
# Note: with two networks they must be mgmt and lan

# Remove my_ip/test_ip, network/netmask/network_base/mtu and domain_name/reverse_domain_name entries for non-existent networks
for zone in "${!network[@]}" ; do
	if [ -z "${nics[${zone}]}" ]; then
		unset my_ip[${zone}]
		unset test_ip[${zone}]
		unset network[${zone}]
		unset netmask[${zone}]
		unset network_base[${zone}]
		unset mtu[${zone}]
		unset domain_name[${zone}]
		unset reverse_domain_name[${zone}]
	fi
done

# Determine network segment identity and parameters
if [ -n "${nics['lan']}" ]; then
	my_zone="lan"
else
	my_zone="mgmt"
fi

# Create network setup fragment
# Note: dynamically created here to make use of full autodiscovery above
# Note: defining statically configured access to autodetected networks
# Note: listing interfaces using reverse alphabetical order for networks (results in: mgmt, lan, gluster)
# TODO: Anaconda/NetworkManager do not add DEFROUTE="no" and MTU="xxxx" parameters - adding workarounds here - remove when fixed upstream
mkdir -p /tmp/hvp-networkmanager-conf
pushd /tmp/hvp-networkmanager-conf
cat << EOF > /tmp/full-network
# Network device configuration - static version (always verify that your nic is supported by install kernel/modules)
# Use a "void" configuration to make sure anaconda quickly steps over "onboot=no" devices
EOF
for zone in "${!network[@]}" ; do
	if [ -n "${nics[${zone}]}" ]; then
		nic_names=$(echo ${nics[${zone}]} | sed -e 's/^\s*//' -e 's/\s*$//')
		further_options=""
		# Add gateway and nameserver options only if the default gateway is on this network
		unset NETWORK
		eval $(ipcalc -s -n "${my_gateway}" "${netmask[${zone}]}")
		if [ "${NETWORK}" = "${network[${zone}]}" ]; then
			further_options="${further_options} --gateway=${my_gateway} --nameserver=${my_nameserver}"
			# TODO: workaround for Anaconda/NetworkManager bug - remove when fixed upstream
			echo 'DEFROUTE="yes"' >> ifcfg-${nic_names}
		else
			further_options="${further_options} --nodefroute"
			# TODO: workaround for Anaconda/NetworkManager bug - remove when fixed upstream
			echo 'DEFROUTE="no"' >> ifcfg-${nic_names}
		fi
		# Add hostname option on the lan zone only (or on mgmt if there is only one network)
		if [ "${zone}" = "${my_zone}" ]; then
			further_options="${further_options} --hostname=${my_name}.${ad_subdomain_prefix}.${domain_name[${zone}]}"
		fi
		# Single (plain) interface
		cat <<- EOF >> /tmp/full-network
		network --device=${nic_names} --activate --onboot=yes --bootproto=static --ip=${my_ip[${zone}]} --netmask=${netmask[${zone}]} --mtu=${mtu[${zone}]} ${further_options}
		EOF
		# TODO: workaround for Anaconda/NetworkManager bug - remove when fixed upstream
		echo "MTU=\"${mtu[${zone}]}\"" >> ifcfg-${nic_names}
	fi
done
for nic_name in ${nics['unused']} ; do
	# TODO: the following makes anaconda crash because of https://bugzilla.redhat.com/show_bug.cgi?id=1418289
	# TODO: restore when fixed upstream
	#network --device=${nic_name} --no-activate --nodefroute --onboot=no --noipv4 --noipv6
	cat <<- EOF >> /tmp/full-network
	network --device=${nic_name} --no-activate --nodefroute --onboot=no
	EOF
done
popd

# Create users setup fragment
cat << EOF > /tmp/full-users
# Use given username and password for SSH access to installation
# Note: you must add inst.sshd to installation commandline for the following to have any effect
sshpw --username=${admin_username} ${admin_password} --plaintext
# Define root password
rootpw ${root_password}
# Create an unprivileged user
user --name=${admin_username} --password=${admin_password} --plaintext --gecos=Admin
EOF
# Prepare users configuration script to be run at first boot
mkdir -p /tmp/hvp-users-conf
cat << EOF > /tmp/hvp-users-conf/rc.users-setup
#!/bin/bash

# Configure SSH (allow only listed users)
sed -i -e "/^PermitRootLogin/s/\\\$/\\\\nAllowUsers root ${admin_username}/" /etc/ssh/sshd_config

# Configure email aliases (divert root email to administrative account)
sed -i -e "s/^#\\\\s*root.*\\\$/root:\\\\t\\\\t${admin_username}/" /etc/aliases
cat << EOM >> /etc/aliases

# Email alias for server monitoring
monitoring:	${admin_username}

EOM
newaliases
EOF

# Create localization setup fragment
# TODO: allow changing system language too
cat << EOF > /tmp/full-localization
# Default system language, additional languages can be enabled installing the appropriate packages below
lang en_US.UTF-8
# Keyboard layout
keyboard --vckeymap=${keyboard_layout}
# Configure time zone (NTP details demanded to post section)
timezone ${local_timezone} --isUtc
EOF

# Create disk setup fragment
# TODO: find a better way to detect emulated/VirtIO devices
all_devices="$(list-harddrives | egrep -v '^(fd|sr)[[:digit:]]*[[:space:]]' | awk '{print $1}' | sort)"
if [ -b /dev/vda ]; then
	device_name="vda"
elif [ -b /dev/xvda ]; then
	device_name="xvda"
else
	device_name="sda"
fi
cat << EOF > /tmp/full-disk
# Simple disk configuration: single SCSI/SATA/VirtIO disk
# Initialize partition table (GPT) on selected disk
clearpart --drives=${device_name} --all --initlabel --disklabel=gpt
# Bootloader placed on MBR, with 3 seconds waiting and with password protection
bootloader --location=mbr --timeout=3 --password=${root_password} --boot-drive=${device_name} --driveorder=${device_name} --append="nomodeset"
# Ignore further disk - maybe USB key!!!
ignoredisk --only-use=${device_name}
# Automatically create UEFI or BIOS boot partition depending on hardware capabilities
reqpart --add-boot
# Simple partitioning: single root and swap
part swap --fstype swap --recommended --ondisk=${device_name} --asprimary
part / --fstype xfs --size=100 --grow --ondisk=${device_name} --asprimary
EOF
# Clean up disks from any previous software-RAID (Linux or BIOS based)
# TODO: this does not work on CentOS7 (it would need some sort of late disk-status refresh induced inside anaconda) - workaround by manually zeroing-out the first 10 MiBs from a rescue boot before starting the install process (or simply restarting when installation stops/hangs at storage setup)
# Note: skipping this on a virtual machine to avoid inflating a thin-provisioned virtual disk
# Note: dmidecode command may no longer be available in pre environment
if cat /sys/class/dmi/id/sys_vendor | egrep -q -v "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	# Note: resetting all disk devices since leftover LVM configurations may interfer with installation and/or setup later on
	for current_device in ${all_devices}; do
		dd if=/dev/zero of=/dev/${current_device} bs=1M count=10
		dd if=/dev/zero of=/dev/${current_device} bs=1M count=10 seek=$(($(blockdev --getsize64 /dev/${current_device}) / (1024 * 1024) - 10))
	done
fi

# Create install source selection fragment
# Note: we use a non-local (hd:) stage2 location as indicator of network boot
given_stage2=$(sed -n -e 's/^.*inst\.stage2=\(\S*\).*$/\1/p' /proc/cmdline)
if echo "${given_stage2}" | grep -q '^hd:' ; then
	# Detect use of NetInstall media
	if [ -d /run/install/repo/repodata ]; then
		# Note: we know that the local stage2 comes from a full DVD image (Packages repo included)
		cat <<- EOF > /tmp/full-installsource
		# Use the inserted optical media as in:
		cdrom
		# alternatively specify a NFS network share as in:
		# nfs --opts=nolock --server NfsFqdnServerName --dir /path/to/CentOS/base/dir/copied/from/DVD/media
		# or an HTTP/FTP area as in:
		#url --url https://dangerous.ovirt.life/hvp-repos/el7/os
		EOF
	else
		# Note: since we detected use of NetInstall media (no local repo) we use network install source from CentOS mirrors
		given_stage2="http://mirror.centos.org/centos/7/os/x86_64"
		cat <<- EOF > /tmp/full-installsource
		# Specify a NFS network share as in:
		# nfs --opts=nolock --server NfsFqdnServerName --dir /path/to/CentOS/base/dir/copied/from/DVD/media
		# or an HTTP/FTP area as in:
		url --url ${given_stage2}
		# alternatively use the inserted optical media as in:
		#cdrom
		EOF
	fi
else
	# Note: we assume that a remote stage2 has been copied together with the full media content preserving the default DVD structure
	# TODO: we assume a HTTP/FTP area - add support for NFS
	cat <<- EOF > /tmp/full-installsource
	# Specify a NFS network share as in:
	# nfs --opts=nolock --server NfsFqdnServerName --dir /path/to/CentOS/base/dir/copied/from/DVD/media
	# or an HTTP/FTP area as in:
	url --url ${given_stage2}
	# alternatively use the inserted optical media as in:
	#cdrom
	EOF
fi

# Prepare NTPdate and Chrony configuration fragments to be appended later on below
mkdir -p /tmp/hvp-ntpd-conf
pushd /tmp/hvp-ntpd-conf
if [ "${domain_join}" = "true" ]; then
	# Make sure to sync only with the proper time reference (emulate Windows behaviour, using as reference the AD domain name to get back the DC holding the PDC emulator FSMO role)
	ntp_server="${ad_subdomain_prefix}.${domain_name[${my_zone}]}"
	cat <<- EOF > chrony.conf

	server ${ntp_server} iburst

	EOF
else
	ntp_server="0.centos.pool.ntp.org"
fi
echo "${ntp_server}" > step-tickers
popd

# Prepare hosts file to be copied later on below
mkdir -p /tmp/hvp-bind-zones
pushd /tmp/hvp-bind-zones
cat << EOF > hosts

# Static hostnames
EOF
for zone in "${!network[@]}" ; do
	if [ "${zone}" = "${my_zone}" ]; then
		cat <<- EOF >> hosts
		${my_ip[${zone}]}		${my_name}.${ad_subdomain_prefix}.${domain_name[${zone}]} ${my_name}
		EOF
	else
		cat <<- EOF >> hosts
		${my_ip[${zone}]}		${my_name}.${domain_name[${zone}]}
		EOF
	fi
done
popd

# Prepare TCP wrappers custom lines to be appended later on
mkdir -p /tmp/hvp-tcp_wrappers-conf
allowed_addr="127.0.0.1"
if [ -n "${nics['lan']}" ]; then
	allowed_addr="${network['lan']}/${netmask['lan']} ${allowed_addr}"
fi
allowed_addr="${network['mgmt']}/${netmask['mgmt']} ${allowed_addr}"
cat << EOF > /tmp/hvp-tcp_wrappers-conf/hosts.allow
ALL: ${allowed_addr}
sshd: ALL

EOF

# Create AD domain joining script
if [ "${domain_join}" = "true" ]; then
	mkdir -p /tmp/hvp-domain-join
	pushd /tmp/hvp-domain-join
	realm_name=$(echo ${ad_subdomain_prefix}.${domain_name[${my_zone}]} | awk '{print toupper($0)}')
	cat <<- EOF > rc.domain-join
	#!/bin/bash
	# Setup krb5.conf properly
	sed -i -e "s/^\\\\(\\\\s*\\\\)\\\\(dns_lookup_realm\\\\s*=.*\\\\)\\$/\\\\1\\\\2\n\\\\1dns_lookup_kdc = true\\\\n\\\\1default_realm = ${realm_name}/" /etc/krb5.conf
	# Perform Kerberos authentication to allow unattended join below
	cat <<- EOM | expect -f -
	set force_conservative 1
	
	if {\\\$force_conservative} {
		set send_slow {1 .1}
		proc send {ignore arg} {
			sleep .1
			exp_send -s -- \\\$arg
		}
	}
	
	set timeout -1
	spawn "kinit" "${winadmin_username}@${realm_name}"
	match_max 100000
	expect -re "Password for.*:.*\\\$"
	send -- "${winadmin_password}\\\\r"
	expect eof
	EOM
	res=\$?
	if [ \${res} -ne 0 ]; then
	    # Report script ending
	    logger -s -p "local7.err" -t "rc.domain-join" "Exiting join (failed Kerberos authentication with join credentials)"
	    exit \${res}
	else
	    klist
	    realm join -v --unattended --os-name=\$(lsb_release -si) --os-version=\$(lsb_release -sr) --automatic-id-mapping=no ${ad_subdomain_prefix}.${domain_name[${my_zone}]}
	    kdestroy
	fi
	EOF
	popd
fi

# Create database provisioning script
mkdir -p /tmp/hvp-db-conf
pushd /tmp/hvp-db-conf
cat << EOF > rc.db-provision
#!/bin/bash
case "${dbtype}" in
	postgresql)
		# Initialize PostgreSQL
		/usr/pgsql-9.6/bin/postgresql96-setup initdb

		# Enable and start PostgreSQL
		systemctl --now enable postgresql-9.6

		# Change system/DB password for PostgreSQL admin user
		echo '${root_password}' | passwd --stdin postgres
		su - postgres -c "psql -d template1 -c \\"ALTER USER postgres WITH PASSWORD '${root_password}';\\""

		# Enable password authentication
		sed -i -e '/^host\s*/s/ident/md5/g' -e '/^local\s*/s/peer/md5/g' /var/lib/pgsql/9.6/data/pg_hba.conf
		# Restart PostgreSQL to apply configuration changes
		systemctl restart postgresql-9.6

		# Configure phpPgAdmin (allow only through HTTPS; allow from localhost and our networks only)
		# TODO: verify with newer conditional (Apache 2.2/2.4) and IPv6-too configuration
		sed -i -e 's/^\\(\\s*\\)\\(Order\\s*\\).*\\\$/\\1\\2allow,deny/' -e "/^\\\\s*Allow\\\\s*from\\\\s*127\\\\.0\\\\.0\\\\.1/s>127\\\\.0\\\\.0\\\\.1.*\\$>${allowed_addr}>" -e "/^\\\\s*Require\\\\s*local/s>local.*\\$>ip ${allowed_addr}>" -e 's>^\\(\\s*\\)\\(Allow\\s*from\\|Require\\s*ip\\)\\(\\s*127\\.0\\.0\\.1.*\\)\$>\\1\\2\\3\\n\\1RewriteEngine On\\n\\1RewriteCond %{HTTPS} !=on\\n\\1RewriteRule ^.*\$ https://%{SERVER_NAME}%{REQUEST_URI} [R,L]>' /etc/httpd/conf.d/phpPgAdmin.conf
		# Add Apache alias for phpPgAdmin
		cat <<- EOM >> /etc/httpd/conf.d/phpPgAdmin.conf

		Alias /sql /usr/share/phpPgAdmin

		<Location /sql>
		    <IfModule mod_authz_core.c>
		        # Apache 2.4
		        Require ip ${allowed_addr}
		    </IfModule>
		    <IfModule !mod_authz_core.c>
		        # Apache 2.2
		        Order allow,deny
		        Deny from all
		        Allow from ${allowed_addr}
		        Allow from ::1
		    </IfModule>
		</Location>
		EOM
		# Restart Apache to apply configuration changes
		systemctl restart httpd
		;;
	mysql)
		# Initialize MySQL
		# Note: the following suggests to use "mysqld --initialize" instead
		# TODO: update the following using new style command
		mysql_install_db --insecure --user=mysql --datadir=/var/lib/mysql

		# Enable and start MySQL
		# Note: Percona service has been renamed "mysqld" (as all others MySQL distributions) instead of "mysql"
		systemctl --now enable mysqld

		# Configure MySQL root password
		/usr/bin/mysql --user=root <<- EOM
		SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${root_password}');
		EOM

		# Configure mysqladmin utility for a password-protected root account
		cat <<- EOM > /root/.my.cnf
		[mysqladmin]
		password = ${root_password}
		user= root
		EOM
		chmod 600 /root/.my.cnf
		
		# Configure mytop utility for a password-protected root account
		cat <<- EOM > /root/.mytop
		user=root
		pass=${root_password}
		host=localhost
		db=
		delay=5
		port=3306
		socket=
		batchmode=0
		header=1
		color=1
		idle=1
		EOM
		chmod 600 /root/.mytop

		# Configure phpMyAdmin (allow only through HTTPS; allow from localhost and our networks only)
		# TODO: verify with newer conditional (Apache 2.2/2.4) and IPv6-too configuration
		sed -i -e 's/^\\(\\s*\\)\\(Order\\s*\\).*\\\$/\\1\\2allow,deny/' -e "/^\\\\s*Allow\\\\s*from\\\\s*127\\\\.0\\\\.0\\\\.1/s>127\\\\.0\\\\.0\\\\.1.*\\$>${allowed_addr}>" -e "/^\\\\s*Require\\\\s*local/s>local.*\\$>ip ${allowed_addr}>" -e 's>^\\(\\s*\\)\\(Allow\\s*from\\|Require\\s*ip\\)\\(\\s*127\\.0\\.0\\.1.*\\)\$>\\1\\2\\3\\n\\1RewriteEngine On\\n\\1RewriteCond %{HTTPS} !=on\\n\\1RewriteRule ^.*\$ https://%{SERVER_NAME}%{REQUEST_URI} [R,L]>' /etc/httpd/conf.d/phpMyAdmin.conf
		# Add Apache alias for phpMyAdmin
		cat <<- EOM >> /etc/httpd/conf.d/phpMyAdmin.conf

		Alias /sql /usr/share/phpMyAdmin

		<Location /sql>
		    <IfModule mod_authz_core.c>
		        # Apache 2.4
		        Require ip ${allowed_addr}
		    </IfModule>
		    <IfModule !mod_authz_core.c>
		        # Apache 2.2
		        Order allow,deny
		        Deny from all
		        Allow from ${allowed_addr}
		        Allow from ::1
		    </IfModule>
		</Location>
		EOM
		# Restart Apache to apply configuration changes
		systemctl restart httpd
		;;
	firebird)
		# No initialization needed for Firebird
		true
		;;
	sqlserver)
		# Initialize SQLServer
		# Note: 3.25 GiB RAM are absolutely required
		# TODO: verify editions/licensing, language/collation and paths
		MSSQL_PID=Developer ACCEPT_EULA=Y MSSQL_SA_PASSWORD='${root_password}' /opt/mssql/bin/mssql-conf -n setup

		# Initialize SQLServer Integration Services
		ACCEPT_EULA=Y /opt/ssis/bin/ssis-conf -n setup

		# Enable and start SQLServer
		systemctl --now enable mssql-server
		;;
esac
EOF
popd

) 2>&1 | tee /tmp/kickstart_pre.log
%end

# Post-installation script (run with bash from installation image at the end of installation)
%post --nochroot --log /dev/console

# Copy configuration parameters files (generated in pre section above) into installed system (to be loaded during chrooted post section below)
mkdir -p ${ANA_INSTALL_PATH}/root/etc/kscfg-pre
for custom_frag in /tmp/kscfg-pre/*.sh ; do
	if [ -f "${custom_frag}" ]; then
		cp "${custom_frag}" ${ANA_INSTALL_PATH}/root/etc/kscfg-pre/
	fi
done

%end

# Post-installation script (run with bash from chroot after the first post section)
# Note: console logging to support commandline virt-install invocation
%post --log /dev/console
( # Run the entire post section as a subshell for logging purposes.

script_version="2018012101"

# Report kickstart version for reference purposes
logger -s -p "local7.info" -t "kickstart-post" "Kickstarting for $(cat /etc/system-release) - version ${script_version}"
# Report kernel commandline for reference purposes
logger -s -p "local7.info" -t "kickstart-post" "Kickstarting with kernel commandline: $(cat /proc/cmdline)"

# Note: NetworkManager correctly updates /etc/resolv.conf inside the installation root even when in DHCP mode

# Note: no need to explicitly set machine time with newer systemd/chrony installation environment

# Force sane language defaults for safe command output parsing
export LANG=C LC_ALL=C

# Set the hostname for apps that need it
# Note: hostnamectl would not work inside the installation chroot
export HOSTNAME=$(cat /etc/hostname)
hostname ${HOSTNAME}

# Set the homedir for apps that need it
export HOME="/root"

# Discover exact post-stage environment
echo "POST env" >> /tmp/post.out
env >> /tmp/post.out
echo "POST devs" >> /tmp/post.out
ls -l /dev/* >> /tmp/post.out
echo "POST block" >> /tmp/post.out
ls -l /sys/block/* >> /tmp/post.out
echo "POST mounts" >> /tmp/post.out
df -h >> /tmp/post.out
echo "POST progs" >> /tmp/post.out
for pathdir in $(echo "${PATH}" | sed -e 's/:/ /'); do
	if [ -d "${pathdir}" ]; then
		ls "${pathdir}"/* >> /tmp/post.out
	fi
done
echo "POST resolv.conf" >> /tmp/post.out
cat /etc/resolv.conf >> /tmp/post.out
echo "POST hosts" >> /tmp/post.out
cat /etc/hosts >> /tmp/post.out

# Define associative arrays
declare -A network netmask network_base mtu
declare -A domain_name
declare -A reverse_domain_name
declare -A test_ip

# Hardcoded defaults

unset nicmacfix
unset dbtype

nicmacfix="false"

dbtype="postgresql"

# Load configuration parameters files (generated in pre section above)
ks_custom_frags="hvp_parameters.sh hvp_parameters_db.sh hvp_parameters_*:*.sh"
pushd /root/etc/kscfg-pre
for custom_frag in ${ks_custom_frags} ; do
	if [ -f "${custom_frag}" ]; then
		# Perform a configuration fragment sanity check before loading
		bash -n "${custom_frag}" > /dev/null 2>&1
		res=$?
		if [ ${res} -ne 0 ]; then
			# Report invalid configuration fragment and skip it
			logger -s -p "local7.err" -t "kickstart-post" "Skipping invalid remote configuration fragment ${custom_frag}"
			continue
		fi
		source "./${custom_frag}"
	fi
done
popd

# Determine choice of nic MAC fixed assignment
if grep -w -q 'hvp_nicmacfix' /proc/cmdline ; then
	nicmacfix="true"
fi

# Determine database type
given_dbtype=$(sed -n -e 's/^.*hvp_dbtype=\(\S*\).*$/\1/p' /proc/cmdline)
case "${given_dbtype}" in
	postgresql|mysql|firebird|sqlserver)
		dbtype="${given_dbtype}"
		;;
esac

# Create /dev/root symlink for grubby (must differentiate for use of LVM or MD based "/")
# TODO: Open a Bugzilla notification
# TODO: remove when grubby gets fixed
mp=$(grep -w "/" /etc/fstab | sed -e 's/ .*//')
if echo "$mp" | grep -q "^UUID="
then
    uuid=$(echo "$mp" |sed 's/UUID=//')
    rootdisk=$(blkid -U $uuid)
elif echo "$mp" | grep -q "^/dev/"
then
    rootdisk=$mp
fi
ln -sf $rootdisk /dev/root

# Add support for CentOS CR repository (to allow up-to-date upgrade later)
yum-config-manager --enable cr > /dev/null

# Add HVP custom repo
yum -y --nogpgcheck install https://dangerous.ovirt.life/hvp-repos/el7/hvp/x86_64/hvp-release-7-2.noarch.rpm

# Add upstream repository definitions
yum -y install http://packages.psychotic.ninja/6/base/i386/RPMS/psychotic-release-1.0.0-1.el6.psychotic.noarch.rpm
yum-config-manager --save --setopt='psychotic.include=unrar*' > /dev/null
yum-config-manager --enable psychotic > /dev/null
yum -y install epel-release

# Add Webmin repo
cat << EOF > /etc/yum.repos.d/webmin.repo
[webmin]
name = Webmin Distribution Neutral
baseurl = http://download.webmin.com/download/yum
gpgcheck = 1
enabled = 1
gpgkey = http://www.webmin.com/jcameron-key.asc
skip_if_unavailable = 1
EOF
chmod 644 /etc/yum.repos.d/webmin.repo

# Comment out mirrorlist directives and uncomment the baseurl ones to make better use of proxy caches
# TODO: investigate whether to disable fastestmirror yum plugin too (may interfer in round-robin-DNS-served names?)
for repofile in /etc/yum.repos.d/*.repo; do
	if egrep -q '^(mirrorlist|metalink)' "${repofile}"; then
		sed -i -e 's/^mirrorlist/#mirrorlist/g' "${repofile}"
		sed -i -e 's/^metalink/#metalink/g' "${repofile}"
		sed -i -e 's/^#baseurl/baseurl/g' "${repofile}"
	fi
done
# Modify baseurl definitions to allow effective use of our proxy cache
sed -i -e 's>http://download.fedoraproject.org/pub/epel/7/>http://www.nic.funet.fi/pub/mirrors/fedora.redhat.com/pub/epel/7/>g' /etc/yum.repos.d/epel.repo
sed -i -e 's>http://download.fedoraproject.org/pub/epel/testing/7/>http://www.nic.funet.fi/pub/mirrors/fedora.redhat.com/pub/epel/testing/7/>g' /etc/yum.repos.d/epel-testing.repo

# Enable use of delta rpms since we are not using a local mirror
yum-config-manager --save --setopt='deltarpm=1' > /dev/null

# Update OS (with "upgrade" to allow package obsoletion) non-interactively ("-y" yum option)
yum -y upgrade

# TODO: Make sure that the latest installed kernel is the default
# TODO: Kernel upgrade in kickstart post phase does not seem to set the latest installed kernel as boot default
# TODO: Open a Bugzilla notification
# TODO: Remove when fixed upstream
# TODO: the following works only with re-instated CentOS6 fix above
grubby --set-default=/boot/vmlinuz-$(rpm -q --last kernel | head -1 | cut -f 1 -d ' ' | sed -e 's/kernel-//')

# Install HAVEGEd
# Note: even in presence of an actual/virtualized hardware random number generator (managed by rngd) we install haveged as a safety measure
yum -y install haveged

# Conditionally install Memtest86+
if dmidecode -s system-manufacturer | egrep -q -v "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	yum -y install memtest86+
fi

# Install YUM-cron, YUM-plugin-ps, Gdisk, PWGen, HPing, 7Zip, UnRAR and ARJ
yum -y install hping3 p7zip{,-plugins} unrar arj pwgen
yum -y install yum-cron yum-plugin-ps gdisk

# Install Nmon and Dstat
yum -y install nmon dstat

# Install Apache
yum -y install httpd mod_ssl

# Install Webalizer and MRTG
yum -y install webalizer mrtg net-snmp net-snmp-utils

# Install Webmin
yum -y install webmin

# Install needed packages to join AD domain
yum -y install sssd-ad realmd adcli krb5-workstation samba-common

# Install database packages
case "${dbtype}" in
	postgresql)
		# Add PostgreSQL upstream repository
		yum -y install https://download.postgresql.org/pub/repos/yum/9.6/redhat/rhel-7-x86_64/pgdg-redhat96-9.6-3.noarch.rpm

		# Install upstream PostgreSQL (newer) instead of the standard (CentOS-provided) one
		yum -y install postgresql96 postgresql96-server

		# Install Barman
		yum -y install barman barman-cli

		# Install phpPgAdmin, PgView, PgTop, PgCenter and PgTune
		yum -y install phpPgAdmin pg_view pg_top pgcenter pgtune
		;;
	mysql)
		# Add Percona repository
		yum -y install https://www.percona.com/downloads/percona-release/redhat/0.1-4/percona-release-0.1-4.noarch.rpm

		# Install Percona custom version of MySQL (newer/tweaked) instead of the standard (CentOS-provided) one
		# Note: this should bring in Percona compat client libraries for MySQL 5.1.x
		yum -y install Percona-Server-client-57 Percona-Server-server-57

		# Install Percona XTRABackup
		yum -y install percona-xtrabackup-24

		# Install Percona Toolkit
		yum -y install percona-toolkit

		# Install phpMyAdmin, MySQLreport, MyTop, MTop, InnoTop and MySQLtuner
		yum -y install phpMyAdmin mysqlreport mytop mtop innotop mysqltuner
		;;
	firebird)
		# Install Firebird
		# Note: Firebird EPEL version is 2.5.x
		yum -y install firebird

		# TODO: create rpm package for firebirdwebadmin from https://github.com/mariuz/firebirdwebadmin and install together with php-interbase
		;;
	sqlserver)
		# Add Microsoft repositories
		wget -O /etc/yum.repos.d/mssql-server.repo https://packages.microsoft.com/config/rhel/7/mssql-server.repo
		chmod 644 /etc/yum.repos.d/mssql-server.repo
		chown root:root /etc/yum.repos.d/mssql-server.repo
		wget -O /etc/yum.repos.d/msprod.repo https://packages.microsoft.com/config/rhel/7/prod.repo
		chmod 644 /etc/yum.repos.d/msprod.repo
		chown root:root /etc/yum.repos.d/msprod.repo

		# Set this variable in order to avoid interactive questions from postinst scripts
		export ACCEPT_EULA=Y

		# Install SQLServer
		yum -y install mssql-server

		# Install SQLServer command-line tools
		yum -y install mssql-tools

		# Install SQLServer Agent
		yum -y install mssql-server-agent

		# Install SQLServer Full-Text Search
		yum -y install mssql-server-fts

		# Install SQLServer Integration Services
		yum -y install mssql-server-is

		# TODO: create rpm package for PHP-MSSQL-Server-Admin from https://github.com/miguelaxcar/PHP-MSSQL-Server-Admin and install together with php-mssql
		;;
esac

# Install Bareos client (file daemon + console)
# TODO: using HVP repo to bring in recompiled packages from Bareos stable GIT tree - remove when regularly published upstream
yum -y install bareos-client

# Install virtualization tools support packages
# TODO: find a way to enable some virtualization technologies (Parallels, VirtualBox) on a server machine without development support packages
if dmidecode -s system-manufacturer | egrep -q "(innotek|Parallels)" ; then
	# Install dkms for virtualization tools support
	# TODO: configure virtualization tools under dkms
	# TODO: disabled since required development packages cannot be installed
	#yum -y install dkms
	echo "DKMS unsupported"
elif dmidecode -s system-manufacturer | grep -q "Red.*Hat" ; then
	yum -y install qemu-guest-agent
elif dmidecode -s system-manufacturer | grep -q "oVirt" ; then
	yum -y install ovirt-guest-agent
elif dmidecode -s system-manufacturer | grep -q "Microsoft" ; then
	yum -y install hyperv-daemons
elif dmidecode -s system-manufacturer | grep -q "VMware" ; then
	# Note: VMware basic support installed here (since it is included in base distro now)
	yum -y install open-vm-tools open-vm-tools-desktop fuse
fi

# Tune package list to underlying platform
if dmidecode -s system-manufacturer | egrep -q "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	# Exclude CPU microcode updates to avoid errors on virtualized platform
	yum -y erase microcode_ctl
else
	# Install MCE logging/management service
	yum -y install mcelog
fi

# Clean up after all installations
yum --enablerepo '*' clean all

# Remove package update leftovers
find /etc -type f -name '*.rpmnew' -exec rename .rpmnew "" '{}' ';'
find /etc -type f -name '*.rpmsave' -exec rm -f '{}' ';'

# Disable mirrorlists and use baseurls only (better utilization of our proxy cache)
# Note: repeated here since repo file could have been upgraded above
for repofile in /etc/yum.repos.d/*.repo; do
	if grep -q '^mirrorlist' "${repofile}"; then
		sed -i -e 's/^mirrorlist/#mirrorlist/g' "${repofile}"
		sed -i -e 's/^#baseurl/baseurl/g' "${repofile}"
	fi
done
# Modify baseurl definitions to allow effective use of our proxy cache
sed -i -e 's>http://apt\.sw\.be/redhat/el7/en/>http://ftp.fi.muni.cz/pub/linux/repoforge/redhat/el7/en/>g' /etc/yum.repos.d/rpmforge.repo
sed -i -e 's>http://download.fedoraproject.org/pub/epel/7/>http://www.nic.funet.fi/pub/mirrors/fedora.redhat.com/pub/epel/7/>g' /etc/yum.repos.d/epel.repo
sed -i -e 's>http://download.fedoraproject.org/pub/epel/testing/7/>http://www.nic.funet.fi/pub/mirrors/fedora.redhat.com/pub/epel/testing/7/>g' /etc/yum.repos.d/epel-testing.repo

# Now configure the base OS

# Setup auto-update via yum-cron (ala CentOS4, replacement for yum-updatesd in CentOS5)
# Note: Updates left to the administrator manual intervention
sed -i -e 's/^update_messages\s.*$/update_messages = no/' -e 's/^download_updates\s.*$/download_updates = no/' -e 's/^apply_updates\s.*$/apply_updates = no/' -e 's/^emit_via\s.*$/emit_via = None/' /etc/yum/yum-cron*.conf
systemctl disable yum-cron

# Limit retained old kernels to 3 (as in CentOS5 default)
yum-config-manager --save --setopt='installonly_limit=3' > /dev/null

# Autodetecting BIOS/UEFI
# Note: the following identifies the symlink under /etc to abstract from BIOS/UEFI actual file placement
if [ -d /sys/firmware/efi ]; then
	grub2_cfg_file="/etc/grub2-efi.cfg"
else
	grub2_cfg_file="/etc/grub2.cfg"
fi

# Setup a serial terminal
sed -i -e '/^GRUB_CMDLINE_LINUX/s/quiet/quiet console=tty0 console=ttyS0,115200n8/' /etc/default/grub
cat << EOF >> /etc/default/grub
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
EOF
grub2-mkconfig -o "${grub2_cfg_file}"

# Configure GRUB2 boot loader (no splash screen, no Plymouth, show menu, wait 5 seconds for manual override)
# Note: alternatively, Plymouth may be instructed to use detailed listing with: plymouth-set-default-theme -R details
sed -i -e '/^GRUB_CMDLINE_LINUX/s/\s*rhgb//' -e '/^GRUB_TIMEOUT/s/=.*$/="5"/' /etc/default/grub
grub2-mkconfig -o "${grub2_cfg_file}"

# Conditionally add memory test entry to boot loader
if dmidecode -s system-manufacturer | egrep -q -v "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	memtest-setup
	grub2-mkconfig -o "${grub2_cfg_file}"
fi

# Configure kernel I/O scheduler policy for a virtual machine
# TODO: test with noop elevator
if dmidecode -s system-manufacturer | egrep -q "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	sed -i -e '/^GRUB_CMDLINE_LINUX/s/\selevator=[^[:space:]"]*//' -e '/^GRUB_CMDLINE_LINUX/s/"$/ elevator=deadline"/' /etc/default/grub
	grub2-mkconfig -o "${grub2_cfg_file}"
fi

# Configuration of session/system management (ignore power actions initiated by keyboard etc.)
# Note: interactive startup is disabled by default (enable with systemd.confirm_spawn=true on kernel commandline) and single user mode uses sulogin by default
if dmidecode -s system-manufacturer | egrep -q -v "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	sed -i -e '/Handle[^=]*=[^i]/s/^#\(Handle[^=]*\)=.*$/\1=ignore/' /etc/systemd/logind.conf
fi

# Configure systemd (no shutdown from keyboard)
systemctl mask ctrl-alt-del.target

# Configure kernel behaviour

# Console verbosity
# TODO: check kernel cmdline option loglevel
cat << EOF > /etc/sysctl.d/console-log.conf
# Controls the severity level of kernel messages on local consoles
kernel.printk = 1
EOF
chmod 644 /etc/sysctl.d/console-log.conf

# Reboot on panic
cat << EOF > /etc/sysctl.d/panic.conf
# Controls the timeout for automatic reboot on panic
kernel.panic = 5
EOF
chmod 644 /etc/sysctl.d/panic.conf

# Conditionally add virtual guest optimizations
# TODO: verify wether we can skip this and delegate to tuned
if dmidecode -s system-manufacturer | egrep -q "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	# Configure block devices for a virtual guest
	
	# Configure timeout for Qemu devices
	# Note: VirtIO devices do not need this (neither do they expose any timeout parameter)
	cat <<- EOF > /etc/udev/rules.d/99-qemu-block-timeout.rules
	#
	# Qemu block devices timeout settings
	#
	ACTION=="add|change", SUBSYSTEMS=="block", ATTRS{model}=="QEMU_HARDDISK", RUN+="/bin/sh -c 'echo 180 >/sys\$DEVPATH/timeout'"
	EOF
	chmod 644 /etc/udev/rules.d/99-qemu-block-timeout.rules
	
	# Configure readahead and requests for VirtIO devices
	cat <<- EOF > /etc/udev/rules.d/99-virtio-block.rules
	#
	# VirtIO block devices settings
	#
	ACTION=="add|change", KERNEL=="vd*[!0-9]", SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", ATTR{queue/nr_requests}="8"
	ACTION=="add|change", KERNEL=="vd*[!0-9]", SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", ATTR{bdi/read_ahead_kb}="4096"
	EOF
	chmod 644 /etc/udev/rules.d/99-virtio-block.rules

	# Configure scheduler and memory for a virtual guest
	cat <<- EOF > /etc/sysctl.d/virtualguest.conf
	# Tune for a KVM virtualization guest
	kernel.sched_min_granularity_ns = 10000000
	kernel.sched_wakeup_granularity_ns = 15000000
	vm.dirty_background_ratio = 10
	vm.dirty_ratio = 40
	vm.dirty_expire_centisecs = 500
	vm.dirty_writeback_centisecs = 100
	vm.swappiness = 30
	kernel.sched_migration_cost = 5000000
	EOF
	chmod 644 /etc/sysctl.d/virtualguest.conf
fi

# Configure log rotation (keep 6 years of logs, compressed)
sed -i -e 's/^rotate.*$/rotate 312/' -e 's/^#\s*compress.*$/compress/' /etc/logrotate.conf

# Enable HAVEGEd
systemctl enable haveged

# Note: users configuration script generated in pre section above and copied in third post section below

# Conditionally force static the nic name<->MAC mapping to work around hardware bugs (eg nic "autoshifting" on some HP MicroServer G7)
if [ "${nicmacfix}" = "true" ] ; then
	for nic_cfg in /etc/sysconfig/network-scripts/ifcfg-* ; do
		eval $(grep '^DEVICE=' "${nic_cfg}")
		nic_name="${DEVICE}"
		if echo "${nic_name}" | egrep -q '^(bond|lo|br|sit)' ; then
			continue
		fi
		nic_mac=$(cat "/sys/class/net/${nic_name}/address" 2>/dev/null)
		# Detect bonding slaves (real MAC address must be specially extracted)
		if [ -L "/sys/class/net/${nic_name}/master" ]; then
			nic_master=$(stat --printf="%N" "/sys/class/net/${nic_name}/master" | sed -e "s%^.*-> \`.*/net/\\([^']*\\)'.*\$%\\1%")
			# Note: all bonding slaves take the apparent MAC address from the bonding master device (which usually takes it from the first slave) - extract the real one
			nic_mac=$(cat /proc/net/bonding/${nic_master} | awk 'BEGIN {IGNORECASE=1; found="false"}; /^Slave Interface:[[:space:]]*'${nic_name}'[[:space:]]*/ {found="true"}; /^Permanent HW addr:[[:space:]]*/ {if (found == "true") {print $4; exit}}')
		fi
		if [ -n "${nic_mac}" ]; then
			if ! grep -q '^HWADDR=' "${nic_cfg}" ; then
				echo "HWADDR=\"${nic_mac}\"" >> "${nic_cfg}"
			fi
		fi
	done
fi

# System clock configuration
# Note: systemd sets clock to UTC by default
#echo 'UTC' >> /etc/adjtime

# Configure NTP time synchronization (immediate hardware synch)
# Note: further configuration fragment created in pre section above and copied in post section below
sed -i -e 's/^SYNC_HWCLOCK=.*$/SYNC_HWCLOCK="yes"/' /etc/sysconfig/ntpdate

# Allow NTPdate hardware clock sync through SELinux
# Note: obtained by means of: cat /var/log/audit/audit.log | audit2allow -M myntpdate
# TODO: remove when SELinux policy fixed upstream
mkdir -p /etc/selinux/local
cat << EOF > /etc/selinux/local/myntpdate.te

module myntpdate 8.0;

require {
        type ntpd_t;
        type hwclock_exec_t;
        type adjtime_t;
        class file { open read write execute execute_no_trans getattr };
        class netlink_audit_socket create;
}

#============= ntpd_t ==============
allow ntpd_t hwclock_exec_t:file { open read execute execute_no_trans getattr };
allow ntpd_t self:netlink_audit_socket create;
allow ntpd_t adjtime_t:file { open read getattr write };
EOF
chmod 644 /etc/selinux/local/myntpdate.te

pushd /etc/selinux/local
checkmodule -M -m -o myntpdate.mod myntpdate.te
semodule_package -o myntpdate.pp -m myntpdate.mod
semodule -i myntpdate.pp
popd

# Configure Chrony
# Note: configuration fragment created in pre section above and appended in post section below

# Enable Chrony
systemctl enable chronyd

# Note: Configured TCP wrappers allow file in pre above and copied in second post below
echo "ALL: ALL" >> /etc/hosts.deny

# Configure SSH (show legal banner, no root login with password, limit authentication tries, no DNS tracing of incoming connections)
sed -i -e 's/^#\s*PermitRootLogin.*$/PermitRootLogin without-password/' -e 's/^#\s*MaxAuthTries.*$/MaxAuthTries 3/' -e 's/^#\s*UseDNS.*$/UseDNS no/' -e 's%^#\s*Banner.*$%Banner /etc/issue.net%' /etc/ssh/sshd_config
# Force security-conscious length of host keys by pre-creating them here
# Note: ED25519 keys have a fixed length so they are not created here
# Note: using haveged to ensure enough entropy (but rngd could be already running from installation environment)
# Note: starting service manually since systemd inside a chroot would need special treatment
haveged -w 1024 -F &
haveged_pid=$!
ssh-keygen -b 4096 -t rsa -N "" -f /etc/ssh/ssh_host_rsa_key
ssh-keygen -b 1024 -t dsa -N "" -f /etc/ssh/ssh_host_dsa_key
ssh-keygen -b 521 -t ecdsa -N "" -f /etc/ssh/ssh_host_ecdsa_key
chgrp ssh_keys /etc/ssh/ssh_host_{rsa,dsa,ecdsa}_key
chmod 640 /etc/ssh/ssh_host_{rsa,dsa,ecdsa}_key
# Stopping haveged started above
kill ${haveged_pid}

# Configure use of at/cron facilities (allow only listed users)
rm -f /etc/{at,cron}.deny
cat << EOF > /etc/at.allow
root
EOF
chmod 600 /etc/at.allow
cat << EOF > /etc/cron.allow
root
EOF
chmod 600 /etc/cron.allow

# Configure legal warning messages
cat << EOF > /etc/issue

WARNING: THIS CONSOLE IS RESERVED FOR SYSTEM ADMINISTRATION ONLY.
EVERY ACCESS IS THOROUGHLY LOGGED.
THERE IS NO PRIVACY PROTECTION ON LOGGED DATA.
VIOLATIONS WILL BE PROSECUTED.
ACCESS IMPLIES ACCEPTANCE OF THE ABOVE CONDITIONS.

EOF
cat << EOF > /etc/issue.net

Access is reserved to explicitly authorized personnel only.
Violations will be prosecuted.
Every access is thoroughly logged.
This access service provides no privacy protection on logged data.
Access through this service implies acceptance of the above conditions.

EOF
cat << EOF > /etc/motd

                                  WARNING

This computer is the private property of his owners.
Permission of use must be individually and explicitly obtained in written form.
If you have not been authorized, you must immediately terminate your connection.
Violations will be prosecuted.
Use of this computer is thoroughly logged.
There is no privacy protection on logged data.
Continued use of this computer implies acceptance of the above conditions.

EOF
chmod 644 /etc/{issue*,motd}

# Note: email aliases configured through script created in pre section above and copied in third post section below

# TODO: Send all log messages to our internal syslog server
# TODO: enable TCP service on internal syslog/firewall servers then uncomment here
# TODO: switch to encrypted/guaranteed delivery (RELP with SSL/Kerberos) when available
#cat << EOF > /etc/rsyslog.d/centralized.conf
## ### begin forwarding rule ###
## The statement between the begin ... end define a SINGLE forwarding
## rule. They belong together, do NOT split them. If you create multiple
## forwarding rules, duplicate the whole block!
## Remote Logging (we use TCP for reliable delivery)
##
## An on-disk queue is created for this action. If the remote host is
## down, messages are spooled to disk and sent when it is up again.
#\$WorkDirectory /var/lib/rsyslog # where to place spool files
#\$ActionQueueFileName VRLRule1 # unique name prefix for spool files
#\$ActionQueueMaxDiskSpace 1g   # 1gb space limit (use as much as possible)
#\$ActionQueueSaveOnShutdown on # save messages to disk on shutdown
#\$ActionQueueType LinkedList   # run asynchronously
#\$ActionResumeRetryCount -1    # infinite retries if host is down
## remote host is: name/ip:port, e.g. 192.168.0.1:514, port optional
#*.* @@syslog.${domain_name['mgmt']}:514
## ### end of the forwarding rule ###
#EOF
#chmod 644 /etc/rsyslog.d/centralized.conf

# Configure ABRTd
# Allow reports for signed packages from 3rd-party repos by adding their keys under /etc/pki/rpm-gpg/
for repokeyurl in $(grep -h '^gpgkey' /etc/yum.repos.d/*.repo | grep -v 'file:///' | sed -e 's/^gpgkey\s*=\s*//' -e 's/\s*$//' -e 's/\$releasever/'$(rpm -q --queryformat '%{version}\n' centos-release)'/g' | sort | uniq); do
	key_file="$(echo ${repokeyurl} | sed -e 's%^.*/\([^/]*\)$%\1%')"
	if [ ! -f "/etc/pki/rpm-gpg/${key_file}" ]; then
		wget -P /etc/pki/rpm-gpg/ "${repokeyurl}"
	fi
done
# Disable automatic reporting by email
sed -i -e 's/^/#/' /etc/libreport/events.d/mailx_event.conf

# Disable SMARTd on a virtual machine
if dmidecode -s system-manufacturer | egrep -q "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	systemctl disable smartd
fi

# Configure Net-SNMP
cp -a /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.orig
cat << EOF > /etc/snmp/snmpd.conf
# Simple setup of Net-SNMP for traffic monitoring
rocommunity public
dontLogTCPWrappersConnects yes
EOF

# Enable Net-SNMP
systemctl enable snmpd

# Configure MRTG

# Configuration file customization through cfgmaker/indexmaker demanded to post-install rc.ks1stboot script

# Configure MRTG-Apache integration (allow access from everywhere)
sed -i -e 's/^\(\s*\)\(Require local.*\)$/\1Require all granted/' /etc/httpd/conf.d/mrtg.conf

# Configure Apache

# Note: using haveged to ensure enough entropy (but rngd could be already running from installation environment)
# Note: starting service manually since systemd inside a chroot would need special treatment
haveged -w 1024 -F &
haveged_pid=$!
# Prepare default (self-signed) certificate
openssl genrsa 2048 > /etc/pki/tls/private/localhost.key
cat << EOF | openssl req -new -sha256 -key /etc/pki/tls/private/localhost.key -x509 -days 3650 -out /etc/pki/tls/certs/localhost.crt
IT
Lombardia
Bergamo
FleurFlower
Heretic oVirt Project Demo Infrastructure
${HOSTNAME}
root@${HOSTNAME}
EOF
chmod 600 /etc/pki/tls/{private,certs}/localhost.*

# Create custom DH parameters
openssl dhparam -out /etc/pki/tls/dhparams.pem 2048
chmod 644 /etc/pki/tls/dhparams.pem
# Stopping haveged started above
kill ${haveged_pid}

# Configure Apache web service (disable certificate expiration warnings, do not advertise OS/Apache, disable default CGI directory and manual pages, create custom home page, disable TRACE/TRACK support, disable older/weakier protocols/crypto for SSL)
cat << EOF >> /etc/sysconfig/httpd

#
# To avoid periodic checking (with warning email) of certificates validity,
# set NOCERTWATCH here.
#
NOCERTWATCH="yes"

EOF

# Append custom DH parameters to our certificate file (needs httpd >= 2.2.15-32)
# Note: newer Apache versions allow specifying custom DH parameters with: SSLOpenSSLConfCmd DHParameters "/etc/pki/tls/dhparams.pem"
cat /etc/pki/tls/dhparams.pem >> /etc/pki/tls/certs/localhost.crt

sed -i -e 's/^ServerTokens.*$/ServerTokens ProductOnly/' -e 's/^ServerSignature.*$/ServerSignature Off\n\n#\n# Disable TRACE for PCI compliance\nTraceEnable off/' -e 's/^\(ScriptAlias.*\)$/#\1/' /etc/httpd/conf/httpd.conf
sed -i -e 's/^\(SSLProtocol.*\)$/#\1/' -e 's/^\(SSLCipherSuite.*\)$/#\1\n# Stricter settings for PCI compliance\nSSLProtocol all -SSLv2 -SSLv3\nSSLCipherSuite ALL:!EXP:!NULL:!ADH:!LOW:!RC4/' /etc/httpd/conf.d/ssl.conf

# Prepare home page
cat << EOF > /var/www/html/index.html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
	<head>
		<title>Database Server</title>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
		<style type="text/css">
			body {
				background-color: #fff;
				color: #000;
				font-size: 0.9em;
				font-family: sans-serif,helvetica;
				margin: 0;
				padding: 0;
			}
			:link {
				color: #0000FF;
			}
			:visited {
				color: #0000FF;
			}
			a:hover {
				color: #3399FF;
			}
			h1 {
				text-align: center;
				margin: 0;
				padding: 0.6em 2em 0.4em;
				background-color: #3399FF;
				color: #ffffff;
				font-weight: normal;
				font-size: 1.75em;
				border-bottom: 2px solid #000;
			}
			h1 strong {
				font-weight: bold;
			}
			h2 {
				font-size: 1.1em;
				font-weight: bold;
			}
			.content {
				padding: 1em 5em;
			}
			.content-columns {
				/* Setting relative positioning allows for
				absolute positioning for sub-classes */
				position: relative;
				padding-top: 1em;
			}
			.content-column-left {
				/* Value for IE/Win; will be overwritten for other browsers */
				width: 47%;
				padding-right: 3%;
				float: left;
				padding-bottom: 2em;
			}
			.content-column-right {
				/* Values for IE/Win; will be overwritten for other browsers */
				width: 47%;
				padding-left: 3%;
				float: left;
				padding-bottom: 2em;
			}
			.content-columns>.content-column-left, .content-columns>.content-column-right {
				/* Non-IE/Win */
			}
			img {
				border: 2px solid #fff;
				padding: 2px;
				margin: 2px;
			}
			a:hover img {
				border: 2px solid #3399FF;
			}
		</style>
	</head>

	<body>
	<h1><strong>Database server</strong></h1>

		<div class="content">
			<div class="content-columns">
				<div class="content-column-left">
					<h2>Avvertenza per gli utenti del servizio:</h2>
					<p>Questa macchina fornisce servizi di base dati.</p>
					<h2>Se siete parte del personale tecnico:</h2>
					<p>Le funzionalit&agrave; predisposte per l'amministrazione/controllo sono elencate di seguito.
					<ul>
						<li>Lo strumento web di amministrazione della macchina &egrave; disponibile <a href="/manage/">qui</a>.</li>
						<li>Lo strumento web di amministrazione del servizio &egrave; disponibile <a href="/sql/">qui</a>.</li>
						<li>Lo strumento web di visualizzazione dell'utilizzo rete &egrave; disponibile <a href="/mrtg/">qui</a>.</li>
						<li>Lo strumento web di visualizzazione dell'utilizzo http &egrave; disponibile <a href="/usage/">qui</a>.</li>
					</ul>
					</p>
				</div>

				<div class="content-column-right">
					<h2>End users notice:</h2>
					<p>This machine provides database services.</p>
					<h2>If you are a technical staff member:</h2>
					<p>The maintenance/administrative resources are listed below.
					<ul>
						<li>The server administration web tool is available <a href="/manage/">here</a>.</li>
						<li>The service administration web tool is available <a href="/sql/">here</a>.</li>
						<li>The server network utilization web tool is available <a href="/mrtg/">here</a>.</li>
						<li>The web server usage statistics are available <a href="/usage/">here</a>.</li>
					</ul>
					</p>
				</div>
			</div>
                </div>
</body>
</html>
EOF
chmod 644 /var/www/html/index.html

# Configure Webalizer (allow access from everywhere)
sed -i -e 's/^\(\s*\)\(Require local.*\)$/\1Require all granted/' /etc/httpd/conf.d/webalizer.conf

# Enable Webalizer
sed -i -e '/WEBALIZER_CRON=/s/^#*\(WEBALIZER_CRON=\).*$/\1yes/' /etc/sysconfig/webalizer

# Enable Apache
firewall-offline-cmd --add-service=http
systemctl enable httpd

# Configure Webmin
# Add "/manage/" location with forced redirect to port 10000 in Apache's configuration
cat << EOF > /etc/httpd/conf.d/webmin.conf
#
#  Apache-based redirection for Webmin
#

<Location /manage>
  RewriteEngine On
  RewriteRule ^.*\$ https://%{HTTP_HOST}:10000 [R,L]
  <IfModule mod_authz_core.c>
    # Apache 2.4
    Require all granted
  </IfModule>
  <IfModule !mod_authz_core.c>
    # Apache 2.2
    Order Deny,Allow
    Deny from all
    Allow from all
  </IfModule>
</Location>

EOF
chmod 644 /etc/httpd/conf.d/webmin.conf

# Configure Webmin to use a custom certificate
# TODO: use our own X.509 certificate (signed by our own CA)
cat /etc/pki/tls/private/localhost.key > /etc/webmin/miniserv.pem
cat /etc/pki/tls/certs/localhost.crt >> /etc/webmin/miniserv.pem

# Modify default setup
cat << EOF >> /etc/webmin/config
logfiles=1
logfullfiles=1
logtime=21900
logperms=
logsyslog=0
logusers=
logmodules=
logclear=1
hostnamemode=0
help_width=
dateformat=dd/mon/yyyy
showhost=0
nofeedbackcc=0
hostnamedisplay=
feedback_to=
sysinfo=0
texttitles=1
showlogin=0
help_height=
acceptlang=0
gotoone=1
gotomodule=
deftab=webmin
nohostname=0
notabs=0
realname=
noremember=1
EOF
sed -i -e 's/^logtime=.*$/logtime=21900/' /etc/webmin/miniserv.conf
cat << EOF >> /etc/webmin/miniserv.conf
no_resolv_myname=1
sockets=
login_script=/etc/webmin/login.pl
logout_script=/etc/webmin/logout.pl
logclf=0
logclear=1
loghost=0
pam_conv=
blockuser_time=
blocklock=
blockuser_failures=
no_pam=0
logouttime=10
utmp=
extracas=
certfile=
ssl_redirect=1
EOF

# Add firewalld configuration for Webmin
cat << EOF > /etc/firewalld/services/webmin.xml
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>webmin</short>
  <description>webmin is a web-based interface for system administration for unix.</description>
  <port protocol="tcp" port="10000"/>
</service>
EOF
chmod 644 /etc/firewalld/services/webmin.xml

# Enable Webmin
firewall-offline-cmd --add-service=webmin
systemctl enable webmin

# Conditionally enable MCE logging/management service
if dmidecode -s system-manufacturer | egrep -q -v "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	systemctl enable mcelog
fi

# TODO: Configure Bareos

# TODO: Enable Bareos
systemctl disable bareos-fd

# Configure database
# Note: initial database provisioning preformed by script created in pre section above and copied in third post section below
case "${dbtype}" in
	postgresql)
		# Configure firewall
		firewall-offline-cmd --add-service=postgresql

		# TODO: Customize PostgreSQL configuration

		# Disable PostgreSQL
		# Note: it needs manual initialization before starting
		systemctl disable postgresql-9.6

		# Enable access through phpPgAdmin
		# Note: further phpPgAdmin access control configuration performed in rc.db-provision script
		sed -i -e "/extra_login_security/s/true/false/" /etc/phpPgAdmin/config.inc.php
		;;
	mysql)
		# Configure firewall
		firewall-offline-cmd --add-service=mysql

		# Customize MySQL configuration
		# TODO: tune /etc/sysctl.conf (from ktune server profile?) for a dedicated host
		# TODO: evaluate whether to switch to latest Percona-specific conf/conf.d paths
		cat <<- EOF > /etc/my.cnf.d/local.cnf
		[mysqld]
		datadir=/var/lib/mysql
		socket=/var/lib/mysql/mysql.sock
		user=mysql
		# Disabling symbolic-links is recommended to prevent assorted security risks
		symbolic-links=0
		# Forcing MySQL to case insensitive behaviour (convert all database/table names to lowercase)
		lower_case_table_names=1
		# Compatibility with MySQL 3.x client libraries
		#old_passwords=1
		
		# Slow query logging
		#slow_query_log=1
		#long_query_time=0.03
		#min_examined_row_limit=0
		#log_queries_not_using_indexes
		#slow_query_log_file=/var/log/mysqld-slow.log
		
		# General settings
		key_buffer_size=16M
		thread_stack=192K
		query_alloc_block_size=16K
		tmp_table_size=64M
		max_heap_table_size=64M
		sort_buffer_size=8M
		join_buffer_size=8M
		thread_cache_size=16
		back_log=50
		max_connections=30
		max_connect_errors=9999999
		connect_timeout=15
		table_open_cache=8192
		
		# Query cache settings
		query_cache_size=64M
		query_cache_limit=2M
		
		# Logging and replication settings
		sync_binlog=1
		expire_logs_days=10
		max_binlog_size=100M
		binlog_cache_size=1M
		binlog_checksum=crc32
		bulk_insert_buffer_size=64M
		
		# MyISAM settings
		myisam_sort_buffer_size=128M
		myisam_max_sort_file_size=10G
		myisam_repair_threads=1
		
		# InnoDB settings
		innodb_buffer_pool_size=128M
		innodb_data_file_path=ibdata1:10M:autoextend
		innodb_file_per_table=true
		innodb_thread_concurrency=16
		innodb_flush_log_at_trx_commit=1
		innodb_fast_shutdown=1
		innodb_log_buffer_size=64M
		innodb_log_file_size=512M
		innodb_log_files_in_group=2
		innodb_max_dirty_pages_pct=80
		innodb_flush_method=O_DIRECT
		innodb_lock_wait_timeout=120
		innodb_checksum_algorithm=crc32
		
		# Configuration parameters from Percona Server 5.6 benchmark tuning
		#innodb_data_file_path=ibdata1:10M:autoextend
		#innodb_log_files_in_group=2
		#innodb_log_file_size=2G
		#innodb_buffer_pool_size=25GB
		#innodb_lru_scan_depth=4000
		#innodb_flush_neighbors=0
		#innodb_log_buffer_size=256M
		#innodb_io_capacity = 25000
		#innodb_io_capacity_max= 50000
		#innodb_flush_log_at_trx_commit = 1
		#innodb_buffer_pool_instances=15
		#innodb_file_format = Barracuda
		#innodb_checksum_algorithm = crc32
		#innodb_file_per_table = true
		#innodb_doublewrite=1
		#innodb_flush_method=O_DIRECT_NO_FSYNC
		#innodb_purge_threads=4
		#table_open_cache=15000
		#open_files_limit=15000
		#max_connections=15000
		#innodb_read_io_threads = 8
		#innodb_write_io_threads = 8
		#innodb_change_buffering=all
		#loose-innodb_sync_array_size=16
		#sync_binlog=0
		#query_cache_type=OFF
		#thread_cache_size=1000
		#back_log=2000
		#connect_timeout=15
		#loose-metadata_locks_hash_instances=256
		#max_prepared_stmt_count=1048560
		#loose-performance_schema=0
		## --- below is Percona Server Specific ---
		#innodb_sched_priority_cleaner=39
		#innodb_log_block_size=4096
		#innodb_adaptive_hash_index_partitions=65
		
		[mysqld_safe]
		log-error=/var/log/mysqld.log
		pid-file=/var/run/mysqld/mysqld.pid
		
		EOF
		chmod 644 /etc/my.cnf.d/local.cnf
		
		# Use our own X.509 certificate for Percona Server
		cat /etc/pki/tls/private/localhost.key > /var/lib/mysql/private_key.pem
		openssl rsa -in /etc/pki/tls/private/localhost.key -pubout > /var/lib/mysql/public_key.pem
		chown mysql:mysql /var/lib/mysql/{private,public}_key.pem
		chmod 440 /var/lib/mysql/{private,public}_key.pem
		
		# Add logrotate support for slow query logging
		# Note: Percona Server has the logrotate fragment named "mysql" instead of "mysqld"
		# Note: Percona Server has the log files under /var/lib/mysql instead of /var/log by default - modifying here to avoid SELinux errors in logrotate
		touch /var/log/mysqld.log
		chown mysql:mysql /var/log/mysqld.log
		restorecon -v /var/log/mysqld.log
		sed -i -e 's%^/var/lib/mysql/mysqld.log%/var/log/mysqld.log /var/log/mysqld-slow.log%' -e 's/^\(\s*\)postrotate.*$/\1sharedscripts\n\1postrotate/' /etc/logrotate.d/mysql
		
		# Enable access through phpMyAdmin
		# Note: further phpMyAdmin access control configuration performed in rc.db-provision script
		# Note: using haveged to ensure enough entropy (but rngd could be already running from installation environment)
		# Note: starting service manually since systemd inside a chroot would need special treatment
		haveged -w 1024 -F &
		haveged_pid=$!
		sed -i -e "s/^\\(.*blowfish_secret.*\\s*=\\s*\\).*\$/\\1'$(pwgen -1cns 40 1)';/" /etc/phpMyAdmin/config.inc.php
		# Stopping haveged started above
		kill ${haveged_pid}

		# Disable MySQL
		# Note: it needs manual initialization before starting
		systemctl disable mysqld
		;;
	firebird)
		# Configure firewall
		cat <<- EOF > /etc/firewalld/services/firebird.xml
		<?xml version="1.0" encoding="utf-8"?>
		<service>
		  <short>firebird</short>
		  <description>Firebird database server.</description>
		  <port protocol="tcp" port="3050"/>
		</service>
		EOF
		chmod 644 /etc/firewalld/services/firebird.xml
		firewall-offline-cmd --add-service=firebird
		
		# Prepare directory
		mkdir -p /tmp/firebird
		chown -R firebird:firebird /tmp/firebird

		# Enable Firebird
		systemctl enable firebird-superserver
		;;
	sqlserver)
		# Configure firewall
		cat <<- EOF > /etc/firewalld/services/mssql.xml
		<?xml version="1.0" encoding="utf-8"?>
		<service>
		  <short>MSSQL</short>
		  <description>SQLServer database server.</description>
		  <port protocol="tcp" port="1433"/>
		</service>
		EOF
		chmod 644 /etc/firewalld/services/mssql.xml
		firewall-offline-cmd --add-service=mssql

		# Configure path for SQLServer command-line tools
		cat <<- EOM > /etc/profile.d/mssql-tools.sh
		MSSQLTOOLS_BIN_DIR="/opt/mssql-tools/bin"

		if [ -z "\$(echo \${PATH} | grep -w \${MSSQLTOOLS_BIN_DIR})" ]; then
		        if [ -z "\${PATH}" ]; then
		                PATH="\${MSSQLTOOLS_BIN_DIR}"
		        else
		                PATH="\${PATH}:\${MSSQLTOOLS_BIN_DIR}"
		        fi
		fi

		export PATH
		EOM
		cat <<- EOM > /etc/profile.d/mssql-tools.csh
		set MSSQLTOOLS_BIN_DIR=/opt/mssql-tools/bin

		if ( "\${PATH}" !~ *\${MSSQLTOOLS_BIN_DIR}* ) then
		        if !(\$?PATH) then
		                setenv PATH \${MSSQLTOOLS_BIN_DIR}
		        else
		                setenv PATH \${PATH}:\${MSSQLTOOLS_BIN_DIR}
		        endif
		endif
		EOM
		chmod 644 /etc/profile.d/mssql-tools.*
		chown root:root /etc/profile.d/mssql-tools.*

		# Configure path for SQLServer Integration Services
		cat <<- EOM > /etc/profile.d/mssql-is.sh
		MSSQLIS_BIN_DIR="/opt/ssis/bin"

		if [ -z "\$(echo \${PATH} | grep -w \${MSSQLIS_BIN_DIR})" ]; then
		        if [ -z "\${PATH}" ]; then
		                PATH="\${MSSQLIS_BIN_DIR}"
		        else
		                PATH="\${PATH}:\${MSSQLIS_BIN_DIR}"
		        fi
		fi

		export PATH
		EOM
		cat <<- EOM > /etc/profile.d/mssql-is.csh
		set MSSQLIS_BIN_DIR=/opt/ssis/bin

		if ( "\${PATH}" !~ *\${MSSQLIS_BIN_DIR}* ) then
		        if !(\$?PATH) then
		                setenv PATH \${MSSQLIS_BIN_DIR}
		        else
		                setenv PATH \${PATH}:\${MSSQLIS_BIN_DIR}
		        endif
		endif
		EOM
		chmod 644 /etc/profile.d/mssql-is.*
		chown root:root /etc/profile.d/mssql-is.*

		# Disable SQLServer
		# Note: it needs manual initialization before starting
		systemctl disable mssql-server
		;;
esac

# Configure root home dir (with utility script for basic configuration backup)
mkdir -p /root/{etc,bin,log,tmp,backup}
cat << EOF > /root/bin/backup-conf
#!/bin/bash
tar -czf /root/backup/\$(hostname)-\$(date '+%Y-%m-%d')-conf.tar.gz \$(cat /root/etc/backup.list)
EOF
chmod 755 /root/bin/backup-conf
cat << EOF > /root/etc/backup.list
/boot/grub2
/etc
/var/www/html
/usr/local/bin
/usr/local/sbin
/usr/local/etc
/root/bin
/root/etc
/root/log
/root/.[^ekmn]?*
EOF
# Initialize administration log journal
cat << EOF > /root/log/sysadm.log
$(date '+%Y/%m/%d')
*) installed $(lsb_release -i -r -s) $(uname -m) from kickstart

EOF

# Set up "first-boot" configuration script (steps that require a fully up system)
cat << EOF > /etc/rc.d/rc.ks1stboot
#!/bin/bash

# Conditionally enable either IPMI or LMsensors monitoring
# TODO: configure IPMI options
# TODO: find a way to ignore partial IPMI implementations (e.g. those needing a [missing] add-on card)
if dmidecode -s system-manufacturer | egrep -q -v "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	if dmidecode --type 38 | grep -q 'IPMI' ; then
		systemctl enable ipmi
		systemctl enable ipmievd
		systemctl start ipmi
		systemctl start ipmievd
	else
		systemctl enable lm_sensors
		yes yes | sensors-detect
		systemctl start lm_sensors
	fi
fi

# Setup virtualization tools (Hyper-V/KVM/VMware/VirtualBox/Parallels supported)
# TODO: Verify that VirtIO drivers get used for Xen/KVM, warn otherwise
# TODO: disable kernel updating or configure dkms (if not already done above or by tools installation)
pushd /tmp
need_reboot="no"
if dmidecode -s system-manufacturer | grep -q "Microsoft" ; then
	# TODO: configure Hyper-V integration agents
	systemctl enable hypervkvpd hypervvssd hypervfcopyd
	systemctl start hypervkvpd hypervvssd hypervfcopyd
elif dmidecode -s system-manufacturer | grep -q 'Xen' ; then
	# Enable ARP notifications for vm migrations
	cat <<- EOM > /etc/sysctl.d/99-xen-guest.conf
	net.ipv4.conf.all.arp_notify=1
	EOM
	chmod 644 /etc/sysctl.d/99-xen-guest.conf
	sysctl -p
	wget https://dangerous.ovirt.life/support/Xen/xe-guest-utilities*.rpm
	yum -y --nogpgcheck install ./xe-guest-utilities*.rpm
	rm -f xe-guest-utilities*.rpm
elif dmidecode -s system-manufacturer | grep -q "VMware" ; then
	# Note: VMware basic support uses distro-provided packages installed during post phase
	# Note: using vmware-hgfsclient (already part of open-vm-tools) for shared folders support
	shared_folders="\$(vmware-hgfsclient)"
	if [ -z "\${shared_folders}" ]; then
		cat <<- EOM >> /etc/fstab
		# Template line to activate boot-mounted shared folders
		#.host:/Test	/mnt/hgfs/Test	fuse.vmhgfs-fuse	allow_other,auto_unmount,defaults	0 0
		EOM
	else
		for shared_folder in \${shared_folders} ; do
			mkdir -p "/mnt/hgfs/\${shared_folder}"
			cat <<- EOM >> /etc/fstab
			.host:/\${shared_folder}	/mnt/hgfs/\${shared_folder}	fuse.vmhgfs-fuse	allow_other,auto_unmount,defaults	0 0
			EOM
		done
	fi
	need_reboot="no"
elif dmidecode -s system-manufacturer | grep -q "innotek" ; then
	wget https://dangerous.ovirt.life/support/VirtualBox/VBoxLinuxAdditions.run
	chmod a+rx VBoxLinuxAdditions.run
	./VBoxLinuxAdditions.run --nox11
	usermod -a -G vboxsf mwtouser
	rm -f VBoxLinuxAdditions.run
	need_reboot="yes"
elif dmidecode -s system-manufacturer | grep -q "Parallels" ; then
	wget https://dangerous.ovirt.life/support/Parallels/ParallelsTools.tar.gz | tar xzf -
	pushd parallels-tools-distrib
	./install --install-unattended-with-deps
	popd
	rm -rf parallels-tools-distrib
	need_reboot="yes"
elif dmidecode -s system-manufacturer | grep -q "Red.*Hat" ; then
	# TODO: configure Qemu agent
	systemctl enable qemu-guest-agent
	systemctl start qemu-guest-agent
elif dmidecode -s system-manufacturer | grep -q "oVirt" ; then
	# TODO: configure oVirt agent
	systemctl enable qemu-guest-agent ovirt-guest-agent
	systemctl start qemu-guest-agent ovirt-guest-agent
fi
popd
# Note: CentOS 7 persistent net device naming means that MAC addresses are not statically registered by default anymore

# Initialize MRTG configuration (needs Net-SNMP up)
# TODO: add CPU/RAM/disk/etc. resource monitoring
cfgmaker --output /etc/mrtg/mrtg.cfg --global "HtmlDir: /var/www/mrtg" --global "ImageDir: /var/www/mrtg" --global "LogDir: /var/lib/mrtg" --global "ThreshDir: /var/lib/mrtg" --no-down --zero-speed=1000000000 --if-filter='(\$default && \$if_is_ethernet)' public@localhost

# Set execution mode parameters
# Note: on CentOS7 MRTG is preferably configured as an always running service (for efficiency reasons)
sed -i -e '/Global Config Options/s/^\\(.*\\)\$/\\1\\nRunAsDaemon: Yes\\nInterval: 5\\nNoDetach: Yes/' /etc/mrtg/mrtg.cfg

# Setup MRTG index page
indexmaker --output=/var/www/mrtg/index.html /etc/mrtg/mrtg.cfg

# Enable MRTG
# Note: MRTG is an always running service (for efficiency reasons) now
systemctl --now enable mrtg

EOF

# Saving installation instructions
# Note: done in rc.ks1stboot since this seems to get created after all post scripts are run
# TODO: something tries to load /root/anaconda-ks.cfg - find out what/why - seems related to https://bugzilla.redhat.com/show_bug.cgi?id=1213114
# TODO: it seems that a side effect of not moving it is the unconditional execution of the graphical firstboot phase - restoring file moving as a workaround
# TODO: it seems that the graphical firstboot phase happens anyway and at the end creates a /root/initial-ks.cfg
cat << EOF >> /etc/rc.d/rc.ks1stboot
mv /root/*-ks.cfg /root/etc
EOF

cat << EOF >> /etc/rc.d/rc.ks1stboot

# Run dynamically determined users configuration actions
if [ -x /etc/rc.d/rc.users-setup ]; then
	/etc/rc.d/rc.users-setup
fi

# Run AD domain joining script
if [ -x /etc/rc.d/rc.domain-join ]; then
	/etc/rc.d/rc.domain-join
fi

# Run database provisioning actions
if [ -x /etc/rc.d/rc.db-provision ]; then
	/etc/rc.d/rc.db-provision
fi

# Disable further executions of this script from systemd
systemctl disable ks1stboot.service

# Perform reboot after virtualization tools installation
if [ "\${need_reboot}" = "yes" ]; then
	shutdown -r +1
	# Note: the command above exits immediately - wait for the most part of the remaining minute
	sleep 57
fi

exit 0
EOF
chmod 750 /etc/rc.d/rc.ks1stboot
# Prepare first-boot execution through systemd
# TODO: find a way to actually block logins till this unit exits
cat << EOF > /etc/systemd/system/ks1stboot.service
[Unit]
Description=Post Kickstart first boot configurations
After=network.target network.service
Requires=network.target network.service
Before=getty.target sshd.service display-manager.service

[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=/usr/bin/bash -c '/etc/rc.d/rc.ks1stboot > /root/log/rc.ks1stboot.log 2>&1'

[Install]
RequiredBy=getty.target sshd.service display-manager.service
EOF
chmod 644 /etc/systemd/system/ks1stboot.service
systemctl enable ks1stboot.service

# TODO: forcibly disable execution of graphical firstboot tool - kickstart directive on top seems to be ignored and moving away anaconda-ks.cfg isn't enough - remove when fixed upstream - see https://bugzilla.redhat.com/show_bug.cgi?id=1213114
systemctl mask firstboot-graphical
systemctl mask initial-setup-graphical
systemctl mask initial-setup-text
systemctl mask initial-setup

) 2>&1 | tee /root/kickstart_post.log
%end

# Post-installation script (run with bash from installation image after the second post section)
%post --nochroot
# Append hosts fragment (generated in pre section above) into installed system
if [ -s /tmp/hvp-bind-zones/hosts ]; then
	cat /tmp/hvp-bind-zones/hosts >> ${ANA_INSTALL_PATH}/etc/hosts
fi

# Copy NTPdate configuration file (generated in pre section above) into installed system
if [ -s /tmp/hvp-ntpd-conf/step-tickers ]; then
	cat /tmp/hvp-ntpd-conf/step-tickers > ${ANA_INSTALL_PATH}/etc/ntp/step-tickers
	chmod 644 ${ANA_INSTALL_PATH}/etc/ntp/step-tickers
	chown root:root ${ANA_INSTALL_PATH}/etc/ntp/step-tickers
fi

# Append Chrony configuration fragment (generated in pre section above) into installed system
# Note: if we specify additional Chrony configuration, then all default servers get disabled
if [ -s /tmp/hvp-ntpd-conf/chrony.conf ]; then
	sed -i -e '/^server\s/s/^/#/g' ${ANA_INSTALL_PATH}/etc/chrony.conf
	cat /tmp/hvp-ntpd-conf/chrony.conf >> ${ANA_INSTALL_PATH}/etc/chrony.conf
fi

# Copy users setup script (generated in pre section above) into installed system
if [ -f /tmp/hvp-users-conf/rc.users-setup ]; then
	cp /tmp/hvp-users-conf/rc.users-setup ${ANA_INSTALL_PATH}/etc/rc.d/rc.users-setup
	chmod 755 ${ANA_INSTALL_PATH}/etc/rc.d/rc.users-setup
	chown root:root ${ANA_INSTALL_PATH}/etc/rc.d/rc.users-setup
fi

# Copy AD domain joining script (generated in pre section above) into installed system
if [ -s /tmp/hvp-domain-join/rc.domain-join ]; then
	cp /tmp/hvp-domain-join/rc.domain-join ${ANA_INSTALL_PATH}/etc/rc.d/rc.domain-join
	# Note: cleartext passwords contained - must restrict access
	chmod 700 ${ANA_INSTALL_PATH}/etc/rc.d/rc.domain-join
	chown root:root ${ANA_INSTALL_PATH}/etc/rc.d/rc.domain-join
fi

# Copy database configuration script (generated in pre section above) into installed system
if [ -s /tmp/hvp-db-conf/rc.db-provision ]; then
	cp /tmp/hvp-db-conf/rc.db-provision ${ANA_INSTALL_PATH}/etc/rc.d/rc.db-provision
	# Note: cleartext passwords contained - must restrict access
	chmod 700 ${ANA_INSTALL_PATH}/etc/rc.d/rc.db-provision
	chown root:root ${ANA_INSTALL_PATH}/etc/rc.d/rc.db-provision
fi

# Copy TCP wrappers configuration (generated in pre section above) into installed system
if [ -f /tmp/hvp-tcp_wrappers-conf/hosts.allow ]; then
	cat /tmp/hvp-tcp_wrappers-conf/hosts.allow >> ${ANA_INSTALL_PATH}/etc/hosts.allow
fi

# TODO: perform NetworkManager workaround configuration on interfaces as detected in pre section above - remove when fixed upstream
for file in /tmp/hvp-networkmanager-conf/ifcfg-* ; do
	if [ -f "${file}" ]; then
		cfg_file_name=$(basename "${file}")
		sed -i -e '/^DEFROUTE=/d' -e '/^MTU=/d' "${ANA_INSTALL_PATH}/etc/sysconfig/network-scripts/${cfg_file_name}"
		cat "${file}" >> "${ANA_INSTALL_PATH}/etc/sysconfig/network-scripts/${cfg_file_name}"
	fi
done

# Save exact pre-stage environment
if [ -f /tmp/pre.out ]; then
	cp /tmp/pre.out ${ANA_INSTALL_PATH}/root/log/pre.out
fi
# Save exact post-stage environment
if [ -f ${ANA_INSTALL_PATH}/tmp/post.out ]; then
	cp ${ANA_INSTALL_PATH}/tmp/post.out ${ANA_INSTALL_PATH}/root/log/post.out
fi
# Save installation instructions/logs
# Note: installation logs are now saved under /var/log/anaconda/ by default
cp /run/install/ks.cfg ${ANA_INSTALL_PATH}/root/etc
for full_frag in /tmp/full-* ; do
	if [ -f "${full_frag}" ]; then
		cp "${full_frag}" ${ANA_INSTALL_PATH}/root/etc
	fi
done
cp /tmp/kickstart_pre.log ${ANA_INSTALL_PATH}/root/log
mv ${ANA_INSTALL_PATH}/root/kickstart_post.log ${ANA_INSTALL_PATH}/root/log
%end

# Post-installation script (run with bash from chroot after the third post section)
%post
# Relabel filesystem
# This has to be the last post action to catch any files we've created/modified
# TODO: verify whether the following is actually needed (latest Anaconda seems to perform a final relabel anyway)
setfiles -F -e /proc -e /sys -e /dev -e /selinux /etc/selinux/targeted/contexts/files/file_contexts /
setfiles -F /etc/selinux/targeted/contexts/files/file_contexts.homedirs /home/ /root/
%end
