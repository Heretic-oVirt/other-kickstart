# Kickstart file for remote desktop server
# Note: minimum amount of RAM successfully tested for installation: 2048 MiB from network - 1024 MiB from local media

# Install with commandline (see below for comments):
# TODO: check each and every custom "hvp_" parameter below for overlap with default dracut/anaconda parameters and convert to using those instead
# elevator=deadline inst.ks=https://dangerous.ovirt.life/hvp-repos/el7/ks/hvp-vd-c7.ks
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
# Note: to force custom multi-instance limit for each vm type (kickstart) add hvp_maxinstances=A where A is the maximum number of instances
# Note: to force custom AD subdomain naming add hvp_ad_subdomainname=myprefix where myprefix is the subdomain name
# Note: to force custom domain action add hvp_joindomain=bool where bool is either "true" (join an AD domain) or "false" (do not join an AD domain)
# Note: to force custom AD DC naming add hvp_dcname=mydcname where mydcname is the unqualified (ie without domain name part) hostname of the AD DC
# Note: to force custom desktop type add hvp_detype=eeee where eeee is the desktop type (either gnome, kde, xfce or lxde)
# Note: to force custom desktop DB type add hvp_dedbtype=uuuu where uuuu is the desktop DB type (either sqlite or postgresql)
# Note: to force custom DB server naming add hvp_dbname=mydbname where mydbname is the unqualified (ie without domain name part) hostname of the DB server
# Note: to force custom Web server naming add hvp_webname=mywebname where mywebname is the unqualified (ie without domain name part) hostname of the Web server
# Note: to force custom nameserver IP add hvp_nameserver=w.w.w.w where w.w.w.w is the nameserver IP
# Note: to force custom gateway IP add hvp_gateway=n.n.n.n where n.n.n.n is the gateway IP
# Note: to force custom root password add hvp_rootpwd=mysecret where mysecret is the root user password
# Note: to force custom admin username add hvp_adminname=myadmin where myadmin is the admin username
# Note: to force custom admin password add hvp_adminpwd=myothersecret where myothersecret is the admin user password
# Note: to force custom email address for notification receiver add hvp_receiver_email=name@domain where name@domain is the email address
# Note: to force custom AD further admin username add hvp_winadminname=mywinadmin where mywinadmin is the further AD admin username
# Note: to force custom AD further admin password add hvp_winadminpwd=mywinothersecret where mywinothersecret is the further AD admin user password
# Note: to force custom keyboard layout add hvp_kblayout=cc where cc is the country code
# Note: to force custom local timezone add hvp_timezone=VV where VV is the timezone specification
# Note: the default behaviour does not register fixed nic name-to-MAC mapping
# Note: the default host naming uses the "My Little Pony" character name grannysmith
# Note: the default addressing on connected networks is assumed to be 172.20.{10,12}.0/24 on {mgmt,lan}
# Note: the default MTU is assumed to be 1500 on {mgmt,lan}
# Note: the default machine IPs are assumed to be the 240th IPs available (network address + 240) on each connected network
# Note: the default domain names are assumed to be {mgmt,lan}.private
# Note: the default multi-instance limit is assumed to be 9
# Note: the default AD subdomain name is assumed to be ad
# Note: the default domain action is "false" (do not join an AD domain)
# Note: the default AD DC naming uses the "My Little Pony" character name spike for the AD DC
# Note: the default desktop type is gnome
# Note: the default desktop DB type is sqlite
# Note: the default DB server naming uses the "My Little Pony" character name bigmcintosh for the DB server
# Note: the default Web server naming uses the "My Little Pony" character name cheerilee for the Web server
# Note: the default nameserver IP is assumed to be 8.8.8.8
# Note: the default gateway IP is assumed to be equal to the test IP on the mgmt network
# Note: the default root user password is HVP_dem0
# Note: the default admin username is hvpadmin
# Note: the default admin user password is HVP_dem0
# Note: the default notification email address for receiver is monitoring@localhost
# Note: the default AD further admin username is the same as the admin username with the string "ad" prefixed
# Note: the default AD further admin user password is HVP_dem0
# Note: the default keyboard layout is us
# Note: the default local timezone is UTC
# Note: to work around a known kernel commandline length limitation, all hvp_* parameters above can be omitted and proper default values (overriding the hardcoded ones) can be placed in Bash-syntax variables-definition files placed alongside the kickstart file - the name of the files retrieved and sourced (in the exact order) is: hvp_parameters.sh hvp_parameters_vd.sh hvp_parameters_hh:hh:hh:hh:hh:hh.sh (where hh:hh:hh:hh:hh:hh is the MAC address of the nic used to retrieve the kickstart file)

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
@network-file-system-client
@gnome-desktop
@graphics
@graphical-admin-tools
@multimedia
@print-client
@office-suite
libreoffice-base
@x11
xorg-x11-server-Xorg
xorg-x11-drivers
-gnome-boxes
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
firefox
nss-tools
patch
expect
ksh
ncompress
libnl
redhat-lsb
vim-X11
tigervnc
tigervnc-server
freerdp
xterm
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
unset ad_dc_name
unset detype
unset dedbtype
unset db_name
unset web_name
unset reverse_domain_name
unset test_ip
unset test_ip_offset
unset my_ip_offset
unset multi_instance_max
unset my_name
unset my_nameserver
unset my_gateway
unset root_password
unset admin_username
unset admin_password
unset notification_receiver
unset winadmin_username
unset winadmin_password
unset keyboard_layout
unset local_timezone

# Hardcoded defaults

nicmacfix="false"

ad_dc_name="spike"

db_name="bigmcintosh"

web_name="cheerilee"

detype="gnome"
dedbtype="sqlite"

# Note: IP offsets below get used to automatically derive IP addresses
# Note: no need to allow offset overriding from commandline if the IP address itself can be specified

# Note: the following can be overridden from commandline
test_ip_offset="1"

my_ip_offset="240"

multi_instance_max="9"

declare -A network netmask network_base mtu
network['mgmt']="172.20.10.0"
netmask['mgmt']="255.255.255.0"
network_base['mgmt']="172.20.10"
mtu['mgmt']="1500"
network['lan']="172.20.12.0"
netmask['lan']="255.255.255.0"
network_base['lan']="172.20.12"
mtu['lan']="1500"
network['internal']="172.20.13.0"
netmask['internal']="255.255.255.0"
network_base['internal']="172.20.13"
mtu['internal']="1500"

declare -A domain_name
domain_name['mgmt']="mgmt.private"
domain_name['lan']="lan.private"
domain_name['internal']="internal.private"

ad_subdomain_prefix="ad"

domain_join="false"

declare -A reverse_domain_name
reverse_domain_name['mgmt']="10.20.172.in-addr.arpa"
reverse_domain_name['lan']="12.20.172.in-addr.arpa"
reverse_domain_name['internal']="13.20.172.in-addr.arpa"

declare -A test_ip
# Note: default values for test_ip derived below - defined here to allow loading as configuration parameters

my_nameserver="8.8.8.8"

my_name="grannysmith"

# Note: passwords must meet the AD complexity requirements
root_password="HVP_dem0"
admin_username="hvpadmin"
admin_password="HVP_dem0"
winadmin_password="HVP_dem0"
keyboard_layout="us"
local_timezone="UTC"

notification_receiver="monitoring@localhost"

# Detect any configuration fragments and load them into the pre environment
# Note: incomplete (no device or filename), BIOS based devices, UUID, file and DHCP methods are unsupported
ks_custom_frags="hvp_parameters.sh hvp_parameters_vd.sh"
mkdir /tmp/kscfg-pre
mkdir /tmp/kscfg-pre/mnt
ks_source="$(cat /proc/cmdline | sed -n -e 's/^.*\s*inst\.ks=\(\S*\)\s*.*$/\1/p')"
if [ -z "${ks_source}" ]; then
	# Note: if we are here and no Kickstart has been explicitly specified, then it must have been found by OEMDRV method (needs CentOS >= 7.2)
	ks_source='hd:LABEL=OEMDRV'
fi
if [ -n "${ks_source}" ]; then
	ks_dev=""
	if echo "${ks_source}" | grep -q '^floppy' ; then
		# Note: hardcoded device name for floppy disk
		ks_dev="/dev/fd0"
		# Note: filesystem type on floppy disk autodetected
		ks_fstype="*"
		ks_fsopt="ro"
		ks_path="$(echo ${ks_source} | awk -F: '{print $2}')"
		if [ -z "${ks_path}" ]; then
			ks_path="/ks.cfg"
		fi
		ks_dir="$(echo ${ks_path} | sed -e 's%/[^/]*$%%')"
	elif echo "${ks_source}" | grep -q '^cdrom' ; then
		# Note: cdrom gets accessed as real device name which must be detected - assuming it is the first removable device
		# Note: hardcoded possible device names for CD/DVD - should cover all reasonable cases
		# Note: on RHEL>=6 even IDE/ATAPI devices have SCSI device names
		for dev in /dev/sd[a-z] /dev/sr[0-9]; do
			if [ -b "${dev}" ]; then
				is_removable="$(cat /sys/block/$(basename ${dev})/removable 2>/dev/null)"
				if [ "${is_removable}" = "1" ]; then
					ks_dev="${dev}"
					ks_fstype="iso9660"
					ks_fsopt="ro"
					ks_path="$(echo ${ks_source} | awk -F: '{print $2}')"
					if [ -z "${ks_path}" ]; then
						ks_path="/ks.cfg"
						ks_dir="/"
					else
						ks_dir="$(echo ${ks_path} | sed -e 's%/[^/]*$%%')"
					fi
					break
				fi
			fi
		done
	elif echo "${ks_source}" | grep -q '^hd:' ; then
		# Note: blindly extracting device name from Kickstart commandline
		ks_spec="$(echo ${ks_source} | awk -F: '{print $2}')"
		ks_dev="/dev/${ks_spec}"
		# Detect LABEL-based device selection
		if echo "${ks_spec}" | grep -q '^LABEL=' ; then
			ks_label="$(echo ${ks_spec} | awk -F= '{print $2}')"
			if [ -z "${ks_label}" ]; then
				echo "Invalid definition of Kickstart labeled device" 1>&2
				ks_dev=""
			else
				ks_dev=/dev/$(lsblk -r -n -o name,label | awk "/\\<$(echo ${ks_label} | sed -e 's%\([./*\\]\)%\\\1%g')\\>/ {print \$1}" | head -1)
			fi
		fi
		# Note: filesystem type on local drive autodetected
		ks_fstype="*"
		ks_fsopt="ro"
		ks_path="$(echo ${ks_source} | awk -F: '{print $3}')"
		if [ -z "${ks_path}" ]; then
			ks_path="/ks.cfg"
			ks_dir="/"
		else
			ks_dir="$(echo ${ks_path} | sed -e 's%/[^/]*$%%')"
		fi
	elif echo "${ks_source}" | grep -q '^nfs:' ; then
		# Note: blindly extracting NFS server from Kickstart commandline
		ks_host="$(echo ${ks_source} | awk -F: '{print $2}')"
		ks_fstype="nfs"
		# TODO: support NFS options
		ks_fsopt="ro,nolock"
		ks_path="$(echo ${ks_source} | awk -F: '{print $3}')"
		if [ -z "${ks_path}" ]; then
			echo "Unable to determine Kickstart NFS source path" 1>&2
			ks_dev=""
		else
			ks_dev="${ks_host}:$(echo ${ks_path} | sed -e 's%/[^/]*$%%')}"
			ks_dir="/"
		fi
	elif echo "${ks_source}" | egrep -q '^(http|https|ftp):' ; then
		# Note: blindly extracting URL from Kickstart commandline
		ks_host="$(echo ${ks_source} | sed -e 's%^.*//%%' -e 's%/.*$%%')"
		ks_dev="$(echo ${ks_source} | sed -e 's%/[^/]*$%%')"
		ks_fstype="url"
	else
		echo "Unsupported Kickstart source detected" 1>&2
	fi
	if [ -z "${ks_dev}" ]; then
		echo "Unable to extract Kickstart source - skipping configuration fragments retrieval" 1>&2
	else
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
			# Note: filesystem type autodetected
			mount -o ${ks_fsopt} ${ks_dev} /tmp/kscfg-pre/mnt
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

# Determine notification receiver email address
given_receiver_email=$(sed -n -e "s/^.*hvp_receiver_email=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
if [ -n "${given_receiver_email}" ]; then
	notification_receiver="${given_receiver_email}"
fi

# Determine hostname
given_hostname=$(sed -n -e 's/^.*hvp_myname=\(\S*\).*$/\1/p' /proc/cmdline)
if echo "${given_hostname}" | grep -q '^[[:alnum:]]\+$' ; then
	my_name="${given_hostname}"
fi

# Determine multi-instance limit
given_multi_instance_max=$(sed -n -e 's/^.*hvp_maxinstances=\(\S*\).*$/\1/p' /proc/cmdline)
if echo "${given_multi_instance_max}" | grep -q '^[[:digit:]]\+$' ; then
	multi_instance_max="${given_multi_instance_max}"
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

# Determine AD DC name
given_dcname=$(sed -n -e 's/^.*hvp_dcname=\(\S*\).*$/\1/p' /proc/cmdline)
if echo "${given_dcname}" | grep -q '^[[:alnum:]]\+$' ; then
	ad_dc_name="${given_dcname}"
fi

# Determine DB server name
given_dbname=$(sed -n -e 's/^.*hvp_dbname=\(\S*\).*$/\1/p' /proc/cmdline)
if echo "${given_dbname}" | grep -q '^[[:alnum:]]\+$' ; then
	db_name="${given_dbname}"
fi

# Determine Web server name
given_webname=$(sed -n -e 's/^.*hvp_webname=\(\S*\).*$/\1/p' /proc/cmdline)
if echo "${given_webname}" | grep -q '^[[:alnum:]]\+$' ; then
	web_name="${given_webname}"
fi

# Determine desktop type
given_detype=$(sed -n -e 's/^.*hvp_detype=\(\S*\).*$/\1/p' /proc/cmdline)
case "${given_detype}" in
	gnome|kde|xfce|lxde)
		detype="${given_detype}"
		;;
esac

# Determine desktop DB type
given_dedbtype=$(sed -n -e 's/^.*hvp_dedbtype=\(\S*\).*$/\1/p' /proc/cmdline)
case "${given_dedbtype}" in
	sqlite|postgresql)
		dedbtype="${given_dedbtype}"
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

# Disable any interface configured by NetworkManager
# Note: NetworkManager may interfer with interface assignment autodetection logic below
# Note: interfaces will be explicitly activated again by our dynamically created network configuration fragment
for nic_device_name in $(nmcli -t device show | awk -F: '/^GENERAL\.DEVICE:/ {print $2}' | egrep -v '^(bonding_masters|lo|sit[0-9])$' | sort); do
	if nmcli -t device show "${nic_device_name}" | grep -q '^GENERAL\.STATE:.*(connected)' ; then
		nmcli device disconnect "${nic_device_name}"
		ip addr flush dev "${nic_device_name}"
		ip link set mtu 1500 dev "${nic_device_name}"
	fi
done
for connection_name in $(nmcli -t connection show | awk -F: '{print $1}' | sort); do
	nmcli connection delete "${connection_name}"
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
			# Perform duplicate IP detection and increment IP till it is unique
			tentative_ip_found="false"
			for ((ip_increment=0;ip_increment<=${multi_instance_max};ip_increment=ip_increment+1)); do
				tentative_ip=$(ipmat ${my_ip[${zone}]} ${ip_increment} +)
				if arping -q -c 2 -w 3 -D -I ${nic_name} ${tentative_ip} ; then
					# No collision detected: try to use this IP address
					tentative_ip_found="true"
					break
				fi
			done
			if [ "${tentative_ip_found}" = "false" ]; then
				# All IP addresses already taken - skip
				continue
			fi
			ip addr add "${tentative_ip}/${PREFIX}" dev "${nic_name}"
			res=$?
			if [ ${res} -ne 0 ] ; then
				# There has been a problem in assigning the IP address - skip
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
				# Note: we keep IP addresses aligned on all zones
				# Note: IP/name coherence check and correction demanded to post-install rc.ks1stboot script
				for zone_to_align in "${!network[@]}" ; do
					my_ip[${zone_to_align}]=$(ipmat ${my_ip[${zone_to_align}]} ${ip_increment} +)
				done
				ip addr flush dev "${nic_name}"
				ip link set mtu 1500 dev "${nic_name}"
				break
			fi
			ip addr flush dev "${nic_name}"
			ip link set mtu 1500 dev "${nic_name}"
		done
		if [ "${nic_assigned}" = "false" ]; then
			# Disable unassignable nics
			nics['unused']="${nics['unused']} ${nic_name}"
		fi
	else
		# Disable unconnected nics
		nics['unused']="${nics['unused']} ${nic_name}"
	fi
done

# TODO: Perform nic connections consistency check
# TODO: either offer service on all networks or keep mgmt as trusted if there is at least another one

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
if [ -n "${nics['mgmt']}" ]; then
	my_zone="mgmt"
elif [ -n "${nics['lan']}" ]; then
	my_zone="lan"
elif [ -n "${nics['internal']}" ]; then
	my_zone="internal"
fi
if [ -z "${my_gateway}" ]; then
	my_gateway="${test_ip[${my_zone}]}"
fi

# Create network setup fragment
# Note: dynamically created here to make use of full autodiscovery above
# Note: defining statically configured access to autodetected networks
# Note: listing interfaces using reverse alphabetical order for networks (results in: mgmt, lan, internal)
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
		# Add hostname option on the trusted zone only
		if [ "${zone}" = "${my_zone}" ]; then
			if [ "${domain_join}" = "true" ]; then
				further_options="${further_options} --hostname=${my_name}.${ad_subdomain_prefix}.${domain_name[${zone}]}"
			else
				further_options="${further_options} --hostname=${my_name}.${domain_name[${zone}]}"
			fi
		fi
		# Single (plain) interface
		# TODO: support multiple interfaces per zone (mainly for the physical machine case) - introduce bondopts for each zone
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
# Note: demanded to post section to allow for preconfigured default settings
#user --name=${admin_username} --password=${admin_password} --plaintext --gecos=Admin
EOF
# Prepare users configuration script to be run at first boot
mkdir -p /tmp/hvp-users-conf
cat << EOF > /tmp/hvp-users-conf/rc.users-setup
#!/bin/bash
# Create local user for maintenance work
# Note: unprivileged user created here to account for default settings
useradd -c "Admin" ${admin_username}
echo '${admin_password}' | passwd --stdin ${admin_username}
if [ "${domain_join}" != "true" ]; then
	# Add user to wheel group to allow liberal use of sudo
	usermod -a -G wheel ${admin_username}
fi

# Note: if not joined to AD then all local users can login

# Configure email aliases
# Divert root email to administrative account
sed -i -e "s/^#\\\\s*root.*\\\$/root:\\\\t\\\\t${admin_username}/" /etc/aliases
# Divert local notification emails to administrative account
if echo "${notification_receiver}" | grep -q '@localhost\$' ; then
	alias=\$(echo "${notification_receiver}" | sed -e 's/@localhost\$//')
	cat <<- EOM >> /etc/aliases
	
	# Email alias for server monitoring
	\${alias}:	${admin_username}
	
	EOM
	newaliases
fi
EOF

# Create localization setup fragment
# TODO: allow changing system language too
if [ "${keyboard_layout}" != "us" ]; then
	# TODO: GNOME3 seems not to respect the keyboard layout preference order (US is always the default) - even when removing additional layout
	xlayouts="'${keyboard_layout}','us'"
else
	xlayouts="'us'"
fi
cat << EOF > /tmp/full-localization
# Default system language, additional languages can be enabled installing the appropriate packages below
lang en_US.UTF-8
# Keyboard layout
keyboard --vckeymap=${keyboard_layout} --xlayouts=${xlayouts}
# Configure time zone (NTP details demanded to post section)
timezone ${local_timezone} --isUtc
EOF

# Create disk setup fragment
# TODO: find a better way to detect emulated/VirtIO devices
all_devices="$(list-harddrives | egrep -v '^(fd|sr)[[:digit:]]*[[:space:]]' | awk '{print $1}' | sort)"
in_use_devices=$(mount | awk '/^\/dev/ {print gensub("/dev/","","g",$1)}')
kickstart_device=$(echo "${ks_dev}" | sed -e 's%^/dev/%%')
if [ -b /dev/vda ]; then
	disk_device_name="vda"
elif [ -b /dev/xvda ]; then
	disk_device_name="xvda"
else
	disk_device_name="sda"
fi
cat << EOF > /tmp/full-disk
# Simple disk configuration: single SCSI/SATA/VirtIO disk
# Initialize partition table (GPT) on selected disk
clearpart --drives=${disk_device_name} --all --initlabel --disklabel=gpt
# Bootloader placed on MBR, with 3 seconds waiting and with password protection
bootloader --location=mbr --timeout=3 --password=${root_password} --boot-drive=${disk_device_name} --driveorder=${disk_device_name}
# Ignore further disks
ignoredisk --only-use=${disk_device_name}
# Automatically create UEFI or BIOS boot partition depending on hardware capabilities
reqpart --add-boot
# Simple partitioning: single root and swap
part swap --fstype swap --hibernation --ondisk=${disk_device_name} --asprimary
part / --fstype xfs --size=100 --grow --ondisk=${disk_device_name} --asprimary
EOF
# Clean up disks from any previous LVM setup
# Note: it seems that simply zeroing out below is not enough
vgscan -v
for vg_name in $(vgs --noheadings -o vg_name); do
	vgremove -v -y "${vg_name}"
	udevadm settle --timeout=5
done
for pv_name in $(pvs --noheadings -o pv_name); do
	pvremove -v -ff -y "${pv_name}"
	udevadm settle --timeout=5
done
# Clean up disks from any previous software-RAID (Linux or BIOS based) setup
# TODO: this does not work on CentOS7 (it would need some sort of late disk-status refresh induced inside anaconda) - workaround by manually zeroing-out the first 10 MiBs from a rescue boot before starting the install process (or simply restarting when installation stops/hangs at storage setup)
# Note: skipping this on a virtual machine to avoid inflating a thin-provisioned virtual disk
# Note: dmidecode command may no longer be available in pre environment
if cat /sys/class/dmi/id/sys_vendor | egrep -q -v "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	# Note: resetting all disk devices since leftover configurations may interfer with installation and/or setup later on
	for current_device in ${all_devices}; do
		# Skipping devices in active use
		if [ "${current_device}" = "${kickstart_device}" ] || echo "${in_use_devices}" | grep -q -w "${current_device}" ; then
			continue
		fi
		dd if=/dev/zero of=/dev/${current_device} bs=1M count=10
		dd if=/dev/zero of=/dev/${current_device} bs=1M count=10 seek=$(($(blockdev --getsize64 /dev/${current_device}) / (1024 * 1024) - 10))
	done
	partprobe
	udevadm settle --timeout=5
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
		if [ "${domain_join}" = "true" ]; then
			cat <<- EOF >> hosts
			${my_ip[${zone}]}		${my_name}.${ad_subdomain_prefix}.${domain_name[${zone}]} ${my_name}
			EOF
		else
			cat <<- EOF >> hosts
			${my_ip[${zone}]}		${my_name}.${domain_name[${zone}]} ${my_name}
			EOF
		fi
	else
		cat <<- EOF >> hosts
		${my_ip[${zone}]}		${my_name}.${domain_name[${zone}]}
		EOF
	fi
done
popd

# Prepare TCP wrappers custom lines to be appended later on
# Note: current logic is: only internal network is untrusted (no services offered)
# TODO: in presence of more than one network, distinguish services to be offered on all from those restricted to the trusted one
# TODO: align firewalld zones/rules with this logic
mkdir -p /tmp/hvp-tcp_wrappers-conf
allowed_addr="127.0.0.1"
for zone in "${!network[@]}" ; do
	if [ "${zone}" = "internal" -a "${zone}" != "${my_zone}" ]; then
		continue
	fi
	if [ -n "${nics[${zone}]}" ]; then
		allowed_addr="${network[${zone}]}/${netmask[${zone}]} ${allowed_addr}"
	fi
done
cat << EOF > /tmp/hvp-tcp_wrappers-conf/hosts.allow
ALL: ${allowed_addr}

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
	cat << EOM | expect -f -
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
	        realm join -v --unattended --os-name=\$(lsb_release -si) --os-version=\$(lsb_release -sr) --computer-ou=OU="Remote Desktop Servers" --automatic-id-mapping=no ${ad_subdomain_prefix}.${domain_name[${my_zone}]}
	        # Add further Kerberos SPNs
	        # TODO: adcli update should be preferred but it's not usable as per https://bugzilla.redhat.com/show_bug.cgi?id=1547013
	        # TODO: try adcli update with explicit --login-ccache parameter as per https://bugs.freedesktop.org/show_bug.cgi?id=99460
		rm -f /etc/krb5.keytab
	        adcli join -C --domain=${ad_subdomain_prefix}.${domain_name[${my_zone}]} --service-name=host --service-name=RestrictedKrbHost --service-name=nfs
	        kdestroy
	        # Limit access from AD accounts
	        # TODO: GPOs must be created to limit access
		# Note: the following nested document-here does not need the <<- notation since document-here must have only tabs in front and the outer one will remove all making this block left-aligned
		cat << EOM >> /etc/sssd/sssd.conf
		ad_gpo_access_control = enforcing
		EOM
	        # Complete SSSD configuration for AD
	        # Note: GDM login fails otherwise as per https://bugzilla.redhat.com/show_bug.cgi?id=1231833
	        sed -i -e '/services/s/\$/, pac/' /etc/sssd/sssd.conf
		# Note: the following nested document-here does not need the <<- notation since document-here must have only tabs in front and the outer one will remove all making this block left-aligned
		cat << EOM >> /etc/sssd/sssd.conf
		auth_provider = ad
		chpass_provider = ad
		EOM
	        # Configure automounter for AD-integrated LDAP maps
	        # Note: oddjobd-mkhomedir is automatically enabled but NFS-based home dirs need NFS root access to be autocreated at logon
	        # Note: using SSSD (instead of direct LDAP access) as autofs backend
	        setsebool -P use_nfs_home_dirs on
	        sed -i -e '/^automount:/s/files.*\$/sss/g' /etc/nsswitch.conf
	        sed -i -e '/services/s/\$/, autofs/' /etc/sssd/sssd.conf
		# Note: the following nested document-here does not need the <<- notation since document-here must have only tabs in front and the outer one will remove all making this block left-aligned
		cat << EOM >> /etc/sssd/sssd.conf
		ldap_autofs_search_base = OU=automount,$(echo "${ad_subdomain_prefix}.${domain_name[${my_zone}]}" | sed -e 's/\./,DC=/g')
		ldap_autofs_map_object_class = automountMap
		ldap_autofs_entry_object_class = automount
		ldap_autofs_map_name = automountMapName
		ldap_autofs_entry_key = automountKey
		ldap_autofs_entry_value = automountInformation
		EOM
	        # Configure sudo for AD-integrated LDAP rules
	        # Note: using SSSD (instead of direct LDAP access) as sudo backend
		# Note: the following nested document-here does not need the <<- notation since document-here must have only tabs in front and the outer one will remove all making this block left-aligned
		cat << EOM >> /etc/nsswitch.conf
		
		sudoers:    files sss
		EOM
	        sed -i -e '/services/s/\$/, sudo/' /etc/sssd/sssd.conf
		# Note: the following nested document-here does not need the <<- notation since document-here must have only tabs in front and the outer one will remove all making this block left-aligned
		cat << EOM >> /etc/sssd/sssd.conf
		sudo_provider = ad
		EOM
	        systemctl restart sssd
	        # Configure SSH server and client for Kerberos SSO
	        # TODO: verify auth_to_local mapping rules in /etc/krb5.conf
	        sed -i -e 's/^#GSSAPIKeyExchange\\s.*\$/GSSAPIKeyExchange yes\\nGSSAPIStoreCredentialsOnRekey yes/' /etc/ssh/sshd_config
	        sed -i -e 's/^\\(\\s*\\)\\(GSSAPIAuthentication\\s*yes\\).*\$/\\1\\2\\n\\1GSSAPIDelegateCredentials yes\\n\\1GSSAPIKeyExchange yes\\n\\1GSSAPIRenewalForcesRekey yes/' /etc/ssh/ssh_config
		# TODO: restart hangs blocking rc.domain-join indefinitely - working around with stop + start
	        systemctl stop sshd
	        systemctl start sshd
	        # Complete automounter configuration
	        mkdir -p /home/{${ad_subdomain_prefix}.${domain_name[${my_zone}]},groups} /usr/local/software
	        chown root:root /home/{${ad_subdomain_prefix}.${domain_name[${my_zone}]},groups} /usr/local/software
	        chmod 711 /home/${ad_subdomain_prefix}.${domain_name[${my_zone}]}
	        chmod 755 /home/groups /usr/local/software
	        systemctl --now enable autofs
	fi
	EOF

	popd
fi

# Prepare desktop environment configuration script to be run at first boot
mkdir -p /tmp/hvp-desktop-conf
cat << EOF > /tmp/hvp-desktop-conf/rc.desktop-setup
#!/bin/bash
# Configure X2Go DB
case "${dedbtype}" in
	sqlite)
		# Nothing to do
		;;
	postgresql)
		# Setup PostgreSQL DB backend
		if [ "${domain_join}" = "true" ]; then
			db_host="${db_name}.${ad_subdomain_prefix}.${domain_name[${my_zone}]}"
			x2go_users_group="Remote Desktop Users@${ad_subdomain_prefix}.${domain_name[${my_zone}]}"
			web_host="${web_name}.${ad_subdomain_prefix}.${domain_name[${my_zone}]}"
			my_host="${my_name}.${ad_subdomain_prefix}.${domain_name[${my_zone}]}"
		else
			db_host="${db_name}.${domain_name[${my_zone}]}"
			x2go_users_group="users"
			web_host="${web_name}.${domain_name[${my_zone}]}"
			my_host="${my_name}.${domain_name[${my_zone}]}"
		fi
		sed -i -e "s/^backend=.*\\\$/backend=postgres/g' -e '/^\\\\[postgres\\\\]/,/^\\\\[/s/^host=.*\\\$/host=\\\${db_host}/" /etc/x2go/x2gosql/sql
		echo '${root_password}' > /etc/x2go/x2gosql/passwords/pgadmin
		chown root:root /etc/x2go/x2gosql/passwords/pgadmin
		chmod 600 /etc/x2go/x2gosql/passwords/pgadmin
		# Perform X2Go DB initialization only if DB is missing
		export PGPASSWORD='${root_password}'
		if ! psql -h "\${db_host}" -w -U postgres -lqt | cut -d \\| -f 1 | grep -qw x2go_sessions ; then
			/usr/lib/x2go/script/x2godbadmin --createdb
			/usr/lib/x2go/script/x2godbadmin --addgroup "\${x2go_users_group}"
		fi
		# TODO: Allow access to the X2Go session broker
		# TODO: the session broker agent must be configured after the session broker server has been setup (on a different machine)
		# TODO: either enroll signed certificates or use a local CA then switch to HTTPS
		#x2gobroker-pubkeyauthorizer --broker-url http://\${web_host}/x2gobroker/pubkeys/
		# TODO: after enrolling, list this host under session broker configuration on session broker server
		#sed -i -e "/^host=/s/\\\$/,\${my_host} (\$(dig \${my_host} A +short))/" /etc/x2go/x2gobroker-sessionprofiles.conf
		;;
esac

# Configure X2Go
systemctl --now enable x2goserver

EOF

) 2>&1 | tee /tmp/kickstart_pre.log
%end

# Post-installation script (run with bash from installation image at the end of installation)
%post --nochroot --log /dev/console
( # Run the entire post section as a subshell for logging purposes.

# Copy configuration parameters files (generated in pre section above) into installed system (to be loaded during chrooted post section below)
mkdir -p ${ANA_INSTALL_PATH}/root/etc/kscfg-pre
for custom_frag in /tmp/kscfg-pre/*.sh ; do
	if [ -f "${custom_frag}" ]; then
		cp "${custom_frag}" ${ANA_INSTALL_PATH}/root/etc/kscfg-pre/
	fi
done

) 2>&1 | tee /tmp/kickstart_post_0.log
%end

# Post-installation script (run with bash from chroot after the first post section)
# Note: console logging to support commandline virt-install invocation
%post --log /dev/console
( # Run the entire post section as a subshell for logging purposes.

script_version="2019030401"

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

# Hardcoded defaults

unset network
unset netmask
unset network_base
unset mtu
unset domain_name
unset reverse_domain_name
unset test_ip
unset multi_instance_max
unset nicmacfix
unset detype
unset dedbtype
unset db_name
unset notification_receiver

# Define associative arrays
declare -A network netmask network_base mtu
declare -A domain_name
declare -A reverse_domain_name
declare -A test_ip

nicmacfix="false"

multi_instance_max="9"

db_name="bigmcintosh"

detype="gnome"
dedbtype="sqlite"

notification_receiver="monitoring@localhost"

# Load configuration parameters files (generated in pre section above)
ks_custom_frags="hvp_parameters.sh hvp_parameters_vd.sh hvp_parameters_*:*.sh"
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

# Determine multi-instance limit
given_multi_instance_max=$(sed -n -e 's/^.*hvp_maxinstances=\(\S*\).*$/\1/p' /proc/cmdline)
if echo "${given_multi_instance_max}" | grep -q '^[[:digit:]]\+$' ; then
	multi_instance_max="${given_multi_instance_max}"
fi

# Determine DB server name
given_dbname=$(sed -n -e 's/^.*hvp_dbname=\(\S*\).*$/\1/p' /proc/cmdline)
if echo "${given_dbname}" | grep -q '^[[:alnum:]]\+$' ; then
	db_name="${given_dbname}"
fi

# Determine desktop type
given_detype=$(sed -n -e 's/^.*hvp_detype=\(\S*\).*$/\1/p' /proc/cmdline)
case "${given_detype}" in
	gnome|kde|xfce|lxde)
		detype="${given_detype}"
		;;
esac

# Determine desktop DB type
given_dedbtype=$(sed -n -e 's/^.*hvp_dedbtype=\(\S*\).*$/\1/p' /proc/cmdline)
case "${given_dedbtype}" in
	sqlite|postgresql)
		dedbtype="${given_dedbtype}"
		;;
esac

# Determine notification receiver email address
given_receiver_email=$(sed -n -e "s/^.*hvp_receiver_email=\\(\\S*\\).*\$/\\1/p" /proc/cmdline)
if [ -n "${given_receiver_email}" ]; then
	notification_receiver="${given_receiver_email}"
fi

# Create /dev/root symlink for grubby (must differentiate for use of LVM or MD based "/")
# TODO: Open a Bugzilla notification
# TODO: remove when grubby gets fixed
mp=$(grep -w "/" /etc/fstab | sed -e 's/ .*//')
if echo "$mp" | grep -q "^UUID="
then
    uuid=$(echo "$mp" | sed -e 's/UUID=//')
    rootdisk=$(blkid -U $uuid)
elif echo "$mp" | grep -q "^/dev/"
then
    rootdisk=$mp
fi
ln -sf $rootdisk /dev/root

# Add YUM priorities plugin
yum -y install yum-plugin-priorities

# Correctly initialize YUM cache to avoid 404 errors
# Note: following advice in https://access.redhat.com/articles/1320623
# TODO: remove when fixed upstream
rm -rf /var/cache/yum/*
yum --enablerepo '*' clean all

# Make YUM more robust in presence of network problems
yum-config-manager --save --setopt='retries=30' --setopt='timeout=60' > /dev/null

# Add YUM priorities plugin
yum -y install yum-plugin-priorities

# Add support for CentOS CR repository (to allow up-to-date upgrade later)
# Note: a partially populated CR repo may introduce dependency-related errors - better to leave this to post-installation manual choices
#yum-config-manager --enable cr > /dev/null

# Add HVP custom repo
yum -y --nogpgcheck install https://dangerous.ovirt.life/hvp-repos/el7/hvp/x86_64/hvp-release-7-5.noarch.rpm

# Add upstream repository definitions
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

# Add X2Go upstream repo
wget -P /etc/yum.repos.d https://packages.x2go.org/epel/x2go.repo
# Note: disabling base repo and enabling ESR one
yum-config-manager --disable x2go-release-epel > /dev/null
yum-config-manager --enable x2go-saimaa-epel > /dev/null
# Note: giving priority to upstream repo over EPEL
yum-config-manager --save --setopt='x2go-saimaa-epel.priority=50' > /dev/null

# Comment out mirrorlist directives and uncomment the baseurl ones to make better use of proxy caches
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
# Disable fastestmirror yum plugin too
sed -i -e 's/^enabled.*/enabled=0/' /etc/yum/pluginconf.d/fastestmirror.conf

# Enable use of delta rpms since we are not using a local mirror
yum-config-manager --save --setopt='deltarpm=1' > /dev/null

# Correctly initialize YUM cache again before actual bulk installations/upgrades
# Note: following advice in https://access.redhat.com/articles/1320623
# TODO: remove when fixed upstream
rm -rf /var/cache/yum/*
yum --enablerepo '*' clean all

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

# Install YUM-cron, YUM-plugin-ps, Gdisk, PWGen, HPing, 7Zip and ARJ
yum -y install hping3 p7zip{,-plugins} arj pwgen
yum -y install yum-cron yum-plugin-ps gdisk

# Install Nmon and Dstat
yum -y install nmon dstat

# Install Apache
yum -y install httpd mod_ssl

# Install Webalizer and MRTG
yum -y install webalizer mrtg net-snmp net-snmp-utils

# Install Logcheck
yum -y install logcheck

# Install Webmin
yum -y install webmin
# Note: immediately stop webmin started by postinst scriptlet
/etc/init.d/webmin stop

# Install X2Go
# TODO: add x2godesktopsharing package when supported under ESR
yum -y install x2goserver x2goserver-xsession x2goserver-fmbindings
# Add session broker agent and PostgreSQL utils for load-balanced setup
yum -y install x2gobroker-agent postgresql

# Install Midnight Commander
yum -y install mc

# Install Java browser and Virt-Viewer support
yum -y install icedtea-web virt-viewer spice-xpi

# Install graphical bootsplash theme
yum -y install plymouth-theme-charge

# Install needed packages to join AD domain
yum -y install sssd-ad realmd adcli krb5-workstation samba-common sssd-tools ldb-tools tdb-tools

# Install desktop packages
case "${detype}" in
	gnome)
		# Install additional GNOME packages
		# Note: basic GNOME support is installed as fallback anyway
		yum -y install @gnome-apps @internet-applications vinagre alacarte dconf-editor dvgrab fonts-tweak-tool gconf-editor gedit-plugins gnome-shell-browser-plugin gnote seahorse-nautilus seahorse-sharing
		;;
	kde)
		# Install KDE packages
		yum -y install @kde-desktop @kde-apps @kde-media kdenetwork-krdc
		;;
	xfce)
		# Install Xfce packages
		yum -y install @xfce
		;;
	lxde)
		# Install LXDE (LXQt actually) packages
		# TODO: switch to a group install method as soon as it will be available
		yum -y install lxqt-about lxqt-common lxqt-config lxqt-globalkeys lxqt-l10n lxqt-notificationd lxqt-openssh-askpass lxqt-panel lxqt-policykit lxqt-powermanagement lxqt-qtplugin lxqt-runner lxqt-session lxqt-sudo lxqt-wallet network-manager-applet nm-connection-editor pcmanfm-qt qterminal-qt5 lximage-qt openbox
		;;
esac
# Note: removing seahorse-sharing to get rid of annoying login messages
yum -y erase seahorse-sharing

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
	yum -y install qemu-guest-agent spice-vdagent
elif dmidecode -s system-manufacturer | grep -q "oVirt" ; then
	yum -y install ovirt-guest-agent spice-vdagent
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
	# Install Memtest86+
	# Note: open source memtest86+ does not support UEFI
	if [ ! -d /sys/firmware/efi ]; then
		yum -y install memtest86+
	fi

	# Install MCE logging/management service
	yum -y install mcelog
fi

# Add virtualization support on suitable platforms
if egrep '^flags:.*(svm|vmx)' /proc/cpuinfo ; then
	yum -y install centos-release-qemu-ev
	yum -y install qemu-kvm qemu-img virt-manager libvirt libvirt-python libvirt-client virt-install virt-viewer virt-top libguestfs numpy
fi

# Clean up after all installations
yum --enablerepo '*' clean all

# Remove package update leftovers
find /etc -type f -name '*.rpmnew' -exec rename .rpmnew "" '{}' ';'
find /etc -type f -name '*.rpmsave' -exec rm -f '{}' ';'

# Now configure the base OS
# TODO: Decide which part to configure here and which part to demand to Ansible

# Setup auto-update via yum-cron (ala CentOS4, replacement for yum-updatesd in CentOS5)
# Note: Enable updates but leave to the user/owner the final authority on download and installation
sed -i -e 's/^update_messages\s.*$/update_messages = yes/' -e 's/^download_updates\s.*$/download_updates = no/' -e 's/^apply_updates\s.*$/apply_updates = no/' -e 's/^emit_via\s.*$/emit_via = None/' /etc/yum/yum-cron*.conf
systemctl enable yum-cron

# Limit retained old kernels to 3 (as in CentOS5 default)
yum-config-manager --save --setopt='installonly_limit=3' > /dev/null

# Autodetecting BIOS/UEFI
# Note: the following identifies the symlink under /etc to abstract from BIOS/UEFI actual file placement
if [ -d /sys/firmware/efi ]; then
	grub2_cfg_file="/etc/grub2-efi.cfg"
else
	grub2_cfg_file="/etc/grub2.cfg"
fi

# Configure GRUB2 boot loader (force a well-known graphical mode, be silent and do not wait for manual override, set graphical Plymouth theme)
sed -i -e 's/^GRUB_TIMEOUT=.*$/GRUB_TIMEOUT="0"\nGRUB_HIDDEN_TIMEOUT="3"\nGRUB_HIDDEN_TIMEOUT_QUIET="true"/' /etc/default/grub
plymouth-set-default-theme -R charge
# TODO: we must manually rebuild the initramfs due to a known plymouth bug (https://bugzilla.redhat.com/show_bug.cgi?id=891039) - remove when fixed upstream
dracut -f /boot/initramfs-$(uname -r).img $(uname -r)

# TODO: Setup a serial terminal
# TODO: find a way to detect serial port use by other software (like ovirt-guest-agent) and skip for console
#serial_found="false"
#for link in /sys/class/tty/*/device/driver ; do
#	if stat -c '%N' ${link} | grep -q 'serial' ; then
#		if [ -n "$(setserial -g -b  /dev/$(echo ${link} | sed -e 's%^.*/tty/\([^/]*\)/.*$%\1%'))" ]; then
#			serial_found="true"
#			break
#		fi
#	fi
#done
#if [ "${serial_found}" = "true" ]; then
#	sed -i -e '/^GRUB_CMDLINE_LINUX/s/quiet/quiet console=tty0 console=ttyS0,115200n8/' /etc/default/grub
#	cat <<- EOF >> /etc/default/grub
#	GRUB_TERMINAL="console serial"
#	GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
#	EOF
#	grub2-mkconfig -o "${grub2_cfg_file}"
#fi

# Conditionally add memory test entry to boot loader
if dmidecode -s system-manufacturer | egrep -q -v "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	# Note: open source memtest86+ does not support UEFI
	if [ ! -d /sys/firmware/efi ]; then
		memtest-setup
		grub2-mkconfig -o "${grub2_cfg_file}"
	fi
fi

# Configure kernel I/O scheduler policy
sed -i -e '/^GRUB_CMDLINE_LINUX/s/\selevator=[^[:space:]"]*//' -e '/^GRUB_CMDLINE_LINUX/s/"$/ elevator=deadline"/' /etc/default/grub
grub2-mkconfig -o "${grub2_cfg_file}"

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
	kernel.sched_migration_cost_ns = 5000000
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
			# Note: the following regex does not catch all stat-printf output characters
			#nic_master=$(stat --printf="%N" "/sys/class/net/${nic_name}/master" | sed -e "s%^.*-> \`.*/net/\\([^']*\\)'.*\$%\\1%")
			nic_master=$(stat --printf="%N" "/sys/class/net/${nic_name}/master" | sed -e "s%^.*->.*/net/\\([[:alnum:]]*\\).*\$%\\1%")
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

# Configure NTP time synchronization (immediate hardware sync)
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

# Configure SSH (show legal banner, limit authentication tries, no DNS tracing of incoming connections)
sed -i -e 's/^#\s*MaxAuthTries.*$/MaxAuthTries 3/' -e 's/^#\s*UseDNS.*$/UseDNS no/' -e 's%^#\s*Banner.*$%Banner /etc/issue.net%' /etc/ssh/sshd_config
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

# Enable persistent Journal logs
mkdir -p /var/log/journal

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

# Configure Logcheck
sed -i -e "/^SENDMAILTO=/s/logcheck/${notification_receiver}/" /etc/logcheck/logcheck.conf
for rule in kernel systemd automount x2goserver; do
	ln -s ../ignore.d.server/${rule} /etc/logcheck/violations.ignore.d/
done

# TODO: reconfigure syslog files for Logcheck as per https://bugzilla.redhat.com/show_bug.cgi?id=1062147 - remove when fixed upstream
sed -i -e 's/^\(\s*\)\(missingok.*\)$/\1\2\n\1create 0640 root adm/' /etc/logrotate.d/syslog
touch /var/log/{messages,secure,cron,maillog,spooler}
chown root:adm /var/log/{messages,secure,cron,maillog,spooler}
chmod 640 /var/log/{messages,secure,cron,maillog,spooler}

# Configure ABRTd
# Keep crash info even for non-rpm-packaged programs but exclude users writable paths
sed -i -e 's/^ProcessUnpackaged.*$/ProcessUnpackaged = yes/' -e 's%\(BlackListedPaths.*\)$%\1, /home*, /tmp/*, /var/tmp/*%' /etc/abrt/abrt-action-save-package-data.conf
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
		<title>Desktop Machine</title>
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
	<h1><strong>Desktop Machine</strong></h1>

		<div class="content">
			<div class="content-columns">
				<div class="content-column-left">
					<h2>Avvertenza per gli utenti del servizio:</h2>
					<p>Questa macchina fornisce servizi di desktop grafico.</p>
					<h2>Se siete parte del personale tecnico:</h2>
					<p>Le funzionalit&agrave; predisposte per amministrazione/controllo sono elencate di seguito.
					<ul>
						<li>Lo strumento web di amministrazione della macchina &egrave; disponibile <a href="/manage/">qui</a>.</li>
						<li>Lo strumento web di visualizzazione dell'utilizzo rete &egrave; disponibile <a href="/mrtg/">qui</a>.</li>
						<li>Lo strumento web di visualizzazione dell'utilizzo http &egrave; disponibile <a href="/usage/">qui</a>.</li>
					</ul>
					</p>
				</div>

				<div class="content-column-right">
					<h2>End users notice:</h2>
					<p>This machine provides desktop services.</p>
					<h2>If you are a technical staff member:</h2>
					<p>The maintenance/administrative resources are listed below.
					<ul>
						<li>The server administration web tool is available <a href="/manage/">here</a>.</li>
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

# Enable Apache
firewall-offline-cmd --add-service=http
systemctl enable httpd

# Configure Webmin
# Add "/manage/" location with forced redirect to Webmin port in Apache configuration
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

# Configure Webalizer (allow access from everywhere)
# Note: webalizer initialization demanded to post-install rc.ks1stboot script
sed -i -e 's/^\(\s*\)\(Require local.*\)$/\1Require all granted/' /etc/httpd/conf.d/webalizer.conf

# Enable Webalizer
sed -i -e '/WEBALIZER_CRON=/s/^#*\(WEBALIZER_CRON=\).*$/\1yes/' /etc/sysconfig/webalizer

# TODO: Debug - enable verbose logging in firewalld - maybe disable for production use?
firewall-offline-cmd --set-log-denied=all

# Enable Postfix
systemctl enable postfix

# Define GNOME3 global settings (mandatory/defaults)
# Note: schema inspected on a live GNOME session using "gsettings list-recursively"
# Note: pre-seeding values with gsettings as root works for root user only and needs dbus running - using dconf instead

# Note: clock panel applet under GNOME3 takes all settings from system defaults (location, time format, display etc.)

# Disable user list and reboot/poweroff from GNOME login greeter
cat << EOF > /etc/dconf/db/gdm.d/01-hvp-settings
# Custom settings for GNOME login screen
[org/gnome/login-screen]
disable-restart-buttons=true
disable-user-list=true
EOF
chmod 644 /etc/dconf/db/gdm.d/01-hvp-settings

# Apply all GNOME3 GDM settings specified above
rm -f /etc/dconf/db/gdm
dconf update

# Disable autorun for external media
# TODO: verify under GNOME 3.14 / CentOS 7.2
cat << EOF > /etc/dconf/db/local.d/01-autorun-settings
# Custom settings for GNOME autorun
[org/gnome/desktop/media-handling]
autorun-never=true
EOF
chmod 644 /etc/dconf/db/local.d/01-autorun-settings

# Disable switch user
# TODO: verify under GNOME 3.14 / CentOS 7.2
cat << EOF > /etc/dconf/db/local.d/01-switchuser-settings
# Custom settings for GNOME user session switching
[org/gnome/desktop/lockdown]
disable-user-switching=true
EOF
chmod 644 /etc/dconf/db/local.d/01-switchuser-settings

# Note: GNOME3 (or newer CUPS) does not show other user print jobs by default
# TODO: verify

# Disable online account providers
cat << EOF > /etc/dconf/db/local.d/01-goa-settings
# Custom settings for GNOME online account providers
[org/gnome/online-accounts]
whitelisted-providers=['']
EOF
chmod 644 /etc/dconf/db/local.d/01-goa-settings

# Conditionally apply custom defaults to screensaver under GNOME3 (do not start on idle, do not lock)
if dmidecode -s system-manufacturer | egrep -q "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	cat <<- EOF > /etc/dconf/db/local.d/01-screensaver-settings
	# Custom settings for GNOME screensaver
	[org/gnome/desktop/lockdown]
	disable-lock-screen=true
	[org/gnome/settings-daemon/plugins/media-keys]
	screensaver=''
	[org/gnome/desktop/screensaver]
	idle-activation-enabled=false
	lock-enabled=false
	lock-delay=uint32 0
	[org/gnome/desktop/session]
	idle-delay=uint32 0
	[org/gnome/session]
	idle-delay=uint32 0
	[org/gnome/settings-daemon/plugins/power]
	sleep-display-ac=0
	sleep-display-battery=0
	sleep-inactive-ac-timeout=0
	sleep-inactive-battery-timeout=0
	sleep-inactive-battery-type='nothing'
	sleep-inactive-ac-type='nothing'
	EOF
	chmod 644 /etc/dconf/db/local.d/01-screensaver-settings
	# Lock our custom defaults applied above
	cat <<- EOF > /etc/dconf/db/local.d/locks/01-screensaver-settings-locks
	/org/gnome/desktop/lockdown/disable-lock-screen
	/org/gnome/settings-daemon/plugins/media-keys/screensaver
	/org/gnome/desktop/screensaver/idle-activation-enabled
	/org/gnome/desktop/screensaver/lock-enabled
	/org/gnome/desktop/screensaver/lock-delay
	/org/gnome/desktop/session/idle-delay
	/org/gnome/session/idle-delay
	/org/gnome/settings-daemon/plugins/power/sleep-display-ac
	/org/gnome/settings-daemon/plugins/power/sleep-display-battery
	/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-timeout
	/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-timeout
	/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type
	/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-type
	EOF
	chmod 644 /etc/dconf/db/local.d/locks/01-screensaver-settings-locks
	# Disable power management (blanking) on the X server side too
	cat <<- EOF > /etc/X11/xorg.conf.d/01-dpms.conf
	Section "ServerFlags"
	        Option "BlankTime" "0"
	        Option "StandbyTime" "0"
	        Option "SuspendTime" "0"
	        Option "OffTime" "0"
	EndSection
	EOF
	chmod 644 /etc/X11/xorg.conf.d/01-dpms.conf
	# Disable power/update actions via PolKit (affects GNOME menus and other ways to perform them)
	# TODO: verify default rules under /usr/share/polkit-1/actions/
	cat <<- EOF > /etc/polkit-1/rules.d/60-nousershutdown.rules
	polkit.addRule(function(action, subject) {
	  if ((action.id.indexOf("org.freedesktop.login1.hibernate") == 0) ||
	      (action.id.indexOf("org.freedesktop.login1.power-off") == 0) ||
	      (action.id.indexOf("org.freedesktop.login1.reboot") == 0)    ||
	      (action.id.indexOf("org.freedesktop.login1.suspend") == 0)   ||
	      (action.id.indexOf("org.freedesktop.packagekit.system-update") == 0)          ||
	      (action.id.indexOf("org.freedesktop.packagekit.trigger-offline-update") == 0) ||
	      (action.id.indexOf("org.freedesktop.packagekit.upgrade-system") == 0))         {
	    if (subject.user === "root") {
	        return polkit.Result.YES;
	    } else {
	        return polkit.Result.NO;
	    }
	  }
	});
	EOF
	chmod 644 /etc/polkit-1/rules.d/60-nousershutdown.rules
fi

# Note: filemanager under GNOME3 does not use spatial mode by default

# Apply all GNOME3 settings specified above
rm -f /etc/dconf/db/local
dconf update

# Disable graphical initial system setup
sed -i -e 's/^\(\[daemon\].*\)$/\1\nInitialSetupEnable=False/' /etc/gdm/custom.conf

# Disable GNOME initial setup
# TODO: there is no way to globally disable this: faking an already performed initial setup - remove when fixed upstream
mkdir -m 700 /etc/skel/.config
echo "yes" > /etc/skel/.config/gnome-initial-setup-done
chmod 644 /etc/skel/.config/gnome-initial-setup-done

# TODO: there is a known inconsistency (personal bin directories not in path) in the PATH setting for a terminal opened through Nautilus "Open in Terminal" menu entry
# TODO: adding workaround here (http://seven.centos.org/2014/04/path-inconsistency-in-el7/) - remove when fixed upstream
cat << EOF > /etc/profile.d/consistent-user-path.sh
#!/bin/sh
# Fix broken nautilus-open-terminal
if ! echo "\${PATH}" | grep -q "\${HOME}/bin" ; then
	PATH=\${PATH}:\${HOME}/.local/bin:\${HOME}/bin
	export PATH
fi
EOF
chmod 644 /etc/profile.d/consistent-user-path.sh

# Note: users configuration script created in pre section above and copied in third post section below

# Exclude /var/tmp from systemd-tmpfiles (equivalent of tmpwatch in CentOS <= 6)
mkdir -p /etc/tmpfiles.d
cp /usr/lib/tmpfiles.d/tmp.conf /etc/tmpfiles.d
sed -i -e 's>^\(.\s*/var/tmp.*\)$>#\1>' /etc/tmpfiles.d/tmp.conf

# Configure X2Go
# Note: X2Go setup included in desktop environment configuration script generated in pre section above and copied in third post section below

# Conditionally enable MCE logging/management service
if dmidecode -s system-manufacturer | egrep -q -v "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	systemctl enable mcelog
fi

# TODO: Configure Bareos

# Create HVP standard directory for machine-specific application dumps
mkdir -p /var/local/backup
chown root:root /var/local/backup
chmod 750 /var/local/backup

# Create HVP standard script for machine-specific application dumps
cat << EOF > /usr/local/sbin/dump2backup
#!/bin/bash
# Nothing to do for a X2Go remote desktop server
exit 0
EOF
chown root:root /usr/local/sbin/dump2backup
chmod 750 /usr/local/sbin/dump2backup

# TODO: Enable Bareos
systemctl disable bareos-fd

# TODO: Configure desktop
# TODO: try to set the preferred desktop environment as global default
case "${detype}" in
	gnome)
		;;
	kde)
		;;
	xfce)
		;;
	lxde)
		;;
esac

# Configure root home dir (with utility scripts for basic configuration/log backup)
mkdir -p /root/{etc,bin,log,tmp,backup}
cat << EOF > /root/bin/backup-log
#!/bin/bash
tar -czf /root/backup/\$(hostname)-\$(date '+%Y-%m-%d')-log.tar.gz /root/etc /root/log \$(find /var/log/ -type f ! -iname '*z' -print)
EOF
chmod 755 /root/bin/backup-log
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

# Allow first boot configuration through SELinux
# Note: obtained by means of: cat /var/log/audit/audit.log | audit2allow -M myks1stboot
# TODO: remove when SELinux policy fixed upstream
mkdir -p /etc/selinux/local
cat << EOF > /etc/selinux/local/myks1stboot.te

module myks1stboot 3.0;

require {
	type sendmail_t;
	type postfix_master_t;
	type admin_home_t;
	type setfiles_t;
	type ifconfig_t;
	type initrc_t;
	type systemd_hostnamed_t;
	class dbus send_msg;
	class file { getattr write };
}

#============= ifconfig_t ==============
allow ifconfig_t admin_home_t:file write;

#============= sendmail_t ==============
allow sendmail_t admin_home_t:file write;

#============= postfix_master_t ==============
allow postfix_master_t admin_home_t:file { getattr write };

#============= setfiles_t ==============
allow setfiles_t admin_home_t:file write;

#============= systemd_hostnamed_t ==============
allow systemd_hostnamed_t initrc_t:dbus send_msg;
EOF
chmod 644 /etc/selinux/local/myks1stboot.te

pushd /etc/selinux/local
checkmodule -M -m -o myks1stboot.mod myks1stboot.te
semodule_package -o myks1stboot.pp -m myks1stboot.mod
semodule -i myks1stboot.pp

# Set up "first-boot" configuration script (steps that require a fully up system)
cat << EOF > /etc/rc.d/rc.ks1stboot
#!/bin/bash

# Conditionally enable either IPMI or LMsensors monitoring
# TODO: configure IPMI options
# TODO: find a way to ignore partial IPMI implementations (e.g. those needing a [missing] add-on card)
if dmidecode -s system-manufacturer | egrep -q -v "(Microsoft|VMware|innotek|Parallels|Red.*Hat|oVirt|Xen)" ; then
	if dmidecode --type 38 | grep -q 'IPMI' ; then
		systemctl --now enable ipmi
		systemctl --now enable ipmievd
	else
		sensors-detect --auto
		systemctl --now enable lm_sensors
	fi
fi

# Setup virtualization tools (Hyper-V/KVM/VMware/VirtualBox/Parallels supported)
# TODO: Verify that VirtIO drivers get used for Xen/KVM, warn otherwise
# TODO: disable kernel updating or configure dkms (if not already done above or by tools installation)
pushd /tmp
need_reboot="no"
if dmidecode -s system-manufacturer | grep -q "Microsoft" ; then
	# TODO: configure Hyper-V integration agents
	systemctl --now enable hypervkvpd hypervvssd hypervfcopyd
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
	# TODO: adding _netdev to break possible systemd ordering cycle - investigate further and remove it
	mkdir -p /mnt/hgfs
	cat <<- EOM >> /etc/fstab
	.host:/	/mnt/hgfs	fuse.vmhgfs-fuse	allow_other,auto_unmount,_netdev,x-systemd.requires=vmtoolsd.service,defaults	0 0
	EOM
	mount /mnt/hgfs
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
	systemctl --now enable qemu-guest-agent
elif dmidecode -s system-manufacturer | grep -q "oVirt" ; then
	# TODO: configure oVirt agent
	systemctl --now enable qemu-guest-agent ovirt-guest-agent
fi
popd
# Note: CentOS 7 persistent net device naming means that MAC addresses are not statically registered by default anymore

# Initialize webalizer
# Note: Apache logs must be not empty
max_steps="30"
for ((i=0;i<\${max_steps};i=i+1)); do
	if systemctl -q is-active httpd ; then
		wget -O /dev/null http://localhost/
		/etc/cron.daily/00webalizer
		break
	fi
	sleep 5
done

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

# Check/modify hostname for uniqueness
main_interface=\$(ip route show | awk '/^default/ {print \$5}')
main_ip=\$(ip address show dev \${main_interface} primary | awk '/inet[[:space:]]/ {print \$2}' | cut -d/ -f1)
current_name=\$(hostname -s)
target_domain=\$(hostname -d)
multi_instance_max="${multi_instance_max}"
check_ip="\$(dig \${current_name}.\${target_domain} A +short)"
# Check whether name resolves and does not match with IP address
if [ -n "\${check_ip}" -a "\${check_ip}" != "\${main_ip}" ]; then
	# Name does not match: modify (starting from suffix 2) and resolve it till it is either unknown or matching with configured IP
	tentative_name_found="false"
	for ((name_increment=2;name_increment<=\${multi_instance_max}+1;name_increment=name_increment+1)); do
		tentative_name="\${current_name}\${name_increment}"
		check_ip="\$(dig \${tentative_name}.\${target_domain} A +short)"
		if [ -z "\${check_ip}" -o "\${check_ip}" = "\${main_ip}" ]; then
			tentative_name_found="true"
			break
		fi
	done
	if [ "\${tentative_name_found}" = "true" ]; then
		# Enact new hostname
		hostnamectl set-hostname \${tentative_name}.\${target_domain}
		# Modify already saved entries
		# Note: names on secondary zones are kept aligned
		sed -i -e "s/\\b\${current_name}\\b/\${tentative_name}/g" /etc/hosts
	fi
fi

# Run AD domain joining script
if [ -x /etc/rc.d/rc.domain-join ]; then
	/etc/rc.d/rc.domain-join
fi

# Run dynamically determined desktop environment configuration actions
if [ -x /etc/rc.d/rc.desktop-setup ]; then
	/etc/rc.d/rc.desktop-setup
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

# TODO: forcibly disable execution of graphical firstboot tool - kickstart directive on top seems to be ignored and moving away anaconda-ks.cfg is not enough - remove when fixed upstream - see https://bugzilla.redhat.com/show_bug.cgi?id=1213114
systemctl mask firstboot-graphical
systemctl mask initial-setup-graphical
systemctl mask initial-setup-text
systemctl mask initial-setup

# TODO: sometimes it seems that an haveged process lingers on, blocking the end of the post phase
# TODO: killing any surviving haveged process as a workaround
pkill -KILL -f havege

) 2>&1 | tee /root/kickstart_post_1.log
%end

# Post-installation script (run with bash from installation image after the second post section)
%post --nochroot
( # Run the entire post section as a subshell for logging purposes.

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
	# Note: cleartext passwords contained - must restrict access
	chmod 700 ${ANA_INSTALL_PATH}/etc/rc.d/rc.users-setup
	chown root:root ${ANA_INSTALL_PATH}/etc/rc.d/rc.users-setup
fi

# Copy AD domain joining script (generated in pre section above) into installed system
if [ -s /tmp/hvp-domain-join/rc.domain-join ]; then
	cp /tmp/hvp-domain-join/rc.domain-join ${ANA_INSTALL_PATH}/etc/rc.d/rc.domain-join
	# Note: cleartext passwords contained - must restrict access
	chmod 700 ${ANA_INSTALL_PATH}/etc/rc.d/rc.domain-join
	chown root:root ${ANA_INSTALL_PATH}/etc/rc.d/rc.domain-join
fi

# Copy desktop environment setup script (generated in pre section above) into installed system
if [ -f /tmp/hvp-desktop-conf/rc.desktop-setup ]; then
	cp /tmp/hvp-desktop-conf/rc.desktop-setup ${ANA_INSTALL_PATH}/etc/rc.d/rc.desktop-setup
	# Note: cleartext passwords contained - must restrict access
	chmod 700 ${ANA_INSTALL_PATH}/etc/rc.d/rc.desktop-setup
	chown root:root ${ANA_INSTALL_PATH}/etc/rc.d/rc.desktop-setup
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
cp /tmp/kickstart_*.log ${ANA_INSTALL_PATH}/root/log
mv ${ANA_INSTALL_PATH}/root/kickstart_post*.log ${ANA_INSTALL_PATH}/root/log

) 2>&1 | tee ${ANA_INSTALL_PATH}/root/log/kickstart_post_2.log
%end

# Post-installation script (run with bash from chroot after the third post section)
%post
( # Run the entire post section as a subshell for logging purposes.

# Relabel filesystem
# This has to be the last post action to catch any files we have created/modified
# TODO: verify whether the following is actually needed (latest Anaconda seems to perform a final relabel anyway)
setfiles -F -e /proc -e /sys -e /dev -e /selinux /etc/selinux/targeted/contexts/files/file_contexts /
setfiles -F /etc/selinux/targeted/contexts/files/file_contexts.homedirs /home/ /root/

) 2>&1 | tee /root/log/kickstart_post_3.log
%end
