# Preconfigured defaults for remote desktop server installation
# Note: the following are all the modifiable parameters for reference only (values are equal to hardcoded defaults)

nicmacfix="false"

db_name="bigmcintosh"

web_name="cheerilee"

detype="gnome"
dedbtype="sqlite"

ad_dc_name="spike"

# Note: for the following values, either the IPs or the offset is enough, but we will list here both as an example
test_ip_offset="1"
test_ip['mgmt']="172.20.10.1"
test_ip['lan']="172.20.12.1"
test_ip['internal']="172.20.13.1"

my_ip_offset="240"

multi_instance_max="9"

# Note: network_base values are derived automatically anyway
network['mgmt']="172.20.10.0"
netmask['mgmt']="255.255.255.0"
mtu['mgmt']="1500"
network['lan']="172.20.12.0"
netmask['lan']="255.255.255.0"
mtu['lan']="1500"
network['internal']="172.20.13.0"
netmask['internal']="255.255.255.0"
mtu['internal']="1500"

# Note: reverse_domain_name values are derived automatically anyway
domain_name['mgmt']="mgmt.private"
domain_name['lan']="lan.private"
domain_name['internal']="internal.private"

ad_subdomain_prefix="ad"

domain_join="false"

# Note: to join an AD domain the nameserver should be an AD-integrated one
my_nameserver="8.8.8.8"

my_name="grannysmith"

# Note: passwords must meet the AD complexity requirements
root_password="HVP_dem0"
admin_username="hvpadmin"
admin_password="HVP_dem0"
# Note: the default AD further admin username will be the admin username above prefixed with the "ad" string
winadmin_password="HVP_dem0"
keyboard_layout="us"
local_timezone="UTC"

notification_receiver="monitoring@localhost"

yum_sleep_time="10"
yum_retries="10"

# Note: default base and GPG-key values for repos are those inside .repo files - reported here as an example
#hvp_repo_baseurl['base']='http://centos.mirror.garr.it/centos/$releasever/os/$basearch/'
#hvp_repo_baseurl['updates']='http://centos.mirror.garr.it/centos/$releasever/updates/$basearch/'
#hvp_repo_baseurl['extras']='http://centos.mirror.garr.it/centos/$releasever/extras/$basearch/'
#hvp_repo_baseurl['epel']='http://www.nic.funet.fi/pub/mirrors/fedora.redhat.com/pub/epel/$releasever/$basearch/'
#hvp_repo_gpgkey['epel']='http://www.nic.funet.fi/pub/mirrors/fedora.redhat.com/pub/epel/RPM-GPG-KEY-EPEL-$releasever'
