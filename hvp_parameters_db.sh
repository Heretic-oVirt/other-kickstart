# Preconfigured defaults for AD DC server installation
# Note: the following are all the modifiable parameters for reference only (values are equal to hardcoded defaults)

dbtype="postgresql"

nicmacfix="false"

# Note: for the following values, either the IPs or the offset is enough, but we will list here both as an example
test_ip_offset="1"
test_ip['mgmt']="172.20.10.1"
test_ip['lan']="172.20.12.1"

my_ip_offset="221"

# Note: network_base values are derived automatically anyway
network['mgmt']="172.20.10.0"
netmask['mgmt']="255.255.255.0"
mtu['mgmt']="1500"
network['lan']="172.20.12.0"
netmask['lan']="255.255.255.0"
mtu['lan']="1500"

# Note: reverse_domain_name values are derived automatically anyway
domain_name['mgmt']="mgmt.private"
domain_name['lan']="lan.private"

my_nameserver="8.8.8.8"

my_forwarders="8.8.8.8"

my_name="bigmcintosh"

dcname="spike"

# Note: passwords must meet the DB complexity requirements
root_password="HVP_dem0"
admin_username="hvpadmin"
admin_password="HVP_dem0"
keyboard_layout="us"
local_timezone="UTC"
