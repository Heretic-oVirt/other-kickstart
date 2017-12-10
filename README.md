# Further kickstarts repository

This repository contains further kickstart files for virtual guests used in the Heretic oVirt Project:

hvp-dc-c7.ks -  kickstart file for a CentOS7 Samba AD DC machine (install this virtual machine *first*)

hvp-db-c7.ks - kickstart file for a CentOS7 database (either PostgreSQL, MySQL, Firebird or SQLServer) machine

hvp-pr-c7.ks - kickstart file for a CentOS7 printer server (Samba) machine

hvp-vd-c7.ks - kickstart file for a CentOS7 virtual desktop machine

Future planned kickstart files (all further virtual machines should be joined to the AD domain created above):

hvp-erp-c7.ks - kickstart file for a CentOS7 application/ERP (TBD) machine

hvp-msg-c7.ks - kickstart file for a CentOS7 messaging/groupware (TBD) machine

hvp-fw-c7.ks - kickstart file for a CentOS7 firewall/proxy/VPN (firewalld/Squid/Strongswan) machine

hvp-vd-win10.xml - autounattend file for a Windows10 virtual desktop machine

Each kickstart file has a corresponding sample hvp_parameters_&ast;.sh configuration parameters file (consisting of comments and variable definitions in GNU/Bash syntax) to overcome Linux kernel commandline length limitations.

Currently there is a rude organization of automation strategies for these additional machines: everything happens inside the Kickstart (arguably something could be delegated to Ansible running on the installer machine, besides orchestrating guest creation/installation).

Inside kickstart files, important points are in comments beginning with "# Note: " while current bugs/workarounds/missing_features are in comments beginning with "# TODO: "

Please note that all kickstarts are independent of the actual virtualization technology used: the corresponding vms can be instantiated on any kind of infrastrucuture (KVM, Xen, VMware, Hyper-V and Parallels are explicitly supported) and the configuration parameters can be independently created and made available.
