# Further kickstarts repository

This repository contains further kickstart files for virtual guests used in the Heretic oVirt Project:

hvp-dc-c7.ks -  kickstart file for a CentOS7 Samba AD DC machine (install this virtual machine *first*)

hvp-db-c7.ks - kickstart file for a CentOS7 database (either PostgreSQL, MySQL, Firebird, MongoDB or SQLServer) machine

hvp-pr-c7.ks - kickstart file for a CentOS7 printer server (Samba) machine

hvp-vd-c7.ks - kickstart file for a CentOS7 remote desktop server (X2Go with either GNOME, KDE, Xfce or LXDE) machine

hvp-web-c7.ks - kickstart file for a CentOS7 Web applications (X2Go session broker/Nextcloud/Online Office with either LibreOfficeOnline or OnlyOffice) machine

hvp-tmpl-c7.ks - kickstart file for a CentOS7 template machine

Future planned kickstart files (all further virtual machines should be joined to the AD domain created above):

hvp-fw-c7.ks - kickstart file for a CentOS7 firewall/proxy/VPN (firewalld/Squid/Strongswan) machine

hvp-mon-c7.ks - kickstart file for a CentOS7 monitoring (oVirt Metrics) machine

hvp-aut-c7.ks - kickstart file for a CentOS7 automation (ManageIQ + AWX) machine

hvp-erp-c7.ks - kickstart file for a CentOS7 application/ERP (either Tryton, Dolibarr, Axelor or Odoo) machine

hvp-msg-c7.ks - kickstart file for a CentOS7 messaging/groupware (TBD) machine

hvp-sat-c7.ks - kickstart file for a CentOS7 management/orchestration/provisioning (Foreman) machine

hvp-vd-win2k19.xml - autounattend file for a Windows Server 2019 remote desktop server (Session Host) machine

Each kickstart file has a corresponding sample hvp_parameters_&ast;.sh configuration parameters file (consisting of comments and variable definitions in GNU/Bash syntax) to overcome Linux kernel commandline length limitations.

Currently there is a rude organization of automation strategies for these additional machines: everything happens inside the Kickstart (arguably something could be delegated to Ansible running on the installer machine, besides orchestrating guest creation/installation).

Inside kickstart files, important points are in comments beginning with "# Note: " while current bugs/workarounds/missing_features are in comments beginning with "# TODO: "

Please note that all kickstarts are independent of the actual virtualization technology used (or even bare-metal physical deployment): the corresponding vms can be instantiated on any kind of infrastructure (KVM, Xen, VMware, Hyper-V and Parallels are explicitly supported) and the configuration parameter files can be independently created and made available.
