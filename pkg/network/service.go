//
// Apache License 2.0
//
// Copyright (c) 2022, Austin Zhai
// All rights reserved.
//

package network

// Created by gen.go, don't edit manually
// Generated at 2023-01-28 16:24:13

func GetPortByServiceAndProtocol(service Service, proto Protocol) int {
	pps, ok := ServicePortProtoMaps[service]
	if !ok {
		return -1
	}
	for _, pp := range pps {
		if proto == pp.Proto {
			return pp.Port
		}
	}
	return -1
}

type Service string

var (
	ServiceUnknown Service = "unknown"
)

func (service Service) Type() string {
	return "Service"
}

func (service Service) Value() string {
	return string(service)
}

type PortProto struct {
	Port  int
	Proto Protocol
}

const (
	ServiceTcpmux          Service = "tcpmux"          // TCP port service multiplexer
	ServiceRje             Service = "rje"             // Remote Job Entry
	ServiceEcho            Service = "echo"            // 7/tcp
	ServiceDiscard         Service = "discard"         // 9/tcp sink null
	ServiceSystat          Service = "systat"          // 11/tcp users
	ServiceDaytime         Service = "daytime"         // 13/tcp
	ServiceQotd            Service = "qotd"            // 17/tcp quote
	ServiceMsp             Service = "msp"             // message send protocol (historic)
	ServiceChargen         Service = "chargen"         // 19/tcp ttytst source
	ServiceFtpData         Service = "ftp-data"        // 20/tcp
	ServiceFtp             Service = "ftp"             // 21/tcp
	ServiceSsh             Service = "ssh"             // The Secure Shell (SSH) Protocol
	ServiceTelnet          Service = "telnet"          // 23/tcp
	ServiceLmtp            Service = "lmtp"            // LMTP Mail Delivery
	ServiceSmtp            Service = "smtp"            // 25/tcp mail
	ServiceTime            Service = "time"            // 37/tcp timserver
	ServiceRlp             Service = "rlp"             // resource location
	ServiceNameserver      Service = "nameserver"      // IEN 116
	ServiceNicname         Service = "nicname"         // 43/tcp whois
	ServiceTacacs          Service = "tacacs"          // Login Host Protocol (TACACS)
	ServiceReMailCk        Service = "re-mail-ck"      // Remote Mail Checking Protocol
	ServiceDomain          Service = "domain"          // name-domain server
	ServiceWhoisPlusPlus   Service = "whois++"         // 63/tcp whoispp
	ServiceBootps          Service = "bootps"          // BOOTP server
	ServiceBootpc          Service = "bootpc"          // BOOTP client
	ServiceTftp            Service = "tftp"            // 69/tcp
	ServiceGopher          Service = "gopher"          // Internet Gopher
	ServiceNetrjs1         Service = "netrjs-1"        // Remote Job Service
	ServiceNetrjs2         Service = "netrjs-2"        // Remote Job Service
	ServiceNetrjs3         Service = "netrjs-3"        // Remote Job Service
	ServiceNetrjs4         Service = "netrjs-4"        // Remote Job Service
	ServiceFinger          Service = "finger"          // 79/tcp
	ServiceHttp            Service = "http"            // WorldWideWeb HTTP
	ServiceKerberos        Service = "kerberos"        // Kerberos v5
	ServiceSupdup          Service = "supdup"          // 95/tcp
	ServiceHostname        Service = "hostname"        // usually from sri-nic
	ServiceIsoTsap         Service = "iso-tsap"        // part of ISODE.
	ServiceCsnetNs         Service = "csnet-ns"        // also used by CSO name server
	ServiceRtelnet         Service = "rtelnet"         // Remote Telnet
	ServicePop2            Service = "pop2"            // POP version 2
	ServicePop3            Service = "pop3"            // POP version 3
	ServiceSunrpc          Service = "sunrpc"          // RPC 4.0 portmapper TCP
	ServiceAuth            Service = "auth"            // 113/tcp authentication tap ident
	ServiceSftp            Service = "sftp"            // 115/tcp
	ServiceUucpPath        Service = "uucp-path"       // 117/tcp
	ServiceNntp            Service = "nntp"            // USENET News Transfer Protocol
	ServiceNtp             Service = "ntp"             // 123/tcp
	ServiceNetbiosNs       Service = "netbios-ns"      // NETBIOS Name Service
	ServiceNetbiosDgm      Service = "netbios-dgm"     // NETBIOS Datagram Service
	ServiceNetbiosSsn      Service = "netbios-ssn"     // NETBIOS session service
	ServiceImap            Service = "imap"            // Interim Mail Access Proto v2
	ServiceSnmp            Service = "snmp"            // Simple Net Mgmt Proto
	ServiceSnmptrap        Service = "snmptrap"        // SNMPTRAP
	ServiceCmipMan         Service = "cmip-man"        // ISO mgmt over IP (CMOT)
	ServiceCmipAgent       Service = "cmip-agent"      // 164/tcp
	ServiceMailq           Service = "mailq"           // MAILQ
	ServiceXdmcp           Service = "xdmcp"           // X Display Mgr. Control Proto
	ServiceNextstep        Service = "nextstep"        // NeXTStep window
	ServiceBgp             Service = "bgp"             // Border Gateway Proto.
	ServiceProspero        Service = "prospero"        // Cliff Neuman's Prospero
	ServiceIrc             Service = "irc"             // Internet Relay Chat
	ServiceSmux            Service = "smux"            // SNMP Unix Multiplexer
	ServiceAtRtmp          Service = "at-rtmp"         // AppleTalk routing
	ServiceAtNbp           Service = "at-nbp"          // AppleTalk name binding
	ServiceAtEcho          Service = "at-echo"         // AppleTalk echo
	ServiceAtZis           Service = "at-zis"          // AppleTalk zone information
	ServiceQmtp            Service = "qmtp"            // Quick Mail Transfer Protocol
	ServiceZ39Dot50        Service = "z39.50"          // NISO Z39.50 database
	ServiceIpx             Service = "ipx"             // IPX
	ServiceImap3           Service = "imap3"           // Interactive Mail Access
	ServiceLink            Service = "link"            // 245/tcp ttylink
	ServiceGist            Service = "gist"            // Q-mode encapsulation for GIST messages
	ServiceFatserv         Service = "fatserv"         // Fatmen Server
	ServiceRsvp_tunnel     Service = "rsvp_tunnel"     // 363/tcp rsvp-tunnel
	ServiceOdmr            Service = "odmr"            // odmr required by fetchmail
	ServiceRpc2portmap     Service = "rpc2portmap"     // 369/tcp
	ServiceCodaauth2       Service = "codaauth2"       // 370/tcp
	ServiceUlistproc       Service = "ulistproc"       // UNIX Listserv
	ServiceLdap            Service = "ldap"            // 389/tcp
	ServiceOsbSd           Service = "osb-sd"          // Oracle Secure Backup
	ServiceSvrloc          Service = "svrloc"          // Server Location Protocl
	ServiceMobileipAgent   Service = "mobileip-agent"  // 434/tcp
	ServiceMobilipMn       Service = "mobilip-mn"      // 435/tcp
	ServiceHttps           Service = "https"           // http protocol over TLS/SSL
	ServiceSnpp            Service = "snpp"            // Simple Network Paging Protocol
	ServiceMicrosoftDs     Service = "microsoft-ds"    // 445/tcp
	ServiceKpasswd         Service = "kpasswd"         // Kerberos "passwd"
	ServicePhoturis        Service = "photuris"        // 468/tcp
	ServiceSaft            Service = "saft"            // Simple Asynchronous File Transfer
	ServiceGssHttp         Service = "gss-http"        // 488/tcp
	ServicePimRpDisc       Service = "pim-rp-disc"     // 496/tcp
	ServiceIsakmp          Service = "isakmp"          // 500/tcp
	ServiceGdomap          Service = "gdomap"          // GNUstep distributed objects
	ServiceIiop            Service = "iiop"            // 535/tcp
	ServiceDhcpv6Client    Service = "dhcpv6-client"   // 546/tcp
	ServiceDhcpv6Server    Service = "dhcpv6-server"   // 547/tcp
	ServiceRtsp            Service = "rtsp"            // Real Time Stream Control Protocol
	ServiceNntps           Service = "nntps"           // NNTP over SSL
	ServiceWhoami          Service = "whoami"          // 565/tcp
	ServiceSubmission      Service = "submission"      // mail message submission
	ServiceNpmpLocal       Service = "npmp-local"      // npmp-local / DQS
	ServiceNpmpGui         Service = "npmp-gui"        // npmp-gui / DQS
	ServiceHmmpInd         Service = "hmmp-ind"        // HMMP Indication / DQS
	ServiceIpp             Service = "ipp"             // Internet Printing Protocol
	ServiceLdaps           Service = "ldaps"           // LDAP over SSL
	ServiceAcap            Service = "acap"            // 674/tcp
	ServiceHaCluster       Service = "ha-cluster"      // Heartbeat HA-cluster
	ServiceKerberosAdm     Service = "kerberos-adm"    // Kerberos `kadmin' (v5)
	ServiceKerberosIv      Service = "kerberos-iv"     // 750/udp kerberos4 kerberos-sec kdc loadav
	ServiceWebster         Service = "webster"         // Network dictionary
	ServicePhonebook       Service = "phonebook"       // Network phonebook
	ServiceRsync           Service = "rsync"           // rsync
	ServiceRquotad         Service = "rquotad"         // rquota daemon
	ServiceTelnets         Service = "telnets"         // 992/tcp
	ServiceImaps           Service = "imaps"           // IMAP over SSL
	ServicePop3s           Service = "pop3s"           // POP-3 over SSL
	ServiceExec            Service = "exec"            // 512/tcp
	ServiceBiff            Service = "biff"            // 512/udp comsat
	ServiceLogin           Service = "login"           // 513/tcp
	ServiceWho             Service = "who"             // 513/udp whod
	ServiceShell           Service = "shell"           // no passwords used
	ServiceSyslog          Service = "syslog"          // 514/udp
	ServicePrinter         Service = "printer"         // line printer spooler
	ServiceTalk            Service = "talk"            // 517/udp
	ServiceNtalk           Service = "ntalk"           // 518/udp
	ServiceUtime           Service = "utime"           // 519/tcp unixtime
	ServiceEfs             Service = "efs"             // 520/tcp
	ServiceRouter          Service = "router"          // RIP
	ServiceRipng           Service = "ripng"           // 521/tcp
	ServiceTimed           Service = "timed"           // 525/tcp timeserver
	ServiceTempo           Service = "tempo"           // 526/tcp newdate
	ServiceCourier         Service = "courier"         // 530/tcp rpc
	ServiceConference      Service = "conference"      // 531/tcp chat
	ServiceNetnews         Service = "netnews"         // 532/tcp
	ServiceNetwall         Service = "netwall"         // -for emergency broadcasts
	ServiceUucp            Service = "uucp"            // uucp daemon
	ServiceKlogin          Service = "klogin"          // Kerberized `rlogin' (v5)
	ServiceKshell          Service = "kshell"          // Kerberized `rsh' (v5)
	ServiceAfpovertcp      Service = "afpovertcp"      // AFP over TCP
	ServiceRemotefs        Service = "remotefs"        // Brunhoff remote filesystem
	ServiceSocks           Service = "socks"           // socks proxy server
	ServiceBvcontrol       Service = "bvcontrol"       // Daniel J. Walsh, Gracilis Packeten remote config server
	ServiceH323hostcallsc  Service = "h323hostcallsc"  // H.323 Secure Call Control
	ServiceMsSqlS          Service = "ms-sql-s"        // Microsoft-SQL-Server
	ServiceMsSqlM          Service = "ms-sql-m"        // Microsoft-SQL-Monitor
	ServiceIca             Service = "ica"             // Citrix ICA Client
	ServiceWins            Service = "wins"            // Microsoft's Windows Internet Name Service
	ServiceIngreslock      Service = "ingreslock"      // 1524/tcp
	ServiceProsperoNp      Service = "prospero-np"     // Prospero non-privileged/oracle
	ServiceDatametrics     Service = "datametrics"     // datametrics / old radius entry
	ServiceSaMsgPort       Service = "sa-msg-port"     // sa-msg-port / old radacct entry
	ServiceKermit          Service = "kermit"          // 1649/tcp
	ServiceL2tp            Service = "l2tp"            // 1701/tcp l2f
	ServiceH323gatedisc    Service = "h323gatedisc"    // 1718/tcp
	ServiceH323gatestat    Service = "h323gatestat"    // 1719/tcp
	ServiceH323hostcall    Service = "h323hostcall"    // 1720/tcp
	ServiceTftpMcast       Service = "tftp-mcast"      // 1758/tcp
	ServiceMtftp           Service = "mtftp"           // 1759/udp spss-lm
	ServiceHello           Service = "hello"           // 1789/tcp
	ServiceRadius          Service = "radius"          // Radius
	ServiceRadiusAcct      Service = "radius-acct"     // Radius Accounting
	ServiceMtp             Service = "mtp"             //
	ServiceHsrp            Service = "hsrp"            // Cisco Hot Standby Router Protocol
	ServiceLicensedaemon   Service = "licensedaemon"   // 1986/tcp
	ServiceGdpPort         Service = "gdp-port"        // Cisco Gateway Discovery Protocol
	ServiceSieveFilter     Service = "sieve-filter"    // Sieve Mail Filter Daemon
	ServiceNfs             Service = "nfs"             // Network File System
	ServiceZephyrSrv       Service = "zephyr-srv"      // Zephyr server
	ServiceZephyrClt       Service = "zephyr-clt"      // Zephyr serv-hm connection
	ServiceZephyrHm        Service = "zephyr-hm"       // Zephyr hostmanager
	ServiceCvspserver      Service = "cvspserver"      // CVS client/server operations
	ServiceVenus           Service = "venus"           // codacon port
	ServiceVenusSe         Service = "venus-se"        // tcp side effects
	ServiceCodasrv         Service = "codasrv"         // not used
	ServiceCodasrvSe       Service = "codasrv-se"      // tcp side effects
	ServiceHpstgmgr        Service = "hpstgmgr"        // HPSTGMGR
	ServiceDiscpClient     Service = "discp-client"    // discp client
	ServiceDiscpServer     Service = "discp-server"    // discp server
	ServiceServicemeter    Service = "servicemeter"    // Service Meter
	ServiceNscCcs          Service = "nsc-ccs"         // NSC CCS
	ServiceNscPosa         Service = "nsc-posa"        // NSC POSA
	ServiceNetmon          Service = "netmon"          // Dell Netmon
	ServiceDict            Service = "dict"            // RFC 2229
	ServiceCorbaloc        Service = "corbaloc"        // CORBA naming service locator
	ServiceIcpv2           Service = "icpv2"           // Internet Cache Protocol V2 (Squid)
	ServiceMysql           Service = "mysql"           // MySQL
	ServiceTrnsprntproxy   Service = "trnsprntproxy"   // Trnsprnt Proxy
	ServicePxe             Service = "pxe"             // PXE server
	ServiceFud             Service = "fud"             // Cyrus IMAP FUD Daemon
	ServiceRwhois          Service = "rwhois"          // Remote Who Is
	ServiceKrb524          Service = "krb524"          // Kerberos 5 to 4 ticket xlator
	ServiceRfe             Service = "rfe"             // Radio Free Ethernet
	ServiceCfengine        Service = "cfengine"        // CFengine
	ServiceCvsup           Service = "cvsup"           // CVSup file transfer/John Polstra/FreeBSD
	ServiceX11             Service = "x11"             // the X Window System
	ServiceAfs3Fileserver  Service = "afs3-fileserver" // file server itself
	ServiceAfs3Callback    Service = "afs3-callback"   // callbacks to cache managers
	ServiceAfs3Prserver    Service = "afs3-prserver"   // users & groups database
	ServiceAfs3Vlserver    Service = "afs3-vlserver"   // volume location database
	ServiceAfs3Kaserver    Service = "afs3-kaserver"   // AFS/Kerberos authentication service
	ServiceAfs3Volser      Service = "afs3-volser"     // volume managment server
	ServiceAfs3Errors      Service = "afs3-errors"     // error interpretation service
	ServiceAfs3Bos         Service = "afs3-bos"        // basic overseer process
	ServiceAfs3Update      Service = "afs3-update"     // server-to-server updater
	ServiceAfs3Rmtsys      Service = "afs3-rmtsys"     // remote cache manager service
	ServiceAmanda          Service = "amanda"          // amanda backup services
	ServicePgpkeyserver    Service = "pgpkeyserver"    // PGP/GPG public keyserver
	ServiceAsgcypresstcps  Service = "asgcypresstcps"  // ASG Cypress Secure Only
	ServiceH323callsigalt  Service = "h323callsigalt"  // H323 Call Signal Alternate
	ServiceBprd            Service = "bprd"            // BPRD (VERITAS NetBackup)
	ServiceBpdbm           Service = "bpdbm"           // BPDBM (VERITAS NetBackup)
	ServiceBpjavaMsvc      Service = "bpjava-msvc"     // BP Java MSVC Protocol
	ServiceVnetd           Service = "vnetd"           // Veritas Network Utility
	ServiceBpcd            Service = "bpcd"            // VERITAS NetBackup
	ServiceVopied          Service = "vopied"          // VOPIED Protocol
	ServiceWnn6            Service = "wnn6"            // 22273/tcp wnn4
	ServiceQuake           Service = "quake"           // 26000/tcp
	ServiceWnn6Ds          Service = "wnn6-ds"         // 26208/tcp
	ServiceTraceroute      Service = "traceroute"      // 33434/tcp
	ServiceRtmp            Service = "rtmp"            // Routing Table Maintenance Protocol
	ServiceNbp             Service = "nbp"             // Name Binding Protocol
	ServiceZip             Service = "zip"             // Zone Information Protocol
	ServiceKerberos_master Service = "kerberos_master" // Kerberos authentication
	ServicePasswd_server   Service = "passwd_server"   // Kerberos passwd server
	ServiceKrbupdate       Service = "krbupdate"       // Kerberos registration
	ServiceKpop            Service = "kpop"            // Pop with Kerberos
	ServiceKnetd           Service = "knetd"           // Kerberos de-multiplexor
	ServiceKrb5_prop       Service = "krb5_prop"       // Kerberos slave propagation
	ServiceEklogin         Service = "eklogin"         // Kerberos encrypted rlogin
	ServiceSupfilesrv      Service = "supfilesrv"      // SUP server
	ServiceSupfiledbg      Service = "supfiledbg"      // SUP debugging
	ServiceNetstat         Service = "netstat"         // (was once asssigned, no more)
	ServicePoppassd        Service = "poppassd"        // Eudora
	ServiceOmirr           Service = "omirr"           // online mirror
	ServiceSwat            Service = "swat"            // Samba Web Administration Tool
	ServiceRndc            Service = "rndc"            // rndc control sockets (BIND 9)
	ServiceSkkserv         Service = "skkserv"         // SKK Japanese input method
	ServiceXtel            Service = "xtel"            // french minitel
	ServiceSupport         Service = "support"         // GNATS, cygnus bug tracker
	ServiceCfinger         Service = "cfinger"         // GNU Finger
	ServiceNinstall        Service = "ninstall"        // ninstall service
	ServiceAfbackup        Service = "afbackup"        // Afbackup system
	ServiceSquid           Service = "squid"           // squid web proxy
	ServicePrsvp           Service = "prsvp"           // RSVP Port
	ServiceDistcc          Service = "distcc"          // distcc
	ServiceSvn             Service = "svn"             // Subversion
	ServicePostgres        Service = "postgres"        // POSTGRES
	ServiceFax             Service = "fax"             // FAX transmission service (old)
	ServiceHylafax         Service = "hylafax"         // HylaFAX client-server protocol (new)
	ServiceSgiDgl          Service = "sgi-dgl"         // SGI Distributed Graphics
	ServiceHostmon         Service = "hostmon"         // hostmon uses TCP (nocol)
	ServiceCanna           Service = "canna"           // 5680/tcp auriga-router
	ServiceX11SshOffset    Service = "x11-ssh-offset"  // SSH X11 forwarding offset
	ServiceXfs             Service = "xfs"             // X font server
	ServiceTircproxy       Service = "tircproxy"       // Tircproxy
	ServiceWebcache        Service = "webcache"        // WWW caching service
	ServiceTproxy          Service = "tproxy"          // Transparent Proxy
	ServiceJetdirect       Service = "jetdirect"       // 9100/tcp laserjet hplj hp-pdl-datastr pdl-datastream
	ServiceMandelspawn     Service = "mandelspawn"     // network mandelbrot
	ServiceKamanda         Service = "kamanda"         // amanda backup services (Kerberos)
	ServiceAmandaidx       Service = "amandaidx"       // amanda backup services
	ServiceAmidxtape       Service = "amidxtape"       // amanda backup services
	ServiceIsdnlog         Service = "isdnlog"         // isdn logging system
	ServiceWnn4_Kr         Service = "wnn4_Kr"         // used by the kWnn package
	ServiceWnn4_Cn         Service = "wnn4_Cn"         // used by the cWnn package
	ServiceWnn4_Tw         Service = "wnn4_Tw"         // used by the tWnn package
	ServiceBinkp           Service = "binkp"           // Binkley
	ServiceCanditv         Service = "canditv"         // Canditv Message Service
	ServiceAsp             Service = "asp"             // Address Search Protocol
	ServiceTfido           Service = "tfido"           // Ifmail
	ServiceFido            Service = "fido"            // Ifmail
	ServiceCompressnet     Service = "compressnet"     // Management Utility
	ServiceNswFe           Service = "nsw-fe"          // NSW User System FE
	ServiceMsgIcp          Service = "msg-icp"         // MSG ICP
	ServiceMsgAuth         Service = "msg-auth"        // MSG Authentication
	ServiceDsp             Service = "dsp"             // Display Support Protocol
	ServiceRap             Service = "rap"             // Route Access Protocol
	ServiceGraphics        Service = "graphics"        // Graphics
	ServiceMpmFlags        Service = "mpm-flags"       // MPM FLAGS Protocol
	ServiceMpm             Service = "mpm"             // Message Processing Module [recv]
	ServiceMpmSnd          Service = "mpm-snd"         // MPM [default send]
	ServiceNiFtp           Service = "ni-ftp"          // NI FTP
	ServiceAuditd          Service = "auditd"          // Digital Audit Daemon
	ServiceLaMaint         Service = "la-maint"        // IMP Logical Address Maintenance
	ServiceXnsTime         Service = "xns-time"        // XNS Time Protocol
	ServiceXnsCh           Service = "xns-ch"          // XNS Clearinghouse
	ServiceIsiGl           Service = "isi-gl"          // ISI Graphics Language
	ServiceXnsAuth         Service = "xns-auth"        // XNS Authentication
	ServiceXnsMail         Service = "xns-mail"        // XNS Mail
	ServiceNiMail          Service = "ni-mail"         // NI MAIL
	ServiceAcas            Service = "acas"            // ACA Services
	ServiceCovia           Service = "covia"           // Communications Integrator (CI)
	ServiceTacacsDs        Service = "tacacs-ds"       // TACACS-Database Service
	ServiceSqlNet          Service = "sql*net"         // Oracle SQL*NET
	ServiceDeos            Service = "deos"            // Distributed External Object Store
	ServiceVettcp          Service = "vettcp"          // vettcp
	ServiceXfer            Service = "xfer"            // XFER Utility
	ServiceMitMlDev        Service = "mit-ml-dev"      // MIT ML Device
	ServiceCtf             Service = "ctf"             // Common Trace Facility
	ServiceMfcobol         Service = "mfcobol"         // Micro Focus Cobol
	ServiceSuMitTg         Service = "su-mit-tg"       // SU/MIT Telnet Gateway
	ServiceDnsix           Service = "dnsix"           // DNSIX Securit Attribute Token Map
	ServiceMitDov          Service = "mit-dov"         // MIT Dover Spooler
	ServiceNpp             Service = "npp"             // Network Printing Protocol
	ServiceDcp             Service = "dcp"             // Device Control Protocol
	ServiceObjcall         Service = "objcall"         // Tivoli Object Dispatcher
	ServiceDixie           Service = "dixie"           // DIXIE Protocol Specification
	ServiceSwiftRvf        Service = "swift-rvf"       // Swift Remote Virtural File Protocol
	ServiceTacnews         Service = "tacnews"         // TAC News
	ServiceMetagram        Service = "metagram"        // Metagram Relay
	ServiceNewacct         Service = "newacct"         // [unauthorized use]
	ServiceGppitnp         Service = "gppitnp"         // Genesis Point-to-Point Trans Net
	ServiceAcrNema         Service = "acr-nema"        // ACR-NEMA Digital Imag. & Comm. 300
	ServiceSnagas          Service = "snagas"          // SNA Gateway Access Server
	ServiceMcidas          Service = "mcidas"          // McIDAS Data Transmission Protocol
	ServiceAnsanotify      Service = "ansanotify"      // ANSA REX Notify
	ServiceSqlserv         Service = "sqlserv"         // SQL Services
	ServiceCfdptkt         Service = "cfdptkt"         // CFDPTKT
	ServiceErpc            Service = "erpc"            // Encore Expedited Remote Pro.Call
	ServiceSmakynet        Service = "smakynet"        // SMAKYNET
	ServiceAnsatrader      Service = "ansatrader"      // ANSA REX Trader
	ServiceLocusMap        Service = "locus-map"       // Locus PC-Interface Net Map Ser
	ServiceNxedit          Service = "nxedit"          // NXEdit
	ServiceLocusCon        Service = "locus-con"       // Locus PC-Interface Conn Server
	ServiceGssXlicen       Service = "gss-xlicen"      // GSS X License Verification
	ServicePwdgen          Service = "pwdgen"          // Password Generator Protocol
	ServiceCiscoFna        Service = "cisco-fna"       // cisco FNATIVE
	ServiceCiscoTna        Service = "cisco-tna"       // cisco TNATIVE
	ServiceCiscoSys        Service = "cisco-sys"       // cisco SYSMAINT
	ServiceStatsrv         Service = "statsrv"         // Statistics Service
	ServiceIngresNet       Service = "ingres-net"      // INGRES-NET Service
	ServiceEpmap           Service = "epmap"           // DCE endpoint resolution
	ServiceProfile         Service = "profile"         // PROFILE Naming System
	ServiceEmfisData       Service = "emfis-data"      // EMFIS Data Service
	ServiceEmfisCntl       Service = "emfis-cntl"      // EMFIS Control Service
	ServiceBlIdm           Service = "bl-idm"          // Britton-Lee IDM
	ServiceUma             Service = "uma"             // Universal Management Architecture
	ServiceUaac            Service = "uaac"            // UAAC Protocol
	ServiceIsoTp0          Service = "iso-tp0"         // ISO-IP0
	ServiceIsoIp           Service = "iso-ip"          // ISO-IP
	ServiceJargon          Service = "jargon"          // Jargon
	ServiceAed512          Service = "aed-512"         // AED 512 Emulation Service
	ServiceHems            Service = "hems"            // HEMS
	ServiceBftp            Service = "bftp"            // Background File Transfer Program
	ServiceSgmp            Service = "sgmp"            // SGMP
	ServiceNetscProd       Service = "netsc-prod"      // NETSC
	ServiceNetscDev        Service = "netsc-dev"       // NETSC
	ServiceSqlsrv          Service = "sqlsrv"          // SQL Service
	ServiceKnetCmp         Service = "knet-cmp"        // KNET/VM Command/Message Protocol
	ServicePcmailSrv       Service = "pcmail-srv"      // PCMail Server
	ServiceNssRouting      Service = "nss-routing"     // NSS-Routing
	ServiceSgmpTraps       Service = "sgmp-traps"      // SGMP-TRAPS
	ServiceXnsCourier      Service = "xns-courier"     // Xerox
	ServiceSNet            Service = "s-net"           // Sirius Systems
	ServiceNamp            Service = "namp"            // NAMP
	ServiceRsvd            Service = "rsvd"            // RSVD
	ServiceSend            Service = "send"            // SEND
	ServicePrintSrv        Service = "print-srv"       // Network PostScript
	ServiceMultiplex       Service = "multiplex"       // Network Innovations Multiplex
	ServiceCl1             Service = "cl/1"            // Network Innovations CL/1
	ServiceXyplexMux       Service = "xyplex-mux"      // Xyplex
	ServiceVmnet           Service = "vmnet"           // VMNET
	ServiceGenradMux       Service = "genrad-mux"      // GENRAD-MUX
	ServiceRis             Service = "ris"             // Intergraph
	ServiceUnify           Service = "unify"           // Unify
	ServiceAudit           Service = "audit"           // Unisys Audit SITP
	ServiceOcbinder        Service = "ocbinder"        // OCBinder
	ServiceOcserver        Service = "ocserver"        // OCServer
	ServiceRemoteKis       Service = "remote-kis"      // Remote-KIS
	ServiceKis             Service = "kis"             // KIS Protocol
	ServiceAci             Service = "aci"             // Application Communication Interface
	ServiceMumps           Service = "mumps"           // Plus Five's MUMPS
	ServiceQft             Service = "qft"             // Queued File Transport
	ServiceGacp            Service = "gacp"            // Gateway Access Control Protocol
	ServiceOsuNms          Service = "osu-nms"         // OSU Network Monitoring System
	ServiceSrmp            Service = "srmp"            // Spider Remote Monitoring Protocol
	ServiceDn6NlmAud       Service = "dn6-nlm-aud"     // DNSIX Network Level Module Audit
	ServiceDn6SmmRed       Service = "dn6-smm-red"     // DNSIX Session Mgt Module Audit Redir
	ServiceDls             Service = "dls"             // Directory Location Service
	ServiceDlsMon          Service = "dls-mon"         // Directory Location Service Monitor
	ServiceSrc             Service = "src"             // IBM System Resource Controller
	ServiceAt3             Service = "at-3"            // AppleTalk Unused
	ServiceAt5             Service = "at-5"            // AppleTalk Unused
	ServiceAt7             Service = "at-7"            // AppleTalk Unused
	ServiceAt8             Service = "at-8"            // AppleTalk Unused
	Service914cG           Service = "914c/g"          // Texas Instruments 914C/G Terminal
	ServiceAnet            Service = "anet"            // ATEXSSTR
	ServiceVmpwscs         Service = "vmpwscs"         // VM PWSCS
	ServiceSoftpc          Service = "softpc"          // Insignia Solutions
	ServiceCAIlic          Service = "CAIlic"          // Computer Associates Int'l License Server
	ServiceDbase           Service = "dbase"           // dBASE Unix
	ServiceMpp             Service = "mpp"             // Netix Message Posting Protocol
	ServiceUarps           Service = "uarps"           // Unisys ARPs
	ServiceFlnSpx          Service = "fln-spx"         // Berkeley rlogind with SPX auth
	ServiceRshSpx          Service = "rsh-spx"         // Berkeley rshd with SPX auth
	ServiceCdc             Service = "cdc"             // Certificate Distribution Center
	ServiceMasqdialer      Service = "masqdialer"      // masqdialer
	ServiceDirect          Service = "direct"          // Direct
	ServiceSurMeas         Service = "sur-meas"        // Survey Measurement
	ServiceInbusiness      Service = "inbusiness"      // inbusiness
	ServiceDsp3270         Service = "dsp3270"         // Display Systems Protocol
	ServiceSubntbcst_tftp  Service = "subntbcst_tftp"  // SUBNTBCST_TFTP
	ServiceBhfhs           Service = "bhfhs"           // bhfhs
	ServiceSet             Service = "set"             // Secure Electronic Transaction
	ServiceEsroGen         Service = "esro-gen"        // Efficient Short Remote Operations
	ServiceOpenport        Service = "openport"        // Openport
	ServiceNsiiops         Service = "nsiiops"         // IIOP Name Service over TLS/SSL
	ServiceArcisdms        Service = "arcisdms"        // Arcisdms
	ServiceHdap            Service = "hdap"            // HDAP
	ServiceBgmp            Service = "bgmp"            // BGMP
	ServiceXBoneCtl        Service = "x-bone-ctl"      // X-Bone CTL
	ServiceSst             Service = "sst"             // SCSI on ST
	ServiceTdService       Service = "td-service"      // Tobit David Service Layer
	ServiceTdReplica       Service = "td-replica"      // Tobit David Replica
	ServiceManet           Service = "manet"           // MANET Protocols
	ServiceHttpMgmt        Service = "http-mgmt"       // http-mgmt
	ServicePersonalLink    Service = "personal-link"   // Personal Link
	ServiceCableportAx     Service = "cableport-ax"    // Cable Port A/X
	ServiceRescap          Service = "rescap"          // rescap
	ServiceCorerjd         Service = "corerjd"         // corerjd
	ServiceFxp             Service = "fxp"             // FXP Communication
	ServiceKBlock          Service = "k-block"         // K-BLOCK
	ServiceNovastorbakcup  Service = "novastorbakcup"  // Novastor Backup
	ServiceEntrusttime     Service = "entrusttime"     // EntrustTime
	ServiceBhmds           Service = "bhmds"           // bhmds
	ServiceAsipWebadmin    Service = "asip-webadmin"   // AppleShare IP WebAdmin
	ServiceVslmp           Service = "vslmp"           // VSLMP
	ServiceMagentaLogic    Service = "magenta-logic"   // Magenta Logic
	ServiceOpalisRobot     Service = "opalis-robot"    // Opalis Robot
	ServiceDpsi            Service = "dpsi"            // DPSI
	ServiceDecauth         Service = "decauth"         // decAuth
	ServiceZannet          Service = "zannet"          // Zannet
	ServicePkixTimestamp   Service = "pkix-timestamp"  // PKIX TimeStamp
	ServicePtpEvent        Service = "ptp-event"       // PTP Event
	ServicePtpGeneral      Service = "ptp-general"     // PTP General
	ServicePip             Service = "pip"             // PIP
	ServiceRtsps           Service = "rtsps"           // RTSPS
	ServiceRpkiRtr         Service = "rpki-rtr"        // Resource PKI to Router
	ServiceRpkiRtrTls      Service = "rpki-rtr-tls"    // Resource PKI to Router
	ServiceTexar           Service = "texar"           // Texar Security Port
	ServicePdap            Service = "pdap"            // Prospero Data Access Protocol
	ServicePawserv         Service = "pawserv"         // Perf Analysis Workbench
	ServiceZserv           Service = "zserv"           // Zebra server
	ServiceCsiSgwp         Service = "csi-sgwp"        // Cabletron Management Protocol
	ServiceMftp            Service = "mftp"            // mftp
	ServiceMatipTypeA      Service = "matip-type-a"    // MATIP Type A
	ServiceMatipTypeB      Service = "matip-type-b"    // MATIP Type B / bhoetty (added 5/21/97)
	ServiceDtagSteSb       Service = "dtag-ste-sb"     // DTAG (assigned long ago) / bhoedap4
	ServiceNdsauth         Service = "ndsauth"         // NDSAUTH
	ServiceBh611           Service = "bh611"           // bh611
	ServiceDatexAsn        Service = "datex-asn"       // DATEX-ASN
	ServiceCloantoNet1     Service = "cloanto-net-1"   // Cloanto Net 1
	ServiceBhevent         Service = "bhevent"         // bhevent
	ServiceShrinkwrap      Service = "shrinkwrap"      // Shrinkwrap
	ServiceNsrmp           Service = "nsrmp"           // Network Security Risk Management Protocol
	ServiceScoi2odialog    Service = "scoi2odialog"    // scoi2odialog
	ServiceSemantix        Service = "semantix"        // Semantix
	ServiceSrssend         Service = "srssend"         // SRS Send
	ServiceAuroraCmgr      Service = "aurora-cmgr"     // Aurora CMGR
	ServiceDtk             Service = "dtk"             // DTK
	ServiceMortgageware    Service = "mortgageware"    // MortgageWare
	ServiceQbikgdp         Service = "qbikgdp"         // QbikGDP
	ServiceClearcase       Service = "clearcase"       // Clearcase
	ServiceLegent1         Service = "legent-1"        // Legent Corporation
	ServiceLegent2         Service = "legent-2"        // Legent Corporation
	ServiceHassle          Service = "hassle"          // Hassle
	ServiceNip             Service = "nip"             // Amiga Envoy Network Inquiry Proto
	ServiceTnETOS          Service = "tnETOS"          // NEC Corporation
	ServiceDsETOS          Service = "dsETOS"          // NEC Corporation
	ServiceIs99c           Service = "is99c"           // TIA/EIA/IS-99 modem client
	ServiceIs99s           Service = "is99s"           // TIA/EIA/IS-99 modem server
	ServiceHpCollector     Service = "hp-collector"    // hp performance data collector
	ServiceHpManagedNode   Service = "hp-managed-node" // hp performance data managed node
	ServiceHpAlarmMgr      Service = "hp-alarm-mgr"    // hp performance data alarm manager
	ServiceArns            Service = "arns"            // A Remote Network Server System
	ServiceIbmApp          Service = "ibm-app"         // IBM Application
	ServiceAsa             Service = "asa"             // ASA Message Router Object Def.
	ServiceAurp            Service = "aurp"            // Appletalk Update-Based Routing Pro.
	ServiceUnidataLdm      Service = "unidata-ldm"     // Unidata LDM
	ServiceUis             Service = "uis"             // UIS
	ServiceSynoticsRelay   Service = "synotics-relay"  // SynOptics SNMP Relay Port
	ServiceSynoticsBroker  Service = "synotics-broker" // SynOptics Port Broker Port
	ServiceMeta5           Service = "meta5"           // Meta5
	ServiceEmblNdt         Service = "embl-ndt"        // EMBL Nucleic Data Transfer
	ServiceNetcp           Service = "netcp"           // NETscout Control Protocol
	ServiceNetwareIp       Service = "netware-ip"      // Novell Netware over IP
	ServiceMptn            Service = "mptn"            // Multi Protocol Trans. Net.
	ServiceKryptolan       Service = "kryptolan"       // Kryptolan
	ServiceIsoTsapC2       Service = "iso-tsap-c2"     // ISO Transport Class 2 Non-Control over TCP
	ServiceUps             Service = "ups"             // Uninterruptible Power Supply
	ServiceGenie           Service = "genie"           // Genie Protocol
	ServiceDecap           Service = "decap"           // decap
	ServiceNced            Service = "nced"            // nced
	ServiceNcld            Service = "ncld"            // ncld
	ServiceImsp            Service = "imsp"            // Interactive Mail Support Protocol
	ServiceTimbuktu        Service = "timbuktu"        // Timbuktu
	ServicePrmSm           Service = "prm-sm"          // Prospero Resource Manager Sys. Man.
	ServicePrmNm           Service = "prm-nm"          // Prospero Resource Manager Node Man.
	ServiceDecladebug      Service = "decladebug"      // DECLadebug Remote Debug Protocol
	ServiceRmt             Service = "rmt"             // Remote MT Protocol
	ServiceSynopticsTrap   Service = "synoptics-trap"  // Trap Convention Port
	ServiceSmsp            Service = "smsp"            // Storage Management Services Protocol
	ServiceInfoseek        Service = "infoseek"        // InfoSeek
	ServiceBnet            Service = "bnet"            // BNet
	ServiceSilverplatter   Service = "silverplatter"   // Silverplatter
	ServiceOnmux           Service = "onmux"           // Onmux
	ServiceHyperG          Service = "hyper-g"         // Hyper-G
	ServiceAriel1          Service = "ariel1"          // Ariel 1
	ServiceSmpte           Service = "smpte"           // SMPTE
	ServiceAriel2          Service = "ariel2"          // Ariel 2
	ServiceAriel3          Service = "ariel3"          // Ariel 3
	ServiceOpcJobStart     Service = "opc-job-start"   // IBM Operations Planning and Control Start
	ServiceOpcJobTrack     Service = "opc-job-track"   // IBM Operations Planning and Control Track
	ServiceIcadEl          Service = "icad-el"         // ICAD
	ServiceSmartsdp        Service = "smartsdp"        // smartsdp
	ServiceOcs_cmu         Service = "ocs_cmu"         // OCS_CMU
	ServiceOcs_amu         Service = "ocs_amu"         // OCS_AMU
	ServiceUtmpsd          Service = "utmpsd"          // UTMPSD
	ServiceUtmpcd          Service = "utmpcd"          // UTMPCD
	ServiceIasd            Service = "iasd"            // IASD
	ServiceNnsp            Service = "nnsp"            // NNSP
	ServiceDnaCml          Service = "dna-cml"         // DNA-CML
	ServiceComscm          Service = "comscm"          // comscm
	ServiceDsfgw           Service = "dsfgw"           // dsfgw
	ServiceDasp            Service = "dasp"            // dasp Thomas Obermair
	ServiceSgcp            Service = "sgcp"            // sgcp
	ServiceDecvmsSysmgt    Service = "decvms-sysmgt"   // decvms-sysmgt
	ServiceCvc_hostd       Service = "cvc_hostd"       // cvc_hostd
	ServiceDdmRdb          Service = "ddm-rdb"         // DDM-Remote Relational Database Access
	ServiceDdmDfm          Service = "ddm-dfm"         // DDM-Distributed File Management
	ServiceDdmSsl          Service = "ddm-ssl"         // DDM-Remote DB Access Using Secure Sockets
	ServiceAsServermap     Service = "as-servermap"    // AS Server Mapper
	ServiceTserver         Service = "tserver"         // Computer Supported Telecomunication Applications
	ServiceSfsSmpNet       Service = "sfs-smp-net"     // Cray Network Semaphore server
	ServiceSfsConfig       Service = "sfs-config"      // Cray SFS config server
	ServiceCreativeserver  Service = "creativeserver"  // CreativeServer
	ServiceContentserver   Service = "contentserver"   // ContentServer
	ServiceCreativepartnr  Service = "creativepartnr"  // CreativePartnr
	ServiceMaconTcp        Service = "macon-tcp"       // macon-tcp
	ServiceMaconUdp        Service = "macon-udp"       // macon-udp
	ServiceScohelp         Service = "scohelp"         // scohelp
	ServiceAppleqtc        Service = "appleqtc"        // apple quick time
	ServiceAmprRcmd        Service = "ampr-rcmd"       // ampr-rcmd
	ServiceSkronk          Service = "skronk"          // skronk
	ServiceDatasurfsrv     Service = "datasurfsrv"     // DataRampSrv
	ServiceDatasurfsrvsec  Service = "datasurfsrvsec"  // DataRampSrvSec
	ServiceAlpes           Service = "alpes"           // alpes
	ServiceUrd             Service = "urd"             // URL Rendesvous Directory for SSM / SMTP over SSL (TLS)
	ServiceIgmpv3lite      Service = "igmpv3lite"      // IGMP over UDP for SSM
	ServiceDigitalVrc      Service = "digital-vrc"     // digital-vrc
	ServiceMylexMapd       Service = "mylex-mapd"      // mylex-mapd
	ServiceRcp             Service = "rcp"             // Radio Control Protocol
	ServiceScxProxy        Service = "scx-proxy"       // scx-proxy
	ServiceMondex          Service = "mondex"          // Mondex
	ServiceLjkLogin        Service = "ljk-login"       // ljk-login
	ServiceHybridPop       Service = "hybrid-pop"      // hybrid-pop
	ServiceTnTlW1          Service = "tn-tl-w1"        // tn-tl-w1
	ServiceTnTlW2          Service = "tn-tl-w2"        // tn-tl-w2
	ServiceTcpnethaspsrv   Service = "tcpnethaspsrv"   // tcpnethaspsrv
	ServiceTnTlFd1         Service = "tn-tl-fd1"       // tn-tl-fd1
	ServiceSs7ns           Service = "ss7ns"           // ss7ns
	ServiceSpsc            Service = "spsc"            // spsc
	ServiceIafserver       Service = "iafserver"       // iafserver
	ServiceIafdbase        Service = "iafdbase"        // iafdbase
	ServicePh              Service = "ph"              // Ph service
	ServiceBgsNsi          Service = "bgs-nsi"         // bgs-nsi
	ServiceUlpnet          Service = "ulpnet"          // ulpnet
	ServiceIntegraSme      Service = "integra-sme"     // Integra Software Management Environment
	ServicePowerburst      Service = "powerburst"      // Air Soft Power Burst
	ServiceAvian           Service = "avian"           // avian
	ServiceNestProtocol    Service = "nest-protocol"   // nest-protocol
	ServiceMicomPfs        Service = "micom-pfs"       // micom-pfs
	ServiceGoLogin         Service = "go-login"        // go-login
	ServiceTicf1           Service = "ticf-1"          // Transport Independent Convergence for FNA
	ServiceTicf2           Service = "ticf-2"          // Transport Independent Convergence for FNA
	ServicePovRay          Service = "pov-ray"         // POV-Ray
	ServiceIntecourier     Service = "intecourier"     // intecourier
	ServiceRetrospect      Service = "retrospect"      // Retrospect backup
	ServiceSiam            Service = "siam"            // siam
	ServiceIsoIll          Service = "iso-ill"         // ISO ILL Protocol
	ServiceStmf            Service = "stmf"            // STMF
	ServiceAsaApplProto    Service = "asa-appl-proto"  // asa-appl-proto
	ServiceIntrinsa        Service = "intrinsa"        // Intrinsa
	ServiceCitadel         Service = "citadel"         // citadel
	ServiceMailboxLm       Service = "mailbox-lm"      // mailbox-lm
	ServiceOhimsrv         Service = "ohimsrv"         // ohimsrv
	ServiceCrs             Service = "crs"             // crs
	ServiceXvttp           Service = "xvttp"           // xvttp
	ServiceSnare           Service = "snare"           // snare
	ServiceFcp             Service = "fcp"             // FirstClass Protocol
	ServicePassgo          Service = "passgo"          // PassGo
	ServiceVideotex        Service = "videotex"        // videotex
	ServiceUlp             Service = "ulp"             // ULP
	ServiceIbmDb2          Service = "ibm-db2"         // IBM-DB2
	ServiceNcp             Service = "ncp"             // NCP
	ServiceStx             Service = "stx"             // Stock IXChange
	ServiceCustix          Service = "custix"          // Customer IXChange
	ServiceIrcServ         Service = "irc-serv"        // IRC-SERV
	ServiceWindream        Service = "windream"        // windream Admin
	ServiceOpalisRdv       Service = "opalis-rdv"      // opalis-rdv
	ServiceNmsp            Service = "nmsp"            // Networked Media Streaming Protocol
	ServiceApertusLdp      Service = "apertus-ldp"     // Apertus Technologies Load Determination
	ServiceUucpRlogin      Service = "uucp-rlogin"     // uucp-rlogin
	ServiceCommerce        Service = "commerce"        // commerce
	ServiceAppleqtcsrvr    Service = "appleqtcsrvr"    // appleqtcsrvr
	ServiceIdfp            Service = "idfp"            // IDFP
	ServiceNewRwho         Service = "new-rwho"        // new-who
	ServiceCybercash       Service = "cybercash"       // cybercash
	ServiceDevshrNts       Service = "devshr-nts"      // DeviceShare
	ServicePirp            Service = "pirp"            // pirp
	ServiceDsf             Service = "dsf"             //
	ServiceOpenvmsSysipc   Service = "openvms-sysipc"  // openvms-sysipc
	ServiceSdnskmp         Service = "sdnskmp"         // SDNSKMP
	ServiceTeedtap         Service = "teedtap"         // TEEDTAP
	ServiceRmonitor        Service = "rmonitor"        // rmonitord
	ServiceMonitor         Service = "monitor"         //
	ServiceChshell         Service = "chshell"         // chcmd
	Service9pfs            Service = "9pfs"            // plan 9 file service
	ServiceStreettalk      Service = "streettalk"      // streettalk
	ServiceBanyanRpc       Service = "banyan-rpc"      // banyan-rpc
	ServiceMsShuttle       Service = "ms-shuttle"      // microsoft shuttle
	ServiceMsRome          Service = "ms-rome"         // microsoft rome
	ServiceMeter           Service = "meter"           // demon
	ServiceSonar           Service = "sonar"           // sonar
	ServiceBanyanVip       Service = "banyan-vip"      // banyan-vip
	ServiceFtpAgent        Service = "ftp-agent"       // FTP Software Agent System
	ServiceVemmi           Service = "vemmi"           // VEMMI
	ServiceIpcd            Service = "ipcd"            // ipcd
	ServiceVnas            Service = "vnas"            // vnas
	ServiceIpdd            Service = "ipdd"            // ipdd
	ServiceDecbsrv         Service = "decbsrv"         // decbsrv
	ServiceSntpHeartbeat   Service = "sntp-heartbeat"  // SNTP HEARTBEAT
	ServiceBdp             Service = "bdp"             // Bundle Discovery Protocol
	ServiceSccSecurity     Service = "scc-security"    // SCC Security
	ServicePhilipsVc       Service = "philips-vc"      // Philips Video-Conferencing
	ServiceKeyserver       Service = "keyserver"       // Key Server
	ServicePasswordChg     Service = "password-chg"    // Password Change
	ServiceCal             Service = "cal"             // CAL
	ServiceEyelink         Service = "eyelink"         // EyeLink
	ServiceTnsCml          Service = "tns-cml"         // TNS CML
	ServiceEudoraSet       Service = "eudora-set"      // Eudora Set
	ServiceHttpRpcEpmap    Service = "http-rpc-epmap"  // HTTP RPC Ep Map
	ServiceTpip            Service = "tpip"            // TPIP
	ServiceCabProtocol     Service = "cab-protocol"    // CAB Protocol
	ServiceSmsd            Service = "smsd"            // SMSD
	ServicePtcnameservice  Service = "ptcnameservice"  // PTC Name Service
	ServiceScoWebsrvrmg3   Service = "sco-websrvrmg3"  // SCO Web Server Manager 3
	ServiceAcp             Service = "acp"             // Aeolon Core Protocol
	ServiceIpcserver       Service = "ipcserver"       // Sun IPC server
	ServiceSyslogConn      Service = "syslog-conn"     // Reliable Syslog Service
	ServiceXmlrpcBeep      Service = "xmlrpc-beep"     // XML-RPC over BEEP
	ServiceIdxp            Service = "idxp"            // IDXP
	ServiceTunnel          Service = "tunnel"          // TUNNEL
	ServiceSoapBeep        Service = "soap-beep"       // SOAP over BEEP
	ServiceUrm             Service = "urm"             // Cray Unified Resource Manager
	ServiceNqs             Service = "nqs"             // nqs
	ServiceSiftUft         Service = "sift-uft"        // Sender-Initiated/Unsolicited File Transfer
	ServiceNpmpTrap        Service = "npmp-trap"       // npmp-trap
	ServiceHmmpOp          Service = "hmmp-op"         // HMMP Operation
	ServiceSshell          Service = "sshell"          // SSLshell
	ServiceScoInetmgr      Service = "sco-inetmgr"     // Internet Configuration Manager
	ServiceScoSysmgr       Service = "sco-sysmgr"      // SCO System Administration Server
	ServiceScoDtmgr        Service = "sco-dtmgr"       // SCO Desktop Administration Server
	ServiceDeiIcda         Service = "dei-icda"        // DEI-ICDA
	ServiceCompaqEvm       Service = "compaq-evm"      // Compaq EVM
	ServiceScoWebsrvrmgr   Service = "sco-websrvrmgr"  // SCO WebServer Manager
	ServiceEscpIp          Service = "escp-ip"         // ESCP
	ServiceCollaborator    Service = "collaborator"    // Collaborator
	ServiceOobWsHttp       Service = "oob-ws-http"     // DMTF out-of-band web services management protocol
	ServiceAsfRmcp         Service = "asf-rmcp"        // ASF Remote Management and Control Protocol
	ServiceCryptoadmin     Service = "cryptoadmin"     // Crypto Admin
	ServiceDec_dlm         Service = "dec_dlm"         // DEC DLM
	ServiceAsia            Service = "asia"            // ASIA
	ServicePassgoTivoli    Service = "passgo-tivoli"   // PassGo Tivoli
	ServiceQmqp            Service = "qmqp"            // QMQP
	Service3comAmp3        Service = "3com-amp3"       // 3Com AMP3
	ServiceRda             Service = "rda"             // RDA
	ServiceBmpp            Service = "bmpp"            // bmpp
	ServiceServstat        Service = "servstat"        // Service Status update (Sterling Software)
	ServiceGinad           Service = "ginad"           // ginad
	ServiceRlzdbase        Service = "rlzdbase"        // RLZ DBase
	ServiceLanserver       Service = "lanserver"       // lanserver
	ServiceMcnsSec         Service = "mcns-sec"        // mcns-sec
	ServiceMsdp            Service = "msdp"            // MSDP
	ServiceEntrustSps      Service = "entrust-sps"     // entrust-sps
	ServiceRepcmd          Service = "repcmd"          // repcmd
	ServiceEsroEmsdp       Service = "esro-emsdp"      // ESRO-EMSDP V1.3
	ServiceSanity          Service = "sanity"          // SANity
	ServiceDwr             Service = "dwr"             // dwr
	ServicePssc            Service = "pssc"            // PSSC
	ServiceLdp             Service = "ldp"             // LDP
	ServiceDhcpFailover    Service = "dhcp-failover"   // DHCP Failover
	ServiceRrp             Service = "rrp"             // Registry Registrar Protocol (RRP)
	ServiceCadview3d       Service = "cadview-3d"      // Cadview-3d - streaming 3d models over the internet
	ServiceObex            Service = "obex"            // OBEX
	ServiceIeeeMms         Service = "ieee-mms"        // IEEE MMS
	ServiceHelloPort       Service = "hello-port"      // HELLO_PORT
	ServiceRepscmd         Service = "repscmd"         // RepCmd
	ServiceAodv            Service = "aodv"            // AODV
	ServiceTinc            Service = "tinc"            // TINC
	ServiceSpmp            Service = "spmp"            // SPMP
	ServiceRmc             Service = "rmc"             // RMC
	ServiceTenfold         Service = "tenfold"         // TenFold
	ServiceMacSrvrAdmin    Service = "mac-srvr-admin"  // MacOS Server Admin
	ServiceHap             Service = "hap"             // HAP
	ServicePftp            Service = "pftp"            // PFTP
	ServicePurenoise       Service = "purenoise"       // PureNoise
	ServiceOobWsHttps      Service = "oob-ws-https"    // DMTF out-of-band secure web services management protocol
	ServiceAsfSecureRmcp   Service = "asf-secure-rmcp" // ASF Secure Remote Management and Control Protocol
	ServiceSunDr           Service = "sun-dr"          // Sun DR
	ServiceMdqs            Service = "mdqs"            // doom Id Software
	ServiceDisclose        Service = "disclose"        // campaign contribution disclosures - SDR Technologies
	ServiceMecomm          Service = "mecomm"          // MeComm
	ServiceMeregister      Service = "meregister"      // MeRegister
	ServiceVacdsmSws       Service = "vacdsm-sws"      // VACDSM-SWS
	ServiceVacdsmApp       Service = "vacdsm-app"      // VACDSM-APP
	ServiceVppsQua         Service = "vpps-qua"        // VPPS-QUA
	ServiceCimplex         Service = "cimplex"         // CIMPLEX
	ServiceDctp            Service = "dctp"            // DCTP
	ServiceVppsVia         Service = "vpps-via"        // VPPS Via
	ServiceVpp             Service = "vpp"             // Virtual Presence Protocol
	ServiceGgfNcp          Service = "ggf-ncp"         // GNU Generation Foundation NCP
	ServiceMrm             Service = "mrm"             // MRM
	ServiceEntrustAaas     Service = "entrust-aaas"    // entrust-aaas
	ServiceEntrustAams     Service = "entrust-aams"    // entrust-aams
	ServiceXfr             Service = "xfr"             // XFR
	ServiceCorbaIiop       Service = "corba-iiop"      // CORBA IIOP
	ServiceCorbaIiopSsl    Service = "corba-iiop-ssl"  // CORBA IIOP SSL
	ServiceMdcPortmapper   Service = "mdc-portmapper"  // MDC Port Mapper
	ServiceHcpWismar       Service = "hcp-wismar"      // Hardware Control Protocol Wismar
	ServiceAsipregistry    Service = "asipregistry"    // asipregistry
	ServiceRealmRusd       Service = "realm-rusd"      // ApplianceWare managment protocol
	ServiceNmap            Service = "nmap"            // NMAP
	ServiceVatp            Service = "vatp"            // Velazquez Application Transfer Protocol
	ServiceMsexchRouting   Service = "msexch-routing"  // MS Exchange Routing
	ServiceHyperwaveIsp    Service = "hyperwave-isp"   // Hyperwave-ISP
	ServiceConnendp        Service = "connendp"        // almanid Connection Endpoint
	ServiceIeeeMmsSsl      Service = "ieee-mms-ssl"    // IEEE-MMS-SSL
	ServiceRushd           Service = "rushd"           // RUSHD
	ServiceUuidgen         Service = "uuidgen"         // UUIDGEN
	ServiceOlsr            Service = "olsr"            // OLSR
	ServiceAccessnetwork   Service = "accessnetwork"   // Access Network
	ServiceEpp             Service = "epp"             // Extensible Provisioning Protocol
	ServiceLmp             Service = "lmp"             // Link Management Protocol (LMP)
	ServiceIrisBeep        Service = "iris-beep"       // IRIS over BEEP
	ServiceElcsd           Service = "elcsd"           // errlog copy/server daemon
	ServiceAgentx          Service = "agentx"          // AgentX
	ServiceSilc            Service = "silc"            // SILC
	ServiceBorlandDsj      Service = "borland-dsj"     // Borland DSJ
	ServiceEntrustKmsh     Service = "entrust-kmsh"    // Entrust Key Management Service Handler
	ServiceEntrustAsh      Service = "entrust-ash"     // Entrust Administration Service Handler
	ServiceCiscoTdp        Service = "cisco-tdp"       // Cisco TDP
	ServiceTbrpf           Service = "tbrpf"           // TBRPF
	ServiceIrisXpc         Service = "iris-xpc"        // IRIS over XPC
	ServiceIrisXpcs        Service = "iris-xpcs"       // IRIS over XPCS
	ServiceIrisLwz         Service = "iris-lwz"        // IRIS-LWZ
	ServicePana            Service = "pana"            // PANA Messages
	ServiceNetviewdm1      Service = "netviewdm1"      // IBM NetView DM/6000 Server/Client
	ServiceNetviewdm2      Service = "netviewdm2"      // IBM NetView DM/6000 send/tcp
	ServiceNetviewdm3      Service = "netviewdm3"      // IBM NetView DM/6000 receive/tcp
	ServiceNetgw           Service = "netgw"           // netGW
	ServiceNetrcs          Service = "netrcs"          // Network based Rev. Cont. Sys.
	ServiceFlexlm          Service = "flexlm"          // Flexible License Manager
	ServiceFujitsuDev      Service = "fujitsu-dev"     // Fujitsu Device Control
	ServiceRisCm           Service = "ris-cm"          // Russell Info Sci Calendar Manager
	ServiceQrh             Service = "qrh"             //
	ServiceRrh             Service = "rrh"             //
	ServiceTell            Service = "tell"            // send
	ServiceNlogin          Service = "nlogin"          //
	ServiceCon             Service = "con"             //
	ServiceNs              Service = "ns"              //
	ServiceRxe             Service = "rxe"             //
	ServiceQuotad          Service = "quotad"          //
	ServiceCycleserv       Service = "cycleserv"       //
	ServiceOmserv          Service = "omserv"          //
	ServiceVid             Service = "vid"             //
	ServiceCadlock         Service = "cadlock"         //
	ServiceRtip            Service = "rtip"            //
	ServiceCycleserv2      Service = "cycleserv2"      //
	ServiceSubmit          Service = "submit"          //
	ServiceNotify          Service = "notify"          //
	ServiceRpasswd         Service = "rpasswd"         //
	ServiceAcmaint_dbd     Service = "acmaint_dbd"     //
	ServiceEntomb          Service = "entomb"          //
	ServiceAcmaint_transd  Service = "acmaint_transd"  //
	ServiceWpages          Service = "wpages"          //
	ServiceMultilingHttp   Service = "multiling-http"  // Multiling HTTP
	ServiceWpgs            Service = "wpgs"            //
	ServiceMdbs_daemon     Service = "mdbs_daemon"     //
	ServiceDevice          Service = "device"          //
	ServiceFcpUdp          Service = "fcp-udp"         // FCP
	ServiceItmMcellS       Service = "itm-mcell-s"     // itm-mcell-s
	ServicePkix3CaRa       Service = "pkix-3-ca-ra"    // PKIX-3 CA/RA
	ServiceNetconfSsh      Service = "netconf-ssh"     // NETCONF over SSH
	ServiceNetconfBeep     Service = "netconf-beep"    // NETCONF over BEEP
	ServiceNetconfsoaphttp Service = "netconfsoaphttp" // NETCONF for SOAP over HTTPS
	ServiceNetconfsoapbeep Service = "netconfsoapbeep" // NETCONF for SOAP over BEEP
	ServiceDhcpFailover2   Service = "dhcp-failover2"  // dhcp-failover 2
	ServiceGdoi            Service = "gdoi"            // GDOI
	ServiceIscsi           Service = "iscsi"           // iSCSI
	ServiceOwampControl    Service = "owamp-control"   // OWAMP-Control
	ServiceTwampControl    Service = "twamp-control"   // Two-way Active Measurement Protocol (TWAMP) Control
	ServiceIclcnetLocate   Service = "iclcnet-locate"  // ICL coNETion locate server
	ServiceIclcnet_svinfo  Service = "iclcnet_svinfo"  // ICL coNETion server info
	ServiceCddbp           Service = "cddbp"           // CD Database Protocol
	ServiceOmginitialrefs  Service = "omginitialrefs"  // OMG Initial Refs
	ServiceSmpnameres      Service = "smpnameres"      // SMPNAMERES
	ServiceIdeafarmDoor    Service = "ideafarm-door"   // self documenting Telnet Door
	ServiceIdeafarmPanic   Service = "ideafarm-panic"  // self documenting Telnet Panic Door
	ServiceKink            Service = "kink"            // Kerberized Internet Negotiation of Keys (KINK)
	ServiceXactBackup      Service = "xact-backup"     // xact-backup
	ServiceApexMesh        Service = "apex-mesh"       // APEX relay-relay service
	ServiceApexEdge        Service = "apex-edge"       // APEX endpoint-relay service
	ServiceFtpsData        Service = "ftps-data"       // ftp protocol, data, over TLS/SSL
	ServiceFtps            Service = "ftps"            // ftp protocol, control, over TLS/SSL
	ServiceNas             Service = "nas"             // Netnews Administration System
	ServiceVsinet          Service = "vsinet"          // vsinet
	ServiceMaitrd          Service = "maitrd"          //
	ServiceBusboy          Service = "busboy"          //
	ServicePuparp          Service = "puparp"          //
	ServiceGarcon          Service = "garcon"          //
	ServiceApplix          Service = "applix"          // Applix ac
	ServiceCadlock2        Service = "cadlock2"        //
	ServiceSurf            Service = "surf"            // surf
	ServiceExp1            Service = "exp1"            // RFC3692-style Experiment 1 (*) [RFC4727]
	ServiceExp2            Service = "exp2"            // RFC3692-style Experiment 2 (*) [RFC4727]
	ServiceBlackjack       Service = "blackjack"       // network blackjack
	ServiceCap             Service = "cap"             // Calendar Access Protocol
	Service6a44            Service = "6a44"            // IPv6 Behind NAT44 CPEs
	ServiceSolidMux        Service = "solid-mux"       // Solid Mux Server
	ServiceIad1            Service = "iad1"            // BBN IAD
	ServiceIad2            Service = "iad2"            // BBN IAD
	ServiceIad3            Service = "iad3"            // BBN IAD
	ServiceNetinfoLocal    Service = "netinfo-local"   // local netinfo port
	ServiceActivesync      Service = "activesync"      // ActiveSync Notifications
	ServiceMxxrlogin       Service = "mxxrlogin"       // MX-XR RPC
	ServiceNsstp           Service = "nsstp"           // Nebula Secure Segment Transfer Protocol
	ServiceAms             Service = "ams"             // AMS
	ServiceMtqp            Service = "mtqp"            // Message Tracking Query Protocol
	ServiceSbl             Service = "sbl"             // Streamlined Blackhole
	ServiceNetarx          Service = "netarx"          // Netarx Netcare
	ServiceDanfAk2         Service = "danf-ak2"        // AK2 Product
	ServiceAfrog           Service = "afrog"           // Subnet Roaming
	ServiceBoincClient     Service = "boinc-client"    // BOINC Client Control
	ServiceDcutility       Service = "dcutility"       // Dev Consortium Utility
	ServiceFpitp           Service = "fpitp"           // Fingerprint Image Transfer Protocol
	ServiceWfremotertm     Service = "wfremotertm"     // WebFilter Remote Monitor
	ServiceNeod1           Service = "neod1"           // Sun's NEO Object Request Broker
	ServiceNeod2           Service = "neod2"           // Sun's NEO Object Request Broker
	ServiceTdPostman       Service = "td-postman"      // Tobit David Postman VPMN
	ServiceCma             Service = "cma"             // CORBA Management Agent
	ServiceOptimaVnet      Service = "optima-vnet"     // Optima VNET
	ServiceDdt             Service = "ddt"             // Dynamic DNS Tools
	ServiceRemoteAs        Service = "remote-as"       // Remote Assistant (RA)
	ServiceBrvread         Service = "brvread"         // BRVREAD
	ServiceAnsyslmd        Service = "ansyslmd"        // ANSYS - License Manager
	ServiceVfo             Service = "vfo"             // VFO
	ServiceStartron        Service = "startron"        // STARTRON
	ServiceNim             Service = "nim"             // nim
	ServiceNimreg          Service = "nimreg"          // nimreg
	ServicePolestar        Service = "polestar"        // POLESTAR
	ServiceKiosk           Service = "kiosk"           // KIOSK
	ServiceVeracity        Service = "veracity"        // Veracity
	ServiceKyoceranetdev   Service = "kyoceranetdev"   // KyoceraNetDev
	ServiceJstel           Service = "jstel"           // JSTEL
	ServiceSyscomlan       Service = "syscomlan"       // SYSCOMLAN
	ServiceFpoFns          Service = "fpo-fns"         // FPO-FNS
	ServiceInstl_boots     Service = "instl_boots"     // Installation Bootstrap Proto. Serv.
	ServiceInstl_bootc     Service = "instl_bootc"     // Installation Bootstrap Proto. Cli.
	ServiceCognexInsight   Service = "cognex-insight"  // COGNEX-INSIGHT
	ServiceGmrupdateserv   Service = "gmrupdateserv"   // GMRUpdateSERV
	ServiceBsquareVoip     Service = "bsquare-voip"    // BSQUARE-VOIP
	ServiceCardax          Service = "cardax"          // CARDAX
	ServiceBridgecontrol   Service = "bridgecontrol"   // Bridge Control
	ServiceWarmspotMgmt    Service = "warmspotMgmt"    // Warmspot Management Protocol
	ServiceRdrmshc         Service = "rdrmshc"         // RDRMSHC
	ServiceDabStiC         Service = "dab-sti-c"       // DAB STI-C
	ServiceImgames         Service = "imgames"         // IMGames
	ServiceAvocentProxy    Service = "avocent-proxy"   // Avocent Proxy Protocol
	ServiceAsprovatalk     Service = "asprovatalk"     // ASPROVATalk
	ServicePvuniwien       Service = "pvuniwien"       // PVUNIWIEN
	ServiceAmtEsdProt      Service = "amt-esd-prot"    // AMT-ESD-PROT
	ServiceAnsoftLm1       Service = "ansoft-lm-1"     // Anasoft License Manager
	ServiceAnsoftLm2       Service = "ansoft-lm-2"     // Anasoft License Manager
	ServiceWebobjects      Service = "webobjects"      // Web Objects
	ServiceCplscramblerLg  Service = "cplscrambler-lg" // CPL Scrambler Logging
	ServiceCplscramblerIn  Service = "cplscrambler-in" // CPL Scrambler Internal
	ServiceCplscramblerAl  Service = "cplscrambler-al" // CPL Scrambler Alarm Log
	ServiceFfAnnunc        Service = "ff-annunc"       // FF Annunciation
	ServiceFfFms           Service = "ff-fms"          // FF Fieldbus Message Specification
	ServiceFfSm            Service = "ff-sm"           // FF System Management
	ServiceObrpd           Service = "obrpd"           // Open Business Reporting Protocol
	ServiceProofd          Service = "proofd"          // PROOFD
	ServiceRootd           Service = "rootd"           // ROOTD
	ServiceNicelink        Service = "nicelink"        // NICELink
	ServiceCnrprotocol     Service = "cnrprotocol"     // Common Name Resolution Protocol
	ServiceSunclustermgr   Service = "sunclustermgr"   // Sun Cluster Manager
	ServiceRmiactivation   Service = "rmiactivation"   // RMI Activation
	ServiceRmiregistry     Service = "rmiregistry"     // RMI Registry
	ServiceMctp            Service = "mctp"            // MCTP
	ServicePt2Discover     Service = "pt2-discover"    // PT2-DISCOVER
	ServiceAdobeserver1    Service = "adobeserver-1"   // ADOBE SERVER 1
	ServiceAdobeserver2    Service = "adobeserver-2"   // ADOBE SERVER 2
	ServiceXrl             Service = "xrl"             // XRL
	ServiceFtranhc         Service = "ftranhc"         // FTRANHC
	ServiceIsoipsigport1   Service = "isoipsigport-1"  // ISOIPSIGPORT-1
	ServiceIsoipsigport2   Service = "isoipsigport-2"  // ISOIPSIGPORT-2
	ServiceRatioAdp        Service = "ratio-adp"       // ratio-adp
	ServiceWebadmstart     Service = "webadmstart"     // Start web admin server
	ServiceNfsdKeepalive   Service = "nfsd-keepalive"  // Client status info
	ServiceLmsocialserver  Service = "lmsocialserver"  // LM Social Server
	ServiceIcp             Service = "icp"             // Intelligent Communication Protocol
	ServiceLtpDeepspace    Service = "ltp-deepspace"   // Licklider Transmission Protocol
	ServiceMiniSql         Service = "mini-sql"        // Mini SQL
	ServiceArdusTrns       Service = "ardus-trns"      // ARDUS Transfer
	ServiceArdusCntl       Service = "ardus-cntl"      // ARDUS Control
	ServiceArdusMtrns      Service = "ardus-mtrns"     // ARDUS Multicast Transfer
	ServiceSacred          Service = "sacred"          // SACRED
	ServiceBnetgame        Service = "bnetgame"        // Battle.net Chat/Game Protocol
	ServiceBnetfile        Service = "bnetfile"        // Battle.net File Transfer Protocol
	ServiceRmpp            Service = "rmpp"            // Datalode RMPP
	ServiceAvailantMgr     Service = "availant-mgr"    // availant-mgr
	ServiceMurray          Service = "murray"          // Murray
	ServiceHpvmmcontrol    Service = "hpvmmcontrol"    // HP VMM Control
	ServiceHpvmmagent      Service = "hpvmmagent"      // HP VMM Agent
	ServiceHpvmmdata       Service = "hpvmmdata"       // HP VMM Agent
	ServiceKwdbCommn       Service = "kwdb-commn"      // KWDB Remote Communication
	ServiceSaphostctrl     Service = "saphostctrl"     // SAPHostControl over SOAP/HTTP
	ServiceSaphostctrls    Service = "saphostctrls"    // SAPHostControl over SOAP/HTTPS
	ServiceCasp            Service = "casp"            // CAC App Service Protocol
	ServiceCaspssl         Service = "caspssl"         // CAC App Service Protocol Encripted
	ServiceKvmViaIp        Service = "kvm-via-ip"      // KVM-via-IP Management Service
	ServiceDfn             Service = "dfn"             // Data Flow Network
	ServiceAplx            Service = "aplx"            // MicroAPL APLX
	ServiceOmnivision      Service = "omnivision"      // OmniVision Communication Service
	ServiceHhbGateway      Service = "hhb-gateway"     // HHB Gateway Control
	ServiceTrim            Service = "trim"            // TRIM Workgroup Service
	ServiceEncrypted_admin Service = "encrypted_admin" // encrypted admin requests
	ServiceEvm             Service = "evm"             // Enterprise Virtual Manager
	ServiceAutonoc         Service = "autonoc"         // AutoNOC Network Operations Protocol
	ServiceMxomss          Service = "mxomss"          // User Message Service
	ServiceEdtools         Service = "edtools"         // User Discovery Service
	ServiceImyx            Service = "imyx"            // Infomatryx Exchange
	ServiceFuscript        Service = "fuscript"        // Fusion Script
	ServiceX9Icue          Service = "x9-icue"         // X9 iCue Show Control
	ServiceAuditTransfer   Service = "audit-transfer"  // audit transfer
	ServiceCapioverlan     Service = "capioverlan"     // CAPIoverLAN
	ServiceElfiqRepl       Service = "elfiq-repl"      // Elfiq Replication Service
	ServiceBvtsonar        Service = "bvtsonar"        // BlueView Sonar Service
	ServiceBlaze           Service = "blaze"           // Blaze File Server
	ServiceUnizensus       Service = "unizensus"       // Unizensus Login Server
	ServiceWinpoplanmess   Service = "winpoplanmess"   // Winpopup LAN Messenger
	ServiceC1222Acse       Service = "c1222-acse"      // ANSI C12.22 Port
	ServiceResacommunity   Service = "resacommunity"   // Community Service
	ServiceNfa             Service = "nfa"             // Network File Access
	ServiceIascontrolOms   Service = "iascontrol-oms"  // iasControl OMS
	ServiceIascontrol      Service = "iascontrol"      // Oracle iASControl
	ServiceDbcontrolOms    Service = "dbcontrol-oms"   // dbControl OMS
	ServiceOracleOms       Service = "oracle-oms"      // Oracle OMS
	ServiceOlsv            Service = "olsv"            // DB Lite Mult-User Server
	ServiceHealthPolling   Service = "health-polling"  // Health Polling
	ServiceHealthTrap      Service = "health-trap"     // Health Trap
	ServiceSddp            Service = "sddp"            // SmartDialer Data Protocol
	ServiceQsmProxy        Service = "qsm-proxy"       // QSM Proxy Service
	ServiceQsmGui          Service = "qsm-gui"         // QSM GUI Service
	ServiceQsmRemote       Service = "qsm-remote"      // QSM RemoteExec
	ServiceCiscoIpsla      Service = "cisco-ipsla"     // Cisco IP SLAs Control Protocol
	ServiceVchat           Service = "vchat"           // VChat Conference Service
	ServiceTripwire        Service = "tripwire"        // TRIPWIRE
	ServiceAtcLm           Service = "atc-lm"          // AT+C License Manager
	ServiceAtcAppserver    Service = "atc-appserver"   // AT+C FmiApplicationServer
	ServiceDnap            Service = "dnap"            // DNA Protocol
	ServiceDCinemaRrp      Service = "d-cinema-rrp"    // D-Cinema Request-Response
	ServiceFnetRemoteUi    Service = "fnet-remote-ui"  // FlashNet Remote Admin
	ServiceDossier         Service = "dossier"         // Dossier Server
	ServiceIndigoServer    Service = "indigo-server"   // Indigo Home Server
	ServiceDkmessenger     Service = "dkmessenger"     // DKMessenger Protocol
	ServiceSgiStorman      Service = "sgi-storman"     // SGI Storage Manager
	ServiceB2n             Service = "b2n"             // Backup To Neighbor
	ServiceMcClient        Service = "mc-client"       // Millicent Client Proxy
	Service3comnetman      Service = "3comnetman"      // 3Com Net Management
	ServiceAccelenet       Service = "accelenet"       // AcceleNet Control
	ServiceAccelenetData   Service = "accelenet-data"  // AcceleNet Data
	ServiceLlsurfupHttp    Service = "llsurfup-http"   // LL Surfup HTTP
	ServiceLlsurfupHttps   Service = "llsurfup-https"  // LL Surfup HTTPS
	ServiceCatchpole       Service = "catchpole"       // Catchpole port
	ServiceMysqlCluster    Service = "mysql-cluster"   // MySQL Cluster Manager
	ServiceAlias           Service = "alias"           // Alias Service
	ServiceHpWebadmin      Service = "hp-webadmin"     // HP Web Admin
	ServiceUnet            Service = "unet"            // Unet Connection
	ServiceCommlinxAvl     Service = "commlinx-avl"    // CommLinx GPS / AVL System
	ServiceGpfs            Service = "gpfs"            // General Parallel File System
	ServiceCaidsSensor     Service = "caids-sensor"    // caids sensors channel
	ServiceFiveacross      Service = "fiveacross"      // Five Across Server
	ServiceOpenvpn         Service = "openvpn"         // OpenVPN
	ServiceRsf1            Service = "rsf-1"           // RSF-1 clustering
	ServiceNetmagic        Service = "netmagic"        // Network Magic
	ServiceCarriusRshell   Service = "carrius-rshell"  // Carrius Remote Access
	ServiceCajoDiscovery   Service = "cajo-discovery"  // cajo reference discovery
	ServiceDmidi           Service = "dmidi"           // DMIDI
	ServiceScol            Service = "scol"            // SCOL
	ServiceNucleusSand     Service = "nucleus-sand"    // Nucleus Sand Database Server
	ServiceCaiccipc        Service = "caiccipc"        // caiccipc
	ServiceSsslicMgr       Service = "ssslic-mgr"      // License Validation
	ServiceSsslogMgr       Service = "ssslog-mgr"      // Log Request Listener
	ServiceAccordMgc       Service = "accord-mgc"      // Accord-MGC
	ServiceAnthonyData     Service = "anthony-data"    // Anthony Data
	ServiceMetasage        Service = "metasage"        // MetaSage
	ServiceSeagullAis      Service = "seagull-ais"     // SEAGULL AIS
	ServiceIpcd3           Service = "ipcd3"           // IPCD3
	ServiceEoss            Service = "eoss"            // EOSS
	ServiceGrooveDpp       Service = "groove-dpp"      // Groove DPP
	ServiceLupa            Service = "lupa"            // lupa
	ServiceMpcLifenet      Service = "mpc-lifenet"     // MPC LIFENET
	ServiceKazaa           Service = "kazaa"           // KAZAA
	ServiceScanstat1       Service = "scanstat-1"      // scanSTAT 1.0
	ServiceEtebac5         Service = "etebac5"         // ETEBAC 5
	ServiceHpssNdapi       Service = "hpss-ndapi"      // HPSS NonDCE Gateway
	ServiceAeroflightAds   Service = "aeroflight-ads"  // AeroFlight-ADs
	ServiceAeroflightRet   Service = "aeroflight-ret"  // AeroFlight-Ret
	ServiceQtServeradmin   Service = "qt-serveradmin"  // QT SERVER ADMIN
	ServiceSweetwareApps   Service = "sweetware-apps"  // SweetWARE Apps
	ServiceNerv            Service = "nerv"            // SNI R&D network
	ServiceTgp             Service = "tgp"             // TrulyGlobal Protocol
	ServiceVpnz            Service = "vpnz"            // VPNz
	ServiceSlinkysearch    Service = "slinkysearch"    // SLINKYSEARCH
	ServiceStgxfws         Service = "stgxfws"         // STGXFWS
	ServiceDns2go          Service = "dns2go"          // DNS2Go
	ServiceFlorence        Service = "florence"        // FLORENCE
	ServiceZented          Service = "zented"          // ZENworks Tiered Electronic Distribution
	ServicePeriscope       Service = "periscope"       // Periscope
	ServiceMenandmiceLpm   Service = "menandmice-lpm"  // menandmice-lpm
	ServiceFirstDefense    Service = "first-defense"   // Remote systems monitoring
	ServiceUnivAppserver   Service = "univ-appserver"  // Universal App Server
	ServiceSearchAgent     Service = "search-agent"    // Infoseek Search Agent
	ServiceMosaicsyssvc1   Service = "mosaicsyssvc1"   // mosaicsyssvc1
	ServiceTsdos390        Service = "tsdos390"        // tsdos390
	ServiceHaclQs          Service = "hacl-qs"         // hacl-qs
	ServiceNmsd            Service = "nmsd"            // NMSD
	ServiceInstantia       Service = "instantia"       // Instantia
	ServiceNessus          Service = "nessus"          // nessus
	ServiceNmasoverip      Service = "nmasoverip"      // NMAS over IP
	ServiceSerialgateway   Service = "serialgateway"   // SerialGateway
	ServiceIsbconference1  Service = "isbconference1"  // isbconference1
	ServiceIsbconference2  Service = "isbconference2"  // isbconference2
	ServicePayrouter       Service = "payrouter"       // payrouter
	ServiceVisionpyramid   Service = "visionpyramid"   // VisionPyramid
	ServiceHermes          Service = "hermes"          // hermes
	ServiceMesavistaco     Service = "mesavistaco"     // Mesa Vista Co
	ServiceSwldySias       Service = "swldy-sias"      // swldy-sias
	ServiceServergraph     Service = "servergraph"     // servergraph
	ServiceBspnePcc        Service = "bspne-pcc"       // bspne-pcc
	ServiceQ55Pcc          Service = "q55-pcc"         // q55-pcc
	ServiceDeNoc           Service = "de-noc"          // de-noc
	ServiceDeCacheQuery    Service = "de-cache-query"  // de-cache-query
	ServiceDeServer        Service = "de-server"       // de-server
	ServiceShockwave2      Service = "shockwave2"      // Shockwave 2
	ServiceOpennl          Service = "opennl"          // Open Network Library
	ServiceOpennlVoice     Service = "opennl-voice"    // Open Network Library Voice
	ServiceIbmSsd          Service = "ibm-ssd"         // ibm-ssd
	ServiceMpshrsv         Service = "mpshrsv"         // mpshrsv
	ServiceQntsOrb         Service = "qnts-orb"        // QNTS-ORB
	ServiceDka             Service = "dka"             // dka
	ServicePrat            Service = "prat"            // PRAT
	ServiceDssiapi         Service = "dssiapi"         // DSSIAPI
	ServiceDellpwrappks    Service = "dellpwrappks"    // DELLPWRAPPKS
	ServiceEpc             Service = "epc"             // eTrust Policy Compliance
	ServicePropelMsgsys    Service = "propel-msgsys"   // PROPEL-MSGSYS
	ServiceWatilapp        Service = "watilapp"        // WATiLaPP
	ServiceOpsmgr          Service = "opsmgr"          // Microsoft Operations Manager
	ServiceExcw            Service = "excw"            // eXcW
	ServiceCspmlockmgr     Service = "cspmlockmgr"     // CSPMLockMgr
	ServiceEmcGateway      Service = "emc-gateway"     // EMC-Gateway
	ServiceT1distproc      Service = "t1distproc"      // t1distproc
	ServiceIvcollector     Service = "ivcollector"     // ivcollector
	ServiceIvmanager       Service = "ivmanager"       // ivmanager
	ServiceMivaMqs         Service = "miva-mqs"        // mqs
	ServiceDellwebadmin1   Service = "dellwebadmin-1"  // Dell Web Admin 1
	ServiceDellwebadmin2   Service = "dellwebadmin-2"  // Dell Web Admin 2
	ServicePictrography    Service = "pictrography"    // Pictrography
	ServiceHealthd         Service = "healthd"         // healthd
	ServiceEmperion        Service = "emperion"        // Emperion
	ServiceProductinfo     Service = "productinfo"     // Product Information
	ServiceIeeQfx          Service = "iee-qfx"         // IEE-QFX
	ServiceNeoiface        Service = "neoiface"        // neoiface
	ServiceNetuitive       Service = "netuitive"       // netuitive
	ServiceRoutematch      Service = "routematch"      // RouteMatch Com
	ServiceNavbuddy        Service = "navbuddy"        // NavBuddy
	ServiceJwalkserver     Service = "jwalkserver"     // JWalkServer
	ServiceWinjaserver     Service = "winjaserver"     // WinJaServer
	ServiceSeagulllms      Service = "seagulllms"      // SEAGULLLMS
	ServiceDsdn            Service = "dsdn"            // dsdn
	ServicePktKrbIpsec     Service = "pkt-krb-ipsec"   // PKT-KRB-IPSec
	ServiceCmmdriver       Service = "cmmdriver"       // CMMdriver
	ServiceEhtp            Service = "ehtp"            // End-by-Hop Transmission Protocol
	ServiceDproxy          Service = "dproxy"          // dproxy
	ServiceSdproxy         Service = "sdproxy"         // sdproxy
	ServiceLpcp            Service = "lpcp"            // lpcp
	ServiceHpSci           Service = "hp-sci"          // hp-sci
	ServiceCi3Software1    Service = "ci3-software-1"  // CI3-Software-1
	ServiceCi3Software2    Service = "ci3-software-2"  // CI3-Software-2
	ServiceSftsrv          Service = "sftsrv"          // sftsrv
	ServiceBoomerang       Service = "boomerang"       // Boomerang
	ServicePeMike          Service = "pe-mike"         // pe-mike
	ServiceReConnProto     Service = "re-conn-proto"   // RE-Conn-Proto
	ServicePacmand         Service = "pacmand"         // Pacmand
	ServiceOdsi            Service = "odsi"            // Optical Domain Service Interconnect (ODSI)
	ServiceJtagServer      Service = "jtag-server"     // JTAG server
	ServiceHusky           Service = "husky"           // Husky
	ServiceRxmon           Service = "rxmon"           // RxMon
	ServiceStiEnvision     Service = "sti-envision"    // STI Envision
	ServiceBmc_patroldb    Service = "bmc_patroldb"    // BMC_PATROLDB
	ServicePdps            Service = "pdps"            // Photoscript Distributed Printing System
	ServiceEls             Service = "els"             // E.L.S., Event Listener Service
	ServiceExbitEscp       Service = "exbit-escp"      // Exbit-ESCP
	ServiceVrtsIpcserver   Service = "vrts-ipcserver"  // vrts-ipcserver
	ServiceKrb5gatekeeper  Service = "krb5gatekeeper"  // krb5gatekeeper
	ServiceAmxIcsp         Service = "amx-icsp"        // AMX-ICSP
	ServiceAmxAxbnet       Service = "amx-axbnet"      // AMX-AXBNET
	ServiceNovation        Service = "novation"        // Novation
	ServiceBrcd            Service = "brcd"            // brcd
	ServiceDeltaMcp        Service = "delta-mcp"       // delta-mcp
	ServiceDxInstrument    Service = "dx-instrument"   // DX-Instrument
	ServiceWimsic          Service = "wimsic"          // WIMSIC
	ServiceUltrex          Service = "ultrex"          // Ultrex
	ServiceEwall           Service = "ewall"           // EWALL
	ServiceNetdbExport     Service = "netdb-export"    // netdb-export
	ServiceStreetperfect   Service = "streetperfect"   // StreetPerfect
	ServiceIntersan        Service = "intersan"        // intersan
	ServicePciaRxpB        Service = "pcia-rxp-b"      // PCIA RXP-B
	ServicePasswrdPolicy   Service = "passwrd-policy"  // Password Policy
	ServiceWritesrv        Service = "writesrv"        // writesrv
	ServiceDigitalNotary   Service = "digital-notary"  // Digital Notary Protocol
	ServiceIschat          Service = "ischat"          // Instant Service Chat
	ServiceMenandmiceDns   Service = "menandmice-dns"  // menandmice DNS
	ServiceWmcLogSvc       Service = "wmc-log-svc"     // WMC-log-svr
	ServiceKjtsiteserver   Service = "kjtsiteserver"   // kjtsiteserver
	ServiceNaap            Service = "naap"            // NAAP
	ServiceQubes           Service = "qubes"           // QuBES
	ServiceEsbroker        Service = "esbroker"        // ESBroker
	ServiceRe101           Service = "re101"           // re101
	ServiceIcap            Service = "icap"            // ICAP
	ServiceVpjp            Service = "vpjp"            // VPJP
	ServiceAltaAnaLm       Service = "alta-ana-lm"     // Alta Analytics License Manager
	ServiceBbnMmc          Service = "bbn-mmc"         // multi media conferencing
	ServiceBbnMmx          Service = "bbn-mmx"         // multi media conferencing
	ServiceSbook           Service = "sbook"           // Registration Network Protocol
	ServiceEditbench       Service = "editbench"       // Registration Network Protocol
	ServiceEquationbuilder Service = "equationbuilder" // Digital Tool Works (MIT)
	ServiceLotusnote       Service = "lotusnote"       // Lotus Note
	ServiceRelief          Service = "relief"          // Relief Consulting
	ServiceXSIPNetwork     Service = "XSIP-network"    // Five Across XSIP Network
	ServiceIntuitiveEdge   Service = "intuitive-edge"  // Intuitive Edge
	ServiceCuillamartin    Service = "cuillamartin"    // CuillaMartin Company
	ServicePegboard        Service = "pegboard"        // Electronic PegBoard
	ServiceConnlcli        Service = "connlcli"        // CONNLCLI
	ServiceFtsrv           Service = "ftsrv"           // FTSRV
	ServiceMimer           Service = "mimer"           // MIMER
	ServiceLinx            Service = "linx"            // LinX
	ServiceTimeflies       Service = "timeflies"       // TimeFlies
	ServiceNdmRequester    Service = "ndm-requester"   // Network DataMover Requester
	ServiceNdmServer       Service = "ndm-server"      // Network DataMover Server
	ServiceAdaptSna        Service = "adapt-sna"       // Network Software Associates
	ServiceNetwareCsp      Service = "netware-csp"     // Novell NetWare Comm Service Platform
	ServiceDcs             Service = "dcs"             // DCS
	ServiceScreencast      Service = "screencast"      // ScreenCast
	ServiceGvUs            Service = "gv-us"           // GlobalView to Unix Shell
	ServiceUsGv            Service = "us-gv"           // Unix Shell to GlobalView
	ServiceFcCli           Service = "fc-cli"          // Fujitsu Config Protocol
	ServiceFcSer           Service = "fc-ser"          // Fujitsu Config Protocol
	ServiceChromagrafx     Service = "chromagrafx"     // Chromagrafx
	ServiceMolly           Service = "molly"           // EPI Software Systems
	ServiceBytex           Service = "bytex"           // Bytex
	ServiceIbmPps          Service = "ibm-pps"         // IBM Person to Person Software
	ServiceCichlid         Service = "cichlid"         // Cichlid License Manager
	ServiceElan            Service = "elan"            // Elan License Manager
	ServiceDbreporter      Service = "dbreporter"      // Integrity Solutions
	ServiceTelesisLicman   Service = "telesis-licman"  // Telesis Network License Manager
	ServiceAppleLicman     Service = "apple-licman"    // Apple Network License Manager
	ServiceUdt_os          Service = "udt_os"          // udt_os
	ServiceGwha            Service = "gwha"            // GW Hannaway Network License Manager
	ServiceOsLicman        Service = "os-licman"       // Objective Solutions License Manager
	ServiceAtex_elmd       Service = "atex_elmd"       // Atex Publishing License Manager
	ServiceChecksum        Service = "checksum"        // CheckSum License Manager
	ServiceCadsiLm         Service = "cadsi-lm"        // Computer Aided Design Software Inc LM
	ServiceObjectiveDbc    Service = "objective-dbc"   // Objective Solutions DataBase Cache
	ServiceIclpvDm         Service = "iclpv-dm"        // Document Manager
	ServiceIclpvSc         Service = "iclpv-sc"        // Storage Controller
	ServiceIclpvSas        Service = "iclpv-sas"       // Storage Access Server
	ServiceIclpvPm         Service = "iclpv-pm"        // Print Manager
	ServiceIclpvNls        Service = "iclpv-nls"       // Network Log Server
	ServiceIclpvNlc        Service = "iclpv-nlc"       // Network Log Client
	ServiceIclpvWsm        Service = "iclpv-wsm"       // PC Workstation Manager software
	ServiceDvlActivemail   Service = "dvl-activemail"  // DVL Active Mail
	ServiceAudioActivmail  Service = "audio-activmail" // Audio Active Mail
	ServiceVideoActivmail  Service = "video-activmail" // Video Active Mail
	ServiceCadkeyLicman    Service = "cadkey-licman"   // Cadkey License Manager
	ServiceCadkeyTablet    Service = "cadkey-tablet"   // Cadkey Tablet Daemon
	ServiceGoldleafLicman  Service = "goldleaf-licman" // Goldleaf License Manager
	ServicePrmSmNp         Service = "prm-sm-np"       // Prospero Resource Manager
	ServicePrmNmNp         Service = "prm-nm-np"       // Prospero Resource Manager
	ServiceIgiLm           Service = "igi-lm"          // Infinite Graphics License Manager
	ServiceIbmRes          Service = "ibm-res"         // IBM Remote Execution Starter
	ServiceNetlabsLm       Service = "netlabs-lm"      // NetLabs License Manager
	ServiceDbsaLm          Service = "dbsa-lm"         // DBSA License Manager
	ServiceSophiaLm        Service = "sophia-lm"       // Sophia License Manager
	ServiceHereLm          Service = "here-lm"         // Here License Manager
	ServiceHiq             Service = "hiq"             // HiQ License Manager
	ServiceAf              Service = "af"              // AudioFile
	ServiceInnosys         Service = "innosys"         // InnoSys
	ServiceInnosysAcl      Service = "innosys-acl"     // Innosys-ACL
	ServiceIbmMqseries     Service = "ibm-mqseries"    // IBM MQSeries
	ServiceDbstar          Service = "dbstar"          // DBStar
	ServiceNovellLu6Dot2   Service = "novell-lu6.2"    // Novell LU6.2
	ServiceTimbuktuSrv1    Service = "timbuktu-srv1"   // Timbuktu Service 1 Port
	ServiceTimbuktuSrv2    Service = "timbuktu-srv2"   // Timbuktu Service 2 Port
	ServiceTimbuktuSrv3    Service = "timbuktu-srv3"   // Timbuktu Service 3 Port
	ServiceTimbuktuSrv4    Service = "timbuktu-srv4"   // Timbuktu Service 4 Port
	ServiceGandalfLm       Service = "gandalf-lm"      // Gandalf License Manager
	ServiceAutodeskLm      Service = "autodesk-lm"     // Autodesk License Manager
	ServiceEssbase         Service = "essbase"         // Essbase Arbor Software
	ServiceHybrid          Service = "hybrid"          // Hybrid Encryption Protocol
	ServiceZionLm          Service = "zion-lm"         // Zion Software License Manager
	ServiceSais            Service = "sais"            // Satellite-data Acquisition System 1
	ServiceMloadd          Service = "mloadd"          // mloadd monitoring tool
	ServiceInformatikLm    Service = "informatik-lm"   // Informatik License Manager
	ServiceNms             Service = "nms"             // Hypercom NMS
	ServiceTpdu            Service = "tpdu"            // Hypercom TPDU
	ServiceRgtp            Service = "rgtp"            // Reverse Gossip Transport
	ServiceBlueberryLm     Service = "blueberry-lm"    // Blueberry Software License Manager
	ServiceIbmCics         Service = "ibm-cics"        // IBM CICS
	ServiceSaism           Service = "saism"           // Satellite-data Acquisition System 2
	ServiceTabula          Service = "tabula"          // Tabula
	ServiceEiconServer     Service = "eicon-server"    // Eicon Security Agent/Server
	ServiceEiconX25        Service = "eicon-x25"       // Eicon X25/SNA Gateway
	ServiceEiconSlp        Service = "eicon-slp"       // Eicon Service Location Protocol
	ServiceCadis1          Service = "cadis-1"         // Cadis License Management
	ServiceCadis2          Service = "cadis-2"         // Cadis License Management
	ServiceIesLm           Service = "ies-lm"          // Integrated Engineering Software
	ServiceMarcamLm        Service = "marcam-lm"       // Marcam License Management
	ServiceProximaLm       Service = "proxima-lm"      // Proxima License Manager
	ServiceOraLm           Service = "ora-lm"          // Optical Research Associates License Manager
	ServiceApriLm          Service = "apri-lm"         // Applied Parallel Research LM
	ServiceOcLm            Service = "oc-lm"           // OpenConnect License Manager
	ServicePeport          Service = "peport"          // PEport
	ServiceDwf             Service = "dwf"             // Tandem Distributed Workbench Facility
	ServiceInfoman         Service = "infoman"         // IBM Information Management
	ServiceGtegscLm        Service = "gtegsc-lm"       // GTE Government Systems License Man
	ServiceGenieLm         Service = "genie-lm"        // Genie License Manager
	ServiceInterhdl_elmd   Service = "interhdl_elmd"   // interHDL License Manager
	ServiceEslLm           Service = "esl-lm"          // ESL License Manager
	ServiceDca             Service = "dca"             // DCA
	ServiceValisysLm       Service = "valisys-lm"      // Valisys License Manager
	ServiceNrcabqLm        Service = "nrcabq-lm"       // Nichols Research Corp.
	ServiceProshare1       Service = "proshare1"       // Proshare Notebook Application
	ServiceProshare2       Service = "proshare2"       // Proshare Notebook Application
	ServiceIbm_wrless_lan  Service = "ibm_wrless_lan"  // IBM Wireless LAN
	ServiceWorldLm         Service = "world-lm"        // World License Manager
	ServiceNucleus         Service = "nucleus"         // Nucleus
	ServiceMsl_lmd         Service = "msl_lmd"         // MSL License Manager
	ServicePipes           Service = "pipes"           // Pipes Platform
	ServiceOceansoftLm     Service = "oceansoft-lm"    // Ocean Software License Manager
	ServiceCsdmbase        Service = "csdmbase"        // CSDMBASE
	ServiceCsdm            Service = "csdm"            // CSDM
	ServiceAalLm           Service = "aal-lm"          // Active Analysis Limited License Manager
	ServiceUaiact          Service = "uaiact"          // Universal Analytics
	ServiceOpenmath        Service = "openmath"        // OpenMath
	ServiceTelefinder      Service = "telefinder"      // Telefinder
	ServiceTaligentLm      Service = "taligent-lm"     // Taligent License Manager
	ServiceClvmCfg         Service = "clvm-cfg"        // clvm-cfg
	ServiceMsSnaServer     Service = "ms-sna-server"   // ms-sna-server
	ServiceMsSnaBase       Service = "ms-sna-base"     // ms-sna-base
	ServiceDberegister     Service = "dberegister"     // dberegister
	ServicePacerforum      Service = "pacerforum"      // PacerForum
	ServiceAirs            Service = "airs"            // AIRS
	ServiceMiteksysLm      Service = "miteksys-lm"     // Miteksys License Manager
	ServiceAfs             Service = "afs"             // AFS License Manager
	ServiceConfluent       Service = "confluent"       // Confluent License Manager
	ServiceLansource       Service = "lansource"       // LANSource
	ServiceNms_topo_serv   Service = "nms_topo_serv"   // nms_topo_serv
	ServiceLocalinfosrvr   Service = "localinfosrvr"   // LocalInfoSrvr
	ServiceDocstor         Service = "docstor"         // DocStor
	ServiceDmdocbroker     Service = "dmdocbroker"     // dmdocbroker
	ServiceInsituConf      Service = "insitu-conf"     // insitu-conf
	ServiceStoneDesign1    Service = "stone-design-1"  // stone-design-1
	ServiceNetmap_lm       Service = "netmap_lm"       // netmap_lm
	ServiceCvc             Service = "cvc"             // cvc
	ServiceLibertyLm       Service = "liberty-lm"      // liberty-lm
	ServiceRfxLm           Service = "rfx-lm"          // rfx-lm
	ServiceSybaseSqlany    Service = "sybase-sqlany"   // Sybase SQL Any
	ServiceFhc             Service = "fhc"             // Federico Heinz Consultora
	ServiceVlsiLm          Service = "vlsi-lm"         // VLSI License Manager
	ServiceSaiscm          Service = "saiscm"          // Satellite-data Acquisition System 3
	ServiceShivadiscovery  Service = "shivadiscovery"  // Shiva
	ServiceImtcMcs         Service = "imtc-mcs"        // Databeam
	ServiceEvbElm          Service = "evb-elm"         // EVB Software Engineering License Manager
	ServiceFunkproxy       Service = "funkproxy"       // Funk Software, Inc.
	ServiceUtcd            Service = "utcd"            // Universal Time daemon (utcd)
	ServiceSymplex         Service = "symplex"         // symplex
	ServiceDiagmond        Service = "diagmond"        // diagmond
	ServiceRobcadLm        Service = "robcad-lm"       // Robcad, Ltd. License Manager
	ServiceMvxLm           Service = "mvx-lm"          // Midland Valley Exploration Ltd. Lic. Man.
	Service3lL1            Service = "3l-l1"           // 3l-l1
	ServiceFujitsuDtc      Service = "fujitsu-dtc"     // Fujitsu Systems Business of America, Inc
	ServiceFujitsuDtcns    Service = "fujitsu-dtcns"   // Fujitsu Systems Business of America, Inc
	ServiceIforProtocol    Service = "ifor-protocol"   // ifor-protocol
	ServiceVpad            Service = "vpad"            // Virtual Places Audio data
	ServiceVpac            Service = "vpac"            // Virtual Places Audio control
	ServiceVpvd            Service = "vpvd"            // Virtual Places Video data
	ServiceVpvc            Service = "vpvc"            // Virtual Places Video control
	ServiceAtmZipOffice    Service = "atm-zip-office"  // atm zip office
	ServiceNcubeLm         Service = "ncube-lm"        // nCube License Manager
	ServiceRicardoLm       Service = "ricardo-lm"      // Ricardo North America License Manager
	ServiceCichildLm       Service = "cichild-lm"      // cichild
	ServicePdapNp          Service = "pdap-np"         // Prospero Data Access Prot non-priv
	ServiceTlisrv          Service = "tlisrv"          // oracle
	ServiceCoauthor        Service = "coauthor"        // oracle
	ServiceRapService      Service = "rap-service"     // rap-service
	ServiceRapListen       Service = "rap-listen"      // rap-listen
	ServiceMiroconnect     Service = "miroconnect"     // miroconnect
	ServiceVirtualPlaces   Service = "virtual-places"  // Virtual Places Software
	ServiceMicromuseLm     Service = "micromuse-lm"    // micromuse-lm
	ServiceAmprInfo        Service = "ampr-info"       // ampr-info
	ServiceAmprInter       Service = "ampr-inter"      // ampr-inter
	ServiceSdscLm          Service = "sdsc-lm"         // isi-lm
	Service3dsLm           Service = "3ds-lm"          // 3ds-lm
	ServiceIntellistorLm   Service = "intellistor-lm"  // Intellistor License Manager
	ServiceRds             Service = "rds"             // rds
	ServiceRds2            Service = "rds2"            // rds2
	ServiceGridgenElmd     Service = "gridgen-elmd"    // gridgen-elmd
	ServiceSimbaCs         Service = "simba-cs"        // simba-cs
	ServiceAspeclmd        Service = "aspeclmd"        // aspeclmd
	ServiceVistiumShare    Service = "vistium-share"   // vistium-share
	ServiceAbbaccuray      Service = "abbaccuray"      // abbaccuray
	ServiceLaplink         Service = "laplink"         // laplink
	ServiceAxonLm          Service = "axon-lm"         // Axon License Manager
	ServiceShivahose       Service = "shivahose"       // Shiva Hose
	ServiceShivasound      Service = "shivasound"      // Shiva Sound
	Service3mImageLm       Service = "3m-image-lm"     // Image Storage license manager 3M Company
	ServiceHecmtlDb        Service = "hecmtl-db"       // HECMTL-DB
	ServicePciarray        Service = "pciarray"        // pciarray
	ServiceSnaCs           Service = "sna-cs"          // sna-cs
	ServiceCaciLm          Service = "caci-lm"         // CACI Products Company License Manager
	ServiceLivelan         Service = "livelan"         // livelan
	ServiceVeritas_pbx     Service = "veritas_pbx"     // VERITAS Private Branch Exchange
	ServiceArbortextLm     Service = "arbortext-lm"    // ArborText License Manager
	ServiceXingmpeg        Service = "xingmpeg"        // xingmpeg
	ServiceWeb2host        Service = "web2host"        // web2host
	ServiceAsciVal         Service = "asci-val"        // ASCI-RemoteSHADOW
	ServiceFacilityview    Service = "facilityview"    // facilityview
	ServicePconnectmgr     Service = "pconnectmgr"     // pconnectmgr
	ServiceCadabraLm       Service = "cadabra-lm"      // Cadabra License Manager
	ServicePayPerView      Service = "pay-per-view"    // Pay-Per-View
	ServiceWinddlb         Service = "winddlb"         // WinDD
	ServiceCorelvideo      Service = "corelvideo"      // CORELVIDEO
	ServiceJlicelmd        Service = "jlicelmd"        // jlicelmd
	ServiceTsspmap         Service = "tsspmap"         // tsspmap
	ServiceEts             Service = "ets"             // ets
	ServiceOrbixd          Service = "orbixd"          // orbixd
	ServiceRdbDbsDisp      Service = "rdb-dbs-disp"    // Oracle Remote Data Base
	ServiceChipLm          Service = "chip-lm"         // Chipcom License Manager
	ServiceItscommNs       Service = "itscomm-ns"      // itscomm-ns
	ServiceMvelLm          Service = "mvel-lm"         // mvel-lm
	ServiceOraclenames     Service = "oraclenames"     // oraclenames
	ServiceMoldflowLm      Service = "moldflow-lm"     // Moldflow License Manager
	ServiceHypercubeLm     Service = "hypercube-lm"    // hypercube-lm
	ServiceJacobusLm       Service = "jacobus-lm"      // Jacobus License Manager
	ServiceIocSeaLm        Service = "ioc-sea-lm"      // ioc-sea-lm
	ServiceTnTlR1          Service = "tn-tl-r1"        // tn-tl-r1
	ServiceTnTlR2          Service = "tn-tl-r2"        // tn-tl-r2
	ServiceMil204547001    Service = "mil-2045-47001"  // MIL-2045-47001
	ServiceMsims           Service = "msims"           // MSIMS
	ServiceSimbaexpress    Service = "simbaexpress"    // simbaexpress
	ServiceTnTlFd2         Service = "tn-tl-fd2"       // tn-tl-fd2
	ServiceIntv            Service = "intv"            // intv
	ServiceIbmAbtact       Service = "ibm-abtact"      // ibm-abtact
	ServicePra_elmd        Service = "pra_elmd"        // pra_elmd
	ServiceTriquestLm      Service = "triquest-lm"     // triquest-lm
	ServiceVqp             Service = "vqp"             // VQP
	ServiceGeminiLm        Service = "gemini-lm"       // gemini-lm
	ServiceNcpmPm          Service = "ncpm-pm"         // ncpm-pm
	ServiceCommonspace     Service = "commonspace"     // commonspace
	ServiceMainsoftLm      Service = "mainsoft-lm"     // mainsoft-lm
	ServiceSixtrak         Service = "sixtrak"         // sixtrak
	ServiceRadio           Service = "radio"           // radio
	ServiceRadioSm         Service = "radio-sm"        // radio-sm
	ServiceRadioBc         Service = "radio-bc"        // radio-bc
	ServiceOrbplusIiop     Service = "orbplus-iiop"    // orbplus-iiop
	ServicePicknfs         Service = "picknfs"         // picknfs
	ServiceSimbaservices   Service = "simbaservices"   // simbaservices
	ServiceIssd            Service = "issd"            // issd
	ServiceAas             Service = "aas"             // aas
	ServiceInspect         Service = "inspect"         // inspect
	ServicePicodbc         Service = "picodbc"         // pickodbc
	ServiceIcabrowser      Service = "icabrowser"      // icabrowser
	ServiceSlp             Service = "slp"             // Salutation Manager (Salutation Protocol)
	ServiceSlmApi          Service = "slm-api"         // Salutation Manager (SLM-API)
	ServiceStt             Service = "stt"             // stt
	ServiceSmartLm         Service = "smart-lm"        // Smart Corp. License Manager
	ServiceIsysgLm         Service = "isysg-lm"        // isysg-lm
	ServiceTaurusWh        Service = "taurus-wh"       // taurus-wh
	ServiceIll             Service = "ill"             // Inter Library Loan
	ServiceNetbillTrans    Service = "netbill-trans"   // NetBill Transaction Server
	ServiceNetbillKeyrep   Service = "netbill-keyrep"  // NetBill Key Repository
	ServiceNetbillCred     Service = "netbill-cred"    // NetBill Credential Server
	ServiceNetbillAuth     Service = "netbill-auth"    // NetBill Authorization Server
	ServiceNetbillProd     Service = "netbill-prod"    // NetBill Product Server
	ServiceNimrodAgent     Service = "nimrod-agent"    // Nimrod Inter-Agent Communication
	ServiceSkytelnet       Service = "skytelnet"       // skytelnet
	ServiceXsOpenstorage   Service = "xs-openstorage"  // xs-openstorage
	ServiceFaxportwinport  Service = "faxportwinport"  // faxportwinport
	ServiceSoftdataphone   Service = "softdataphone"   // softdataphone
	ServiceOntime          Service = "ontime"          // ontime
	ServiceJaleosnd        Service = "jaleosnd"        // jaleosnd
	ServiceUdpSrPort       Service = "udp-sr-port"     // udp-sr-port
	ServiceSvsOmagent      Service = "svs-omagent"     // svs-omagent
	ServiceShockwave       Service = "shockwave"       // Shockwave
	ServiceT128Gateway     Service = "t128-gateway"    // T.128 Gateway
	ServiceLontalkNorm     Service = "lontalk-norm"    // LonTalk normal
	ServiceLontalkUrgnt    Service = "lontalk-urgnt"   // LonTalk urgent
	ServiceOraclenet8cman  Service = "oraclenet8cman"  // Oracle Net8 Cman
	ServiceVisitview       Service = "visitview"       // Visit view
	ServicePammratc        Service = "pammratc"        // PAMMRATC
	ServicePammrpc         Service = "pammrpc"         // PAMMRPC
	ServiceLoaprobe        Service = "loaprobe"        // Log On America Probe
	ServiceEdbServer1      Service = "edb-server1"     // EDB Server 1
	ServiceIsdc            Service = "isdc"            // ISP shared public data control
	ServiceIslc            Service = "islc"            // ISP shared local data control
	ServiceIsmc            Service = "ismc"            // ISP shared management control
	ServiceCertInitiator   Service = "cert-initiator"  // cert-initiator
	ServiceCertResponder   Service = "cert-responder"  // cert-responder
	ServiceInvision        Service = "invision"        // InVision
	ServiceIsisAm          Service = "isis-am"         // isis-am
	ServiceIsisAmbc        Service = "isis-ambc"       // isis-ambc
	ServiceSaiseh          Service = "saiseh"          // Satellite-data Acquisition System 4
	ServiceRsap            Service = "rsap"            // rsap
	ServiceConcurrentLm    Service = "concurrent-lm"   // concurrent-lm
	ServiceNkd             Service = "nkd"             // nkdn
	ServiceShiva_confsrvr  Service = "shiva_confsrvr"  // shiva_confsrvr
	ServiceXnmp            Service = "xnmp"            // xnmp
	ServiceAlphatechLm     Service = "alphatech-lm"    // alphatech-lm
	ServiceStargatealerts  Service = "stargatealerts"  // stargatealerts
	ServiceDecMbadmin      Service = "dec-mbadmin"     // dec-mbadmin
	ServiceDecMbadminH     Service = "dec-mbadmin-h"   // dec-mbadmin-h
	ServiceFujitsuMmpdc    Service = "fujitsu-mmpdc"   // fujitsu-mmpdc
	ServiceSixnetudr       Service = "sixnetudr"       // sixnetudr
	ServiceSgLm            Service = "sg-lm"           // Silicon Grail License Manager
	ServiceSkipMcGikreq    Service = "skip-mc-gikreq"  // skip-mc-gikreq
	ServiceNetviewAix1     Service = "netview-aix-1"   // netview-aix-1
	ServiceNetviewAix2     Service = "netview-aix-2"   // netview-aix-2
	ServiceNetviewAix3     Service = "netview-aix-3"   // netview-aix-3
	ServiceNetviewAix4     Service = "netview-aix-4"   // netview-aix-4
	ServiceNetviewAix5     Service = "netview-aix-5"   // netview-aix-5
	ServiceNetviewAix6     Service = "netview-aix-6"   // netview-aix-6
	ServiceNetviewAix7     Service = "netview-aix-7"   // netview-aix-7
	ServiceNetviewAix8     Service = "netview-aix-8"   // netview-aix-8
	ServiceNetviewAix9     Service = "netview-aix-9"   // netview-aix-9
	ServiceNetviewAix10    Service = "netview-aix-10"  // netview-aix-10
	ServiceNetviewAix11    Service = "netview-aix-11"  // netview-aix-11
	ServiceNetviewAix12    Service = "netview-aix-12"  // netview-aix-12
	ServiceProshareMc1     Service = "proshare-mc-1"   // Intel Proshare Multicast
	ServiceProshareMc2     Service = "proshare-mc-2"   // Intel Proshare Multicast
	ServicePdp             Service = "pdp"             // Pacific Data Products
	ServiceNetcomm1        Service = "netcomm1"        // netcomm1
	ServiceNetcomm2        Service = "netcomm2"        // netcomm2
	ServiceGroupwise       Service = "groupwise"       // groupwise
	ServiceProlink         Service = "prolink"         // prolink
	ServiceDarcorpLm       Service = "darcorp-lm"      // darcorp-lm
	ServiceMicrocomSbp     Service = "microcom-sbp"    // microcom-sbp
	ServiceSdElmd          Service = "sd-elmd"         // sd-elmd
	ServiceLanyonLantern   Service = "lanyon-lantern"  // lanyon-lantern
	ServiceNcpmHip         Service = "ncpm-hip"        // ncpm-hip
	ServiceSnaresecure     Service = "snaresecure"     // SnareSecure
	ServiceN2nremote       Service = "n2nremote"       // n2nremote
	ServiceCvmon           Service = "cvmon"           // cvmon
	ServiceNsjtpCtrl       Service = "nsjtp-ctrl"      // nsjtp-ctrl
	ServiceNsjtpData       Service = "nsjtp-data"      // nsjtp-data
	ServiceFirefox         Service = "firefox"         // firefox
	ServiceNgUmds          Service = "ng-umds"         // ng-umds
	ServiceEmpireEmpuma    Service = "empire-empuma"   // empire-empuma
	ServiceSstsysLm        Service = "sstsys-lm"       // sstsys-lm
	ServiceRrirtr          Service = "rrirtr"          // rrirtr
	ServiceRrimwm          Service = "rrimwm"          // rrimwm
	ServiceRrilwm          Service = "rrilwm"          // rrilwm
	ServiceRrifmm          Service = "rrifmm"          // rrifmm
	ServiceRrisat          Service = "rrisat"          // rrisat
	ServiceRsvpEncap1      Service = "rsvp-encap-1"    // RSVP-ENCAPSULATION-1
	ServiceRsvpEncap2      Service = "rsvp-encap-2"    // RSVP-ENCAPSULATION-2
	ServiceMpsRaft         Service = "mps-raft"        // mps-raft
	ServiceDeskshare       Service = "deskshare"       // deskshare
	ServiceHbEngine        Service = "hb-engine"       // hb-engine
	ServiceBcsBroker       Service = "bcs-broker"      // bcs-broker
	ServiceSlingshot       Service = "slingshot"       // slingshot
	ServiceJetform         Service = "jetform"         // jetform
	ServiceVdmplay         Service = "vdmplay"         // vdmplay
	ServiceGatLmd          Service = "gat-lmd"         // gat-lmd
	ServiceCentra          Service = "centra"          // centra
	ServiceImpera          Service = "impera"          // impera
	ServicePptconference   Service = "pptconference"   // pptconference
	ServiceRegistrar       Service = "registrar"       // resource monitoring service
	ServiceConferencetalk  Service = "conferencetalk"  // ConferenceTalk
	ServiceSesiLm          Service = "sesi-lm"         // sesi-lm
	ServiceHoudiniLm       Service = "houdini-lm"      // houdini-lm
	ServiceXmsg            Service = "xmsg"            // xmsg
	ServiceFjHdnet         Service = "fj-hdnet"        // fj-hdnet
	ServiceCaicci          Service = "caicci"          // caicci
	ServiceHksLm           Service = "hks-lm"          // HKS License Manager
	ServicePptp            Service = "pptp"            // pptp
	ServiceCsbphonemaster  Service = "csbphonemaster"  // csbphonemaster
	ServiceIdenRalp        Service = "iden-ralp"       // iden-ralp
	ServiceIberiagames     Service = "iberiagames"     // IBERIAGAMES
	ServiceWinddx          Service = "winddx"          // winddx
	ServiceTelindus        Service = "telindus"        // TELINDUS
	ServiceCitynl          Service = "citynl"          // CityNL License Management
	ServiceRoketz          Service = "roketz"          // roketz
	ServiceMsiccp          Service = "msiccp"          // MSICCP
	ServiceProxim          Service = "proxim"          // proxim
	ServiceSiipat          Service = "siipat"          // SIMS - SIIPAT Protocol for Alarm Transmission
	ServiceCambertxLm      Service = "cambertx-lm"     // Camber Corporation License Management
	ServicePrivatechat     Service = "privatechat"     // PrivateChat
	ServiceStreetStream    Service = "street-stream"   // street-stream
	ServiceUltimad         Service = "ultimad"         // ultimad
	ServiceGamegen1        Service = "gamegen1"        // GameGen1
	ServiceWebaccess       Service = "webaccess"       // webaccess
	ServiceEncore          Service = "encore"          // encore
	ServiceCiscoNetMgmt    Service = "cisco-net-mgmt"  // cisco-net-mgmt
	Service3ComNsd         Service = "3Com-nsd"        // 3Com-nsd
	ServiceCinegrfxLm      Service = "cinegrfx-lm"     // Cinema Graphics License Manager
	ServiceNcpmFt          Service = "ncpm-ft"         // ncpm-ft
	ServiceRemoteWinsock   Service = "remote-winsock"  // remote-winsock
	ServiceFtrapid1        Service = "ftrapid-1"       // ftrapid-1
	ServiceFtrapid2        Service = "ftrapid-2"       // ftrapid-2
	ServiceOracleEm1       Service = "oracle-em1"      // oracle-em1
	ServiceAspenServices   Service = "aspen-services"  // aspen-services
	ServiceSslp            Service = "sslp"            // Simple Socket Library's PortMaster
	ServiceSwiftnet        Service = "swiftnet"        // SwiftNet
	ServiceLofrLm          Service = "lofr-lm"         // Leap of Faith Research License Manager
	ServicePredatarComms   Service = "predatar-comms"  // Predatar Comms Service
	ServiceOracleEm2       Service = "oracle-em2"      // oracle-em2
	ServiceMsStreaming     Service = "ms-streaming"    // ms-streaming
	ServiceCapfastLmd      Service = "capfast-lmd"     // capfast-lmd
	ServiceCnhrp           Service = "cnhrp"           // cnhrp
	ServiceSpssLm          Service = "spss-lm"         // SPSS License Manager
	ServiceWwwLdapGw       Service = "www-ldap-gw"     // www-ldap-gw
	ServiceCft0            Service = "cft-0"           // cft-0
	ServiceCft1            Service = "cft-1"           // cft-1
	ServiceCft2            Service = "cft-2"           // cft-2
	ServiceCft3            Service = "cft-3"           // cft-3
	ServiceCft4            Service = "cft-4"           // cft-4
	ServiceCft5            Service = "cft-5"           // cft-5
	ServiceCft6            Service = "cft-6"           // cft-6
	ServiceCft7            Service = "cft-7"           // cft-7
	ServiceBmcNetAdm       Service = "bmc-net-adm"     // bmc-net-adm
	ServiceBmcNetSvc       Service = "bmc-net-svc"     // bmc-net-svc
	ServiceVaultbase       Service = "vaultbase"       // vaultbase
	ServiceEsswebGw        Service = "essweb-gw"       // EssWeb Gateway
	ServiceKmscontrol      Service = "kmscontrol"      // KMSControl
	ServiceGlobalDtserv    Service = "global-dtserv"   // global-dtserv
	ServiceFemis           Service = "femis"           // Federal Emergency Management Information System
	ServicePowerguardian   Service = "powerguardian"   // powerguardian
	ServiceProdigyIntrnet  Service = "prodigy-intrnet" // prodigy-internet
	ServicePharmasoft      Service = "pharmasoft"      // pharmasoft
	ServiceDpkeyserv       Service = "dpkeyserv"       // dpkeyserv
	ServiceAnswersoftLm    Service = "answersoft-lm"   // answersoft-lm
	ServiceHpHcip          Service = "hp-hcip"         // hp-hcip
	ServiceFinleLm         Service = "finle-lm"        // Finle License Manager
	ServiceWindlm          Service = "windlm"          // Wind River Systems License Manager
	ServiceFunkLogger      Service = "funk-logger"     // funk-logger
	ServiceFunkLicense     Service = "funk-license"    // funk-license
	ServicePsmond          Service = "psmond"          // psmond
	ServiceEa1             Service = "ea1"             // EA1
	ServiceIbmDt2          Service = "ibm-dt-2"        // ibm-dt-2
	ServiceRscRobot        Service = "rsc-robot"       // rsc-robot
	ServiceCeraBcm         Service = "cera-bcm"        // cera-bcm
	ServiceDpiProxy        Service = "dpi-proxy"       // dpi-proxy
	ServiceVocaltecAdmin   Service = "vocaltec-admin"  // Vocaltec Server Administration
	ServiceEtp             Service = "etp"             // Event Transfer Protocol
	ServiceNetrisk         Service = "netrisk"         // NETRISK
	ServiceAnsysLm         Service = "ansys-lm"        // ANSYS-License manager
	ServiceMsmq            Service = "msmq"            // Microsoft Message Que
	ServiceConcomp1        Service = "concomp1"        // ConComp1
	ServiceHpHcipGwy       Service = "hp-hcip-gwy"     // HP-HCIP-GWY
	ServiceEnl             Service = "enl"             // ENL
	ServiceEnlName         Service = "enl-name"        // ENL-Name
	ServiceMusiconline     Service = "musiconline"     // Musiconline
	ServiceFhsp            Service = "fhsp"            // Fujitsu Hot Standby Protocol
	ServiceOracleVp2       Service = "oracle-vp2"      // Oracle-VP2
	ServiceOracleVp1       Service = "oracle-vp1"      // Oracle-VP1
	ServiceJerandLm        Service = "jerand-lm"       // Jerand License Manager
	ServiceScientiaSdb     Service = "scientia-sdb"    // Scientia-SDB
	ServiceTdpSuite        Service = "tdp-suite"       // TDP Suite
	ServiceMmpft           Service = "mmpft"           // MMPFT
	ServiceHarp            Service = "harp"            // HARP
	ServiceRkbOscs         Service = "rkb-oscs"        // RKB-OSCS
	ServiceEtftp           Service = "etftp"           // Enhanced Trivial File Transfer Protocol
	ServicePlatoLm         Service = "plato-lm"        // Plato License Manager
	ServiceMcagent         Service = "mcagent"         // mcagent
	ServiceDonnyworld      Service = "donnyworld"      // donnyworld
	ServiceEsElmd          Service = "es-elmd"         // es-elmd
	ServiceUnisysLm        Service = "unisys-lm"       // Unisys Natural Language License Manager
	ServiceMetricsPas      Service = "metrics-pas"     // metrics-pas
	ServiceDirecpcVideo    Service = "direcpc-video"   // DirecPC Video
	ServiceArdt            Service = "ardt"            // ARDT
	ServiceAsi             Service = "asi"             // ASI
	ServiceItmMcellU       Service = "itm-mcell-u"     // itm-mcell-u
	ServiceOptikaEmedia    Service = "optika-emedia"   // Optika eMedia
	ServiceNet8Cman        Service = "net8-cman"       // Oracle Net8 CMan Admin
	ServiceMyrtle          Service = "myrtle"          // Myrtle
	ServiceThtTreasure     Service = "tht-treasure"    // ThoughtTreasure
	ServiceUdpradio        Service = "udpradio"        // udpradio
	ServiceArdusuni        Service = "ardusuni"        // ARDUS Unicast
	ServiceArdusmul        Service = "ardusmul"        // ARDUS Multicast
	ServiceSteSmsc         Service = "ste-smsc"        // ste-smsc
	ServiceCsoft1          Service = "csoft1"          // csoft1
	ServiceTalnet          Service = "talnet"          // TALNET
	ServiceNetopiaVo1      Service = "netopia-vo1"     // netopia-vo1
	ServiceNetopiaVo2      Service = "netopia-vo2"     // netopia-vo2
	ServiceNetopiaVo3      Service = "netopia-vo3"     // netopia-vo3
	ServiceNetopiaVo4      Service = "netopia-vo4"     // netopia-vo4
	ServiceNetopiaVo5      Service = "netopia-vo5"     // netopia-vo5
	ServiceDirecpcDll      Service = "direcpc-dll"     // DirecPC-DLL
	ServiceAltalink        Service = "altalink"        // altalink
	ServiceTunstallPnc     Service = "tunstall-pnc"    // Tunstall PNC
	ServiceSlpNotify       Service = "slp-notify"      // SLP Notification
	ServiceFjdocdist       Service = "fjdocdist"       // fjdocdist
	ServiceAlphaSms        Service = "alpha-sms"       // ALPHA-SMS
	ServiceGsi             Service = "gsi"             // GSI
	ServiceCtcd            Service = "ctcd"            // ctcd
	ServiceVirtualTime     Service = "virtual-time"    // Virtual Time
	ServiceVidsAvtp        Service = "vids-avtp"       // VIDS-AVTP
	ServiceBuddyDraw       Service = "buddy-draw"      // Buddy Draw
	ServiceFioranoRtrsvc   Service = "fiorano-rtrsvc"  // Fiorano RtrSvc
	ServiceFioranoMsgsvc   Service = "fiorano-msgsvc"  // Fiorano MsgSvc
	ServiceDatacaptor      Service = "datacaptor"      // DataCaptor
	ServicePrivateark      Service = "privateark"      // PrivateArk
	ServiceGammafetchsvr   Service = "gammafetchsvr"   // Gamma Fetcher Server
	ServiceSunscalarSvc    Service = "sunscalar-svc"   // SunSCALAR Services
	ServiceLecroyVicp      Service = "lecroy-vicp"     // LeCroy VICP
	ServiceMysqlCmAgent    Service = "mysql-cm-agent"  // MySQL Cluster Manager Agent
	ServiceMsnp            Service = "msnp"            // MSNP
	ServiceParadym31port   Service = "paradym-31port"  // Paradym 31 Port
	ServiceEntp            Service = "entp"            // ENTP
	ServiceSwrmi           Service = "swrmi"           // swrmi
	ServiceUdrive          Service = "udrive"          // UDRIVE
	ServiceViziblebrowser  Service = "viziblebrowser"  // VizibleBrowser
	ServiceTransact        Service = "transact"        // TransAct
	ServiceSunscalarDns    Service = "sunscalar-dns"   // SunSCALAR DNS Service
	ServiceCanocentral0    Service = "canocentral0"    // Cano Central 0
	ServiceCanocentral1    Service = "canocentral1"    // Cano Central 1
	ServiceFjmpjps         Service = "fjmpjps"         // Fjmpjps
	ServiceFjswapsnp       Service = "fjswapsnp"       // Fjswapsnp
	ServiceWestellStats    Service = "westell-stats"   // westell stats
	ServiceEwcappsrv       Service = "ewcappsrv"       // ewcappsrv
	ServiceHpWebqosdb      Service = "hp-webqosdb"     // hp-webqosdb
	ServiceDrmsmc          Service = "drmsmc"          // drmsmc
	ServiceNettgainNms     Service = "nettgain-nms"    // NettGain NMS
	ServiceVsatControl     Service = "vsat-control"    // Gilat VSAT Control
	ServiceIbmMqseries2    Service = "ibm-mqseries2"   // IBM WebSphere MQ Everyplace
	ServiceEcsqdmn         Service = "ecsqdmn"         // CA eTrust Common Services
	ServiceIbmMqisdp       Service = "ibm-mqisdp"      // IBM MQSeries SCADA
	ServiceIdmaps          Service = "idmaps"          // Internet Distance Map Svc
	ServiceVrtstrapserver  Service = "vrtstrapserver"  // Veritas Trap Server
	ServiceLeoip           Service = "leoip"           // Leonardo over IP
	ServiceFilexLport      Service = "filex-lport"     // FileX Listening Port
	ServiceNcconfig        Service = "ncconfig"        // NC Config Port
	ServiceUnifyAdapter    Service = "unify-adapter"   // Unify Web Adapter Service
	ServiceWilkenlistener  Service = "wilkenlistener"  // wilkenListener
	ServiceChildkeyNotif   Service = "childkey-notif"  // ChildKey Notification
	ServiceChildkeyCtrl    Service = "childkey-ctrl"   // ChildKey Control
	ServiceElad            Service = "elad"            // ELAD Protocol
	ServiceO2serverPort    Service = "o2server-port"   // O2Server Port
	ServiceBNovativeLs     Service = "b-novative-ls"   // b-novative license server
	ServiceMetaagent       Service = "metaagent"       // MetaAgent
	ServiceCymtecPort      Service = "cymtec-port"     // Cymtec secure management
	ServiceMc2studios      Service = "mc2studios"      // MC2Studios
	ServiceSsdp            Service = "ssdp"            // SSDP
	ServiceFjiclTepA       Service = "fjicl-tep-a"     // Fujitsu ICL Terminal Emulator Program A
	ServiceFjiclTepB       Service = "fjicl-tep-b"     // Fujitsu ICL Terminal Emulator Program B
	ServiceLinkname        Service = "linkname"        // Local Link Name Resolution
	ServiceFjiclTepC       Service = "fjicl-tep-c"     // Fujitsu ICL Terminal Emulator Program C
	ServiceSugp            Service = "sugp"            // Secure UP.Link Gateway Protocol
	ServiceTpmd            Service = "tpmd"            // TPortMapperReq
	ServiceIntrastar       Service = "intrastar"       // IntraSTAR
	ServiceDawn            Service = "dawn"            // Dawn
	ServiceGlobalWlink     Service = "global-wlink"    // Global World Link
	ServiceUltrabac        Service = "ultrabac"        // UltraBac Software communications port
	ServiceRhpIibp         Service = "rhp-iibp"        // rhp-iibp
	ServiceArmadp          Service = "armadp"          // armadp
	ServiceElmMomentum     Service = "elm-momentum"    // Elm-Momentum
	ServiceFacelink        Service = "facelink"        // FACELINK
	ServicePersona         Service = "persona"         // Persoft Persona
	ServiceNoagent         Service = "noagent"         // nOAgent
	ServiceCanNds          Service = "can-nds"         // IBM Tivole Directory Service - NDS
	ServiceCanDch          Service = "can-dch"         // IBM Tivoli Directory Service - DCH
	ServiceCanFerret       Service = "can-ferret"      // IBM Tivoli Directory Service - FERRET
	ServiceNoadmin         Service = "noadmin"         // NoAdmin
	ServiceTapestry        Service = "tapestry"        // Tapestry
	ServiceSpice           Service = "spice"           // SPICE
	ServiceXiip            Service = "xiip"            // XIIP
	ServiceDiscoveryPort   Service = "discovery-port"  // Surrogate Discovery Port
	ServiceEgs             Service = "egs"             // Evolution Game Server
	ServiceVideteCipc      Service = "videte-cipc"     // Videte CIPC Port
	ServiceEmsdPort        Service = "emsd-port"       // Expnd Maui Srvr Dscovr
	ServiceBandwizSystem   Service = "bandwiz-system"  // Bandwiz System - Server
	ServiceDriveappserver  Service = "driveappserver"  // Drive AppServer
	ServiceAmdsched        Service = "amdsched"        // AMD SCHED
	ServiceCttBroker       Service = "ctt-broker"      // CTT Broker
	ServiceXmapi           Service = "xmapi"           // IBM LM MT Agent
	ServiceXaapi           Service = "xaapi"           // IBM LM Appl Agent
	ServiceMacromediaFcs   Service = "macromedia-fcs"  // Macromedia Flash Communications Server MX
	ServiceJetcmeserver    Service = "jetcmeserver"    // JetCmeServer Server Port
	ServiceJwserver        Service = "jwserver"        // JetVWay Server Port
	ServiceJwclient        Service = "jwclient"        // JetVWay Client Port
	ServiceJvserver        Service = "jvserver"        // JetVision Server Port
	ServiceJvclient        Service = "jvclient"        // JetVision Client Port
	ServiceDicAida         Service = "dic-aida"        // DIC-Aida
	ServiceRes             Service = "res"             // Real Enterprise Service
	ServiceBeeyondMedia    Service = "beeyond-media"   // Beeyond Media
	ServiceCloseCombat     Service = "close-combat"    // close-combat
	ServiceDialogicElmd    Service = "dialogic-elmd"   // dialogic-elmd
	ServiceTekpls          Service = "tekpls"          // tekpls
	ServiceSentinelsrm     Service = "sentinelsrm"     // SentinelSRM
	ServiceEye2eye         Service = "eye2eye"         // eye2eye
	ServiceIsmaeasdaqlive  Service = "ismaeasdaqlive"  // ISMA Easdaq Live
	ServiceIsmaeasdaqtest  Service = "ismaeasdaqtest"  // ISMA Easdaq Test
	ServiceBcsLmserver     Service = "bcs-lmserver"    // bcs-lmserver
	ServiceMpnjsc          Service = "mpnjsc"          // mpnjsc
	ServiceRapidbase       Service = "rapidbase"       // Rapid Base
	ServiceAbrApi          Service = "abr-api"         // ABR-API (diskbridge)
	ServiceAbrSecure       Service = "abr-secure"      // ABR-Secure Data (diskbridge)
	ServiceVrtlVmfDs       Service = "vrtl-vmf-ds"     // Vertel VMF DS
	ServiceUnixStatus      Service = "unix-status"     // unix-status
	ServiceDxadmind        Service = "dxadmind"        // CA Administration Daemon
	ServiceSimpAll         Service = "simp-all"        // SIMP Channel
	ServiceNasmanager      Service = "nasmanager"      // Merit DAC NASmanager
	ServiceBtsAppserver    Service = "bts-appserver"   // BTS APPSERVER
	ServiceBiapMp          Service = "biap-mp"         // BIAP-MP
	ServiceWebmachine      Service = "webmachine"      // WebMachine
	ServiceSolidEEngine    Service = "solid-e-engine"  // SOLID E ENGINE
	ServiceTivoliNpm       Service = "tivoli-npm"      // Tivoli NPM
	ServiceSlush           Service = "slush"           // Slush
	ServiceSnsQuote        Service = "sns-quote"       // SNS Quote
	ServiceLipsinc         Service = "lipsinc"         // LIPSinc
	ServiceLipsinc1        Service = "lipsinc1"        // LIPSinc 1
	ServiceNetopRc         Service = "netop-rc"        // NetOp Remote Control
	ServiceNetopSchool     Service = "netop-school"    // NetOp School
	ServiceIntersysCache   Service = "intersys-cache"  // Cache
	ServiceDlsrap          Service = "dlsrap"          // Data Link Switching Remote Access Protocol
	ServiceDrp             Service = "drp"             // DRP
	ServiceTcoflashagent   Service = "tcoflashagent"   // TCO Flash Agent
	ServiceTcoregagent     Service = "tcoregagent"     // TCO Reg Agent
	ServiceTcoaddressbook  Service = "tcoaddressbook"  // TCO Address Book
	ServiceUnisql          Service = "unisql"          // UniSQL
	ServiceUnisqlJava      Service = "unisql-java"     // UniSQL Java
	ServicePearldocXact    Service = "pearldoc-xact"   // PearlDoc XACT
	ServiceP2pq            Service = "p2pq"            // p2pQ
	ServiceEstamp          Service = "estamp"          // Evidentiary Timestamp
	ServiceLhtp            Service = "lhtp"            // Loophole Test Protocol
	ServiceBb              Service = "bb"              // BB
	ServiceTrRsrbP1        Service = "tr-rsrb-p1"      // cisco RSRB Priority 1 port
	ServiceTrRsrbP2        Service = "tr-rsrb-p2"      // cisco RSRB Priority 2 port
	ServiceTrRsrbP3        Service = "tr-rsrb-p3"      // cisco RSRB Priority 3 port
	ServiceStunP1          Service = "stun-p1"         // cisco STUN Priority 1 port
	ServiceStunP2          Service = "stun-p2"         // cisco STUN Priority 2 port
	ServiceStunP3          Service = "stun-p3"         // cisco STUN Priority 3 port
	ServiceSnmpTcpPort     Service = "snmp-tcp-port"   // cisco SNMP TCP port
	ServiceStunPort        Service = "stun-port"       // cisco serial tunnel port
	ServicePerfPort        Service = "perf-port"       // cisco perf port
	ServiceTrRsrbPort      Service = "tr-rsrb-port"    // cisco Remote SRB port
	ServiceX25SvcPort      Service = "x25-svc-port"    // cisco X.25 service (XOT)
	ServiceTcpIdPort       Service = "tcp-id-port"     // cisco identification port
	ServiceDc              Service = "dc"              //
	ServiceWizard          Service = "wizard"          // curry
	ServiceGlobe           Service = "globe"           //
	ServiceBrutus          Service = "brutus"          // Brutus Server
	ServiceMailbox         Service = "mailbox"         //
	ServiceEmce            Service = "emce"            // CCWS mm conf
	ServiceBerknet         Service = "berknet"         // csync for cyrus-imapd
	ServiceOracle          Service = "oracle"          // csync for cyrus-imapd
	ServiceInvokator       Service = "invokator"       //
	ServiceRaidCd          Service = "raid-cd"         // raid
	ServiceDectalk         Service = "dectalk"         //
	ServiceRaidAm          Service = "raid-am"         //
	ServiceConf            Service = "conf"            //
	ServiceTerminaldb      Service = "terminaldb"      //
	ServiceNews            Service = "news"            //
	ServiceWhosockami      Service = "whosockami"      //
	ServiceSearch          Service = "search"          //
	ServicePipe_server     Service = "pipe_server"     //
	ServiceRaidCc          Service = "raid-cc"         // raid
	ServiceServserv        Service = "servserv"        //
	ServiceTtyinfo         Service = "ttyinfo"         //
	ServiceRaidAc          Service = "raid-ac"         //
	ServiceTroff           Service = "troff"           //
	ServiceRaidSf          Service = "raid-sf"         //
	ServiceCypress         Service = "cypress"         //
	ServiceRaidCs          Service = "raid-cs"         //
	ServiceBootserver      Service = "bootserver"      //
	ServiceCypressStat     Service = "cypress-stat"    //
	ServiceBootclient      Service = "bootclient"      //
	ServiceRellpack        Service = "rellpack"        //
	ServiceAbout           Service = "about"           //
	ServiceXinupageserver  Service = "xinupageserver"  //
	ServiceServexec        Service = "servexec"        //
	ServiceXinuexpansion1  Service = "xinuexpansion1"  //
	ServiceDown            Service = "down"            //
	ServiceXinuexpansion2  Service = "xinuexpansion2"  //
	ServiceXinuexpansion3  Service = "xinuexpansion3"  //
	ServiceXinuexpansion4  Service = "xinuexpansion4"  //
	ServiceEllpack         Service = "ellpack"         //
	ServiceXribs           Service = "xribs"           //
	ServiceScrabble        Service = "scrabble"        //
	ServiceShadowserver    Service = "shadowserver"    //
	ServiceSubmitserver    Service = "submitserver"    //
	ServiceHsrpv6          Service = "hsrpv6"          // Hot Standby Router Protocol IPv6
	ServiceDevice2         Service = "device2"         //
	ServiceMobrienChat     Service = "mobrien-chat"    // mobrien-chat
	ServiceBlackboard      Service = "blackboard"      //
	ServiceGlogger         Service = "glogger"         //
	ServiceScoremgr        Service = "scoremgr"        //
	ServiceImsldoc         Service = "imsldoc"         //
	ServiceEDpnet          Service = "e-dpnet"         // Ethernet WS DP network
	ServiceApplus          Service = "applus"          // APplus Application Server
	ServiceObjectmanager   Service = "objectmanager"   //
	ServicePrizma          Service = "prizma"          // Prizma Monitoring Service
	ServiceLam             Service = "lam"             //
	ServiceInterbase       Service = "interbase"       //
	ServiceIsis            Service = "isis"            // isis
	ServiceIsisBcast       Service = "isis-bcast"      // isis-bcast
	ServiceRimsl           Service = "rimsl"           //
	ServiceCdfunc          Service = "cdfunc"          //
	ServiceSdfunc          Service = "sdfunc"          //
	ServiceDlsMonitor      Service = "dls-monitor"     //
	ServiceAvEmbConfig     Service = "av-emb-config"   // Avaya EMB Config Port
	ServiceEpnsdp          Service = "epnsdp"          // EPNSDP
	ServiceClearvisn       Service = "clearvisn"       // clearVisn Services Port
	ServiceLot105DsUpd     Service = "lot105-ds-upd"   // Lot105 DSuper Updates
	ServiceWeblogin        Service = "weblogin"        // Weblogin Port
	ServiceIop             Service = "iop"             // Iliad-Odyssey Protocol
	ServiceOmnisky         Service = "omnisky"         // OmniSky Port
	ServiceRichCp          Service = "rich-cp"         // Rich Content Protocol
	ServiceNewwavesearch   Service = "newwavesearch"   // NewWaveSearchables RMI
	ServiceBmcMessaging    Service = "bmc-messaging"   // BMC Messaging Service
	ServiceTeleniumdaemon  Service = "teleniumdaemon"  // Telenium Daemon IF
	ServiceNetmount        Service = "netmount"        // NetMount
	ServiceIcgSwp          Service = "icg-swp"         // ICG SWP Port
	ServiceIcgBridge       Service = "icg-bridge"      // ICG Bridge Port
	ServiceIcgIprelay      Service = "icg-iprelay"     // ICG IP Relay Port
	ServiceDlsrpn          Service = "dlsrpn"          // Data Link Switch Read Port Number
	ServiceAura            Service = "aura"            // AVM USB Remote Architecture
	ServiceDlswpn          Service = "dlswpn"          // Data Link Switch Write Port Number
	ServiceAvauthsrvprtcl  Service = "avauthsrvprtcl"  // Avocent AuthSrv Protocol
	ServiceEventPort       Service = "event-port"      // HTTP Event Port
	ServiceAhEspEncap      Service = "ah-esp-encap"    // AH and ESP Encapsulated in UDP packet
	ServiceAcpPort         Service = "acp-port"        // Axon Control Protocol
	ServiceMsync           Service = "msync"           // GlobeCast mSync
	ServiceGxsDataPort     Service = "gxs-data-port"   // DataReel Database Socket
	ServiceVrtlVmfSa       Service = "vrtl-vmf-sa"     // Vertel VMF SA
	ServiceNewlixengine    Service = "newlixengine"    // Newlix ServerWare Engine
	ServiceNewlixconfig    Service = "newlixconfig"    // Newlix JSPConfig
	ServiceTsrmagt         Service = "tsrmagt"         // Old Tivoli Storage Manager
	ServiceTpcsrvr         Service = "tpcsrvr"         // IBM Total Productivity Center Server
	ServiceIdwareRouter    Service = "idware-router"   // IDWARE Router Port
	ServiceAutodeskNlm     Service = "autodesk-nlm"    // Autodesk NLM (FLEXlm)
	ServiceKmeTrapPort     Service = "kme-trap-port"   // KME PRINTER TRAP PORT
	ServiceInfowave        Service = "infowave"        // Infowave Mobility Server
	ServiceRadsec          Service = "radsec"          // Secure Radius Service
	ServiceSunclustergeo   Service = "sunclustergeo"   // SunCluster Geographic
	ServiceAdaCip          Service = "ada-cip"         // ADA Control
	ServiceGnunet          Service = "gnunet"          // GNUnet
	ServiceEli             Service = "eli"             // ELI - Event Logging Integration
	ServiceIpBlf           Service = "ip-blf"          // IP Busy Lamp Field
	ServiceSep             Service = "sep"             // Security Encapsulation Protocol - SEP
	ServiceLrp             Service = "lrp"             // Load Report Protocol
	ServicePrp             Service = "prp"             // PRP
	ServiceDescent3        Service = "descent3"        // Descent 3
	ServiceNbxCc           Service = "nbx-cc"          // NBX CC
	ServiceNbxAu           Service = "nbx-au"          // NBX AU
	ServiceNbxSer          Service = "nbx-ser"         // NBX SER
	ServiceNbxDir          Service = "nbx-dir"         // NBX DIR
	ServiceJetformpreview  Service = "jetformpreview"  // Jet Form Preview
	ServiceDialogPort      Service = "dialog-port"     // Dialog Port
	ServiceH2250AnnexG     Service = "h2250-annex-g"   // H.225.0 Annex G
	ServiceAmiganetfs      Service = "amiganetfs"      // Amiga Network Filesystem
	ServiceRtcmSc104       Service = "rtcm-sc104"      // rtcm-sc104
	ServiceMinipay         Service = "minipay"         // MiniPay
	ServiceMzap            Service = "mzap"            // MZAP
	ServiceBintecAdmin     Service = "bintec-admin"    // BinTec Admin
	ServiceComcam          Service = "comcam"          // Comcam
	ServiceErgolight       Service = "ergolight"       // Ergolight
	ServiceUmsp            Service = "umsp"            // UMSP
	ServiceDsatp           Service = "dsatp"           // DSATP
	ServiceIdonixMetanet   Service = "idonix-metanet"  // Idonix MetaNet
	ServiceHslStorm        Service = "hsl-storm"       // HSL StoRM
	ServiceNewheights      Service = "newheights"      // NEWHEIGHTS
	ServiceKdm             Service = "kdm"             // Key Distribution Manager
	ServiceCcowcmr         Service = "ccowcmr"         // CCOWCMR
	ServiceMentaclient     Service = "mentaclient"     // MENTACLIENT
	ServiceMentaserver     Service = "mentaserver"     // MENTASERVER
	ServiceGsigatekeeper   Service = "gsigatekeeper"   // GSIGATEKEEPER
	ServiceQencp           Service = "qencp"           // Quick Eagle Networks CP
	ServiceScientiaSsdb    Service = "scientia-ssdb"   // SCIENTIA-SSDB
	ServiceCaupcRemote     Service = "caupc-remote"    // CauPC Remote Control
	ServiceGtpControl      Service = "gtp-control"     // GTP-Control Plane (3GPP)
	ServiceElatelink       Service = "elatelink"       // ELATELINK
	ServiceLockstep        Service = "lockstep"        // LOCKSTEP
	ServicePktcableCops    Service = "pktcable-cops"   // PktCable-COPS
	ServiceIndexPcWb       Service = "index-pc-wb"     // INDEX-PC-WB
	ServiceNetSteward      Service = "net-steward"     // Net Steward Control
	ServiceCsLive          Service = "cs-live"         // cs-live.com
	ServiceXds             Service = "xds"             // XDS
	ServiceAvantageb2b     Service = "avantageb2b"     // Avantageb2b
	ServiceSoleraEpmap     Service = "solera-epmap"    // SoleraTec End Point Map
	ServiceZymedZpp        Service = "zymed-zpp"       // ZYMED-ZPP
	ServiceAvenue          Service = "avenue"          // AVENUE
	ServiceGris            Service = "gris"            // Grid Resource Information Server
	ServiceAppworxsrv      Service = "appworxsrv"      // APPWORXSRV
	ServiceConnect         Service = "connect"         // CONNECT
	ServiceUnbindCluster   Service = "unbind-cluster"  // UNBIND-CLUSTER
	ServiceIasAuth         Service = "ias-auth"        // IAS-AUTH
	ServiceIasReg          Service = "ias-reg"         // IAS-REG
	ServiceIasAdmind       Service = "ias-admind"      // IAS-ADMIND
	ServiceTdmoip          Service = "tdmoip"          // TDM OVER IP
	ServiceLvJc            Service = "lv-jc"           // Live Vault Job Control
	ServiceLvFfx           Service = "lv-ffx"          // Live Vault Fast Object Transfer
	ServiceLvPici          Service = "lv-pici"         // Live Vault Remote Diagnostic Console Support
	ServiceLvNot           Service = "lv-not"          // Live Vault Admin Event Notification
	ServiceLvAuth          Service = "lv-auth"         // Live Vault Authentication
	ServiceVeritasUcl      Service = "veritas-ucl"     // VERITAS UNIVERSAL COMMUNICATION LAYER
	ServiceAcptsys         Service = "acptsys"         // ACPTSYS
	ServiceDocent          Service = "docent"          // DOCENT
	ServiceGtpUser         Service = "gtp-user"        // GTP-User Plane (3GPP)
	ServiceCtlptc          Service = "ctlptc"          // Control Protocol
	ServiceStdptc          Service = "stdptc"          // Standard Protocol
	ServiceBrdptc          Service = "brdptc"          // Bridge Protocol
	ServiceTrp             Service = "trp"             // Talari Reliable Protocol
	ServiceXnds            Service = "xnds"            // Xerox Network Document Scan Protocol
	ServiceTouchnetplus    Service = "touchnetplus"    // TouchNetPlus Service
	ServiceGdbremote       Service = "gdbremote"       // GDB Remote Debug Port
	ServiceApc2160         Service = "apc-2160"        // APC 2160
	ServiceApc2161         Service = "apc-2161"        // APC 2161
	ServiceNavisphere      Service = "navisphere"      // Navisphere
	ServiceNavisphereSec   Service = "navisphere-sec"  // Navisphere Secure
	ServiceDdnsV3          Service = "ddns-v3"         // Dynamic DNS Version 3
	ServiceXBoneApi        Service = "x-bone-api"      // X-Bone API
	ServiceIwserver        Service = "iwserver"        // iwserver
	ServiceRawSerial       Service = "raw-serial"      // Raw Async Serial Link
	ServiceEasySoftMux     Service = "easy-soft-mux"   // easy-soft Multiplexer
	ServiceBrain           Service = "brain"           // Backbone for Academic Information Notification (BRAIN)
	ServiceEyetv           Service = "eyetv"           // EyeTV Server Port
	ServiceMsfwStorage     Service = "msfw-storage"    // MS Firewall Storage
	ServiceMsfwSStorage    Service = "msfw-s-storage"  // MS Firewall SecureStorage
	ServiceMsfwReplica     Service = "msfw-replica"    // MS Firewall Replication
	ServiceMsfwArray       Service = "msfw-array"      // MS Firewall Intra Array
	ServiceAirsync         Service = "airsync"         // Microsoft Desktop AirSync Protocol
	ServiceRapi            Service = "rapi"            // Microsoft ActiveSync Remote API
	ServiceQwave           Service = "qwave"           // qWAVE Bandwidth Estimate
	ServiceBitspeer        Service = "bitspeer"        // Peer Services for BITS
	ServiceVmrdp           Service = "vmrdp"           // Microsoft RDP for virtual machines
	ServiceMcGtSrv         Service = "mc-gt-srv"       // Millicent Vendor Gateway Server
	ServiceEforward        Service = "eforward"        // eforward
	ServiceCgnStat         Service = "cgn-stat"        // CGN status
	ServiceCgnConfig       Service = "cgn-config"      // Code Green configuration
	ServiceNvd             Service = "nvd"             // NVD User
	ServiceOnbaseDds       Service = "onbase-dds"      // OnBase Distributed Disk Services
	ServiceGtaua           Service = "gtaua"           // Guy-Tek Automated Update Applications
	ServiceSsmc            Service = "ssmc"            // Sepehr System Management Control
	ServiceSsmd            Service = "ssmd"            // Sepehr System Management Data
	ServiceRadwareRpm      Service = "radware-rpm"     // Radware Resource Pool Manager
	ServiceRadwareRpmS     Service = "radware-rpm-s"   // Secure Radware Resource Pool Manager
	ServiceTivoconnect     Service = "tivoconnect"     // TiVoConnect Beacon
	ServiceTvbus           Service = "tvbus"           // TvBus Messaging
	ServiceAsdis           Service = "asdis"           // ASDIS software management
	ServiceDrwcs           Service = "drwcs"           // Dr.Web Enterprise Management Service
	ServiceMnpExchange     Service = "mnp-exchange"    // MNP data exchange
	ServiceOnehomeRemote   Service = "onehome-remote"  // OneHome Remote Access
	ServiceOnehomeHelp     Service = "onehome-help"    // OneHome Service Port
	ServiceIci             Service = "ici"             // ICI
	ServiceAts             Service = "ats"             // Advanced Training System Program
	ServiceImtcMap         Service = "imtc-map"        // Int. Multimedia Teleconferencing Cosortium
	ServiceB2Runtime       Service = "b2-runtime"      // b2 Runtime Protocol
	ServiceB2License       Service = "b2-license"      // b2 License Server
	ServiceJps             Service = "jps"             // Java Presentation Server
	ServiceHpocbus         Service = "hpocbus"         // HP OpenCall bus
	ServiceHpssd           Service = "hpssd"           // HP Status and Services
	ServiceHpiod           Service = "hpiod"           // HP I/O Backend
	ServiceRimfPs          Service = "rimf-ps"         // HP RIM for Files Portal Service
	ServiceNoaaport        Service = "noaaport"        // NOAAPORT Broadcast Network
	ServiceEmwin           Service = "emwin"           // EMWIN
	ServiceLeecoposserver  Service = "leecoposserver"  // LeeCO POS Server Service
	ServiceKali            Service = "kali"            // Kali
	ServiceRpi             Service = "rpi"             // RDQ Protocol Interface
	ServiceIpcore          Service = "ipcore"          // IPCore.co.za GPRS
	ServiceVtuComms        Service = "vtu-comms"       // VTU data service
	ServiceGotodevice      Service = "gotodevice"      // GoToDevice Device Management
	ServiceBounzza         Service = "bounzza"         // Bounzza IRC Proxy
	ServiceNetiqNcap       Service = "netiq-ncap"      // NetIQ NCAP Protocol
	ServiceNetiq           Service = "netiq"           // NetIQ End2End
	ServiceRockwellCsp1    Service = "rockwell-csp1"   // Rockwell CSP1
	ServiceEtherNetIP1     Service = "EtherNet/IP-1"   // EtherNet/IP I/O
	ServiceRockwellCsp2    Service = "rockwell-csp2"   // Rockwell CSP2
	ServiceEfiMg           Service = "efi-mg"          // Easy Flexible Internet/Multiplayer Games
	ServiceRcipItu         Service = "rcip-itu"        // Resource Connection Initiation Protocol
	ServiceDiDrm           Service = "di-drm"          // Digital Instinct DRM
	ServiceDiMsg           Service = "di-msg"          // DI Messaging Service
	ServiceEhomeMs         Service = "ehome-ms"        // eHome Message Server
	ServiceDatalens        Service = "datalens"        // DataLens Service
	ServiceQueueadm        Service = "queueadm"        // MetaSoft Job Queue Administration Service
	ServiceWimaxasncp      Service = "wimaxasncp"      // WiMAX ASN Control Plane Protocol
	ServiceIvsVideo        Service = "ivs-video"       // IVS Video default
	ServiceInfocrypt       Service = "infocrypt"       // INFOCRYPT
	ServiceDirectplay      Service = "directplay"      // DirectPlay
	ServiceSercommWlink    Service = "sercomm-wlink"   // Sercomm-WLink
	ServiceNani            Service = "nani"            // Nani
	ServiceOptechPort1Lm   Service = "optech-port1-lm" // Optech Port1 License Manager
	ServiceAvivaSna        Service = "aviva-sna"       // AVIVA SNA SERVER
	ServiceImagequery      Service = "imagequery"      // Image Query
	ServiceRecipe          Service = "recipe"          // RECIPe
	ServiceIvsd            Service = "ivsd"            // IVS Daemon
	ServiceFoliocorp       Service = "foliocorp"       // Folio Remote Server
	ServiceMagicom         Service = "magicom"         // Magicom Protocol
	ServiceNmsserver       Service = "nmsserver"       // NMS Server
	ServiceHao             Service = "hao"             // HaO
	ServicePcMtaAddrmap    Service = "pc-mta-addrmap"  // PacketCable MTA Addr Map
	ServiceAntidotemgrsvr  Service = "antidotemgrsvr"  // Antidote Deployment Manager Service
	ServiceUms             Service = "ums"             // User Management Service
	ServiceRfmp            Service = "rfmp"            // RISO File Manager Protocol
	ServiceRemoteCollab    Service = "remote-collab"   // remote-collab
	ServiceDifPort         Service = "dif-port"        // Distributed Framework Port
	ServiceNjenetSsl       Service = "njenet-ssl"      // NJENET using SSL
	ServiceDtvChanReq      Service = "dtv-chan-req"    // DTV Channel Request
	ServiceSeispoc         Service = "seispoc"         // Seismic P.O.C. Port
	ServiceVrtp            Service = "vrtp"            // VRTP - ViRtue Transfer Protocol
	ServicePccMfp          Service = "pcc-mfp"         // PCC MFP
	ServiceSimpleTxRx      Service = "simple-tx-rx"    // simple text/file transfer
	ServiceRcts            Service = "rcts"            // Rotorcraft Communications Test System
	ServiceApc2260         Service = "apc-2260"        // APC 2260
	ServiceComotionmaster  Service = "comotionmaster"  // CoMotion Master Server
	ServiceComotionback    Service = "comotionback"    // CoMotion Backup Server
	ServiceEcwcfg          Service = "ecwcfg"          // ECweb Configuration Service
	ServiceApx500api1      Service = "apx500api-1"     // Audio Precision Apx500 API Port 1
	ServiceApx500api2      Service = "apx500api-2"     // Audio Precision Apx500 API Port 2
	ServiceMfserver        Service = "mfserver"        // M-Files Server
	ServiceOntobroker      Service = "ontobroker"      // OntoBroker
	ServiceAmt             Service = "amt"             // AMT
	ServiceMikey           Service = "mikey"           // MIKEY
	ServiceStarschool      Service = "starschool"      // starSchool
	ServiceMmcals          Service = "mmcals"          // Secure Meeting Maker Scheduling
	ServiceMmcal           Service = "mmcal"           // Meeting Maker Scheduling
	ServiceMysqlIm         Service = "mysql-im"        // MySQL Instance Manager
	ServicePcttunnell      Service = "pcttunnell"      // PCTTunneller
	ServiceIbridgeData     Service = "ibridge-data"    // iBridge Conferencing
	ServiceIbridgeMgmt     Service = "ibridge-mgmt"    // iBridge Management
	ServiceBluectrlproxy   Service = "bluectrlproxy"   // Bt device control proxy
	ServiceS3db            Service = "s3db"            // Simple Stacked Sequences Database
	ServiceXmquery         Service = "xmquery"         // xmquery
	ServiceLnvpoller       Service = "lnvpoller"       // LNVPOLLER
	ServiceLnvconsole      Service = "lnvconsole"      // LNVCONSOLE
	ServiceLnvalarm        Service = "lnvalarm"        // LNVALARM
	ServiceLnvstatus       Service = "lnvstatus"       // LNVSTATUS
	ServiceLnvmaps         Service = "lnvmaps"         // LNVMAPS
	ServiceLnvmailmon      Service = "lnvmailmon"      // LNVMAILMON
	ServiceNasMetering     Service = "nas-metering"    // NAS-Metering
	ServiceDna             Service = "dna"             // DNA
	ServiceNetml           Service = "netml"           // NETML
	ServiceDictLookup      Service = "dict-lookup"     // Lookup dict server
	ServiceSonusLogging    Service = "sonus-logging"   // Sonus Logging Services
	ServiceEapsp           Service = "eapsp"           // EPSON Advanced Printer Share Protocol
	ServiceMibStreaming    Service = "mib-streaming"   // Sonus Element Management Services
	ServiceNpdbgmngr       Service = "npdbgmngr"       // Network Platform Debug Manager
	ServiceKonshusLm       Service = "konshus-lm"      // Konshus License Manager (FLEX)
	ServiceAdvantLm        Service = "advant-lm"       // Advant License Manager
	ServiceThetaLm         Service = "theta-lm"        // Theta License Manager (Rainbow)
	ServiceD2kDatamover1   Service = "d2k-datamover1"  // D2K DataMover 1
	ServiceD2kDatamover2   Service = "d2k-datamover2"  // D2K DataMover 2
	ServicePcTelecommute   Service = "pc-telecommute"  // PC Telecommute
	ServiceCvmmon          Service = "cvmmon"          // CVMMON
	ServiceCpqWbem         Service = "cpq-wbem"        // Compaq HTTP
	ServiceBinderysupport  Service = "binderysupport"  // Bindery Support
	ServiceProxyGateway    Service = "proxy-gateway"   // Proxy Gateway
	ServiceAttachmateUts   Service = "attachmate-uts"  // Attachmate UTS
	ServiceMtScaleserver   Service = "mt-scaleserver"  // MT ScaleServer
	ServiceTappiBoxnet     Service = "tappi-boxnet"    // TAPPI BoxNet
	ServicePehelp          Service = "pehelp"          // pehelp
	ServiceSdhelp          Service = "sdhelp"          // sdhelp
	ServiceSdserver        Service = "sdserver"        // SD Server
	ServiceSdclient        Service = "sdclient"        // SD Client
	ServiceMessageservice  Service = "messageservice"  // Message Service
	ServiceWanscaler       Service = "wanscaler"       // WANScaler Communication Service
	ServiceIapp            Service = "iapp"            // IAPP (Inter Access Point Protocol)
	ServiceCrWebsystems    Service = "cr-websystems"   // CR WebSystems
	ServicePreciseSft      Service = "precise-sft"     // Precise Sft.
	ServiceSentLm          Service = "sent-lm"         // SENT License Manager
	ServiceAttachmateG32   Service = "attachmate-g32"  // Attachmate G32
	ServiceCadencecontrol  Service = "cadencecontrol"  // Cadence Control
	ServiceInfolibria      Service = "infolibria"      // InfoLibria
	ServiceSiebelNs        Service = "siebel-ns"       // Siebel NS
	ServiceRdlap           Service = "rdlap"           // RDLAP
	ServiceOfsd            Service = "ofsd"            // ofsd
	Service3dNfsd          Service = "3d-nfsd"         // 3d-nfsd
	ServiceCosmocall       Service = "cosmocall"       // Cosmocall
	ServiceAnsysli         Service = "ansysli"         // ANSYS Licensing Interconnect
	ServiceIdcp            Service = "idcp"            // IDCP
	ServiceXingcsm         Service = "xingcsm"         // xingcsm
	ServiceNetrixSftm      Service = "netrix-sftm"     // Netrix SFTM
	ServiceTscchat         Service = "tscchat"         // TSCCHAT
	ServiceAgentview       Service = "agentview"       // AGENTVIEW
	ServiceRccHost         Service = "rcc-host"        // RCC Host
	ServiceSnapp           Service = "snapp"           // SNAPP
	ServiceAceClient       Service = "ace-client"      // ACE Client Auth
	ServiceAceProxy        Service = "ace-proxy"       // ACE Proxy
	ServiceAppleugcontrol  Service = "appleugcontrol"  // Apple UG Control
	ServiceIdeesrv         Service = "ideesrv"         // ideesrv
	ServiceNortonLambert   Service = "norton-lambert"  // Norton Lambert
	Service3comWebview     Service = "3com-webview"    // 3Com WebView
	ServiceWrs_registry    Service = "wrs_registry"    // WRS Registry
	ServiceXiostatus       Service = "xiostatus"       // XIO Status
	ServiceManageExec      Service = "manage-exec"     // Seagate Manage Exec
	ServiceNatiLogos       Service = "nati-logos"      // nati logos
	ServiceFcmsys          Service = "fcmsys"          // fcmsys
	ServiceDbm             Service = "dbm"             // dbm
	ServiceRedstorm_join   Service = "redstorm_join"   // Game Connection Port
	ServiceRedstorm_find   Service = "redstorm_find"   // Game Announcement and Location
	ServiceRedstorm_info   Service = "redstorm_info"   // Information to query for game status
	ServiceRedstorm_diag   Service = "redstorm_diag"   // Diagnostics Port
	ServicePsbserver       Service = "psbserver"       // Pharos Booking Server
	ServicePsrserver       Service = "psrserver"       // psrserver
	ServicePslserver       Service = "pslserver"       // pslserver
	ServicePspserver       Service = "pspserver"       // pspserver
	ServicePsprserver      Service = "psprserver"      // psprserver
	ServicePsdbserver      Service = "psdbserver"      // psdbserver
	ServiceGxtelmd         Service = "gxtelmd"         // GXT License Managemant
	ServiceUnihubServer    Service = "unihub-server"   // UniHub Server
	ServiceFutrix          Service = "futrix"          // Futrix
	ServiceFlukeserver     Service = "flukeserver"     // FlukeServer
	ServiceNexstorindltd   Service = "nexstorindltd"   // NexstorIndLtd
	ServiceTl1             Service = "tl1"             // TL1
	ServiceDigiman         Service = "digiman"         // digiman
	ServiceMediacntrlnfsd  Service = "mediacntrlnfsd"  // Media Central NFSD
	ServiceOi2000          Service = "oi-2000"         // OI-2000
	ServiceDbref           Service = "dbref"           // dbref
	ServiceQipLogin        Service = "qip-login"       // qip-login
	ServiceServiceCtrl     Service = "service-ctrl"    // Service Control
	ServiceOpentable       Service = "opentable"       // OpenTable
	ServiceL3Hbmon         Service = "l3-hbmon"        // L3-HBMon
	ServiceWorldwire       Service = "worldwire"       // Compaq WorldWire Port
	ServiceLanmessenger    Service = "lanmessenger"    // LanMessenger
	ServiceRemographlm     Service = "remographlm"     // Remograph License Manager
	ServiceHydra           Service = "hydra"           // Hydra RPC
	ServiceCompaqHttps     Service = "compaq-https"    // Compaq HTTPS
	ServiceMsOlap3         Service = "ms-olap3"        // Microsoft OLAP
	ServiceMsOlap4         Service = "ms-olap4"        // Microsoft OLAP
	ServiceSdRequest       Service = "sd-request"      // SD-REQUEST
	ServiceSdCapacity      Service = "sd-capacity"     // SD-CAPACITY
	ServiceSdData          Service = "sd-data"         // SD-DATA
	ServiceVirtualtape     Service = "virtualtape"     // Virtual Tape
	ServiceVsamredirector  Service = "vsamredirector"  // VSAM Redirector
	ServiceMynahautostart  Service = "mynahautostart"  // MYNAH AutoStart
	ServiceOvsessionmgr    Service = "ovsessionmgr"    // OpenView Session Mgr
	ServiceRsmtp           Service = "rsmtp"           // RSMTP
	Service3comNetMgmt     Service = "3com-net-mgmt"   // 3COM Net Management
	ServiceTacticalauth    Service = "tacticalauth"    // Tactical Auth
	ServiceMsOlap1         Service = "ms-olap1"        // MS OLAP 1
	ServiceMsOlap2         Service = "ms-olap2"        // MS OLAP 2
	ServiceLan900_remote   Service = "lan900_remote"   // LAN900 Remote
	ServiceWusage          Service = "wusage"          // Wusage
	ServiceNcl             Service = "ncl"             // NCL
	ServiceOrbiter         Service = "orbiter"         // Orbiter
	ServiceFmproFdal       Service = "fmpro-fdal"      // FileMaker, Inc. - Data Access Layer
	ServiceOpequusServer   Service = "opequus-server"  // OpEquus Server
	ServiceTaskmaster2000  Service = "taskmaster2000"  // TaskMaster 2000 Server
	ServiceIec104          Service = "iec-104"         // IEC 60870-5-104 process control over IP
	ServiceTrcNetpoll      Service = "trc-netpoll"     // TRC Netpoll
	ServiceJediserver      Service = "jediserver"      // JediServer
	ServiceOrion           Service = "orion"           // Orion
	ServiceRailgunWebaccl  Service = "railgun-webaccl" // CloudFlare Railgun Web
	ServiceSnsProtocol     Service = "sns-protocol"    // SNS Protocol
	ServiceVrtsRegistry    Service = "vrts-registry"   // VRTS Registry
	ServiceNetwaveApMgmt   Service = "netwave-ap-mgmt" // Netwave AP Management
	ServiceCdn             Service = "cdn"             // CDN
	ServiceOrionRmiReg     Service = "orion-rmi-reg"   // orion-rmi-reg
	ServiceBeeyond         Service = "beeyond"         // Beeyond
	ServiceCodimaRtp       Service = "codima-rtp"      // Codima Remote Transaction Protocol
	ServiceRmtserver       Service = "rmtserver"       // RMT Server
	ServiceCompositServer  Service = "composit-server" // Composit Server
	ServiceCas             Service = "cas"             // cas
	ServiceAttachmateS2s   Service = "attachmate-s2s"  // Attachmate S2S
	ServiceDslremoteMgmt   Service = "dslremote-mgmt"  // DSL Remote Management
	ServiceGTalk           Service = "g-talk"          // G-Talk
	ServiceCrmsbits        Service = "crmsbits"        // CRMSBITS
	ServiceRnrp            Service = "rnrp"            // RNRP
	ServiceKofaxSvr        Service = "kofax-svr"       // KOFAX-SVR
	ServiceFjitsuappmgr    Service = "fjitsuappmgr"    // Fujitsu App Manager
	ServiceMgcpGateway     Service = "mgcp-gateway"    // Media Gateway Control Protocol Gateway
	ServiceOtt             Service = "ott"             // One Way Trip Time
	ServiceFtRole          Service = "ft-role"         // FT-ROLE
	ServicePxcEpmap        Service = "pxc-epmap"       // pxc-epmap
	ServiceOptilogic       Service = "optilogic"       // OptiLogic
	ServiceTopx            Service = "topx"            // TOP/X
	ServiceUnicontrol      Service = "unicontrol"      // UniControl
	ServiceSybasedbsynch   Service = "sybasedbsynch"   // SybaseDBSynch
	ServiceSpearway        Service = "spearway"        // Spearway Lockers
	ServicePvswInet        Service = "pvsw-inet"       // Pervasive I*net Data Server
	ServiceNetangel        Service = "netangel"        // Netangel
	ServicePowerclientcsf  Service = "powerclientcsf"  // PowerClient Central Storage Facility
	ServiceBtpp2sectrans   Service = "btpp2sectrans"   // BT PP2 Sectrans
	ServiceDtn1            Service = "dtn1"            // DTN1
	ServiceBues_service    Service = "bues_service"    // bues_service
	ServiceOvwdb           Service = "ovwdb"           // OpenView NNM daemon
	ServiceHpppssvr        Service = "hpppssvr"        // hpppsvr
	ServiceRatl            Service = "ratl"            // RATL
	ServiceNetadmin        Service = "netadmin"        // netadmin
	ServiceNetchat         Service = "netchat"         // netchat
	ServiceSnifferclient   Service = "snifferclient"   // SnifferClient
	ServiceMadgeLtd        Service = "madge-ltd"       // madge ltd
	ServiceIndxDds         Service = "indx-dds"        // IndX-DDS
	ServiceWagoIoSystem    Service = "wago-io-system"  // WAGO-IO-SYSTEM
	ServiceAltavRemmgt     Service = "altav-remmgt"    // altav-remmgt
	ServiceRapidoIp        Service = "rapido-ip"       // Rapido_IP
	ServiceGriffin         Service = "griffin"         // griffin
	ServiceCommunity       Service = "community"       // Community
	ServiceMsTheater       Service = "ms-theater"      // ms-theater
	ServiceQadmifoper      Service = "qadmifoper"      // qadmifoper
	ServiceQadmifevent     Service = "qadmifevent"     // qadmifevent
	ServiceLsiRaidMgmt     Service = "lsi-raid-mgmt"   // LSI RAID Management
	ServiceDirecpcSi       Service = "direcpc-si"      // DirecPC SI
	ServiceLbm             Service = "lbm"             // Load Balance Management
	ServiceLbf             Service = "lbf"             // Load Balance Forwarding
	ServiceHighCriteria    Service = "high-criteria"   // High Criteria
	ServiceQipMsgd         Service = "qip-msgd"        // qip_msgd
	ServiceMtiTcsComm      Service = "mti-tcs-comm"    // MTI-TCS-COMM
	ServiceTaskmanPort     Service = "taskman-port"    // taskman port
	ServiceSeaodbc         Service = "seaodbc"         // SeaODBC
	ServiceC3              Service = "c3"              // C3
	ServiceAkerCdp         Service = "aker-cdp"        // Aker-cdp
	ServiceVitalanalysis   Service = "vitalanalysis"   // Vital Analysis
	ServiceAceServer       Service = "ace-server"      // ACE Server
	ServiceAceSvrProp      Service = "ace-svr-prop"    // ACE Server Propagation
	ServiceSsmCvs          Service = "ssm-cvs"         // SecurSight Certificate Valifation Service
	ServiceSsmCssps        Service = "ssm-cssps"       // SecurSight Authentication Server (SSL)
	ServiceSsmEls          Service = "ssm-els"         // SecurSight Event Logging Server (SSL)
	ServicePowerexchange   Service = "powerexchange"   // Informatica PowerExchange Listener
	ServiceGiop            Service = "giop"            // Oracle GIOP
	ServiceGiopSsl         Service = "giop-ssl"        // Oracle GIOP SSL
	ServiceTtc             Service = "ttc"             // Oracle TTC
	ServiceTtcSsl          Service = "ttc-ssl"         // Oracle TTC SSL
	ServiceNetobjects1     Service = "netobjects1"     // Net Objects1
	ServiceNetobjects2     Service = "netobjects2"     // Net Objects2
	ServicePns             Service = "pns"             // Policy Notice Service
	ServiceMoyCorp         Service = "moy-corp"        // Moy Corporation
	ServiceTsilb           Service = "tsilb"           // TSILB
	ServiceQipQdhcp        Service = "qip-qdhcp"       // qip_qdhcp
	ServiceConclaveCpp     Service = "conclave-cpp"    // Conclave CPP
	ServiceGroove          Service = "groove"          // GROOVE
	ServiceTalarianMqs     Service = "talarian-mqs"    // Talarian MQS
	ServiceBmcAr           Service = "bmc-ar"          // BMC AR
	ServiceFastRemServ     Service = "fast-rem-serv"   // Fast Remote Services
	ServiceDirgis          Service = "dirgis"          // DIRGIS
	ServiceQuaddb          Service = "quaddb"          // Quad DB
	ServiceOdnCastraq      Service = "odn-castraq"     // ODN-CasTraq
	ServiceRtsserv         Service = "rtsserv"         // Resource Tracking system server
	ServiceRtsclient       Service = "rtsclient"       // Resource Tracking system client
	ServiceKentroxProt     Service = "kentrox-prot"    // Kentrox Protocol
	ServiceNmsDpnss        Service = "nms-dpnss"       // NMS-DPNSS
	ServiceWlbs            Service = "wlbs"            // WLBS
	ServicePpcontrol       Service = "ppcontrol"       // PowerPlay Control
	ServiceJbroker         Service = "jbroker"         // jbroker
	ServiceSpock           Service = "spock"           // spock
	ServiceJdatastore      Service = "jdatastore"      // JDataStore
	ServiceFjmpss          Service = "fjmpss"          // fjmpss
	ServiceFjappmgrbulk    Service = "fjappmgrbulk"    // fjappmgrbulk
	ServiceMetastorm       Service = "metastorm"       // Metastorm
	ServiceCitrixima       Service = "citrixima"       // Citrix IMA
	ServiceCitrixadmin     Service = "citrixadmin"     // Citrix ADMIN
	ServiceFacsysNtp       Service = "facsys-ntp"      // Facsys NTP
	ServiceFacsysRouter    Service = "facsys-router"   // Facsys Router
	ServiceMaincontrol     Service = "maincontrol"     // Main Control
	ServiceCallSigTrans    Service = "call-sig-trans"  // H.323 Annex E call signaling transport
	ServiceWilly           Service = "willy"           // Willy
	ServiceGlobmsgsvc      Service = "globmsgsvc"      // globmsgsvc
	ServicePvsw            Service = "pvsw"            // Pervasive Listener
	ServiceAdaptecmgr      Service = "adaptecmgr"      // Adaptec Manager
	ServiceWindb           Service = "windb"           // WinDb
	ServiceQkeLlcV3        Service = "qke-llc-v3"      // Qke LLC V.3
	ServiceOptiwaveLm      Service = "optiwave-lm"     // Optiwave License Management
	ServiceMsVWorlds       Service = "ms-v-worlds"     // MS V-Worlds
	ServiceEmaSentLm       Service = "ema-sent-lm"     // EMA License Manager
	ServiceIqserver        Service = "iqserver"        // IQ Server
	ServiceNcr_ccl         Service = "ncr_ccl"         // NCR CCL
	ServiceUtsftp          Service = "utsftp"          // UTS FTP
	ServiceVrcommerce      Service = "vrcommerce"      // VR Commerce
	ServiceItoEGui         Service = "ito-e-gui"       // ITO-E GUI
	ServiceOvtopmd         Service = "ovtopmd"         // OVTOPMD
	ServiceSnifferserver   Service = "snifferserver"   // SnifferServer
	ServiceComboxWebAcc    Service = "combox-web-acc"  // Combox Web Access
	ServiceMadcap          Service = "madcap"          // MADCAP
	ServiceBtpp2audctr1    Service = "btpp2audctr1"    // btpp2audctr1
	ServiceUpgrade         Service = "upgrade"         // Upgrade Protocol
	ServiceVnwkPrapi       Service = "vnwk-prapi"      // vnwk-prapi
	ServiceVsiadmin        Service = "vsiadmin"        // VSI Admin
	ServiceLonworks        Service = "lonworks"        // LonWorks
	ServiceLonworks2       Service = "lonworks2"       // LonWorks2
	ServiceUdrawgraph      Service = "udrawgraph"      // uDraw(Graph)
	ServiceReftek          Service = "reftek"          // REFTEK
	ServiceNovellZen       Service = "novell-zen"      // Management Daemon Refresh
	ServiceSisEmt          Service = "sis-emt"         // sis-emt
	ServiceVytalvaultbrtp  Service = "vytalvaultbrtp"  // vytalvaultbrtp
	ServiceVytalvaultvsmp  Service = "vytalvaultvsmp"  // vytalvaultvsmp
	ServiceVytalvaultpipe  Service = "vytalvaultpipe"  // vytalvaultpipe
	ServiceIpass           Service = "ipass"           // IPASS
	ServiceAds             Service = "ads"             // ADS
	ServiceIsgUdaServer    Service = "isg-uda-server"  // ISG UDA Server
	ServiceCallLogging     Service = "call-logging"    // Call Logging
	ServiceEfidiningport   Service = "efidiningport"   // efidiningport
	ServiceVcnetLinkV10    Service = "vcnet-link-v10"  // VCnet-Link v10
	ServiceCompaqWcp       Service = "compaq-wcp"      // Compaq WCP
	ServiceNicetecNmsvc    Service = "nicetec-nmsvc"   // nicetec-nmsvc
	ServiceNicetecMgmt     Service = "nicetec-mgmt"    // nicetec-mgmt
	ServicePclemultimedia  Service = "pclemultimedia"  // PCLE Multi Media
	ServiceLstp            Service = "lstp"            // LSTP
	ServiceLabrat          Service = "labrat"          // labrat
	ServiceMosaixcc        Service = "mosaixcc"        // MosaixCC
	ServiceDelibo          Service = "delibo"          // Delibo
	ServiceCtiRedwood      Service = "cti-redwood"     // CTI Redwood
	ServiceHp3000Telnet    Service = "hp-3000-telnet"  // HP 3000 NS/VT block mode telnet
	ServiceCoordSvr        Service = "coord-svr"       // Coordinator Server
	ServicePcsPcw          Service = "pcs-pcw"         // pcs-pcw
	ServiceClp             Service = "clp"             // Cisco Line Protocol
	ServiceSpamtrap        Service = "spamtrap"        // SPAM TRAP
	ServiceSonuscallsig    Service = "sonuscallsig"    // Sonus Call Signal
	ServiceHsPort          Service = "hs-port"         // HS Port
	ServiceCecsvc          Service = "cecsvc"          // CECSVC
	ServiceIbp             Service = "ibp"             // IBP
	ServiceTrustestablish  Service = "trustestablish"  // Trust Establish
	ServiceBlockadeBpsp    Service = "blockade-bpsp"   // Blockade BPSP
	ServiceHl7             Service = "hl7"             // HL7
	ServiceTclprodebugger  Service = "tclprodebugger"  // TCL Pro Debugger
	ServiceScipticslsrvr   Service = "scipticslsrvr"   // Scriptics Lsrvr
	ServiceRvsIsdnDcp      Service = "rvs-isdn-dcp"    // RVS ISDN DCP
	ServiceMpfoncl         Service = "mpfoncl"         // mpfoncl
	ServiceTributary       Service = "tributary"       // Tributary
	ServiceArgisTe         Service = "argis-te"        // ARGIS TE
	ServiceArgisDs         Service = "argis-ds"        // ARGIS DS
	ServiceMon             Service = "mon"             // MON
	ServiceCyaserv         Service = "cyaserv"         // cyaserv
	ServiceNetxServer      Service = "netx-server"     // NETX Server
	ServiceNetxAgent       Service = "netx-agent"      // NETX Agent
	ServiceMasc            Service = "masc"            // MASC
	ServicePrivilege       Service = "privilege"       // Privilege
	ServiceQuartusTcl      Service = "quartus-tcl"     // quartus tcl
	ServiceIdotdist        Service = "idotdist"        // idotdist
	ServiceMaytagshuffle   Service = "maytagshuffle"   // Maytag Shuffle
	ServiceNetrek          Service = "netrek"          // netrek
	ServiceMnsMail         Service = "mns-mail"        // MNS Mail Notice Service
	ServiceDts             Service = "dts"             // Data Base Server
	ServiceWorldfusion1    Service = "worldfusion1"    // World Fusion 1
	ServiceWorldfusion2    Service = "worldfusion2"    // World Fusion 2
	ServiceHomesteadglory  Service = "homesteadglory"  // Homestead Glory
	ServiceCitriximaclient Service = "citriximaclient" // Citrix MA Client
	ServiceSnapd           Service = "snapd"           // Snap Discovery
	ServiceConnection      Service = "connection"      // Dell Connection
	ServiceWagService      Service = "wag-service"     // Wag Service
	ServiceSystemMonitor   Service = "system-monitor"  // System Monitor
	ServiceVersaTek        Service = "versa-tek"       // VersaTek
	ServiceLionhead        Service = "lionhead"        // LIONHEAD
	ServiceQpasaAgent      Service = "qpasa-agent"     // Qpasa Agent
	ServiceSmntubootstrap  Service = "smntubootstrap"  // SMNTUBootstrap
	ServiceNeveroffline    Service = "neveroffline"    // Never Offline
	ServiceFirepower       Service = "firepower"       // firepower
	ServiceAppswitchEmp    Service = "appswitch-emp"   // appswitch-emp
	ServiceCmadmin         Service = "cmadmin"         // Clinical Context Managers
	ServicePriorityECom    Service = "priority-e-com"  // Priority E-Com
	ServiceBruce           Service = "bruce"           // bruce
	ServiceLpsrecommender  Service = "lpsrecommender"  // LPSRecommender
	ServiceMilesApart      Service = "miles-apart"     // Miles Apart Jukebox Server
	ServiceMetricadbc      Service = "metricadbc"      // MetricaDBC
	ServiceLmdp            Service = "lmdp"            // LMDP
	ServiceAria            Service = "aria"            // Aria
	ServiceBlwnklPort      Service = "blwnkl-port"     // Blwnkl Port
	ServiceGbjd816         Service = "gbjd816"         // gbjd816
	ServiceMoshebeeri      Service = "moshebeeri"      // Moshe Beeri
	ServiceSitaraserver    Service = "sitaraserver"    // Sitara Server
	ServiceSitaramgmt      Service = "sitaramgmt"      // Sitara Management
	ServiceSitaradir       Service = "sitaradir"       // Sitara Dir
	ServiceIrdgPost        Service = "irdg-post"       // IRdg Post
	ServiceInterintelli    Service = "interintelli"    // InterIntelli
	ServicePkElectronics   Service = "pk-electronics"  // PK Electronics
	ServiceBackburner      Service = "backburner"      // Back Burner
	ServiceSolve           Service = "solve"           // Solve
	ServiceImdocsvc        Service = "imdocsvc"        // Import Document Service
	ServiceSybaseanywhere  Service = "sybaseanywhere"  // Sybase Anywhere
	ServiceAminet          Service = "aminet"          // AMInet
	ServiceSai_sentlm      Service = "sai_sentlm"      // Sabbagh Associates Licence Manager
	ServiceHdlSrv          Service = "hdl-srv"         // HDL Server
	ServiceTragic          Service = "tragic"          // Tragic
	ServiceGteSamp         Service = "gte-samp"        // GTE-SAMP
	ServiceTravsoftIpxT    Service = "travsoft-ipx-t"  // Travsoft IPX Tunnel
	ServiceNovellIpxCmd    Service = "novell-ipx-cmd"  // Novell IPX CMD
	ServiceAndLm           Service = "and-lm"          // AND License Manager
	ServiceSyncserver      Service = "syncserver"      // SyncServer
	ServiceUpsnotifyprot   Service = "upsnotifyprot"   // Upsnotifyprot
	ServiceVpsipport       Service = "vpsipport"       // VPSIPPORT
	ServiceEristwoguns     Service = "eristwoguns"     // eristwoguns
	ServiceEbinsite        Service = "ebinsite"        // EBInSite
	ServiceInterpathpanel  Service = "interpathpanel"  // InterPathPanel
	ServiceSonus           Service = "sonus"           // Sonus
	ServiceCorel_vncadmin  Service = "corel_vncadmin"  // Corel VNC Admin
	ServiceUnglue          Service = "unglue"          // UNIX Nt Glue
	ServiceKana            Service = "kana"            // Kana
	ServiceSnsDispatcher   Service = "sns-dispatcher"  // SNS Dispatcher
	ServiceSnsAdmin        Service = "sns-admin"       // SNS Admin
	ServiceSnsQuery        Service = "sns-query"       // SNS Query
	ServiceGcmonitor       Service = "gcmonitor"       // GC Monitor
	ServiceOlhost          Service = "olhost"          // OLHOST
	ServiceBintecCapi      Service = "bintec-capi"     // BinTec-CAPI
	ServiceBintecTapi      Service = "bintec-tapi"     // BinTec-TAPI
	ServicePatrolMqGm      Service = "patrol-mq-gm"    // Patrol for MQ GM
	ServicePatrolMqNm      Service = "patrol-mq-nm"    // Patrol for MQ NM
	ServiceExtensis        Service = "extensis"        // extensis
	ServiceAlarmClockS     Service = "alarm-clock-s"   // Alarm Clock Server
	ServiceAlarmClockC     Service = "alarm-clock-c"   // Alarm Clock Client
	ServiceToad            Service = "toad"            // TOAD
	ServiceTveAnnounce     Service = "tve-announce"    // TVE Announce
	ServiceNewlixreg       Service = "newlixreg"       // newlixreg
	ServiceNhserver        Service = "nhserver"        // nhserver
	ServiceFirstcall42     Service = "firstcall42"     // First Call 42
	ServiceEwnn            Service = "ewnn"            // ewnn
	ServiceTtcEtap         Service = "ttc-etap"        // TTC ETAP
	ServiceSimslink        Service = "simslink"        // SIMSLink
	ServiceGadgetgate1way  Service = "gadgetgate1way"  // Gadget Gate 1 Way
	ServiceGadgetgate2way  Service = "gadgetgate2way"  // Gadget Gate 2 Way
	ServiceSyncserverssl   Service = "syncserverssl"   // Sync Server SSL
	ServicePxcSapxom       Service = "pxc-sapxom"      // pxc-sapxom
	ServiceMpnjsomb        Service = "mpnjsomb"        // mpnjsomb
	ServiceNcdloadbalance  Service = "ncdloadbalance"  // NCDLoadBalance
	ServiceMpnjsosv        Service = "mpnjsosv"        // mpnjsosv
	ServiceMpnjsocl        Service = "mpnjsocl"        // mpnjsocl
	ServiceMpnjsomg        Service = "mpnjsomg"        // mpnjsomg
	ServicePqLicMgmt       Service = "pq-lic-mgmt"     // pq-lic-mgmt
	ServiceMdCgHttp        Service = "md-cg-http"      // md-cf-http
	ServiceFastlynx        Service = "fastlynx"        // FastLynx
	ServiceHpNnmData       Service = "hp-nnm-data"     // HP NNM Embedded Database
	ServiceItinternet      Service = "itinternet"      // ITInternet ISM Server
	ServiceAdminsLms       Service = "admins-lms"      // Admins LMS
	ServicePwrsevent       Service = "pwrsevent"       // pwrsevent
	ServiceVspread         Service = "vspread"         // VSPREAD
	ServiceUnifyadmin      Service = "unifyadmin"      // Unify Admin
	ServiceOceSnmpTrap     Service = "oce-snmp-trap"   // Oce SNMP Trap Port
	ServiceMckIvpip        Service = "mck-ivpip"       // MCK-IVPIP
	ServiceCsoftPlusclnt   Service = "csoft-plusclnt"  // Csoft Plus Client
	ServiceTqdata          Service = "tqdata"          // tqdata
	ServiceSmsRcinfo       Service = "sms-rcinfo"      // SMS RCINFO
	ServiceSmsXfer         Service = "sms-xfer"        // SMS XFER
	ServiceSmsChat         Service = "sms-chat"        // SMS CHAT
	ServiceSmsRemctrl      Service = "sms-remctrl"     // SMS REMCTRL
	ServiceSdsAdmin        Service = "sds-admin"       // SDS Admin
	ServiceNcdmirroring    Service = "ncdmirroring"    // NCD Mirroring
	ServiceEmcsymapiport   Service = "emcsymapiport"   // EMCSYMAPIPORT
	ServiceBanyanNet       Service = "banyan-net"      // Banyan-Net
	ServiceSupermon        Service = "supermon"        // Supermon
	ServiceSsoService      Service = "sso-service"     // SSO Service
	ServiceSsoControl      Service = "sso-control"     // SSO Control
	ServiceAocp            Service = "aocp"            // Axapta Object Communication Protocol
	ServiceRaventbs        Service = "raventbs"        // Raven Trinity Broker Service
	ServiceRaventdm        Service = "raventdm"        // Raven Trinity Data Mover
	ServiceHpstgmgr2       Service = "hpstgmgr2"       // HPSTGMGR2
	ServiceInovaIpDisco    Service = "inova-ip-disco"  // Inova IP Disco
	ServicePnRequester     Service = "pn-requester"    // PN REQUESTER
	ServicePnRequester2    Service = "pn-requester2"   // PN REQUESTER 2
	ServiceScanChange      Service = "scan-change"     // Scan & Change
	ServiceWkars           Service = "wkars"           // wkars
	ServiceSmartDiagnose   Service = "smart-diagnose"  // Smart Diagnose
	ServiceProactivesrvr   Service = "proactivesrvr"   // Proactive Server
	ServiceWatchdogNt      Service = "watchdog-nt"     // WatchDog NT Protocol
	ServiceQotps           Service = "qotps"           // qotps
	ServiceMsolapPtp2      Service = "msolap-ptp2"     // MSOLAP PTP2
	ServiceTams            Service = "tams"            // TAMS
	ServiceMgcpCallagent   Service = "mgcp-callagent"  // Media Gateway Control Protocol Call Agent
	ServiceSqdr            Service = "sqdr"            // SQDR
	ServiceTcimControl     Service = "tcim-control"    // TCIM Control
	ServiceNecRaidplus     Service = "nec-raidplus"    // NEC RaidPlus
	ServiceFyreMessanger   Service = "fyre-messanger"  // Fyre Messanger
	ServiceG5m             Service = "g5m"             // G5M
	ServiceSignetCtf       Service = "signet-ctf"      // Signet CTF
	ServiceCcsSoftware     Service = "ccs-software"    // CCS Software
	ServiceNetiqMc         Service = "netiq-mc"        // NetIQ Monitor Console
	ServiceRadwizNmsSrv    Service = "radwiz-nms-srv"  // RADWIZ NMS SRV
	ServiceSrpFeedback     Service = "srp-feedback"    // SRP Feedback
	ServiceNdlTcpOisGw     Service = "ndl-tcp-ois-gw"  // NDL TCP-OSI Gateway
	ServiceTnTiming        Service = "tn-timing"       // TN Timing
	ServiceAlarm           Service = "alarm"           // Alarm
	ServiceTsb             Service = "tsb"             // TSB
	ServiceTsb2            Service = "tsb2"            // TSB2
	ServiceMurx            Service = "murx"            // murx
	ServiceHonyaku         Service = "honyaku"         // honyaku
	ServiceUrbisnet        Service = "urbisnet"        // URBISNET
	ServiceCpudpencap      Service = "cpudpencap"      // CPUDPENCAP
	ServiceFjippolSwrly    Service = "fjippol-swrly"   //
	ServiceFjippolPolsvr   Service = "fjippol-polsvr"  //
	ServiceFjippolCnsl     Service = "fjippol-cnsl"    //
	ServiceFjippolPort1    Service = "fjippol-port1"   //
	ServiceFjippolPort2    Service = "fjippol-port2"   //
	ServiceRsisysaccess    Service = "rsisysaccess"    // RSISYS ACCESS
	ServiceDeSpot          Service = "de-spot"         // de-spot
	ServiceApolloCc        Service = "apollo-cc"       // APOLLO CC
	ServiceExpresspay      Service = "expresspay"      // Express Pay
	ServiceSimplementTie   Service = "simplement-tie"  // simplement-tie
	ServiceCnrp            Service = "cnrp"            // CNRP
	ServiceApolloStatus    Service = "apollo-status"   // APOLLO Status
	ServiceApolloGms       Service = "apollo-gms"      // APOLLO GMS
	ServiceSabams          Service = "sabams"          // Saba MS
	ServiceDicomIscl       Service = "dicom-iscl"      // DICOM ISCL
	ServiceDicomTls        Service = "dicom-tls"       // DICOM TLS
	ServiceDesktopDna      Service = "desktop-dna"     // Desktop DNA
	ServiceDataInsurance   Service = "data-insurance"  // Data Insurance
	ServiceQipAudup        Service = "qip-audup"       // qip-audup
	ServiceCompaqScp       Service = "compaq-scp"      // Compaq SCP
	ServiceUadtc           Service = "uadtc"           // UADTC
	ServiceUacs            Service = "uacs"            // UACS
	ServiceExce            Service = "exce"            // eXcE
	ServiceVeronica        Service = "veronica"        // Veronica
	ServiceVergencecm      Service = "vergencecm"      // Vergence CM
	ServiceAuris           Service = "auris"           // auris
	ServiceRbakcup1        Service = "rbakcup1"        // RBackup Remote Backup
	ServiceRbakcup2        Service = "rbakcup2"        // RBackup Remote Backup
	ServiceSmpp            Service = "smpp"            // SMPP
	ServiceRidgeway1       Service = "ridgeway1"       // Ridgeway Systems & Software
	ServiceRidgeway2       Service = "ridgeway2"       // Ridgeway Systems & Software
	ServiceGwenSonya       Service = "gwen-sonya"      // Gwen-Sonya
	ServiceLbcSync         Service = "lbc-sync"        // LBC Sync
	ServiceLbcControl      Service = "lbc-control"     // LBC Control
	ServiceWhosells        Service = "whosells"        // whosells
	ServiceEverydayrc      Service = "everydayrc"      // everydayrc
	ServiceAises           Service = "aises"           // AISES
	ServiceWwwDev          Service = "www-dev"         // world wide web - development
	ServiceAicNp           Service = "aic-np"          // aic-np
	ServiceAicOncrpc       Service = "aic-oncrpc"      // aic-oncrpc - Destiny MCD database
	ServicePiccolo         Service = "piccolo"         // piccolo - Cornerstone Software
	ServiceFryeserv        Service = "fryeserv"        // NetWare Loadable Module - Seagate Software
	ServiceMediaAgent      Service = "media-agent"     // Media Agent
	ServicePlgproxy        Service = "plgproxy"        // PLG Proxy
	ServiceMtportRegist    Service = "mtport-regist"   // MT Port Registrator
	ServiceF5Globalsite    Service = "f5-globalsite"   // f5-globalsite
	ServiceInitlsmsad      Service = "initlsmsad"      // initlsmsad
	ServiceLivestats       Service = "livestats"       // LiveStats
	ServiceAcTech          Service = "ac-tech"         // ac-tech
	ServiceEspEncap        Service = "esp-encap"       // esp-encap
	ServiceTmesisUpshot    Service = "tmesis-upshot"   // TMESIS-UPShot
	ServiceIconDiscover    Service = "icon-discover"   // ICON Discover
	ServiceAccRaid         Service = "acc-raid"        // ACC RAID
	ServiceIgcp            Service = "igcp"            // IGCP
	ServiceVeritasTcp1     Service = "veritas-tcp1"    // Veritas TCP1
	ServiceVeritasUdp1     Service = "veritas-udp1"    // Veritas UDP1
	ServiceBtprjctrl       Service = "btprjctrl"       // btprjctrl
	ServiceDvrEsm          Service = "dvr-esm"         // March Networks Digital Video Recorders and Enterprise Service Manager products
	ServiceWtaWspS         Service = "wta-wsp-s"       // WTA WSP-S
	ServiceCspuni          Service = "cspuni"          // cspuni
	ServiceCspmulti        Service = "cspmulti"        // cspmulti
	ServiceJLanP           Service = "j-lan-p"         // J-LAN-P
	ServiceNetsteward      Service = "netsteward"      // Active Net Steward
	ServiceGsiftp          Service = "gsiftp"          // GSI FTP
	ServiceAtmtcp          Service = "atmtcp"          // atmtcp
	ServiceLlmPass         Service = "llm-pass"        // llm-pass
	ServiceLlmCsv          Service = "llm-csv"         // llm-csv
	ServiceLbcMeasure      Service = "lbc-measure"     // LBC Measurement
	ServiceLbcWatchdog     Service = "lbc-watchdog"    // LBC Watchdog
	ServiceNmsigport       Service = "nmsigport"       // NMSig Port
	ServiceRmlnk           Service = "rmlnk"           // rmlnk
	ServiceFcFaultnotify   Service = "fc-faultnotify"  // FC Fault Notification
	ServiceUnivision       Service = "univision"       // UniVision
	ServiceVrtsAtPort      Service = "vrts-at-port"    // VERITAS Authentication Service
	ServiceKa0wuc          Service = "ka0wuc"          // ka0wuc
	ServiceCqgNetlan       Service = "cqg-netlan"      // CQG Net/LAN
	ServiceCqgNetlan1      Service = "cqg-netlan-1"    // CQG Net/LAN 1
	ServiceSlcSystemlog    Service = "slc-systemlog"   // slc systemlog
	ServiceSlcCtrlrloops   Service = "slc-ctrlrloops"  // slc ctrlrloops
	ServiceItmLm           Service = "itm-lm"          // ITM License Manager
	ServiceSilkp1          Service = "silkp1"          // silkp1
	ServiceSilkp2          Service = "silkp2"          // silkp2
	ServiceSilkp3          Service = "silkp3"          // silkp3
	ServiceSilkp4          Service = "silkp4"          // silkp4
	ServiceGlishd          Service = "glishd"          // glishd
	ServiceEvtp            Service = "evtp"            // EVTP
	ServiceEvtpData        Service = "evtp-data"       // EVTP-DATA
	ServiceCatalyst        Service = "catalyst"        // catalyst
	ServiceRepliweb        Service = "repliweb"        // Repliweb
	ServiceStarbot         Service = "starbot"         // Starbot
	ServiceL3Exprt         Service = "l3-exprt"        // l3-exprt
	ServiceL3Ranger        Service = "l3-ranger"       // l3-ranger
	ServiceL3Hawk          Service = "l3-hawk"         // l3-hawk
	ServicePdnet           Service = "pdnet"           // PDnet
	ServiceBpcpPoll        Service = "bpcp-poll"       // BPCP POLL
	ServiceBpcpTrap        Service = "bpcp-trap"       // BPCP TRAP
	ServiceAimppHello      Service = "aimpp-hello"     // AIMPP Hello
	ServiceAimppPortReq    Service = "aimpp-port-req"  // AIMPP Port Req
	ServiceAmtBlcPort      Service = "amt-blc-port"    // AMT-BLC-PORT
	ServiceMetaconsole     Service = "metaconsole"     // MetaConsole
	ServiceWebemshttp      Service = "webemshttp"      // webemshttp
	ServiceBears01         Service = "bears-01"        // bears-01
	ServiceIspipes         Service = "ispipes"         // ISPipes
	ServiceInfomover       Service = "infomover"       // InfoMover
	ServiceMsrp            Service = "msrp"            // MSRP over TCP
	ServiceCesdinv         Service = "cesdinv"         // cesdinv
	ServiceSimctlp         Service = "simctlp"         // SimCtIP
	ServiceEcnp            Service = "ecnp"            // ECNP
	ServiceActivememory    Service = "activememory"    // Active Memory
	ServiceDialpadVoice1   Service = "dialpad-voice1"  // Dialpad Voice 1
	ServiceDialpadVoice2   Service = "dialpad-voice2"  // Dialpad Voice 2
	ServiceTtgProtocol     Service = "ttg-protocol"    // TTG Protocol
	ServiceSonardata       Service = "sonardata"       // Sonar Data
	ServiceAstromedMain    Service = "astromed-main"   // main 5001 cmd
	ServicePitVpn          Service = "pit-vpn"         // pit-vpn
	ServiceIwlistener      Service = "iwlistener"      // iwlistener
	ServiceEspsPortal      Service = "esps-portal"     // esps-portal
	ServiceNpepMessaging   Service = "npep-messaging"  // NPEP Messaging
	ServiceIcslap          Service = "icslap"          // ICSLAP
	ServiceDaishi          Service = "daishi"          // daishi
	ServiceMsiSelectplay   Service = "msi-selectplay"  // MSI Select Play
	ServiceRadix           Service = "radix"           // RADIX
	ServiceDxmessagebase1  Service = "dxmessagebase1"  // DX Message Base Transport Protocol
	ServiceDxmessagebase2  Service = "dxmessagebase2"  // DX Message Base Transport Protocol
	ServiceSpsTunnel       Service = "sps-tunnel"      // SPS Tunnel
	ServiceBluelance       Service = "bluelance"       // BLUELANCE
	ServiceAap             Service = "aap"             // AAP
	ServiceUcentricDs      Service = "ucentric-ds"     // ucentric-ds
	ServiceSynapse         Service = "synapse"         // Synapse Transport
	ServiceNdsp            Service = "ndsp"            // NDSP
	ServiceNdtp            Service = "ndtp"            // NDTP
	ServiceNdnp            Service = "ndnp"            // NDNP
	ServiceFlashmsg        Service = "flashmsg"        // Flash Msg
	ServiceTopflow         Service = "topflow"         // TopFlow
	ServiceResponselogic   Service = "responselogic"   // RESPONSELOGIC
	ServiceAironetddp      Service = "aironetddp"      // aironet
	ServiceSpcsdlobby      Service = "spcsdlobby"      // SPCSDLOBBY
	ServiceRsom            Service = "rsom"            // RSOM
	ServiceCspclmulti      Service = "cspclmulti"      // CSPCLMULTI
	ServiceCinegrfxElmd    Service = "cinegrfx-elmd"   // CINEGRFX-ELMD License Manager
	ServiceSnifferdata     Service = "snifferdata"     // SNIFFERDATA
	ServiceVseconnector    Service = "vseconnector"    // VSECONNECTOR
	ServiceAbacusRemote    Service = "abacus-remote"   // ABACUS-REMOTE
	ServiceNatuslink       Service = "natuslink"       // NATUS LINK
	ServiceEcovisiong61    Service = "ecovisiong6-1"   // ECOVISIONG6-1
	ServiceCitrixRtmp      Service = "citrix-rtmp"     // Citrix RTMP
	ServiceApplianceCfg    Service = "appliance-cfg"   // APPLIANCE-CFG
	ServicePowergemplus    Service = "powergemplus"    // POWERGEMPLUS
	ServiceQuicksuite      Service = "quicksuite"      // QUICKSUITE
	ServiceAllstorcns      Service = "allstorcns"      // ALLSTORCNS
	ServiceNetaspi         Service = "netaspi"         // NET ASPI
	ServiceSuitcase        Service = "suitcase"        // SUITCASE
	ServiceM2ua            Service = "m2ua"            // M2UA
	ServiceM3ua            Service = "m3ua"            // M3UA
	ServiceCaller9         Service = "caller9"         // CALLER9
	ServiceWebmethodsB2b   Service = "webmethods-b2b"  // WEBMETHODS B2B
	ServiceMao             Service = "mao"             // mao
	ServiceFunkDialout     Service = "funk-dialout"    // Funk Dialout
	ServiceTdaccess        Service = "tdaccess"        // TDAccess
	ServiceBlockade        Service = "blockade"        // Blockade
	ServiceEpicon          Service = "epicon"          // Epicon
	ServiceBoosterware     Service = "boosterware"     // Booster Ware
	ServiceGamelobby       Service = "gamelobby"       // Game Lobby
	ServiceTksocket        Service = "tksocket"        // TK Socket
	ServiceElvin_server    Service = "elvin_server"    // Elvin Server
	ServiceElvin_client    Service = "elvin_client"    // Elvin Client
	ServiceKastenchasepad  Service = "kastenchasepad"  // Kasten Chase Pad
	ServiceRoboer          Service = "roboer"          // roboER
	ServiceRoboeda         Service = "roboeda"         // roboEDA
	ServiceCesdcdman       Service = "cesdcdman"       // CESD Contents Delivery Management
	ServiceCesdcdtrn       Service = "cesdcdtrn"       // CESD Contents Delivery Data Transfer
	ServiceWtaWspWtpS      Service = "wta-wsp-wtp-s"   // WTA-WSP-WTP-S
	ServicePreciseVip      Service = "precise-vip"     // PRECISE-VIP
	ServiceMobileFileDl    Service = "mobile-file-dl"  // MOBILE-FILE-DL
	ServiceUnimobilectrl   Service = "unimobilectrl"   // UNIMOBILECTRL
	ServiceRedstoneCpss    Service = "redstone-cpss"   // REDSTONE-CPSS
	ServiceAmxWebadmin     Service = "amx-webadmin"    // AMX-WEBADMIN
	ServiceAmxWeblinx      Service = "amx-weblinx"     // AMX-WEBLINX
	ServiceCircleX         Service = "circle-x"        // Circle-X
	ServiceIncp            Service = "incp"            // INCP
	Service4Tieropmgw      Service = "4-tieropmgw"     // 4-TIER OPM GW
	Service4Tieropmcli     Service = "4-tieropmcli"    // 4-TIER OPM CLI
	ServiceQtp             Service = "qtp"             // QTP
	ServiceOtpatch         Service = "otpatch"         // OTPatch
	ServicePnaconsultLm    Service = "pnaconsult-lm"   // PNACONSULT-LM
	ServiceSmPas1          Service = "sm-pas-1"        // SM-PAS-1
	ServiceSmPas2          Service = "sm-pas-2"        // SM-PAS-2
	ServiceSmPas3          Service = "sm-pas-3"        // SM-PAS-3
	ServiceSmPas4          Service = "sm-pas-4"        // SM-PAS-4
	ServiceSmPas5          Service = "sm-pas-5"        // SM-PAS-5
	ServiceTtnrepository   Service = "ttnrepository"   // TTNRepository
	ServiceMegacoH248      Service = "megaco-h248"     // Megaco H-248
	ServiceH248Binary      Service = "h248-binary"     // H248 Binary
	ServiceFjsvmpor        Service = "fjsvmpor"        // FJSVmpor
	ServiceGpsd            Service = "gpsd"            // GPSD
	ServiceWapPush         Service = "wap-push"        // WAP PUSH
	ServiceWapPushsecure   Service = "wap-pushsecure"  // WAP PUSH SECURE
	ServiceEsip            Service = "esip"            // ESIP
	ServiceOttp            Service = "ottp"            // OTTP
	ServiceMpfwsas         Service = "mpfwsas"         // MPFWSAS
	ServiceOvalarmsrv      Service = "ovalarmsrv"      // OVALARMSRV
	ServiceOvalarmsrvCmd   Service = "ovalarmsrv-cmd"  // OVALARMSRV-CMD
	ServiceCsnotify        Service = "csnotify"        // CSNOTIFY
	ServiceOvrimosdbman    Service = "ovrimosdbman"    // OVRIMOSDBMAN
	ServiceJmact5          Service = "jmact5"          // JAMCT5
	ServiceJmact6          Service = "jmact6"          // JAMCT6
	ServiceRmopagt         Service = "rmopagt"         // RMOPAGT
	ServiceDfoxserver      Service = "dfoxserver"      // DFOXSERVER
	ServiceBoldsoftLm      Service = "boldsoft-lm"     // BOLDSOFT-LM
	ServiceIphPolicyCli    Service = "iph-policy-cli"  // IPH-POLICY-CLI
	ServiceIphPolicyAdm    Service = "iph-policy-adm"  // IPH-POLICY-ADM
	ServiceBullantSrap     Service = "bullant-srap"    // BULLANT SRAP
	ServiceBullantRap      Service = "bullant-rap"     // BULLANT RAP
	ServiceIdpInfotrieve   Service = "idp-infotrieve"  // IDP-INFOTRIEVE
	ServiceSscAgent        Service = "ssc-agent"       // SSC-AGENT
	ServiceEnpp            Service = "enpp"            // ENPP
	ServiceEssp            Service = "essp"            // ESSP
	ServiceIndexNet        Service = "index-net"       // INDEX-NET
	ServiceNetclip         Service = "netclip"         // NetClip clipboard daemon
	ServicePmsmWebrctl     Service = "pmsm-webrctl"    // PMSM Webrctl
	ServiceSvnetworks      Service = "svnetworks"      // SV Networks
	ServiceSignal          Service = "signal"          // Signal
	ServiceFjmpcm          Service = "fjmpcm"          // Fujitsu Configuration Management Service
	ServiceCnsSrvPort      Service = "cns-srv-port"    // CNS Server Port
	ServiceTtcEtapNs       Service = "ttc-etap-ns"     // TTCs Enterprise Test Access Protocol - NS
	ServiceTtcEtapDs       Service = "ttc-etap-ds"     // TTCs Enterprise Test Access Protocol - DS
	ServiceH263Video       Service = "h263-video"      // H.263 Video Streaming
	ServiceWimd            Service = "wimd"            // Instant Messaging Service
	ServiceMylxamport      Service = "mylxamport"      // MYLXAMPORT
	ServiceIwbWhiteboard   Service = "iwb-whiteboard"  // IWB-WHITEBOARD
	ServiceNetplan         Service = "netplan"         // NETPLAN
	ServiceHpidsadmin      Service = "hpidsadmin"      // HPIDSADMIN
	ServiceHpidsagent      Service = "hpidsagent"      // HPIDSAGENT
	ServiceStonefalls      Service = "stonefalls"      // STONEFALLS
	ServiceIdentify        Service = "identify"        // identify
	ServiceZarkov          Service = "zarkov"          // ZARKOV Intelligent Agent Communication
	ServiceBoscap          Service = "boscap"          // BOSCAP
	ServiceWkstnMon        Service = "wkstn-mon"       // WKSTN-MON
	ServiceAvenyo          Service = "avenyo"          // Avenyo Server
	ServiceVeritasVis1     Service = "veritas-vis1"    // VERITAS VIS1
	ServiceVeritasVis2     Service = "veritas-vis2"    // VERITAS VIS2
	ServiceIdrs            Service = "idrs"            // IDRS
	ServiceVsixml          Service = "vsixml"          // vsixml
	ServiceRebol           Service = "rebol"           // REBOL
	ServiceRealsecure      Service = "realsecure"      // Real Secure
	ServiceRemotewareUn    Service = "remoteware-un"   // RemoteWare Unassigned
	ServiceHbci            Service = "hbci"            // HBCI
	ServiceOrigoNative     Service = "origo-native"    // OrigoDB Server Native
	ServiceExlmAgent       Service = "exlm-agent"      // EXLM Agent
	ServiceCgms            Service = "cgms"            // CGMS
	ServiceCsoftragent     Service = "csoftragent"     // Csoft Agent
	ServiceGeniuslm        Service = "geniuslm"        // Genius License Manager
	ServiceIiAdmin         Service = "ii-admin"        // Instant Internet Admin
	ServiceLotusmtap       Service = "lotusmtap"       // Lotus Mail Tracking Agent Protocol
	ServiceMidnightTech    Service = "midnight-tech"   // Midnight Technologies
	ServicePxcNtfy         Service = "pxc-ntfy"        // PXC-NTFY
	ServiceGw              Service = "gw"              // Telerate Workstation
	ServicePingPong        Service = "ping-pong"       // Telerate Workstation
	ServiceTrustedWeb      Service = "trusted-web"     // Trusted Web
	ServiceTwsdss          Service = "twsdss"          // Trusted Web Client
	ServiceGilatskysurfer  Service = "gilatskysurfer"  // Gilat Sky Surfer
	ServiceBroker_service  Service = "broker_service"  // Broker Service
	ServiceNatiDstp        Service = "nati-dstp"       // NATI DSTP
	ServiceNotify_srvr     Service = "notify_srvr"     // Notify Server
	ServiceEvent_listener  Service = "event_listener"  // Event Listener
	ServiceSrvc_registry   Service = "srvc_registry"   // Service Registry
	ServiceResource_mgr    Service = "resource_mgr"    // Resource Manager
	ServiceCifs            Service = "cifs"            // CIFS
	ServiceAgriserver      Service = "agriserver"      // AGRI Server
	ServiceCsregagent      Service = "csregagent"      // CSREGAGENT
	ServiceMagicnotes      Service = "magicnotes"      // magicnotes
	ServiceNds_sso         Service = "nds_sso"         // NDS_SSO
	ServiceArepaRaft       Service = "arepa-raft"      // Arepa Raft
	ServiceAgriGateway     Service = "agri-gateway"    // AGRI Gateway
	ServiceLiebDevMgmt_C   Service = "LiebDevMgmt_C"   // LiebDevMgmt_C
	ServiceLiebDevMgmt_DM  Service = "LiebDevMgmt_DM"  // LiebDevMgmt_DM
	ServiceLiebDevMgmt_A   Service = "LiebDevMgmt_A"   // LiebDevMgmt_A
	ServiceArepaCas        Service = "arepa-cas"       // Arepa Cas
	ServiceEppc            Service = "eppc"            // Remote AppleEvents/PPC Toolbox
	ServiceRedwoodChat     Service = "redwood-chat"    // Redwood Chat
	ServicePdb             Service = "pdb"             // PDB
	ServiceOsmosisAeea     Service = "osmosis-aeea"    // Osmosis / Helix (R) AEEA Port
	ServiceFjsvGssagt      Service = "fjsv-gssagt"     // FJSV gssagt
	ServiceHagelDump       Service = "hagel-dump"      // Hagel DUMP
	ServiceHpSanMgmt       Service = "hp-san-mgmt"     // HP SAN Mgmt
	ServiceSantakUps       Service = "santak-ups"      // Santak UPS
	ServiceCogitate        Service = "cogitate"        // Cogitate, Inc.
	ServiceTomatoSprings   Service = "tomato-springs"  // Tomato Springs
	ServiceDiTraceware     Service = "di-traceware"    // di-traceware
	ServiceJournee         Service = "journee"         // journee
	ServiceBrp             Service = "brp"             // Broadcast Routing Protocol
	ServiceResponsenet     Service = "responsenet"     // ResponseNet
	ServiceDiAse           Service = "di-ase"          // di-ase
	ServiceHlserver        Service = "hlserver"        // Fast Security HL Server
	ServicePctrader        Service = "pctrader"        // Sierra Net PC Trader
	ServiceNsws            Service = "nsws"            // NSWS
	ServiceGds_db          Service = "gds_db"          // gds_db
	ServiceGalaxyServer    Service = "galaxy-server"   // Galaxy Server
	ServiceApc3052         Service = "apc-3052"        // APC 3052
	ServiceDsomServer      Service = "dsom-server"     // dsom-server
	ServiceAmtCnfProt      Service = "amt-cnf-prot"    // AMT CNF PROT
	ServicePolicyserver    Service = "policyserver"    // Policy Server
	ServiceCdlServer       Service = "cdl-server"      // CDL Server
	ServiceGoaheadFldup    Service = "goahead-fldup"   // GoAhead FldUp
	ServiceVideobeans      Service = "videobeans"      // videobeans
	ServiceQsoft           Service = "qsoft"           // qsoft
	ServiceInterserver     Service = "interserver"     // interserver
	ServiceCautcpd         Service = "cautcpd"         // cautcpd
	ServiceNcacnIpTcp      Service = "ncacn-ip-tcp"    // ncacn-ip-tcp
	ServiceNcadgIpUdp      Service = "ncadg-ip-udp"    // ncadg-ip-udp
	ServiceRprt            Service = "rprt"            // Remote Port Redirector
	ServiceSlinterbase     Service = "slinterbase"     // slinterbase
	ServiceNetattachsdmp   Service = "netattachsdmp"   // NETATTACHSDMP
	ServiceFjhpjp          Service = "fjhpjp"          // FJHPJP
	ServiceLs3bcast        Service = "ls3bcast"        // ls3 Broadcast
	ServiceLs3             Service = "ls3"             // ls3
	ServiceMgxswitch       Service = "mgxswitch"       // MGXSWITCH
	ServiceCsdMgmtPort     Service = "csd-mgmt-port"   // ContinuStor Manager Port
	ServiceCsdMonitor      Service = "csd-monitor"     // ContinuStor Monitor Port
	ServiceVcrp            Service = "vcrp"            // Very simple chatroom prot
	ServiceXbox            Service = "xbox"            // Xbox game port
	ServiceOrbixLocator    Service = "orbix-locator"   // Orbix 2000 Locator
	ServiceOrbixConfig     Service = "orbix-config"    // Orbix 2000 Config
	ServiceOrbixLocSsl     Service = "orbix-loc-ssl"   // Orbix 2000 Locator SSL
	ServiceOrbixCfgSsl     Service = "orbix-cfg-ssl"   // Orbix 2000 Locator SSL
	ServiceLvFrontpanel    Service = "lv-frontpanel"   // LV Front Panel
	ServiceStm_pproc       Service = "stm_pproc"       // stm_pproc
	ServiceTl1Lv           Service = "tl1-lv"          // TL1-LV
	ServiceTl1Raw          Service = "tl1-raw"         // TL1-RAW
	ServiceTl1Telnet       Service = "tl1-telnet"      // TL1-TELNET
	ServiceItmMccs         Service = "itm-mccs"        // ITM-MCCS
	ServicePcihreq         Service = "pcihreq"         // PCIHReq
	ServiceJdlDbkitchen    Service = "jdl-dbkitchen"   // JDL-DBKitchen
	ServiceAsokiSma        Service = "asoki-sma"       // Asoki SMA
	ServiceXdtp            Service = "xdtp"            // eXtensible Data Transfer Protocol
	ServicePtkAlink        Service = "ptk-alink"       // ParaTek Agent Linking
	ServiceStss            Service = "stss"            // Senforce Session Services
	Service1ciSmcs         Service = "1ci-smcs"        // 1Ci Server Management
	ServiceRapidmqCenter   Service = "rapidmq-center"  // Jiiva RapidMQ Center
	ServiceRapidmqReg      Service = "rapidmq-reg"     // Jiiva RapidMQ Registry
	ServicePanasas         Service = "panasas"         // Panasas rendevous port
	ServiceNdlAps          Service = "ndl-aps"         // Active Print Server Port
	ServiceItuBiccStc      Service = "itu-bicc-stc"    // ITU-T Q.1902.1/Q.2150.3
	ServiceUmmPort         Service = "umm-port"        // Universal Message Manager
	ServiceChmd            Service = "chmd"            // CHIPSY Machine Daemon
	ServiceOpconXps        Service = "opcon-xps"       // OpCon/xps
	ServiceHpPxpib         Service = "hp-pxpib"        // HP PolicyXpert PIB Server
	ServiceSlslavemon      Service = "slslavemon"      // SoftlinK Slave Mon Port
	ServiceAutocuesmi      Service = "autocuesmi"      // Autocue SMI Protocol
	ServiceAutocuelog      Service = "autocuelog"      // Autocue Logger Protocol
	ServiceAutocuetime     Service = "autocuetime"     // Autocue Time Service
	ServiceCardbox         Service = "cardbox"         // Cardbox
	ServiceCardboxHttp     Service = "cardbox-http"    // Cardbox HTTP
	ServiceBusiness        Service = "business"        // Business protocol
	ServiceGeolocate       Service = "geolocate"       // Geolocate protocol
	ServicePersonnel       Service = "personnel"       // Personnel protocol
	ServiceSimControl      Service = "sim-control"     // simulator control port
	ServiceWsynch          Service = "wsynch"          // Web Synchronous Services
	ServiceKsysguard       Service = "ksysguard"       // KDE System Guard
	ServiceCsAuthSvr       Service = "cs-auth-svr"     // CS-Authenticate Svr Port
	ServiceCcmad           Service = "ccmad"           // CCM AutoDiscover
	ServiceMctetMaster     Service = "mctet-master"    // MCTET Master
	ServiceMctetGateway    Service = "mctet-gateway"   // MCTET Gateway
	ServiceMctetJserv      Service = "mctet-jserv"     // MCTET Jserv
	ServicePkagent         Service = "pkagent"         // PKAgent
	ServiceD2000kernel     Service = "d2000kernel"     // D2000 Kernel Port
	ServiceD2000webserver  Service = "d2000webserver"  // D2000 Webserver Port
	ServicePcmkRemote      Service = "pcmk-remote"     // pacemaker remote service
	ServiceVtrEmulator     Service = "vtr-emulator"    // MTI VTR Emulator port
	ServiceEdix            Service = "edix"            // EDI Translation Protocol
	ServiceBeaconPort      Service = "beacon-port"     // Beacon Port
	ServiceA13An           Service = "a13-an"          // A13-AN Interface
	ServiceCtxBridge       Service = "ctx-bridge"      // CTX Bridge Port
	ServiceNdlAas          Service = "ndl-aas"         // Active API Server Port
	ServiceNetportId       Service = "netport-id"      // NetPort Discovery Port
	ServiceNetbookmark     Service = "netbookmark"     // Net Book Mark
	ServiceMsRuleEngine    Service = "ms-rule-engine"  // Microsoft Business Rule Engine Update Service
	ServicePrismDeploy     Service = "prism-deploy"    // Prism Deploy User Port
	ServiceEcp             Service = "ecp"             // Extensible Code Protocol
	ServicePeerbookPort    Service = "peerbook-port"   // PeerBook Port
	ServiceGrubd           Service = "grubd"           // Grub Server Port
	ServiceRtnt1           Service = "rtnt-1"          // rtnt-1 data packets
	ServiceRtnt2           Service = "rtnt-2"          // rtnt-2 data packets
	ServiceIncognitorv     Service = "incognitorv"     // Incognito Rendez-Vous
	ServiceAriliamulti     Service = "ariliamulti"     // Arilia Multiplexor
	ServiceVmodem          Service = "vmodem"          // VMODEM
	ServiceRdcWhEos        Service = "rdc-wh-eos"      // RDC WH EOS
	ServiceSeaview         Service = "seaview"         // Sea View
	ServiceTarantella      Service = "tarantella"      // Tarantella
	ServiceCsiLfap         Service = "csi-lfap"        // CSI-LFAP
	ServiceBears02         Service = "bears-02"        // bears-02
	ServiceRfio            Service = "rfio"            // RFIO
	ServiceNmGameAdmin     Service = "nm-game-admin"   // NetMike Game Administrator
	ServiceNmGameServer    Service = "nm-game-server"  // NetMike Game Server
	ServiceNmAssesAdmin    Service = "nm-asses-admin"  // NetMike Assessor Administrator
	ServiceNmAssessor      Service = "nm-assessor"     // NetMike Assessor
	ServiceFeitianrockey   Service = "feitianrockey"   // FeiTian Port
	ServiceS8ClientPort    Service = "s8-client-port"  // S8Cargo Client Port
	ServiceCcmrmi          Service = "ccmrmi"          // ON RMI Registry
	ServiceJpegmpeg        Service = "jpegmpeg"        // JpegMpeg Port
	ServiceIndura          Service = "indura"          // Indura Collector
	ServiceE3consultants   Service = "e3consultants"   // CCC Listener Port
	ServiceStvp            Service = "stvp"            // SmashTV Protocol
	ServiceNavegawebPort   Service = "navegaweb-port"  // NavegaWeb Tarification
	ServiceTipAppServer    Service = "tip-app-server"  // TIP Application Server
	ServiceDoc1lm          Service = "doc1lm"          // DOC1 License Manager
	ServiceSflm            Service = "sflm"            // SFLM
	ServiceResSap          Service = "res-sap"         // RES-SAP
	ServiceImprs           Service = "imprs"           // IMPRS
	ServiceNewgenpay       Service = "newgenpay"       // Newgenpay Engine Service
	ServiceSossecollector  Service = "sossecollector"  // Quest Spotlight Out-Of-Process Collector
	ServiceNowcontact      Service = "nowcontact"      // Now Contact Public Server
	ServicePoweronnud      Service = "poweronnud"      // Now Up-to-Date Public Server
	ServiceServerviewAs    Service = "serverview-as"   // SERVERVIEW-AS
	ServiceServerviewAsn   Service = "serverview-asn"  // SERVERVIEW-ASN
	ServiceServerviewGf    Service = "serverview-gf"   // SERVERVIEW-GF
	ServiceServerviewRm    Service = "serverview-rm"   // SERVERVIEW-RM
	ServiceServerviewIcc   Service = "serverview-icc"  // SERVERVIEW-ICC
	ServiceArmiServer      Service = "armi-server"     // ARMI Server
	ServiceT1E1OverIp      Service = "t1-e1-over-ip"   // T1_E1_Over_IP
	ServiceArsMaster       Service = "ars-master"      // ARS Master
	ServicePhonexPort      Service = "phonex-port"     // Phonex Protocol
	ServiceRadclientport   Service = "radclientport"   // Radiance UltraEdge Port
	ServiceH2gfW2m         Service = "h2gf-w-2m"       // H2GF W.2m Handover prot.
	ServiceMcBrkSrv        Service = "mc-brk-srv"      // Millicent Broker Server
	ServiceBmcpatrolagent  Service = "bmcpatrolagent"  // BMC Patrol Agent
	ServiceBmcpatrolrnvu   Service = "bmcpatrolrnvu"   // BMC Patrol Rendezvous
	ServiceCopsTls         Service = "cops-tls"        // COPS/TLS
	ServiceApogeexPort     Service = "apogeex-port"    // ApogeeX Port
	ServiceSmpppd          Service = "smpppd"          // SuSE Meta PPPD
	ServiceIiwPort         Service = "iiw-port"        // IIW Monitor User Port
	ServiceOdiPort         Service = "odi-port"        // Open Design Listen Port
	ServiceBrcmCommPort    Service = "brcm-comm-port"  // Broadcom Port
	ServicePcleInfex       Service = "pcle-infex"      // Pinnacle Sys InfEx Port
	ServiceCsvrProxy       Service = "csvr-proxy"      // ConServR Proxy
	ServiceCsvrSslproxy    Service = "csvr-sslproxy"   // ConServR SSL Proxy
	ServiceFiremonrcc      Service = "firemonrcc"      // FireMon Revision Control
	ServiceSpandataport    Service = "spandataport"    // SpanDataPort
	ServiceMagbind         Service = "magbind"         // Rockstorm MAG protocol
	ServiceNcu1            Service = "ncu-1"           // Network Control Unit
	ServiceNcu2            Service = "ncu-2"           // Network Control Unit
	ServiceEmbraceDpS      Service = "embrace-dp-s"    // Embrace Device Protocol Server
	ServiceEmbraceDpC      Service = "embrace-dp-c"    // Embrace Device Protocol Client
	ServiceDmodWorkspace   Service = "dmod-workspace"  // DMOD WorkSpace
	ServiceTickPort        Service = "tick-port"       // Press-sense Tick Port
	ServiceCpqTasksmart    Service = "cpq-tasksmart"   // CPQ-TaskSmart
	ServiceIntraintra      Service = "intraintra"      // IntraIntra
	ServiceNetwatcherMon   Service = "netwatcher-mon"  // Network Watcher Monitor
	ServiceNetwatcherDb    Service = "netwatcher-db"   // Network Watcher DB Access
	ServiceIsns            Service = "isns"            // iSNS Server Port
	ServiceIronmail        Service = "ironmail"        // IronMail POP Proxy
	ServiceVxAuthPort      Service = "vx-auth-port"    // Veritas Authentication Port
	ServicePfuPrcallback   Service = "pfu-prcallback"  // PFU PR Callback
	ServiceNetwkpathengine Service = "netwkpathengine" // HP OpenView Network Path Engine Server
	ServiceFlamencoProxy   Service = "flamenco-proxy"  // Flamenco Networks Proxy
	ServiceAvsecuremgmt    Service = "avsecuremgmt"    // Avocent Secure Management
	ServiceSurveyinst      Service = "surveyinst"      // Survey Instrument
	ServiceNeon24x7        Service = "neon24x7"        // NEON 24X7 Mission Control
	ServiceJmqDaemon1      Service = "jmq-daemon-1"    // JMQ Daemon Port 1
	ServiceJmqDaemon2      Service = "jmq-daemon-2"    // JMQ Daemon Port 2
	ServiceFerrariFoam     Service = "ferrari-foam"    // Ferrari electronic FOAM
	ServiceUnite           Service = "unite"           // Unified IP & Telecomm Environment
	ServiceSmartpackets    Service = "smartpackets"    // EMC SmartPackets
	ServiceWmsMessenger    Service = "wms-messenger"   // WMS Messenger
	ServiceXnmSsl          Service = "xnm-ssl"         // XML NM over SSL
	ServiceXnmClearText    Service = "xnm-clear-text"  // XML NM over TCP
	ServiceGlbp            Service = "glbp"            // Gateway Load Balancing Pr
	ServiceDigivote        Service = "digivote"        // DIGIVOTE (R) Vote-Server
	ServiceAesDiscovery    Service = "aes-discovery"   // AES Discovery Port
	ServiceFcipPort        Service = "fcip-port"       // FCIP
	ServiceIsiIrp          Service = "isi-irp"         // ISI Industry Software IRP
	ServiceDwnmshttp       Service = "dwnmshttp"       // DiamondWave NMS Server
	ServiceDwmsgserver     Service = "dwmsgserver"     // DiamondWave MSG Server
	ServiceGlobalCdPort    Service = "global-cd-port"  // Global CD Port
	ServiceSftdstPort      Service = "sftdst-port"     // Software Distributor Port
	ServiceVidigo          Service = "vidigo"          // VidiGo communication
	ServiceMdtp            Service = "mdtp"            // MDT port
	ServiceWhisker         Service = "whisker"         // WhiskerControl main port
	ServiceAlchemy         Service = "alchemy"         // Alchemy Server
	ServiceMdapPort        Service = "mdap-port"       // MDAP port
	ServiceApparenetTs     Service = "apparenet-ts"    // appareNet Test Server
	ServiceApparenetTps    Service = "apparenet-tps"   // appareNet Test Packet Sequencer
	ServiceApparenetAs     Service = "apparenet-as"    // appareNet Analysis Server
	ServiceApparenetUi     Service = "apparenet-ui"    // appareNet User Interface
	ServiceTriomotion      Service = "triomotion"      // Trio Motion Control Port
	ServiceSysorb          Service = "sysorb"          // SysOrb Monitoring Server
	ServiceSdpIdPort       Service = "sdp-id-port"     // Session Description ID
	ServiceTimelot         Service = "timelot"         // Timelot Port
	ServiceOnesaf          Service = "onesaf"          // OneSAF
	ServiceVieoFe          Service = "vieo-fe"         // VIEO Fabric Executive
	ServiceDvtSystem       Service = "dvt-system"      // DVT SYSTEM PORT
	ServiceDvtData         Service = "dvt-data"        // DVT DATA LINK
	ServiceProcosLm        Service = "procos-lm"       // PROCOS LM
	ServiceSsp             Service = "ssp"             // State Sync Protocol
	ServiceHicp            Service = "hicp"            // HMS hicp port
	ServiceSysscanner      Service = "sysscanner"      // Sys Scanner
	ServiceDhe             Service = "dhe"             // DHE port
	ServicePdaData         Service = "pda-data"        // PDA Data
	ServicePdaSys          Service = "pda-sys"         // PDA System
	ServiceSemaphore       Service = "semaphore"       // Semaphore Connection Port
	ServiceCpqrpmAgent     Service = "cpqrpm-agent"    // Compaq RPM Agent Port
	ServiceCpqrpmServer    Service = "cpqrpm-server"   // Compaq RPM Server Port
	ServiceIveconPort      Service = "ivecon-port"     // Ivecon Server Port
	ServiceEpncdp2         Service = "epncdp2"         // Epson Network Common Devi
	ServiceIscsiTarget     Service = "iscsi-target"    // iSCSI port
	ServiceWinshadow       Service = "winshadow"       // winShadow
	ServiceNecp            Service = "necp"            // NECP
	ServiceEcolorImager    Service = "ecolor-imager"   // E-Color Enterprise Imager
	ServiceCcmail          Service = "ccmail"          // cc:mail/lotus
	ServiceAltavTunnel     Service = "altav-tunnel"    // Altav Tunnel
	ServiceNsCfgServer     Service = "ns-cfg-server"   // NS CFG Server
	ServiceIbmDialOut      Service = "ibm-dial-out"    // IBM Dial Out
	ServiceMsftGc          Service = "msft-gc"         // Microsoft Global Catalog
	ServiceMsftGcSsl       Service = "msft-gc-ssl"     // Microsoft Global Catalog with LDAP/SSL
	ServiceVerismart       Service = "verismart"       // Verismart
	ServiceCsoftPrev       Service = "csoft-prev"      // CSoft Prev Port
	ServiceUserManager     Service = "user-manager"    // Fujitsu User Manager
	ServiceSxmp            Service = "sxmp"            // Simple Extensible Multiplexed Protocol
	ServiceOrdinoxServer   Service = "ordinox-server"  // Ordinox Server
	ServiceSamd            Service = "samd"            // SAMD
	ServiceMaximAsics      Service = "maxim-asics"     // Maxim ASICs
	ServiceAwgProxy        Service = "awg-proxy"       // AWG Proxy
	ServiceLkcmserver      Service = "lkcmserver"      // LKCM Server
	ServiceAdmind          Service = "admind"          // admind
	ServiceVsServer        Service = "vs-server"       // VS Server
	ServiceSysopt          Service = "sysopt"          // SYSOPT
	ServiceDatusorb        Service = "datusorb"        // Datusorb
	ServiceNetAssistant    Service = "net-assistant"   // Apple Remote Desktop - Net Assistant
	Service4talk           Service = "4talk"           // 4Talk
	ServicePlato           Service = "plato"           // Plato
	ServiceENet            Service = "e-net"           // E-Net
	ServiceDirectvdata     Service = "directvdata"     // DIRECTVDATA
	ServiceCops            Service = "cops"            // COPS
	ServiceEnpc            Service = "enpc"            // ENPC
	ServiceCapsLm          Service = "caps-lm"         // CAPS LOGISTICS TOOLKIT - LM
	ServiceSahLm           Service = "sah-lm"          // S A Holditch & Associates - LM
	ServiceCartORama       Service = "cart-o-rama"     // Cart O Rama
	ServiceFgFps           Service = "fg-fps"          // fg-fps
	ServiceFgGip           Service = "fg-gip"          // fg-gip
	ServiceDyniplookup     Service = "dyniplookup"     // Dynamic IP Lookup
	ServiceRibSlm          Service = "rib-slm"         // Rib License Manager
	ServiceCytelLm         Service = "cytel-lm"        // Cytel License Manager
	ServiceDeskview        Service = "deskview"        // DeskView
	ServicePdrncs          Service = "pdrncs"          // pdrncs
	ServiceMcsFastmail     Service = "mcs-fastmail"    // MCS Fastmail
	ServiceOpsessionClnt   Service = "opsession-clnt"  // OP Session Client
	ServiceOpsessionSrvr   Service = "opsession-srvr"  // OP Session Server
	ServiceOdetteFtp       Service = "odette-ftp"      // ODETTE-FTP
	ServiceOpsessionPrxy   Service = "opsession-prxy"  // OP Session Proxy
	ServiceTnsServer       Service = "tns-server"      // TNS Server
	ServiceTnsAdv          Service = "tns-adv"         // TNS ADV
	ServiceDynaAccess      Service = "dyna-access"     // Dyna Access
	ServiceMcnsTelRet      Service = "mcns-tel-ret"    // MCNS Tel Ret
	ServiceAppmanServer    Service = "appman-server"   // Application Management Server
	ServiceUorb            Service = "uorb"            // Unify Object Broker
	ServiceUohost          Service = "uohost"          // Unify Object Host
	ServiceCdid            Service = "cdid"            // CDID
	ServiceAiccCmi         Service = "aicc-cmi"        // AICC/CMI
	ServiceVsaiport        Service = "vsaiport"        // VSAI PORT
	ServiceSsrip           Service = "ssrip"           // Swith to Swith Routing Information Protocol
	ServiceSdtLmd          Service = "sdt-lmd"         // SDT License Manager
	ServiceOfficelink2000  Service = "officelink2000"  // Office Link 2000
	ServiceVnsstr          Service = "vnsstr"          // VNSSTR
	ServiceSftu            Service = "sftu"            // SFTU
	ServiceBbars           Service = "bbars"           // BBARS
	ServiceEgptlm          Service = "egptlm"          // Eaglepoint License Manager
	ServiceHpDeviceDisc    Service = "hp-device-disc"  // HP Device Disc
	ServiceMcsCalypsoicf   Service = "mcs-calypsoicf"  // MCS Calypso ICF
	ServiceMcsMessaging    Service = "mcs-messaging"   // MCS Messaging
	ServiceMcsMailsvr      Service = "mcs-mailsvr"     // MCS Mail Server
	ServiceDecNotes        Service = "dec-notes"       // DEC Notes
	ServiceDirectvWeb      Service = "directv-web"     // Direct TV Webcasting
	ServiceDirectvSoft     Service = "directv-soft"    // Direct TV Software Updates
	ServiceDirectvTick     Service = "directv-tick"    // Direct TV Tickers
	ServiceDirectvCatlg    Service = "directv-catlg"   // Direct TV Data Catalog
	ServiceAnetB           Service = "anet-b"          // OMF data b
	ServiceAnetL           Service = "anet-l"          // OMF data l
	ServiceAnetM           Service = "anet-m"          // OMF data m
	ServiceAnetH           Service = "anet-h"          // OMF data h
	ServiceWebtie          Service = "webtie"          // WebTIE
	ServiceMsClusterNet    Service = "ms-cluster-net"  // MS Cluster Net
	ServiceBntManager      Service = "bnt-manager"     // BNT Manager
	ServiceInfluence       Service = "influence"       // Influence
	ServicePhoenixRpc      Service = "phoenix-rpc"     // Phoenix RPC
	ServicePangolinLaser   Service = "pangolin-laser"  // Pangolin Laser
	ServiceChevinservices  Service = "chevinservices"  // Chevin Services
	ServiceFindviatv       Service = "findviatv"       // FINDVIATV
	ServiceBtrieve         Service = "btrieve"         // Btrieve port
	ServiceSsql            Service = "ssql"            // Scalable SQL
	ServiceFatpipe         Service = "fatpipe"         // FATPIPE
	ServiceSuitjd          Service = "suitjd"          // SUITJD
	ServiceOrdinoxDbase    Service = "ordinox-dbase"   // Ordinox Dbase
	ServiceUpnotifyps      Service = "upnotifyps"      // UPNOTIFYPS
	ServiceAdtechTest      Service = "adtech-test"     // Adtech Test IP
	ServiceMpsysrmsvr      Service = "mpsysrmsvr"      // Mp Sys Rmsvr
	ServiceWgNetforce      Service = "wg-netforce"     // WG NetForce
	ServiceKvServer        Service = "kv-server"       // KV Server
	ServiceKvAgent         Service = "kv-agent"        // KV Agent
	ServiceDjIlm           Service = "dj-ilm"          // DJ ILM
	ServiceNatiViServer    Service = "nati-vi-server"  // NATI Vi Server
	ServiceTip2            Service = "tip2"            // TIP 2
	ServiceLavenirLm       Service = "lavenir-lm"      // Lavenir License Manager
	ServiceClusterDisc     Service = "cluster-disc"    // Cluster Disc
	ServiceVsnmAgent       Service = "vsnm-agent"      // VSNM Agent
	ServiceCdbroker        Service = "cdbroker"        // CD Broker
	ServiceCogsysLm        Service = "cogsys-lm"       // Cogsys Network License Manager
	ServiceWsicopy         Service = "wsicopy"         // WSICOPY
	ServiceSocorfs         Service = "socorfs"         // SOCORFS
	ServiceSnsChannels     Service = "sns-channels"    // SNS Channels
	ServiceGeneous         Service = "geneous"         // Geneous
	ServiceFujitsuNeat     Service = "fujitsu-neat"    // Fujitsu Network Enhanced Antitheft function
	ServiceEspLm           Service = "esp-lm"          // Enterprise Software Products License Manager
	ServiceHpClic          Service = "hp-clic"         // Cluster Management Services
	ServiceQnxnetman       Service = "qnxnetman"       // qnxnetman
	ServiceGprsData        Service = "gprs-data"       // GPRS Data
	ServiceGprsSig         Service = "gprs-sig"        // GPRS SIG
	ServiceBackroomnet     Service = "backroomnet"     // Back Room Net
	ServiceCbserver        Service = "cbserver"        // CB Server
	ServiceMsWbtServer     Service = "ms-wbt-server"   // MS WBT Server
	ServiceDsc             Service = "dsc"             // Distributed Service Coordinator
	ServiceSavant          Service = "savant"          // SAVANT
	ServiceEfiLm           Service = "efi-lm"          // EFI License Management
	ServiceD2kTapestry1    Service = "d2k-tapestry1"   // D2K Tapestry Client to Server
	ServiceD2kTapestry2    Service = "d2k-tapestry2"   // D2K Tapestry Server to Server
	ServiceDynaLm          Service = "dyna-lm"         // Dyna License Manager (Elam)
	ServicePrinter_agent   Service = "printer_agent"   // Printer Agent
	ServiceCloantoLm       Service = "cloanto-lm"      // Cloanto License Manager
	ServiceMercantile      Service = "mercantile"      // Mercantile
	ServiceCsms            Service = "csms"            // CSMS
	ServiceCsms2           Service = "csms2"           // CSMS2
	ServiceFilecast        Service = "filecast"        // filecast
	ServiceFxaengineNet    Service = "fxaengine-net"   // FXa Engine Network Port
	ServiceNokiaAnnCh1     Service = "nokia-ann-ch1"   // Nokia Announcement ch 1
	ServiceNokiaAnnCh2     Service = "nokia-ann-ch2"   // Nokia Announcement ch 2
	ServiceLdapAdmin       Service = "ldap-admin"      // LDAP admin server port
	ServiceBESApi          Service = "BESApi"          // BES Api Port
	ServiceNetworklens     Service = "networklens"     // NetworkLens Event Port
	ServiceNetworklenss    Service = "networklenss"    // NetworkLens SSL Event
	ServiceBiolinkAuth     Service = "biolink-auth"    // BioLink Authenteon server
	ServiceXmlblaster      Service = "xmlblaster"      // xmlBlaster
	ServiceSvnet           Service = "svnet"           // SpecView Networking
	ServiceWipPort         Service = "wip-port"        // BroadCloud WIP Port
	ServiceBcinameservice  Service = "bcinameservice"  // BCI Name Service
	ServiceCommandport     Service = "commandport"     // AirMobile IS Command Port
	ServiceCsvr            Service = "csvr"            // ConServR file translation
	ServiceRnmap           Service = "rnmap"           // Remote nmap
	ServiceSoftaudit       Service = "softaudit"       // Isogon SoftAudit
	ServiceIfcpPort        Service = "ifcp-port"       // iFCP User Port
	ServiceBmap            Service = "bmap"            // Bull Apprise portmapper
	ServiceRusbSysPort     Service = "rusb-sys-port"   // Remote USB System Port
	ServiceXtrm            Service = "xtrm"            // xTrade Reliable Messaging
	ServiceXtrms           Service = "xtrms"           // xTrade over TLS/SSL
	ServiceAgpsPort        Service = "agps-port"       // AGPS Access Port
	ServiceArkivio         Service = "arkivio"         // Arkivio Storage Protocol
	ServiceWebsphereSnmp   Service = "websphere-snmp"  // WebSphere SNMP
	ServiceTwcss           Service = "twcss"           // 2Wire CSS
	ServiceGcsp            Service = "gcsp"            // GCSP user port
	ServiceSsdispatch      Service = "ssdispatch"      // Scott Studios Dispatch
	ServiceNdlAls          Service = "ndl-als"         // Active License Server Port
	ServiceOsdcp           Service = "osdcp"           // Secure Device Protocol
	ServiceOpnetSmp        Service = "opnet-smp"       // OPNET Service Management Platform
	ServiceOpencm          Service = "opencm"          // OpenCM Server
	ServicePacom           Service = "pacom"           // Pacom Security User Port
	ServiceGcConfig        Service = "gc-config"       // GuardControl Exchange Protocol
	ServiceAutocueds       Service = "autocueds"       // Autocue Directory Service
	ServiceSpiralAdmin     Service = "spiral-admin"    // Spiralcraft Admin
	ServiceHriPort         Service = "hri-port"        // HRI Interface Port
	ServiceAnsConsole      Service = "ans-console"     // Net Steward Mgmt Console
	ServiceConnectClient   Service = "connect-client"  // OC Connect Client
	ServiceConnectServer   Service = "connect-server"  // OC Connect Server
	ServiceOvNnmWebsrv     Service = "ov-nnm-websrv"   // OpenView Network Node Manager WEB Server
	ServiceDenaliServer    Service = "denali-server"   // Denali Server
	ServiceMonp            Service = "monp"            // Media Object Network
	Service3comfaxrpc      Service = "3comfaxrpc"      // 3Com FAX RPC port
	ServiceDirectnet       Service = "directnet"       // DirectNet IM System
	ServiceDncPort         Service = "dnc-port"        // Discovery and Net Config
	ServiceHotuChat        Service = "hotu-chat"       // HotU Chat
	ServiceCastorproxy     Service = "castorproxy"     // CAStorProxy
	ServiceAsam            Service = "asam"            // ASAM Services
	ServiceSabpSignal      Service = "sabp-signal"     // SABP-Signalling Protocol
	ServicePscupd          Service = "pscupd"          // PSC Update Port
	ServiceMira            Service = "mira"            // Apple Remote Access Protocol
	ServiceVat             Service = "vat"             // VAT default data
	ServiceVatControl      Service = "vat-control"     // VAT default control
	ServiceD3winosfi       Service = "d3winosfi"       // D3WinOSFI
	ServiceIntegral        Service = "integral"        // TIP Integral
	ServiceEdmManager      Service = "edm-manager"     // EDM Manger
	ServiceEdmStager       Service = "edm-stager"      // EDM Stager
	ServiceEdmStdNotify    Service = "edm-std-notify"  // EDM STD Notify
	ServiceEdmAdmNotify    Service = "edm-adm-notify"  // EDM ADM Notify
	ServiceEdmMgrSync      Service = "edm-mgr-sync"    // EDM MGR Sync
	ServiceEdmMgrCntrl     Service = "edm-mgr-cntrl"   // EDM MGR Cntrl
	ServiceWorkflow        Service = "workflow"        // WORKFLOW
	ServiceRcst            Service = "rcst"            // RCST
	ServiceTtcmremotectrl  Service = "ttcmremotectrl"  // TTCM Remote Controll
	ServicePluribus        Service = "pluribus"        // Pluribus
	ServiceJt400           Service = "jt400"           // jt400
	ServiceJt400Ssl        Service = "jt400-ssl"       // jt400-ssl
	ServiceJaugsremotec1   Service = "jaugsremotec-1"  // JAUGS N-G Remotec 1
	ServiceJaugsremotec2   Service = "jaugsremotec-2"  // JAUGS N-G Remotec 2
	ServiceTtntspauto      Service = "ttntspauto"      // TSP Automation
	ServiceGenisarPort     Service = "genisar-port"    // Genisar Comm Port
	ServiceNppmp           Service = "nppmp"           // NVIDIA Mgmt Protocol
	ServiceEcomm           Service = "ecomm"           // eComm link port
	ServiceStun            Service = "stun"            // Session Traversal Utilities for NAT (STUN) port, TURN over TCP
	ServiceTwrpc           Service = "twrpc"           // 2Wire RPC
	ServicePlethora        Service = "plethora"        // Secure Virtual Workspace
	ServiceCleanerliverc   Service = "cleanerliverc"   // CleanerLive remote ctrl
	ServiceVulture         Service = "vulture"         // Vulture Monitoring System
	ServiceSlimDevices     Service = "slim-devices"    // Slim Devices Protocol
	ServiceGbsStp          Service = "gbs-stp"         // GBS SnapTalk Protocol
	ServiceCelatalk        Service = "celatalk"        // CelaTalk
	ServiceIfsfHbPort      Service = "ifsf-hb-port"    // IFSF Heartbeat Port
	ServiceLtctcp          Service = "ltctcp"          // LISA TCP Transfer Channel
	ServiceLtcudp          Service = "ltcudp"          // LISA UDP Transfer Channel
	ServiceFsRhSrv         Service = "fs-rh-srv"       // FS Remote Host Server
	ServiceDtpDia          Service = "dtp-dia"         // DTP/DIA
	ServiceColubris        Service = "colubris"        // Colubris Management Port
	ServiceSwrPort         Service = "swr-port"        // SWR Port
	ServiceTvdumtrayPort   Service = "tvdumtray-port"  // TVDUM Tray Port
	ServiceNut             Service = "nut"             // Network UPS Tools
	ServiceIbm3494         Service = "ibm3494"         // IBM 3494
	ServiceSeclayerTcp     Service = "seclayer-tcp"    // securitylayer over tcp
	ServiceSeclayerTls     Service = "seclayer-tls"    // securitylayer over tls
	ServiceIpether232port  Service = "ipether232port"  // ipEther232Port
	ServiceDashpasPort     Service = "dashpas-port"    // DASHPAS user port
	ServiceSccipMedia      Service = "sccip-media"     // SccIP Media
	ServiceRtmpPort        Service = "rtmp-port"       // RTMP Port
	ServiceIsoftP2p        Service = "isoft-p2p"       // iSoft-P2P
	ServiceAvinstalldisc   Service = "avinstalldisc"   // Avocent Install Discovery
	ServiceLspPing         Service = "lsp-ping"        // MPLS LSP-echo Port
	ServiceIronstorm       Service = "ironstorm"       // IronStorm game server
	ServiceCcmcomm         Service = "ccmcomm"         // CCM communications port
	ServiceApc3506         Service = "apc-3506"        // APC 3506
	ServiceNeshBroker      Service = "nesh-broker"     // Nesh Broker Port
	ServiceInteractionweb  Service = "interactionweb"  // Interaction Web
	ServiceVtSsl           Service = "vt-ssl"          // Virtual Token SSL Port
	ServiceXssPort         Service = "xss-port"        // XSS Port
	ServiceWebmail2        Service = "webmail-2"       // WebMail/2
	ServiceAztec           Service = "aztec"           // Aztec Distribution Port
	ServiceArcpd           Service = "arcpd"           // Adaptec Remote Protocol
	ServiceMustP2p         Service = "must-p2p"        // MUST Peer to Peer
	ServiceMustBackplane   Service = "must-backplane"  // MUST Backplane
	ServiceSmartcardPort   Service = "smartcard-port"  // Smartcard Port
	Service80211Iapp       Service = "802-11-iapp"     // IEEE 802.11 WLANs WG IAPP
	ServiceArtifactMsg     Service = "artifact-msg"    // Artifact Message Server
	ServiceNvmsgd          Service = "nvmsgd"          // Netvion Messenger Port
	ServiceGalileo         Service = "galileo"         // Netvion Galileo Port
	ServiceGalileolog      Service = "galileolog"      // Netvion Galileo Log Port
	ServiceMc3ss           Service = "mc3ss"           // Telequip Labs MC3SS
	ServiceNssocketport    Service = "nssocketport"    // DO over NSSocketPort
	ServiceOdeumservlink   Service = "odeumservlink"   // Odeum Serverlink
	ServiceEcmport         Service = "ecmport"         // ECM Server port
	ServiceEisport         Service = "eisport"         // EIS Server port
	ServiceStarquizPort    Service = "starquiz-port"   // starQuiz Port
	ServiceBeserverMsgQ    Service = "beserver-msg-q"  // VERITAS Backup Exec Server
	ServiceJbossIiop       Service = "jboss-iiop"      // JBoss IIOP
	ServiceJbossIiopSsl    Service = "jboss-iiop-ssl"  // JBoss IIOP/SSL
	ServiceGf              Service = "gf"              // Grid Friendly
	ServiceJoltid          Service = "joltid"          // Joltid
	ServiceRavenRmp        Service = "raven-rmp"       // Raven Remote Management Control
	ServiceRavenRdp        Service = "raven-rdp"       // Raven Remote Management Data
	ServiceUrldPort        Service = "urld-port"       // URL Daemon Port
	ServiceMsLa            Service = "ms-la"           // MS-LA
	ServiceSnac            Service = "snac"            // SNAC
	ServiceNiVisaRemote    Service = "ni-visa-remote"  // Remote NI-VISA port
	ServiceIbmDiradm       Service = "ibm-diradm"      // IBM Directory Server
	ServiceIbmDiradmSsl    Service = "ibm-diradm-ssl"  // IBM Directory Server SSL
	ServicePnrpPort        Service = "pnrp-port"       // PNRP User Port
	ServiceVoispeedPort    Service = "voispeed-port"   // VoiSpeed Port
	ServiceHaclMonitor     Service = "hacl-monitor"    // HA cluster monitor
	ServiceQftestLookup    Service = "qftest-lookup"   // qftest Lookup Port
	ServiceTeredo          Service = "teredo"          // Teredo Port
	ServiceCamac           Service = "camac"           // CAMAC equipment
	ServiceSymantecSim     Service = "symantec-sim"    // Symantec SIM
	ServiceInterworld      Service = "interworld"      // Interworld
	ServiceTellumatNms     Service = "tellumat-nms"    // Tellumat MDR NMS
	ServiceSsmpp           Service = "ssmpp"           // Secure SMPP
	ServiceApcupsd         Service = "apcupsd"         // Apcupsd Information Port
	ServiceTaserver        Service = "taserver"        // TeamAgenda Server Port
	ServiceRbrDiscovery    Service = "rbr-discovery"   // Red Box Recorder ADP
	ServiceQuestnotify     Service = "questnotify"     // Quest Notification Server
	ServiceRazor           Service = "razor"           // Vipul's Razor
	ServiceSkyTransport    Service = "sky-transport"   // Sky Transport Protocol
	ServicePersonalos001   Service = "personalos-001"  // PersonalOS Comm Port
	ServiceMcpPort         Service = "mcp-port"        // MCP user port
	ServiceCctvPort        Service = "cctv-port"       // CCTV control port
	ServiceIniservePort    Service = "iniserve-port"   // INIServe port
	ServiceBmcOnekey       Service = "bmc-onekey"      // BMC-OneKey
	ServiceSdbproxy        Service = "sdbproxy"        // SDBProxy
	ServiceWatcomdebug     Service = "watcomdebug"     // Watcom Debug
	ServiceEsimport        Service = "esimport"        // Electromed SIM port
	ServiceM2pa            Service = "m2pa"            // M2PA
	ServiceQuestDataHub    Service = "quest-data-hub"  // Quest Data Hub
	ServiceEncEps          Service = "enc-eps"         // EMIT protocol stack
	ServiceEncTunelSec     Service = "enc-tunel-sec"   // EMIT secure tunnel
	ServiceMbgCtrl         Service = "mbg-ctrl"        // Meinberg Control Service
	ServiceMccwebsvrPort   Service = "mccwebsvr-port"  // MCC Web Server Port
	ServiceMegardsvrPort   Service = "megardsvr-port"  // MegaRAID Server Port
	ServiceMegaregsvrport  Service = "megaregsvrport"  // Registration Server Port
	ServiceTagUps1         Service = "tag-ups-1"       // Advantage Group UPS Suite
	ServiceDmafServer      Service = "dmaf-server"     // DMAF Server
	ServiceDmafCaster      Service = "dmaf-caster"     // DMAF Caster
	ServiceCcmPort         Service = "ccm-port"        // Coalsere CCM Port
	ServiceCmcPort         Service = "cmc-port"        // Coalsere CMC Port
	ServiceConfigPort      Service = "config-port"     // Configuration Port
	ServiceDataPort        Service = "data-port"       // Data Port
	ServiceTtat3lb         Service = "ttat3lb"         // Tarantella Load Balancing
	ServiceNatiSvrloc      Service = "nati-svrloc"     // NATI-ServiceLocator
	ServiceKfxaclicensing  Service = "kfxaclicensing"  // Ascent Capture Licensing
	ServicePress           Service = "press"           // PEG PRESS Server
	ServiceCanexWatch      Service = "canex-watch"     // CANEX Watch System
	ServiceUDbap           Service = "u-dbap"          // U-DBase Access Protocol
	ServiceEmpriseLls      Service = "emprise-lls"     // Emprise License Server
	ServiceEmpriseLsc      Service = "emprise-lsc"     // License Server Console
	ServiceP2pgroup        Service = "p2pgroup"        // Peer to Peer Grouping
	ServiceSentinel        Service = "sentinel"        // Sentinel Server
	ServiceIsomair         Service = "isomair"         // isomair
	ServiceWvCspSms        Service = "wv-csp-sms"      // WV CSP SMS Binding
	ServiceGtrackServer    Service = "gtrack-server"   // LOCANIS G-TRACK Server
	ServiceGtrackNe        Service = "gtrack-ne"       // LOCANIS G-TRACK NE Port
	ServiceBpmd            Service = "bpmd"            // BP Model Debugger
	ServiceMediaspace      Service = "mediaspace"      // MediaSpace
	ServiceShareapp        Service = "shareapp"        // ShareApp
	ServiceIwMmogame       Service = "iw-mmogame"      // Illusion Wireless MMOG
	ServiceA14             Service = "a14"             // A14 (AN-to-SC/MM)
	ServiceA15             Service = "a15"             // A15 (AN-to-AN)
	ServiceQuasarServer    Service = "quasar-server"   // Quasar Accounting Server
	ServiceTrapDaemon      Service = "trap-daemon"     // text relay-answer
	ServiceVisinetGui      Service = "visinet-gui"     // Visinet Gui
	ServiceInfiniswitchcl  Service = "infiniswitchcl"  // InfiniSwitch Mgr Client
	ServiceIntRcvCntrl     Service = "int-rcv-cntrl"   // Integrated Rcvr Control
	ServiceBmcJmxPort      Service = "bmc-jmx-port"    // BMC JMX Port
	ServiceComcamIo        Service = "comcam-io"       // ComCam IO Port
	ServiceSplitlock       Service = "splitlock"       // Splitlock Server
	ServicePreciseI3       Service = "precise-i3"      // Precise I3
	ServiceTrendchipDcp    Service = "trendchip-dcp"   // Trendchip control protocol
	ServiceCpdiPidasCm     Service = "cpdi-pidas-cm"   // CPDI PIDAS Connection Mon
	ServiceEchonet         Service = "echonet"         // ECHONET
	ServiceSixDegrees      Service = "six-degrees"     // Six Degrees Port
	ServiceHpDataprotect   Service = "hp-dataprotect"  // HP Data Protector
	ServiceAlarisDisc      Service = "alaris-disc"     // Alaris Device Discovery
	ServiceSigmaPort       Service = "sigma-port"      // Satchwell Sigma
	ServiceStartNetwork    Service = "start-network"   // Start Messaging Network
	ServiceCd3oProtocol    Service = "cd3o-protocol"   // cd3o Control Protocol
	ServiceSharpServer     Service = "sharp-server"    // ATI SHARP Logic Engine
	ServiceAairnet1        Service = "aairnet-1"       // AAIR-Network 1
	ServiceAairnet2        Service = "aairnet-2"       // AAIR-Network 2
	ServiceEpPcp           Service = "ep-pcp"          // EPSON Projector Control Port
	ServiceEpNsp           Service = "ep-nsp"          // EPSON Network Screen Port
	ServiceFfLrPort        Service = "ff-lr-port"      // FF LAN Redundancy Port
	ServiceHaipeDiscover   Service = "haipe-discover"  // HAIPIS Dynamic Discovery
	ServiceDistUpgrade     Service = "dist-upgrade"    // Distributed Upgrade Port
	ServiceVolley          Service = "volley"          // Volley
	ServiceBvcdaemonPort   Service = "bvcdaemon-port"  // bvControl Daemon
	ServiceJamserverport   Service = "jamserverport"   // Jam Server Port
	ServiceEptMachine      Service = "ept-machine"     // EPT Machine Interface
	ServiceEscvpnet        Service = "escvpnet"        // ESC/VP.net
	ServiceCsRemoteDb      Service = "cs-remote-db"    // C&S Remote Database Port
	ServiceCsServices      Service = "cs-services"     // C&S Web Services Port
	ServiceWacp            Service = "wacp"            // Wyrnix AIS port
	ServiceHlibmgr         Service = "hlibmgr"         // hNTSP Library Manager
	ServiceSdo             Service = "sdo"             // Simple Distributed Objects
	ServiceServistaitsm    Service = "servistaitsm"    // SerVistaITSM
	ServiceScservp         Service = "scservp"         // Customer Service Port
	ServiceEhpBackup       Service = "ehp-backup"      // EHP Backup Protocol
	ServiceXapHa           Service = "xap-ha"          // Extensible Automation
	ServiceNetplayPort1    Service = "netplay-port1"   // Netplay Port 1
	ServiceNetplayPort2    Service = "netplay-port2"   // Netplay Port 2
	ServiceJuxmlPort       Service = "juxml-port"      // Juxml Replication port
	ServiceAudiojuggler    Service = "audiojuggler"    // AudioJuggler
	ServiceSsowatch        Service = "ssowatch"        // ssowatch
	ServiceCyc             Service = "cyc"             // Cyc
	ServiceXssSrvPort      Service = "xss-srv-port"    // XSS Server Port
	ServiceSplitlockGw     Service = "splitlock-gw"    // Splitlock Gateway
	ServiceFjcp            Service = "fjcp"            // Fujitsu Cooperation Port
	ServiceNmmp            Service = "nmmp"            // Nishioka Miyuki Msg Protocol
	ServicePrismiqPlugin   Service = "prismiq-plugin"  // PRISMIQ VOD plug-in
	ServiceXrpcRegistry    Service = "xrpc-registry"   // XRPC Registry
	ServiceVxcrnbuport     Service = "vxcrnbuport"     // VxCR NBU Default Port
	ServiceTsp             Service = "tsp"             // Tunnel Setup Protocol
	ServiceVaprtm          Service = "vaprtm"          // VAP RealTime Messenger
	ServiceAbatemgr        Service = "abatemgr"        // ActiveBatch Exec Agent
	ServiceAbatjss         Service = "abatjss"         // ActiveBatch Job Scheduler
	ServiceImmedianetBcn   Service = "immedianet-bcn"  // ImmediaNet Beacon
	ServicePsAms           Service = "ps-ams"          // PlayStation AMS (Secure)
	ServiceAppleSasl       Service = "apple-sasl"      // Apple SASL
	ServiceCanNdsSsl       Service = "can-nds-ssl"     // IBM Tivoli Directory Service using SSL
	ServiceCanFerretSsl    Service = "can-ferret-ssl"  // IBM Tivoli Directory Service using SSL
	ServicePserver         Service = "pserver"         // pserver
	ServiceDtp             Service = "dtp"             // DIRECWAY Tunnel Protocol
	ServiceUpsEngine       Service = "ups-engine"      // UPS Engine Port
	ServiceEntEngine       Service = "ent-engine"      // Enterprise Engine Port
	ServiceEserverPap      Service = "eserver-pap"     // IBM eServer PAP
	ServiceInfoexch        Service = "infoexch"        // IBM Information Exchange
	ServiceDellRmPort      Service = "dell-rm-port"    // Dell Remote Management
	ServiceCasanswmgmt     Service = "casanswmgmt"     // CA SAN Switch Management
	ServiceSmile           Service = "smile"           // SMILE TCP/UDP Interface
	ServiceEfcp            Service = "efcp"            // e Field Control (EIBnet)
	ServiceLispworksOrb    Service = "lispworks-orb"   // LispWorks ORB
	ServiceMediavaultGui   Service = "mediavault-gui"  // Openview Media Vault GUI
	ServiceWininstallIpc   Service = "wininstall-ipc"  // WinINSTALL IPC Port
	ServiceCalltrax        Service = "calltrax"        // CallTrax Data Port
	ServiceVaPacbase       Service = "va-pacbase"      // VisualAge Pacbase server
	ServiceRoverlog        Service = "roverlog"        // RoverLog IPC
	ServiceIprDglt         Service = "ipr-dglt"        // DataGuardianLT
	ServiceNewtonDock      Service = "newton-dock"     // Newton Dock (Escale)
	ServiceNpdsTracker     Service = "npds-tracker"    // NPDS Tracker
	ServiceBtsX73          Service = "bts-x73"         // BTS X73 Port
	ServiceCasMapi         Service = "cas-mapi"        // EMC SmartPackets-MAPI
	ServiceBmcEa           Service = "bmc-ea"          // BMC EDV/EA
	ServiceFaxstfxPort     Service = "faxstfx-port"    // FAXstfX
	ServiceDsxAgent        Service = "dsx-agent"       // DS Expert Agent
	ServiceTnmpv2          Service = "tnmpv2"          // Trivial Network Management
	ServiceSimplePush      Service = "simple-push"     // simple-push
	ServiceSimplePushS     Service = "simple-push-s"   // simple-push Secure
	ServiceDaap            Service = "daap"            // Digital Audio Access Protocol
	ServiceMagayaNetwork   Service = "magaya-network"  // Magaya Network Port
	ServiceIntelsync       Service = "intelsync"       // Brimstone IntelSync
	ServiceBmcDataColl     Service = "bmc-data-coll"   // BMC Data Collection
	ServiceTelnetcpcd      Service = "telnetcpcd"      // Telnet Com Port Control
	ServiceNwLicense       Service = "nw-license"      // NavisWorks License System
	ServiceSagectlpanel    Service = "sagectlpanel"    // SAGECTLPANEL
	ServiceKpnIcw          Service = "kpn-icw"         // Internet Call Waiting
	ServiceLrsPaging       Service = "lrs-paging"      // LRS NetPage
	ServiceNetcelera       Service = "netcelera"       // NetCelera
	ServiceWsDiscovery     Service = "ws-discovery"    // Web Service Discovery
	ServiceAdobeserver3    Service = "adobeserver-3"   // Adobe Server 3
	ServiceAdobeserver4    Service = "adobeserver-4"   // Adobe Server 4
	ServiceAdobeserver5    Service = "adobeserver-5"   // Adobe Server 5
	ServiceRtEvent         Service = "rt-event"        // Real-Time Event Port
	ServiceRtEventS        Service = "rt-event-s"      // Real-Time Event Secure Port
	ServiceSunAsIiops      Service = "sun-as-iiops"    // Sun App Svr - Naming
	ServiceCaIdms          Service = "ca-idms"         // CA-IDMS Server
	ServicePortgateAuth    Service = "portgate-auth"   // PortGate Authentication
	ServiceEdbServer2      Service = "edb-server2"     // EBD Server 2
	ServiceSentinelEnt     Service = "sentinel-ent"    // Sentinel Enterprise
	ServiceTftps           Service = "tftps"           // TFTP over TLS
	ServiceDelosDms        Service = "delos-dms"       // DELOS Direct Messaging
	ServiceAnotoRendezv    Service = "anoto-rendezv"   // Anoto Rendezvous Port
	ServiceWvCspSmsCir     Service = "wv-csp-sms-cir"  // WV CSP SMS CIR Channel
	ServiceWvCspUdpCir     Service = "wv-csp-udp-cir"  // WV CSP UDP/IP CIR Channel
	ServiceOpusServices    Service = "opus-services"   // OPUS Server Port
	ServiceItelserverport  Service = "itelserverport"  // iTel Server Port
	ServiceUfastroInstr    Service = "ufastro-instr"   // UF Astro. Instr. Services
	ServiceXsync           Service = "xsync"           // Xsync
	ServiceXserveraid      Service = "xserveraid"      // Xserve RAID
	ServiceSychrond        Service = "sychrond"        // Sychron Service Daemon
	ServiceBlizwow         Service = "blizwow"         // World of Warcraft
	ServiceNaErTip         Service = "na-er-tip"       // Netia NA-ER Port
	ServiceArrayManager    Service = "array-manager"   // Xyratex Array Manager
	ServiceEMdu            Service = "e-mdu"           // Ericsson Mobile Data Unit
	ServiceEWoa            Service = "e-woa"           // Ericsson Web on Air
	ServiceFkspAudit       Service = "fksp-audit"      // Fireking Audit Port
	ServiceClientCtrl      Service = "client-ctrl"     // Client Control
	ServiceSmap            Service = "smap"            // Service Manager
	ServiceMWnn            Service = "m-wnn"           // Mobile Wnn
	ServiceMultipMsg       Service = "multip-msg"      // Multipuesto Msg Port
	ServiceSynelData       Service = "synel-data"      // Synel Data Collection Port
	ServicePwdis           Service = "pwdis"           // Password Distribution
	ServiceRsRmi           Service = "rs-rmi"          // RealSpace RMI
	ServiceXpanel          Service = "xpanel"          // Xpanel Daemon
	ServiceVersatalk       Service = "versatalk"       // versaTalk Server Port
	ServiceLaunchbirdLm    Service = "launchbird-lm"   // Launchbird LicenseManager
	ServiceHeartbeat       Service = "heartbeat"       // Heartbeat Protocol
	ServiceWysdma          Service = "wysdma"          // WysDM Agent
	ServiceCstPort         Service = "cst-port"        // CST - Configuration & Service Tracker
	ServiceIpcsCommand     Service = "ipcs-command"    // IP Control Systems Ltd.
	ServiceSasg            Service = "sasg"            // SASG
	ServiceGwCallPort      Service = "gw-call-port"    // GWRTC Call Port
	ServiceLinktest        Service = "linktest"        // LXPRO.COM LinkTest
	ServiceLinktestS       Service = "linktest-s"      // LXPRO.COM LinkTest SSL
	ServiceWebdata         Service = "webdata"         // webData
	ServiceCimtrak         Service = "cimtrak"         // CimTrak
	ServiceCbosIpPort      Service = "cbos-ip-port"    // CBOS/IP ncapsalation port
	ServiceGprsCube        Service = "gprs-cube"       // CommLinx GPRS Cube
	ServiceVipremoteagent  Service = "vipremoteagent"  // Vigil-IP RemoteAgent
	ServiceNattyserver     Service = "nattyserver"     // NattyServer Port
	ServiceTimestenbroker  Service = "timestenbroker"  // TimesTen Broker Port
	ServiceSasRemoteHlp    Service = "sas-remote-hlp"  // SAS Remote Help Server
	ServiceCanonCapt       Service = "canon-capt"      // Canon CAPT Port
	ServiceGrfPort         Service = "grf-port"        // GRF Server Port
	ServiceApwRegistry     Service = "apw-registry"    // apw RMI registry
	ServiceExaptLmgr       Service = "exapt-lmgr"      // Exapt License Manager
	ServiceAdtempusclient  Service = "adtempusclient"  // adTempus Client
	ServiceGsakmp          Service = "gsakmp"          // gsakmp port
	ServiceGbsSmp          Service = "gbs-smp"         // GBS SnapMail Protocol
	ServiceXoWave          Service = "xo-wave"         // XO Wave Control Port
	ServiceMniProtRout     Service = "mni-prot-rout"   // MNI Protected Routing
	ServiceRtraceroute     Service = "rtraceroute"     // Remote Traceroute
	ServiceListmgrPort     Service = "listmgr-port"    // ListMGR Port
	ServiceRblcheckd       Service = "rblcheckd"       // rblcheckd server daemon
	ServiceHaipeOtnk       Service = "haipe-otnk"      // HAIPE Network Keying
	ServiceCindycollab     Service = "cindycollab"     // Cinderella Collaboration
	ServicePagingPort      Service = "paging-port"     // RTP Paging Port
	ServiceCtp             Service = "ctp"             // Chantry Tunnel Protocol
	ServiceCtdhercules     Service = "ctdhercules"     // ctdhercules
	ServiceZicom           Service = "zicom"           // ZICOM
	ServiceIspmmgr         Service = "ispmmgr"         // ISPM Manager Port
	ServiceDvcprovPort     Service = "dvcprov-port"    // Device Provisioning Port
	ServiceJibeEb          Service = "jibe-eb"         // Jibe EdgeBurst
	ServiceCHItPort        Service = "c-h-it-port"     // Cutler-Hammer IT Port
	ServiceCognima         Service = "cognima"         // Cognima Replication
	ServiceNnp             Service = "nnp"             // Nuzzler Network Protocol
	ServiceAbcvoicePort    Service = "abcvoice-port"   // ABCvoice server port
	ServiceIsoTp0s         Service = "iso-tp0s"        // Secure ISO TP0 port
	ServiceBimPem          Service = "bim-pem"         // Impact Mgr./PEM Gateway
	ServiceBfdControl      Service = "bfd-control"     // BFD Control Protocol
	ServiceBfdEcho         Service = "bfd-echo"        // BFD Echo Protocol
	ServiceUpstriggervsw   Service = "upstriggervsw"   // VSW Upstrigger port
	ServiceFintrx          Service = "fintrx"          // Fintrx
	ServiceIsrpPort        Service = "isrp-port"       // SPACEWAY Routing port
	ServiceRemotedeploy    Service = "remotedeploy"    // RemoteDeploy Administration Port
	ServiceQuickbooksrds   Service = "quickbooksrds"   // QuickBooks RDS
	ServiceTvnetworkvideo  Service = "tvnetworkvideo"  // TV NetworkVideo Data port
	ServiceSitewatch       Service = "sitewatch"       // e-Watch Corporation SiteWatch
	ServiceDcsoftware      Service = "dcsoftware"      // DataCore Software
	ServiceJaus            Service = "jaus"            // JAUS Robots
	ServiceMyblast         Service = "myblast"         // myBLAST Mekentosj port
	ServiceSpwDialer       Service = "spw-dialer"      // Spaceway Dialer
	ServiceIdps            Service = "idps"            // idps
	ServiceMinilock        Service = "minilock"        // Minilock
	ServiceRadiusDynauth   Service = "radius-dynauth"  // RADIUS Dynamic Authorization
	ServicePwgpsi          Service = "pwgpsi"          // Print Services Interface
	ServiceIbmMgr          Service = "ibm-mgr"         // ibm manager service
	ServiceVhd             Service = "vhd"             // VHD
	ServiceSoniqsync       Service = "soniqsync"       // SoniqSync
	ServiceIqnetPort       Service = "iqnet-port"      // Harman IQNet Port
	ServiceTcpdataserver   Service = "tcpdataserver"   // ThorGuard Server Port
	ServiceWsmlb           Service = "wsmlb"           // Remote System Manager
	ServiceSpugna          Service = "spugna"          // SpuGNA Communication Port
	ServiceSunAsIiopsCa    Service = "sun-as-iiops-ca" // Sun App Svr-IIOPClntAuth
	ServiceApocd           Service = "apocd"           // Java Desktop System Configuration Agent
	ServiceWlanauth        Service = "wlanauth"        // WLAN AS server
	ServiceAmp             Service = "amp"             // AMP
	ServiceNetoWolServer   Service = "neto-wol-server" // netO WOL Server
	ServiceRapIp           Service = "rap-ip"          // Rhapsody Interface Protocol
	ServiceNetoDcs         Service = "neto-dcs"        // netO DCS
	ServiceLansurveyorxml  Service = "lansurveyorxml"  // LANsurveyor XML
	ServiceSunlpsHttp      Service = "sunlps-http"     // Sun Local Patch Server
	ServiceTapeware        Service = "tapeware"        // Yosemite Tech Tapeware
	ServiceCrinisHb        Service = "crinis-hb"       // Crinis Heartbeat
	ServiceEplSlp          Service = "epl-slp"         // EPL Sequ Layer Protocol
	ServiceScp             Service = "scp"             // Siemens AuD SCP
	ServicePmcp            Service = "pmcp"            // ATSC PMCP Standard
	ServiceAcpDiscovery    Service = "acp-discovery"   // Compute Pool Discovery
	ServiceAcpConduit      Service = "acp-conduit"     // Compute Pool Conduit
	ServiceAcpPolicy       Service = "acp-policy"      // Compute Pool Policy
	ServiceFfserver        Service = "ffserver"        // Antera FlowFusion Process Simulation
	ServiceWarmux          Service = "warmux"          // WarMUX game server
	ServiceNetmpi          Service = "netmpi"          // Netadmin Systems MPI service
	ServiceNeteh           Service = "neteh"           // Netadmin Systems Event Handler
	ServiceNetehExt        Service = "neteh-ext"       // Netadmin Systems Event Handler External
	ServiceCernsysmgmtagt  Service = "cernsysmgmtagt"  // Cerner System Management Agent
	ServiceDvapps          Service = "dvapps"          // Docsvault Application Service
	ServiceXxnetserver     Service = "xxnetserver"     // xxNETserver
	ServiceAipnAuth        Service = "aipn-auth"       // AIPN LS Authentication
	ServiceSpectardata     Service = "spectardata"     // Spectar Data Stream Service
	ServiceSpectardb       Service = "spectardb"       // Spectar Database Rights Service
	ServiceMarkemDcp       Service = "markem-dcp"      // MARKEM NEXTGEN DCP
	ServiceMkmDiscovery    Service = "mkm-discovery"   // MARKEM Auto-Discovery
	ServiceSos             Service = "sos"             // Scito Object Server
	ServiceAmxRms          Service = "amx-rms"         // AMX Resource Management Suite
	ServiceFlirtmitmir     Service = "flirtmitmir"     // www.FlirtMitMir.de
	ServiceZfirmShiprush3  Service = "zfirm-shiprush3" // Z-Firm ShipRush v3
	ServiceNhci            Service = "nhci"            // NHCI status port
	ServiceQuestAgent      Service = "quest-agent"     // Quest Common Agent
	ServiceRnm             Service = "rnm"             // RNM
	ServiceVOneSpp         Service = "v-one-spp"       // V-ONE Single Port Proxy
	ServiceAnPcp           Service = "an-pcp"          // Astare Network PCP
	ServiceMsfwControl     Service = "msfw-control"    // MS Firewall Control
	ServiceItem            Service = "item"            // IT Environmental Monitor
	ServiceSpwDnspreload   Service = "spw-dnspreload"  // SPACEWAY DNS Preload
	ServiceQtmsBootstrap   Service = "qtms-bootstrap"  // QTMS Bootstrap Protocol
	ServiceSpectraport     Service = "spectraport"     // SpectraTalk Port
	ServiceSseAppConfig    Service = "sse-app-config"  // SSE App Configuration
	ServiceSscan           Service = "sscan"           // SONY scanning protocol
	ServiceStrykerCom      Service = "stryker-com"     // Stryker Comm Port
	ServiceOpentrac        Service = "opentrac"        // OpenTRAC
	ServiceInformer        Service = "informer"        // INFORMER
	ServiceTrapPort        Service = "trap-port"       // Trap Port
	ServiceTrapPortMom     Service = "trap-port-mom"   // Trap Port MOM
	ServiceNavPort         Service = "nav-port"        // Navini Port
	ServiceSasp            Service = "sasp"            // Server/Application State Protocol (SASP)
	ServiceWinshadowHd     Service = "winshadow-hd"    // winShadow Host Discovery
	ServiceGigaPocket      Service = "giga-pocket"     // GIGA-POCKET
	ServiceAsapTcp         Service = "asap-tcp"        // asap tcp port
	ServiceAsapUdp         Service = "asap-udp"        // asap udp port
	ServiceAsapSctp        Service = "asap-sctp"       // asap sctp
	ServiceAsapTcpTls      Service = "asap-tcp-tls"    // asap/tls tcp port
	ServiceAsapSctpTls     Service = "asap-sctp-tls"   // asap-sctp/tls
	ServiceXpl             Service = "xpl"             // xpl automation protocol
	ServiceDzdaemon        Service = "dzdaemon"        // Sun SDViz DZDAEMON Port
	ServiceDzoglserver     Service = "dzoglserver"     // Sun SDViz DZOGLSERVER Port
	ServiceDiameter        Service = "diameter"        // DIAMETER
	ServiceOvsamMgmt       Service = "ovsam-mgmt"      // hp OVSAM MgmtServer Disco
	ServiceOvsamDAgent     Service = "ovsam-d-agent"   // hp OVSAM HostAgent Disco
	ServiceAvocentAdsap    Service = "avocent-adsap"   // Avocent DS Authorization
	ServiceOemAgent        Service = "oem-agent"       // OEM Agent
	ServiceFagordnc        Service = "fagordnc"        // fagordnc
	ServiceSixxsconfig     Service = "sixxsconfig"     // SixXS Configuration
	ServicePnbscada        Service = "pnbscada"        // PNBSCADA
	ServiceDl_agent        Service = "dl_agent"        // DirectoryLockdown Agent
	ServiceXmpcrInterface  Service = "xmpcr-interface" // XMPCR Interface Port
	ServiceFotogcad        Service = "fotogcad"        // FotoG CAD interface
	ServiceAppssLm         Service = "appss-lm"        // appss license manager
	ServiceIgrs            Service = "igrs"            // IGRS
	ServiceIdac            Service = "idac"            // Data Acquisition and Control
	ServiceMsdts1          Service = "msdts1"          // DTS Service Port
	ServiceVrpn            Service = "vrpn"            // VR Peripheral Network
	ServiceSoftrackMeter   Service = "softrack-meter"  // SofTrack Metering
	ServiceTopflowSsl      Service = "topflow-ssl"     // TopFlow SSL
	ServiceNeiManagement   Service = "nei-management"  // NEI management port
	ServiceCiphireData     Service = "ciphire-data"    // Ciphire Data Transport
	ServiceCiphireServ     Service = "ciphire-serv"    // Ciphire Services
	ServiceDandvTester     Service = "dandv-tester"    // D and V Tester Control Port
	ServiceNdsconnect      Service = "ndsconnect"      // Niche Data Server Connect
	ServiceRtcPmPort       Service = "rtc-pm-port"     // Oracle RTC-PM port
	ServicePccImagePort    Service = "pcc-image-port"  // PCC-image-port
	ServiceCgiStarapi      Service = "cgi-starapi"     // CGI StarAPI Server
	ServiceSyamAgent       Service = "syam-agent"      // SyAM Agent Port
	ServiceSyamSmc         Service = "syam-smc"        // SyAm SMC Service Port
	ServiceSdoTls          Service = "sdo-tls"         // Simple Distributed Objects over TLS
	ServiceSdoSsh          Service = "sdo-ssh"         // Simple Distributed Objects over SSH
	ServiceSenip           Service = "senip"           // IAS, Inc. SmartEye NET Internet Protocol
	ServiceItvControl      Service = "itv-control"     // ITV Port
	ServiceNimsh           Service = "nimsh"           // NIM Service Handler
	ServiceNimaux          Service = "nimaux"          // NIMsh Auxiliary Port
	ServiceCharsetmgr      Service = "charsetmgr"      // CharsetMGR
	ServiceOmnilinkPort    Service = "omnilink-port"   // Arnet Omnilink Port
	ServiceMupdate         Service = "mupdate"         // Mailbox Update (MUPDATE) protocol
	ServiceTopovistaData   Service = "topovista-data"  // TopoVista elevation data
	ServiceImoguiaPort     Service = "imoguia-port"    // Imoguia Port
	ServiceHppronetman     Service = "hppronetman"     // HP Procurve NetManagement
	ServiceSurfcontrolcpa  Service = "surfcontrolcpa"  // SurfControl CPA
	ServicePrnrequest      Service = "prnrequest"      // Printer Request Port
	ServicePrnstatus       Service = "prnstatus"       // Printer Status Port
	ServiceGbmtStars       Service = "gbmt-stars"      // Global Maintech Stars
	ServiceListcrtPort     Service = "listcrt-port"    // ListCREATOR Port
	ServiceListcrtPort2    Service = "listcrt-port-2"  // ListCREATOR Port 2
	ServiceAgcat           Service = "agcat"           // Auto-Graphics Cataloging
	ServiceWysdmc          Service = "wysdmc"          // WysDM Controller
	ServiceAftmux          Service = "aftmux"          // AFT multiplex port
	ServicePktcablemmcops  Service = "pktcablemmcops"  // PacketCableMultimediaCOPS
	ServiceHyperip         Service = "hyperip"         // HyperIP
	ServiceExasoftport1    Service = "exasoftport1"    // Exasoft IP Port
	ServiceHerodotusNet    Service = "herodotus-net"   // Herodotus Net
	ServiceSorUpdate       Service = "sor-update"      // Soronti Update Port
	ServiceSymbSbPort      Service = "symb-sb-port"    // Symbian Service Broker
	ServiceMplGprsPort     Service = "mpl-gprs-port"   // MPL_GPRS_PORT
	ServiceZmp             Service = "zmp"             // Zoran Media Port
	ServiceWinport         Service = "winport"         // WINPort
	ServiceNatdataservice  Service = "natdataservice"  // ScsTsr
	ServiceNetbootPxe      Service = "netboot-pxe"     // PXE NetBoot Manager
	ServiceSmauthPort      Service = "smauth-port"     // AMS Port
	ServiceSyamWebserver   Service = "syam-webserver"  // Syam Web Server Port
	ServiceMsrPluginPort   Service = "msr-plugin-port" // MSR Plugin Port
	ServiceDynSite         Service = "dyn-site"        // Dynamic Site System
	ServicePlbservePort    Service = "plbserve-port"   // PL/B App Server User Port
	ServiceSunfmPort       Service = "sunfm-port"      // PL/B File Manager Port
	ServiceSdpPortmapper   Service = "sdp-portmapper"  // SDP Port Mapper Protocol
	ServiceMailprox        Service = "mailprox"        // Mailprox
	ServiceDvbservdsc      Service = "dvbservdsc"      // DVB Service Discovery
	ServiceDbcontrol_agent Service = "dbcontrol_agent" // Oracle dbControl Agent po
	ServiceAamp            Service = "aamp"            // Anti-virus Application Management Port
	ServiceXecpNode        Service = "xecp-node"       // XeCP Node Service
	ServiceHomeportalWeb   Service = "homeportal-web"  // Home Portal Web Server
	ServiceSrdp            Service = "srdp"            // satellite distribution
	ServiceTig             Service = "tig"             // TetraNode Ip Gateway
	ServiceSops            Service = "sops"            // S-Ops Management
	ServiceEmcads          Service = "emcads"          // EMCADS Server Port
	ServiceBackupedge      Service = "backupedge"      // BackupEDGE Server
	ServiceCcp             Service = "ccp"             // Connect and Control Protocol for Consumer, Commercial, and Industrial Electronic Devices
	ServiceApdap           Service = "apdap"           // Anton Paar Device Administration Protocol
	ServiceDrip            Service = "drip"            // Dynamic Routing Information Protocol
	ServiceNamemunge       Service = "namemunge"       // Name Munging
	ServicePwgippfax       Service = "pwgippfax"       // PWG IPP Facsimile
	ServiceI3Sessionmgr    Service = "i3-sessionmgr"   // I3 Session Manager
	ServiceXmlinkConnect   Service = "xmlink-connect"  // Eydeas XMLink Connect
	ServiceAdrep           Service = "adrep"           // AD Replication RPC
	ServiceP2pcommunity    Service = "p2pcommunity"    // p2pCommunity
	ServiceGvcp            Service = "gvcp"            // GigE Vision Control
	ServiceMqeBroker       Service = "mqe-broker"      // MQEnterprise Broker
	ServiceMqeAgent        Service = "mqe-agent"       // MQEnterprise Agent
	ServiceTreehopper      Service = "treehopper"      // Tree Hopper Networking
	ServiceBess            Service = "bess"            // Bess Peer Assessment
	ServiceProaxess        Service = "proaxess"        // ProAxess Server
	ServiceSbiAgent        Service = "sbi-agent"       // SBI Agent Protocol
	ServiceThrp            Service = "thrp"            // Teran Hybrid Routing Protocol
	ServiceSasggprs        Service = "sasggprs"        // SASG GPRS
	ServiceAtiIpToNcpe     Service = "ati-ip-to-ncpe"  // Avanti IP to NCPE API
	ServiceBflckmgr        Service = "bflckmgr"        // BuildForge Lock Manager
	ServicePpsms           Service = "ppsms"           // PPS Message Service
	ServiceIanywhereDbns   Service = "ianywhere-dbns"  // iAnywhere DBNS
	ServiceLandmarks       Service = "landmarks"       // Landmark Messages
	ServiceLanrevagent     Service = "lanrevagent"     // LANrev Agent
	ServiceLanrevserver    Service = "lanrevserver"    // LANrev Server
	ServiceIconp           Service = "iconp"           // ict-control Protocol
	ServiceProgistics      Service = "progistics"      // ConnectShip Progistics
	ServiceCitysearch      Service = "citysearch"      // Remote Applicant Tracking Service
	ServiceAirshot         Service = "airshot"         // Air Shot
	ServiceOpswagent       Service = "opswagent"       // Opsware Agent
	ServiceOpswmanager     Service = "opswmanager"     // Opsware Manager
	ServiceSecureCfgSvr    Service = "secure-cfg-svr"  // Secured Configuration Server
	ServiceSmwan           Service = "smwan"           // Smith Micro Wide Area Network Service
	ServiceAcms            Service = "acms"            // Aircraft Cabin Management System
	ServiceStarfish        Service = "starfish"        // Starfish System Admin
	ServiceEis             Service = "eis"             // ESRI Image Server
	ServiceEisp            Service = "eisp"            // ESRI Image Service
	ServiceMapperNodemgr   Service = "mapper-nodemgr"  // MAPPER network node manager
	ServiceMapperMapethd   Service = "mapper-mapethd"  // MAPPER TCP/IP server
	ServiceMapperWs_ethd   Service = "mapper-ws_ethd"  // MAPPER workstation server
	ServiceCenterline      Service = "centerline"      // Centerline
	ServiceDcsConfig       Service = "dcs-config"      // DCS Configuration Port
	ServiceBvQueryengine   Service = "bv-queryengine"  // BindView-Query Engine
	ServiceBvIs            Service = "bv-is"           // BindView-IS
	ServiceBvSmcsrv        Service = "bv-smcsrv"       // BindView-SMCServer
	ServiceBvDs            Service = "bv-ds"           // BindView-DirectoryServer
	ServiceBvAgent         Service = "bv-agent"        // BindView-Agent
	ServiceIssMgmtSsl      Service = "iss-mgmt-ssl"    // ISS Management Svcs SSL
	ServiceAbcsoftware     Service = "abcsoftware"     // abcsoftware-01
	ServiceAgentseaseDb    Service = "agentsease-db"   // aes_db
	ServiceDnx             Service = "dnx"             // Distributed Nagios Executor Service
	ServiceNvcnet          Service = "nvcnet"          // Norman distributes scanning service
	ServiceTerabase        Service = "terabase"        // Terabase
	ServiceNewoak          Service = "newoak"          // NewOak
	ServicePxcSpvrFt       Service = "pxc-spvr-ft"     // pxc-spvr-ft
	ServicePxcSplrFt       Service = "pxc-splr-ft"     // pxc-splr-ft
	ServicePxcRoid         Service = "pxc-roid"        // pxc-roid
	ServicePxcPin          Service = "pxc-pin"         // pxc-pin
	ServicePxcSpvr         Service = "pxc-spvr"        // pxc-spvr
	ServicePxcSplr         Service = "pxc-splr"        // pxc-splr
	ServiceNetcheque       Service = "netcheque"       // NetCheque accounting
	ServiceChimeraHwm      Service = "chimera-hwm"     // Chimera HWM
	ServiceSamsungUnidex   Service = "samsung-unidex"  // Samsung Unidex
	ServiceAltserviceboot  Service = "altserviceboot"  // Alternate Service Boot
	ServicePdaGate         Service = "pda-gate"        // PDA Gate
	ServiceAclManager      Service = "acl-manager"     // ACL Manager
	ServiceTaiclock        Service = "taiclock"        // TAICLOCK
	ServiceTalarianMcast1  Service = "talarian-mcast1" // Talarian Mcast
	ServiceTalarianMcast2  Service = "talarian-mcast2" // Talarian Mcast
	ServiceTalarianMcast3  Service = "talarian-mcast3" // Talarian Mcast
	ServiceTalarianMcast4  Service = "talarian-mcast4" // Talarian Mcast
	ServiceTalarianMcast5  Service = "talarian-mcast5" // Talarian Mcast
	ServiceTrap            Service = "trap"            // TRAP Port
	ServiceNexusPortal     Service = "nexus-portal"    // Nexus Portal
	ServiceDnox            Service = "dnox"            // DNOX
	ServiceEsnmZoning      Service = "esnm-zoning"     // ESNM Zoning Port
	ServiceTnp1Port        Service = "tnp1-port"       // TNP1 User Port
	ServicePartimage       Service = "partimage"       // Partition Image Port
	ServiceAsDebug         Service = "as-debug"        // Graphical Debug Server
	ServiceBxp             Service = "bxp"             // bitxpress
	ServiceDtserverPort    Service = "dtserver-port"   // DTServer Port
	ServiceIpQsig          Service = "ip-qsig"         // IP Q signaling protocol
	ServiceJdmnPort        Service = "jdmn-port"       // Accell/JSP Daemon Port
	ServiceSuucp           Service = "suucp"           // UUCP over SSL
	ServiceVrtsAuthPort    Service = "vrts-auth-port"  // VERITAS Authorization Service
	ServiceSanavigator     Service = "sanavigator"     // SANavigator Peer Port
	ServiceUbxd            Service = "ubxd"            // Ubiquinox Daemon
	ServiceWapPushHttp     Service = "wap-push-http"   // WAP Push OTA-HTTP port
	ServiceWapPushHttps    Service = "wap-push-https"  // WAP Push OTA-HTTP secure
	ServiceRavehd          Service = "ravehd"          // RaveHD network control
	ServiceFazztPtp        Service = "fazzt-ptp"       // Fazzt Point-To-Point
	ServiceFazztAdmin      Service = "fazzt-admin"     // Fazzt Administration
	ServiceYoMain          Service = "yo-main"         // Yo.net main service
	ServiceHouston         Service = "houston"         // Rocketeer-Houston
	ServiceLdxp            Service = "ldxp"            // LDXP
	ServiceNirp            Service = "nirp"            // Neighbour Identity Resolution
	ServiceLtp             Service = "ltp"             // Location Tracking Protocol
	ServiceAcpProto        Service = "acp-proto"       // Accounting Protocol
	ServiceCtpState        Service = "ctp-state"       // Context Transfer Protocol
	ServiceWafs            Service = "wafs"            // Wide Area File Services
	ServiceCiscoWafs       Service = "cisco-wafs"      // Wide Area File Services
	ServiceCppdp           Service = "cppdp"           // Cisco Peer to Peer Distribution Protocol
	ServiceInteract        Service = "interact"        // VoiceConnect Interact
	ServiceCcuComm1        Service = "ccu-comm-1"      // CosmoCall Universe Communications Port 1
	ServiceCcuComm2        Service = "ccu-comm-2"      // CosmoCall Universe Communications Port 2
	ServiceCcuComm3        Service = "ccu-comm-3"      // CosmoCall Universe Communications Port 3
	ServiceLms             Service = "lms"             // Location Message Service
	ServiceWfm             Service = "wfm"             // Servigistics WFM server
	ServiceKingfisher      Service = "kingfisher"      // Kingfisher protocol
	ServiceDlmsCosem       Service = "dlms-cosem"      // DLMS/COSEM
	ServiceDsmeter_iatc    Service = "dsmeter_iatc"    // DSMETER Inter-Agent Transfer Channel
	ServiceIceLocation     Service = "ice-location"    // Ice Location Service (TCP)
	ServiceIceSlocation    Service = "ice-slocation"   // Ice Location Service (SSL)
	ServiceIceRouter       Service = "ice-router"      // Ice Firewall Traversal Service (TCP)
	ServiceIceSrouter      Service = "ice-srouter"     // Ice Firewall Traversal Service (SSL)
	ServiceAvanti_cdp      Service = "avanti_cdp"      // Avanti Common Data
	ServicePmas            Service = "pmas"            // Performance Measurement and Analysis
	ServiceIdp             Service = "idp"             // Information Distribution Protocol
	ServiceIpfltbcst       Service = "ipfltbcst"       // IP Fleet Broadcast
	ServiceMinger          Service = "minger"          // Minger Email Address Validation Service
	ServiceTripe           Service = "tripe"           // Trivial IP Encryption (TrIPE)
	ServiceAibkup          Service = "aibkup"          // Automatically Incremental Backup
	ServiceZietoSock       Service = "zieto-sock"      // Zieto Socket Communications
	ServiceIRAPP           Service = "iRAPP"           // iRAPP Server Protocol
	ServiceCequintCityid   Service = "cequint-cityid"  // Cequint City ID UI trigger
	ServicePerimlan        Service = "perimlan"        // ISC Alarm Message Service
	ServiceSeraph          Service = "seraph"          // Seraph DCS
	ServiceAscomalarm      Service = "ascomalarm"      // Ascom IP Alarming
	ServiceCssp            Service = "cssp"            // Coordinated Security Service Protocol
	ServiceLoricaIn        Service = "lorica-in"       // Lorica inside facing
	ServiceLoricaInSec     Service = "lorica-in-sec"   // Lorica inside facing (SSL)
	ServiceLoricaOut       Service = "lorica-out"      // Lorica outside facing
	ServiceLoricaOutSec    Service = "lorica-out-sec"  // Lorica outside facing (SSL)
	ServiceFortisphereVm   Service = "fortisphere-vm"  // Fortisphere VM Service
	ServiceEzmessagesrv    Service = "ezmessagesrv"    // EZNews Newsroom Message Service
	ServiceFtsync          Service = "ftsync"          // Firewall/NAT state table synchronization
	ServiceApplusservice   Service = "applusservice"   // APplus Service
	ServiceNpsp            Service = "npsp"            // Noah Printing Service Protocol
	ServiceOpencore        Service = "opencore"        // OpenCORE Remote Control Service
	ServiceOmasgport       Service = "omasgport"       // OMA BCAST Service Guide
	ServiceEwinstaller     Service = "ewinstaller"     // EminentWare Installer
	ServiceEwdgs           Service = "ewdgs"           // EminentWare DGS
	ServicePvxpluscs       Service = "pvxpluscs"       // Pvx Plus CS Host
	ServiceSysrqd          Service = "sysrqd"          // sysrq daemon
	ServiceXtgui           Service = "xtgui"           // xtgui information service
	ServiceBre             Service = "bre"             // BRE (Bridge Relay Element)
	ServicePatrolview      Service = "patrolview"      // Patrol View
	ServiceDrmsfsd         Service = "drmsfsd"         // drmsfsd
	ServiceDpcp            Service = "dpcp"            // DPCP
	ServiceIgoIncognito    Service = "igo-incognito"   // IGo Incognito Data Port
	ServiceBrlp0           Service = "brlp-0"          // Braille protocol
	ServiceBrlp1           Service = "brlp-1"          // Braille protocol
	ServiceBrlp2           Service = "brlp-2"          // Braille protocol
	ServiceBrlp3           Service = "brlp-3"          // Braille protocol
	ServiceShofar          Service = "shofar"          // Shofar
	ServiceSynchronite     Service = "synchronite"     // Synchronite
	ServiceJAc             Service = "j-ac"            // JDL Accounting LAN Service
	ServiceAccel           Service = "accel"           // ACCEL
	ServiceIzm             Service = "izm"             // Instantiated Zero-control Messaging
	ServiceG2tag           Service = "g2tag"           // G2 RFID Tag Telemetry Data
	ServiceXgrid           Service = "xgrid"           // Xgrid
	ServiceAppleVpnsRp     Service = "apple-vpns-rp"   // Apple VPN Server Reporting Protocol
	ServiceAipnReg         Service = "aipn-reg"        // AIPN LS Registration
	ServiceJomamqmonitor   Service = "jomamqmonitor"   // JomaMQMonitor
	ServiceCds             Service = "cds"             // CDS Transfer Agent
	ServiceSmartcardTls    Service = "smartcard-tls"   // smartcard-TLS
	ServiceHillrserv       Service = "hillrserv"       // Hillr Connection Manager
	ServiceNetscript       Service = "netscript"       // Netadmin Systems NETscript service
	ServiceAssuriaSlm      Service = "assuria-slm"     // Assuria Log Manager
	ServiceEBuilder        Service = "e-builder"       // e-Builder Application Communication
	ServiceFprams          Service = "fprams"          // Fiber Patrol Alarm Service
	ServiceZWave           Service = "z-wave"          // Zensys Z-Wave Control Protocol
	ServiceTigv2           Service = "tigv2"           // Rohill TetraNode Ip Gateway v2
	ServiceOpsviewEnvoy    Service = "opsview-envoy"   // Opsview Envoy
	ServiceDdrepl          Service = "ddrepl"          // Data Domain Replication Service
	ServiceUnikeypro       Service = "unikeypro"       // NetUniKeyServer
	ServiceNufw            Service = "nufw"            // NuFW decision delegation protocol
	ServiceNuauth          Service = "nuauth"          // NuFW authentication protocol
	ServiceFronet          Service = "fronet"          // FRONET message protocol
	ServiceStars           Service = "stars"           // Global Maintech Stars
	ServiceNuts_dem        Service = "nuts_dem"        // NUTS Daemon
	ServiceNuts_bootp      Service = "nuts_bootp"      // NUTS Bootp Server
	ServiceNiftyHmi        Service = "nifty-hmi"       // NIFTY-Serve HMI protocol
	ServiceClDbAttach      Service = "cl-db-attach"    // Classic Line Database Server Attach
	ServiceClDbRequest     Service = "cl-db-request"   // Classic Line Database Server Request
	ServiceClDbRemote      Service = "cl-db-remote"    // Classic Line Database Server Remote
	ServiceNettest         Service = "nettest"         // nettest
	ServiceThrtx           Service = "thrtx"           // Imperfect Networks Server
	ServiceCedros_fds      Service = "cedros_fds"      // Cedros Fraud Detection System
	ServiceOirtgsvc        Service = "oirtgsvc"        // Workflow Server
	ServiceOidocsvc        Service = "oidocsvc"        // Document Server
	ServiceOidsr           Service = "oidsr"           // Document Replication
	ServiceVvrControl      Service = "vvr-control"     // VVR Control
	ServiceTgcconnect      Service = "tgcconnect"      // TGCConnect Beacon
	ServiceVrxpservman     Service = "vrxpservman"     // Multum Service Manager
	ServiceHhbHandheld     Service = "hhb-handheld"    // HHB Handheld Client
	ServiceAgslb           Service = "agslb"           // A10 GSLB Service
	ServicePowerAlertNsa   Service = "PowerAlert-nsa"  // PowerAlert Network Shutdown Agent
	ServiceMenandmice_noh  Service = "menandmice_noh"  // Men & Mice Remote Control
	ServiceIdig_mux        Service = "idig_mux"        // iDigTech Multiplex
	ServiceMblBattd        Service = "mbl-battd"       // MBL Remote Battery Monitoring
	ServiceAtlinks         Service = "atlinks"         // atlinks device discovery
	ServiceBzr             Service = "bzr"             // Bazaar version control system
	ServiceStatResults     Service = "stat-results"    // STAT Results
	ServiceStatScanner     Service = "stat-scanner"    // STAT Scanner Control
	ServiceStatCc          Service = "stat-cc"         // STAT Command Center
	ServiceNss             Service = "nss"             // Network Security Service
	ServiceJiniDiscovery   Service = "jini-discovery"  // Jini Discovery
	ServiceOmscontact      Service = "omscontact"      // OMS Contact
	ServiceOmstopology     Service = "omstopology"     // OMS Topology
	ServiceSilverpeakpeer  Service = "silverpeakpeer"  // Silver Peak Peer Protocol
	ServiceSilverpeakcomm  Service = "silverpeakcomm"  // Silver Peak Communication Protocol
	ServiceAltcp           Service = "altcp"           // ArcLink over Ethernet
	ServiceJoost           Service = "joost"           // Joost Peer to Peer Protocol
	ServiceDdgn            Service = "ddgn"            // DeskDirect Global Network
	ServicePslicser        Service = "pslicser"        // PrintSoft License Server
	ServiceIadt            Service = "iadt"            // Automation Drive Interface Transport
	ServiceIadtDisc        Service = "iadt-disc"       // Internet ADT Discovery Protocol
	ServiceDCinemaCsp      Service = "d-cinema-csp"    // SMPTE Content Synchonization Protocol
	ServiceMlSvnet         Service = "ml-svnet"        // Maxlogic Supervisor Communication
	ServicePcoip           Service = "pcoip"           // PC over IP
	ServiceMmaDiscovery    Service = "mma-discovery"   // MMA Device Discovery
	ServiceSmcluster       Service = "smcluster"       // StorMagic Cluster Services
	ServiceSmDisc          Service = "sm-disc"         // StorMagic Discovery
	ServiceBccp            Service = "bccp"            // Brocade Cluster Communication Protocol
	ServiceTlIpcproxy      Service = "tl-ipcproxy"     // Translattice Cluster IPC Proxy
	ServiceWello           Service = "wello"           // Wello P2P pubsub service
	ServiceStorman         Service = "storman"         // StorMan
	ServiceMaxumSP         Service = "MaxumSP"         // Maxum Services
	ServiceHttpx           Service = "httpx"           // HTTPX
	ServiceMacbak          Service = "macbak"          // MacBak
	ServicePcptcpservice   Service = "pcptcpservice"   // Production Company Pro TCP Service
	ServiceGmmp            Service = "gmmp"            // General Metaverse Messaging Protocol
	ServiceUniverse_suite  Service = "universe_suite"  // UNIVERSE SUITE MESSAGE SERVICE
	ServiceWcpp            Service = "wcpp"            // Woven Control Plane Protocol
	ServiceBoxbackupstore  Service = "boxbackupstore"  // Box Backup Store Service
	ServiceCsc_proxy       Service = "csc_proxy"       // Cascade Proxy
	ServiceVatata          Service = "vatata"          // Vatata Peer to Peer Protocol
	ServicePcep            Service = "pcep"            // Path Computation Element Communication Protocol
	ServiceSieve           Service = "sieve"           // ManageSieve Protocol
	ServiceDsmipv6         Service = "dsmipv6"         // Dual Stack MIPv6 NAT Traversal
	ServiceAzeti           Service = "azeti"           // Azeti Agent Service
	ServiceAzetiBd         Service = "azeti-bd"        // azeti blinddate
	ServicePvxplusio       Service = "pvxplusio"       // PxPlus remote file srvr
	ServiceEimsAdmin       Service = "eims-admin"      // EIMS ADMIN
	ServiceCorelccam       Service = "corelccam"       // Corel CCam
	ServiceDData           Service = "d-data"          // Diagnostic Data
	ServiceDDataControl    Service = "d-data-control"  // Diagnostic Data Control
	ServiceSrcp            Service = "srcp"            // Simple Railroad Command Protocol
	ServiceOwserver        Service = "owserver"        // One-Wire Filesystem Server
	ServiceBatman          Service = "batman"          // better approach to mobile ad-hoc networking
	ServicePinghgl         Service = "pinghgl"         // Hellgate London
	ServiceVisicronVs      Service = "visicron-vs"     // Visicron Videoconference Service
	ServiceCompxLockview   Service = "compx-lockview"  // CompX-LockView
	ServiceDserver         Service = "dserver"         // Exsequi Appliance Discovery
	ServiceMirrtex         Service = "mirrtex"         // Mir-RT exchange service
	ServiceP6ssmc          Service = "p6ssmc"          // P6R Secure Server Management Console
	ServicePsclMgt         Service = "pscl-mgt"        // Parascale Membership Manager
	ServicePerrla          Service = "perrla"          // PERRLA User Services
	ServiceChoiceviewAgt   Service = "choiceview-agt"  // ChoiceView Agent
	ServiceChoiceviewClt   Service = "choiceview-clt"  // ChoiceView Client
	ServiceFdtRcatp        Service = "fdt-rcatp"       // FDT Remote Categorization Protocol
	ServiceTrimEvent       Service = "trim-event"      // TRIM Event Service
	ServiceTrimIce         Service = "trim-ice"        // TRIM ICE Service
	ServiceBalour          Service = "balour"          // Balour Game Server
	ServiceGeognosisman    Service = "geognosisman"    // Cadcorp GeognoSIS Manager Service
	ServiceGeognosis       Service = "geognosis"       // Cadcorp GeognoSIS Service
	ServiceJaxerWeb        Service = "jaxer-web"       // Jaxer Web Protocol
	ServiceJaxerManager    Service = "jaxer-manager"   // Jaxer Manager Command Protocol
	ServicePubliqareSync   Service = "publiqare-sync"  // PubliQare Distributed Environment Synchronisation Engine
	ServiceDeySapi         Service = "dey-sapi"        // DEY Storage Administration
	ServiceGaia            Service = "gaia"            // Gaia Connector Protocol
	ServiceLispData        Service = "lisp-data"       // LISP Data Packets
	ServiceLispCons        Service = "lisp-cons"       // LISP-CONS Control
	ServiceLispControl     Service = "lisp-control"    // LISP Control Packets
	ServiceUnicall         Service = "unicall"         // UNICALL
	ServiceVinainstall     Service = "vinainstall"     // VinaInstall
	ServiceM4NetworkAs     Service = "m4-network-as"   // Macro 4 Network AS
	ServiceElanlm          Service = "elanlm"          // ELAN LM
	ServiceLansurveyor     Service = "lansurveyor"     // LAN Surveyor
	ServiceItose           Service = "itose"           // ITOSE
	ServiceFsportmap       Service = "fsportmap"       // File System Port Map
	ServiceNetDevice       Service = "net-device"      // Net Device
	ServicePlcyNetSvcs     Service = "plcy-net-svcs"   // PLCY Net Services
	ServicePjlink          Service = "pjlink"          // Projector Link
	ServiceF5Iquery        Service = "f5-iquery"       // F5 iQuery
	ServiceQsnetTrans      Service = "qsnet-trans"     // QSNet Transmitter
	ServiceQsnetWorkst     Service = "qsnet-workst"    // QSNet Workstation
	ServiceQsnetAssist     Service = "qsnet-assist"    // QSNet Assistant
	ServiceQsnetCond       Service = "qsnet-cond"      // QSNet Conductor
	ServiceQsnetNucl       Service = "qsnet-nucl"      // QSNet Nucleus
	ServiceOmabcastltkm    Service = "omabcastltkm"    // OMA BCAST Long-Term Key Messages
	ServiceMatrix_vnet     Service = "matrix_vnet"     // Matrix VNet Communication Protocol
	ServiceNacnl           Service = "nacnl"           // Navcom Discovery and Control Port
	ServiceAforeVdpDisc    Service = "afore-vdp-disc"  // AFORE vNode Discovery protocol
	ServiceWxbrief         Service = "wxbrief"         // WeatherBrief Direct
	ServiceEpmd            Service = "epmd"            // Erlang Port Mapper Daemon
	ServiceElpro_tunnel    Service = "elpro_tunnel"    // ELPRO V2 Protocol Tunnel
	ServiceL2cControl      Service = "l2c-control"     // LAN2CAN Control
	ServiceL2cDisc         Service = "l2c-disc"        // LAN2CAN Discovery
	ServiceL2cData         Service = "l2c-data"        // LAN2CAN Data
	ServiceRemctl          Service = "remctl"          // Remote Authenticated Command Service
	ServicePsiPtt          Service = "psi-ptt"         // PSI Push-to-Talk Protocol
	ServiceTolteces        Service = "tolteces"        // Toltec EasyShare
	ServiceBip             Service = "bip"             // BioAPI Interworking
	ServiceCpSpxsvr        Service = "cp-spxsvr"       // Cambridge Pixel SPx Server
	ServiceCpSpxdpy        Service = "cp-spxdpy"       // Cambridge Pixel SPx Display
	ServiceCtdb            Service = "ctdb"            // CTDB
	ServiceXandrosCms      Service = "xandros-cms"     // Xandros Community Management Service
	ServiceWiegand         Service = "wiegand"         // Physical Access Control
	ServiceApwiImserver    Service = "apwi-imserver"   // American Printware IMServer Protocol
	ServiceApwiRxserver    Service = "apwi-rxserver"   // American Printware RXServer Protocol
	ServiceApwiRxspooler   Service = "apwi-rxspooler"  // American Printware RXSpooler Protocol
	ServiceApwiDisc        Service = "apwi-disc"       // American Printware Discovery
	ServiceOmnivisionesx   Service = "omnivisionesx"   // OmniVision communication for Virtual environments
	ServiceFly             Service = "fly"             // Fly Object Space
	ServiceDsSrv           Service = "ds-srv"          // ASIGRA Services
	ServiceDsSrvr          Service = "ds-srvr"         // ASIGRA Televaulting DS-System Service
	ServiceDsClnt          Service = "ds-clnt"         // ASIGRA Televaulting DS-Client Service
	ServiceDsUser          Service = "ds-user"         // ASIGRA Televaulting DS-Client Monitoring/Management
	ServiceDsAdmin         Service = "ds-admin"        // ASIGRA Televaulting DS-System Monitoring/Management
	ServiceDsMail          Service = "ds-mail"         // ASIGRA Televaulting Message Level Restore service
	ServiceDsSlp           Service = "ds-slp"          // ASIGRA Televaulting DS-Sleeper Service
	ServiceNacagent        Service = "nacagent"        // Network Access Control Agent
	ServiceSlscc           Service = "slscc"           // SLS Technology Control Centre
	ServiceNetcabinetCom   Service = "netcabinet-com"  // Net-Cabinet comunication
	ServiceItwoServer      Service = "itwo-server"     // RIB iTWO Application Server
	ServiceFound           Service = "found"           // Found Messaging Protocol
	ServiceNetrockey6      Service = "netrockey6"      // NetROCKEY6 SMART Plus Service
	ServiceBeaconPort2     Service = "beacon-port-2"   // SMARTS Beacon Port
	ServiceDrizzle         Service = "drizzle"         // Drizzle database server
	ServiceOmviserver      Service = "omviserver"      // OMV-Investigation Server-Client
	ServiceOmviagent       Service = "omviagent"       // OMV Investigation Agent-Server
	ServiceSqlserver       Service = "sqlserver"       // REAL SQL Server
	ServiceRsqlserver      Service = "rsqlserver"      // REAL SQL Server
	ServiceWspipe          Service = "wspipe"          // adWISE Pipe
	ServiceLAcoustics      Service = "l-acoustics"     // L-ACOUSTICS management
	ServiceVop             Service = "vop"             // Versile Object Protocol
	ServiceNetblox         Service = "netblox"         // Netblox Protocol
	ServiceSaris           Service = "saris"           // Saris
	ServicePharos          Service = "pharos"          // Pharos
	ServiceUpnotifyp       Service = "upnotifyp"       // UPNOTIFYP
	ServiceN1Fwp           Service = "n1-fwp"          // N1-FWP
	ServiceN1Rmgmt         Service = "n1-rmgmt"        // N1-RMGMT
	ServiceAscSlmd         Service = "asc-slmd"        // ASC Licence Manager
	ServicePrivatewire     Service = "privatewire"     // PrivateWire
	ServiceCamp            Service = "camp"            // Camp
	ServiceCtisystemmsg    Service = "ctisystemmsg"    // CTI System Msg
	ServiceCtiprogramload  Service = "ctiprogramload"  // CTI Program Load
	ServiceNssalertmgr     Service = "nssalertmgr"     // NSS Alert Manager
	ServiceNssagentmgr     Service = "nssagentmgr"     // NSS Agent Manager
	ServicePrchatUser      Service = "prchat-user"     // PR Chat User
	ServicePrchatServer    Service = "prchat-server"   // PR Chat Server
	ServicePrRegister      Service = "prRegister"      // PR Register
	ServiceMcp             Service = "mcp"             // Matrix Configuration Protocol
	ServiceHpssmgmt        Service = "hpssmgmt"        // hpssmgmt service
	ServiceAssystDr        Service = "assyst-dr"       // Assyst Data Repository Service
	ServiceIcms            Service = "icms"            // Integrated Client Message Service
	ServicePrexTcp         Service = "prex-tcp"        // Protocol for Remote Execution over TCP
	ServiceAwacsIce        Service = "awacs-ice"       // Apple Wide Area Connectivity Service ICE Bootstrap
	ServiceIpsecNatT       Service = "ipsec-nat-t"     // IPsec NAT-Traversal
	ServiceA25FapFgw       Service = "a25-fap-fgw"     // A25 (FAP-FGW)
	ServiceArmagetronad    Service = "armagetronad"    // Armagetron Advanced Game
	ServiceEhs             Service = "ehs"             // Event Heap Server
	ServiceEhsSsl          Service = "ehs-ssl"         // Event Heap Server SSL
	ServiceWssauthsvc      Service = "wssauthsvc"      // WSS Security Service
	ServiceSwxGate         Service = "swx-gate"        // Software Data Exchange Gateway
	ServiceWorldscores     Service = "worldscores"     // WorldScores
	ServiceSfLm            Service = "sf-lm"           // SF License Manager (Sentinel)
	ServiceLannerLm        Service = "lanner-lm"       // Lanner License Manager
	ServiceSynchromesh     Service = "synchromesh"     // Synchromesh
	ServiceAegate          Service = "aegate"          // Aegate PMR Service
	ServiceGdsAdppiwDb     Service = "gds-adppiw-db"   // Perman I Interbase Server
	ServiceIeeeMih         Service = "ieee-mih"        // MIH Services
	ServiceMenandmiceMon   Service = "menandmice-mon"  // Men and Mice Monitoring
	ServiceIcshostsvc      Service = "icshostsvc"      // ICS host services
	ServiceMsfrs           Service = "msfrs"           // MS FRS Replication
	ServiceRsip            Service = "rsip"            // RSIP Port
	ServiceDtnBundleTcp    Service = "dtn-bundle-tcp"  // DTN Bundle TCP CL Protocol
	ServiceDtnBundleUdp    Service = "dtn-bundle-udp"  // DTN Bundle UDP CL Protocol
	ServiceMtcevrunqss     Service = "mtcevrunqss"     // Marathon everRun Quorum Service Server
	ServiceMtcevrunqman    Service = "mtcevrunqman"    // Marathon everRun Quorum Service Manager
	ServiceKwtc            Service = "kwtc"            // Kids Watch Time Control Service
	ServiceTram            Service = "tram"            // TRAM
	ServiceBmcReporting    Service = "bmc-reporting"   // BMC Reporting
	ServiceIax             Service = "iax"             // Inter-Asterisk eXchange
	ServiceRid             Service = "rid"             // RID over HTTP/TLS
	ServiceL3tAtAn         Service = "l3t-at-an"       // HRPD L3T (AT-AN)
	ServiceHrpdIthAtAn     Service = "hrpd-ith-at-an"  // HRPD-ITH (AT-AN)
	ServiceIptAnriAnri     Service = "ipt-anri-anri"   // IPT (ANRI-ANRI)
	ServiceIasSession      Service = "ias-session"     // IAS-Session (ANRI-ANRI)
	ServiceIasPaging       Service = "ias-paging"      // IAS-Paging (ANRI-ANRI)
	ServiceIasNeighbor     Service = "ias-neighbor"    // IAS-Neighbor (ANRI-ANRI)
	ServiceA21An1xbs       Service = "a21-an-1xbs"     // A21 (AN-1xBS)
	ServiceA16AnAn         Service = "a16-an-an"       // A16 (AN-AN)
	ServiceA17AnAn         Service = "a17-an-an"       // A17 (AN-AN)
	ServicePiranha1        Service = "piranha1"        // Piranha1
	ServicePiranha2        Service = "piranha2"        // Piranha2
	ServiceMtsserver       Service = "mtsserver"       // EAX MTS Server
	ServiceMenandmiceUpg   Service = "menandmice-upg"  // Men & Mice Upgrade Agent
	ServicePlaysta2App     Service = "playsta2-app"    // PlayStation2 App Port
	ServicePlaysta2Lob     Service = "playsta2-lob"    // PlayStation2 Lobby Port
	ServiceSmaclmgr        Service = "smaclmgr"        // smaclmgr
	ServiceKar2ouche       Service = "kar2ouche"       // Kar2ouche Peer location service
	ServiceOms             Service = "oms"             // OrbitNet Message Service
	ServiceNoteit          Service = "noteit"          // Note It! Message Service
	ServiceEms             Service = "ems"             // Rimage Messaging Server
	ServiceContclientms    Service = "contclientms"    // Container Client Message Service
	ServiceEportcomm       Service = "eportcomm"       // E-Port Message Service
	ServiceMmacomm         Service = "mmacomm"         // MMA Comm Services
	ServiceMmaeds          Service = "mmaeds"          // MMA EDS Service
	ServiceEportcommdata   Service = "eportcommdata"   // E-Port Data Service
	ServiceLight           Service = "light"           // Light packets transfer protocol
	ServiceActer           Service = "acter"           // Bull RSF action server
	ServiceRfa             Service = "rfa"             // remote file access server
	ServiceCxws            Service = "cxws"            // CXWS Operations
	ServiceAppiqMgmt       Service = "appiq-mgmt"      // AppIQ Agent Management
	ServiceDhctStatus      Service = "dhct-status"     // BIAP Device Status
	ServiceDhctAlerts      Service = "dhct-alerts"     // BIAP Generic Alert
	ServiceBcs             Service = "bcs"             // Business Continuity Servi
	ServiceTraversal       Service = "traversal"       // boundary traversal
	ServiceMgesupervision  Service = "mgesupervision"  // MGE UPS Supervision
	ServiceMgemanagement   Service = "mgemanagement"   // MGE UPS Management
	ServiceParliant        Service = "parliant"        // Parliant Telephony System
	ServiceFinisar         Service = "finisar"         // finisar
	ServiceSpike           Service = "spike"           // Spike Clipboard Service
	ServiceRfidRp1         Service = "rfid-rp1"        // RFID Reader Protocol 1.0
	ServiceAutopac         Service = "autopac"         // Autopac Protocol
	ServiceMspOs           Service = "msp-os"          // Manina Service Protocol
	ServiceNst             Service = "nst"             // Network Scanner Tool FTP
	ServiceMobileP2p       Service = "mobile-p2p"      // Mobile P2P Service
	ServiceAltovacentral   Service = "altovacentral"   // Altova DatabaseCentral
	ServicePrelude         Service = "prelude"         // Prelude IDS message proto
	ServiceMtn             Service = "mtn"             // Monotone Netsync Protocol
	ServiceConspiracy      Service = "conspiracy"      // Conspiracy messaging
	ServiceNetxmsAgent     Service = "netxms-agent"    // NetXMS Agent
	ServiceNetxmsMgmt      Service = "netxms-mgmt"     // NetXMS Management
	ServiceNetxmsSync      Service = "netxms-sync"     // NetXMS Server Synchronization
	ServiceNpqesTest       Service = "npqes-test"      // Network Performance Quality Evaluation System Test Service
	ServiceAssuriaIns      Service = "assuria-ins"     // Assuria Insider
	ServicePulseaudio      Service = "pulseaudio"      // Pulseaudio
	ServiceTruckstar       Service = "truckstar"       // TruckStar Service
	ServiceA26FapFgw       Service = "a26-fap-fgw"     // A26 (FAP-FGW)
	ServiceFcis            Service = "fcis"            // F-Link Client Information Service
	ServiceFcisDisc        Service = "fcis-disc"       // F-Link Client Information Service Discovery
	ServiceCapmux          Service = "capmux"          // CA Port Multiplexer
	ServiceGsmtap          Service = "gsmtap"          // GSM Interface Tap
	ServiceGearman         Service = "gearman"         // Gearman Job Queue System
	ServiceRemcap          Service = "remcap"          // Remote Capture Protocol
	ServiceOhmtrigger      Service = "ohmtrigger"      // OHM server trigger
	ServiceResorcs         Service = "resorcs"         // RES Orchestration Catalog Services
	ServiceIpdrSp          Service = "ipdr-sp"         // IPDR/SP
	ServiceSoleraLpn       Service = "solera-lpn"      // SoleraTec Locator
	ServiceIpfix           Service = "ipfix"           // IP Flow Info Export
	ServiceIpfixs          Service = "ipfixs"          // ipfix protocol over TLS
	ServiceLumimgrd        Service = "lumimgrd"        // Luminizer Manager
	ServiceSicct           Service = "sicct"           // SICCT
	ServiceSicctSdp        Service = "sicct-sdp"       // SICCT Service Discovery Protocol
	ServiceOpenhpid        Service = "openhpid"        // openhpi HPI service
	ServiceIfsp            Service = "ifsp"            // Internet File Synchronization Protocol
	ServiceFmp             Service = "fmp"             // Funambol Mobile Push
	ServiceBuschtrommel    Service = "buschtrommel"    // peer-to-peer file exchange
	ServiceProfilemac      Service = "profilemac"      // Profile for Mac
	ServiceSsad            Service = "ssad"            // Simple Service Auto Discovery
	ServiceSpocp           Service = "spocp"           // Simple Policy Control Protocol
	ServiceSnap            Service = "snap"            // Simple Network Audio Protocol
	ServiceSimon           Service = "simon"           // Simple Invocation of Methods
	ServiceSimonDisc       Service = "simon-disc"      // Over Network (SIMON)
	ServiceBfdMultiCtl     Service = "bfd-multi-ctl"   // BFD Multihop Control
	ServiceCncp            Service = "cncp"            // Cisco Nexus Control Protocol
	ServiceSmartInstall    Service = "smart-install"   // Smart Install Service
	ServiceSiaCtrlPlane    Service = "sia-ctrl-plane"  // Service Insertion Architecture (SIA) Control-Plane
	ServiceXmcp            Service = "xmcp"            // eXtensible Messaging Client Protocol
	ServiceIims            Service = "iims"            // Icona Instant Messenging System
	ServiceIwec            Service = "iwec"            // Icona Web Embedded Chat
	ServiceIlss            Service = "ilss"            // Icona License System Server
	ServiceNotateit        Service = "notateit"        // Notateit Messaging
	ServiceNotateitDisc    Service = "notateit-disc"   // Notateit Messaging Discovery
	ServiceAjaNtv4Disc     Service = "aja-ntv4-disc"   // AJA ntv4 Video System Discovery
	ServiceHtcp            Service = "htcp"            // HTCP
	ServiceVaradero0       Service = "varadero-0"      // Varadero-0
	ServiceVaradero1       Service = "varadero-1"      // Varadero-1
	ServiceVaradero2       Service = "varadero-2"      // Varadero-2
	ServiceOpcuaTcp        Service = "opcua-tcp"       // OPC UA TCP Protocol
	ServiceOpcuaUdp        Service = "opcua-udp"       // OPC UA TCP Protocol
	ServiceQuosa           Service = "quosa"           // QUOSA Virtual Library Service
	ServiceGwAsv           Service = "gw-asv"          // nCode ICE-flow Library AppServer
	ServiceOpcuaTls        Service = "opcua-tls"       // OPC UA TCP Protocol over TLS/SSL
	ServiceGwLog           Service = "gw-log"          // nCode ICE-flow Library LogServer
	ServiceWcrRemlib       Service = "wcr-remlib"      // WordCruncher Remote Library Service
	ServiceContamac_icm    Service = "contamac_icm"    // Contamac ICM Service
	ServiceWfc             Service = "wfc"             // Web Fresh Communication
	ServiceAppservHttp     Service = "appserv-http"    // App Server - Admin HTTP
	ServiceAppservHttps    Service = "appserv-https"   // App Server - Admin HTTPS
	ServiceSunAsNodeagt    Service = "sun-as-nodeagt"  // Sun App Server - NA
	ServiceDerbyRepli      Service = "derby-repli"     // Apache Derby Replication
	ServiceUnifyDebug      Service = "unify-debug"     // Unify Debugger
	ServicePhrelay         Service = "phrelay"         // Photon Relay
	ServicePhrelaydbg      Service = "phrelaydbg"      // Photon Relay Debug
	ServiceCcTracking      Service = "cc-tracking"     // Citcom Tracking Service
	ServiceWired           Service = "wired"           // Wired
	ServiceTritiumCan      Service = "tritium-can"     // Tritium CAN Bus Bridge Service
	ServiceLmcs            Service = "lmcs"            // Lighting Management Control System
	ServiceInstDiscovery   Service = "inst-discovery"  // Agilent Instrument Discovery
	ServiceWsdlEvent       Service = "wsdl-event"      // WSDL Event Receiver
	ServiceHislip          Service = "hislip"          // IVI High-Speed LAN Instrument Protocol
	ServiceSocpT           Service = "socp-t"          // SOCP Time Synchronization Protocol
	ServiceSocpC           Service = "socp-c"          // SOCP Control Protocol
	ServiceWmlserver       Service = "wmlserver"       // Meier-Phelps License Server
	ServiceHivestor        Service = "hivestor"        // HiveStor Distributed File System
	ServiceAbbs            Service = "abbs"            // ABBS
	ServiceLyskom          Service = "lyskom"          // LysKOM Protocol A
	ServiceRadminPort      Service = "radmin-port"     // RAdmin Port
	ServiceHfcs            Service = "hfcs"            // HyperFileSQL Client/Server Database Engine
	ServiceFlr_agent       Service = "flr_agent"       // FileLocator Remote Search Agent
	ServiceMagiccontrol    Service = "magiccontrol"    // magicCONROL RF and Data Interface
	ServiceLutap           Service = "lutap"           // Technicolor LUT Access Protocol
	ServiceLutcp           Service = "lutcp"           // LUTher Control Protocol
	ServiceBones           Service = "bones"           // Bones Remote Control
	ServiceFrcs            Service = "frcs"            // Fibics Remote Control Service
	ServiceAtscMhSsc       Service = "atsc-mh-ssc"     // ATSC-M/H Service Signaling Channel
	ServiceEqOffice4940    Service = "eq-office-4940"  // Equitrac Office
	ServiceEqOffice4941    Service = "eq-office-4941"  // Equitrac Office
	ServiceEqOffice4942    Service = "eq-office-4942"  // Equitrac Office
	ServiceMunin           Service = "munin"           // Munin Graphing Framework
	ServiceSybasesrvmon    Service = "sybasesrvmon"    // Sybase Server Monitor
	ServicePwgwims         Service = "pwgwims"         // PWG WIMS
	ServiceSagxtsds        Service = "sagxtsds"        // SAG Directory Server
	ServiceDbsyncarbiter   Service = "dbsyncarbiter"   // Synchronization Arbiter
	ServiceCcssQmm         Service = "ccss-qmm"        // CCSS QMessageMonitor
	ServiceCcssQsm         Service = "ccss-qsm"        // CCSS QSystemMonitor
	ServiceWebyast         Service = "webyast"         // WebYast
	ServiceGerhcs          Service = "gerhcs"          // GER HC Standard
	ServiceMrip            Service = "mrip"            // Model Railway Interface Program
	ServiceSmarSePort1     Service = "smar-se-port1"   // SMAR Ethernet Port 1
	ServiceSmarSePort2     Service = "smar-se-port2"   // SMAR Ethernet Port 2
	ServiceParallel        Service = "parallel"        // Parallel for GAUSS (tm)
	ServiceBusycal         Service = "busycal"         // BusySync Calendar Synch. Protocol
	ServiceVrt             Service = "vrt"             // VITA Radio Transport
	ServiceHfcsManager     Service = "hfcs-manager"    // Hyper File Client/Server Database Engine Manager
	ServiceCommplexMain    Service = "commplex-main"   //
	ServiceCommplexLink    Service = "commplex-link"   //
	ServiceFmproInternal   Service = "fmpro-internal"  // FileMaker, Inc. - Proprietary transport
	ServiceAvtProfile1     Service = "avt-profile-1"   // RTP media data [RFC 3551, RFC 4571]
	ServiceAvtProfile2     Service = "avt-profile-2"   // RTP control protocol [RFC 3551, RFC 4571]
	ServiceWsmServer       Service = "wsm-server"      // wsm server
	ServiceWsmServerSsl    Service = "wsm-server-ssl"  // wsm server ssl
	ServiceSynapsisEdge    Service = "synapsis-edge"   // Synapsis EDGE
	ServiceWinfs           Service = "winfs"           // Microsoft Windows Filesystem
	ServiceTelelpathstart  Service = "telelpathstart"  // TelepathStart
	ServiceTelelpathattack Service = "telelpathattack" // TelepathAttack
	ServiceNsp             Service = "nsp"             // NetOnTap Service
	ServiceFmproV6         Service = "fmpro-v6"        // FileMaker, Inc. - Proprietary transport
	ServiceOnpsocket       Service = "onpsocket"       // Overlay Network Protocol
	ServiceFmwp            Service = "fmwp"            // FileMaker, Inc. - Web publishing
	ServiceZenginkyo1      Service = "zenginkyo-1"     // zenginkyo-1
	ServiceZenginkyo2      Service = "zenginkyo-2"     // zenginkyo-2
	ServiceMice            Service = "mice"            // mice server
	ServiceHtuilsrv        Service = "htuilsrv"        // Htuil Server for PLD2
	ServiceScpiTelnet      Service = "scpi-telnet"     // SCPI-TELNET
	ServiceScpiRaw         Service = "scpi-raw"        // SCPI-RAW
	ServiceStrexecD        Service = "strexec-d"       // Storix I/O daemon (data)
	ServiceStrexecS        Service = "strexec-s"       // Storix I/O daemon (stat)
	ServiceQvr             Service = "qvr"             // Quiqum Virtual Relais
	ServiceInfobright      Service = "infobright"      // Infobright Database Server
	ServiceSurfpass        Service = "surfpass"        // SurfPass
	ServiceDmp             Service = "dmp"             // Direct Message Protocol
	ServiceSignacertAgent  Service = "signacert-agent" // SignaCert Enterprise Trust Server Agent
	ServiceAsnaacceler8db  Service = "asnaacceler8db"  // asnaacceler8db
	ServiceSwxadmin        Service = "swxadmin"        // ShopWorX Administration
	ServiceLxiEvntsvc      Service = "lxi-evntsvc"     // LXI Event Service
	ServiceOsp             Service = "osp"             // Open Settlement Protocol
	ServiceVpmUdp          Service = "vpm-udp"         // Vishay PM UDP Service
	ServiceIscape          Service = "iscape"          // iSCAPE Data Broadcasting
	ServiceTexai           Service = "texai"           // Texai Message Service
	ServiceIvocalize       Service = "ivocalize"       // iVocalize Web Conference
	ServiceMmcc            Service = "mmcc"            // multimedia conference control tool
	ServiceItaAgent        Service = "ita-agent"       // ITA Agent
	ServiceItaManager      Service = "ita-manager"     // ITA Manager
	ServiceRlm             Service = "rlm"             // RLM License Server
	ServiceRlmDisc         Service = "rlm-disc"        // RLM Discovery Server
	ServiceRlmAdmin        Service = "rlm-admin"       // RLM administrative interface
	ServiceUnot            Service = "unot"            // UNOT
	ServiceIntecomPs1      Service = "intecom-ps1"     // Intecom Pointspan 1
	ServiceIntecomPs2      Service = "intecom-ps2"     // Intecom Pointspan 2
	ServiceLocusDisc       Service = "locus-disc"      // Locus Discovery
	ServiceSds             Service = "sds"             // SIP Directory Services
	ServiceSip             Service = "sip"             // SIP
	ServiceSipTls          Service = "sip-tls"         // SIP-TLS
	ServiceNaLocalise      Service = "na-localise"     // Localisation access
	ServiceCsrpc           Service = "csrpc"           // centrify secure RPC
	ServiceCa1             Service = "ca-1"            // Channel Access 1
	ServiceCa2             Service = "ca-2"            // Channel Access 2
	ServiceStanag5066      Service = "stanag-5066"     // STANAG-5066-SUBNET-INTF
	ServiceAuthentx        Service = "authentx"        // Authentx Service
	ServiceBitforestsrv    Service = "bitforestsrv"    // Bitforest Data Service
	ServiceINet2000Npr     Service = "i-net-2000-npr"  // I/Net 2000-NPR
	ServiceVtsas           Service = "vtsas"           // VersaTrans Server Agent Service
	ServicePowerschool     Service = "powerschool"     // PowerSchool
	ServiceAyiya           Service = "ayiya"           // Anything In Anything
	ServiceTagPm           Service = "tag-pm"          // Advantage Group Port Mgr
	ServiceAlesquery       Service = "alesquery"       // ALES Query
	ServicePvaccess        Service = "pvaccess"        // Experimental Physics and Industrial Control System
	ServiceCpSpxrpts       Service = "cp-spxrpts"      // Cambridge Pixel SPx Reports
	ServiceOnscreen        Service = "onscreen"        // OnScreen Data Collection Service
	ServiceSdlEts          Service = "sdl-ets"         // SDL - Ent Trans Server
	ServiceQcp             Service = "qcp"             // Qpur Communication Protocol
	ServiceQfp             Service = "qfp"             // Qpur File Protocol
	ServiceLlrp            Service = "llrp"            // EPCglobal Low-Level Reader Protocol
	ServiceEncryptedLlrp   Service = "encrypted-llrp"  // EPCglobal Encrypted LLRP
	ServiceAprigoCs        Service = "aprigo-cs"       // Aprigo Collection Service
	ServiceCar             Service = "car"             // Candidate AR
	ServiceCxtp            Service = "cxtp"            // Context Transfer Protocol
	ServiceMagpie          Service = "magpie"          // Magpie Binary
	ServiceSentinelLm      Service = "sentinel-lm"     // Sentinel LM
	ServiceHartIp          Service = "hart-ip"         // HART-IP
	ServiceSentlmSrv2srv   Service = "sentlm-srv2srv"  // SentLM Srv2Srv
	ServiceSocalia         Service = "socalia"         // Socalia service mux
	ServiceTalarianTcp     Service = "talarian-tcp"    // Talarian_TCP
	ServiceTalarianUdp     Service = "talarian-udp"    // Talarian_UDP
	ServiceOmsNonsecure    Service = "oms-nonsecure"   // Oracle OMS non-secure
	ServiceActifioC2c      Service = "actifio-c2c"     // Actifio C2C
	ServiceTinymessage     Service = "tinymessage"     // TinyMessage
	ServiceHughesAp        Service = "hughes-ap"       // Hughes Association Protocol
	ServiceTaepAsSvc       Service = "taep-as-svc"     // TAEP AS service
	ServicePmCmdsvr        Service = "pm-cmdsvr"       // PeerMe Msg Cmd Service
	ServiceEvServices      Service = "ev-services"     // Enterprise Vault Services
	ServiceAutobuild       Service = "autobuild"       // Symantec Autobuild Service
	ServiceEmbProjCmd      Service = "emb-proj-cmd"    // EPSON Projecter Image Transfer
	ServiceGradecam        Service = "gradecam"        // GradeCam Image Processing
	ServiceBarracudaBbs    Service = "barracuda-bbs"   // Barracuda Backup Protocol
	ServiceNbtPc           Service = "nbt-pc"          // Policy Commander
	ServicePpactivation    Service = "ppactivation"    // PP ActivationServer
	ServiceErpScale        Service = "erp-scale"       // ERP-Scale
	ServiceMinotaurSa      Service = "minotaur-sa"     // Minotaur SA
	ServiceCtsd            Service = "ctsd"            // MyCTS server port
	ServiceRmonitor_secure Service = "rmonitor_secure" // RMONITOR SECURE
	ServiceSocialAlarm     Service = "social-alarm"    // Social Alarm Service
	ServiceAtmp            Service = "atmp"            // Ascend Tunnel Management Protocol
	ServiceEsri_sde        Service = "esri_sde"        // ESRI SDE Instance
	ServiceSdeDiscovery    Service = "sde-discovery"   // ESRI SDE Instance Discovery
	ServiceToruxserver     Service = "toruxserver"     // ToruX Game Server
	ServiceBzflag          Service = "bzflag"          // BZFlag game server
	ServiceAsctrlAgent     Service = "asctrl-agent"    // Oracle asControl Agent
	ServiceRugameonline    Service = "rugameonline"    // Russian Online Game
	ServiceMediat          Service = "mediat"          // Mediat Remote Object Exchange
	ServiceSnmpssh         Service = "snmpssh"         // SNMP over SSH Transport Model
	ServiceSnmpsshTrap     Service = "snmpssh-trap"    // SNMP Notification over SSH Transport Model
	ServiceSbackup         Service = "sbackup"         // Shadow Backup
	ServiceVpa             Service = "vpa"             // Virtual Protocol Adapter
	ServiceVpaDisc         Service = "vpa-disc"        // Virtual Protocol Adapter Discovery
	ServiceIfe_icorp       Service = "ife_icorp"       // ife_1corp
	ServiceWinpcs          Service = "winpcs"          // WinPCS Service Connection
	ServiceScte104         Service = "scte104"         // SCTE104 Connection
	ServiceScte30          Service = "scte30"          // SCTE30 Connection
	ServiceAol             Service = "aol"             // America-Online
	ServiceAol1            Service = "aol-1"           // AmericaOnline1
	ServiceAol2            Service = "aol-2"           // AmericaOnline2
	ServiceAol3            Service = "aol-3"           // AmericaOnline3
	ServiceCpscomm         Service = "cpscomm"         // CipherPoint Config Service
	ServiceAmplLic         Service = "ampl-lic"        // AMPL_Optimization - program licenses
	ServiceAmplTableproxy  Service = "ampl-tableproxy" // AMPL_Optimization - table data
	ServiceTargusGetdata   Service = "targus-getdata"  // TARGUS GetData
	ServiceTargusGetdata1  Service = "targus-getdata1" // TARGUS GetData 1
	ServiceTargusGetdata2  Service = "targus-getdata2" // TARGUS GetData 2
	ServiceTargusGetdata3  Service = "targus-getdata3" // TARGUS GetData 3
	ServiceNomad           Service = "nomad"           // Nomad Device Video Transfer
	Service3exmp           Service = "3exmp"           // 3eTI Extensible Management Protocol for OAMP
	ServiceXmppClient      Service = "xmpp-client"     // XMPP Client Connection
	ServiceHpvirtgrp       Service = "hpvirtgrp"       // HP Virtual Machine Group Management
	ServiceHpvirtctrl      Service = "hpvirtctrl"      // HP Virtual Machine Console Operations
	ServiceHpServer        Service = "hp-server"       // HP Server
	ServiceHpStatus        Service = "hp-status"       // HP Status
	ServicePerfd           Service = "perfd"           // HP System Performance Metric Service
	ServiceHpvroom         Service = "hpvroom"         // HP Virtual Room Service
	ServiceEnfs            Service = "enfs"            // Etinnae Network File Service
	ServiceEenet           Service = "eenet"           // EEnet communications
	ServiceGalaxyNetwork   Service = "galaxy-network"  // Galaxy Network Service
	ServicePadl2sim        Service = "padl2sim"        //
	ServiceMnetDiscovery   Service = "mnet-discovery"  // m-net discovery
	ServiceDowntools       Service = "downtools"       // DownTools Control Protocol
	ServiceDowntoolsDisc   Service = "downtools-disc"  // DownTools Discovery Protocol
	ServiceCapwapControl   Service = "capwap-control"  // CAPWAP Control Protocol
	ServiceCapwapData      Service = "capwap-data"     // CAPWAP Data Protocol
	ServiceCaacws          Service = "caacws"          // CA Access Control Web Service
	ServiceCaaclang2       Service = "caaclang2"       // CA AC Lang Service
	ServiceSoagateway      Service = "soagateway"      // soaGateway
	ServiceCaevms          Service = "caevms"          // CA eTrust VM Service
	ServiceMovazSsc        Service = "movaz-ssc"       // Movaz SSC
	ServiceKpdp            Service = "kpdp"            // Kohler Power Device Protocol
	Service3comNjack1      Service = "3com-njack-1"    // 3Com Network Jack Port 1
	Service3comNjack2      Service = "3com-njack-2"    // 3Com Network Jack Port 2
	ServiceXmppServer      Service = "xmpp-server"     // XMPP Server Connection
	ServiceCartographerxmp Service = "cartographerxmp" // Cartographer XMP
	ServiceCuelink         Service = "cuelink"         // StageSoft CueLink messaging
	ServiceCuelinkDisc     Service = "cuelink-disc"    // StageSoft CueLink discovery
	ServicePk              Service = "pk"              // PK
	ServiceXmppBosh        Service = "xmpp-bosh"       // Bidirectional-streams Over Synchronous HTTP (BOSH)
	ServiceUndoLm          Service = "undo-lm"         // Undo License Manager
	ServiceTransmitPort    Service = "transmit-port"   // Marimba Transmitter Port
	ServicePresence        Service = "presence"        // XMPP Link-Local Messaging
	ServiceNlgData         Service = "nlg-data"        // NLG Data Service
	ServiceHaclHb          Service = "hacl-hb"         // HA cluster heartbeat
	ServiceHaclGs          Service = "hacl-gs"         // HA cluster general services
	ServiceHaclCfg         Service = "hacl-cfg"        // HA cluster configuration
	ServiceHaclProbe       Service = "hacl-probe"      // HA cluster probing
	ServiceHaclLocal       Service = "hacl-local"      // HA Cluster Commands
	ServiceHaclTest        Service = "hacl-test"       // HA Cluster Test
	ServiceSunMcGrp        Service = "sun-mc-grp"      // Sun MC Group
	ServiceScoAip          Service = "sco-aip"         // SCO AIP
	ServiceJprinter        Service = "jprinter"        // J Printer
	ServiceOutlaws         Service = "outlaws"         // Outlaws
	ServicePermabitCs      Service = "permabit-cs"     // Permabit Client-Server
	ServiceRrdp            Service = "rrdp"            // Real-time & Reliable Data
	ServiceOpalisRbtIpc    Service = "opalis-rbt-ipc"  // opalis-rbt-ipc
	ServiceHaclPoll        Service = "hacl-poll"       // HA Cluster UDP Polling
	ServiceHpbladems       Service = "hpbladems"       // HPBladeSystem Monitor Service
	ServiceHpdevms         Service = "hpdevms"         // HP Device Monitor Service
	ServicePkixCmc         Service = "pkix-cmc"        // PKIX Certificate
	ServiceBsfserverZn     Service = "bsfserver-zn"    // Webservices-based Zn interface of BSF
	ServiceBsfsvrZnSsl     Service = "bsfsvr-zn-ssl"   // Webservices-based Zn interface of BSF over SSL
	ServiceKfserver        Service = "kfserver"        // Sculptor Database Server
	ServiceXkotodrcp       Service = "xkotodrcp"       // xkoto DRCP
	ServiceStuns           Service = "stuns"           // STUN over TLS, TURN over TLS
	ServicePcpMulticast    Service = "pcp-multicast"   // Port Control Protocol
	ServicePcp             Service = "pcp"             // Port Control Protocol
	ServiceDnsLlq          Service = "dns-llq"         // DNS Long-Lived Queries
	ServiceMdns            Service = "mdns"            // Multicast DNS
	ServiceMdnsresponder   Service = "mdnsresponder"   // Multicast DNS Responder IPC
	ServiceMsSmlbiz        Service = "ms-smlbiz"       // Microsoft Small Business
	ServiceWsdapi          Service = "wsdapi"          // Web Services for Devices
	ServiceWsdapiS         Service = "wsdapi-s"        // WS for Devices Secured
	ServiceMsAlerter       Service = "ms-alerter"      // Microsoft Alerter
	ServiceMsSideshow      Service = "ms-sideshow"     // Protocol for Windows SideShow
	ServiceMsSSideshow     Service = "ms-s-sideshow"   // Secure Protocol for Windows SideShow
	ServiceServerwsd2      Service = "serverwsd2"      // Microsoft Windows Server WSD2 Service
	ServiceNetProjection   Service = "net-projection"  // Windows Network Projection
	ServiceStresstester    Service = "stresstester"    // StressTester(tm) Injector
	ServiceElektronAdmin   Service = "elektron-admin"  // Elektron Administration
	ServiceSecuritychase   Service = "securitychase"   // SecurityChase
	ServiceExcerpt         Service = "excerpt"         // Excerpt Search
	ServiceExcerpts        Service = "excerpts"        // Excerpt Search Secure
	ServiceHpomsCiLstn     Service = "hpoms-ci-lstn"   // HPOMS-CI-LSTN
	ServiceHpomsDpsLstn    Service = "hpoms-dps-lstn"  // HPOMS-DPS-LSTN
	ServiceNetsupport      Service = "netsupport"      // NetSupport
	ServiceSystemicsSox    Service = "systemics-sox"   // Systemics Sox
	ServiceForesyteClear   Service = "foresyte-clear"  // Foresyte-Clear
	ServiceForesyteSec     Service = "foresyte-sec"    // Foresyte-Sec
	ServiceSalientDtasrv   Service = "salient-dtasrv"  // Salient Data Server
	ServiceSalientUsrmgr   Service = "salient-usrmgr"  // Salient User Manager
	ServiceActnet          Service = "actnet"          // ActNet
	ServiceContinuus       Service = "continuus"       // Continuus
	ServiceWwiotalk        Service = "wwiotalk"        // WWIOTALK
	ServiceStatusd         Service = "statusd"         // StatusD
	ServiceNsServer        Service = "ns-server"       // NS Server
	ServiceSnsGateway      Service = "sns-gateway"     // SNS Gateway
	ServiceSnsAgent        Service = "sns-agent"       // SNS Agent
	ServiceMcntp           Service = "mcntp"           // MCNTP
	ServiceDjIce           Service = "dj-ice"          // DJ-ICE
	ServiceCylinkC         Service = "cylink-c"        // Cylink-C
	ServiceNetsupport2     Service = "netsupport2"     // Net Support 2
	ServiceSalientMux      Service = "salient-mux"     // Salient MUX
	ServiceVirtualuser     Service = "virtualuser"     // VIRTUALUSER
	ServiceBeyondRemote    Service = "beyond-remote"   // Beyond Remote
	ServiceBrChannel       Service = "br-channel"      // Beyond Remote Command Channel
	ServiceDevbasic        Service = "devbasic"        // DEVBASIC
	ServiceScoPeerTta      Service = "sco-peer-tta"    // SCO-PEER-TTA
	ServiceTelaconsole     Service = "telaconsole"     // TELACONSOLE
	ServiceBase            Service = "base"            // Billing and Accounting System Exchange
	ServiceRadecCorp       Service = "radec-corp"      // RADEC CORP
	ServiceParkAgent       Service = "park-agent"      // PARK AGENT
	ServicePyrrho          Service = "pyrrho"          // Pyrrho DBMS
	ServiceSgiArrayd       Service = "sgi-arrayd"      // SGI Array Services Daemon
	ServiceSceanics        Service = "sceanics"        // SCEANICS situation and action notification
	ServicePmip6Cntl       Service = "pmip6-cntl"      // pmip6-cntl
	ServicePmip6Data       Service = "pmip6-data"      // pmip6-data
	ServiceSpss            Service = "spss"            // Pearson HTTPS
	ServiceSmbdirect       Service = "smbdirect"       // Server Message Block over Remote Direct Memory Access
	ServiceSurebox         Service = "surebox"         // SureBox
	ServiceApc5454         Service = "apc-5454"        // APC 5454
	ServiceApc5455         Service = "apc-5455"        // APC 5455
	ServiceApc5456         Service = "apc-5456"        // APC 5456
	ServiceSilkmeter       Service = "silkmeter"       // SILKMETER
	ServiceTtlPublisher    Service = "ttl-publisher"   // TTL Publisher
	ServiceTtlpriceproxy   Service = "ttlpriceproxy"   // TTL Price Proxy
	ServiceQuailnet        Service = "quailnet"        // Quail Networks Object Broker
	ServiceNetopsBroker    Service = "netops-broker"   // NETOPS-BROKER
	ServiceFcpAddrSrvr1    Service = "fcp-addr-srvr1"  // fcp-addr-srvr1
	ServiceFcpAddrSrvr2    Service = "fcp-addr-srvr2"  // fcp-addr-srvr2
	ServiceFcpSrvrInst1    Service = "fcp-srvr-inst1"  // fcp-srvr-inst1
	ServiceFcpSrvrInst2    Service = "fcp-srvr-inst2"  // fcp-srvr-inst2
	ServiceFcpCicsGw1      Service = "fcp-cics-gw1"    // fcp-cics-gw1
	ServiceCheckoutdb      Service = "checkoutdb"      // Checkout Database
	ServiceAmc             Service = "amc"             // Amcom Mobile Connect
	ServiceSgiEventmond    Service = "sgi-eventmond"   // SGI Eventmond Port
	ServiceSgiEsphttp      Service = "sgi-esphttp"     // SGI ESP HTTP
	ServicePersonalAgent   Service = "personal-agent"  // Personal Agent
	ServiceFreeciv         Service = "freeciv"         // Freeciv gameplay
	ServiceFarenet         Service = "farenet"         // Sandlab FARENET
	ServiceWestecConnect   Service = "westec-connect"  // Westec Connect
	ServiceEncEpsMcSec     Service = "enc-eps-mc-sec"  // EMIT protocol stack
	ServiceSdt             Service = "sdt"             // Session Data Transport Multicast
	ServiceRdmnetCtrl      Service = "rdmnet-ctrl"     // Management (RDM) controller status notifications
	ServiceRdmnetDevice    Service = "rdmnet-device"   // PLASA E1.33, Remote Device Management (RDM) messages
	ServiceSdmmp           Service = "sdmmp"           // SAS Domain Management Messaging Protocol
	ServiceLsiBobcat       Service = "lsi-bobcat"      // SAS IO Forwarding
	ServiceOraOap          Service = "ora-oap"         // Oracle Access Protocol
	ServiceFdtracks        Service = "fdtracks"        // FleetDisplay Tracking Service
	ServiceTmosms0         Service = "tmosms0"         // T-Mobile SMS Protocol Message 0
	ServiceTmosms1         Service = "tmosms1"         // T-Mobile SMS Protocol Message 1
	ServiceFacRestore      Service = "fac-restore"     // T-Mobile SMS Protocol Message 3
	ServiceTmoIconSync     Service = "tmo-icon-sync"   // T-Mobile SMS Protocol Message 2
	ServiceBisWeb          Service = "bis-web"         // BeInSync-Web
	ServiceBisSync         Service = "bis-sync"        // BeInSync-sync
	ServiceIninmessaging   Service = "ininmessaging"   // inin secure messaging
	ServiceMctfeed         Service = "mctfeed"         // MCT Market Data Feed
	ServiceEsinstall       Service = "esinstall"       // Enterprise Security Remote Install
	ServiceEsmmanager      Service = "esmmanager"      // Enterprise Security Manager
	ServiceEsmagent        Service = "esmagent"        // Enterprise Security Agent
	ServiceA1Msc           Service = "a1-msc"          // A1-MSC
	ServiceA1Bs            Service = "a1-bs"           // A1-BS
	ServiceA3Sdunode       Service = "a3-sdunode"      // A3-SDUNode
	ServiceA4Sdunode       Service = "a4-sdunode"      // A4-SDUNode
	ServiceNinaf           Service = "ninaf"           // Node Initiated Network Association Forma
	ServiceHtrust          Service = "htrust"          // HTrust API
	ServiceSymantecSfdb    Service = "symantec-sfdb"   // Symantec Storage Foundation for Database
	ServicePreciseComm     Service = "precise-comm"    // PreciseCommunication
	ServicePcanywheredata  Service = "pcanywheredata"  // pcANYWHEREdata
	ServicePcanywherestat  Service = "pcanywherestat"  // pcANYWHEREstat
	ServiceBeorl           Service = "beorl"           // BE Operations Request Listener
	ServiceXprtld          Service = "xprtld"          // SF Message Service
	ServiceSfmsso          Service = "sfmsso"          // SFM Authentication Subsystem
	ServiceSfmDbServer     Service = "sfm-db-server"   // SFMdb - SFM DB server
	ServiceCssc            Service = "cssc"            // Symantec CSSC
	ServiceFlcrs           Service = "flcrs"           // Symantec Fingerprint Lookup and Container Reference
	ServiceIcs             Service = "ics"             // Symantec Integrity Checking
	ServiceVfmobile        Service = "vfmobile"        // Ventureforth Mobile
	ServiceFilemq          Service = "filemq"          // ZeroMQ file
	ServiceZreDisc         Service = "zre-disc"        // Local area discovery and msging over ZeroMQ
	ServiceAmqps           Service = "amqps"           // amqp protocol over TLS/SSL
	ServiceAmqp            Service = "amqp"            // AMQP
	ServiceJms             Service = "jms"             // JACL Message Server
	ServiceHyperscsiPort   Service = "hyperscsi-port"  // HyperSCSI Port
	ServiceV5ua            Service = "v5ua"            // V5UA application port
	ServiceRaadmin         Service = "raadmin"         // RA Administration
	ServiceQuestdb2Lnchr   Service = "questdb2-lnchr"  // Quest Central DB2 Launchr
	ServiceRrac            Service = "rrac"            // Remote Replication Agent Connection
	ServiceDccm            Service = "dccm"            // Direct Cable Connect Manager
	ServiceAurigaRouter    Service = "auriga-router"   // Auriga Router Service
	ServiceNcxcp           Service = "ncxcp"           // Net-coneX Control Protocol
	ServiceBrightcore      Service = "brightcore"      // BrightCore control & data transfer exchange
	ServiceCoap            Service = "coap"            // Constrained Application Protocol
	ServiceGgz             Service = "ggz"             // GGZ Gaming Zone
	ServiceQmvideo         Service = "qmvideo"         // QM video network management protocol
	ServiceRbsystem        Service = "rbsystem"        // Robert Bosch Data Transfer
	ServiceKmip            Service = "kmip"            // Key Management Interoperability Protocol
	ServiceProshareaudio   Service = "proshareaudio"   // proshare conf audio
	ServiceProsharevideo   Service = "prosharevideo"   // proshare conf video
	ServiceProsharedata    Service = "prosharedata"    // proshare conf data
	ServiceProsharerequest Service = "prosharerequest" // proshare conf request
	ServiceProsharenotify  Service = "prosharenotify"  // proshare conf notify
	ServiceDpm             Service = "dpm"             // DPM Communication Server
	ServiceDpmAgent        Service = "dpm-agent"       // DPM Agent Coordinator
	ServiceMsLicensing     Service = "ms-licensing"    // MS-Licensing
	ServiceDtpt            Service = "dtpt"            // Desktop Passthru Service
	ServiceMsdfsr          Service = "msdfsr"          // Microsoft DFS Replication Service
	ServiceOmhs            Service = "omhs"            // Operations Manager - Health Service
	ServiceOmsdk           Service = "omsdk"           // Operations Manager - SDK Service
	ServiceMsIlm           Service = "ms-ilm"          // Microsoft Identity Lifecycle Manager
	ServiceMsIlmSts        Service = "ms-ilm-sts"      // Microsoft Lifecycle Manager Secure Token Service
	ServiceAsgenf          Service = "asgenf"          // ASG Event Notification Framework
	ServiceIoDistData      Service = "io-dist-data"    // Dist. I/O Comm. Service Data and Control
	ServiceIoDistGroup     Service = "io-dist-group"   // Dist. I/O Comm. Service Group Membership
	ServiceOpenmail        Service = "openmail"        // Openmail User Agent Layer
	ServiceUnieng          Service = "unieng"          // Steltor's calendar access
	ServiceIdaDiscover1    Service = "ida-discover1"   // IDA Discover Port 1
	ServiceIdaDiscover2    Service = "ida-discover2"   // IDA Discover Port 2
	ServiceWatchdocPod     Service = "watchdoc-pod"    // Watchdoc NetPOD Protocol
	ServiceWatchdoc        Service = "watchdoc"        // Watchdoc Server
	ServiceFcopyServer     Service = "fcopy-server"    // fcopy-server
	ServiceFcopysServer    Service = "fcopys-server"   // fcopys-server
	ServiceTunatic         Service = "tunatic"         // Wildbits Tunatic
	ServiceTunalyzer       Service = "tunalyzer"       // Wildbits Tunalyzer
	ServiceRscd            Service = "rscd"            // Bladelogic Agent Service
	ServiceOpenmailg       Service = "openmailg"       // OpenMail Desk Gateway server
	ServiceX500ms          Service = "x500ms"          // OpenMail X.500 Directory Server
	ServiceOpenmailns      Service = "openmailns"      // OpenMail NewMail Server
	ServiceSOpenmail       Service = "s-openmail"      // OpenMail Suer Agent Layer (Secure)
	ServiceOpenmailpxy     Service = "openmailpxy"     // OpenMail CMTS Server
	ServiceSpramsca        Service = "spramsca"        // x509solutions Internal CA
	ServiceSpramsd         Service = "spramsd"         // x509solutions Secure Data
	ServiceNetagent        Service = "netagent"        // NetAgent
	ServiceDaliPort        Service = "dali-port"       // DALI Port
	ServiceVtsRpc          Service = "vts-rpc"         // Visual Tag System RPC
	Service3parEvts        Service = "3par-evts"       // 3PAR Event Reporting Service
	Service3parMgmt        Service = "3par-mgmt"       // 3PAR Management Service
	Service3parMgmtSsl     Service = "3par-mgmt-ssl"   // 3PAR Management Service with SSL
	ServiceIbar            Service = "ibar"            // Cisco Interbox Application Redundancy
	Service3parRcopy       Service = "3par-rcopy"      // 3PAR Inform Remote Copy
	ServiceCiscoRedu       Service = "cisco-redu"      // redundancy notification
	ServiceWaascluster     Service = "waascluster"     // Cisco WAAS Cluster Protocol
	ServiceXtreamx         Service = "xtreamx"         // XtreamX Supervised Peer message
	ServiceSpdp            Service = "spdp"            // Simple Peered Discovery Protocol
	ServiceIcmpd           Service = "icmpd"           // ICMPD
	ServiceSptAutomation   Service = "spt-automation"  // Support Automation
	ServiceReversion       Service = "reversion"       // Reversion Backup/Restore
	ServiceWherehoo        Service = "wherehoo"        // WHEREHOO
	ServicePpsuitemsg      Service = "ppsuitemsg"      // PlanetPress Suite Messeng
	ServiceDiameters       Service = "diameters"       // Diameter over TLS/TCP
	ServiceJute            Service = "jute"            // Javascript Unit Test Environment
	ServiceRfb             Service = "rfb"             // Remote Framebuffer
	ServiceCm              Service = "cm"              // Context Management
	ServiceCpdlc           Service = "cpdlc"           // Controller Pilot Data Link Communication
	ServiceFis             Service = "fis"             // Flight Information Services
	ServiceAdsC            Service = "ads-c"           // Automatic Dependent Surveillance
	ServiceIndy            Service = "indy"            // Indy Application Server
	ServiceMppolicyV5      Service = "mppolicy-v5"     // mppolicy-v5
	ServiceMppolicyMgr     Service = "mppolicy-mgr"    // mppolicy-mgr
	ServiceCouchdb         Service = "couchdb"         // CouchDB
	ServiceWsman           Service = "wsman"           // WBEM WS-Management HTTP
	ServiceWsmans          Service = "wsmans"          // WBEM WS-Management HTTP over TLS/SSL
	ServiceWbemRmi         Service = "wbem-rmi"        // WBEM RMI
	ServiceWbemHttp        Service = "wbem-http"       // WBEM CIM-XML (HTTP)
	ServiceWbemHttps       Service = "wbem-https"      // WBEM CIM-XML (HTTPS)
	ServiceWbemExpHttps    Service = "wbem-exp-https"  // WBEM Export HTTPS
	ServiceNuxsl           Service = "nuxsl"           // NUXSL
	ServiceConsulInsight   Service = "consul-insight"  // Consul InSight Security
	ServiceNdlAhpSvc       Service = "ndl-ahp-svc"     // NDL-AHP-SVC
	ServiceWinpharaoh      Service = "winpharaoh"      // WinPharaoh
	ServiceEwctsp          Service = "ewctsp"          // EWCTSP
	ServiceGsmpAncp        Service = "gsmp-ancp"       // GSMP/ANCP
	ServiceTrip            Service = "trip"            // TRIP
	ServiceMessageasap     Service = "messageasap"     // Messageasap
	ServiceSsdtp           Service = "ssdtp"           // SSDTP
	ServiceDiagnoseProc    Service = "diagnose-proc"   // DIAGNOSE-PROC
	ServiceDirectplay8     Service = "directplay8"     // DirectPlay8
	ServiceMax             Service = "max"             // Microsoft Max
	ServiceDpmAcm          Service = "dpm-acm"         // Microsoft DPM Access Control Manager
	ServiceMsftDpmCert     Service = "msft-dpm-cert"   // Microsoft DPM WCF Certificates
	ServiceIconstructsrv   Service = "iconstructsrv"   // iConstruct Server
	ServiceP25cai          Service = "p25cai"          // APCO Project 25 Common Air Interface
	ServiceMiamiBcast      Service = "miami-bcast"     // telecomsoftware miami broadcast
	ServiceReloadConfig    Service = "reload-config"   // Peer to Peer Infrastructure Protocol
	ServiceKonspire2b      Service = "konspire2b"      // konspire2b p2p network
	ServicePdtp            Service = "pdtp"            // PDTP P2P
	ServiceLdss            Service = "ldss"            // Local Download Sharing Service
	ServiceDoglms          Service = "doglms"          // SuperDog License Manager
	ServiceDoglmsNotify    Service = "doglms-notify"   // SuperDog License Manager
	ServiceRaxaMgmt        Service = "raxa-mgmt"       // RAXA Management
	ServiceSynchronetDb    Service = "synchronet-db"   // SynchroNet-db
	ServiceSynchronetRtc   Service = "synchronet-rtc"  // SynchroNet-rtc
	ServiceSynchronetUpd   Service = "synchronet-upd"  // SynchroNet-upd
	ServiceRets            Service = "rets"            // RETS
	ServiceDbdb            Service = "dbdb"            // DBDB
	ServicePrimaserver     Service = "primaserver"     // Prima Server
	ServiceMpsserver       Service = "mpsserver"       // MPS Server
	ServiceEtcControl      Service = "etc-control"     // ETC Control
	ServiceSercommScadmin  Service = "sercomm-scadmin" // Sercomm-SCAdmin
	ServiceGlobecastId     Service = "globecast-id"    // GLOBECAST-ID
	ServiceSoftcm          Service = "softcm"          // HP SoftBench CM
	ServiceSpc             Service = "spc"             // HP SoftBench Sub-Process Control
	ServiceDtspcd          Service = "dtspcd"          // Desk-Top Sub-Process Control Daemon
	ServiceDayliteserver   Service = "dayliteserver"   // Daylite Server
	ServiceWrspice         Service = "wrspice"         // WRspice IPC Service
	ServiceXic             Service = "xic"             // Xic IPC Service
	ServiceXtlserv         Service = "xtlserv"         // XicTools License Manager Service
	ServiceDaylitetouch    Service = "daylitetouch"    // Daylite Touch Sync
	ServiceTipc            Service = "tipc"            // Transparent Inter Process Communication
	ServiceSpdy            Service = "spdy"            // SPDY for a faster web
	ServiceBexWebadmin     Service = "bex-webadmin"    // Backup Express Web Server
	ServiceBackupExpress   Service = "backup-express"  // Backup Express
	ServicePnbs            Service = "pnbs"            // Phlexible Network Backup Service
	ServiceNbtWol          Service = "nbt-wol"         // New Boundary Tech WOL
	ServicePulsonixnls     Service = "pulsonixnls"     // Pulsonix Network License Service
	ServiceMetaCorp        Service = "meta-corp"       // Meta Corporation License Manager
	ServiceAspentecLm      Service = "aspentec-lm"     // Aspen Technology License Manager
	ServiceWatershedLm     Service = "watershed-lm"    // Watershed License Manager
	ServiceStatsci1Lm      Service = "statsci1-lm"     // StatSci License Manager - 1
	ServiceStatsci2Lm      Service = "statsci2-lm"     // StatSci License Manager - 2
	ServiceLonewolfLm      Service = "lonewolf-lm"     // Lone Wolf Systems License Manager
	ServiceMontageLm       Service = "montage-lm"      // Montage License Manager
	ServiceTalPod          Service = "tal-pod"         // tal-pod
	ServiceEfbAci          Service = "efb-aci"         // EFB Application Control Interface
	ServiceEcmp            Service = "ecmp"            // Emerson Extensible Control and Management Protocol
	ServiceEcmpData        Service = "ecmp-data"       // Emerson Extensible Control and Management Protocol Data
	ServicePatrolIsm       Service = "patrol-ism"      // PATROL Internet Srv Mgr
	ServicePatrolColl      Service = "patrol-coll"     // PATROL Collector
	ServicePscribe         Service = "pscribe"         // Precision Scribe Cnx Port
	ServiceLmX             Service = "lm-x"            // LM-X License Manager by X-Formation
	ServiceThermoCalc      Service = "thermo-calc"     // Thermo-Calc_Software
	ServiceRadmind         Service = "radmind"         // Radmind Access Protocol
	ServiceJeolNsdtp1      Service = "jeol-nsdtp-1"    // JEOL Network Services Data Transport Protocol 1
	ServiceJeolNsddp1      Service = "jeol-nsddp-1"    // JEOL Network Services Dynamic Discovery Protocol 1
	ServiceJeolNsdtp2      Service = "jeol-nsdtp-2"    // JEOL Network Services Data Transport Protocol 2
	ServiceJeolNsddp2      Service = "jeol-nsddp-2"    // JEOL Network Services Dynamic Discovery Protocol 2
	ServiceJeolNsdtp3      Service = "jeol-nsdtp-3"    // JEOL Network Services Data Transport Protocol 3
	ServiceJeolNsddp3      Service = "jeol-nsddp-3"    // JEOL Network Services Dynamic Discovery Protocol 3
	ServiceJeolNsdtp4      Service = "jeol-nsdtp-4"    // JEOL Network Services Data Transport Protocol 4
	ServiceJeolNsddp4      Service = "jeol-nsddp-4"    // JEOL Network Services Dynamic Discovery Protocol 4
	ServiceTl1RawSsl       Service = "tl1-raw-ssl"     // TL1 Raw Over SSL/TLS
	ServiceTl1Ssh          Service = "tl1-ssh"         // TL1 over SSH
	ServiceCrip            Service = "crip"            // CRIP
	ServiceGld             Service = "gld"             // GridLAB-D User Interface
	ServiceGrid            Service = "grid"            // Grid Authentication
	ServiceGridAlt         Service = "grid-alt"        // Grid Authentication Alt
	ServiceBmcGrx          Service = "bmc-grx"         // BMC GRX
	ServiceBmc_ctd_ldap    Service = "bmc_ctd_ldap"    // BMC CONTROL-D LDAP SERVER
	ServiceUfmp            Service = "ufmp"            // Unified Fabric Management Protocol
	ServiceScup            Service = "scup"            // Sensor Control Unit Protocol
	ServiceScupDisc        Service = "scup-disc"       // Sensor Control Unit Protocol Discovery Protocol
	ServiceAbbEscp         Service = "abb-escp"        // Ethernet Sensor Communications Protocol
	ServiceNavDataCmd      Service = "nav-data-cmd"    // Navtech Radar Sensor Data command
	ServiceNavData         Service = "nav-data"        // Navtech Radar Sensor Data
	ServiceRepsvc          Service = "repsvc"          // Double-Take Replication Service
	ServiceEmpServer1      Service = "emp-server1"     // Empress Software Connectivity Server 1
	ServiceEmpServer2      Service = "emp-server2"     // Empress Software Connectivity Server 2
	ServiceHrdNcs          Service = "hrd-ncs"         // HR Device Network
	ServiceHrdNsDisc       Service = "hrd-ns-disc"     // HR Device Network service
	ServiceDtMgmtsvc       Service = "dt-mgmtsvc"      // Double-Take Management Service
	ServiceDtVra           Service = "dt-vra"          // Double-Take Virtual Recovery
	ServiceSflow           Service = "sflow"           // sFlow traffic monitoring
	ServiceGnutellaSvc     Service = "gnutella-svc"    // gnutella-svc
	ServiceGnutellaRtr     Service = "gnutella-rtr"    // gnutella-rtr
	ServiceAdap            Service = "adap"            // App Discovery and Access Protocol
	ServicePmcs            Service = "pmcs"            // PMCS applications
	ServiceMetaeditMu      Service = "metaedit-mu"     // MetaEdit+ Multi-User
	ServiceMetaeditSe      Service = "metaedit-se"     // MetaEdit+ Server Administration
	ServiceMetatudeMds     Service = "metatude-mds"    // Metatude Dialogue Server
	ServiceClariionEvr01   Service = "clariion-evr01"  // clariion-evr01
	ServiceMetaeditWs      Service = "metaedit-ws"     // MetaEdit+ WebService API
	ServiceBoeCms          Service = "boe-cms"         // Business Objects CMS contact port
	ServiceBoeWas          Service = "boe-was"         // boe-was
	ServiceBoeEventsrv     Service = "boe-eventsrv"    // boe-eventsrv
	ServiceBoeCachesvr     Service = "boe-cachesvr"    // boe-cachesvr
	ServiceBoeFilesvr      Service = "boe-filesvr"     // Business Objects Enterprise internal server
	ServiceBoePagesvr      Service = "boe-pagesvr"     // Business Objects Enterprise internal server
	ServiceBoeProcesssvr   Service = "boe-processsvr"  // Business Objects Enterprise internal server
	ServiceBoeResssvr1     Service = "boe-resssvr1"    // Business Objects Enterprise internal server
	ServiceBoeResssvr2     Service = "boe-resssvr2"    // Business Objects Enterprise internal server
	ServiceBoeResssvr3     Service = "boe-resssvr3"    // Business Objects Enterprise internal server
	ServiceBoeResssvr4     Service = "boe-resssvr4"    // Business Objects Enterprise internal server
	ServiceFaxcomservice   Service = "faxcomservice"   // Faxcom Message Service
	ServiceSyserverremote  Service = "syserverremote"  // SYserver remote commands
	ServiceSvdrp           Service = "svdrp"           // Simple VDR Protocol
	ServiceNimVdrshell     Service = "nim-vdrshell"    // NIM_VDRShell
	ServiceNimWan          Service = "nim-wan"         // NIM_WAN
	ServicePgbouncer       Service = "pgbouncer"       // PgBouncer
	ServiceSunSrHttps      Service = "sun-sr-https"    // Service Registry Default HTTPS Domain
	ServiceSge_qmaster     Service = "sge_qmaster"     // Grid Engine Qmaster Service
	ServiceSge_execd       Service = "sge_execd"       // Grid Engine Execution Service
	ServiceMysqlProxy      Service = "mysql-proxy"     // MySQL Proxy
	ServiceSkipCertRecv    Service = "skip-cert-recv"  // SKIP Certificate Receive
	ServiceSkipCertSend    Service = "skip-cert-send"  // SKIP Certificate Send
	ServiceLvisionLm       Service = "lvision-lm"      // LVision License Manager
	ServiceSunSrHttp       Service = "sun-sr-http"     // Service Registry Default HTTP Domain
	ServiceServicetags     Service = "servicetags"     // Service Tags
	ServiceLdomsMgmt       Service = "ldoms-mgmt"      // Logical Domains Management Interface
	ServiceSunVTSRMI       Service = "SunVTS-RMI"      // SunVTS RMI
	ServiceSunSrJms        Service = "sun-sr-jms"      // Service Registry Default JMS Domain
	ServiceSunSrIiop       Service = "sun-sr-iiop"     // Service Registry Default IIOP Domain
	ServiceSunSrIiops      Service = "sun-sr-iiops"    // Service Registry Default IIOPS Domain
	ServiceSunSrIiopAut    Service = "sun-sr-iiop-aut" // Service Registry Default IIOPAuth Domain
	ServiceSunSrJmx        Service = "sun-sr-jmx"      // Service Registry Default JMX Domain
	ServiceSunSrAdmin      Service = "sun-sr-admin"    // Service Registry Default Admin Domain
	ServiceBoks            Service = "boks"            // BoKS Master
	ServiceBoks_servc      Service = "boks_servc"      // BoKS Servc
	ServiceBoks_servm      Service = "boks_servm"      // BoKS Servm
	ServiceBoks_clntd      Service = "boks_clntd"      // BoKS Clntd
	ServiceBadm_priv       Service = "badm_priv"       // BoKS Admin Private Port
	ServiceBadm_pub        Service = "badm_pub"        // BoKS Admin Public Port
	ServiceBdir_priv       Service = "bdir_priv"       // BoKS Dir Server, Private Port
	ServiceBdir_pub        Service = "bdir_pub"        // BoKS Dir Server, Public Port
	ServiceMgcsMfpPort     Service = "mgcs-mfp-port"   // MGCS-MFP Port
	ServiceMcerPort        Service = "mcer-port"       // MCER Port
	ServiceDccpUdp         Service = "dccp-udp"        // Protocol Encapsulation for NAT Traversal
	ServiceNetconfTls      Service = "netconf-tls"     // NETCONF over TLS
	ServiceSyslogTls       Service = "syslog-tls"      // Syslog over TLS
	ServiceElipseRec       Service = "elipse-rec"      // Elipse RPC Protocol
	ServiceLdsDistrib      Service = "lds-distrib"     // lds_distrib
	ServiceLdsDump         Service = "lds-dump"        // LDS Dump Service
	ServiceApc6547         Service = "apc-6547"        // APC 6547
	ServiceApc6548         Service = "apc-6548"        // APC 6548
	ServiceApc6549         Service = "apc-6549"        // APC 6549
	ServiceFgSysupdate     Service = "fg-sysupdate"    // fg-sysupdate
	ServiceSum             Service = "sum"             // Software Update Manager
	ServiceXdsxdm          Service = "xdsxdm"          //
	ServiceSanePort        Service = "sane-port"       // SANE Control Port
	ServiceCanit_store     Service = "canit_store"     // CanIt Storage Manager
	ServiceRpReputation    Service = "rp-reputation"   // Roaring Penguin IP Address Reputation Collection
	ServiceAffiliate       Service = "affiliate"       // Affiliate
	ServiceParsecMaster    Service = "parsec-master"   // Parsec Masterserver
	ServiceParsecPeer      Service = "parsec-peer"     // Parsec Peer-to-Peer
	ServiceParsecGame      Service = "parsec-game"     // Parsec Gameserver
	ServiceJoaJewelSuite   Service = "joaJewelSuite"   // JOA Jewel Suite
	ServiceMshvlm          Service = "mshvlm"          // Microsoft Hyper-V Live Migration
	ServiceMstmgSstp       Service = "mstmg-sstp"      // Microsoft Threat Management Gateway SSTP
	ServiceWsscomfrmwk     Service = "wsscomfrmwk"     // Windows WSS Communication Framework
	ServiceOdetteFtps      Service = "odette-ftps"     // ODETTE-FTP over TLS/SSL
	ServiceKftpData        Service = "kftp-data"       // Kerberos V5 FTP Data
	ServiceKftp            Service = "kftp"            // Kerberos V5 FTP Control
	ServiceMcftp           Service = "mcftp"           // Multicast FTP
	ServiceKtelnet         Service = "ktelnet"         // Kerberos V5 Telnet
	ServiceDatascalerDb    Service = "datascaler-db"   // DataScaler database
	ServiceDatascalerCtl   Service = "datascaler-ctl"  // DataScaler control
	ServiceWagoService     Service = "wago-service"    // WAGO Service and Update
	ServiceNexgen          Service = "nexgen"          // Allied Electronics NeXGen
	ServiceAfescMc         Service = "afesc-mc"        // AFE Stock Channel M/C
	ServiceMxodbcConnect   Service = "mxodbc-connect"  // eGenix mxODBC Connect
	ServiceCiscoVpathTun   Service = "cisco-vpath-tun" // Cisco vPath Services Overlay
	ServicePcsSfUiMan      Service = "pcs-sf-ui-man"   // PC SOFT - Software factory UI/manager
	ServiceEmgmsg          Service = "emgmsg"          // Emergency Message Control Service
	ServicePalcomDisc      Service = "palcom-disc"     // PalCom Discovery
	ServiceIrcu            Service = "ircu"            // IRCU
	ServiceIrcu2           Service = "ircu-2"          // IRCU
	ServiceIrcu3           Service = "ircu-3"          // IRCU
	ServiceIrcu4           Service = "ircu-4"          // IRCU
	ServiceIrcu5           Service = "ircu-5"          // IRCU
	ServiceVocaltecGold    Service = "vocaltec-gold"   // Vocaltec Global Online Directory
	ServiceP4pPortal       Service = "p4p-portal"      // P4P Portal Service
	ServiceVision_server   Service = "vision_server"   // vision_server
	ServiceVision_elmd     Service = "vision_elmd"     // vision_elmd
	ServiceVfbp            Service = "vfbp"            // Viscount Freedom Bridge Protocol
	ServiceVfbpDisc        Service = "vfbp-disc"       // Viscount Freedom Bridge Discovery
	ServiceOsaut           Service = "osaut"           // Osorno Automation
	ServiceCleverCtrace    Service = "clever-ctrace"   // CleverView for cTrace Message Service
	ServiceCleverTcpip     Service = "clever-tcpip"    // CleverView for TCP/IP Message Service
	ServiceTsa             Service = "tsa"             // Tofino Security Appliance
	ServiceBabel           Service = "babel"           // Babel Routing Protocol
	ServiceKtiIcadSrvr     Service = "kti-icad-srvr"   // KTI/ICAD Nameserver
	ServiceEDesignNet      Service = "e-design-net"    // e-Design network
	ServiceEDesignWeb      Service = "e-design-web"    // e-Design web
	ServiceFrcHp           Service = "frc-hp"          // ForCES HP (High Priority) channel
	ServiceFrcMp           Service = "frc-mp"          // ForCES MP (Medium Priority) channel
	ServiceFrcLp           Service = "frc-lp"          // ForCES LP (Low priority) channel
	ServiceIbprotocol      Service = "ibprotocol"      // Internet Backplane Protocol
	ServiceFibotraderCom   Service = "fibotrader-com"  // Fibotrader Communications
	ServiceBmcPerfAgent    Service = "bmc-perf-agent"  // BMC PERFORM AGENT
	ServiceBmcPerfMgrd     Service = "bmc-perf-mgrd"   // BMC PERFORM MGRD
	ServiceAdiGxpSrvprt    Service = "adi-gxp-srvprt"  // ADInstruments GxP Server
	ServicePlysrvHttp      Service = "plysrv-http"     // PolyServe http
	ServicePlysrvHttps     Service = "plysrv-https"    // PolyServe https
	ServiceBfdLag          Service = "bfd-lag"         // Bidirectional Forwarding Detection on LAG
	ServiceDgpfExchg       Service = "dgpf-exchg"      // DGPF Individual Exchange
	ServiceSmcJmx          Service = "smc-jmx"         // Sun Java Web Console JMX
	ServiceSmcAdmin        Service = "smc-admin"       // Sun Web Console Admin
	ServiceSmcHttp         Service = "smc-http"        // SMC-HTTP
	ServiceSmcHttps        Service = "smc-https"       // SMC-HTTPS
	ServiceHnmp            Service = "hnmp"            // HNMP
	ServiceHnm             Service = "hnm"             // Halcyon Network Manager
	ServiceAcnet           Service = "acnet"           // ACNET Control System Protocol
	ServicePentboxSim      Service = "pentbox-sim"     // PenTBox Secure IM Protocol
	ServiceAmbitLm         Service = "ambit-lm"        // ambit-lm
	ServiceNetmoDefault    Service = "netmo-default"   // Netmo Default
	ServiceNetmoHttp       Service = "netmo-http"      // Netmo HTTP
	ServiceIccrushmore     Service = "iccrushmore"     // ICCRUSHMORE
	ServiceAcctopusCc      Service = "acctopus-cc"     // Acctopus Command Channel
	ServiceAcctopusSt      Service = "acctopus-st"     // Acctopus Status
	ServiceMuse            Service = "muse"            // MUSE
	ServiceJetstream       Service = "jetstream"       // Novell Jetstream messaging protocol
	ServiceEthoscan        Service = "ethoscan"        // EthoScan Service
	ServiceXsmsvc          Service = "xsmsvc"          // XenSource Management Service
	ServiceBioserver       Service = "bioserver"       // Biometrics Server
	ServiceOtlp            Service = "otlp"            // OTLP
	ServiceJmact3          Service = "jmact3"          // JMACT3
	ServiceJmevt2          Service = "jmevt2"          // jmevt2
	ServiceSwismgr1        Service = "swismgr1"        // swismgr1
	ServiceSwismgr2        Service = "swismgr2"        // swismgr2
	ServiceSwistrap        Service = "swistrap"        // swistrap
	ServiceSwispol         Service = "swispol"         // swispol
	ServiceAcmsoda         Service = "acmsoda"         // acmsoda
	ServiceMobilitySrv     Service = "MobilitySrv"     // Mobility XE Protocol
	ServiceIatpHighpri     Service = "iatp-highpri"    // IATP-highPri
	ServiceIatpNormalpri   Service = "iatp-normalpri"  // IATP-normalPri
	ServiceUpsOnlinet      Service = "ups-onlinet"     // onlinet uninterruptable power supplies
	ServiceTalonDisc       Service = "talon-disc"      // Talon Discovery Port
	ServiceTalonEngine     Service = "talon-engine"    // Talon Engine
	ServiceMicrotalonDis   Service = "microtalon-dis"  // Microtalon Discovery
	ServiceMicrotalonCom   Service = "microtalon-com"  // Microtalon Communications
	ServiceTalonWebserver  Service = "talon-webserver" // Talon Webserver
	ServiceFisaSvc         Service = "fisa-svc"        // FISA Service
	ServiceDoceriCtl       Service = "doceri-ctl"      // doceri drawing service control
	ServiceDoceriView      Service = "doceri-view"     // doceri drawing service screen view
	ServiceDpserve         Service = "dpserve"         // DP Serve
	ServiceDpserveadmin    Service = "dpserveadmin"    // DP Serve Admin
	ServiceCtdp            Service = "ctdp"            // CT Discovery Protocol
	ServiceCt2nmcs         Service = "ct2nmcs"         // Comtech T2 NMCS
	ServiceVmsvc           Service = "vmsvc"           // Vormetric service
	ServiceVmsvc2          Service = "vmsvc-2"         // Vormetric Service II
	ServiceOpProbe         Service = "op-probe"        // ObjectPlanet probe
	ServiceIposplanet      Service = "iposplanet"      // IPOSPLANET retailing multi devices protocol
	ServiceQuestDisc       Service = "quest-disc"      // Quest application level network service discovery
	ServiceArcp            Service = "arcp"            // ARCP
	ServiceIwg1            Service = "iwg1"            // IWGADTS Aircraft Housekeeping Message
	ServiceEmpowerid       Service = "empowerid"       // EmpowerID Communication
	ServiceJdpDisc         Service = "jdp-disc"        // Java Discovery Protocol
	ServiceLazyPtop        Service = "lazy-ptop"       // lazy-ptop
	ServiceFontService     Service = "font-service"    // X Font Service
	ServiceElcn            Service = "elcn"            // Embedded Light Control Network
	ServiceAesX170         Service = "aes-x170"        // AES-X170
	ServiceVirprotLm       Service = "virprot-lm"      // Virtual Prototypes License Manager
	ServiceScenidm         Service = "scenidm"         // intelligent data manager
	ServiceScenccs         Service = "scenccs"         // Catalog Content Search
	ServiceCabsmComm       Service = "cabsm-comm"      // CA BSM Comm
	ServiceCaistoragemgr   Service = "caistoragemgr"   // CA Storage Manager
	ServiceCacsambroker    Service = "cacsambroker"    // CA Connection Broker
	ServiceFsr             Service = "fsr"             // File System Repository Agent
	ServiceDocServer       Service = "doc-server"      // Document WCF Server
	ServiceArubaServer     Service = "aruba-server"    // Aruba eDiscovery Server
	ServiceCasrmagent      Service = "casrmagent"      // CA SRM Agent
	ServiceCnckadserver    Service = "cnckadserver"    // cncKadServer DB & Inventory Services
	ServiceCcagPib         Service = "ccag-pib"        // Consequor Consulting Process Integration Bridge
	ServiceNsrp            Service = "nsrp"            // Adaptive Name/Service Resolution
	ServiceDrmProduction   Service = "drm-production"  // Discovery and Retention Mgt Production
	ServiceMetalbend       Service = "metalbend"       // MetalBend programmable interface
	ServiceZsecure         Service = "zsecure"         // zSecure Server
	ServiceClutild         Service = "clutild"         // Clutild
	ServiceFodms           Service = "fodms"           // FODMS FLIP
	ServiceDlip            Service = "dlip"            // DLIP
	ServiceRamp            Service = "ramp"            // Registry A & M Protocol
	ServiceCitrixupp       Service = "citrixupp"       // Citrix Universal Printing Port
	ServiceCitrixuppg      Service = "citrixuppg"      // Citrix UPP Gateway
	ServiceDisplay         Service = "display"         // Wi-Fi Alliance Wi-Fi Display Protocol
	ServicePads            Service = "pads"            // PADS (Public Area Display System) Server
	ServiceCnap            Service = "cnap"            // Calypso Network Access Protocol
	ServiceWatchme7272     Service = "watchme-7272"    // WatchMe Monitoring 7272
	ServiceOmaRlp          Service = "oma-rlp"         // OMA Roaming Location
	ServiceOmaRlpS         Service = "oma-rlp-s"       // OMA Roaming Location SEC
	ServiceOmaUlp          Service = "oma-ulp"         // OMA UserPlane Location
	ServiceOmaIlp          Service = "oma-ilp"         // OMA Internal Location Protocol
	ServiceOmaIlpS         Service = "oma-ilp-s"       // OMA Internal Location Secure Protocol
	ServiceOmaDcdocbs      Service = "oma-dcdocbs"     // OMA Dynamic Content Delivery over CBS
	ServiceCtxlic          Service = "ctxlic"          // Citrix Licensing
	ServiceItactionserver1 Service = "itactionserver1" // ITACTIONSERVER 1
	ServiceItactionserver2 Service = "itactionserver2" // ITACTIONSERVER 2
	ServiceMzcaAction      Service = "mzca-action"     // eventACTION/ussACTION (MZCA) server
	ServiceMzcaAlert       Service = "mzca-alert"      // eventACTION/ussACTION (MZCA) alert
	ServiceGenstat         Service = "genstat"         // General Statistics Rendezvous Protocol
	ServiceLcmServer       Service = "lcm-server"      // LifeKeeper Communications
	ServiceMindfilesys     Service = "mindfilesys"     // mind-file system server
	ServiceMrssrendezvous  Service = "mrssrendezvous"  // mrss-rendezvous server
	ServiceNfoldman        Service = "nfoldman"        // nFoldMan Remote Publish
	ServiceFse             Service = "fse"             // File system export of backup images
	ServiceWinqedit        Service = "winqedit"        // winqedit
	ServiceHexarc          Service = "hexarc"          // Hexarc Command Language
	ServiceRtpsDiscovery   Service = "rtps-discovery"  // RTPS Discovery
	ServiceRtpsDdUt        Service = "rtps-dd-ut"      // RTPS Data-Distribution User-Traffic
	ServiceRtpsDdMt        Service = "rtps-dd-mt"      // RTPS Data-Distribution Meta-Traffic
	ServiceIonixnetmon     Service = "ionixnetmon"     // Ionix Network Monitor
	ServiceDaqstream       Service = "daqstream"       // Streaming of measurement
	ServiceMtportmon       Service = "mtportmon"       // Matisse Port Monitor
	ServicePmdmgr          Service = "pmdmgr"          // OpenView DM Postmaster Manager
	ServiceOveadmgr        Service = "oveadmgr"        // OpenView DM Event Agent Manager
	ServiceOvladmgr        Service = "ovladmgr"        // OpenView DM Log Agent Manager
	ServiceOpiSock         Service = "opi-sock"        // OpenView DM rqt communication
	ServiceXmpv7           Service = "xmpv7"           // OpenView DM xmpv7 api pipe
	ServicePmd             Service = "pmd"             // OpenView DM ovc/xmpv3 api pipe
	ServiceFaximum         Service = "faximum"         // Faximum
	ServiceOracleasHttps   Service = "oracleas-https"  // Oracle Application Server HTTPS
	ServiceRise            Service = "rise"            // Rise: The Vieneo Province
	ServiceNeo4j           Service = "neo4j"           // Neo4j Graph Database
	ServiceTelopsLmd       Service = "telops-lmd"      // telops-lmd
	ServiceSilhouette      Service = "silhouette"      // Silhouette User
	ServiceOvbus           Service = "ovbus"           // HP OpenView Bus Daemon
	ServiceAdcp            Service = "adcp"            // Automation Device Configuration Protocol
	ServiceAcplt           Service = "acplt"           // ACPLT - process automation service
	ServiceOvhpas          Service = "ovhpas"          // HP OpenView Application Server
	ServicePafecLm         Service = "pafec-lm"        // pafec-lm
	ServiceSaratoga        Service = "saratoga"        // Saratoga Transfer Protocol
	ServiceAtul            Service = "atul"            // atul server
	ServiceNtaDs           Service = "nta-ds"          // FlowAnalyzer DisplayServer
	ServiceNtaUs           Service = "nta-us"          // FlowAnalyzer UtilityServer
	ServiceCfs             Service = "cfs"             // Cisco Fabric service
	ServiceCwmp            Service = "cwmp"            // DSL Forum CWMP
	ServiceTidp            Service = "tidp"            // Threat Information Distribution Protocol
	ServiceNlsTl           Service = "nls-tl"          // Network Layer Signaling Transport Layer
	ServiceCloudsignaling  Service = "cloudsignaling"  // Cloud Signaling Service
	ServiceSncp            Service = "sncp"            // Sniffer Command Protocol
	ServiceCfw             Service = "cfw"             // Control Framework
	ServiceVsiOmega        Service = "vsi-omega"       // VSI Omega
	ServiceDellEqlAsm      Service = "dell-eql-asm"    // Dell EqualLogic Host Group Management
	ServiceAriesKfinder    Service = "aries-kfinder"   // Aries Kfinder
	ServiceSunLm           Service = "sun-lm"          // Sun License Manager
	ServiceIndi            Service = "indi"            // Instrument Neutral Distributed Interface
	ServiceSimco           Service = "simco"           // SImple Middlebox COnfiguration (SIMCO) Server
	ServiceSoapHttp        Service = "soap-http"       // SOAP Service Port
	ServiceZenPawn         Service = "zen-pawn"        // Primary Agent Work Notification
	ServiceXdas            Service = "xdas"            // OpenXDAS Wire Protocol
	ServiceHawk            Service = "hawk"            // HA Web Konsole
	ServiceTeslaSysMsg     Service = "tesla-sys-msg"   // TESLA System Messaging
	ServicePmdfmgt         Service = "pmdfmgt"         // PMDF Management
	ServiceCuseeme         Service = "cuseeme"         // bonjour-cuseeme
	ServiceImqstomp        Service = "imqstomp"        // iMQ STOMP Server
	ServiceImqstomps       Service = "imqstomps"       // iMQ STOMP Server over SSL
	ServiceImqtunnels      Service = "imqtunnels"      // iMQ SSL tunnel
	ServiceImqtunnel       Service = "imqtunnel"       // iMQ Tunnel
	ServiceImqbrokerd      Service = "imqbrokerd"      // iMQ Broker Rendezvous
	ServiceSunUserHttps    Service = "sun-user-https"  // Sun App Server - HTTPS
	ServicePandoPub        Service = "pando-pub"       // Pando Media Public Distribution
	ServiceCollaber        Service = "collaber"        // Collaber Network Service
	ServiceKlio            Service = "klio"            // KLIO communications
	ServiceEm7Secom        Service = "em7-secom"       // EM7 Secure Communications
	ServiceSyncEm7         Service = "sync-em7"        // EM7 Dynamic Updates
	ServiceScinet          Service = "scinet"          // scientia.net
	ServiceMedimageportal  Service = "medimageportal"  // MedImage Portal
	ServiceNsdeepfreezectl Service = "nsdeepfreezectl" // Novell Snap-in Deep Freeze Control
	ServiceNitrogen        Service = "nitrogen"        // Nitrogen Service
	ServiceFreezexservice  Service = "freezexservice"  // FreezeX Console Service
	ServiceTridentData     Service = "trident-data"    // Trident Systems Data
	ServiceSmip            Service = "smip"            // Smith Protocol over IP
	ServiceAiagent         Service = "aiagent"         // HP Enterprise Discovery Agent
	ServiceScriptview      Service = "scriptview"      // ScriptView Network
	ServiceMsss            Service = "msss"            // Mugginsoft Script Server Service
	ServiceSstp1           Service = "sstp-1"          // Sakura Script Transfer Protocol
	ServiceRaqmonPdu       Service = "raqmon-pdu"      // RAQMON PDU
	ServicePrgp            Service = "prgp"            // Put/Run/Get Protocol
	ServiceCbt             Service = "cbt"             // cbt
	ServiceInterwise       Service = "interwise"       // Interwise
	ServiceVstat           Service = "vstat"           // VSTAT
	ServiceAccuLmgr        Service = "accu-lmgr"       // accu-lmgr
	ServiceMinivend        Service = "minivend"        // MINIVEND
	ServicePopupReminders  Service = "popup-reminders" // Popup Reminders Receive
	ServiceOfficeTools     Service = "office-tools"    // Office Tools Pro Receive
	ServiceQ3ade           Service = "q3ade"           // Q3ADE Cluster Service
	ServicePnetConn        Service = "pnet-conn"       // Propel Connector port
	ServicePnetEnc         Service = "pnet-enc"        // Propel Encoder port
	ServiceAltbsdp         Service = "altbsdp"         // Alternate BSDP Service
	ServiceAsr             Service = "asr"             // Apple Software Restore
	ServiceSspClient       Service = "ssp-client"      // Secure Server Protocol - client
	ServiceVnsTp           Service = "vns-tp"          // Virtualized Network Services tunnel protocol
	ServiceRbtWanopt       Service = "rbt-wanopt"      // Riverbed WAN Optimization Protocol
	ServiceApc7845         Service = "apc-7845"        // APC 7845
	ServiceApc7846         Service = "apc-7846"        // APC 7846
	ServiceMobileanalyzer  Service = "mobileanalyzer"  // MobileAnalyzer& MobileMonitor
	ServiceRbtSmc          Service = "rbt-smc"         // Riverbed Steelhead Mobile Service
	ServiceMdm             Service = "mdm"             // Mobile Device Management
	ServiceMipv6tls        Service = "mipv6tls"        // TLS-based Mobile IPv6 Security
	ServicePss             Service = "pss"             // Pearson
	ServiceUbroker         Service = "ubroker"         // Universal Broker
	ServiceMevent          Service = "mevent"          // Multicast Event
	ServiceTnosSp          Service = "tnos-sp"         // TNOS Service Protocol
	ServiceTnosDp          Service = "tnos-dp"         // TNOS shell Protocol
	ServiceTnosDps         Service = "tnos-dps"        // TNOS Secure DiaguardProtocol
	ServiceQoSecure        Service = "qo-secure"       // QuickObjects secure port
	ServiceT2Drm           Service = "t2-drm"          // Tier 2 Data Resource Manager
	ServiceT2Brm           Service = "t2-brm"          // Tier 2 Business Rules Manager
	ServiceSupercell       Service = "supercell"       // Supercell
	ServiceMicromuseNcps   Service = "micromuse-ncps"  // Micromuse-ncps
	ServiceQuestVista      Service = "quest-vista"     // Quest Vista
	ServiceSossdCollect    Service = "sossd-collect"   // Spotlight on SQL Server Desktop Collect
	ServiceSossdAgent      Service = "sossd-agent"     // Spotlight on SQL Server Desktop Agent
	ServiceSossdDisc       Service = "sossd-disc"      // Spotlight on SQL Server Desktop Agent Discovery
	ServicePushns          Service = "pushns"          // PUSH Notification Service
	ServiceUsicontentpush  Service = "usicontentpush"  // USI Content Push Service
	ServiceIrdmi2          Service = "irdmi2"          // iRDMI2
	ServiceIrdmi           Service = "irdmi"           // iRDMI
	ServiceVcomTunnel      Service = "vcom-tunnel"     // VCOM Tunnel
	ServiceTeradataordbms  Service = "teradataordbms"  // Teradata ORDBMS
	ServiceMcreport        Service = "mcreport"        // Mulberry Connect Reporting Service
	ServiceMxi             Service = "mxi"             // MXI Generation II for z/OS
	ServiceQbdb            Service = "qbdb"            // QB DB Dynamic Port
	ServiceIntuEcSvcdisc   Service = "intu-ec-svcdisc" // Intuit Entitlement Service and Discovery
	ServiceIntuEcClient    Service = "intu-ec-client"  // Intuit Entitlement Client
	ServiceOaSystem        Service = "oa-system"       // oa-system
	ServiceCaAuditDa       Service = "ca-audit-da"     // CA Audit Distribution Agent
	ServiceCaAuditDs       Service = "ca-audit-ds"     // CA Audit Distribution Server
	ServiceProEd           Service = "pro-ed"          // ProEd
	ServiceMindprint       Service = "mindprint"       // MindPrint
	ServiceVantronixMgmt   Service = "vantronix-mgmt"  // .vantronix Management
	ServiceAmpify          Service = "ampify"          // Ampify Messaging Protocol
	ServiceFsAgent         Service = "fs-agent"        // FireScope Agent
	ServiceFsServer        Service = "fs-server"       // FireScope Server
	ServiceFsMgmt          Service = "fs-mgmt"         // FireScope Management Interface
	ServiceRocrail         Service = "rocrail"         // Rocrail Client Service
	ServiceSenomix01       Service = "senomix01"       // Senomix Timesheets Server
	ServiceSenomix02       Service = "senomix02"       // Senomix Timesheets Client [1 year assignment]
	ServiceSenomix03       Service = "senomix03"       // Senomix Timesheets Server [1 year assignment]
	ServiceSenomix04       Service = "senomix04"       // Senomix Timesheets Server [1 year assignment]
	ServiceSenomix05       Service = "senomix05"       // Senomix Timesheets Server [1 year assignment]
	ServiceSenomix06       Service = "senomix06"       // Senomix Timesheets Client [1 year assignment]
	ServiceSenomix07       Service = "senomix07"       // Senomix Timesheets Client [1 year assignment]
	ServiceSenomix08       Service = "senomix08"       // Senomix Timesheets Client [1 year assignment]
	ServiceAero            Service = "aero"            // Asymmetric Extended Route Optimization (AERO)
	ServiceGadugadu        Service = "gadugadu"        // Gadu-Gadu
	ServiceUsCli           Service = "us-cli"          // Utilistor (Client)
	ServiceUsSrv           Service = "us-srv"          // Utilistor (Server)
	ServiceDSN             Service = "d-s-n"           // Distributed SCADA Networking Rendezvous Port
	ServiceSimplifymedia   Service = "simplifymedia"   // Simplify Media SPP Protocol
	ServiceRadanHttp       Service = "radan-http"      // Radan HTTP
	ServiceJamlink         Service = "jamlink"         // Jam Link Framework
	ServiceSac             Service = "sac"             // SAC Port Id
	ServiceXprintServer    Service = "xprint-server"   // Xprint Server
	ServiceLdomsMigr       Service = "ldoms-migr"      // Logical Domains Migration
	ServiceMtl8000Matrix   Service = "mtl8000-matrix"  // MTL8000 Matrix
	ServiceCpCluster       Service = "cp-cluster"      // Check Point Clustering
	ServicePrivoxy         Service = "privoxy"         // Privoxy HTTP proxy
	ServiceApolloData      Service = "apollo-data"     // Apollo Data Port
	ServiceApolloAdmin     Service = "apollo-admin"    // Apollo Admin Port
	ServicePaycashOnline   Service = "paycash-online"  // PayCash Online Protocol
	ServicePaycashWbp      Service = "paycash-wbp"     // PayCash Wallet-Browser
	ServiceIndigoVrmi      Service = "indigo-vrmi"     // INDIGO-VRMI
	ServiceIndigoVbcp      Service = "indigo-vbcp"     // INDIGO-VBCP
	ServiceDbabble         Service = "dbabble"         // dbabble
	ServiceIsdd            Service = "isdd"            // i-SDD file transfer
	ServiceEorGame         Service = "eor-game"        // Edge of Reality game data
	ServiceQuantastor      Service = "quantastor"      // QuantaStor Management interface
	ServicePatrol          Service = "patrol"          // Patrol
	ServicePatrolSnmp      Service = "patrol-snmp"     // Patrol SNMP
	ServiceIntermapper     Service = "intermapper"     // Intermapper network management system
	ServiceVmwareFdm       Service = "vmware-fdm"      // VMware Fault Domain Manager
	ServiceProremote       Service = "proremote"       // ProRemote
	ServiceItach           Service = "itach"           // Remote iTach Connection
	ServiceSpytechphone    Service = "spytechphone"    // SpyTech Phone Service
	ServiceBlp1            Service = "blp1"            // Bloomberg data API
	ServiceBlp2            Service = "blp2"            // Bloomberg feed
	ServiceVvrData         Service = "vvr-data"        // VVR DATA
	ServiceTrivnet1        Service = "trivnet1"        // TRIVNET
	ServiceTrivnet2        Service = "trivnet2"        // TRIVNET
	ServiceAesop           Service = "aesop"           // Audio+Ethernet Standard Open Protocol
	ServiceLmPerfworks     Service = "lm-perfworks"    // LM Perfworks
	ServiceLmInstmgr       Service = "lm-instmgr"      // LM Instmgr
	ServiceLmDta           Service = "lm-dta"          // LM Dta
	ServiceLmSserver       Service = "lm-sserver"      // LM SServer
	ServiceLmWebwatcher    Service = "lm-webwatcher"   // LM Webwatcher
	ServiceRexecj          Service = "rexecj"          // RexecJ Server
	ServiceSynapseNhttps   Service = "synapse-nhttps"  // Synapse Non Blocking HTTPS
	ServicePandoSec        Service = "pando-sec"       // Pando Media Controlled Distribution
	ServiceSynapseNhttp    Service = "synapse-nhttp"   // Synapse Non Blocking HTTP
	ServiceBlp3            Service = "blp3"            // Bloomberg professional
	ServiceBlp4            Service = "blp4"            // Bloomberg intelligent client
	ServiceHiperscanId     Service = "hiperscan-id"    // Hiperscan Identification Service
	ServiceTmi             Service = "tmi"             // Transport Management Interface
	ServiceAmberon         Service = "amberon"         // Amberon PPC/PPS
	ServiceHubOpenNet      Service = "hub-open-net"    // Hub Open Network
	ServiceTnpDiscover     Service = "tnp-discover"    // Thin(ium) Network Protocol
	ServiceTnp             Service = "tnp"             // Thin(ium) Network Protocol
	ServiceServerFind      Service = "server-find"     // Server Find
	ServiceCruiseEnum      Service = "cruise-enum"     // Cruise ENUM
	ServiceCruiseSwroute   Service = "cruise-swroute"  // Cruise SWROUTE
	ServiceCruiseConfig    Service = "cruise-config"   // Cruise CONFIG
	ServiceCruiseDiags     Service = "cruise-diags"    // Cruise DIAGS
	ServiceCruiseUpdate    Service = "cruise-update"   // Cruise UPDATE
	ServiceM2mservices     Service = "m2mservices"     // M2m Services
	ServiceCvd             Service = "cvd"             // cvd
	ServiceSabarsd         Service = "sabarsd"         // sabarsd
	ServiceAbarsd          Service = "abarsd"          // abarsd
	ServiceAdmind2         Service = "admind2"         // admind
	ServiceSvcloud         Service = "svcloud"         // SuperVault Cloud
	ServiceSvbackup        Service = "svbackup"        // SuperVault Backup
	ServiceDlpxSp          Service = "dlpx-sp"         // Delphix Session Protocol
	ServiceEspeech         Service = "espeech"         // eSpeech Session Protocol
	ServiceEspeechRtp      Service = "espeech-rtp"     // eSpeech RTP Protocol
	ServiceCybroABus       Service = "cybro-a-bus"     // CyBro A-bus Protocol
	ServicePcsyncHttps     Service = "pcsync-https"    // PCsync HTTPS
	ServicePcsyncHttp      Service = "pcsync-http"     // PCsync HTTP
	ServiceCopy            Service = "copy"            // Port for copy per sync feature
	ServiceCopyDisc        Service = "copy-disc"       // Port for copy discovery
	ServiceNpmp            Service = "npmp"            // npmp
	ServiceNexentamv       Service = "nexentamv"       // Nexenta Management GUI
	ServiceCiscoAvp        Service = "cisco-avp"       // Cisco Address Validation Protocol
	ServicePimPort         Service = "pim-port"        // PIM over Reliable Transport
	ServiceOtv             Service = "otv"             // Overlay Transport Virtualization (OTV)
	ServiceVp2p            Service = "vp2p"            // Virtual Point to Point
	ServiceNoteshare       Service = "noteshare"       // AquaMinds NoteShare
	ServiceFmtp            Service = "fmtp"            // Flight Message Transfer Protocol
	ServiceCmtpMgt         Service = "cmtp-mgt"        // CYTEL Message Transfer Management
	ServiceCmtpAv          Service = "cmtp-av"         // CYTEL Message Transfer Audio and Video
	ServiceRtspAlt         Service = "rtsp-alt"        // RTSP Alternate (see port 554)
	ServiceDFence          Service = "d-fence"         // SYMAX D-FENCE
	ServiceEncTunnel       Service = "enc-tunnel"      // EMIT tunneling protocol
	ServiceAsterix         Service = "asterix"         // Surveillance Data
	ServiceCanonCppDisc    Service = "canon-cpp-disc"  // Canon Compact Printer Protocol Discovery
	ServiceCanonMfnp       Service = "canon-mfnp"      // Canon MFNP Service
	ServiceCanonBjnp1      Service = "canon-bjnp1"     // Canon BJNP Port 1
	ServiceCanonBjnp2      Service = "canon-bjnp2"     // Canon BJNP Port 2
	ServiceCanonBjnp3      Service = "canon-bjnp3"     // Canon BJNP Port 3
	ServiceCanonBjnp4      Service = "canon-bjnp4"     // Canon BJNP Port 4
	ServiceImink           Service = "imink"           // Imink Service Control
	ServiceMonetra         Service = "monetra"         // Monetra
	ServiceMonetraAdmin    Service = "monetra-admin"   // Monetra Administrative
	ServiceMsiCpsRm        Service = "msi-cps-rm"      // Programming Software for Radio Management Motorola Solutions Customer
	ServiceMsiCpsRmDisc    Service = "msi-cps-rm-disc" // Programming Software for Radio Management Discovery
	ServiceSunAsJmxrmi     Service = "sun-as-jmxrmi"   // Sun App Server - JMX/RMI
	ServiceOpenremoteCtrl  Service = "openremote-ctrl" // OpenRemote Controller
	ServiceVnyx            Service = "vnyx"            // VNYX Primary Port
	ServiceNvc             Service = "nvc"             // Nuance Voice Control
	ServiceDtpNet          Service = "dtp-net"         // DASGIP Net Services
	ServiceIbus            Service = "ibus"            // iBus
	ServiceDeyKeyneg       Service = "dey-keyneg"      // DEY Storage Key Negotiation
	ServiceMcAppserver     Service = "mc-appserver"    // MC-APPSERVER
	ServiceOpenqueue       Service = "openqueue"       // OPENQUEUE
	ServiceUltraseekHttp   Service = "ultraseek-http"  // Ultraseek HTTP
	ServiceAmcs            Service = "amcs"            // Agilent Connectivity Service
	ServiceDpap            Service = "dpap"            // Digital Photo Access Protocol
	ServiceMsgclnt         Service = "msgclnt"         // Message Client
	ServiceMsgsrvr         Service = "msgsrvr"         // Message Server
	ServiceAcdPm           Service = "acd-pm"          // Accedian Performance Measurement
	ServiceSunwebadmin     Service = "sunwebadmin"     // Sun Web Server Admin Service
	ServiceTruecm          Service = "truecm"          // truecm
	ServiceDxspider        Service = "dxspider"        // dxspider linking protocol
	ServiceCddbpAlt        Service = "cddbp-alt"       // CDDBP
	ServiceGalaxy4d        Service = "galaxy4d"        // Galaxy4D Online Game Engine
	ServiceSecureMqtt      Service = "secure-mqtt"     // Secure MQTT
	ServiceDdiTcp1         Service = "ddi-tcp-1"       // NewsEDGE server TCP (TCP 1)
	ServiceDdiUdp1         Service = "ddi-udp-1"       // NewsEDGE server UDP (UDP 1)
	ServiceDdiTcp2         Service = "ddi-tcp-2"       // Desktop Data TCP 1
	ServiceDdiUdp2         Service = "ddi-udp-2"       // NewsEDGE server broadcast
	ServiceDdiTcp3         Service = "ddi-tcp-3"       // Desktop Data TCP 2
	ServiceDdiUdp3         Service = "ddi-udp-3"       // NewsEDGE client broadcast
	ServiceDdiTcp4         Service = "ddi-tcp-4"       // Desktop Data TCP 3: NESS application
	ServiceDdiUdp4         Service = "ddi-udp-4"       // Desktop Data UDP 3: NESS application
	ServiceDdiTcp5         Service = "ddi-tcp-5"       // Desktop Data TCP 4: FARM product
	ServiceDdiUdp5         Service = "ddi-udp-5"       // Desktop Data UDP 4: FARM product
	ServiceDdiTcp6         Service = "ddi-tcp-6"       // Desktop Data TCP 5: NewsEDGE/Web application
	ServiceDdiUdp6         Service = "ddi-udp-6"       // Desktop Data UDP 5: NewsEDGE/Web application
	ServiceDdiTcp7         Service = "ddi-tcp-7"       // Desktop Data TCP 6: COAL application
	ServiceDdiUdp7         Service = "ddi-udp-7"       // Desktop Data UDP 6: COAL application
	ServiceOspfLite        Service = "ospf-lite"       // ospf-lite
	ServiceJmbCds1         Service = "jmb-cds1"        // JMB-CDS 1
	ServiceJmbCds2         Service = "jmb-cds2"        // JMB-CDS 2
	ServiceManyoneHttp     Service = "manyone-http"    // manyone-http
	ServiceManyoneXml      Service = "manyone-xml"     // manyone-xml
	ServiceWcbackup        Service = "wcbackup"        // Windows Client Backup
	ServiceDragonfly       Service = "dragonfly"       // Dragonfly System Service
	ServiceTwds            Service = "twds"            // Transaction Warehouse Data Service
	ServiceUbDnsControl    Service = "ub-dns-control"  // unbound dns nameserver control
	ServiceCumulusAdmin    Service = "cumulus-admin"   // Cumulus Admin Port
	ServiceSunwebadmins    Service = "sunwebadmins"    // Sun Web Server SSL Admin Service
	ServiceHttpWmap        Service = "http-wmap"       // webmail HTTP service
	ServiceHttpsWmap       Service = "https-wmap"      // webmail HTTPS service
	ServiceBctp            Service = "bctp"            // Brodos Crypto Trade Protocol
	ServiceCslistener      Service = "cslistener"      // CSlistener
	ServiceEtlservicemgr   Service = "etlservicemgr"   // ETL Service Manager
	ServiceDynamid         Service = "dynamid"         // DynamID authentication
	ServiceOgsClient       Service = "ogs-client"      // Open Grid Services Client
	ServiceOgsServer       Service = "ogs-server"      // Open Grid Services Server
	ServicePichat          Service = "pichat"          // Pichat Server
	ServiceSdr             Service = "sdr"             // Secure Data Replicator Protocol
	ServiceTambora         Service = "tambora"         // TAMBORA
	ServicePanagolinIdent  Service = "panagolin-ident" // Pangolin Identification
	ServiceParagent        Service = "paragent"        // PrivateArk Remote Agent
	ServiceSwa1            Service = "swa-1"           // Secure Web Access - 1
	ServiceSwa2            Service = "swa-2"           // Secure Web Access - 2
	ServiceSwa3            Service = "swa-3"           // Secure Web Access - 3
	ServiceSwa4            Service = "swa-4"           // Secure Web Access - 4
	ServiceVersiera        Service = "versiera"        // Versiera Agent Listener
	ServiceFioCmgmt        Service = "fio-cmgmt"       // Fusion-io Central Manager Service
	ServiceGlrpc           Service = "glrpc"           // Groove GLRPC
	ServiceLcsAp           Service = "lcs-ap"          // LCS Application Protocol
	ServiceEmcPpMgmtsvc    Service = "emc-pp-mgmtsvc"  // EMC PowerPath Mgmt Service
	ServiceAurora          Service = "aurora"          // IBM AURORA Performance Visualizer
	ServiceIbmRsyscon      Service = "ibm-rsyscon"     // IBM Remote System Console
	ServiceNet2display     Service = "net2display"     // Vesa Net2Display
	ServiceClassic         Service = "classic"         // Classic Data Server
	ServiceSqlexec         Service = "sqlexec"         // IBM Informix SQL Interface
	ServiceSqlexecSsl      Service = "sqlexec-ssl"     // IBM Informix SQL Interface - Encrypted
	ServiceWebsm           Service = "websm"           // WebSM
	ServiceXmltecXmlmail   Service = "xmltec-xmlmail"  // xmltec-xmlmail
	ServiceXmlIpcRegSvc    Service = "XmlIpcRegSvc"    // Xml-Ipc Server Reg
	ServiceCopycat         Service = "copycat"         // Copycat database replication service
	ServiceHpPdlDatastr    Service = "hp-pdl-datastr"  // PDL Data Streaming Port
	ServiceBaculaDir       Service = "bacula-dir"      // Bacula Director
	ServiceBaculaFd        Service = "bacula-fd"       // Bacula File Daemon
	ServiceBaculaSd        Service = "bacula-sd"       // Bacula Storage Daemon
	ServicePeerwire        Service = "peerwire"        // PeerWire
	ServiceXadmin          Service = "xadmin"          // Xadmin Control Service
	ServiceAstergate       Service = "astergate"       // Astergate Control Service
	ServiceAstergateDisc   Service = "astergate-disc"  // Astergate Discovery Service
	ServiceAstergatefax    Service = "astergatefax"    // AstergateFax Control Service
	ServiceMxit            Service = "mxit"            // MXit Instant Messaging
	ServiceGrcmp           Service = "grcmp"           // Global Relay compliant mobile IM protocol
	ServiceGrcp            Service = "grcp"            // Global Relay compliant IM protocol
	ServiceDddp            Service = "dddp"            // Dynamic Device Discovery
	ServiceApani1          Service = "apani1"          // apani1
	ServiceApani2          Service = "apani2"          // apani2
	ServiceApani3          Service = "apani3"          // apani3
	ServiceApani4          Service = "apani4"          // apani4
	ServiceApani5          Service = "apani5"          // apani5
	ServiceSunAsJpda       Service = "sun-as-jpda"     // Sun AppSvr JPDA
	ServiceWapWsp          Service = "wap-wsp"         // WAP connectionless session service
	ServiceWapWspWtp       Service = "wap-wsp-wtp"     // WAP session service
	ServiceWapWspS         Service = "wap-wsp-s"       // WAP secure connectionless session service
	ServiceWapWspWtpS      Service = "wap-wsp-wtp-s"   // WAP secure session service
	ServiceWapVcard        Service = "wap-vcard"       // WAP vCard
	ServiceWapVcal         Service = "wap-vcal"        // WAP vCal
	ServiceWapVcardS       Service = "wap-vcard-s"     // WAP vCard Secure
	ServiceWapVcalS        Service = "wap-vcal-s"      // WAP vCal Secure
	ServiceRjcdbVcards     Service = "rjcdb-vcards"    // rjcdb vCard
	ServiceAlmobileSystem  Service = "almobile-system" // ALMobile System Service
	ServiceOmaMlp          Service = "oma-mlp"         // OMA Mobile Location Protocol
	ServiceOmaMlpS         Service = "oma-mlp-s"       // OMA Mobile Location Protocol Secure
	ServiceServerviewdbms  Service = "serverviewdbms"  // Server View dbms access
	ServiceServerstart     Service = "serverstart"     // ServerStart RemoteControl
	ServiceIpdcesgbs       Service = "ipdcesgbs"       // IPDC ESG BootstrapService
	ServiceInsis           Service = "insis"           // Integrated Setup and Install Service
	ServiceAcme            Service = "acme"            // Aionex Communication Management Engine
	ServiceFscPort         Service = "fsc-port"        // FSC Communication Port
	ServiceTeamcoherence   Service = "teamcoherence"   // QSC Team Coherence
	ServiceTraingpsdata    Service = "traingpsdata"    // GPS Data transmition from train to ground network
	ServicePegasus         Service = "pegasus"         // Pegasus GPS Platform
	ServicePegasusCtl      Service = "pegasus-ctl"     // Pegaus GPS System Control Interface
	ServicePgps            Service = "pgps"            // Predicted GPS
	ServiceSwtpPort1       Service = "swtp-port1"      // SofaWare transport port 1
	ServiceSwtpPort2       Service = "swtp-port2"      // SofaWare transport port 2
	ServiceCallwaveiam     Service = "callwaveiam"     // CallWaveIAM
	ServiceVisd            Service = "visd"            // VERITAS Information Serve
	ServiceN2h2server      Service = "n2h2server"      // N2H2 Filter Service Port
	ServiceN2receive       Service = "n2receive"       // n2 monitoring receiver
	ServiceCumulus         Service = "cumulus"         // Cumulus
	ServiceArmtechdaemon   Service = "armtechdaemon"   // ArmTech Daemon
	ServiceStorview        Service = "storview"        // StorView Client
	ServiceArmcenterhttp   Service = "armcenterhttp"   // ARMCenter http Service
	ServiceArmcenterhttps  Service = "armcenterhttps"  // ARMCenter https Service
	ServiceVrace           Service = "vrace"           // Virtual Racing Service
	ServiceSphinxql        Service = "sphinxql"        // Sphinx search server (MySQL listener)
	ServiceSphinxapi       Service = "sphinxapi"       // Sphinx search server
	ServiceSecureTs        Service = "secure-ts"       // PKIX TimeStamp over TLS
	ServiceGuibase         Service = "guibase"         // guibase
	ServiceMpidcmgr        Service = "mpidcmgr"        // MpIdcMgr
	ServiceMphlpdmc        Service = "mphlpdmc"        // Mphlpdmc
	ServiceCtechlicensing  Service = "ctechlicensing"  // C Tech Licensing
	ServiceFjdmimgr        Service = "fjdmimgr"        // fjdmimgr
	ServiceBoxp            Service = "boxp"            // Brivs! Open Extensible Protocol
	ServiceD2dconfig       Service = "d2dconfig"       // D2D Configuration Service
	ServiceD2ddatatrans    Service = "d2ddatatrans"    // D2D Data Transfer Service
	ServiceAdws            Service = "adws"            // Active Directory Web Services
	ServiceOtp             Service = "otp"             // OpenVAS Transfer Protocol
	ServiceFjinvmgr        Service = "fjinvmgr"        // fjinvmgr
	ServiceMpidcagt        Service = "mpidcagt"        // MpIdcAgt
	ServiceSecT4netSrv     Service = "sec-t4net-srv"   // Samsung Twain for Network Server
	ServiceSecT4netClt     Service = "sec-t4net-clt"   // Samsung Twain for Network Client
	ServiceSecPc2faxSrv    Service = "sec-pc2fax-srv"  // Samsung PC2FAX for Network Server
	ServiceGit             Service = "git"             // git pack transfer service
	ServiceTungstenHttps   Service = "tungsten-https"  // WSO2 Tungsten HTTPS
	ServiceWso2esbConsole  Service = "wso2esb-console" // WSO2 ESB Administration Console HTTPS
	ServiceMindarrayCa     Service = "mindarray-ca"    // MindArray Systems Console Agent
	ServiceSntlkeyssrvr    Service = "sntlkeyssrvr"    // Sentinel Keys Server
	ServiceIsmserver       Service = "ismserver"       // ismserver
	ServiceSmaSpw          Service = "sma-spw"         // SMA Speedwire
	ServiceMngsuite        Service = "mngsuite"        // Management Suite Remote Control
	ServiceLaesBf          Service = "laes-bf"         // Surveillance buffering function
	ServiceTrispenSra      Service = "trispen-sra"     // Trispen Secure Remote Access
	ServiceLdgateway       Service = "ldgateway"       // LANDesk Gateway
	ServiceCba8            Service = "cba8"            // LANDesk Management Agent (cba8)
	ServiceMsgsys          Service = "msgsys"          // Message System
	ServicePds             Service = "pds"             // Ping Discovery Service
	ServiceMercuryDisc     Service = "mercury-disc"    // Mercury Discovery
	ServicePdAdmin         Service = "pd-admin"        // PD Administration
	ServiceVscp            Service = "vscp"            // Very Simple Ctrl Protocol
	ServiceRobix           Service = "robix"           // Robix
	ServiceMicromuseNcpw   Service = "micromuse-ncpw"  // MICROMUSE-NCPW
	ServiceStreamcommDs    Service = "streamcomm-ds"   // StreamComm User Directory
	ServiceIadtTls         Service = "iadt-tls"        // iADT Protocol over TLS
	ServiceErunbook_agent  Service = "erunbook_agent"  // eRunbook Agent
	ServiceErunbook_server Service = "erunbook_server" // eRunbook Server
	ServiceCondor          Service = "condor"          // Condor Collector Service
	ServiceOdbcpathway     Service = "odbcpathway"     // ODBC Pathway Service
	ServiceUniport         Service = "uniport"         // UniPort SSO Controller
	ServicePeoctlr         Service = "peoctlr"         // Peovica Controller
	ServicePeocoll         Service = "peocoll"         // Peovica Collector
	ServiceMcComm          Service = "mc-comm"         // Mobile-C Communications
	ServicePqsflows        Service = "pqsflows"        // ProQueSys Flows Service
	ServiceXmms2           Service = "xmms2"           // Cross-platform Music Multiplexing System
	ServiceTec5Sdctp       Service = "tec5-sdctp"      // tec5 Spectral Device Control Protocol
	ServiceClientWakeup    Service = "client-wakeup"   // T-Mobile Client Wakeup Message
	ServiceCcnx            Service = "ccnx"            // Content Centric Networking
	ServiceBoardRoar       Service = "board-roar"      // Board M.I.T. Service
	ServiceL5nasParchan    Service = "l5nas-parchan"   // L5NAS Parallel Channel
	ServiceBoardVoip       Service = "board-voip"      // Board M.I.T. Synchronous Collaboration
	ServiceRasadv          Service = "rasadv"          // rasadv
	ServiceTungstenHttp    Service = "tungsten-http"   // WSO2 Tungsten HTTP
	ServiceDavsrc          Service = "davsrc"          // WebDav Source Port
	ServiceSstp2           Service = "sstp-2"          // Sakura Script Transfer Protocol-2
	ServiceDavsrcs         Service = "davsrcs"         // WebDAV Source TLS/SSL
	ServiceSapv1           Service = "sapv1"           // Session Announcement v1
	ServiceSd              Service = "sd"              // Session Director
	ServiceKcaService      Service = "kca-service"     // Certificate Issuance
	ServiceCyborgSystems   Service = "cyborg-systems"  // CYBORG Systems
	ServiceGtProxy         Service = "gt-proxy"        // Port for Cable network related data proxy or repeater
	ServiceMonkeycom       Service = "monkeycom"       // MonkeyCom
	ServiceSctpTunneling   Service = "sctp-tunneling"  // SCTP TUNNELING
	ServiceIua             Service = "iua"             // IUA
	ServiceEnrp            Service = "enrp"            // enrp server channel
	ServiceEnrpSctp        Service = "enrp-sctp"       // enrp server channel
	ServiceEnrpSctpTls     Service = "enrp-sctp-tls"   // enrp/tls server channel
	ServiceMulticastPing   Service = "multicast-ping"  // Multicast Ping Protocol
	ServiceDomaintime      Service = "domaintime"      // domaintime
	ServiceSypeTransport   Service = "sype-transport"  // SYPECom Transport Protocol
	ServiceApc9950         Service = "apc-9950"        // APC 9950
	ServiceApc9951         Service = "apc-9951"        // APC 9951
	ServiceApc9952         Service = "apc-9952"        // APC 9952
	ServiceAcis            Service = "acis"            // 9953
	ServiceHinp            Service = "hinp"            // HaloteC Instrument Network
	ServiceAlljoynStm      Service = "alljoyn-stm"     // Contact Port for AllJoyn
	ServiceAlljoynMcm      Service = "alljoyn-mcm"     // multiplexed constrained messaging
	ServiceAlljoyn         Service = "alljoyn"         // Alljoyn Name Service
	ServiceOdnsp           Service = "odnsp"           // OKI Data Network Setting Protocol
	ServiceXybridRt        Service = "xybrid-rt"       // XYBRID RT Server
	ServiceDsmScmTarget    Service = "dsm-scm-target"  // DSM/SCM Target Interface
	ServiceNsesrvr         Service = "nsesrvr"         // Software Essentials Secure HTTP server
	ServiceOsmAppsrvr      Service = "osm-appsrvr"     // OSM Applet Server
	ServiceOsmOev          Service = "osm-oev"         // OSM Event Server
	ServicePalace1         Service = "palace-1"        // OnLive-1
	ServicePalace2         Service = "palace-2"        // OnLive-2
	ServicePalace3         Service = "palace-3"        // OnLive-3
	ServicePalace4         Service = "palace-4"        // Palace-4
	ServicePalace5         Service = "palace-5"        // Palace-5
	ServicePalace6         Service = "palace-6"        // Palace-6
	ServiceDistinct32      Service = "distinct32"      // Distinct32
	ServiceDistinct        Service = "distinct"        // distinct
	ServiceNdmp            Service = "ndmp"            // Network Data Management Protocol
	ServiceScpConfig       Service = "scp-config"      // SCP Configuration
	ServiceDocumentum      Service = "documentum"      // EMC-Documentum Content Server Product
	ServiceDocumentum_s    Service = "documentum_s"    // EMC-Documentum Content Server Product
	ServiceEmcrmirccd      Service = "emcrmirccd"      // EMC Replication Manager Client
	ServiceEmcrmird        Service = "emcrmird"        // EMC Replication Manager Server
	ServiceMvsCapacity     Service = "mvs-capacity"    // MVS Capacity
	ServiceOctopus         Service = "octopus"         // Octopus Multiplexer
	ServiceSwdtpSv         Service = "swdtp-sv"        // Systemwalker Desktop Patrol
	ServiceRxapi           Service = "rxapi"           // ooRexx rxapi services
	ServiceZabbixAgent     Service = "zabbix-agent"    // Zabbix Agent
	ServiceZabbixTrapper   Service = "zabbix-trapper"  // Zabbix Trapper
	ServiceQptlmd          Service = "qptlmd"          // Quantapoint FLEXlm Licensing Service
	ServiceItapDdtp        Service = "itap-ddtp"       // VERITAS ITAP DDTP
	ServiceEzmeeting2      Service = "ezmeeting-2"     // eZmeeting
	ServiceEzproxy2        Service = "ezproxy-2"       // eZproxy
	ServiceEzrelay         Service = "ezrelay"         // eZrelay
	ServiceSwdtp           Service = "swdtp"           // Systemwalker Desktop Patrol
	ServiceBctpServer      Service = "bctp-server"     // VERITAS BCTP, server
	ServiceNmea0183        Service = "nmea-0183"       // NMEA-0183 Navigational Data
	ServiceNmeaOnenet      Service = "nmea-onenet"     // NMEA OneNet multicast messaging
	ServiceNetiqEndpoint   Service = "netiq-endpoint"  // NetIQ Endpoint
	ServiceNetiqQcheck     Service = "netiq-qcheck"    // NetIQ Qcheck
	ServiceNetiqEndpt      Service = "netiq-endpt"     // NetIQ Endpoint
	ServiceNetiqVoipa      Service = "netiq-voipa"     // NetIQ VoIP Assessor
	ServiceIqrm            Service = "iqrm"            // NetIQ IQCResource Managament Svc
	ServiceBmcPerfSd       Service = "bmc-perf-sd"     // BMC-PERFORM-SERVICE DAEMON
	ServiceBmcGms          Service = "bmc-gms"         // BMC General Manager Server
	ServiceQbDbServer      Service = "qb-db-server"    // QB Database Server
	ServiceSnmptls         Service = "snmptls"         // SNMP-TLS
	ServiceSnmpdtls        Service = "snmpdtls"        // SNMP-DTLS
	ServiceSnmptlsTrap     Service = "snmptls-trap"    // SNMP-Trap-TLS
	ServiceSnmpdtlsTrap    Service = "snmpdtls-trap"   // SNMP-Trap-DTLS
	ServiceTrisoap         Service = "trisoap"         // Trigence AE Soap Service
	ServiceRsms            Service = "rsms"            // Remote Server Management Service
	ServiceRscs            Service = "rscs"            // Remote Server Control and Test Service
	ServiceApolloRelay     Service = "apollo-relay"    // Apollo Relay Port
	ServiceAxisWimpPort    Service = "axis-wimp-port"  // Axis WIMP Port
	ServiceBlocks          Service = "blocks"          // Blocks
	ServiceCosir           Service = "cosir"           // Computer Op System Information Report
	ServiceHipNatT         Service = "hip-nat-t"       // HIP NAT-traversal
	ServiceMOSLower        Service = "MOS-lower"       // MOS Media Object Metadata Port
	ServiceMOSUpper        Service = "MOS-upper"       // MOS Running Order Port
	ServiceMOSAux          Service = "MOS-aux"         // MOS Low Priority Port
	ServiceMOSSoap         Service = "MOS-soap"        // MOS SOAP Default Port
	ServiceMOSSoapOpt      Service = "MOS-soap-opt"    // MOS SOAP Optional Port
	ServicePrintopia       Service = "printopia"       // administration and control of "Printopia"
	ServiceGap             Service = "gap"             // Gestor de Acaparamiento para Pocket PCs
	ServiceLpdg            Service = "lpdg"            // LUCIA Pareja Data Group
	ServiceNbd             Service = "nbd"             // Linux Network Block Device
	ServiceNmcDisc         Service = "nmc-disc"        // Nuance Mobile Care Discovery
	ServiceHelix           Service = "helix"           // Helix Client/Server
	ServiceBveapi          Service = "bveapi"          // BVEssentials HTTP API
	ServiceRmiaux          Service = "rmiaux"          // Auxiliary RMI Port
	ServiceIrisa           Service = "irisa"           // IRISA
	ServiceMetasys         Service = "metasys"         // Metasys
	ServiceOrigoSync       Service = "origo-sync"      // OrigoDB Server Sync
	ServiceNetappIcmgmt    Service = "netapp-icmgmt"   // NetApp Intercluster Management
	ServiceNetappIcdata    Service = "netapp-icdata"   // NetApp Intercluster Data
	ServiceSgiLk           Service = "sgi-lk"          // SGI LK Licensing service
	ServiceSgiDmfmgr       Service = "sgi-dmfmgr"      // Data migration facility manager
	ServiceSgiSoap         Service = "sgi-soap"        // Data migration facility SOAP
	ServiceVce             Service = "vce"             // Viral Computing Environment (VCE)
	ServiceDicom           Service = "dicom"           // DICOM
	ServiceSuncacaoSnmp    Service = "suncacao-snmp"   // sun cacao snmp access point
	ServiceSuncacaoJmxmp   Service = "suncacao-jmxmp"  // sun cacao JMX-remoting access point
	ServiceSuncacaoRmi     Service = "suncacao-rmi"    // sun cacao rmi registry access point
	ServiceSuncacaoCsa     Service = "suncacao-csa"    // sun cacao command-streaming access point
	ServiceSuncacaoWebsvc  Service = "suncacao-websvc" // sun cacao web service access point
	ServiceSnss            Service = "snss"            // Surgical Notes Security Service Discovery (SNSS)
	ServiceOemcacaoJmxmp   Service = "oemcacao-jmxmp"  // OEM cacao JMX-remoting access point
	ServiceT5Straton       Service = "t5-straton"      // Straton Runtime Programing
	ServiceOemcacaoRmi     Service = "oemcacao-rmi"    // OEM cacao rmi registry access point
	ServiceOemcacaoWebsvc  Service = "oemcacao-websvc" // OEM cacao web service access point
	ServiceSmsqp           Service = "smsqp"           // smsqp
	ServiceDcslBackup      Service = "dcsl-backup"     // DCSL Network Backup Services
	ServiceWifree          Service = "wifree"          // WiFree Service
	ServiceMemcache        Service = "memcache"        // Memory cache service
	ServiceImip            Service = "imip"            // IMIP
	ServiceImipChannels    Service = "imip-channels"   // IMIP Channels Port
	ServiceArenaServer     Service = "arena-server"    // Arena Server Listen
	ServiceAtmUhas         Service = "atm-uhas"        // ATM UHAS
	ServiceTempestPort     Service = "tempest-port"    // Tempest Protocol Port
	ServiceIntrepidSsl     Service = "intrepid-ssl"    // Intrepid SSL
	ServiceLanschool       Service = "lanschool"       // LanSchool
	ServiceLanschoolMpt    Service = "lanschool-mpt"   // Lanschool Multipoint
	ServiceXoraya          Service = "xoraya"          // X2E Xoraya Multichannel protocol
	ServiceX2eDisc         Service = "x2e-disc"        // X2E service discovery protocol
	ServiceSysinfoSp       Service = "sysinfo-sp"      // SysInfo Service Protocol
	ServiceWmereceiving    Service = "wmereceiving"    // WorldMailExpress
	ServiceWmedistribution Service = "wmedistribution" // WorldMailExpress
	ServiceWmereporting    Service = "wmereporting"    // WorldMailExpress
	ServiceEntextxid       Service = "entextxid"       // IBM Enterprise Extender SNA XID Exchange
	ServiceEntextnetwk     Service = "entextnetwk"     // IBM Enterprise Extender SNA COS Network Priority
	ServiceEntexthigh      Service = "entexthigh"      // IBM Enterprise Extender SNA COS High Priority
	ServiceEntextmed       Service = "entextmed"       // IBM Enterprise Extender SNA COS Medium Priority
	ServiceEntextlow       Service = "entextlow"       // IBM Enterprise Extender SNA COS Low Priority
	ServiceDbisamserver1   Service = "dbisamserver1"   // DBISAM Database Server - Regular
	ServiceDbisamserver2   Service = "dbisamserver2"   // DBISAM Database Server - Admin
	ServiceAccuracer       Service = "accuracer"       // Accuracer Database System √± Server
	ServiceAccuracerDbms   Service = "accuracer-dbms"  // Accuracer Database System √± Admin
	ServiceGhvpn           Service = "ghvpn"           // Green Hills VPN
	ServiceEdbsrvr         Service = "edbsrvr"         // ElevateDB Server
	ServiceVipera          Service = "vipera"          // Vipera Messaging Service
	ServiceViperaSsl       Service = "vipera-ssl"      // Vipera Messaging Service over SSL Communication
	ServiceRetsSsl         Service = "rets-ssl"        // RETS over SSL
	ServiceNupaperSs       Service = "nupaper-ss"      // NuPaper Session Service
	ServiceCawas           Service = "cawas"           // CA Web Access Service
	ServiceHivep           Service = "hivep"           // HiveP
	ServiceLinogridengine  Service = "linogridengine"  // LinoGrid Engine
	ServiceRads            Service = "rads"            // Remote Administration Daemon
	ServiceWarehouseSss    Service = "warehouse-sss"   // Warehouse Monitoring Syst SSS
	ServiceWarehouse       Service = "warehouse"       // Warehouse Monitoring Syst
	ServiceItalk           Service = "italk"           // Italk Chat System
	ServiceTsaf            Service = "tsaf"            // tsaf port
	ServiceNetperf         Service = "netperf"         // control port for netperf benchmark
	ServiceIZipqd          Service = "i-zipqd"         // I-ZIPQD
	ServiceBcslogc         Service = "bcslogc"         // Black Crow Software application logging
	ServiceRsPias          Service = "rs-pias"         // R&S Proxy Installation Assistant Service
	ServiceEmcVcasTcp      Service = "emc-vcas-tcp"    // EMC Virtual CAS Service
	ServiceEmcVcasUdp      Service = "emc-vcas-udp"    // EMV Virtual CAS Service Discovery
	ServicePowwowClient    Service = "powwow-client"   // PowWow Client
	ServicePowwowServer    Service = "powwow-server"   // PowWow Server
	ServiceDoipData        Service = "doip-data"       // DoIP Data
	ServiceDoipDisc        Service = "doip-disc"       // DoIP Discovery
	ServiceNbdb            Service = "nbdb"            // NetBackup Database
	ServiceNomdb           Service = "nomdb"           // Veritas-nomdb
	ServiceDsmccConfig     Service = "dsmcc-config"    // DSMCC Config
	ServiceDsmccSession    Service = "dsmcc-session"   // DSMCC Session Messages
	ServiceDsmccPassthru   Service = "dsmcc-passthru"  // DSMCC Pass-Thru Messages
	ServiceDsmccDownload   Service = "dsmcc-download"  // DSMCC Download Protocol
	ServiceDsmccCcp        Service = "dsmcc-ccp"       // DSMCC Channel Change Protocol
	ServiceBmdss           Service = "bmdss"           // Blackmagic Design Streaming Server
	ServiceUcontrol        Service = "ucontrol"        // Ultimate Control communication protocol
	ServiceDtaSystems      Service = "dta-systems"     // D-TA SYSTEMS
	ServiceMedevolve       Service = "medevolve"       // MedEvolve Port Requester
	ServiceScottyFt        Service = "scotty-ft"       // SCOTTY High-Speed Filetransfer
	ServiceSua             Service = "sua"             // SUA
	ServiceScottyDisc      Service = "scotty-disc"     // Discovery of a SCOTTY hardware codec board
	ServiceSageBestCom1    Service = "sage-best-com1"  // sage Best! Config Server 1
	ServiceSageBestCom2    Service = "sage-best-com2"  // sage Best! Config Server 2
	ServiceVcsApp          Service = "vcs-app"         // VCS Application
	ServiceIcpp            Service = "icpp"            // IceWall Cert Protocol
	ServiceGcmApp          Service = "gcm-app"         // GCM Application
	ServiceVrtsTdd         Service = "vrts-tdd"        // Veritas Traffic Director
	ServiceVcscmd          Service = "vcscmd"          // Veritas Cluster Server Command Server
	ServiceVad             Service = "vad"             // Veritas Application Director
	ServiceCps             Service = "cps"             // Fencing Server
	ServiceCaWebUpdate     Service = "ca-web-update"   // CA eTrust Web Update Service
	ServiceHdeLcesrvr1     Service = "hde-lcesrvr-1"   // hde-lcesrvr-1
	ServiceHdeLcesrvr2     Service = "hde-lcesrvr-2"   // hde-lcesrvr-2
	ServiceHydap           Service = "hydap"           // Hypack Data Aquisition
	ServiceV2gSecc         Service = "v2g-secc"        // v2g Supply Equipment Communication Controller Discovery Protocol
	ServiceXpilot          Service = "xpilot"          // XPilot Contact Port
	Service3link           Service = "3link"           // 3Link Negotiation
	ServiceCiscoSnat       Service = "cisco-snat"      // Cisco Stateful NAT
	ServiceBexXr           Service = "bex-xr"          // Backup Express Restore Server
	ServicePtp             Service = "ptp"             // Picture Transfer Protocol
	Service2ping           Service = "2ping"           // 2ping Bi-Directional Ping Service
	ServiceProgrammar      Service = "programmar"      // ProGrammar Enterprise
	ServiceFmsas           Service = "fmsas"           // Administration Server Access
	ServiceFmsascon        Service = "fmsascon"        // Administration Server Connector
	ServiceGsms            Service = "gsms"            // GoodSync Mediation Service
	ServiceAlfin           Service = "alfin"           // Automation and Control by REGULACE.ORG
	ServiceJwpc            Service = "jwpc"            // Filemaker Java Web Publishing Core
	ServiceJwpcBin         Service = "jwpc-bin"        // Filemaker Java Web Publishing Core Binary
	ServiceSunSeaPort      Service = "sun-sea-port"    // Solaris SEA Port
	ServiceSolarisAudit    Service = "solaris-audit"   // Solaris Audit - secure remote audit log
	ServiceEtb4j           Service = "etb4j"           // etb4j
	ServicePduncs          Service = "pduncs"          // Policy Distribute, Update Notification
	ServicePdefmns         Service = "pdefmns"         // Policy definition and update management
	ServiceNetserialext1   Service = "netserialext1"   // Network Serial Extension Ports One
	ServiceNetserialext2   Service = "netserialext2"   // Network Serial Extension Ports Two
	ServiceNetserialext3   Service = "netserialext3"   // Network Serial Extension Ports Three
	ServiceNetserialext4   Service = "netserialext4"   // Network Serial Extension Ports Four
	ServiceConnected       Service = "connected"       // Connected Corp
	ServiceXoms            Service = "xoms"            // X509 Objects Management Service
	ServiceVtp             Service = "vtp"             // Vidder Tunnel Protocol
	ServiceNewbaySncMc     Service = "newbay-snc-mc"   // Newbay Mobile Client Update Service
	ServiceSgcip           Service = "sgcip"           // Simple Generic Client Interface Protocol
	ServiceIntelRciMp      Service = "intel-rci-mp"    // INTEL-RCI-MP
	ServiceAmtSoapHttp     Service = "amt-soap-http"   // Intel(R) AMT SOAP/HTTP
	ServiceAmtSoapHttps    Service = "amt-soap-https"  // Intel(R) AMT SOAP/HTTPS
	ServiceAmtRedirTcp     Service = "amt-redir-tcp"   // Intel(R) AMT Redirection/TCP
	ServiceAmtRedirTls     Service = "amt-redir-tls"   // Intel(R) AMT Redirection/TLS
	ServiceIsodeDua        Service = "isode-dua"       //
	ServiceSoundsvirtual   Service = "soundsvirtual"   // Sounds Virtual
	ServiceChipper         Service = "chipper"         // Chipper
	ServiceAvdecc          Service = "avdecc"          // IEEE 1722.1 AVB Discovery, Enumeration, Connection management, and Control
	ServiceCpsp            Service = "cpsp"            // Control Plane Synchronization Protocol
	ServiceIntegriusStp    Service = "integrius-stp"   // Integrius Secure Tunnel Protocol
	ServiceSshMgmt         Service = "ssh-mgmt"        // SSH Tectia Manager
	ServiceDbLsp           Service = "db-lsp"          // Dropbox LanSync Protocol
	ServiceDbLspDisc       Service = "db-lsp-disc"     // Dropbox LanSync Discovery
	ServiceEa              Service = "ea"              // Eclipse Aviation
	ServiceZep             Service = "zep"             // Encap. ZigBee Packets
	ServiceZigbeeIp        Service = "zigbee-ip"       // ZigBee IP Transport Service
	ServiceZigbeeIps       Service = "zigbee-ips"      // ZigBee IP Transport Secure Service
	ServiceSwOrion         Service = "sw-orion"        // SolarWinds Orion
	ServiceBiimenu         Service = "biimenu"         // Beckman Instruments, Inc.
	ServiceRadpdf          Service = "radpdf"          // RAD PDF Service
	ServiceRacf            Service = "racf"            // z/OS Resource Access Control Facility
	ServiceOpsecCvp        Service = "opsec-cvp"       // OPSEC CVP
	ServiceOpsecUfp        Service = "opsec-ufp"       // OPSEC UFP
	ServiceOpsecSam        Service = "opsec-sam"       // OPSEC SAM
	ServiceOpsecLea        Service = "opsec-lea"       // OPSEC LEA
	ServiceOpsecOmi        Service = "opsec-omi"       // OPSEC OMI
	ServiceOhsc            Service = "ohsc"            // Occupational Health SC
	ServiceOpsecEla        Service = "opsec-ela"       // OPSEC ELA
	ServiceCheckpointRtm   Service = "checkpoint-rtm"  // Check Point RTM
	ServiceIclid           Service = "iclid"           // Checkpoint router monitoring
	ServiceClusterxl       Service = "clusterxl"       // Checkpoint router state backup
	ServiceGvPf            Service = "gv-pf"           // GV NetConfig Service
	ServiceAcCluster       Service = "ac-cluster"      // AC Cluster
	ServiceRdsIb           Service = "rds-ib"          // Reliable Datagram Service
	ServiceRdsIp           Service = "rds-ip"          // Reliable Datagram Service over IP
	ServiceIque            Service = "ique"            // IQue Protocol
	ServiceInfotos         Service = "infotos"         // Infotos
	ServiceApcNecmp        Service = "apc-necmp"       // APCNECMP
	ServiceIgrid           Service = "igrid"           // iGrid Server
	ServiceJLink           Service = "j-link"          // J-Link TCP/IP Protocol
	ServiceOpsecUaa        Service = "opsec-uaa"       // OPSEC UAA
	ServiceUaSecureagent   Service = "ua-secureagent"  // UserAuthority SecureAgent
	ServiceKeysrvr         Service = "keysrvr"         // Key Server for SASSAFRAS
	ServiceKeyshadow       Service = "keyshadow"       // Key Shadow for SASSAFRAS
	ServiceMtrgtrans       Service = "mtrgtrans"       // mtrgtrans
	ServiceHpSco           Service = "hp-sco"          // hp-sco
	ServiceHpSca           Service = "hp-sca"          // hp-sca
	ServiceHpSessmon       Service = "hp-sessmon"      // HP-SESSMON
	ServiceFxuptp          Service = "fxuptp"          // FXUPTP
	ServiceSxuptp          Service = "sxuptp"          // SXUPTP
	ServiceJcp             Service = "jcp"             // JCP Client
	ServiceMle             Service = "mle"             // Mesh Link Establishment
	ServiceIec104Sec       Service = "iec-104-sec"     // IEC 60870-5-104 process control - secure
	ServiceDnpSec          Service = "dnp-sec"         // Distributed Network Protocol - Secure
	ServiceDnp             Service = "dnp"             // DNP
	ServiceMicrosan        Service = "microsan"        // MicroSAN
	ServiceCommtactHttp    Service = "commtact-http"   // Commtact HTTP
	ServiceCommtactHttps   Service = "commtact-https"  // Commtact HTTPS
	ServiceOpenwebnet      Service = "openwebnet"      // OpenWebNet protocol for electric network
	ServiceSsIdiDisc       Service = "ss-idi-disc"     // Samsung Interdevice Interaction discovery
	ServiceSsIdi           Service = "ss-idi"          // Samsung Interdevice Interaction
	ServiceOpendeploy      Service = "opendeploy"      // OpenDeploy Listener
	ServiceNburn_id        Service = "nburn_id"        // NetBurner ID Port
	ServiceTmophl7mts      Service = "tmophl7mts"      // TMOP HL7 Message Transfer Service
	ServiceMountd          Service = "mountd"          // NFS mount protocol
	ServiceNfsrdma         Service = "nfsrdma"         // Network File System (NFS) over RDMA
	ServiceTolfab          Service = "tolfab"          // TOLfab Data Change
	ServiceIpdtpPort       Service = "ipdtp-port"      // IPD Tunneling Port
	ServiceIpulseIcs       Service = "ipulse-ics"      // iPulse-ICS
	ServiceEmwavemsg       Service = "emwavemsg"       // emWave Message Service
	ServiceTrack           Service = "track"           // Track
	ServiceAthandMmp       Service = "athand-mmp"      // At Hand MMP
	ServiceIrtrans         Service = "irtrans"         // IRTrans Control
	ServiceRdmTfs          Service = "rdm-tfs"         // Raima RDM TFS
	ServiceDfserver        Service = "dfserver"        // MineScape Design File Server
	ServiceVofrGateway     Service = "vofr-gateway"    // VoFR Gateway
	ServiceTvpm            Service = "tvpm"            // TVNC Pro Multiplexing
	ServiceWebphone        Service = "webphone"        // webphone
	ServiceNetspeakIs      Service = "netspeak-is"     // NetSpeak Corp. Directory Services
	ServiceNetspeakCs      Service = "netspeak-cs"     // NetSpeak Corp. Connection Services
	ServiceNetspeakAcd     Service = "netspeak-acd"    // NetSpeak Corp. Automatic Call Distribution
	ServiceNetspeakCps     Service = "netspeak-cps"    // NetSpeak Corp. Credit Processing System
	ServiceSnapenetio      Service = "snapenetio"      // SNAPenetIO
	ServiceOptocontrol     Service = "optocontrol"     // OptoControl
	ServiceOptohost002     Service = "optohost002"     // Opto Host Port 2
	ServiceOptohost003     Service = "optohost003"     // Opto Host Port 3
	ServiceOptohost004     Service = "optohost004"     // Opto Host Port 4
	ServiceOptohost005     Service = "optohost005"     // Opto Host Port 5
	ServiceDcap            Service = "dcap"            // dCache Access Protocol
	ServiceGsidcap         Service = "gsidcap"         // GSI dCache Access Protocol
	ServiceCis             Service = "cis"             // CompactIS Tunnel
	ServiceCisSecure       Service = "cis-secure"      // CompactIS Secure Tunnel
	ServiceWibuKey         Service = "WibuKey"         // WibuKey Standard WkLan
	ServiceCodeMeter       Service = "CodeMeter"       // CodeMeter Standard
	ServiceCaldsoftBackup  Service = "caldsoft-backup" // CaldSoft Backup server file transfer
	ServiceVocaltecWconf   Service = "vocaltec-wconf"  // Vocaltec Web Conference
	ServiceVocaltecPhone   Service = "vocaltec-phone"  // Vocaltec Internet Phone
	ServiceTalikaserver    Service = "talikaserver"    // Talika Main Server
	ServiceAwsBrf          Service = "aws-brf"         // Telerate Information Platform LAN
	ServiceBrfGw           Service = "brf-gw"          // Telerate Information Platform WAN
	ServiceInovaport1      Service = "inovaport1"      // Inova LightLink Server Type 1
	ServiceInovaport2      Service = "inovaport2"      // Inova LightLink Server Type 2
	ServiceInovaport3      Service = "inovaport3"      // Inova LightLink Server Type 3
	ServiceInovaport4      Service = "inovaport4"      // Inova LightLink Server Type 4
	ServiceInovaport5      Service = "inovaport5"      // Inova LightLink Server Type 5
	ServiceInovaport6      Service = "inovaport6"      // Inova LightLink Server Type 6
	ServiceGntp            Service = "gntp"            // Generic Notification Transport Protocol
	ServiceS102            Service = "s102"            // S102 application
	ServiceElxmgmt         Service = "elxmgmt"         // Emulex HBAnyware Remote Management
	ServiceNovarDbase      Service = "novar-dbase"     // Novar Data
	ServiceNovarAlarm      Service = "novar-alarm"     // Novar Alarm
	ServiceNovarGlobal     Service = "novar-global"    // Novar Global
	ServiceAequus          Service = "aequus"          // Aequus Service
	ServiceAequusAlt       Service = "aequus-alt"      // Aequus Service Mgmt
	ServiceAreaguardNeo    Service = "areaguard-neo"   // AreaGuard Neo - WebServer
	ServiceMedLtp          Service = "med-ltp"         // med-ltp
	ServiceMedFspRx        Service = "med-fsp-rx"      // med-fsp-rx
	ServiceMedFspTx        Service = "med-fsp-tx"      // med-fsp-tx
	ServiceMedSupp         Service = "med-supp"        // med-supp
	ServiceMedOvw          Service = "med-ovw"         // med-ovw
	ServiceMedCi           Service = "med-ci"          // med-ci
	ServiceMedNetSvc       Service = "med-net-svc"     // med-net-svc
	ServiceFilesphere      Service = "filesphere"      // fileSphere
	ServiceVista4gl        Service = "vista-4gl"       // Vista 4GL
	ServiceIld             Service = "ild"             // Isolv Local Directory
	ServiceHid             Service = "hid"             // Human Interface Device data streams transport
	ServiceIntel_rci       Service = "intel_rci"       // Intel RCI
	ServiceTonidods        Service = "tonidods"        // Tonido Domain Server
	ServiceFlashfiler      Service = "flashfiler"      // FlashFiler
	ServiceProactivate     Service = "proactivate"     // Turbopower Proactivate
	ServiceTccHttp         Service = "tcc-http"        // TCC User HTTP Service
	ServiceCslg            Service = "cslg"            // Citrix StorageLink Gateway
	ServiceAssocDisc       Service = "assoc-disc"      // Device Association Discovery
	ServiceFind            Service = "find"            // Find Identification of Network Devices
	ServiceIclTwobase1     Service = "icl-twobase1"    // icl-twobase1
	ServiceIclTwobase2     Service = "icl-twobase2"    // icl-twobase2
	ServiceIclTwobase3     Service = "icl-twobase3"    // icl-twobase3
	ServiceIclTwobase4     Service = "icl-twobase4"    // icl-twobase4
	ServiceIclTwobase5     Service = "icl-twobase5"    // icl-twobase5
	ServiceIclTwobase6     Service = "icl-twobase6"    // icl-twobase6
	ServiceIclTwobase7     Service = "icl-twobase7"    // icl-twobase7
	ServiceIclTwobase8     Service = "icl-twobase8"    // icl-twobase8
	ServiceIclTwobase9     Service = "icl-twobase9"    // icl-twobase9
	ServiceIclTwobase10    Service = "icl-twobase10"   // icl-twobase10
	ServiceRna             Service = "rna"             // RNSAP User Adaptation for Iurh
	ServiceSauterdongle    Service = "sauterdongle"    // Sauter Dongle
	ServiceIdtp            Service = "idtp"            // Identifier Tracing Protocol
	ServiceVocaltecHos     Service = "vocaltec-hos"    // Vocaltec Address Server
	ServiceTaspNet         Service = "tasp-net"        // TASP Network Comm
	ServiceNiobserver      Service = "niobserver"      // NIObserver
	ServiceNilinkanalyst   Service = "nilinkanalyst"   // NILinkAnalyst
	ServiceNiprobe         Service = "niprobe"         // NIProbe
	ServiceBfGame          Service = "bf-game"         // Bitfighter game server
	ServiceBfMaster        Service = "bf-master"       // Bitfighter master server
	ServiceScscp           Service = "scscp"           // Symbolic Computation Software Composability Protocol
	ServiceEzproxy         Service = "ezproxy"         // eZproxy
	ServiceEzmeeting       Service = "ezmeeting"       // eZmeeting
	ServiceK3softwareSvr   Service = "k3software-svr"  // K3 Software-Server
	ServiceK3softwareCli   Service = "k3software-cli"  // K3 Software-Client
	ServiceExolineTcp      Service = "exoline-tcp"     // EXOline-TCP
	ServiceExolineUdp      Service = "exoline-udp"     // EXOline-UDP
	ServiceExoconfig       Service = "exoconfig"       // EXOconfig
	ServiceExonet          Service = "exonet"          // EXOnet
	ServiceImagepump       Service = "imagepump"       // ImagePump
	ServiceJesmsjc         Service = "jesmsjc"         // Job controller service
	ServiceKopekHttphead   Service = "kopek-httphead"  // Kopek HTTP Head Port
	ServiceArsVista        Service = "ars-vista"       // ARS VISTA Application
	ServiceAstrolink       Service = "astrolink"       // Astrolink Protocol
	ServiceTwAuthKey       Service = "tw-auth-key"     // TW Authentication/Key Distribution and
	ServiceNxlmd           Service = "nxlmd"           // NX License Manager
	ServicePqsp            Service = "pqsp"            // PQ Service
	ServiceVoxelstorm      Service = "voxelstorm"      // VoxelStorm game server
	ServiceSiemensgsm      Service = "siemensgsm"      // Siemens GSM
	ServiceSgsap           Service = "sgsap"           // SGsAP in 3GPP
	ServiceA27RanRan       Service = "a27-ran-ran"     // A27 cdma2000 RAN Management
	ServiceOtmp            Service = "otmp"            // ObTools Message Protocol
	ServiceSbcap           Service = "sbcap"           // SBcAP in 3GPP
	ServiceIuhsctpassoc    Service = "iuhsctpassoc"    // HNBAP and RUA Common Association
	ServiceBingbang        Service = "bingbang"        // data exchange protocol for IEC61850 inn wind power plants
	ServiceNdmps           Service = "ndmps"           // Secure Network Data Management Protocol
	ServicePagoServices1   Service = "pago-services1"  // Pago Services 1
	ServicePagoServices2   Service = "pago-services2"  // Pago Services 2
	ServiceKingdomsonline  Service = "kingdomsonline"  // Kingdoms Online (CraigAvenue)
	ServiceOvobs           Service = "ovobs"           // OpenView Service Desk Client
	ServiceAutotracAcp     Service = "autotrac-acp"    // Autotrac ACP 245
	ServiceYawn            Service = "yawn"            // YaWN - Yet Another Windows Notifie
	ServiceXqosd           Service = "xqosd"           // XQoS network monitor
	ServiceTetrinet        Service = "tetrinet"        // TetriNET Protocol
	ServiceLmMon           Service = "lm-mon"          // lm mon
	ServiceDsx_monitor     Service = "dsx_monitor"     // DS Expert Monitor
	ServiceGamesmithPort   Service = "gamesmith-port"  // GameSmith Port
	ServiceIceedcp_tx      Service = "iceedcp_tx"      // Embedded Device Configuration Protocol TX
	ServiceIceedcp_rx      Service = "iceedcp_rx"      // Embedded Device Configuration Protocol RX
	ServiceIracinghelper   Service = "iracinghelper"   // iRacing helper service
	ServiceT1distproc60    Service = "t1distproc60"    // T1 Distributed Processor
	ServiceApmLink         Service = "apm-link"        // Access Point Manager Link
	ServiceSecNtbClnt      Service = "sec-ntb-clnt"    // SecureNotebook-CLNT
	ServiceDMExpress       Service = "DMExpress"       // DMExpress
	ServiceFilenetPowsrm   Service = "filenet-powsrm"  // FileNet BPM WS-ReliableMessaging Client
	ServiceFilenetTms      Service = "filenet-tms"     // Filenet TMS
	ServiceFilenetRpc      Service = "filenet-rpc"     // Filenet RPC
	ServiceFilenetNch      Service = "filenet-nch"     // Filenet NCH
	ServiceFilenetRmi      Service = "filenet-rmi"     // FileNET RMI
	ServiceFilenetPa       Service = "filenet-pa"      // FileNET Process Analyzer
	ServiceFilenetCm       Service = "filenet-cm"      // FileNET Component Manager
	ServiceFilenetRe       Service = "filenet-re"      // FileNET Rules Engine
	ServiceFilenetPch      Service = "filenet-pch"     // Performance Clearinghouse
	ServiceFilenetPeior    Service = "filenet-peior"   // FileNET BPM IOR
	ServiceFilenetObrok    Service = "filenet-obrok"   // FileNet BPM CORBA
	ServiceMlsn            Service = "mlsn"            // Multiple Listing Service Network
	ServiceRetp            Service = "retp"            // Real Estate Transport Protocol
	ServiceIdmgratm        Service = "idmgratm"        // Attachmate ID Manager
	ServiceAuroraBalaena   Service = "aurora-balaena"  // Aurora (Balaena Ltd)
	ServiceDiamondport     Service = "diamondport"     // DiamondCentral Interface
	ServiceDgiServ         Service = "dgi-serv"        // Digital Gaslight Service
	ServiceSpeedtrace      Service = "speedtrace"      // SpeedTrace TraceAgent
	ServiceSpeedtraceDisc  Service = "speedtrace-disc" // SpeedTrace TraceAgent Discovery
	ServiceSnipSlave       Service = "snip-slave"      // SNIP Slave
	ServiceTurbonote2      Service = "turbonote-2"     // TurboNote Relay Server Default Port
	ServicePNetLocal       Service = "p-net-local"     // P-Net on IP local
	ServicePNetRemote      Service = "p-net-remote"    // P-Net on IP remote
	ServiceDhanalakshmi    Service = "dhanalakshmi"    // dhanalakshmi.org EDI Service
	ServiceProfinetRt      Service = "profinet-rt"     // PROFInet RT Unicast
	ServiceProfinetRtm     Service = "profinet-rtm"    // PROFInet RT Multicast
	ServiceProfinetCm      Service = "profinet-cm"     // PROFInet Context Manager
	ServiceEthercat        Service = "ethercat"        // EtherCAT Port
	ServiceHeathview       Service = "heathview"       // HeathView
	ServiceKitim           Service = "kitim"           // KIT Messenger
	ServiceAltovaLm        Service = "altova-lm"       // Altova License Management
	ServiceAltovaLmDisc    Service = "altova-lm-disc"  // Altova License Management Discovery
	ServiceGuttersnex      Service = "guttersnex"      // Gutters Note Exchange
	ServiceOpenstackId     Service = "openstack-id"    // OpenStack ID Service
	ServiceAllpeers        Service = "allpeers"        // AllPeers Network
	ServiceS1Control       Service = "s1-control"      // S1-Control Plane (3GPP)
	ServiceX2Control       Service = "x2-control"      // X2-Control Plane (3GPP)
	ServiceM2ap            Service = "m2ap"            // M2 Application Part
	ServiceM3ap            Service = "m3ap"            // M3 Application Part
	ServiceFebootiAw       Service = "febooti-aw"      // Febooti Automation Workshop
	ServiceKastenxpipe     Service = "kastenxpipe"     // KastenX Pipe
	ServiceNeckar          Service = "neckar"          // science + computing's Venus Administration Port
	ServiceUnisysEportal   Service = "unisys-eportal"  // Unisys ClearPath ePortal
	ServiceGdriveSync      Service = "gdrive-sync"     // Google Drive Sync
	ServiceGalaxy7Data     Service = "galaxy7-data"    // Galaxy7 Data Tunnel
	ServiceFairview        Service = "fairview"        // Fairview Message Service
	ServiceAgpolicy        Service = "agpolicy"        // AppGate Policy Server
	ServiceSruth           Service = "sruth"           // Sruth - University_Corporation_for_Atmospheric_Research
	ServiceSecrmmsafecopya Service = "secrmmsafecopya" // for use of the secRMM SafeCopy program
	ServiceTurbonote1      Service = "turbonote-1"     // TurboNote Default Port
	ServiceSafetynetp      Service = "safetynetp"      // SafetyNET p
	ServiceCscp            Service = "cscp"            // CSCP
	ServiceCsccredir       Service = "csccredir"       // CSCCREDIR
	ServiceCsccfirewall    Service = "csccfirewall"    // CSCCFIREWALL
	ServiceOrtecDisc       Service = "ortec-disc"      // ORTEC Service Discovery
	ServiceFsQos           Service = "fs-qos"          // Foursticks QoS Protocol
	ServiceTentacle        Service = "tentacle"        // Tentacle Server
	ServiceCrestronCip     Service = "crestron-cip"    // Crestron Control Port
	ServiceCrestronCtp     Service = "crestron-ctp"    // Crestron Terminal Port
	ServiceCrestronCips    Service = "crestron-cips"   // Crestron Secure Control Port
	ServiceCrestronCtps    Service = "crestron-ctps"   // Crestron Secure Terminal Port
	ServiceCandp           Service = "candp"           // Computer Associates network discovery protocol
	ServiceCandrp          Service = "candrp"          // CA discovery response
	ServiceCaerpc          Service = "caerpc"          // CA eTrust RPC
	ServiceRecvrRc         Service = "recvr-rc"        // Receiver Remote Control
	ServiceRecvrRcDisc     Service = "recvr-rc-disc"   // Receiver Remote Control Discovery
	ServiceReachout        Service = "reachout"        // REACHOUT
	ServiceNdmAgentPort    Service = "ndm-agent-port"  // NDM-AGENT-PORT
	ServiceIpProvision     Service = "ip-provision"    // IP-PROVISION
	ServiceNoitTransport   Service = "noit-transport"  // Reconnoiter Agent Data Transport
	ServiceShaperai        Service = "shaperai"        // Shaper Automation Server
	ServiceShaperaiDisc    Service = "shaperai-disc"   // Shaper Automation Server Management Discovery
	ServiceEq3Update       Service = "eq3-update"      // EQ3 firmware update
	ServiceEq3Config       Service = "eq3-config"      // EQ3 discovery and configuration
	ServiceEwMgmt          Service = "ew-mgmt"         // Cisco EnergyWise Management
	ServiceEwDiscCmd       Service = "ew-disc-cmd"     // Cisco EnergyWise Discovery and Command Flooding
	ServiceCiscocsdb       Service = "ciscocsdb"       // Cisco NetMgmt DB Ports
	ServiceZWaveS          Service = "z-wave-s"        // Z-Wave Secure Tunnel
	ServicePmcd            Service = "pmcd"            // PCP server (pmcd)
	ServicePmcdproxy       Service = "pmcdproxy"       // PCP server (pmcd) proxy
	ServiceCognexDataman   Service = "cognex-dataman"  // Cognex DataMan Management
	ServiceDomiq           Service = "domiq"           // DOMIQ Building Automation
	ServiceRbrDebug        Service = "rbr-debug"       // REALbasic Remote Debug
	ServiceEtherNetIP2     Service = "EtherNet/IP-2"   // EtherNet/IP messaging
	ServiceM3da            Service = "m3da"            // M3DA (efficient machine-to-machine communication)
	ServiceM3daDisc        Service = "m3da-disc"       // M3DA Discovery (efficient machine-to-machine communication)
	ServiceAsmp            Service = "asmp"            // NSi AutoStore Status Monitoring Protocol data transfer
	ServiceAsmpMon         Service = "asmp-mon"        // NSi AutoStore Status Monitoring Protocol device monitoring
	ServiceAsmps           Service = "asmps"           // NSi AutoStore Status Monitoring Protocol secure data transfer
	ServiceSynctest        Service = "synctest"        // Remote application control
	ServiceInvisionAg      Service = "invision-ag"     // InVision AG
	ServiceEba             Service = "eba"             // EBA PRISE
	ServiceDaiShell        Service = "dai-shell"       // Server for the DAI family of client-server products
	ServiceQdb2service     Service = "qdb2service"     // Qpuncture Data Access Service
	ServiceSsrServermgr    Service = "ssr-servermgr"   // SSRServerMgr
	ServiceSpRemotetablet  Service = "sp-remotetablet" // connection between computer and a signature tablet
	ServiceMediabox        Service = "mediabox"        // MediaBox Server
	ServiceMbus            Service = "mbus"            // Message Bus
	ServiceWinrm           Service = "winrm"           // Windows Remote Management Service
	ServiceJvlMactalk      Service = "jvl-mactalk"     // Configuration of motors conneced to industrial ethernet
	ServiceDbbrowse        Service = "dbbrowse"        // Databeam Corporation
	ServiceDirectplaysrvr  Service = "directplaysrvr"  // Direct Play Server
	ServiceAp              Service = "ap"              // ALC Protocol
	ServiceBacnet          Service = "bacnet"          // Building Automation and Control Networks
	ServiceNimcontroller   Service = "nimcontroller"   // Nimbus Controller
	ServiceNimspooler      Service = "nimspooler"      // Nimbus Spooler
	ServiceNimhub          Service = "nimhub"          // Nimbus Hub
	ServiceNimgtw          Service = "nimgtw"          // Nimbus Gateway
	ServiceNimbusdb        Service = "nimbusdb"        // NimbusDB Connector
	ServiceNimbusdbctrl    Service = "nimbusdbctrl"    // NimbusDB Control
	Service3gppCbsp        Service = "3gpp-cbsp"       // 3GPP Cell Broadcast Service Protocol
	ServiceIsnetserv       Service = "isnetserv"       // Image Systems Network Services
	ServiceBlp5            Service = "blp5"            // Bloomberg locator
	ServiceComBardacDw     Service = "com-bardac-dw"   // com-bardac-dw
	ServiceIqobject        Service = "iqobject"        // iqobject
	ServiceMatahari        Service = "matahari"        // Matahari Broker
)

var (
	ServicePortProtoMaps = map[Service][]PortProto{
		Service1ciSmcs:         {{3091, 6}, {3091, 17}},
		Service2ping:           {{15998, 17}},
		Service3ComNsd:         {{1742, 6}, {1742, 17}},
		Service3comAmp3:        {{629, 6}, {629, 17}},
		Service3comNetMgmt:     {{2391, 6}, {2391, 17}},
		Service3comNjack1:      {{5264, 6}, {5264, 17}},
		Service3comNjack2:      {{5265, 6}, {5265, 17}},
		Service3comWebview:     {{2339, 6}, {2339, 17}},
		Service3comfaxrpc:      {{3446, 6}, {3446, 17}},
		Service3comnetman:      {{1181, 6}, {1181, 17}},
		Service3dNfsd:          {{2323, 6}, {2323, 17}},
		Service3dsLm:           {{1538, 6}, {1538, 17}},
		Service3exmp:           {{5221, 6}},
		Service3gppCbsp:        {{48049, 6}},
		Service3lL1:            {{1511, 6}, {1511, 17}},
		Service3link:           {{15363, 6}, {15363, 17}},
		Service3mImageLm:       {{1550, 6}, {1550, 17}},
		Service3parEvts:        {{5781, 6}, {5781, 17}},
		Service3parMgmt:        {{5782, 6}, {5782, 17}},
		Service3parMgmtSsl:     {{5783, 6}, {5783, 17}},
		Service3parRcopy:       {{5785, 6}, {5785, 17}},
		Service4Tieropmcli:     {{2934, 6}, {2934, 17}},
		Service4Tieropmgw:      {{2933, 6}, {2933, 17}},
		Service4talk:           {{3284, 6}, {3284, 17}},
		Service6a44:            {{1027, 17}},
		Service80211Iapp:       {{3517, 6}, {3517, 17}},
		Service914cG:           {{211, 6}, {211, 17}},
		Service9pfs:            {{564, 6}, {564, 17}},
		ServiceA13An:           {{3125, 6}, {3125, 17}},
		ServiceA14:             {{3597, 6}, {3597, 17}},
		ServiceA15:             {{3598, 6}, {3598, 17}},
		ServiceA16AnAn:         {{4598, 6}, {4598, 17}},
		ServiceA17AnAn:         {{4599, 6}, {4599, 17}},
		ServiceA1Bs:            {{5603, 6}, {5603, 17}},
		ServiceA1Msc:           {{5602, 6}, {5602, 17}},
		ServiceA21An1xbs:       {{4597, 6}, {4597, 17}},
		ServiceA25FapFgw:       {{4502, 132}},
		ServiceA26FapFgw:       {{4726, 17}},
		ServiceA27RanRan:       {{28119, 17}},
		ServiceA3Sdunode:       {{5604, 6}, {5604, 17}},
		ServiceA4Sdunode:       {{5605, 6}, {5605, 17}},
		ServiceAairnet1:        {{3618, 6}, {3618, 17}},
		ServiceAairnet2:        {{3619, 6}, {3619, 17}},
		ServiceAalLm:           {{1469, 6}, {1469, 17}},
		ServiceAamp:            {{3939, 6}, {3939, 17}},
		ServiceAap:             {{2878, 6}, {2878, 17}},
		ServiceAas:             {{1601, 6}, {1601, 17}},
		ServiceAbacusRemote:    {{2894, 6}, {2894, 17}},
		ServiceAbarsd:          {{8402, 6}, {8402, 17}},
		ServiceAbatemgr:        {{3655, 6}, {3655, 17}},
		ServiceAbatjss:         {{3656, 6}, {3656, 17}},
		ServiceAbbEscp:         {{6316, 6}, {6316, 17}},
		ServiceAbbaccuray:      {{1546, 6}, {1546, 17}},
		ServiceAbbs:            {{4885, 6}, {4885, 17}},
		ServiceAbcsoftware:     {{3996, 6}, {3996, 17}},
		ServiceAbcvoicePort:    {{3781, 6}, {3781, 17}},
		ServiceAbout:           {{2019, 17}},
		ServiceAbrApi:          {{1954, 6}, {1954, 17}},
		ServiceAbrSecure:       {{1955, 6}, {1955, 17}},
		ServiceAcCluster:       {{18463, 6}, {18463, 17}},
		ServiceAcTech:          {{2796, 6}, {2796, 17}},
		ServiceAcap:            {{674, 6}, {674, 17}},
		ServiceAcas:            {{62, 6}, {62, 17}},
		ServiceAccRaid:         {{2800, 6}, {2800, 17}},
		ServiceAccel:           {{4108, 6}, {4108, 17}},
		ServiceAccelenet:       {{1182, 6}},
		ServiceAccelenetData:   {{1182, 17}},
		ServiceAccessnetwork:   {{699, 6}, {699, 17}},
		ServiceAccordMgc:       {{1205, 6}, {1205, 17}},
		ServiceAcctopusCc:      {{6868, 6}},
		ServiceAcctopusSt:      {{6868, 17}},
		ServiceAccuLmgr:        {{7781, 6}, {7781, 17}},
		ServiceAccuracer:       {{12007, 6}, {12007, 17}},
		ServiceAccuracerDbms:   {{12008, 6}, {12008, 17}},
		ServiceAcdPm:           {{8793, 6}, {8793, 17}},
		ServiceAceClient:       {{2334, 6}, {2334, 17}},
		ServiceAceProxy:        {{2335, 6}, {2335, 17}},
		ServiceAceServer:       {{2475, 6}, {2475, 17}},
		ServiceAceSvrProp:      {{2476, 6}, {2476, 17}},
		ServiceAci:             {{187, 6}, {187, 17}},
		ServiceAcis:            {{9953, 6}, {9953, 17}},
		ServiceAclManager:      {{4013, 6}, {4013, 17}},
		ServiceAcmaint_dbd:     {{774, 17}},
		ServiceAcmaint_transd:  {{775, 17}},
		ServiceAcme:            {{9216, 6}, {9216, 17}},
		ServiceAcms:            {{3980, 6}, {3980, 17}},
		ServiceAcmsoda:         {{6969, 6}, {6969, 17}},
		ServiceAcnet:           {{6801, 6}, {6801, 17}},
		ServiceAcp:             {{599, 6}, {599, 17}},
		ServiceAcpConduit:      {{3823, 6}, {3823, 17}},
		ServiceAcpDiscovery:    {{3822, 6}, {3822, 17}},
		ServiceAcpPolicy:       {{3824, 6}, {3824, 17}},
		ServiceAcpPort:         {{2071, 6}, {2071, 17}},
		ServiceAcpProto:        {{4046, 6}, {4046, 17}},
		ServiceAcplt:           {{7509, 6}},
		ServiceAcptsys:         {{2149, 6}, {2149, 17}},
		ServiceAcrNema:         {{104, 6}, {104, 17}},
		ServiceActer:           {{4671, 6}, {4671, 17}},
		ServiceActifioC2c:      {{5103, 6}},
		ServiceActivememory:    {{2859, 6}, {2859, 17}},
		ServiceActivesync:      {{1034, 6}, {1034, 17}},
		ServiceActnet:          {{5411, 6}, {5411, 17}},
		ServiceAdaCip:          {{2085, 6}, {2085, 17}},
		ServiceAdap:            {{6350, 6}, {6350, 17}},
		ServiceAdaptSna:        {{1365, 6}, {1365, 17}},
		ServiceAdaptecmgr:      {{2521, 6}, {2521, 17}},
		ServiceAdcp:            {{7508, 6}},
		ServiceAdiGxpSrvprt:    {{6769, 6}, {6769, 17}},
		ServiceAdmind:          {{3279, 6}, {3279, 17}},
		ServiceAdmind2:         {{8403, 6}, {8403, 17}},
		ServiceAdminsLms:       {{2692, 6}, {2692, 17}},
		ServiceAdobeserver1:    {{1102, 6}, {1102, 17}},
		ServiceAdobeserver2:    {{1103, 6}, {1103, 17}},
		ServiceAdobeserver3:    {{3703, 6}, {3703, 17}},
		ServiceAdobeserver4:    {{3704, 6}, {3704, 17}},
		ServiceAdobeserver5:    {{3705, 6}, {3705, 17}},
		ServiceAdrep:           {{3954, 6}, {3954, 17}},
		ServiceAds:             {{2550, 6}, {2550, 17}},
		ServiceAdsC:            {{5913, 6}, {5913, 17}, {5913, 132}},
		ServiceAdtechTest:      {{3357, 6}, {3357, 17}},
		ServiceAdtempusclient:  {{3760, 6}, {3760, 17}},
		ServiceAdvantLm:        {{2295, 6}, {2295, 17}},
		ServiceAdws:            {{9389, 6}},
		ServiceAed512:          {{149, 6}, {149, 17}},
		ServiceAegate:          {{4549, 6}, {4549, 17}},
		ServiceAequus:          {{23456, 6}},
		ServiceAequusAlt:       {{23457, 6}},
		ServiceAero:            {{8060, 17}},
		ServiceAeroflightAds:   {{1218, 6}, {1218, 17}},
		ServiceAeroflightRet:   {{1219, 6}, {1219, 17}},
		ServiceAesDiscovery:    {{3224, 6}, {3224, 17}},
		ServiceAesX170:         {{7107, 17}},
		ServiceAesop:           {{8202, 17}},
		ServiceAf:              {{1411, 6}, {1411, 17}},
		ServiceAfbackup:        {{2988, 6}, {2988, 17}},
		ServiceAfescMc:         {{6628, 6}, {6628, 17}},
		ServiceAffiliate:       {{6579, 6}, {6579, 17}},
		ServiceAforeVdpDisc:    {{4362, 17}},
		ServiceAfpovertcp:      {{548, 6}, {548, 17}},
		ServiceAfrog:           {{1042, 6}, {1042, 17}},
		ServiceAfs:             {{1483, 6}, {1483, 17}},
		ServiceAfs3Bos:         {{7007, 6}, {7007, 17}},
		ServiceAfs3Callback:    {{7001, 6}, {7001, 17}},
		ServiceAfs3Errors:      {{7006, 6}, {7006, 17}},
		ServiceAfs3Fileserver:  {{7000, 6}, {7000, 17}},
		ServiceAfs3Kaserver:    {{7004, 6}, {7004, 17}},
		ServiceAfs3Prserver:    {{7002, 6}, {7002, 17}},
		ServiceAfs3Rmtsys:      {{7009, 6}, {7009, 17}},
		ServiceAfs3Update:      {{7008, 6}, {7008, 17}},
		ServiceAfs3Vlserver:    {{7003, 6}, {7003, 17}},
		ServiceAfs3Volser:      {{7005, 6}, {7005, 17}},
		ServiceAftmux:          {{3917, 6}, {3917, 17}},
		ServiceAgcat:           {{3915, 6}, {3915, 17}},
		ServiceAgentseaseDb:    {{3997, 6}, {3997, 17}},
		ServiceAgentview:       {{2331, 6}, {2331, 17}},
		ServiceAgentx:          {{705, 6}, {705, 17}},
		ServiceAgpolicy:        {{38203, 6}, {38203, 17}},
		ServiceAgpsPort:        {{3425, 6}, {3425, 17}},
		ServiceAgriGateway:     {{3026, 6}, {3026, 17}},
		ServiceAgriserver:      {{3021, 6}, {3021, 17}},
		ServiceAgslb:           {{4149, 6}, {4149, 17}},
		ServiceAhEspEncap:      {{2070, 6}, {2070, 17}},
		ServiceAiagent:         {{7738, 6}, {7738, 17}},
		ServiceAibkup:          {{4071, 6}, {4071, 17}},
		ServiceAicNp:           {{2785, 6}, {2785, 17}},
		ServiceAicOncrpc:       {{2786, 6}, {2786, 17}},
		ServiceAiccCmi:         {{3316, 6}, {3316, 17}},
		ServiceAimppHello:      {{2846, 6}, {2846, 17}},
		ServiceAimppPortReq:    {{2847, 6}, {2847, 17}},
		ServiceAipnAuth:        {{3833, 6}, {3833, 17}},
		ServiceAipnReg:         {{4113, 6}, {4113, 17}},
		ServiceAironetddp:      {{2887, 6}, {2887, 17}},
		ServiceAirs:            {{1481, 6}, {1481, 17}},
		ServiceAirshot:         {{3975, 6}, {3975, 17}},
		ServiceAirsync:         {{2175, 6}, {2175, 17}},
		ServiceAises:           {{2783, 6}, {2783, 17}},
		ServiceAjaNtv4Disc:     {{4804, 17}},
		ServiceAkerCdp:         {{2473, 6}, {2473, 17}},
		ServiceAlarisDisc:      {{3613, 6}, {3613, 17}},
		ServiceAlarm:           {{2740, 6}, {2740, 17}},
		ServiceAlarmClockC:     {{2668, 6}, {2668, 17}},
		ServiceAlarmClockS:     {{2667, 6}, {2667, 17}},
		ServiceAlchemy:         {{3234, 6}, {3234, 17}},
		ServiceAlesquery:       {{5074, 6}, {5074, 17}},
		ServiceAlfin:           {{16003, 17}},
		ServiceAlias:           {{1187, 6}, {1187, 17}},
		ServiceAlljoyn:         {{9956, 17}},
		ServiceAlljoynMcm:      {{9955, 17}},
		ServiceAlljoynStm:      {{9955, 6}},
		ServiceAllpeers:        {{36001, 6}, {36001, 17}},
		ServiceAllstorcns:      {{2901, 6}, {2901, 17}},
		ServiceAlmobileSystem:  {{9209, 6}, {9209, 17}},
		ServiceAlpes:           {{463, 6}, {463, 17}},
		ServiceAlphaSms:        {{1849, 6}, {1849, 17}},
		ServiceAlphatechLm:     {{1653, 6}, {1653, 17}},
		ServiceAltaAnaLm:       {{1346, 6}, {1346, 17}},
		ServiceAltalink:        {{1845, 6}, {1845, 17}},
		ServiceAltavRemmgt:     {{2456, 6}, {2456, 17}},
		ServiceAltavTunnel:     {{3265, 6}, {3265, 17}},
		ServiceAltbsdp:         {{7799, 6}, {7799, 17}},
		ServiceAltcp:           {{4165, 6}, {4165, 17}},
		ServiceAltovaLm:        {{35355, 6}},
		ServiceAltovaLmDisc:    {{35355, 17}},
		ServiceAltovacentral:   {{4689, 6}, {4689, 17}},
		ServiceAltserviceboot:  {{4011, 6}},
		ServiceAmanda:          {{10080, 6}, {10080, 17}},
		ServiceAmandaidx:       {{10082, 6}},
		ServiceAmberon:         {{8301, 6}, {8301, 17}},
		ServiceAmbitLm:         {{6831, 6}, {6831, 17}},
		ServiceAmc:             {{5506, 6}, {5506, 17}},
		ServiceAmcs:            {{8766, 6}, {8766, 17}},
		ServiceAmdsched:        {{1931, 6}, {1931, 17}},
		ServiceAmidxtape:       {{10083, 6}},
		ServiceAmiganetfs:      {{2100, 6}, {2100, 17}},
		ServiceAminet:          {{2639, 6}, {2639, 17}},
		ServiceAmp:             {{3811, 6}, {3811, 17}},
		ServiceAmpify:          {{8040, 6}, {8040, 17}},
		ServiceAmplLic:         {{5195, 6}},
		ServiceAmplTableproxy:  {{5196, 6}},
		ServiceAmprInfo:        {{1535, 6}, {1535, 17}},
		ServiceAmprInter:       {{1536, 6}, {1536, 17}},
		ServiceAmprRcmd:        {{459, 6}, {459, 17}},
		ServiceAmqp:            {{5672, 6}, {5672, 17}, {5672, 132}},
		ServiceAmqps:           {{5671, 6}, {5671, 17}},
		ServiceAms:             {{1037, 6}, {1037, 17}},
		ServiceAmt:             {{2268, 6}, {2268, 17}},
		ServiceAmtBlcPort:      {{2848, 6}, {2848, 17}},
		ServiceAmtCnfProt:      {{3054, 6}, {3054, 17}},
		ServiceAmtEsdProt:      {{1082, 6}, {1082, 17}},
		ServiceAmtRedirTcp:     {{16994, 6}, {16994, 17}},
		ServiceAmtRedirTls:     {{16995, 6}, {16995, 17}},
		ServiceAmtSoapHttp:     {{16992, 6}, {16992, 17}},
		ServiceAmtSoapHttps:    {{16993, 6}, {16993, 17}},
		ServiceAmxAxbnet:       {{1320, 6}, {1320, 17}},
		ServiceAmxIcsp:         {{1319, 6}, {1319, 17}},
		ServiceAmxRms:          {{3839, 6}, {3839, 17}},
		ServiceAmxWebadmin:     {{2929, 6}, {2929, 17}},
		ServiceAmxWeblinx:      {{2930, 6}, {2930, 17}},
		ServiceAnPcp:           {{3846, 6}, {3846, 17}},
		ServiceAndLm:           {{2646, 6}, {2646, 17}},
		ServiceAnet:            {{212, 6}, {212, 17}},
		ServiceAnetB:           {{3338, 6}, {3338, 17}},
		ServiceAnetH:           {{3341, 6}, {3341, 17}},
		ServiceAnetL:           {{3339, 6}, {3339, 17}},
		ServiceAnetM:           {{3340, 6}, {3340, 17}},
		ServiceAnotoRendezv:    {{3715, 6}, {3715, 17}},
		ServiceAnsConsole:      {{3440, 6}, {3440, 17}},
		ServiceAnsanotify:      {{116, 6}, {116, 17}},
		ServiceAnsatrader:      {{124, 6}, {124, 17}},
		ServiceAnsoftLm1:       {{1083, 6}, {1083, 17}},
		ServiceAnsoftLm2:       {{1084, 6}, {1084, 17}},
		ServiceAnswersoftLm:    {{1781, 6}, {1781, 17}},
		ServiceAnsysLm:         {{1800, 6}, {1800, 17}},
		ServiceAnsysli:         {{2325, 6}, {2325, 17}},
		ServiceAnsyslmd:        {{1055, 6}, {1055, 17}},
		ServiceAnthonyData:     {{1206, 6}, {1206, 17}},
		ServiceAntidotemgrsvr:  {{2247, 6}, {2247, 17}},
		ServiceAocp:            {{2712, 6}, {2712, 17}},
		ServiceAodv:            {{654, 6}, {654, 17}},
		ServiceAol:             {{5190, 6}, {5190, 17}},
		ServiceAol1:            {{5191, 6}, {5191, 17}},
		ServiceAol2:            {{5192, 6}, {5192, 17}},
		ServiceAol3:            {{5193, 6}, {5193, 17}},
		ServiceAp:              {{47806, 6}, {47806, 17}},
		ServiceApani1:          {{9160, 6}, {9160, 17}},
		ServiceApani2:          {{9161, 6}, {9161, 17}},
		ServiceApani3:          {{9162, 6}, {9162, 17}},
		ServiceApani4:          {{9163, 6}, {9163, 17}},
		ServiceApani5:          {{9164, 6}, {9164, 17}},
		ServiceApc2160:         {{2160, 6}, {2160, 17}},
		ServiceApc2161:         {{2161, 6}, {2161, 17}},
		ServiceApc2260:         {{2260, 6}, {2260, 17}},
		ServiceApc3052:         {{3052, 6}, {3052, 17}},
		ServiceApc3506:         {{3506, 6}, {3506, 17}},
		ServiceApc5454:         {{5454, 6}, {5454, 17}},
		ServiceApc5455:         {{5455, 6}, {5455, 17}},
		ServiceApc5456:         {{5456, 6}, {5456, 17}},
		ServiceApc6547:         {{6547, 6}, {6547, 17}},
		ServiceApc6548:         {{6548, 6}, {6548, 17}},
		ServiceApc6549:         {{6549, 6}, {6549, 17}},
		ServiceApc7845:         {{7845, 6}, {7845, 17}},
		ServiceApc7846:         {{7846, 6}, {7846, 17}},
		ServiceApc9950:         {{9950, 6}, {9950, 17}},
		ServiceApc9951:         {{9951, 6}, {9951, 17}},
		ServiceApc9952:         {{9952, 6}, {9952, 17}},
		ServiceApcNecmp:        {{18888, 6}, {18888, 17}},
		ServiceApcupsd:         {{3551, 6}, {3551, 17}},
		ServiceApdap:           {{3948, 6}, {3948, 17}},
		ServiceApertusLdp:      {{539, 6}, {539, 17}},
		ServiceApexEdge:        {{913, 6}, {913, 17}},
		ServiceApexMesh:        {{912, 6}, {912, 17}},
		ServiceAplx:            {{1134, 6}, {1134, 17}},
		ServiceApmLink:         {{32483, 6}, {32483, 17}},
		ServiceApocd:           {{3809, 6}, {3809, 17}},
		ServiceApogeexPort:     {{3184, 6}, {3184, 17}},
		ServiceApolloAdmin:     {{8122, 6}, {8122, 17}},
		ServiceApolloCc:        {{2754, 6}, {2754, 17}},
		ServiceApolloData:      {{8121, 6}, {8121, 17}},
		ServiceApolloGms:       {{2759, 6}, {2759, 17}},
		ServiceApolloRelay:     {{10252, 6}, {10252, 17}},
		ServiceApolloStatus:    {{2758, 6}, {2758, 17}},
		ServiceApparenetAs:     {{3238, 6}, {3238, 17}},
		ServiceApparenetTps:    {{3237, 6}, {3237, 17}},
		ServiceApparenetTs:     {{3236, 6}, {3236, 17}},
		ServiceApparenetUi:     {{3239, 6}, {3239, 17}},
		ServiceAppiqMgmt:       {{4674, 6}, {4674, 17}},
		ServiceAppleLicman:     {{1381, 6}, {1381, 17}},
		ServiceAppleSasl:       {{3659, 6}, {3659, 17}},
		ServiceAppleVpnsRp:     {{4112, 6}, {4112, 17}},
		ServiceAppleqtc:        {{458, 6}, {458, 17}},
		ServiceAppleqtcsrvr:    {{545, 6}, {545, 17}},
		ServiceAppleugcontrol:  {{2336, 6}, {2336, 17}},
		ServiceApplianceCfg:    {{2898, 6}, {2898, 17}},
		ServiceApplix:          {{999, 17}},
		ServiceApplus:          {{2037, 6}, {2037, 17}},
		ServiceApplusservice:   {{4087, 6}},
		ServiceAppmanServer:    {{3312, 6}, {3312, 17}},
		ServiceAppservHttp:     {{4848, 6}, {4848, 17}},
		ServiceAppservHttps:    {{4849, 6}, {4849, 17}},
		ServiceAppssLm:         {{3879, 6}, {3879, 17}},
		ServiceAppswitchEmp:    {{2616, 6}, {2616, 17}},
		ServiceAppworxsrv:      {{2136, 6}, {2136, 17}},
		ServiceApriLm:          {{1447, 6}, {1447, 17}},
		ServiceAprigoCs:        {{5086, 6}},
		ServiceApwRegistry:     {{3758, 6}, {3758, 17}},
		ServiceApwiDisc:        {{4394, 17}},
		ServiceApwiImserver:    {{4391, 6}},
		ServiceApwiRxserver:    {{4392, 6}},
		ServiceApwiRxspooler:   {{4393, 6}},
		ServiceApx500api1:      {{2264, 6}, {2264, 17}},
		ServiceApx500api2:      {{2265, 6}, {2265, 17}},
		ServiceArbortextLm:     {{1557, 6}, {1557, 17}},
		ServiceArcisdms:        {{262, 6}, {262, 17}},
		ServiceArcp:            {{7070, 6}, {7070, 17}},
		ServiceArcpd:           {{3513, 6}, {3513, 17}},
		ServiceArdt:            {{1826, 6}, {1826, 17}},
		ServiceArdusCntl:       {{1116, 6}, {1116, 17}},
		ServiceArdusMtrns:      {{1117, 6}, {1117, 17}},
		ServiceArdusTrns:       {{1115, 6}, {1115, 17}},
		ServiceArdusmul:        {{1835, 6}, {1835, 17}},
		ServiceArdusuni:        {{1834, 6}, {1834, 17}},
		ServiceAreaguardNeo:    {{23546, 6}},
		ServiceArenaServer:     {{11321, 6}, {11321, 17}},
		ServiceArepaCas:        {{3030, 6}, {3030, 17}},
		ServiceArepaRaft:       {{3025, 6}, {3025, 17}},
		ServiceArgisDs:         {{2582, 6}, {2582, 17}},
		ServiceArgisTe:         {{2581, 6}, {2581, 17}},
		ServiceAria:            {{2624, 6}, {2624, 17}},
		ServiceAriel1:          {{419, 6}, {419, 17}},
		ServiceAriel2:          {{421, 6}, {421, 17}},
		ServiceAriel3:          {{422, 6}, {422, 17}},
		ServiceAriesKfinder:    {{7570, 6}, {7570, 17}},
		ServiceAriliamulti:     {{3140, 6}, {3140, 17}},
		ServiceArkivio:         {{3426, 6}, {3426, 17}},
		ServiceArmadp:          {{1913, 6}, {1913, 17}},
		ServiceArmagetronad:    {{4534, 17}},
		ServiceArmcenterhttp:   {{9294, 6}, {9294, 17}},
		ServiceArmcenterhttps:  {{9295, 6}, {9295, 17}},
		ServiceArmiServer:      {{3174, 6}, {3174, 17}},
		ServiceArmtechdaemon:   {{9292, 6}, {9292, 17}},
		ServiceArns:            {{384, 6}, {384, 17}},
		ServiceArrayManager:    {{3726, 6}, {3726, 17}},
		ServiceArsMaster:       {{3176, 6}, {3176, 17}},
		ServiceArsVista:        {{27782, 6}, {27782, 17}},
		ServiceArtifactMsg:     {{3518, 6}, {3518, 17}},
		ServiceArubaServer:     {{7166, 6}, {7166, 17}},
		ServiceAsDebug:         {{4026, 6}, {4026, 17}},
		ServiceAsServermap:     {{449, 6}, {449, 17}},
		ServiceAsa:             {{386, 6}, {386, 17}},
		ServiceAsaApplProto:    {{502, 6}, {502, 17}},
		ServiceAsam:            {{3451, 6}, {3451, 17}},
		ServiceAsapSctp:        {{3863, 132}},
		ServiceAsapSctpTls:     {{3864, 132}},
		ServiceAsapTcp:         {{3863, 6}},
		ServiceAsapTcpTls:      {{3864, 6}},
		ServiceAsapUdp:         {{3863, 17}},
		ServiceAscSlmd:         {{4448, 6}, {4448, 17}},
		ServiceAsciVal:         {{1560, 6}, {1560, 17}},
		ServiceAscomalarm:      {{4077, 17}},
		ServiceAsctrlAgent:     {{5155, 6}, {5155, 17}},
		ServiceAsdis:           {{2192, 6}, {2192, 17}},
		ServiceAsfRmcp:         {{623, 17}},
		ServiceAsfSecureRmcp:   {{664, 17}},
		ServiceAsgcypresstcps:  {{11489, 6}},
		ServiceAsgenf:          {{5727, 6}},
		ServiceAsi:             {{1827, 6}, {1827, 17}},
		ServiceAsia:            {{626, 6}, {626, 17}},
		ServiceAsipWebadmin:    {{311, 6}, {311, 17}},
		ServiceAsipregistry:    {{687, 6}, {687, 17}},
		ServiceAsmp:            {{45000, 6}},
		ServiceAsmpMon:         {{45000, 17}},
		ServiceAsmps:           {{45001, 6}},
		ServiceAsnaacceler8db:  {{5042, 6}, {5042, 17}},
		ServiceAsokiSma:        {{3087, 6}, {3087, 17}},
		ServiceAsp:             {{27374, 6}, {27374, 17}},
		ServiceAspeclmd:        {{1544, 6}, {1544, 17}},
		ServiceAspenServices:   {{1749, 6}, {1749, 17}},
		ServiceAspentecLm:      {{6142, 6}, {6142, 17}},
		ServiceAsprovatalk:     {{1079, 6}, {1079, 17}},
		ServiceAsr:             {{7800, 6}, {7800, 17}},
		ServiceAssocDisc:       {{24850, 17}},
		ServiceAssuriaIns:      {{4704, 6}},
		ServiceAssuriaSlm:      {{4119, 6}, {4119, 17}},
		ServiceAssystDr:        {{4485, 6}},
		ServiceAstergate:       {{9106, 6}},
		ServiceAstergateDisc:   {{9106, 17}},
		ServiceAstergatefax:    {{9107, 6}},
		ServiceAsterix:         {{8600, 6}, {8600, 17}},
		ServiceAstrolink:       {{27876, 6}},
		ServiceAstromedMain:    {{2864, 6}, {2864, 17}},
		ServiceAt3:             {{203, 6}, {203, 17}},
		ServiceAt5:             {{205, 6}, {205, 17}},
		ServiceAt7:             {{207, 6}, {207, 17}},
		ServiceAt8:             {{208, 6}, {208, 17}},
		ServiceAtEcho:          {{204, 6}, {204, 17}},
		ServiceAtNbp:           {{202, 6}, {202, 17}},
		ServiceAtRtmp:          {{201, 6}, {201, 17}},
		ServiceAtZis:           {{206, 6}, {206, 17}},
		ServiceAtcAppserver:    {{1171, 6}, {1171, 17}},
		ServiceAtcLm:           {{1170, 6}, {1170, 17}},
		ServiceAtex_elmd:       {{1385, 6}, {1385, 17}},
		ServiceAthandMmp:       {{20999, 6}, {20999, 17}},
		ServiceAtiIpToNcpe:     {{3965, 6}, {3965, 17}},
		ServiceAtlinks:         {{4154, 6}, {4154, 17}},
		ServiceAtmUhas:         {{11367, 6}, {11367, 17}},
		ServiceAtmZipOffice:    {{1520, 6}, {1520, 17}},
		ServiceAtmp:            {{5150, 6}, {5150, 17}},
		ServiceAtmtcp:          {{2812, 6}, {2812, 17}},
		ServiceAts:             {{2201, 6}, {2201, 17}},
		ServiceAtscMhSsc:       {{4937, 17}},
		ServiceAttachmateG32:   {{2317, 6}, {2317, 17}},
		ServiceAttachmateS2s:   {{2419, 6}, {2419, 17}},
		ServiceAttachmateUts:   {{2304, 6}, {2304, 17}},
		ServiceAtul:            {{7543, 6}, {7543, 17}},
		ServiceAudioActivmail:  {{1397, 6}, {1397, 17}},
		ServiceAudiojuggler:    {{3643, 6}, {3643, 17}},
		ServiceAudit:           {{182, 6}, {182, 17}},
		ServiceAuditTransfer:   {{1146, 6}, {1146, 17}},
		ServiceAuditd:          {{48, 6}, {48, 17}},
		ServiceAura:            {{2066, 6}, {2066, 17}},
		ServiceAurigaRouter:    {{5680, 17}},
		ServiceAuris:           {{2772, 6}, {2772, 17}},
		ServiceAurora:          {{9084, 6}, {9084, 17}, {9084, 132}},
		ServiceAuroraBalaena:   {{33123, 6}, {33123, 17}},
		ServiceAuroraCmgr:      {{364, 6}, {364, 17}},
		ServiceAurp:            {{387, 6}, {387, 17}},
		ServiceAuth:            {{113, 6}, {113, 17}},
		ServiceAuthentx:        {{5067, 6}, {5067, 17}},
		ServiceAutobuild:       {{5115, 6}},
		ServiceAutocueds:       {{3437, 6}, {3437, 17}},
		ServiceAutocuelog:      {{3104, 6}},
		ServiceAutocuesmi:      {{3103, 6}, {3103, 17}},
		ServiceAutocuetime:     {{3104, 17}},
		ServiceAutodeskLm:      {{1422, 6}, {1422, 17}},
		ServiceAutodeskNlm:     {{2080, 6}, {2080, 17}},
		ServiceAutonoc:         {{1140, 6}, {1140, 17}},
		ServiceAutopac:         {{4685, 6}, {4685, 17}},
		ServiceAutotracAcp:     {{31020, 6}},
		ServiceAvEmbConfig:     {{2050, 6}, {2050, 17}},
		ServiceAvailantMgr:     {{1122, 6}, {1122, 17}},
		ServiceAvantageb2b:     {{2131, 6}, {2131, 17}},
		ServiceAvanti_cdp:      {{4065, 6}, {4065, 17}},
		ServiceAvauthsrvprtcl:  {{2068, 6}, {2068, 17}},
		ServiceAvdecc:          {{17221, 6}, {17221, 17}},
		ServiceAvenue:          {{2134, 6}, {2134, 17}},
		ServiceAvenyo:          {{2992, 6}, {2992, 17}},
		ServiceAvian:           {{486, 6}, {486, 17}},
		ServiceAvinstalldisc:   {{3502, 6}, {3502, 17}},
		ServiceAvivaSna:        {{2238, 6}, {2238, 17}},
		ServiceAvocentAdsap:    {{3871, 6}, {3871, 17}},
		ServiceAvocentProxy:    {{1078, 6}, {1078, 17}},
		ServiceAvsecuremgmt:    {{3211, 6}, {3211, 17}},
		ServiceAvtProfile1:     {{5004, 6}, {5004, 17}, {5004, 33}},
		ServiceAvtProfile2:     {{5005, 6}, {5005, 17}, {5005, 33}},
		ServiceAwacsIce:        {{4488, 6}, {4488, 17}},
		ServiceAwgProxy:        {{3277, 6}, {3277, 17}},
		ServiceAwsBrf:          {{22800, 6}, {22800, 17}},
		ServiceAxisWimpPort:    {{10260, 6}, {10260, 17}},
		ServiceAxonLm:          {{1548, 6}, {1548, 17}},
		ServiceAyiya:           {{5072, 6}, {5072, 17}},
		ServiceAzeti:           {{4192, 6}},
		ServiceAzetiBd:         {{4192, 17}},
		ServiceAztec:           {{3512, 6}, {3512, 17}},
		ServiceB2License:       {{2204, 6}, {2204, 17}},
		ServiceB2Runtime:       {{2203, 6}, {2203, 17}},
		ServiceB2n:             {{1179, 6}, {1179, 17}},
		ServiceBESApi:          {{3408, 6}, {3408, 17}},
		ServiceBNovativeLs:     {{1896, 6}, {1896, 17}},
		ServiceBabel:           {{6696, 17}},
		ServiceBackburner:      {{2635, 6}, {2635, 17}},
		ServiceBackroomnet:     {{3387, 6}, {3387, 17}},
		ServiceBackupExpress:   {{6123, 6}, {6123, 17}},
		ServiceBackupedge:      {{3946, 6}, {3946, 17}},
		ServiceBacnet:          {{47808, 6}, {47808, 17}},
		ServiceBaculaDir:       {{9101, 6}, {9101, 17}},
		ServiceBaculaFd:        {{9102, 6}, {9102, 17}},
		ServiceBaculaSd:        {{9103, 6}, {9103, 17}},
		ServiceBadm_priv:       {{6505, 6}, {6505, 17}},
		ServiceBadm_pub:        {{6506, 6}, {6506, 17}},
		ServiceBalour:          {{4324, 6}, {4324, 17}},
		ServiceBandwizSystem:   {{1929, 6}, {1929, 17}},
		ServiceBanyanNet:       {{2708, 6}, {2708, 17}},
		ServiceBanyanRpc:       {{567, 6}, {567, 17}},
		ServiceBanyanVip:       {{573, 6}, {573, 17}},
		ServiceBarracudaBbs:    {{5120, 6}, {5120, 17}},
		ServiceBase:            {{5429, 6}, {5429, 17}},
		ServiceBatman:          {{4305, 6}, {4305, 17}},
		ServiceBb:              {{1984, 6}, {1984, 17}},
		ServiceBbars:           {{3327, 6}, {3327, 17}},
		ServiceBbnMmc:          {{1347, 6}, {1347, 17}},
		ServiceBbnMmx:          {{1348, 6}, {1348, 17}},
		ServiceBccp:            {{4175, 6}},
		ServiceBcinameservice:  {{3415, 6}, {3415, 17}},
		ServiceBcs:             {{4677, 6}, {4677, 17}},
		ServiceBcsBroker:       {{1704, 6}, {1704, 17}},
		ServiceBcsLmserver:     {{1951, 6}, {1951, 17}},
		ServiceBcslogc:         {{13216, 6}, {13216, 17}},
		ServiceBctp:            {{8999, 6}, {8999, 17}},
		ServiceBctpServer:      {{10107, 6}, {10107, 17}},
		ServiceBdir_priv:       {{6507, 6}, {6507, 17}},
		ServiceBdir_pub:        {{6508, 6}, {6508, 17}},
		ServiceBdp:             {{581, 6}, {581, 17}},
		ServiceBeaconPort:      {{3124, 6}, {3124, 17}},
		ServiceBeaconPort2:     {{4426, 6}, {4426, 17}},
		ServiceBears01:         {{2852, 6}, {2852, 17}},
		ServiceBears02:         {{3146, 6}, {3146, 17}},
		ServiceBeeyond:         {{2414, 6}, {2414, 17}},
		ServiceBeeyondMedia:    {{1943, 6}, {1943, 17}},
		ServiceBeorl:           {{5633, 6}, {5633, 17}},
		ServiceBerknet:         {{2005, 6}},
		ServiceBeserverMsgQ:    {{3527, 6}, {3527, 17}},
		ServiceBess:            {{3960, 6}, {3960, 17}},
		ServiceBexWebadmin:     {{6122, 6}, {6122, 17}},
		ServiceBexXr:           {{15660, 6}, {15660, 17}},
		ServiceBeyondRemote:    {{5424, 6}, {5424, 17}},
		ServiceBfGame:          {{25954, 17}},
		ServiceBfMaster:        {{25955, 17}},
		ServiceBfdControl:      {{3784, 6}, {3784, 17}},
		ServiceBfdEcho:         {{3785, 6}, {3785, 17}},
		ServiceBfdLag:          {{6784, 17}},
		ServiceBfdMultiCtl:     {{4784, 6}, {4784, 17}},
		ServiceBflckmgr:        {{3966, 6}, {3966, 17}},
		ServiceBftp:            {{152, 6}, {152, 17}},
		ServiceBgmp:            {{264, 6}, {264, 17}},
		ServiceBgp:             {{179, 6}, {179, 17}, {179, 132}},
		ServiceBgsNsi:          {{482, 6}, {482, 17}},
		ServiceBh611:           {{354, 6}, {354, 17}},
		ServiceBhevent:         {{357, 6}, {357, 17}},
		ServiceBhfhs:           {{248, 6}, {248, 17}},
		ServiceBhmds:           {{310, 6}, {310, 17}},
		ServiceBiapMp:          {{1962, 6}, {1962, 17}},
		ServiceBiff:            {{512, 17}},
		ServiceBiimenu:         {{18000, 6}, {18000, 17}},
		ServiceBimPem:          {{3783, 6}, {3783, 17}},
		ServiceBinderysupport:  {{2302, 6}, {2302, 17}},
		ServiceBingbang:        {{29999, 6}},
		ServiceBinkp:           {{24554, 6}, {24554, 17}},
		ServiceBintecAdmin:     {{2107, 6}, {2107, 17}},
		ServiceBintecCapi:      {{2662, 6}, {2662, 17}},
		ServiceBintecTapi:      {{2663, 6}, {2663, 17}},
		ServiceBiolinkAuth:     {{3411, 6}, {3411, 17}},
		ServiceBioserver:       {{6946, 6}, {6946, 17}},
		ServiceBip:             {{4376, 6}, {4376, 17}},
		ServiceBisSync:         {{5585, 6}, {5585, 17}},
		ServiceBisWeb:          {{5584, 6}, {5584, 17}},
		ServiceBitforestsrv:    {{5068, 6}},
		ServiceBitspeer:        {{2178, 6}, {2178, 17}},
		ServiceBlIdm:           {{142, 6}, {142, 17}},
		ServiceBlackboard:      {{2032, 6}, {2032, 17}},
		ServiceBlackjack:       {{1025, 6}, {1025, 17}},
		ServiceBlaze:           {{1150, 6}, {1150, 17}},
		ServiceBlizwow:         {{3724, 6}, {3724, 17}},
		ServiceBlockade:        {{2911, 6}, {2911, 17}},
		ServiceBlockadeBpsp:    {{2574, 6}, {2574, 17}},
		ServiceBlocks:          {{10288, 6}, {10288, 17}},
		ServiceBlp1:            {{8194, 6}, {8194, 17}},
		ServiceBlp2:            {{8195, 6}, {8195, 17}},
		ServiceBlp3:            {{8292, 6}, {8292, 17}},
		ServiceBlp4:            {{8294, 6}, {8294, 17}},
		ServiceBlp5:            {{48129, 6}, {48129, 17}},
		ServiceBlueberryLm:     {{1432, 6}, {1432, 17}},
		ServiceBluectrlproxy:   {{2277, 6}, {2277, 17}},
		ServiceBluelance:       {{2877, 6}, {2877, 17}},
		ServiceBlwnklPort:      {{2625, 6}, {2625, 17}},
		ServiceBmap:            {{3421, 6}, {3421, 17}},
		ServiceBmcAr:           {{2494, 6}, {2494, 17}},
		ServiceBmcDataColl:     {{3695, 6}, {3695, 17}},
		ServiceBmcEa:           {{3683, 6}, {3683, 17}},
		ServiceBmcGms:          {{10129, 6}},
		ServiceBmcGrx:          {{6300, 6}, {6300, 17}},
		ServiceBmcJmxPort:      {{3604, 6}, {3604, 17}},
		ServiceBmcMessaging:    {{2059, 6}, {2059, 17}},
		ServiceBmcNetAdm:       {{1769, 6}, {1769, 17}},
		ServiceBmcNetSvc:       {{1770, 6}, {1770, 17}},
		ServiceBmcOnekey:       {{3561, 6}, {3561, 17}},
		ServiceBmcPerfAgent:    {{6767, 6}, {6767, 17}},
		ServiceBmcPerfMgrd:     {{6768, 6}, {6768, 17}},
		ServiceBmcPerfSd:       {{10128, 6}, {10128, 17}},
		ServiceBmcReporting:    {{4568, 6}, {4568, 17}},
		ServiceBmc_ctd_ldap:    {{6301, 6}, {6301, 17}},
		ServiceBmc_patroldb:    {{1313, 17}},
		ServiceBmcpatrolagent:  {{3181, 6}, {3181, 17}},
		ServiceBmcpatrolrnvu:   {{3182, 6}, {3182, 17}},
		ServiceBmdss:           {{13823, 6}},
		ServiceBmpp:            {{632, 6}, {632, 17}},
		ServiceBnet:            {{415, 6}, {415, 17}},
		ServiceBnetfile:        {{1120, 6}, {1120, 17}},
		ServiceBnetgame:        {{1119, 6}, {1119, 17}},
		ServiceBntManager:      {{3344, 6}, {3344, 17}},
		ServiceBoardRoar:       {{9700, 6}, {9700, 17}},
		ServiceBoardVoip:       {{9750, 6}, {9750, 17}},
		ServiceBoeCachesvr:     {{6403, 6}, {6403, 17}},
		ServiceBoeCms:          {{6400, 6}, {6400, 17}},
		ServiceBoeEventsrv:     {{6402, 6}, {6402, 17}},
		ServiceBoeFilesvr:      {{6404, 6}, {6404, 17}},
		ServiceBoePagesvr:      {{6405, 6}, {6405, 17}},
		ServiceBoeProcesssvr:   {{6406, 6}, {6406, 17}},
		ServiceBoeResssvr1:     {{6407, 6}, {6407, 17}},
		ServiceBoeResssvr2:     {{6408, 6}, {6408, 17}},
		ServiceBoeResssvr3:     {{6409, 6}, {6409, 17}},
		ServiceBoeResssvr4:     {{6410, 6}, {6410, 17}},
		ServiceBoeWas:          {{6401, 6}, {6401, 17}},
		ServiceBoincClient:     {{1043, 6}, {1043, 17}},
		ServiceBoks:            {{6500, 6}, {6500, 17}},
		ServiceBoks_clntd:      {{6503, 6}, {6503, 17}},
		ServiceBoks_servc:      {{6501, 6}, {6501, 17}},
		ServiceBoks_servm:      {{6502, 6}, {6502, 17}},
		ServiceBoldsoftLm:      {{2961, 6}, {2961, 17}},
		ServiceBones:           {{4914, 6}, {4914, 17}},
		ServiceBoomerang:       {{1304, 6}, {1304, 17}},
		ServiceBoosterware:     {{2913, 6}, {2913, 17}},
		ServiceBootclient:      {{2017, 17}},
		ServiceBootpc:          {{68, 6}, {68, 17}},
		ServiceBootps:          {{67, 6}, {67, 17}},
		ServiceBootserver:      {{2016, 6}, {2016, 17}},
		ServiceBorlandDsj:      {{707, 6}, {707, 17}},
		ServiceBoscap:          {{2990, 6}, {2990, 17}},
		ServiceBounzza:         {{2218, 6}, {2218, 17}},
		ServiceBoxbackupstore:  {{4186, 6}},
		ServiceBoxp:            {{9380, 6}, {9380, 17}},
		ServiceBpcd:            {{13782, 6}, {13782, 17}},
		ServiceBpcpPoll:        {{2844, 6}, {2844, 17}},
		ServiceBpcpTrap:        {{2845, 6}, {2845, 17}},
		ServiceBpdbm:           {{13721, 6}, {13721, 17}},
		ServiceBpjavaMsvc:      {{13722, 6}, {13722, 17}},
		ServiceBpmd:            {{3593, 6}, {3593, 17}},
		ServiceBprd:            {{13720, 6}, {13720, 17}},
		ServiceBrChannel:       {{5425, 6}, {5425, 17}},
		ServiceBrain:           {{2169, 6}, {2169, 17}},
		ServiceBrcd:            {{1323, 6}, {1323, 17}},
		ServiceBrcmCommPort:    {{3188, 6}, {3188, 17}},
		ServiceBrdptc:          {{2155, 6}, {2155, 17}},
		ServiceBre:             {{4096, 6}, {4096, 17}},
		ServiceBrfGw:           {{22951, 6}, {22951, 17}},
		ServiceBridgecontrol:   {{1073, 6}, {1073, 17}},
		ServiceBrightcore:      {{5682, 17}},
		ServiceBrlp0:           {{4101, 6}, {4101, 17}},
		ServiceBrlp1:           {{4102, 6}, {4102, 17}},
		ServiceBrlp2:           {{4103, 6}, {4103, 17}},
		ServiceBrlp3:           {{4104, 6}, {4104, 17}},
		ServiceBroker_service:  {{3014, 6}, {3014, 17}},
		ServiceBrp:             {{3043, 6}, {3043, 17}},
		ServiceBruce:           {{2619, 6}, {2619, 17}},
		ServiceBrutus:          {{2003, 17}},
		ServiceBrvread:         {{1054, 6}, {1054, 17}},
		ServiceBsfserverZn:     {{5320, 6}},
		ServiceBsfsvrZnSsl:     {{5321, 6}},
		ServiceBspnePcc:        {{1252, 6}, {1252, 17}},
		ServiceBsquareVoip:     {{1071, 6}, {1071, 17}},
		ServiceBtpp2audctr1:    {{2536, 6}, {2536, 17}},
		ServiceBtpp2sectrans:   {{2444, 6}, {2444, 17}},
		ServiceBtprjctrl:       {{2803, 6}, {2803, 17}},
		ServiceBtrieve:         {{3351, 6}, {3351, 17}},
		ServiceBtsAppserver:    {{1961, 6}, {1961, 17}},
		ServiceBtsX73:          {{3681, 6}, {3681, 17}},
		ServiceBuddyDraw:       {{1854, 6}, {1854, 17}},
		ServiceBues_service:    {{2446, 6}, {2446, 17}},
		ServiceBullantRap:      {{2965, 6}, {2965, 17}},
		ServiceBullantSrap:     {{2964, 6}, {2964, 17}},
		ServiceBusboy:          {{998, 6}},
		ServiceBuschtrommel:    {{4747, 17}},
		ServiceBusiness:        {{3107, 6}, {3107, 17}},
		ServiceBusycal:         {{4990, 6}, {4990, 17}},
		ServiceBvAgent:         {{3993, 6}, {3993, 17}},
		ServiceBvDs:            {{3992, 6}, {3992, 17}},
		ServiceBvIs:            {{3990, 6}, {3990, 17}},
		ServiceBvQueryengine:   {{3989, 6}, {3989, 17}},
		ServiceBvSmcsrv:        {{3991, 6}, {3991, 17}},
		ServiceBvcdaemonPort:   {{3626, 6}, {3626, 17}},
		ServiceBvcontrol:       {{1236, 6}, {1236, 17}},
		ServiceBveapi:          {{10880, 6}, {10880, 17}},
		ServiceBvtsonar:        {{1149, 6}, {1149, 17}},
		ServiceBxp:             {{4027, 6}, {4027, 17}},
		ServiceBytex:           {{1375, 6}, {1375, 17}},
		ServiceBzflag:          {{5154, 6}, {5154, 17}},
		ServiceBzr:             {{4155, 6}, {4155, 17}},
		ServiceC1222Acse:       {{1153, 6}, {1153, 17}},
		ServiceC3:              {{2472, 6}, {2472, 17}},
		ServiceCAIlic:          {{216, 6}, {216, 17}},
		ServiceCHItPort:        {{3778, 6}, {3778, 17}},
		ServiceCa1:             {{5064, 6}, {5064, 17}},
		ServiceCa2:             {{5065, 6}, {5065, 17}},
		ServiceCaAuditDa:       {{8025, 6}, {8025, 17}},
		ServiceCaAuditDs:       {{8026, 6}, {8026, 17}},
		ServiceCaIdms:          {{3709, 6}, {3709, 17}},
		ServiceCaWebUpdate:     {{14414, 6}, {14414, 17}},
		ServiceCaaclang2:       {{5249, 6}, {5249, 17}},
		ServiceCaacws:          {{5248, 6}, {5248, 17}},
		ServiceCabProtocol:     {{595, 6}, {595, 17}},
		ServiceCableportAx:     {{282, 6}, {282, 17}},
		ServiceCabsmComm:       {{7161, 6}, {7161, 17}},
		ServiceCaciLm:          {{1554, 6}, {1554, 17}},
		ServiceCacsambroker:    {{7163, 6}, {7163, 17}},
		ServiceCadabraLm:       {{1563, 6}, {1563, 17}},
		ServiceCadencecontrol:  {{2318, 6}, {2318, 17}},
		ServiceCadis1:          {{1441, 6}, {1441, 17}},
		ServiceCadis2:          {{1442, 6}, {1442, 17}},
		ServiceCadkeyLicman:    {{1399, 6}, {1399, 17}},
		ServiceCadkeyTablet:    {{1400, 6}, {1400, 17}},
		ServiceCadlock:         {{770, 6}, {770, 17}},
		ServiceCadlock2:        {{1000, 6}, {1000, 17}},
		ServiceCadsiLm:         {{1387, 6}, {1387, 17}},
		ServiceCadview3d:       {{649, 6}, {649, 17}},
		ServiceCaerpc:          {{42510, 6}, {42510, 17}},
		ServiceCaevms:          {{5251, 6}, {5251, 17}},
		ServiceCaicci:          {{1721, 6}, {1721, 17}},
		ServiceCaiccipc:        {{1202, 6}, {1202, 17}},
		ServiceCaidsSensor:     {{1192, 6}, {1192, 17}},
		ServiceCaistoragemgr:   {{7162, 6}, {7162, 17}},
		ServiceCajoDiscovery:   {{1198, 6}, {1198, 17}},
		ServiceCal:             {{588, 6}, {588, 17}},
		ServiceCaldsoftBackup:  {{22537, 6}},
		ServiceCallLogging:     {{2552, 6}, {2552, 17}},
		ServiceCallSigTrans:    {{2517, 6}, {2517, 17}},
		ServiceCaller9:         {{2906, 6}, {2906, 17}},
		ServiceCalltrax:        {{3675, 6}, {3675, 17}},
		ServiceCallwaveiam:     {{9283, 6}, {9283, 17}},
		ServiceCamac:           {{3545, 6}, {3545, 17}},
		ServiceCambertxLm:      {{1734, 6}, {1734, 17}},
		ServiceCamp:            {{4450, 6}, {4450, 17}},
		ServiceCanDch:          {{1919, 6}, {1919, 17}},
		ServiceCanFerret:       {{1920, 6}, {1920, 17}},
		ServiceCanFerretSsl:    {{3661, 6}, {3661, 17}},
		ServiceCanNds:          {{1918, 6}, {1918, 17}},
		ServiceCanNdsSsl:       {{3660, 6}, {3660, 17}},
		ServiceCanditv:         {{24676, 6}, {24676, 17}},
		ServiceCandp:           {{42508, 6}, {42508, 17}},
		ServiceCandrp:          {{42509, 6}, {42509, 17}},
		ServiceCanexWatch:      {{3583, 6}, {3583, 17}},
		ServiceCanit_store:     {{6568, 6}},
		ServiceCanna:           {{5680, 6}},
		ServiceCanocentral0:    {{1871, 6}, {1871, 17}},
		ServiceCanocentral1:    {{1872, 6}, {1872, 17}},
		ServiceCanonBjnp1:      {{8611, 6}, {8611, 17}},
		ServiceCanonBjnp2:      {{8612, 6}, {8612, 17}},
		ServiceCanonBjnp3:      {{8613, 6}, {8613, 17}},
		ServiceCanonBjnp4:      {{8614, 6}, {8614, 17}},
		ServiceCanonCapt:       {{3756, 6}, {3756, 17}},
		ServiceCanonCppDisc:    {{8609, 17}},
		ServiceCanonMfnp:       {{8610, 6}, {8610, 17}},
		ServiceCap:             {{1026, 6}, {1026, 17}},
		ServiceCapfastLmd:      {{1756, 6}, {1756, 17}},
		ServiceCapioverlan:     {{1147, 6}, {1147, 17}},
		ServiceCapmux:          {{4728, 6}, {4728, 17}},
		ServiceCapsLm:          {{3290, 6}, {3290, 17}},
		ServiceCapwapControl:   {{5246, 17}},
		ServiceCapwapData:      {{5247, 17}},
		ServiceCar:             {{5090, 132}},
		ServiceCardax:          {{1072, 6}, {1072, 17}},
		ServiceCardbox:         {{3105, 6}, {3105, 17}},
		ServiceCardboxHttp:     {{3106, 6}, {3106, 17}},
		ServiceCarriusRshell:   {{1197, 6}, {1197, 17}},
		ServiceCartORama:       {{3292, 6}, {3292, 17}},
		ServiceCartographerxmp: {{5270, 6}, {5270, 17}},
		ServiceCas:             {{2418, 6}, {2418, 17}},
		ServiceCasMapi:         {{3682, 6}, {3682, 17}},
		ServiceCasanswmgmt:     {{3669, 6}, {3669, 17}},
		ServiceCasp:            {{1130, 6}, {1130, 17}},
		ServiceCaspssl:         {{1131, 6}, {1131, 17}},
		ServiceCasrmagent:      {{7167, 6}},
		ServiceCastorproxy:     {{3450, 6}, {3450, 17}},
		ServiceCatalyst:        {{2836, 6}, {2836, 17}},
		ServiceCatchpole:       {{1185, 6}, {1185, 17}},
		ServiceCaupcRemote:     {{2122, 6}, {2122, 17}},
		ServiceCautcpd:         {{3061, 6}, {3061, 17}},
		ServiceCawas:           {{12168, 6}, {12168, 17}},
		ServiceCba8:            {{9593, 6}, {9593, 17}},
		ServiceCbosIpPort:      {{3750, 6}, {3750, 17}},
		ServiceCbserver:        {{3388, 6}, {3388, 17}},
		ServiceCbt:             {{7777, 6}, {7777, 17}},
		ServiceCcTracking:      {{4870, 6}, {4870, 17}},
		ServiceCcagPib:         {{7169, 6}, {7169, 17}},
		ServiceCcmPort:         {{3575, 6}, {3575, 17}},
		ServiceCcmad:           {{3114, 6}, {3114, 17}},
		ServiceCcmail:          {{3264, 6}, {3264, 17}},
		ServiceCcmcomm:         {{3505, 6}, {3505, 17}},
		ServiceCcmrmi:          {{3154, 6}, {3154, 17}},
		ServiceCcnx:            {{9695, 6}, {9695, 17}},
		ServiceCcowcmr:         {{2116, 6}, {2116, 17}},
		ServiceCcp:             {{3947, 6}, {3947, 17}},
		ServiceCcsSoftware:     {{2734, 6}, {2734, 17}},
		ServiceCcssQmm:         {{4969, 6}, {4969, 17}},
		ServiceCcssQsm:         {{4970, 6}, {4970, 17}},
		ServiceCctvPort:        {{3559, 6}, {3559, 17}},
		ServiceCcuComm1:        {{4053, 6}, {4053, 17}},
		ServiceCcuComm2:        {{4054, 6}, {4054, 17}},
		ServiceCcuComm3:        {{4055, 6}, {4055, 17}},
		ServiceCd3oProtocol:    {{3616, 6}, {3616, 17}},
		ServiceCdbroker:        {{3376, 6}, {3376, 17}},
		ServiceCdc:             {{223, 6}, {223, 17}},
		ServiceCddbp:           {{888, 6}},
		ServiceCddbpAlt:        {{8880, 6}, {8880, 17}},
		ServiceCdfunc:          {{2045, 6}, {2045, 17}},
		ServiceCdid:            {{3315, 6}, {3315, 17}},
		ServiceCdlServer:       {{3056, 6}, {3056, 17}},
		ServiceCdn:             {{2412, 6}, {2412, 17}},
		ServiceCds:             {{4115, 6}, {4115, 17}},
		ServiceCecsvc:          {{2571, 6}, {2571, 17}},
		ServiceCedros_fds:      {{4140, 6}, {4140, 17}},
		ServiceCelatalk:        {{3485, 6}, {3485, 17}},
		ServiceCenterline:      {{3987, 6}, {3987, 17}},
		ServiceCentra:          {{1709, 6}, {1709, 17}},
		ServiceCequintCityid:   {{4074, 6}, {4074, 17}},
		ServiceCeraBcm:         {{1794, 6}, {1794, 17}},
		ServiceCernsysmgmtagt:  {{3830, 6}, {3830, 17}},
		ServiceCertInitiator:   {{1639, 6}, {1639, 17}},
		ServiceCertResponder:   {{1640, 6}, {1640, 17}},
		ServiceCesdcdman:       {{2921, 6}, {2921, 17}},
		ServiceCesdcdtrn:       {{2922, 6}, {2922, 17}},
		ServiceCesdinv:         {{2856, 6}, {2856, 17}},
		ServiceCfdptkt:         {{120, 6}, {120, 17}},
		ServiceCfengine:        {{5308, 6}, {5308, 17}},
		ServiceCfinger:         {{2003, 6}},
		ServiceCfs:             {{7546, 6}, {7546, 17}},
		ServiceCft0:            {{1761, 6}, {1761, 17}},
		ServiceCft1:            {{1762, 6}, {1762, 17}},
		ServiceCft2:            {{1763, 6}, {1763, 17}},
		ServiceCft3:            {{1764, 6}, {1764, 17}},
		ServiceCft4:            {{1765, 6}, {1765, 17}},
		ServiceCft5:            {{1766, 6}, {1766, 17}},
		ServiceCft6:            {{1767, 6}, {1767, 17}},
		ServiceCft7:            {{1768, 6}, {1768, 17}},
		ServiceCfw:             {{7563, 6}},
		ServiceCgiStarapi:      {{3893, 6}, {3893, 17}},
		ServiceCgms:            {{3003, 6}, {3003, 17}},
		ServiceCgnConfig:       {{2183, 6}, {2183, 17}},
		ServiceCgnStat:         {{2182, 6}, {2182, 17}},
		ServiceChargen:         {{19, 6}, {19, 17}},
		ServiceCharsetmgr:      {{3903, 6}, {3903, 17}},
		ServiceCheckoutdb:      {{5505, 6}, {5505, 17}},
		ServiceCheckpointRtm:   {{18241, 6}, {18241, 17}},
		ServiceChecksum:        {{1386, 6}, {1386, 17}},
		ServiceChevinservices:  {{3349, 6}, {3349, 17}},
		ServiceChildkeyCtrl:    {{1892, 6}, {1892, 17}},
		ServiceChildkeyNotif:   {{1891, 6}, {1891, 17}},
		ServiceChimeraHwm:      {{4009, 6}, {4009, 17}},
		ServiceChipLm:          {{1572, 6}, {1572, 17}},
		ServiceChipper:         {{17219, 6}, {17219, 17}},
		ServiceChmd:            {{3099, 6}, {3099, 17}},
		ServiceChoiceviewAgt:   {{4314, 6}},
		ServiceChoiceviewClt:   {{4316, 6}},
		ServiceChromagrafx:     {{1373, 6}, {1373, 17}},
		ServiceChshell:         {{562, 6}, {562, 17}},
		ServiceCi3Software1:    {{1301, 6}, {1301, 17}},
		ServiceCi3Software2:    {{1302, 6}, {1302, 17}},
		ServiceCichildLm:       {{1523, 6}, {1523, 17}},
		ServiceCichlid:         {{1377, 6}, {1377, 17}},
		ServiceCifs:            {{3020, 6}, {3020, 17}},
		ServiceCimplex:         {{673, 6}, {673, 17}},
		ServiceCimtrak:         {{3749, 6}, {3749, 17}},
		ServiceCindycollab:     {{3770, 6}, {3770, 17}},
		ServiceCinegrfxElmd:    {{2891, 6}, {2891, 17}},
		ServiceCinegrfxLm:      {{1743, 6}, {1743, 17}},
		ServiceCiphireData:     {{3887, 6}, {3887, 17}},
		ServiceCiphireServ:     {{3888, 6}, {3888, 17}},
		ServiceCircleX:         {{2931, 6}, {2931, 17}},
		ServiceCis:             {{22305, 17}},
		ServiceCisSecure:       {{22343, 6}, {22343, 17}},
		ServiceCiscoAvp:        {{8470, 6}},
		ServiceCiscoFna:        {{130, 6}, {130, 17}},
		ServiceCiscoIpsla:      {{1167, 6}, {1167, 17}, {1167, 132}},
		ServiceCiscoNetMgmt:    {{1741, 6}, {1741, 17}},
		ServiceCiscoRedu:       {{5786, 17}},
		ServiceCiscoSnat:       {{15555, 6}, {15555, 17}},
		ServiceCiscoSys:        {{132, 6}, {132, 17}},
		ServiceCiscoTdp:        {{711, 6}, {711, 17}},
		ServiceCiscoTna:        {{131, 6}, {131, 17}},
		ServiceCiscoVpathTun:   {{6633, 17}},
		ServiceCiscoWafs:       {{4050, 6}, {4050, 17}},
		ServiceCiscocsdb:       {{43441, 6}, {43441, 17}},
		ServiceCitadel:         {{504, 6}, {504, 17}},
		ServiceCitrixRtmp:      {{2897, 6}, {2897, 17}},
		ServiceCitrixadmin:     {{2513, 6}, {2513, 17}},
		ServiceCitrixima:       {{2512, 6}, {2512, 17}},
		ServiceCitriximaclient: {{2598, 6}, {2598, 17}},
		ServiceCitrixupp:       {{7228, 6}},
		ServiceCitrixuppg:      {{7229, 6}},
		ServiceCitynl:          {{1729, 6}, {1729, 17}},
		ServiceCitysearch:      {{3974, 6}, {3974, 17}},
		ServiceCl1:             {{172, 6}, {172, 17}},
		ServiceClDbAttach:      {{4135, 6}, {4135, 17}},
		ServiceClDbRemote:      {{4137, 6}, {4137, 17}},
		ServiceClDbRequest:     {{4136, 6}, {4136, 17}},
		ServiceClariionEvr01:   {{6389, 6}, {6389, 17}},
		ServiceClassic:         {{9087, 6}, {9087, 17}},
		ServiceCleanerliverc:   {{3481, 6}, {3481, 17}},
		ServiceClearcase:       {{371, 6}, {371, 17}},
		ServiceClearvisn:       {{2052, 6}, {2052, 17}},
		ServiceCleverCtrace:    {{6687, 6}},
		ServiceCleverTcpip:     {{6688, 6}},
		ServiceClientCtrl:      {{3730, 6}, {3730, 17}},
		ServiceClientWakeup:    {{9694, 6}, {9694, 17}},
		ServiceCloantoLm:       {{3397, 6}, {3397, 17}},
		ServiceCloantoNet1:     {{356, 6}, {356, 17}},
		ServiceCloseCombat:     {{1944, 6}, {1944, 17}},
		ServiceCloudsignaling:  {{7550, 17}},
		ServiceClp:             {{2567, 6}, {2567, 17}},
		ServiceClusterDisc:     {{3374, 6}, {3374, 17}},
		ServiceClusterxl:       {{18243, 6}},
		ServiceClutild:         {{7174, 6}, {7174, 17}},
		ServiceClvmCfg:         {{1476, 6}, {1476, 17}},
		ServiceCm:              {{5910, 6}, {5910, 17}, {5910, 132}},
		ServiceCma:             {{1050, 6}, {1050, 17}},
		ServiceCmadmin:         {{2617, 6}, {2617, 17}},
		ServiceCmcPort:         {{3576, 6}, {3576, 17}},
		ServiceCmipAgent:       {{164, 6}, {164, 17}},
		ServiceCmipMan:         {{163, 6}, {163, 17}},
		ServiceCmmdriver:       {{1294, 6}, {1294, 17}},
		ServiceCmtpAv:          {{8501, 17}},
		ServiceCmtpMgt:         {{8501, 6}},
		ServiceCnap:            {{7262, 6}, {7262, 17}},
		ServiceCnckadserver:    {{7168, 6}},
		ServiceCncp:            {{4785, 17}},
		ServiceCnhrp:           {{1757, 6}, {1757, 17}},
		ServiceCnrp:            {{2757, 6}, {2757, 17}},
		ServiceCnrprotocol:     {{1096, 6}, {1096, 17}},
		ServiceCnsSrvPort:      {{2976, 6}, {2976, 17}},
		ServiceCoap:            {{5683, 17}},
		ServiceCoauthor:        {{1529, 17}},
		ServiceCodaauth2:       {{370, 6}, {370, 17}},
		ServiceCodasrv:         {{2432, 6}, {2432, 17}},
		ServiceCodasrvSe:       {{2433, 6}, {2433, 17}},
		ServiceCodeMeter:       {{22350, 6}, {22350, 17}},
		ServiceCodimaRtp:       {{2415, 6}, {2415, 17}},
		ServiceCogitate:        {{3039, 6}, {3039, 17}},
		ServiceCognexDataman:   {{44444, 6}},
		ServiceCognexInsight:   {{1069, 6}, {1069, 17}},
		ServiceCognima:         {{3779, 6}, {3779, 17}},
		ServiceCogsysLm:        {{3377, 6}, {3377, 17}},
		ServiceCollaber:        {{7689, 6}, {7689, 17}},
		ServiceCollaborator:    {{622, 6}, {622, 17}},
		ServiceColubris:        {{3490, 6}, {3490, 17}},
		ServiceComBardacDw:     {{48556, 6}, {48556, 17}},
		ServiceComboxWebAcc:    {{2534, 6}, {2534, 17}},
		ServiceComcam:          {{2108, 6}, {2108, 17}},
		ServiceComcamIo:        {{3605, 6}, {3605, 17}},
		ServiceCommandport:     {{3416, 6}, {3416, 17}},
		ServiceCommerce:        {{542, 6}, {542, 17}},
		ServiceCommlinxAvl:     {{1190, 6}, {1190, 17}},
		ServiceCommonspace:     {{1592, 6}, {1592, 17}},
		ServiceCommplexLink:    {{5001, 6}, {5001, 17}},
		ServiceCommplexMain:    {{5000, 6}, {5000, 17}},
		ServiceCommtactHttp:    {{20002, 6}, {20002, 17}},
		ServiceCommtactHttps:   {{20003, 6}, {20003, 17}},
		ServiceCommunity:       {{2459, 6}, {2459, 17}},
		ServiceComotionback:    {{2262, 6}, {2262, 17}},
		ServiceComotionmaster:  {{2261, 6}, {2261, 17}},
		ServiceCompaqEvm:       {{619, 6}, {619, 17}},
		ServiceCompaqHttps:     {{2381, 6}, {2381, 17}},
		ServiceCompaqScp:       {{2766, 6}, {2766, 17}},
		ServiceCompaqWcp:       {{2555, 6}, {2555, 17}},
		ServiceCompositServer:  {{2417, 6}, {2417, 17}},
		ServiceCompressnet:     {{2, 6}, {2, 17}},
		ServiceCompxLockview:   {{4308, 6}, {4308, 17}},
		ServiceComscm:          {{437, 6}, {437, 17}},
		ServiceCon:             {{759, 6}, {759, 17}},
		ServiceConclaveCpp:     {{2491, 6}, {2491, 17}},
		ServiceConcomp1:        {{1802, 6}, {1802, 17}},
		ServiceConcurrentLm:    {{1648, 6}, {1648, 17}},
		ServiceCondor:          {{9618, 6}, {9618, 17}},
		ServiceConf:            {{2008, 6}},
		ServiceConference:      {{531, 6}, {531, 17}},
		ServiceConferencetalk:  {{1713, 6}, {1713, 17}},
		ServiceConfigPort:      {{3577, 6}, {3577, 17}},
		ServiceConfluent:       {{1484, 6}, {1484, 17}},
		ServiceConnect:         {{2137, 6}, {2137, 17}},
		ServiceConnectClient:   {{3441, 6}, {3441, 17}},
		ServiceConnectServer:   {{3442, 6}, {3442, 17}},
		ServiceConnected:       {{16384, 6}, {16384, 17}},
		ServiceConnection:      {{2607, 6}, {2607, 17}},
		ServiceConnendp:        {{693, 6}, {693, 17}},
		ServiceConnlcli:        {{1358, 6}, {1358, 17}},
		ServiceConspiracy:      {{4692, 6}, {4692, 17}},
		ServiceConsulInsight:   {{5992, 6}, {5992, 17}},
		ServiceContamac_icm:    {{4846, 6}, {4846, 17}},
		ServiceContclientms:    {{4665, 6}, {4665, 17}},
		ServiceContentserver:   {{454, 6}, {454, 17}},
		ServiceContinuus:       {{5412, 6}, {5412, 17}},
		ServiceCoordSvr:        {{2565, 6}, {2565, 17}},
		ServiceCops:            {{3288, 6}, {3288, 17}},
		ServiceCopsTls:         {{3183, 6}, {3183, 17}},
		ServiceCopy:            {{8445, 6}},
		ServiceCopyDisc:        {{8445, 17}},
		ServiceCopycat:         {{9093, 6}},
		ServiceCorbaIiop:       {{683, 6}, {683, 17}},
		ServiceCorbaIiopSsl:    {{684, 6}, {684, 17}},
		ServiceCorbaloc:        {{2809, 6}, {2809, 17}},
		ServiceCorel_vncadmin:  {{2654, 6}, {2654, 17}},
		ServiceCorelccam:       {{4300, 6}, {4300, 17}},
		ServiceCorelvideo:      {{1566, 6}, {1566, 17}},
		ServiceCorerjd:         {{284, 6}, {284, 17}},
		ServiceCosir:           {{10321, 6}},
		ServiceCosmocall:       {{2324, 6}, {2324, 17}},
		ServiceCouchdb:         {{5984, 6}, {5984, 17}},
		ServiceCourier:         {{530, 6}, {530, 17}},
		ServiceCovia:           {{64, 6}, {64, 17}},
		ServiceCpCluster:       {{8116, 6}, {8116, 17}},
		ServiceCpSpxdpy:        {{4378, 6}, {4378, 17}},
		ServiceCpSpxrpts:       {{5079, 17}},
		ServiceCpSpxsvr:        {{4377, 6}, {4377, 17}},
		ServiceCpdiPidasCm:     {{3609, 6}, {3609, 17}},
		ServiceCpdlc:           {{5911, 6}, {5911, 17}, {5911, 132}},
		ServiceCplscramblerAl:  {{1088, 6}, {1088, 17}},
		ServiceCplscramblerIn:  {{1087, 6}, {1087, 17}},
		ServiceCplscramblerLg:  {{1086, 6}, {1086, 17}},
		ServiceCppdp:           {{4051, 6}, {4051, 17}},
		ServiceCpqTasksmart:    {{3201, 6}, {3201, 17}},
		ServiceCpqWbem:         {{2301, 6}, {2301, 17}},
		ServiceCpqrpmAgent:     {{3256, 6}, {3256, 17}},
		ServiceCpqrpmServer:    {{3257, 6}, {3257, 17}},
		ServiceCps:             {{14250, 6}, {14250, 17}},
		ServiceCpscomm:         {{5194, 6}},
		ServiceCpsp:            {{17222, 17}},
		ServiceCpudpencap:      {{2746, 6}, {2746, 17}},
		ServiceCqgNetlan:       {{2823, 6}, {2823, 17}},
		ServiceCqgNetlan1:      {{2824, 6}, {2824, 17}},
		ServiceCrWebsystems:    {{2314, 6}, {2314, 17}},
		ServiceCreativepartnr:  {{455, 6}, {455, 17}},
		ServiceCreativeserver:  {{453, 6}, {453, 17}},
		ServiceCrestronCip:     {{41794, 6}, {41794, 17}},
		ServiceCrestronCips:    {{41796, 6}},
		ServiceCrestronCtp:     {{41795, 6}, {41795, 17}},
		ServiceCrestronCtps:    {{41797, 6}},
		ServiceCrinisHb:        {{3818, 6}, {3818, 17}},
		ServiceCrip:            {{6253, 6}, {6253, 17}},
		ServiceCrmsbits:        {{2422, 6}, {2422, 17}},
		ServiceCrs:             {{507, 6}, {507, 17}},
		ServiceCruiseConfig:    {{8378, 6}, {8378, 17}},
		ServiceCruiseDiags:     {{8379, 6}, {8379, 17}},
		ServiceCruiseEnum:      {{8376, 6}, {8376, 17}},
		ServiceCruiseSwroute:   {{8377, 6}, {8377, 17}},
		ServiceCruiseUpdate:    {{8380, 6}, {8380, 17}},
		ServiceCryptoadmin:     {{624, 6}, {624, 17}},
		ServiceCsAuthSvr:       {{3113, 6}, {3113, 17}},
		ServiceCsLive:          {{2129, 6}, {2129, 17}},
		ServiceCsRemoteDb:      {{3630, 6}, {3630, 17}},
		ServiceCsServices:      {{3631, 6}, {3631, 17}},
		ServiceCsbphonemaster:  {{1724, 6}, {1724, 17}},
		ServiceCsc_proxy:       {{4187, 6}},
		ServiceCsccfirewall:    {{40843, 6}, {40843, 17}},
		ServiceCsccredir:       {{40842, 6}, {40842, 17}},
		ServiceCscp:            {{40841, 6}, {40841, 17}},
		ServiceCsdMgmtPort:     {{3071, 6}, {3071, 17}},
		ServiceCsdMonitor:      {{3072, 6}, {3072, 17}},
		ServiceCsdm:            {{1468, 6}, {1468, 17}},
		ServiceCsdmbase:        {{1467, 6}, {1467, 17}},
		ServiceCsiLfap:         {{3145, 6}, {3145, 17}},
		ServiceCsiSgwp:         {{348, 6}, {348, 17}},
		ServiceCslg:            {{24754, 6}},
		ServiceCslistener:      {{9000, 6}, {9000, 17}},
		ServiceCsms:            {{3399, 6}, {3399, 17}},
		ServiceCsms2:           {{3400, 6}, {3400, 17}},
		ServiceCsnetNs:         {{105, 6}, {105, 17}},
		ServiceCsnotify:        {{2955, 6}, {2955, 17}},
		ServiceCsoft1:          {{1837, 6}, {1837, 17}},
		ServiceCsoftPlusclnt:   {{2699, 6}, {2699, 17}},
		ServiceCsoftPrev:       {{3271, 6}, {3271, 17}},
		ServiceCsoftragent:     {{3004, 6}, {3004, 17}},
		ServiceCspclmulti:      {{2890, 6}, {2890, 17}},
		ServiceCspmlockmgr:     {{1272, 6}, {1272, 17}},
		ServiceCspmulti:        {{2807, 6}, {2807, 17}},
		ServiceCspuni:          {{2806, 6}, {2806, 17}},
		ServiceCsregagent:      {{3022, 6}, {3022, 17}},
		ServiceCsrpc:           {{5063, 6}},
		ServiceCssc:            {{5637, 6}},
		ServiceCssp:            {{4078, 6}},
		ServiceCstPort:         {{3742, 6}, {3742, 17}},
		ServiceCsvr:            {{3417, 6}, {3417, 17}},
		ServiceCsvrProxy:       {{3190, 6}, {3190, 17}},
		ServiceCsvrSslproxy:    {{3191, 6}, {3191, 17}},
		ServiceCt2nmcs:         {{7023, 6}, {7023, 17}},
		ServiceCtcd:            {{1851, 6}, {1851, 17}},
		ServiceCtdb:            {{4379, 6}, {4379, 17}},
		ServiceCtdhercules:     {{3773, 6}, {3773, 17}},
		ServiceCtdp:            {{7022, 6}, {7022, 17}},
		ServiceCtechlicensing:  {{9346, 6}, {9346, 17}},
		ServiceCtf:             {{84, 6}, {84, 17}},
		ServiceCtiRedwood:      {{2563, 6}, {2563, 17}},
		ServiceCtiprogramload:  {{4452, 6}, {4452, 17}},
		ServiceCtisystemmsg:    {{4451, 6}, {4451, 17}},
		ServiceCtlptc:          {{2153, 6}, {2153, 17}},
		ServiceCtp:             {{3772, 6}, {3772, 17}},
		ServiceCtpState:        {{4047, 6}, {4047, 17}},
		ServiceCtsd:            {{5137, 6}, {5137, 17}},
		ServiceCttBroker:       {{1932, 6}, {1932, 17}},
		ServiceCtxBridge:       {{3127, 6}, {3127, 17}},
		ServiceCtxlic:          {{7279, 6}, {7279, 17}},
		ServiceCuelink:         {{5271, 6}},
		ServiceCuelinkDisc:     {{5271, 17}},
		ServiceCuillamartin:    {{1356, 6}, {1356, 17}},
		ServiceCumulus:         {{9287, 6}, {9287, 17}},
		ServiceCumulusAdmin:    {{8954, 6}, {8954, 17}},
		ServiceCuseeme:         {{7648, 6}, {7648, 17}},
		ServiceCustix:          {{528, 6}, {528, 17}},
		ServiceCvc:             {{1495, 6}, {1495, 17}},
		ServiceCvc_hostd:       {{442, 6}, {442, 17}},
		ServiceCvd:             {{8400, 6}, {8400, 17}},
		ServiceCvmmon:          {{2300, 6}, {2300, 17}},
		ServiceCvmon:           {{1686, 6}, {1686, 17}},
		ServiceCvspserver:      {{2401, 6}, {2401, 17}},
		ServiceCvsup:           {{5999, 6}, {5999, 17}},
		ServiceCwmp:            {{7547, 6}, {7547, 17}},
		ServiceCxtp:            {{5091, 132}},
		ServiceCxws:            {{4673, 6}, {4673, 17}},
		ServiceCyaserv:         {{2584, 6}, {2584, 17}},
		ServiceCybercash:       {{551, 6}, {551, 17}},
		ServiceCyborgSystems:   {{9888, 6}, {9888, 17}},
		ServiceCybroABus:       {{8442, 6}, {8442, 17}},
		ServiceCyc:             {{3645, 6}, {3645, 17}},
		ServiceCycleserv:       {{763, 6}, {763, 17}},
		ServiceCycleserv2:      {{772, 6}, {772, 17}},
		ServiceCylinkC:         {{5420, 6}, {5420, 17}},
		ServiceCymtecPort:      {{1898, 6}, {1898, 17}},
		ServiceCypress:         {{2015, 6}},
		ServiceCypressStat:     {{2017, 6}},
		ServiceCytelLm:         {{3297, 6}, {3297, 17}},
		ServiceD2000kernel:     {{3119, 6}, {3119, 17}},
		ServiceD2000webserver:  {{3120, 6}, {3120, 17}},
		ServiceD2dconfig:       {{9387, 6}},
		ServiceD2ddatatrans:    {{9388, 6}},
		ServiceD2kDatamover1:   {{2297, 6}, {2297, 17}},
		ServiceD2kDatamover2:   {{2298, 6}, {2298, 17}},
		ServiceD2kTapestry1:    {{3393, 6}, {3393, 17}},
		ServiceD2kTapestry2:    {{3394, 6}, {3394, 17}},
		ServiceD3winosfi:       {{3458, 6}, {3458, 17}},
		ServiceDCinemaCsp:      {{4170, 6}},
		ServiceDCinemaRrp:      {{1173, 6}, {1173, 17}},
		ServiceDData:           {{4301, 6}, {4301, 17}},
		ServiceDDataControl:    {{4302, 6}, {4302, 17}},
		ServiceDFence:          {{8555, 6}, {8555, 17}},
		ServiceDMExpress:       {{32636, 6}, {32636, 17}},
		ServiceDSN:             {{8086, 6}, {8086, 17}},
		ServiceDaap:            {{3689, 6}, {3689, 17}},
		ServiceDabStiC:         {{1076, 6}, {1076, 17}},
		ServiceDaiShell:        {{45824, 6}},
		ServiceDaishi:          {{2870, 6}, {2870, 17}},
		ServiceDaliPort:        {{5777, 6}, {5777, 17}},
		ServiceDandvTester:     {{3889, 6}, {3889, 17}},
		ServiceDanfAk2:         {{1041, 6}, {1041, 17}},
		ServiceDaqstream:       {{7411, 6}, {7411, 17}},
		ServiceDarcorpLm:       {{1679, 6}, {1679, 17}},
		ServiceDashpasPort:     {{3498, 6}, {3498, 17}},
		ServiceDasp:            {{439, 6}, {439, 17}},
		ServiceDataInsurance:   {{2764, 6}, {2764, 17}},
		ServiceDataPort:        {{3578, 6}, {3578, 17}},
		ServiceDatacaptor:      {{1857, 6}, {1857, 17}},
		ServiceDatalens:        {{2229, 6}, {2229, 17}},
		ServiceDatametrics:     {{1645, 6}, {1645, 17}},
		ServiceDatascalerCtl:   {{6625, 6}},
		ServiceDatascalerDb:    {{6624, 6}},
		ServiceDatasurfsrv:     {{461, 6}, {461, 17}},
		ServiceDatasurfsrvsec:  {{462, 6}, {462, 17}},
		ServiceDatexAsn:        {{355, 6}, {355, 17}},
		ServiceDatusorb:        {{3282, 6}, {3282, 17}},
		ServiceDavsrc:          {{9800, 6}, {9800, 17}},
		ServiceDavsrcs:         {{9802, 6}, {9802, 17}},
		ServiceDawn:            {{1908, 6}, {1908, 17}},
		ServiceDayliteserver:   {{6113, 6}},
		ServiceDaylitetouch:    {{6117, 6}},
		ServiceDaytime:         {{13, 6}, {13, 17}},
		ServiceDbLsp:           {{17500, 6}},
		ServiceDbLspDisc:       {{17500, 17}},
		ServiceDbabble:         {{8132, 6}, {8132, 17}},
		ServiceDbase:           {{217, 6}, {217, 17}},
		ServiceDbbrowse:        {{47557, 6}, {47557, 17}},
		ServiceDbcontrolOms:    {{1158, 6}, {1158, 17}},
		ServiceDbcontrol_agent: {{3938, 6}, {3938, 17}},
		ServiceDbdb:            {{6104, 6}, {6104, 17}},
		ServiceDberegister:     {{1479, 6}, {1479, 17}},
		ServiceDbisamserver1:   {{12005, 6}, {12005, 17}},
		ServiceDbisamserver2:   {{12006, 6}, {12006, 17}},
		ServiceDbm:             {{2345, 6}, {2345, 17}},
		ServiceDbref:           {{2365, 6}, {2365, 17}},
		ServiceDbreporter:      {{1379, 6}, {1379, 17}},
		ServiceDbsaLm:          {{1407, 6}, {1407, 17}},
		ServiceDbstar:          {{1415, 6}, {1415, 17}},
		ServiceDbsyncarbiter:   {{4953, 6}},
		ServiceDc:              {{2001, 6}},
		ServiceDca:             {{1456, 6}, {1456, 17}},
		ServiceDcap:            {{22125, 6}},
		ServiceDccm:            {{5679, 6}, {5679, 17}},
		ServiceDccpUdp:         {{6511, 17}},
		ServiceDcp:             {{93, 6}, {93, 17}},
		ServiceDcs:             {{1367, 6}, {1367, 17}},
		ServiceDcsConfig:       {{3988, 6}, {3988, 17}},
		ServiceDcslBackup:      {{11202, 6}},
		ServiceDcsoftware:      {{3793, 6}, {3793, 17}},
		ServiceDctp:            {{675, 6}, {675, 17}},
		ServiceDcutility:       {{1044, 6}, {1044, 17}},
		ServiceDddp:            {{9131, 6}, {9131, 17}},
		ServiceDdgn:            {{4167, 6}, {4167, 17}},
		ServiceDdiTcp1:         {{8888, 6}},
		ServiceDdiTcp2:         {{8889, 6}},
		ServiceDdiTcp3:         {{8890, 6}},
		ServiceDdiTcp4:         {{8891, 6}},
		ServiceDdiTcp5:         {{8892, 6}},
		ServiceDdiTcp6:         {{8893, 6}},
		ServiceDdiTcp7:         {{8894, 6}},
		ServiceDdiUdp1:         {{8888, 17}},
		ServiceDdiUdp2:         {{8889, 17}},
		ServiceDdiUdp3:         {{8890, 17}},
		ServiceDdiUdp4:         {{8891, 17}},
		ServiceDdiUdp5:         {{8892, 17}},
		ServiceDdiUdp6:         {{8893, 17}},
		ServiceDdiUdp7:         {{8894, 17}},
		ServiceDdmDfm:          {{447, 6}, {447, 17}},
		ServiceDdmRdb:          {{446, 6}, {446, 17}},
		ServiceDdmSsl:          {{448, 6}, {448, 17}},
		ServiceDdnsV3:          {{2164, 6}, {2164, 17}},
		ServiceDdrepl:          {{4126, 6}, {4126, 17}},
		ServiceDdt:             {{1052, 6}, {1052, 17}},
		ServiceDeCacheQuery:    {{1255, 6}, {1255, 17}},
		ServiceDeNoc:           {{1254, 6}, {1254, 17}},
		ServiceDeServer:        {{1256, 6}, {1256, 17}},
		ServiceDeSpot:          {{2753, 6}, {2753, 17}},
		ServiceDecMbadmin:      {{1655, 6}, {1655, 17}},
		ServiceDecMbadminH:     {{1656, 6}, {1656, 17}},
		ServiceDecNotes:        {{3333, 6}, {3333, 17}},
		ServiceDec_dlm:         {{625, 6}, {625, 17}},
		ServiceDecap:           {{403, 6}, {403, 17}},
		ServiceDecauth:         {{316, 6}, {316, 17}},
		ServiceDecbsrv:         {{579, 6}, {579, 17}},
		ServiceDecladebug:      {{410, 6}, {410, 17}},
		ServiceDectalk:         {{2007, 6}},
		ServiceDecvmsSysmgt:    {{441, 6}, {441, 17}},
		ServiceDeiIcda:         {{618, 6}, {618, 17}},
		ServiceDelibo:          {{2562, 6}, {2562, 17}},
		ServiceDellEqlAsm:      {{7569, 6}},
		ServiceDellRmPort:      {{3668, 6}, {3668, 17}},
		ServiceDellpwrappks:    {{1266, 6}, {1266, 17}},
		ServiceDellwebadmin1:   {{1278, 6}, {1278, 17}},
		ServiceDellwebadmin2:   {{1279, 6}, {1279, 17}},
		ServiceDelosDms:        {{3714, 6}, {3714, 17}},
		ServiceDeltaMcp:        {{1324, 6}, {1324, 17}},
		ServiceDenaliServer:    {{3444, 6}, {3444, 17}},
		ServiceDeos:            {{76, 6}, {76, 17}},
		ServiceDerbyRepli:      {{4851, 6}, {4851, 17}},
		ServiceDescent3:        {{2092, 6}, {2092, 17}},
		ServiceDeskshare:       {{1702, 6}, {1702, 17}},
		ServiceDesktopDna:      {{2763, 6}, {2763, 17}},
		ServiceDeskview:        {{3298, 6}, {3298, 17}},
		ServiceDevbasic:        {{5426, 6}, {5426, 17}},
		ServiceDevice:          {{801, 6}, {801, 17}},
		ServiceDevice2:         {{2030, 6}, {2030, 17}},
		ServiceDevshrNts:       {{552, 6}, {552, 17}},
		ServiceDeyKeyneg:       {{8750, 6}},
		ServiceDeySapi:         {{4330, 6}},
		ServiceDfn:             {{1133, 6}, {1133, 17}},
		ServiceDfoxserver:      {{2960, 6}, {2960, 17}},
		ServiceDfserver:        {{21554, 6}, {21554, 17}},
		ServiceDgiServ:         {{33333, 6}},
		ServiceDgpfExchg:       {{6785, 6}, {6785, 17}},
		ServiceDhanalakshmi:    {{34567, 6}},
		ServiceDhcpFailover:    {{647, 6}, {647, 17}},
		ServiceDhcpFailover2:   {{847, 6}, {847, 17}},
		ServiceDhcpv6Client:    {{546, 6}, {546, 17}},
		ServiceDhcpv6Server:    {{547, 6}, {547, 17}},
		ServiceDhctAlerts:      {{4676, 6}, {4676, 17}},
		ServiceDhctStatus:      {{4675, 6}, {4675, 17}},
		ServiceDhe:             {{3252, 6}, {3252, 17}},
		ServiceDiAse:           {{3046, 6}, {3046, 17}},
		ServiceDiDrm:           {{2226, 6}, {2226, 17}},
		ServiceDiMsg:           {{2227, 6}, {2227, 17}},
		ServiceDiTraceware:     {{3041, 6}, {3041, 17}},
		ServiceDiagmond:        {{1508, 6}, {1508, 17}},
		ServiceDiagnoseProc:    {{6072, 6}, {6072, 17}},
		ServiceDialogPort:      {{2098, 6}, {2098, 17}},
		ServiceDialogicElmd:    {{1945, 6}, {1945, 17}},
		ServiceDialpadVoice1:   {{2860, 6}, {2860, 17}},
		ServiceDialpadVoice2:   {{2861, 6}, {2861, 17}},
		ServiceDiameter:        {{3868, 6}, {3868, 132}},
		ServiceDiameters:       {{5868, 6}, {5868, 132}},
		ServiceDiamondport:     {{33331, 6}, {33331, 17}},
		ServiceDicAida:         {{1941, 6}, {1941, 17}},
		ServiceDicom:           {{11112, 6}, {11112, 17}},
		ServiceDicomIscl:       {{2761, 6}, {2761, 17}},
		ServiceDicomTls:        {{2762, 6}, {2762, 17}},
		ServiceDict:            {{2628, 6}, {2628, 17}},
		ServiceDictLookup:      {{2289, 6}, {2289, 17}},
		ServiceDifPort:         {{2251, 6}, {2251, 17}},
		ServiceDigiman:         {{2362, 6}, {2362, 17}},
		ServiceDigitalNotary:   {{1335, 6}, {1335, 17}},
		ServiceDigitalVrc:      {{466, 6}, {466, 17}},
		ServiceDigivote:        {{3223, 6}, {3223, 17}},
		ServiceDirecpcDll:      {{1844, 6}, {1844, 17}},
		ServiceDirecpcSi:       {{2464, 6}, {2464, 17}},
		ServiceDirecpcVideo:    {{1825, 6}, {1825, 17}},
		ServiceDirect:          {{242, 6}, {242, 17}},
		ServiceDirectnet:       {{3447, 6}, {3447, 17}},
		ServiceDirectplay:      {{2234, 6}, {2234, 17}},
		ServiceDirectplay8:     {{6073, 6}, {6073, 17}},
		ServiceDirectplaysrvr:  {{47624, 6}, {47624, 17}},
		ServiceDirectvCatlg:    {{3337, 6}, {3337, 17}},
		ServiceDirectvSoft:     {{3335, 6}, {3335, 17}},
		ServiceDirectvTick:     {{3336, 6}, {3336, 17}},
		ServiceDirectvWeb:      {{3334, 6}, {3334, 17}},
		ServiceDirectvdata:     {{3287, 6}, {3287, 17}},
		ServiceDirgis:          {{2496, 6}, {2496, 17}},
		ServiceDiscard:         {{9, 6}, {9, 17}, {9, 132}, {9, 33}},
		ServiceDisclose:        {{667, 6}, {667, 17}},
		ServiceDiscoveryPort:   {{1925, 6}, {1925, 17}},
		ServiceDiscpClient:     {{2601, 6}, {2601, 17}},
		ServiceDiscpServer:     {{2602, 6}, {2602, 17}},
		ServiceDisplay:         {{7236, 6}},
		ServiceDistUpgrade:     {{3624, 6}, {3624, 17}},
		ServiceDistcc:          {{3632, 6}, {3632, 17}},
		ServiceDistinct:        {{9999, 6}, {9999, 17}},
		ServiceDistinct32:      {{9998, 6}, {9998, 17}},
		ServiceDixie:           {{96, 6}, {96, 17}},
		ServiceDjIce:           {{5419, 6}, {5419, 17}},
		ServiceDjIlm:           {{3362, 6}, {3362, 17}},
		ServiceDka:             {{1263, 6}, {1263, 17}},
		ServiceDkmessenger:     {{1177, 6}, {1177, 17}},
		ServiceDl_agent:        {{3876, 6}, {3876, 17}},
		ServiceDlip:            {{7201, 6}, {7201, 17}},
		ServiceDlmsCosem:       {{4059, 6}, {4059, 17}},
		ServiceDlpxSp:          {{8415, 6}},
		ServiceDls:             {{197, 6}, {197, 17}},
		ServiceDlsMon:          {{198, 6}, {198, 17}},
		ServiceDlsMonitor:      {{2048, 6}, {2048, 17}},
		ServiceDlsrap:          {{1973, 6}, {1973, 17}},
		ServiceDlsrpn:          {{2065, 6}, {2065, 17}},
		ServiceDlswpn:          {{2067, 6}, {2067, 17}},
		ServiceDmafCaster:      {{3574, 17}},
		ServiceDmafServer:      {{3574, 6}},
		ServiceDmdocbroker:     {{1489, 6}, {1489, 17}},
		ServiceDmidi:           {{1199, 6}, {1199, 17}},
		ServiceDmodWorkspace:   {{3199, 6}, {3199, 17}},
		ServiceDmp:             {{5031, 17}},
		ServiceDn6NlmAud:       {{195, 6}, {195, 17}},
		ServiceDn6SmmRed:       {{196, 6}, {196, 17}},
		ServiceDna:             {{2287, 6}, {2287, 17}},
		ServiceDnaCml:          {{436, 6}, {436, 17}},
		ServiceDnap:            {{1172, 6}, {1172, 17}},
		ServiceDncPort:         {{3448, 6}, {3448, 17}},
		ServiceDnox:            {{4022, 6}, {4022, 17}},
		ServiceDnp:             {{20000, 6}, {20000, 17}},
		ServiceDnpSec:          {{19999, 6}, {19999, 17}},
		ServiceDns2go:          {{1227, 6}, {1227, 17}},
		ServiceDnsLlq:          {{5352, 6}, {5352, 17}},
		ServiceDnsix:           {{90, 6}, {90, 17}},
		ServiceDnx:             {{3998, 6}, {3998, 17}},
		ServiceDoc1lm:          {{3161, 6}, {3161, 17}},
		ServiceDocServer:       {{7165, 6}, {7165, 17}},
		ServiceDocent:          {{2151, 6}, {2151, 17}},
		ServiceDoceriCtl:       {{7019, 6}},
		ServiceDoceriView:      {{7019, 17}},
		ServiceDocstor:         {{1488, 6}, {1488, 17}},
		ServiceDocumentum:      {{10002, 6}, {10002, 17}},
		ServiceDocumentum_s:    {{10003, 6}, {10003, 17}},
		ServiceDoglms:          {{6088, 6}},
		ServiceDoglmsNotify:    {{6088, 17}},
		ServiceDoipData:        {{13400, 6}},
		ServiceDoipDisc:        {{13400, 17}},
		ServiceDomain:          {{53, 6}, {53, 17}},
		ServiceDomaintime:      {{9909, 6}, {9909, 17}},
		ServiceDomiq:           {{44544, 17}},
		ServiceDonnyworld:      {{1821, 6}, {1821, 17}},
		ServiceDossier:         {{1175, 6}, {1175, 17}},
		ServiceDown:            {{2022, 6}},
		ServiceDowntools:       {{5245, 6}},
		ServiceDowntoolsDisc:   {{5245, 17}},
		ServiceDpap:            {{8770, 6}, {8770, 17}},
		ServiceDpcp:            {{4099, 6}, {4099, 17}},
		ServiceDpiProxy:        {{1795, 6}, {1795, 17}},
		ServiceDpkeyserv:       {{1780, 6}, {1780, 17}},
		ServiceDpm:             {{5718, 6}, {5718, 17}},
		ServiceDpmAcm:          {{6075, 6}},
		ServiceDpmAgent:        {{5719, 6}, {5719, 17}},
		ServiceDproxy:          {{1296, 6}, {1296, 17}},
		ServiceDpserve:         {{7020, 6}, {7020, 17}},
		ServiceDpserveadmin:    {{7021, 6}, {7021, 17}},
		ServiceDpsi:            {{315, 6}, {315, 17}},
		ServiceDragonfly:       {{8913, 6}, {8913, 17}},
		ServiceDrip:            {{3949, 6}, {3949, 17}},
		ServiceDriveappserver:  {{1930, 6}, {1930, 17}},
		ServiceDrizzle:         {{4427, 6}},
		ServiceDrmProduction:   {{7171, 6}, {7171, 17}},
		ServiceDrmsfsd:         {{4098, 6}, {4098, 17}},
		ServiceDrmsmc:          {{1878, 6}, {1878, 17}},
		ServiceDrp:             {{1974, 6}, {1974, 17}},
		ServiceDrwcs:           {{2193, 6}, {2193, 17}},
		ServiceDsAdmin:         {{4404, 6}, {4404, 17}},
		ServiceDsClnt:          {{4402, 6}, {4402, 17}},
		ServiceDsETOS:          {{378, 6}, {378, 17}},
		ServiceDsMail:          {{4405, 6}, {4405, 17}},
		ServiceDsSlp:           {{4406, 6}, {4406, 17}},
		ServiceDsSrv:           {{4400, 6}, {4400, 17}},
		ServiceDsSrvr:          {{4401, 6}, {4401, 17}},
		ServiceDsUser:          {{4403, 6}, {4403, 17}},
		ServiceDsatp:           {{2111, 6}, {2111, 17}},
		ServiceDsc:             {{3390, 6}, {3390, 17}},
		ServiceDsdn:            {{1292, 6}, {1292, 17}},
		ServiceDserver:         {{4309, 6}, {4309, 17}},
		ServiceDsf:             {{555, 6}, {555, 17}},
		ServiceDsfgw:           {{438, 6}, {438, 17}},
		ServiceDslremoteMgmt:   {{2420, 6}, {2420, 17}},
		ServiceDsmScmTarget:    {{9987, 6}, {9987, 17}},
		ServiceDsmccCcp:        {{13822, 6}, {13822, 17}},
		ServiceDsmccConfig:     {{13818, 6}, {13818, 17}},
		ServiceDsmccDownload:   {{13821, 6}, {13821, 17}},
		ServiceDsmccPassthru:   {{13820, 6}, {13820, 17}},
		ServiceDsmccSession:    {{13819, 6}, {13819, 17}},
		ServiceDsmeter_iatc:    {{4060, 6}, {4060, 17}},
		ServiceDsmipv6:         {{4191, 17}},
		ServiceDsomServer:      {{3053, 6}, {3053, 17}},
		ServiceDsp:             {{33, 6}, {33, 17}},
		ServiceDsp3270:         {{246, 6}, {246, 17}},
		ServiceDssiapi:         {{1265, 6}, {1265, 17}},
		ServiceDsxAgent:        {{3685, 6}, {3685, 17}},
		ServiceDsx_monitor:     {{31685, 6}},
		ServiceDtMgmtsvc:       {{6325, 6}},
		ServiceDtVra:           {{6326, 6}},
		ServiceDtaSystems:      {{13929, 6}, {13929, 17}},
		ServiceDtagSteSb:       {{352, 6}, {352, 17}},
		ServiceDtk:             {{365, 6}, {365, 17}},
		ServiceDtn1:            {{2445, 6}, {2445, 17}},
		ServiceDtnBundleTcp:    {{4556, 6}},
		ServiceDtnBundleUdp:    {{4556, 17}},
		ServiceDtp:             {{3663, 6}, {3663, 17}},
		ServiceDtpDia:          {{3489, 6}, {3489, 17}},
		ServiceDtpNet:          {{8732, 17}},
		ServiceDtpt:            {{5721, 6}, {5721, 17}},
		ServiceDts:             {{2594, 6}, {2594, 17}},
		ServiceDtserverPort:    {{4028, 6}, {4028, 17}},
		ServiceDtspcd:          {{6112, 6}, {6112, 17}},
		ServiceDtvChanReq:      {{2253, 6}, {2253, 17}},
		ServiceDvapps:          {{3831, 6}, {3831, 17}},
		ServiceDvbservdsc:      {{3937, 6}, {3937, 17}},
		ServiceDvcprovPort:     {{3776, 6}, {3776, 17}},
		ServiceDvlActivemail:   {{1396, 6}, {1396, 17}},
		ServiceDvrEsm:          {{2804, 6}, {2804, 17}},
		ServiceDvtData:         {{3247, 6}, {3247, 17}},
		ServiceDvtSystem:       {{3246, 6}, {3246, 17}},
		ServiceDwf:             {{1450, 6}, {1450, 17}},
		ServiceDwmsgserver:     {{3228, 6}, {3228, 17}},
		ServiceDwnmshttp:       {{3227, 6}, {3227, 17}},
		ServiceDwr:             {{644, 6}, {644, 17}},
		ServiceDxInstrument:    {{1325, 6}, {1325, 17}},
		ServiceDxadmind:        {{1958, 6}, {1958, 17}},
		ServiceDxmessagebase1:  {{2874, 6}, {2874, 17}},
		ServiceDxmessagebase2:  {{2875, 6}, {2875, 17}},
		ServiceDxspider:        {{8873, 6}, {8873, 17}},
		ServiceDynSite:         {{3932, 6}, {3932, 17}},
		ServiceDynaAccess:      {{3310, 6}, {3310, 17}},
		ServiceDynaLm:          {{3395, 6}, {3395, 17}},
		ServiceDynamid:         {{9002, 6}, {9002, 17}},
		ServiceDyniplookup:     {{3295, 6}, {3295, 17}},
		ServiceDzdaemon:        {{3866, 6}, {3866, 17}},
		ServiceDzoglserver:     {{3867, 6}, {3867, 17}},
		ServiceE3consultants:   {{3157, 6}, {3157, 17}},
		ServiceEBuilder:        {{4121, 6}, {4121, 17}},
		ServiceEDesignNet:      {{6702, 6}, {6702, 17}},
		ServiceEDesignWeb:      {{6703, 6}, {6703, 17}},
		ServiceEDpnet:          {{2036, 6}, {2036, 17}},
		ServiceEMdu:            {{3727, 6}, {3727, 17}},
		ServiceENet:            {{3286, 6}, {3286, 17}},
		ServiceEWoa:            {{3728, 6}, {3728, 17}},
		ServiceEa:              {{17729, 6}, {17729, 17}},
		ServiceEa1:             {{1791, 6}, {1791, 17}},
		ServiceEapsp:           {{2291, 6}, {2291, 17}},
		ServiceEasySoftMux:     {{2168, 6}, {2168, 17}},
		ServiceEba:             {{45678, 6}, {45678, 17}},
		ServiceEbinsite:        {{2651, 6}, {2651, 17}},
		ServiceEcho:            {{7, 6}, {7, 17}, {4, 6}},
		ServiceEchonet:         {{3610, 6}, {3610, 17}},
		ServiceEcmp:            {{6160, 6}},
		ServiceEcmpData:        {{6160, 17}},
		ServiceEcmport:         {{3524, 6}, {3524, 17}},
		ServiceEcnp:            {{2858, 6}, {2858, 17}},
		ServiceEcolorImager:    {{3263, 6}, {3263, 17}},
		ServiceEcomm:           {{3477, 6}, {3477, 17}},
		ServiceEcovisiong61:    {{2896, 6}, {2896, 17}},
		ServiceEcp:             {{3134, 6}, {3134, 17}},
		ServiceEcsqdmn:         {{1882, 6}, {1882, 17}},
		ServiceEcwcfg:          {{2263, 6}, {2263, 17}},
		ServiceEdbServer1:      {{1635, 6}, {1635, 17}},
		ServiceEdbServer2:      {{3711, 6}, {3711, 17}},
		ServiceEdbsrvr:         {{12010, 6}},
		ServiceEditbench:       {{1350, 6}, {1350, 17}},
		ServiceEdix:            {{3123, 6}, {3123, 17}},
		ServiceEdmAdmNotify:    {{3463, 6}, {3463, 17}},
		ServiceEdmManager:      {{3460, 6}, {3460, 17}},
		ServiceEdmMgrCntrl:     {{3465, 6}, {3465, 17}},
		ServiceEdmMgrSync:      {{3464, 6}, {3464, 17}},
		ServiceEdmStager:       {{3461, 6}, {3461, 17}},
		ServiceEdmStdNotify:    {{3462, 6}, {3462, 17}},
		ServiceEdtools:         {{1142, 6}, {1142, 17}},
		ServiceEenet:           {{5234, 6}, {5234, 17}},
		ServiceEfbAci:          {{6159, 6}},
		ServiceEfcp:            {{3671, 6}, {3671, 17}},
		ServiceEfiLm:           {{3392, 6}, {3392, 17}},
		ServiceEfiMg:           {{2224, 6}, {2224, 17}},
		ServiceEfidiningport:   {{2553, 6}, {2553, 17}},
		ServiceEforward:        {{2181, 6}, {2181, 17}},
		ServiceEfs:             {{520, 6}},
		ServiceEgptlm:          {{3328, 6}, {3328, 17}},
		ServiceEgs:             {{1926, 6}, {1926, 17}},
		ServiceEhomeMs:         {{2228, 6}, {2228, 17}},
		ServiceEhpBackup:       {{3638, 6}, {3638, 17}},
		ServiceEhs:             {{4535, 6}, {4535, 17}},
		ServiceEhsSsl:          {{4536, 6}, {4536, 17}},
		ServiceEhtp:            {{1295, 6}, {1295, 17}},
		ServiceEiconServer:     {{1438, 6}, {1438, 17}},
		ServiceEiconSlp:        {{1440, 6}, {1440, 17}},
		ServiceEiconX25:        {{1439, 6}, {1439, 17}},
		ServiceEimsAdmin:       {{4199, 6}, {4199, 17}},
		ServiceEis:             {{3982, 6}, {3982, 17}},
		ServiceEisp:            {{3983, 6}, {3983, 17}},
		ServiceEisport:         {{3525, 6}, {3525, 17}},
		ServiceEklogin:         {{2105, 6}},
		ServiceElad:            {{1893, 6}, {1893, 17}},
		ServiceElan:            {{1378, 6}, {1378, 17}},
		ServiceElanlm:          {{4346, 6}, {4346, 17}},
		ServiceElatelink:       {{2124, 6}, {2124, 17}},
		ServiceElcn:            {{7101, 6}, {7101, 17}},
		ServiceElcsd:           {{704, 6}, {704, 17}},
		ServiceElektronAdmin:   {{5398, 6}, {5398, 17}},
		ServiceElfiqRepl:       {{1148, 6}, {1148, 17}},
		ServiceEli:             {{2087, 6}, {2087, 17}},
		ServiceElipseRec:       {{6515, 6}, {6515, 17}},
		ServiceEllpack:         {{2025, 6}},
		ServiceElmMomentum:     {{1914, 6}, {1914, 17}},
		ServiceElpro_tunnel:    {{4370, 6}, {4370, 17}},
		ServiceEls:             {{1315, 6}, {1315, 17}},
		ServiceElvin_client:    {{2917, 6}, {2917, 17}},
		ServiceElvin_server:    {{2916, 6}, {2916, 17}},
		ServiceElxmgmt:         {{23333, 6}, {23333, 17}},
		ServiceEm7Secom:        {{7700, 6}},
		ServiceEmaSentLm:       {{2526, 6}, {2526, 17}},
		ServiceEmbProjCmd:      {{5116, 17}},
		ServiceEmblNdt:         {{394, 6}, {394, 17}},
		ServiceEmbraceDpC:      {{3198, 6}, {3198, 17}},
		ServiceEmbraceDpS:      {{3197, 6}, {3197, 17}},
		ServiceEmcGateway:      {{1273, 6}, {1273, 17}},
		ServiceEmcPpMgmtsvc:    {{9083, 6}},
		ServiceEmcVcasTcp:      {{13218, 6}},
		ServiceEmcVcasUdp:      {{13218, 17}},
		ServiceEmcads:          {{3945, 6}, {3945, 17}},
		ServiceEmce:            {{2004, 17}},
		ServiceEmcrmirccd:      {{10004, 6}},
		ServiceEmcrmird:        {{10005, 6}},
		ServiceEmcsymapiport:   {{2707, 6}, {2707, 17}},
		ServiceEmfisCntl:       {{141, 6}, {141, 17}},
		ServiceEmfisData:       {{140, 6}, {140, 17}},
		ServiceEmgmsg:          {{6656, 6}},
		ServiceEmpServer1:      {{6321, 6}, {6321, 17}},
		ServiceEmpServer2:      {{6322, 6}, {6322, 17}},
		ServiceEmperion:        {{1282, 6}, {1282, 17}},
		ServiceEmpireEmpuma:    {{1691, 6}, {1691, 17}},
		ServiceEmpowerid:       {{7080, 6}, {7080, 17}},
		ServiceEmpriseLls:      {{3585, 6}, {3585, 17}},
		ServiceEmpriseLsc:      {{3586, 6}, {3586, 17}},
		ServiceEms:             {{4664, 6}, {4664, 17}},
		ServiceEmsdPort:        {{1928, 6}, {1928, 17}},
		ServiceEmwavemsg:       {{20480, 6}, {20480, 17}},
		ServiceEmwin:           {{2211, 6}, {2211, 17}},
		ServiceEncEps:          {{3567, 6}, {3567, 17}},
		ServiceEncEpsMcSec:     {{5567, 6}, {5567, 17}},
		ServiceEncTunelSec:     {{3568, 6}, {3568, 17}},
		ServiceEncTunnel:       {{8567, 6}, {8567, 17}},
		ServiceEncore:          {{1740, 6}, {1740, 17}},
		ServiceEncryptedLlrp:   {{5085, 6}, {5085, 17}},
		ServiceEncrypted_admin: {{1138, 6}, {1138, 17}},
		ServiceEnfs:            {{5233, 6}},
		ServiceEnl:             {{1804, 6}, {1804, 17}},
		ServiceEnlName:         {{1805, 6}, {1805, 17}},
		ServiceEnpc:            {{3289, 6}, {3289, 17}},
		ServiceEnpp:            {{2968, 6}, {2968, 17}},
		ServiceEnrp:            {{9901, 17}},
		ServiceEnrpSctp:        {{9901, 132}},
		ServiceEnrpSctpTls:     {{9902, 132}},
		ServiceEntEngine:       {{3665, 6}, {3665, 17}},
		ServiceEntexthigh:      {{12002, 6}, {12002, 17}},
		ServiceEntextlow:       {{12004, 6}, {12004, 17}},
		ServiceEntextmed:       {{12003, 6}, {12003, 17}},
		ServiceEntextnetwk:     {{12001, 6}, {12001, 17}},
		ServiceEntextxid:       {{12000, 6}, {12000, 17}},
		ServiceEntomb:          {{775, 6}},
		ServiceEntp:            {{1865, 6}, {1865, 17}},
		ServiceEntrustAaas:     {{680, 6}, {680, 17}},
		ServiceEntrustAams:     {{681, 6}, {681, 17}},
		ServiceEntrustAsh:      {{710, 6}, {710, 17}},
		ServiceEntrustKmsh:     {{709, 6}, {709, 17}},
		ServiceEntrustSps:      {{640, 6}, {640, 17}},
		ServiceEntrusttime:     {{309, 6}, {309, 17}},
		ServiceEorGame:         {{8149, 17}},
		ServiceEoss:            {{1210, 6}, {1210, 17}},
		ServiceEpNsp:           {{3621, 6}, {3621, 17}},
		ServiceEpPcp:           {{3620, 6}, {3620, 17}},
		ServiceEpc:             {{1267, 6}, {1267, 17}},
		ServiceEpicon:          {{2912, 6}, {2912, 17}},
		ServiceEplSlp:          {{3819, 6}, {3819, 17}},
		ServiceEpmap:           {{135, 6}, {135, 17}},
		ServiceEpmd:            {{4369, 6}, {4369, 17}},
		ServiceEpncdp2:         {{3259, 6}, {3259, 17}},
		ServiceEpnsdp:          {{2051, 6}, {2051, 17}},
		ServiceEportcomm:       {{4666, 6}, {4666, 17}},
		ServiceEportcommdata:   {{4669, 6}, {4669, 17}},
		ServiceEpp:             {{700, 6}, {700, 17}},
		ServiceEppc:            {{3031, 6}, {3031, 17}},
		ServiceEptMachine:      {{3628, 6}, {3628, 17}},
		ServiceEq3Config:       {{43439, 17}},
		ServiceEq3Update:       {{43439, 6}},
		ServiceEqOffice4940:    {{4940, 6}, {4940, 17}},
		ServiceEqOffice4941:    {{4941, 6}, {4941, 17}},
		ServiceEqOffice4942:    {{4942, 6}, {4942, 17}},
		ServiceEquationbuilder: {{1351, 6}, {1351, 17}},
		ServiceErgolight:       {{2109, 6}, {2109, 17}},
		ServiceEristwoguns:     {{2650, 6}, {2650, 17}},
		ServiceErpScale:        {{5135, 6}},
		ServiceErpc:            {{121, 6}, {121, 17}},
		ServiceErunbook_agent:  {{9616, 6}},
		ServiceErunbook_server: {{9617, 6}},
		ServiceEsElmd:          {{1822, 6}, {1822, 17}},
		ServiceEsbroker:        {{1342, 6}, {1342, 17}},
		ServiceEscpIp:          {{621, 6}, {621, 17}},
		ServiceEscvpnet:        {{3629, 6}, {3629, 17}},
		ServiceEserverPap:      {{3666, 6}, {3666, 17}},
		ServiceEsimport:        {{3564, 6}, {3564, 17}},
		ServiceEsinstall:       {{5599, 6}, {5599, 17}},
		ServiceEsip:            {{2950, 6}, {2950, 17}},
		ServiceEslLm:           {{1455, 6}, {1455, 17}},
		ServiceEsmagent:        {{5601, 6}, {5601, 17}},
		ServiceEsmmanager:      {{5600, 6}, {5600, 17}},
		ServiceEsnmZoning:      {{4023, 6}, {4023, 17}},
		ServiceEspEncap:        {{2797, 6}, {2797, 17}},
		ServiceEspLm:           {{3383, 6}, {3383, 17}},
		ServiceEspeech:         {{8416, 6}, {8416, 17}},
		ServiceEspeechRtp:      {{8417, 6}, {8417, 17}},
		ServiceEspsPortal:      {{2867, 6}, {2867, 17}},
		ServiceEsri_sde:        {{5151, 6}, {5151, 17}},
		ServiceEsroEmsdp:       {{642, 6}, {642, 17}},
		ServiceEsroGen:         {{259, 6}, {259, 17}},
		ServiceEssbase:         {{1423, 6}, {1423, 17}},
		ServiceEssp:            {{2969, 6}, {2969, 17}},
		ServiceEsswebGw:        {{1772, 6}, {1772, 17}},
		ServiceEstamp:          {{1982, 6}, {1982, 17}},
		ServiceEtb4j:           {{16309, 6}, {16309, 17}},
		ServiceEtcControl:      {{6107, 6}, {6107, 17}},
		ServiceEtebac5:         {{1216, 6}, {1216, 17}},
		ServiceEtftp:           {{1818, 6}, {1818, 17}},
		ServiceEtherNetIP1:     {{2222, 6}, {2222, 17}},
		ServiceEtherNetIP2:     {{44818, 6}, {44818, 17}},
		ServiceEthercat:        {{34980, 6}, {34980, 17}},
		ServiceEthoscan:        {{6935, 6}, {6935, 17}},
		ServiceEtlservicemgr:   {{9001, 6}, {9001, 17}},
		ServiceEtp:             {{1798, 6}, {1798, 17}},
		ServiceEts:             {{1569, 6}, {1569, 17}},
		ServiceEudoraSet:       {{592, 6}, {592, 17}},
		ServiceEvServices:      {{5114, 6}},
		ServiceEvbElm:          {{1504, 6}, {1504, 17}},
		ServiceEventPort:       {{2069, 6}, {2069, 17}},
		ServiceEvent_listener:  {{3017, 6}, {3017, 17}},
		ServiceEverydayrc:      {{2782, 6}, {2782, 17}},
		ServiceEvm:             {{1139, 6}, {1139, 17}},
		ServiceEvtp:            {{2834, 6}, {2834, 17}},
		ServiceEvtpData:        {{2835, 6}, {2835, 17}},
		ServiceEwDiscCmd:       {{43440, 17}},
		ServiceEwMgmt:          {{43440, 6}},
		ServiceEwall:           {{1328, 6}, {1328, 17}},
		ServiceEwcappsrv:       {{1876, 6}, {1876, 17}},
		ServiceEwctsp:          {{6066, 6}, {6066, 17}},
		ServiceEwdgs:           {{4092, 6}, {4092, 17}},
		ServiceEwinstaller:     {{4091, 6}, {4091, 17}},
		ServiceEwnn:            {{2674, 6}, {2674, 17}},
		ServiceExaptLmgr:       {{3759, 6}, {3759, 17}},
		ServiceExasoftport1:    {{3920, 6}, {3920, 17}},
		ServiceExbitEscp:       {{1316, 6}, {1316, 17}},
		ServiceExce:            {{2769, 6}, {2769, 17}},
		ServiceExcerpt:         {{5400, 6}, {5400, 17}},
		ServiceExcerpts:        {{5401, 6}, {5401, 17}},
		ServiceExcw:            {{1271, 6}, {1271, 17}},
		ServiceExec:            {{512, 6}},
		ServiceExlmAgent:       {{3002, 6}, {3002, 17}},
		ServiceExoconfig:       {{26487, 6}, {26487, 17}},
		ServiceExolineTcp:      {{26486, 6}},
		ServiceExolineUdp:      {{26486, 17}},
		ServiceExonet:          {{26489, 6}, {26489, 17}},
		ServiceExp1:            {{1021, 6}, {1021, 17}, {1021, 132}, {1021, 33}},
		ServiceExp2:            {{1022, 6}, {1022, 17}, {1022, 132}, {1022, 33}},
		ServiceExpresspay:      {{2755, 6}, {2755, 17}},
		ServiceExtensis:        {{2666, 6}, {2666, 17}},
		ServiceEye2eye:         {{1948, 6}, {1948, 17}},
		ServiceEyelink:         {{589, 6}, {589, 17}},
		ServiceEyetv:           {{2170, 6}, {2170, 17}},
		ServiceEzmeeting:       {{26261, 6}, {26261, 17}},
		ServiceEzmeeting2:      {{10101, 6}, {10101, 17}},
		ServiceEzmessagesrv:    {{4085, 6}},
		ServiceEzproxy:         {{26260, 6}, {26260, 17}},
		ServiceEzproxy2:        {{10102, 6}, {10102, 17}},
		ServiceEzrelay:         {{10103, 6}, {10103, 17}},
		ServiceF5Globalsite:    {{2792, 6}, {2792, 17}},
		ServiceF5Iquery:        {{4353, 6}, {4353, 17}},
		ServiceFacRestore:      {{5582, 6}, {5582, 17}},
		ServiceFacelink:        {{1915, 6}, {1915, 17}},
		ServiceFacilityview:    {{1561, 6}, {1561, 17}},
		ServiceFacsysNtp:       {{2514, 6}, {2514, 17}},
		ServiceFacsysRouter:    {{2515, 6}, {2515, 17}},
		ServiceFagordnc:        {{3873, 6}, {3873, 17}},
		ServiceFairview:        {{38202, 6}, {38202, 17}},
		ServiceFarenet:         {{5557, 6}},
		ServiceFastRemServ:     {{2495, 6}, {2495, 17}},
		ServiceFastlynx:        {{2689, 6}, {2689, 17}},
		ServiceFatpipe:         {{3353, 6}, {3353, 17}},
		ServiceFatserv:         {{347, 6}, {347, 17}},
		ServiceFax:             {{4557, 6}},
		ServiceFaxcomservice:   {{6417, 6}, {6417, 17}},
		ServiceFaximum:         {{7437, 6}, {7437, 17}},
		ServiceFaxportwinport:  {{1620, 6}, {1620, 17}},
		ServiceFaxstfxPort:     {{3684, 6}, {3684, 17}},
		ServiceFazztAdmin:      {{4039, 6}, {4039, 17}},
		ServiceFazztPtp:        {{4038, 6}, {4038, 17}},
		ServiceFcCli:           {{1371, 6}, {1371, 17}},
		ServiceFcFaultnotify:   {{2819, 6}, {2819, 17}},
		ServiceFcSer:           {{1372, 6}, {1372, 17}},
		ServiceFcipPort:        {{3225, 6}, {3225, 17}},
		ServiceFcis:            {{4727, 6}},
		ServiceFcisDisc:        {{4727, 17}},
		ServiceFcmsys:          {{2344, 6}, {2344, 17}},
		ServiceFcopyServer:     {{5745, 6}, {5745, 17}},
		ServiceFcopysServer:    {{5746, 6}, {5746, 17}},
		ServiceFcp:             {{510, 6}, {510, 17}},
		ServiceFcpAddrSrvr1:    {{5500, 6}, {5500, 17}},
		ServiceFcpAddrSrvr2:    {{5501, 6}, {5501, 17}},
		ServiceFcpCicsGw1:      {{5504, 6}, {5504, 17}},
		ServiceFcpSrvrInst1:    {{5502, 6}, {5502, 17}},
		ServiceFcpSrvrInst2:    {{5503, 6}, {5503, 17}},
		ServiceFcpUdp:          {{810, 6}, {810, 17}},
		ServiceFdtRcatp:        {{4320, 6}, {4320, 17}},
		ServiceFdtracks:        {{5579, 6}},
		ServiceFebootiAw:       {{36524, 6}},
		ServiceFeitianrockey:   {{3152, 6}, {3152, 17}},
		ServiceFemis:           {{1776, 6}, {1776, 17}},
		ServiceFerrariFoam:     {{3216, 6}, {3216, 17}},
		ServiceFfAnnunc:        {{1089, 6}, {1089, 17}},
		ServiceFfFms:           {{1090, 6}, {1090, 17}},
		ServiceFfLrPort:        {{3622, 6}, {3622, 17}},
		ServiceFfSm:            {{1091, 6}, {1091, 17}},
		ServiceFfserver:        {{3825, 6}, {3825, 17}},
		ServiceFgFps:           {{3293, 6}, {3293, 17}},
		ServiceFgGip:           {{3294, 6}, {3294, 17}},
		ServiceFgSysupdate:     {{6550, 6}, {6550, 17}},
		ServiceFhc:             {{1499, 6}, {1499, 17}},
		ServiceFhsp:            {{1807, 6}, {1807, 17}},
		ServiceFibotraderCom:   {{6715, 6}, {6715, 17}},
		ServiceFido:            {{60179, 6}, {60179, 17}},
		ServiceFilecast:        {{3401, 6}, {3401, 17}},
		ServiceFilemq:          {{5670, 6}},
		ServiceFilenetCm:       {{32773, 6}, {32773, 17}},
		ServiceFilenetNch:      {{32770, 6}, {32770, 17}},
		ServiceFilenetObrok:    {{32777, 6}, {32777, 17}},
		ServiceFilenetPa:       {{32772, 6}, {32772, 17}},
		ServiceFilenetPch:      {{32775, 6}, {32775, 17}},
		ServiceFilenetPeior:    {{32776, 6}, {32776, 17}},
		ServiceFilenetPowsrm:   {{32767, 6}, {32767, 17}},
		ServiceFilenetRe:       {{32774, 6}, {32774, 17}},
		ServiceFilenetRmi:      {{32771, 6}, {32771, 17}},
		ServiceFilenetRpc:      {{32769, 6}, {32769, 17}},
		ServiceFilenetTms:      {{32768, 6}, {32768, 17}},
		ServiceFilesphere:      {{24242, 6}, {24242, 17}},
		ServiceFilexLport:      {{1887, 6}, {1887, 17}},
		ServiceFind:            {{24922, 6}, {24922, 17}},
		ServiceFindviatv:       {{3350, 6}, {3350, 17}},
		ServiceFinger:          {{79, 6}, {79, 17}},
		ServiceFinisar:         {{4682, 6}, {4682, 17}},
		ServiceFinleLm:         {{1784, 6}, {1784, 17}},
		ServiceFintrx:          {{3787, 6}, {3787, 17}},
		ServiceFioCmgmt:        {{9051, 6}},
		ServiceFioranoMsgsvc:   {{1856, 6}, {1856, 17}},
		ServiceFioranoRtrsvc:   {{1855, 6}, {1855, 17}},
		ServiceFirefox:         {{1689, 6}, {1689, 17}},
		ServiceFiremonrcc:      {{3192, 6}, {3192, 17}},
		ServiceFirepower:       {{2615, 6}, {2615, 17}},
		ServiceFirstDefense:    {{1232, 6}, {1232, 17}},
		ServiceFirstcall42:     {{2673, 6}, {2673, 17}},
		ServiceFis:             {{5912, 6}, {5912, 17}, {5912, 132}},
		ServiceFisaSvc:         {{7018, 6}},
		ServiceFiveacross:      {{1193, 6}, {1193, 17}},
		ServiceFjHdnet:         {{1717, 6}, {1717, 17}},
		ServiceFjappmgrbulk:    {{2510, 6}, {2510, 17}},
		ServiceFjcp:            {{3648, 6}, {3648, 17}},
		ServiceFjdmimgr:        {{9374, 6}, {9374, 17}},
		ServiceFjdocdist:       {{1848, 6}, {1848, 17}},
		ServiceFjhpjp:          {{3067, 6}, {3067, 17}},
		ServiceFjiclTepA:       {{1901, 6}, {1901, 17}},
		ServiceFjiclTepB:       {{1902, 6}, {1902, 17}},
		ServiceFjiclTepC:       {{1904, 6}, {1904, 17}},
		ServiceFjinvmgr:        {{9396, 6}, {9396, 17}},
		ServiceFjippolCnsl:     {{2749, 6}, {2749, 17}},
		ServiceFjippolPolsvr:   {{2748, 6}, {2748, 17}},
		ServiceFjippolPort1:    {{2750, 6}, {2750, 17}},
		ServiceFjippolPort2:    {{2751, 6}, {2751, 17}},
		ServiceFjippolSwrly:    {{2747, 6}, {2747, 17}},
		ServiceFjitsuappmgr:    {{2425, 6}, {2425, 17}},
		ServiceFjmpcm:          {{2975, 6}, {2975, 17}},
		ServiceFjmpjps:         {{1873, 6}, {1873, 17}},
		ServiceFjmpss:          {{2509, 6}, {2509, 17}},
		ServiceFjsvGssagt:      {{3035, 6}, {3035, 17}},
		ServiceFjsvmpor:        {{2946, 6}, {2946, 17}},
		ServiceFjswapsnp:       {{1874, 6}, {1874, 17}},
		ServiceFkspAudit:       {{3729, 6}, {3729, 17}},
		ServiceFlamencoProxy:   {{3210, 6}, {3210, 17}},
		ServiceFlashfiler:      {{24677, 6}, {24677, 17}},
		ServiceFlashmsg:        {{2884, 6}, {2884, 17}},
		ServiceFlcrs:           {{5638, 6}},
		ServiceFlexlm:          {{744, 6}, {744, 17}},
		ServiceFlirtmitmir:     {{3840, 6}, {3840, 17}},
		ServiceFlnSpx:          {{221, 6}, {221, 17}},
		ServiceFlorence:        {{1228, 6}, {1228, 17}},
		ServiceFlr_agent:       {{4901, 6}},
		ServiceFlukeserver:     {{2359, 6}, {2359, 17}},
		ServiceFly:             {{4396, 6}},
		ServiceFmp:             {{4745, 6}, {4745, 17}},
		ServiceFmproFdal:       {{2399, 6}, {2399, 17}},
		ServiceFmproInternal:   {{5003, 6}, {5003, 17}},
		ServiceFmproV6:         {{5013, 6}, {5013, 17}},
		ServiceFmsas:           {{16000, 6}},
		ServiceFmsascon:        {{16001, 6}},
		ServiceFmtp:            {{8500, 6}, {8500, 17}},
		ServiceFmwp:            {{5015, 6}},
		ServiceFnetRemoteUi:    {{1174, 6}, {1174, 17}},
		ServiceFodms:           {{7200, 6}, {7200, 17}},
		ServiceFoliocorp:       {{2242, 6}, {2242, 17}},
		ServiceFontService:     {{7100, 17}},
		ServiceForesyteClear:   {{5407, 6}, {5407, 17}},
		ServiceForesyteSec:     {{5408, 6}, {5408, 17}},
		ServiceFortisphereVm:   {{4084, 17}},
		ServiceFotogcad:        {{3878, 6}, {3878, 17}},
		ServiceFound:           {{4411, 6}},
		ServiceFpitp:           {{1045, 6}, {1045, 17}},
		ServiceFpoFns:          {{1066, 6}, {1066, 17}},
		ServiceFprams:          {{4122, 6}, {4122, 17}},
		ServiceFrcHp:           {{6704, 132}},
		ServiceFrcLp:           {{6706, 132}},
		ServiceFrcMp:           {{6705, 132}},
		ServiceFrcs:            {{4915, 6}},
		ServiceFreeciv:         {{5556, 6}, {5556, 17}},
		ServiceFreezexservice:  {{7726, 6}, {7726, 17}},
		ServiceFronet:          {{4130, 6}, {4130, 17}},
		ServiceFryeserv:        {{2788, 6}, {2788, 17}},
		ServiceFsAgent:         {{8042, 6}},
		ServiceFsMgmt:          {{8044, 6}},
		ServiceFsQos:           {{41111, 6}, {41111, 17}},
		ServiceFsRhSrv:         {{3488, 6}, {3488, 17}},
		ServiceFsServer:        {{8043, 6}},
		ServiceFscPort:         {{9217, 6}, {9217, 17}},
		ServiceFse:             {{7394, 6}, {7394, 17}},
		ServiceFsportmap:       {{4349, 6}, {4349, 17}},
		ServiceFsr:             {{7164, 6}, {7164, 17}},
		ServiceFtRole:          {{2429, 6}, {2429, 17}},
		ServiceFtp:             {{21, 6}, {21, 17}, {21, 132}},
		ServiceFtpAgent:        {{574, 6}, {574, 17}},
		ServiceFtpData:         {{20, 6}, {20, 17}, {20, 132}},
		ServiceFtps:            {{990, 6}, {990, 17}},
		ServiceFtpsData:        {{989, 6}, {989, 17}},
		ServiceFtranhc:         {{1105, 6}, {1105, 17}},
		ServiceFtrapid1:        {{1746, 6}, {1746, 17}},
		ServiceFtrapid2:        {{1747, 6}, {1747, 17}},
		ServiceFtsrv:           {{1359, 6}, {1359, 17}},
		ServiceFtsync:          {{4086, 17}},
		ServiceFud:             {{4201, 17}},
		ServiceFujitsuDev:      {{747, 6}, {747, 17}},
		ServiceFujitsuDtc:      {{1513, 6}, {1513, 17}},
		ServiceFujitsuDtcns:    {{1514, 6}, {1514, 17}},
		ServiceFujitsuMmpdc:    {{1657, 6}, {1657, 17}},
		ServiceFujitsuNeat:     {{3382, 6}, {3382, 17}},
		ServiceFunkDialout:     {{2909, 6}, {2909, 17}},
		ServiceFunkLicense:     {{1787, 6}, {1787, 17}},
		ServiceFunkLogger:      {{1786, 6}, {1786, 17}},
		ServiceFunkproxy:       {{1505, 6}, {1505, 17}},
		ServiceFuscript:        {{1144, 6}, {1144, 17}},
		ServiceFutrix:          {{2358, 6}, {2358, 17}},
		ServiceFxaengineNet:    {{3402, 6}, {3402, 17}},
		ServiceFxp:             {{286, 6}, {286, 17}},
		ServiceFxuptp:          {{19539, 6}, {19539, 17}},
		ServiceFyreMessanger:   {{2731, 6}, {2731, 17}},
		ServiceG2tag:           {{4110, 6}, {4110, 17}},
		ServiceG5m:             {{2732, 6}, {2732, 17}},
		ServiceGTalk:           {{2421, 6}, {2421, 17}},
		ServiceGacp:            {{190, 6}, {190, 17}},
		ServiceGadgetgate1way:  {{2677, 6}, {2677, 17}},
		ServiceGadgetgate2way:  {{2678, 6}, {2678, 17}},
		ServiceGadugadu:        {{8074, 6}, {8074, 17}},
		ServiceGaia:            {{4340, 6}, {4340, 17}},
		ServiceGalaxy4d:        {{8881, 6}},
		ServiceGalaxy7Data:     {{38201, 6}, {38201, 17}},
		ServiceGalaxyNetwork:   {{5235, 6}, {5235, 17}},
		ServiceGalaxyServer:    {{3051, 6}, {3051, 17}},
		ServiceGalileo:         {{3519, 17}},
		ServiceGalileolog:      {{3520, 6}, {3520, 17}},
		ServiceGamegen1:        {{1738, 6}, {1738, 17}},
		ServiceGamelobby:       {{2914, 6}, {2914, 17}},
		ServiceGamesmithPort:   {{31765, 6}, {31765, 17}},
		ServiceGammafetchsvr:   {{1859, 6}, {1859, 17}},
		ServiceGandalfLm:       {{1421, 6}, {1421, 17}},
		ServiceGap:             {{10800, 6}, {10800, 17}},
		ServiceGarcon:          {{999, 6}},
		ServiceGatLmd:          {{1708, 6}, {1708, 17}},
		ServiceGbjd816:         {{2626, 6}, {2626, 17}},
		ServiceGbmtStars:       {{3912, 6}, {3912, 17}},
		ServiceGbsSmp:          {{3762, 6}, {3762, 17}},
		ServiceGbsStp:          {{3484, 6}, {3484, 17}},
		ServiceGcConfig:        {{3436, 6}, {3436, 17}},
		ServiceGcmApp:          {{14145, 6}, {14145, 17}},
		ServiceGcmonitor:       {{2660, 6}, {2660, 17}},
		ServiceGcsp:            {{3429, 6}, {3429, 17}},
		ServiceGdbremote:       {{2159, 6}, {2159, 17}},
		ServiceGdoi:            {{848, 6}, {848, 17}},
		ServiceGdomap:          {{538, 6}, {538, 17}},
		ServiceGdpPort:         {{1997, 6}, {1997, 17}},
		ServiceGdriveSync:      {{37483, 6}},
		ServiceGdsAdppiwDb:     {{4550, 6}, {4550, 17}},
		ServiceGds_db:          {{3050, 6}, {3050, 17}},
		ServiceGearman:         {{4730, 6}, {4730, 17}},
		ServiceGeminiLm:        {{1590, 6}, {1590, 17}},
		ServiceGeneous:         {{3381, 6}, {3381, 17}},
		ServiceGenie:           {{402, 6}, {402, 17}},
		ServiceGenieLm:         {{1453, 6}, {1453, 17}},
		ServiceGenisarPort:     {{3475, 6}, {3475, 17}},
		ServiceGeniuslm:        {{3005, 6}, {3005, 17}},
		ServiceGenradMux:       {{176, 6}, {176, 17}},
		ServiceGenstat:         {{7283, 6}},
		ServiceGeognosis:       {{4326, 6}, {4326, 17}},
		ServiceGeognosisman:    {{4325, 6}, {4325, 17}},
		ServiceGeolocate:       {{3108, 6}, {3108, 17}},
		ServiceGerhcs:          {{4985, 6}},
		ServiceGf:              {{3530, 6}, {3530, 17}},
		ServiceGgfNcp:          {{678, 6}, {678, 17}},
		ServiceGgz:             {{5688, 6}, {5688, 17}},
		ServiceGhvpn:           {{12009, 17}},
		ServiceGigaPocket:      {{3862, 6}, {3862, 17}},
		ServiceGilatskysurfer:  {{3013, 6}, {3013, 17}},
		ServiceGinad:           {{634, 6}, {634, 17}},
		ServiceGiop:            {{2481, 6}, {2481, 17}},
		ServiceGiopSsl:         {{2482, 6}, {2482, 17}},
		ServiceGist:            {{270, 17}},
		ServiceGit:             {{9418, 6}, {9418, 17}},
		ServiceGlbp:            {{3222, 6}, {3222, 17}},
		ServiceGld:             {{6267, 6}},
		ServiceGlishd:          {{2833, 6}, {2833, 17}},
		ServiceGlobalCdPort:    {{3229, 6}, {3229, 17}},
		ServiceGlobalDtserv:    {{1774, 6}, {1774, 17}},
		ServiceGlobalWlink:     {{1909, 6}, {1909, 17}},
		ServiceGlobe:           {{2002, 6}, {2002, 17}},
		ServiceGlobecastId:     {{6109, 6}, {6109, 17}},
		ServiceGlobmsgsvc:      {{2519, 6}, {2519, 17}},
		ServiceGlogger:         {{2033, 6}, {2033, 17}},
		ServiceGlrpc:           {{9080, 6}, {9080, 17}},
		ServiceGmmp:            {{4183, 6}, {4183, 17}},
		ServiceGmrupdateserv:   {{1070, 6}, {1070, 17}},
		ServiceGntp:            {{23053, 6}},
		ServiceGnunet:          {{2086, 6}, {2086, 17}},
		ServiceGnutellaRtr:     {{6347, 6}, {6347, 17}},
		ServiceGnutellaSvc:     {{6346, 6}, {6346, 17}},
		ServiceGoLogin:         {{491, 6}, {491, 17}},
		ServiceGoaheadFldup:    {{3057, 6}, {3057, 17}},
		ServiceGoldleafLicman:  {{1401, 6}, {1401, 17}},
		ServiceGopher:          {{70, 6}, {70, 17}},
		ServiceGotodevice:      {{2217, 6}, {2217, 17}},
		ServiceGpfs:            {{1191, 6}, {1191, 17}},
		ServiceGppitnp:         {{103, 6}, {103, 17}},
		ServiceGprsCube:        {{3751, 6}, {3751, 17}},
		ServiceGprsData:        {{3386, 6}},
		ServiceGprsSig:         {{3386, 17}},
		ServiceGpsd:            {{2947, 6}, {2947, 17}},
		ServiceGradecam:        {{5117, 6}},
		ServiceGraphics:        {{41, 6}, {41, 17}},
		ServiceGrcmp:           {{9122, 6}},
		ServiceGrcp:            {{9123, 6}},
		ServiceGrfPort:         {{3757, 6}, {3757, 17}},
		ServiceGrid:            {{6268, 6}, {6268, 17}},
		ServiceGridAlt:         {{6269, 6}, {6269, 17}},
		ServiceGridgenElmd:     {{1542, 6}, {1542, 17}},
		ServiceGriffin:         {{2458, 6}, {2458, 17}},
		ServiceGris:            {{2135, 6}, {2135, 17}},
		ServiceGroove:          {{2492, 6}, {2492, 17}},
		ServiceGrooveDpp:       {{1211, 6}, {1211, 17}},
		ServiceGroupwise:       {{1677, 6}, {1677, 17}},
		ServiceGrubd:           {{3136, 6}, {3136, 17}},
		ServiceGsakmp:          {{3761, 6}, {3761, 17}},
		ServiceGsi:             {{1850, 6}, {1850, 17}},
		ServiceGsidcap:         {{22128, 6}},
		ServiceGsiftp:          {{2811, 6}, {2811, 17}},
		ServiceGsigatekeeper:   {{2119, 6}, {2119, 17}},
		ServiceGsmpAncp:        {{6068, 6}},
		ServiceGsms:            {{16002, 6}},
		ServiceGsmtap:          {{4729, 17}},
		ServiceGssHttp:         {{488, 6}, {488, 17}},
		ServiceGssXlicen:       {{128, 6}, {128, 17}},
		ServiceGtProxy:         {{9889, 6}, {9889, 17}},
		ServiceGtaua:           {{2186, 6}, {2186, 17}},
		ServiceGteSamp:         {{2643, 6}, {2643, 17}},
		ServiceGtegscLm:        {{1452, 6}, {1452, 17}},
		ServiceGtpControl:      {{2123, 6}, {2123, 17}},
		ServiceGtpUser:         {{2152, 6}, {2152, 17}},
		ServiceGtrackNe:        {{3592, 6}, {3592, 17}},
		ServiceGtrackServer:    {{3591, 6}, {3591, 17}},
		ServiceGuibase:         {{9321, 6}, {9321, 17}},
		ServiceGuttersnex:      {{35356, 6}},
		ServiceGvPf:            {{18262, 6}, {18262, 17}},
		ServiceGvUs:            {{1369, 6}, {1369, 17}},
		ServiceGvcp:            {{3956, 6}, {3956, 17}},
		ServiceGw:              {{3010, 6}},
		ServiceGwAsv:           {{4842, 6}, {4842, 17}},
		ServiceGwCallPort:      {{3745, 6}, {3745, 17}},
		ServiceGwLog:           {{4844, 6}, {4844, 17}},
		ServiceGwenSonya:       {{2778, 6}, {2778, 17}},
		ServiceGwha:            {{1383, 6}, {1383, 17}},
		ServiceGxsDataPort:     {{2073, 6}, {2073, 17}},
		ServiceGxtelmd:         {{2356, 6}, {2356, 17}},
		ServiceH2250AnnexG:     {{2099, 6}, {2099, 17}},
		ServiceH248Binary:      {{2945, 6}, {2945, 17}, {2945, 132}},
		ServiceH263Video:       {{2979, 6}, {2979, 17}},
		ServiceH2gfW2m:         {{3179, 6}, {3179, 17}},
		ServiceH323callsigalt:  {{11720, 6}, {11720, 17}},
		ServiceH323gatedisc:    {{1718, 6}, {1718, 17}},
		ServiceH323gatestat:    {{1719, 6}, {1719, 17}},
		ServiceH323hostcall:    {{1720, 6}, {1720, 17}},
		ServiceH323hostcallsc:  {{1300, 6}, {1300, 17}},
		ServiceHaCluster:       {{694, 6}, {694, 17}},
		ServiceHaclCfg:         {{5302, 6}, {5302, 17}},
		ServiceHaclGs:          {{5301, 6}, {5301, 17}},
		ServiceHaclHb:          {{5300, 6}, {5300, 17}},
		ServiceHaclLocal:       {{5304, 6}, {5304, 17}},
		ServiceHaclMonitor:     {{3542, 6}, {3542, 17}},
		ServiceHaclPoll:        {{5315, 6}, {5315, 17}},
		ServiceHaclProbe:       {{5303, 6}, {5303, 17}},
		ServiceHaclQs:          {{1238, 6}, {1238, 17}},
		ServiceHaclTest:        {{5305, 6}, {5305, 17}},
		ServiceHagelDump:       {{3036, 6}, {3036, 17}},
		ServiceHaipeDiscover:   {{3623, 6}, {3623, 17}},
		ServiceHaipeOtnk:       {{3769, 6}, {3769, 17}},
		ServiceHao:             {{2245, 6}, {2245, 17}},
		ServiceHap:             {{661, 6}, {661, 17}},
		ServiceHarp:            {{1816, 6}, {1816, 17}},
		ServiceHartIp:          {{5094, 6}, {5094, 17}},
		ServiceHassle:          {{375, 6}, {375, 17}},
		ServiceHawk:            {{7630, 6}},
		ServiceHbEngine:        {{1703, 6}, {1703, 17}},
		ServiceHbci:            {{3000, 6}, {3000, 17}},
		ServiceHcpWismar:       {{686, 6}, {686, 17}},
		ServiceHdap:            {{263, 6}, {263, 17}},
		ServiceHdeLcesrvr1:     {{14936, 6}, {14936, 17}},
		ServiceHdeLcesrvr2:     {{14937, 6}, {14937, 17}},
		ServiceHdlSrv:          {{2641, 6}, {2641, 17}},
		ServiceHealthPolling:   {{1161, 6}, {1161, 17}},
		ServiceHealthTrap:      {{1162, 6}, {1162, 17}},
		ServiceHealthd:         {{1281, 6}, {1281, 17}},
		ServiceHeartbeat:       {{3740, 6}, {3740, 17}},
		ServiceHeathview:       {{35000, 6}},
		ServiceHecmtlDb:        {{1551, 6}, {1551, 17}},
		ServiceHelix:           {{10860, 6}, {10860, 17}},
		ServiceHello:           {{1789, 6}, {1789, 17}},
		ServiceHelloPort:       {{652, 6}, {652, 17}},
		ServiceHems:            {{151, 6}, {151, 17}},
		ServiceHereLm:          {{1409, 6}, {1409, 17}},
		ServiceHermes:          {{1248, 6}, {1248, 17}},
		ServiceHerodotusNet:    {{3921, 6}, {3921, 17}},
		ServiceHexarc:          {{7397, 6}, {7397, 17}},
		ServiceHfcs:            {{4900, 6}, {4900, 17}},
		ServiceHfcsManager:     {{4999, 6}, {4999, 17}},
		ServiceHhbGateway:      {{1136, 6}, {1136, 17}},
		ServiceHhbHandheld:     {{4148, 6}, {4148, 17}},
		ServiceHicp:            {{3250, 6}, {3250, 17}},
		ServiceHid:             {{24322, 17}},
		ServiceHighCriteria:    {{2467, 6}, {2467, 17}},
		ServiceHillrserv:       {{4117, 6}, {4117, 17}},
		ServiceHinp:            {{9954, 6}},
		ServiceHipNatT:         {{10500, 17}},
		ServiceHiperscanId:     {{8293, 6}},
		ServiceHiq:             {{1410, 6}, {1410, 17}},
		ServiceHislip:          {{4880, 6}},
		ServiceHivep:           {{12172, 6}, {12172, 17}},
		ServiceHivestor:        {{4884, 6}, {4884, 17}},
		ServiceHksLm:           {{1722, 6}, {1722, 17}},
		ServiceHl7:             {{2575, 6}, {2575, 17}},
		ServiceHlibmgr:         {{3634, 6}, {3634, 17}},
		ServiceHlserver:        {{3047, 6}, {3047, 17}},
		ServiceHmmpInd:         {{612, 6}, {612, 17}},
		ServiceHmmpOp:          {{613, 6}, {613, 17}},
		ServiceHnm:             {{6791, 6}, {6791, 17}},
		ServiceHnmp:            {{6790, 6}, {6790, 17}},
		ServiceHomeportalWeb:   {{3941, 6}, {3941, 17}},
		ServiceHomesteadglory:  {{2597, 6}, {2597, 17}},
		ServiceHonyaku:         {{2744, 6}, {2744, 17}},
		ServiceHostmon:         {{5355, 6}, {5355, 17}},
		ServiceHostname:        {{101, 6}, {101, 17}},
		ServiceHotuChat:        {{3449, 6}, {3449, 17}},
		ServiceHoudiniLm:       {{1715, 6}, {1715, 17}},
		ServiceHouston:         {{4041, 6}, {4041, 17}},
		ServiceHp3000Telnet:    {{2564, 6}, {2564, 17}},
		ServiceHpAlarmMgr:      {{383, 6}, {383, 17}},
		ServiceHpClic:          {{3384, 6}, {3384, 17}},
		ServiceHpCollector:     {{381, 6}, {381, 17}},
		ServiceHpDataprotect:   {{3612, 6}, {3612, 17}},
		ServiceHpDeviceDisc:    {{3329, 6}, {3329, 17}},
		ServiceHpHcip:          {{1782, 6}, {1782, 17}},
		ServiceHpHcipGwy:       {{1803, 6}, {1803, 17}},
		ServiceHpManagedNode:   {{382, 6}, {382, 17}},
		ServiceHpNnmData:       {{2690, 6}, {2690, 17}},
		ServiceHpPdlDatastr:    {{9100, 17}},
		ServiceHpPxpib:         {{3101, 6}, {3101, 17}},
		ServiceHpSanMgmt:       {{3037, 6}, {3037, 17}},
		ServiceHpSca:           {{19411, 6}, {19411, 17}},
		ServiceHpSci:           {{1299, 6}, {1299, 17}},
		ServiceHpSco:           {{19410, 6}, {19410, 17}},
		ServiceHpServer:        {{5225, 6}, {5225, 17}},
		ServiceHpSessmon:       {{19412, 6}, {19412, 17}},
		ServiceHpStatus:        {{5226, 6}, {5226, 17}},
		ServiceHpWebadmin:      {{1188, 6}, {1188, 17}},
		ServiceHpWebqosdb:      {{1877, 6}, {1877, 17}},
		ServiceHpbladems:       {{5316, 6}},
		ServiceHpdevms:         {{5317, 6}},
		ServiceHpidsadmin:      {{2984, 6}, {2984, 17}},
		ServiceHpidsagent:      {{2985, 6}, {2985, 17}},
		ServiceHpiod:           {{2208, 6}, {2208, 17}},
		ServiceHpocbus:         {{2206, 6}, {2206, 17}},
		ServiceHpomsCiLstn:     {{5403, 6}, {5403, 17}},
		ServiceHpomsDpsLstn:    {{5404, 6}, {5404, 17}},
		ServiceHpppssvr:        {{2448, 6}, {2448, 17}},
		ServiceHppronetman:     {{3908, 6}, {3908, 17}},
		ServiceHpssNdapi:       {{1217, 6}, {1217, 17}},
		ServiceHpssd:           {{2207, 6}, {2207, 17}},
		ServiceHpssmgmt:        {{4484, 6}, {4484, 17}},
		ServiceHpstgmgr:        {{2600, 6}, {2600, 17}},
		ServiceHpstgmgr2:       {{2715, 6}, {2715, 17}},
		ServiceHpvirtctrl:      {{5224, 6}, {5224, 17}},
		ServiceHpvirtgrp:       {{5223, 6}, {5223, 17}},
		ServiceHpvmmagent:      {{1125, 6}, {1125, 17}},
		ServiceHpvmmcontrol:    {{1124, 6}, {1124, 17}},
		ServiceHpvmmdata:       {{1126, 6}, {1126, 17}},
		ServiceHpvroom:         {{5228, 6}},
		ServiceHrdNcs:          {{6324, 6}},
		ServiceHrdNsDisc:       {{6324, 17}},
		ServiceHriPort:         {{3439, 6}, {3439, 17}},
		ServiceHrpdIthAtAn:     {{4592, 17}},
		ServiceHsPort:          {{2570, 6}, {2570, 17}},
		ServiceHslStorm:        {{2113, 6}, {2113, 17}},
		ServiceHsrp:            {{1985, 6}, {1985, 17}},
		ServiceHsrpv6:          {{2029, 6}, {2029, 17}},
		ServiceHtcp:            {{4827, 6}, {4827, 17}},
		ServiceHtrust:          {{5628, 6}, {5628, 17}},
		ServiceHttp:            {{80, 6}, {80, 17}, {80, 132}},
		ServiceHttpMgmt:        {{280, 6}, {280, 17}},
		ServiceHttpRpcEpmap:    {{593, 6}, {593, 17}},
		ServiceHttpWmap:        {{8990, 6}, {8990, 17}},
		ServiceHttps:           {{443, 6}, {443, 17}, {443, 132}},
		ServiceHttpsWmap:       {{8991, 6}, {8991, 17}},
		ServiceHttpx:           {{4180, 6}, {4180, 17}},
		ServiceHtuilsrv:        {{5023, 6}, {5023, 17}},
		ServiceHubOpenNet:      {{8313, 6}},
		ServiceHughesAp:        {{5105, 17}},
		ServiceHusky:           {{1310, 6}, {1310, 17}},
		ServiceHybrid:          {{1424, 6}, {1424, 17}},
		ServiceHybridPop:       {{473, 6}, {473, 17}},
		ServiceHydap:           {{15000, 6}, {15000, 17}},
		ServiceHydra:           {{2374, 6}},
		ServiceHylafax:         {{4559, 6}, {4559, 17}},
		ServiceHyperG:          {{418, 6}, {418, 17}},
		ServiceHypercubeLm:     {{1577, 6}, {1577, 17}},
		ServiceHyperip:         {{3919, 6}, {3919, 17}},
		ServiceHyperscsiPort:   {{5674, 6}, {5674, 17}},
		ServiceHyperwaveIsp:    {{692, 6}, {692, 17}},
		ServiceI3Sessionmgr:    {{3952, 6}, {3952, 17}},
		ServiceINet2000Npr:     {{5069, 6}, {5069, 17}},
		ServiceIRAPP:           {{4073, 6}, {4073, 17}},
		ServiceIZipqd:          {{13160, 6}, {13160, 17}},
		ServiceIad1:            {{1030, 6}, {1030, 17}},
		ServiceIad2:            {{1031, 6}, {1031, 17}},
		ServiceIad3:            {{1032, 6}, {1032, 17}},
		ServiceIadt:            {{4169, 6}},
		ServiceIadtDisc:        {{4169, 17}},
		ServiceIadtTls:         {{9614, 6}},
		ServiceIafdbase:        {{480, 6}, {480, 17}},
		ServiceIafserver:       {{479, 6}, {479, 17}},
		ServiceIanywhereDbns:   {{3968, 6}, {3968, 17}},
		ServiceIapp:            {{2313, 6}, {2313, 17}},
		ServiceIasAdmind:       {{2141, 6}, {2141, 17}},
		ServiceIasAuth:         {{2139, 6}, {2139, 17}},
		ServiceIasNeighbor:     {{4596, 6}, {4596, 17}},
		ServiceIasPaging:       {{4595, 6}, {4595, 17}},
		ServiceIasReg:          {{2140, 6}, {2140, 17}},
		ServiceIasSession:      {{4594, 6}, {4594, 17}},
		ServiceIascontrol:      {{1157, 6}, {1157, 17}},
		ServiceIascontrolOms:   {{1156, 6}, {1156, 17}},
		ServiceIasd:            {{432, 6}, {432, 17}},
		ServiceIatpHighpri:     {{6998, 6}, {6998, 17}},
		ServiceIatpNormalpri:   {{6999, 6}, {6999, 17}},
		ServiceIax:             {{4569, 6}, {4569, 17}},
		ServiceIbar:            {{5784, 17}},
		ServiceIberiagames:     {{1726, 6}, {1726, 17}},
		ServiceIbm3494:         {{3494, 6}, {3494, 17}},
		ServiceIbmAbtact:       {{1586, 6}, {1586, 17}},
		ServiceIbmApp:          {{385, 6}, {385, 17}},
		ServiceIbmCics:         {{1435, 6}, {1435, 17}},
		ServiceIbmDb2:          {{523, 6}, {523, 17}},
		ServiceIbmDialOut:      {{3267, 6}, {3267, 17}},
		ServiceIbmDiradm:       {{3538, 6}, {3538, 17}},
		ServiceIbmDiradmSsl:    {{3539, 6}, {3539, 17}},
		ServiceIbmDt2:          {{1792, 6}, {1792, 17}},
		ServiceIbmMgr:          {{3801, 6}, {3801, 17}},
		ServiceIbmMqisdp:       {{1883, 6}, {1883, 17}},
		ServiceIbmMqseries:     {{1414, 6}, {1414, 17}},
		ServiceIbmMqseries2:    {{1881, 6}, {1881, 17}},
		ServiceIbmPps:          {{1376, 6}, {1376, 17}},
		ServiceIbmRes:          {{1405, 6}, {1405, 17}},
		ServiceIbmRsyscon:      {{9085, 6}, {9085, 17}},
		ServiceIbmSsd:          {{1260, 6}, {1260, 17}},
		ServiceIbm_wrless_lan:  {{1461, 6}, {1461, 17}},
		ServiceIbp:             {{2572, 6}, {2572, 17}},
		ServiceIbprotocol:      {{6714, 6}, {6714, 17}},
		ServiceIbridgeData:     {{2275, 6}, {2275, 17}},
		ServiceIbridgeMgmt:     {{2276, 6}, {2276, 17}},
		ServiceIbus:            {{8733, 6}, {8733, 17}},
		ServiceIca:             {{1494, 6}, {1494, 17}},
		ServiceIcabrowser:      {{1604, 6}, {1604, 17}},
		ServiceIcadEl:          {{425, 6}, {425, 17}},
		ServiceIcap:            {{1344, 6}, {1344, 17}},
		ServiceIccrushmore:     {{6850, 6}, {6850, 17}},
		ServiceIceLocation:     {{4061, 6}, {4061, 17}},
		ServiceIceRouter:       {{4063, 6}, {4063, 17}},
		ServiceIceSlocation:    {{4062, 6}, {4062, 17}},
		ServiceIceSrouter:      {{4064, 6}, {4064, 17}},
		ServiceIceedcp_rx:      {{31949, 6}, {31949, 17}},
		ServiceIceedcp_tx:      {{31948, 6}, {31948, 17}},
		ServiceIcgBridge:       {{2063, 6}, {2063, 17}},
		ServiceIcgIprelay:      {{2064, 6}, {2064, 17}},
		ServiceIcgSwp:          {{2062, 6}, {2062, 17}},
		ServiceIci:             {{2200, 6}, {2200, 17}},
		ServiceIclTwobase1:     {{25000, 6}, {25000, 17}},
		ServiceIclTwobase10:    {{25009, 6}, {25009, 17}},
		ServiceIclTwobase2:     {{25001, 6}, {25001, 17}},
		ServiceIclTwobase3:     {{25002, 6}, {25002, 17}},
		ServiceIclTwobase4:     {{25003, 6}, {25003, 17}},
		ServiceIclTwobase5:     {{25004, 6}, {25004, 17}},
		ServiceIclTwobase6:     {{25005, 6}, {25005, 17}},
		ServiceIclTwobase7:     {{25006, 6}, {25006, 17}},
		ServiceIclTwobase8:     {{25007, 6}, {25007, 17}},
		ServiceIclTwobase9:     {{25008, 6}, {25008, 17}},
		ServiceIclcnetLocate:   {{886, 6}, {886, 17}},
		ServiceIclcnet_svinfo:  {{887, 6}, {887, 17}},
		ServiceIclid:           {{18242, 6}},
		ServiceIclpvDm:         {{1389, 6}, {1389, 17}},
		ServiceIclpvNlc:        {{1394, 6}, {1394, 17}},
		ServiceIclpvNls:        {{1393, 6}, {1393, 17}},
		ServiceIclpvPm:         {{1392, 6}, {1392, 17}},
		ServiceIclpvSas:        {{1391, 6}, {1391, 17}},
		ServiceIclpvSc:         {{1390, 6}, {1390, 17}},
		ServiceIclpvWsm:        {{1395, 6}, {1395, 17}},
		ServiceIcmpd:           {{5813, 6}, {5813, 17}},
		ServiceIcms:            {{4486, 6}, {4486, 17}},
		ServiceIconDiscover:    {{2799, 6}, {2799, 17}},
		ServiceIconp:           {{3972, 6}, {3972, 17}},
		ServiceIconstructsrv:   {{6077, 6}},
		ServiceIcp:             {{1112, 6}, {1112, 17}},
		ServiceIcpp:            {{14142, 6}, {14142, 17}},
		ServiceIcpv2:           {{3130, 6}, {3130, 17}},
		ServiceIcs:             {{5639, 6}},
		ServiceIcshostsvc:      {{4553, 6}},
		ServiceIcslap:          {{2869, 6}, {2869, 17}},
		ServiceIdaDiscover1:    {{5741, 6}, {5741, 17}},
		ServiceIdaDiscover2:    {{5742, 6}, {5742, 17}},
		ServiceIdac:            {{3881, 6}, {3881, 17}},
		ServiceIdcp:            {{2326, 6}, {2326, 17}},
		ServiceIdeafarmDoor:    {{902, 6}, {902, 17}},
		ServiceIdeafarmPanic:   {{903, 6}, {903, 17}},
		ServiceIdeesrv:         {{2337, 6}, {2337, 17}},
		ServiceIdenRalp:        {{1725, 6}, {1725, 17}},
		ServiceIdentify:        {{2987, 6}, {2987, 17}},
		ServiceIdfp:            {{549, 6}, {549, 17}},
		ServiceIdig_mux:        {{4152, 6}, {4152, 17}},
		ServiceIdmaps:          {{1884, 6}, {1884, 17}},
		ServiceIdmgratm:        {{32896, 6}, {32896, 17}},
		ServiceIdonixMetanet:   {{2112, 6}, {2112, 17}},
		ServiceIdotdist:        {{2590, 6}, {2590, 17}},
		ServiceIdp:             {{4067, 6}, {4067, 17}},
		ServiceIdpInfotrieve:   {{2966, 6}, {2966, 17}},
		ServiceIdps:            {{3797, 6}, {3797, 17}},
		ServiceIdrs:            {{2995, 6}, {2995, 17}},
		ServiceIdtp:            {{25604, 6}},
		ServiceIdwareRouter:    {{2079, 6}, {2079, 17}},
		ServiceIdxp:            {{603, 6}, {603, 17}},
		ServiceIec104:          {{2404, 6}, {2404, 17}},
		ServiceIec104Sec:       {{19998, 6}},
		ServiceIeeQfx:          {{1284, 6}, {1284, 17}},
		ServiceIeeeMih:         {{4551, 6}, {4551, 17}},
		ServiceIeeeMms:         {{651, 6}, {651, 17}},
		ServiceIeeeMmsSsl:      {{695, 6}, {695, 17}},
		ServiceIesLm:           {{1443, 6}, {1443, 17}},
		ServiceIfcpPort:        {{3420, 6}, {3420, 17}},
		ServiceIfe_icorp:       {{5165, 6}, {5165, 17}},
		ServiceIforProtocol:    {{1515, 6}, {1515, 17}},
		ServiceIfsfHbPort:      {{3486, 6}, {3486, 17}},
		ServiceIfsp:            {{4744, 6}, {4744, 17}},
		ServiceIgcp:            {{2801, 6}, {2801, 17}},
		ServiceIgiLm:           {{1404, 6}, {1404, 17}},
		ServiceIgmpv3lite:      {{465, 17}},
		ServiceIgoIncognito:    {{4100, 6}, {4100, 17}},
		ServiceIgrid:           {{19000, 6}, {19000, 17}},
		ServiceIgrs:            {{3880, 6}, {3880, 17}},
		ServiceIiAdmin:         {{3006, 6}, {3006, 17}},
		ServiceIims:            {{4800, 6}, {4800, 17}},
		ServiceIiop:            {{535, 6}, {535, 17}},
		ServiceIiwPort:         {{3186, 6}, {3186, 17}},
		ServiceIld:             {{24321, 6}, {24321, 17}},
		ServiceIll:             {{1611, 6}, {1611, 17}},
		ServiceIlss:            {{4802, 6}, {4802, 17}},
		ServiceImagepump:       {{27345, 6}, {27345, 17}},
		ServiceImagequery:      {{2239, 6}, {2239, 17}},
		ServiceImap:            {{143, 6}, {143, 17}},
		ServiceImap3:           {{220, 6}, {220, 17}},
		ServiceImaps:           {{993, 6}, {993, 17}},
		ServiceImdocsvc:        {{2637, 6}, {2637, 17}},
		ServiceImgames:         {{1077, 6}, {1077, 17}},
		ServiceImink:           {{8615, 6}},
		ServiceImip:            {{11319, 6}, {11319, 17}},
		ServiceImipChannels:    {{11320, 6}, {11320, 17}},
		ServiceImmedianetBcn:   {{3657, 6}, {3657, 17}},
		ServiceImoguiaPort:     {{3907, 6}, {3907, 17}},
		ServiceImpera:          {{1710, 6}, {1710, 17}},
		ServiceImprs:           {{3164, 6}, {3164, 17}},
		ServiceImqbrokerd:      {{7676, 6}, {7676, 17}},
		ServiceImqstomp:        {{7672, 6}},
		ServiceImqstomps:       {{7673, 6}},
		ServiceImqtunnel:       {{7675, 6}, {7675, 17}},
		ServiceImqtunnels:      {{7674, 6}, {7674, 17}},
		ServiceImsldoc:         {{2035, 6}, {2035, 17}},
		ServiceImsp:            {{406, 6}, {406, 17}},
		ServiceImtcMap:         {{2202, 6}, {2202, 17}},
		ServiceImtcMcs:         {{1503, 6}, {1503, 17}},
		ServiceImyx:            {{1143, 6}, {1143, 17}},
		ServiceInbusiness:      {{244, 6}, {244, 17}},
		ServiceIncognitorv:     {{3139, 6}, {3139, 17}},
		ServiceIncp:            {{2932, 6}, {2932, 17}},
		ServiceIndexNet:        {{2970, 6}, {2970, 17}},
		ServiceIndexPcWb:       {{2127, 6}, {2127, 17}},
		ServiceIndi:            {{7624, 6}, {7624, 17}},
		ServiceIndigoServer:    {{1176, 6}, {1176, 17}},
		ServiceIndigoVbcp:      {{8131, 6}, {8131, 17}},
		ServiceIndigoVrmi:      {{8130, 6}, {8130, 17}},
		ServiceIndura:          {{3156, 6}, {3156, 17}},
		ServiceIndxDds:         {{2454, 6}, {2454, 17}},
		ServiceIndy:            {{5963, 6}, {5963, 17}},
		ServiceInfiniswitchcl:  {{3602, 6}, {3602, 17}},
		ServiceInfluence:       {{3345, 6}, {3345, 17}},
		ServiceInfobright:      {{5029, 6}, {5029, 17}},
		ServiceInfocrypt:       {{2233, 6}, {2233, 17}},
		ServiceInfoexch:        {{3667, 6}, {3667, 17}},
		ServiceInfolibria:      {{2319, 6}, {2319, 17}},
		ServiceInfoman:         {{1451, 6}, {1451, 17}},
		ServiceInfomover:       {{2854, 6}, {2854, 17}},
		ServiceInformatikLm:    {{1428, 6}, {1428, 17}},
		ServiceInformer:        {{3856, 6}, {3856, 17}},
		ServiceInfoseek:        {{414, 6}, {414, 17}},
		ServiceInfotos:         {{18881, 6}, {18881, 17}},
		ServiceInfowave:        {{2082, 6}, {2082, 17}},
		ServiceIngresNet:       {{134, 6}, {134, 17}},
		ServiceIngreslock:      {{1524, 6}, {1524, 17}},
		ServiceIninmessaging:   {{5597, 6}, {5597, 17}},
		ServiceIniservePort:    {{3560, 6}, {3560, 17}},
		ServiceInitlsmsad:      {{2793, 6}, {2793, 17}},
		ServiceInnosys:         {{1412, 6}, {1412, 17}},
		ServiceInnosysAcl:      {{1413, 6}, {1413, 17}},
		ServiceInovaIpDisco:    {{2716, 6}, {2716, 17}},
		ServiceInovaport1:      {{23000, 6}, {23000, 17}},
		ServiceInovaport2:      {{23001, 6}, {23001, 17}},
		ServiceInovaport3:      {{23002, 6}, {23002, 17}},
		ServiceInovaport4:      {{23003, 6}, {23003, 17}},
		ServiceInovaport5:      {{23004, 6}, {23004, 17}},
		ServiceInovaport6:      {{23005, 6}, {23005, 17}},
		ServiceInsis:           {{9215, 6}, {9215, 17}},
		ServiceInsituConf:      {{1490, 6}, {1490, 17}},
		ServiceInspect:         {{1602, 6}, {1602, 17}},
		ServiceInstDiscovery:   {{4878, 17}},
		ServiceInstantia:       {{1240, 6}, {1240, 17}},
		ServiceInstl_bootc:     {{1068, 6}, {1068, 17}},
		ServiceInstl_boots:     {{1067, 6}, {1067, 17}},
		ServiceIntRcvCntrl:     {{3603, 6}, {3603, 17}},
		ServiceIntecomPs1:      {{5056, 6}, {5056, 17}},
		ServiceIntecomPs2:      {{5057, 6}, {5057, 17}},
		ServiceIntecourier:     {{495, 6}, {495, 17}},
		ServiceIntegraSme:      {{484, 6}, {484, 17}},
		ServiceIntegral:        {{3459, 6}, {3459, 17}},
		ServiceIntegriusStp:    {{17234, 6}, {17234, 17}},
		ServiceIntelRciMp:      {{16991, 6}, {16991, 17}},
		ServiceIntel_rci:       {{24386, 6}, {24386, 17}},
		ServiceIntellistorLm:   {{1539, 6}, {1539, 17}},
		ServiceIntelsync:       {{3692, 6}, {3692, 17}},
		ServiceInteract:        {{4052, 6}, {4052, 17}},
		ServiceInteractionweb:  {{3508, 6}, {3508, 17}},
		ServiceInterbase:       {{2041, 6}, {2041, 17}},
		ServiceInterhdl_elmd:   {{1454, 6}, {1454, 17}},
		ServiceInterintelli:    {{2633, 6}, {2633, 17}},
		ServiceIntermapper:     {{8181, 6}},
		ServiceInterpathpanel:  {{2652, 6}, {2652, 17}},
		ServiceIntersan:        {{1331, 6}, {1331, 17}},
		ServiceInterserver:     {{3060, 6}, {3060, 17}},
		ServiceIntersysCache:   {{1972, 6}, {1972, 17}},
		ServiceInterwise:       {{7778, 6}, {7778, 17}},
		ServiceInterworld:      {{3548, 6}, {3548, 17}},
		ServiceIntraintra:      {{3202, 6}, {3202, 17}},
		ServiceIntrastar:       {{1907, 6}, {1907, 17}},
		ServiceIntrepidSsl:     {{11751, 6}, {11751, 17}},
		ServiceIntrinsa:        {{503, 6}, {503, 17}},
		ServiceIntuEcClient:    {{8021, 6}, {8021, 17}},
		ServiceIntuEcSvcdisc:   {{8020, 6}, {8020, 17}},
		ServiceIntuitiveEdge:   {{1355, 6}, {1355, 17}},
		ServiceIntv:            {{1585, 6}, {1585, 17}},
		ServiceInvision:        {{1641, 6}, {1641, 17}},
		ServiceInvisionAg:      {{45054, 6}, {45054, 17}},
		ServiceInvokator:       {{2006, 6}},
		ServiceIoDistData:      {{5728, 6}},
		ServiceIoDistGroup:     {{5728, 17}},
		ServiceIocSeaLm:        {{1579, 6}, {1579, 17}},
		ServiceIonixnetmon:     {{7410, 6}, {7410, 17}},
		ServiceIop:             {{2055, 6}, {2055, 17}},
		ServiceIpBlf:           {{2088, 6}, {2088, 17}},
		ServiceIpProvision:     {{43190, 6}, {43190, 17}},
		ServiceIpQsig:          {{4029, 6}, {4029, 17}},
		ServiceIpass:           {{2549, 6}, {2549, 17}},
		ServiceIpcd:            {{576, 6}, {576, 17}},
		ServiceIpcd3:           {{1209, 6}, {1209, 17}},
		ServiceIpcore:          {{2215, 6}, {2215, 17}},
		ServiceIpcsCommand:     {{3743, 6}, {3743, 17}},
		ServiceIpcserver:       {{600, 6}, {600, 17}},
		ServiceIpdcesgbs:       {{9214, 6}, {9214, 17}},
		ServiceIpdd:            {{578, 6}, {578, 17}},
		ServiceIpdrSp:          {{4737, 6}, {4737, 17}},
		ServiceIpdtpPort:       {{20202, 6}, {20202, 17}},
		ServiceIpether232port:  {{3497, 6}, {3497, 17}},
		ServiceIpfix:           {{4739, 6}, {4739, 17}, {4739, 132}},
		ServiceIpfixs:          {{4740, 6}, {4740, 132}, {4740, 17}},
		ServiceIpfltbcst:       {{4068, 6}, {4068, 17}},
		ServiceIphPolicyAdm:    {{2963, 6}, {2963, 17}},
		ServiceIphPolicyCli:    {{2962, 6}, {2962, 17}},
		ServiceIposplanet:      {{7031, 6}},
		ServiceIpp:             {{631, 6}, {631, 17}},
		ServiceIprDglt:         {{3678, 6}, {3678, 17}},
		ServiceIpsecNatT:       {{4500, 6}, {4500, 17}},
		ServiceIptAnriAnri:     {{4593, 6}, {4593, 17}},
		ServiceIpulseIcs:       {{20222, 6}, {20222, 17}},
		ServiceIpx:             {{213, 6}, {213, 17}},
		ServiceIqnetPort:       {{3804, 6}, {3804, 17}},
		ServiceIqobject:        {{48619, 6}, {48619, 17}},
		ServiceIqrm:            {{10117, 6}, {10117, 17}},
		ServiceIqserver:        {{2527, 6}, {2527, 17}},
		ServiceIque:            {{18769, 6}, {18769, 17}},
		ServiceIracinghelper:   {{32034, 6}, {32034, 17}},
		ServiceIrc:             {{194, 6}, {194, 17}},
		ServiceIrcServ:         {{529, 6}, {529, 17}},
		ServiceIrcu:            {{6665, 6}, {6665, 17}},
		ServiceIrcu2:           {{6666, 6}, {6666, 17}},
		ServiceIrcu3:           {{6667, 6}, {6667, 17}},
		ServiceIrcu4:           {{6668, 6}, {6668, 17}},
		ServiceIrcu5:           {{6669, 6}, {6669, 17}},
		ServiceIrdgPost:        {{2632, 6}, {2632, 17}},
		ServiceIrdmi:           {{8000, 6}, {8000, 17}},
		ServiceIrdmi2:          {{7999, 6}, {7999, 17}},
		ServiceIrisBeep:        {{702, 6}, {702, 17}},
		ServiceIrisLwz:         {{715, 6}, {715, 17}},
		ServiceIrisXpc:         {{713, 6}, {713, 17}},
		ServiceIrisXpcs:        {{714, 6}, {714, 17}},
		ServiceIrisa:           {{11000, 6}, {11000, 17}},
		ServiceIronmail:        {{3206, 6}, {3206, 17}},
		ServiceIronstorm:       {{3504, 6}, {3504, 17}},
		ServiceIrtrans:         {{21000, 6}, {21000, 17}},
		ServiceIs99c:           {{379, 6}, {379, 17}},
		ServiceIs99s:           {{380, 6}, {380, 17}},
		ServiceIsakmp:          {{500, 6}, {500, 17}},
		ServiceIsbconference1:  {{1244, 6}, {1244, 17}},
		ServiceIsbconference2:  {{1245, 6}, {1245, 17}},
		ServiceIscape:          {{5047, 17}},
		ServiceIschat:          {{1336, 6}, {1336, 17}},
		ServiceIscsi:           {{860, 6}, {860, 17}},
		ServiceIscsiTarget:     {{3260, 6}, {3260, 17}},
		ServiceIsdc:            {{1636, 6}, {1636, 17}},
		ServiceIsdd:            {{8148, 6}, {8148, 17}},
		ServiceIsdnlog:         {{20011, 6}, {20011, 17}},
		ServiceIsgUdaServer:    {{2551, 6}, {2551, 17}},
		ServiceIsiGl:           {{55, 6}, {55, 17}},
		ServiceIsiIrp:          {{3226, 6}, {3226, 17}},
		ServiceIsis:            {{2042, 6}, {2042, 17}},
		ServiceIsisAm:          {{1642, 6}, {1642, 17}},
		ServiceIsisAmbc:        {{1643, 6}, {1643, 17}},
		ServiceIsisBcast:       {{2043, 6}, {2043, 17}},
		ServiceIslc:            {{1637, 6}, {1637, 17}},
		ServiceIsmaeasdaqlive:  {{1949, 6}, {1949, 17}},
		ServiceIsmaeasdaqtest:  {{1950, 6}, {1950, 17}},
		ServiceIsmc:            {{1638, 6}, {1638, 17}},
		ServiceIsmserver:       {{9500, 6}, {9500, 17}},
		ServiceIsnetserv:       {{48128, 6}, {48128, 17}},
		ServiceIsns:            {{3205, 6}, {3205, 17}},
		ServiceIsoIll:          {{499, 6}, {499, 17}},
		ServiceIsoIp:           {{147, 6}, {147, 17}},
		ServiceIsoTp0:          {{146, 6}, {146, 17}},
		ServiceIsoTp0s:         {{3782, 6}, {3782, 17}},
		ServiceIsoTsap:         {{102, 6}, {102, 17}},
		ServiceIsoTsapC2:       {{399, 6}, {399, 17}},
		ServiceIsodeDua:        {{17007, 6}, {17007, 17}},
		ServiceIsoftP2p:        {{3501, 6}, {3501, 17}},
		ServiceIsoipsigport1:   {{1106, 6}, {1106, 17}},
		ServiceIsoipsigport2:   {{1107, 6}, {1107, 17}},
		ServiceIsomair:         {{3589, 6}, {3589, 17}},
		ServiceIspipes:         {{2853, 6}, {2853, 17}},
		ServiceIspmmgr:         {{3775, 6}, {3775, 17}},
		ServiceIsrpPort:        {{3788, 6}, {3788, 17}},
		ServiceIssMgmtSsl:      {{3995, 6}, {3995, 17}},
		ServiceIssd:            {{1600, 6}, {1600, 17}},
		ServiceIsysgLm:         {{1609, 6}, {1609, 17}},
		ServiceItaAgent:        {{5051, 6}, {5051, 17}},
		ServiceItaManager:      {{5052, 6}, {5052, 17}},
		ServiceItach:           {{8184, 6}, {8184, 17}},
		ServiceItactionserver1: {{7280, 6}, {7280, 17}},
		ServiceItactionserver2: {{7281, 6}, {7281, 17}},
		ServiceItalk:           {{12345, 6}, {12345, 17}},
		ServiceItapDdtp:        {{10100, 6}, {10100, 17}},
		ServiceItelserverport:  {{3719, 6}, {3719, 17}},
		ServiceItem:            {{3848, 6}, {3848, 17}},
		ServiceItinternet:      {{2691, 6}, {2691, 17}},
		ServiceItmLm:           {{2828, 6}, {2828, 17}},
		ServiceItmMccs:         {{3084, 6}, {3084, 17}},
		ServiceItmMcellS:       {{828, 6}, {828, 17}},
		ServiceItmMcellU:       {{1828, 6}, {1828, 17}},
		ServiceItoEGui:         {{2531, 6}, {2531, 17}},
		ServiceItose:           {{4348, 6}, {4348, 17}},
		ServiceItscommNs:       {{1573, 6}, {1573, 17}},
		ServiceItuBiccStc:      {{3097, 132}},
		ServiceItvControl:      {{3899, 6}, {3899, 17}},
		ServiceItwoServer:      {{4410, 6}},
		ServiceIua:             {{9900, 6}, {9900, 17}, {9900, 132}},
		ServiceIuhsctpassoc:    {{29169, 132}},
		ServiceIvcollector:     {{1275, 6}, {1275, 17}},
		ServiceIveconPort:      {{3258, 6}, {3258, 17}},
		ServiceIvmanager:       {{1276, 6}, {1276, 17}},
		ServiceIvocalize:       {{5049, 6}, {5049, 17}},
		ServiceIvsVideo:        {{2232, 6}, {2232, 17}},
		ServiceIvsd:            {{2241, 6}, {2241, 17}},
		ServiceIwMmogame:       {{3596, 6}, {3596, 17}},
		ServiceIwbWhiteboard:   {{2982, 6}, {2982, 17}},
		ServiceIwec:            {{4801, 6}, {4801, 17}},
		ServiceIwg1:            {{7071, 6}, {7071, 17}},
		ServiceIwlistener:      {{2866, 6}, {2866, 17}},
		ServiceIwserver:        {{2166, 6}, {2166, 17}},
		ServiceIzm:             {{4109, 6}, {4109, 17}},
		ServiceJAc:             {{4107, 6}, {4107, 17}},
		ServiceJLanP:           {{2808, 6}, {2808, 17}},
		ServiceJLink:           {{19020, 6}},
		ServiceJacobusLm:       {{1578, 6}, {1578, 17}},
		ServiceJaleosnd:        {{1623, 6}, {1623, 17}},
		ServiceJamlink:         {{8091, 6}},
		ServiceJamserverport:   {{3627, 6}, {3627, 17}},
		ServiceJargon:          {{148, 6}, {148, 17}},
		ServiceJaugsremotec1:   {{3472, 6}, {3472, 17}},
		ServiceJaugsremotec2:   {{3473, 6}, {3473, 17}},
		ServiceJaus:            {{3794, 6}, {3794, 17}},
		ServiceJaxerManager:    {{4328, 6}, {4328, 17}},
		ServiceJaxerWeb:        {{4327, 6}, {4327, 17}},
		ServiceJbossIiop:       {{3528, 6}, {3528, 17}},
		ServiceJbossIiopSsl:    {{3529, 6}, {3529, 17}},
		ServiceJbroker:         {{2506, 6}, {2506, 17}},
		ServiceJcp:             {{19541, 6}, {19541, 17}},
		ServiceJdatastore:      {{2508, 6}, {2508, 17}},
		ServiceJdlDbkitchen:    {{3086, 6}, {3086, 17}},
		ServiceJdmnPort:        {{4030, 6}, {4030, 17}},
		ServiceJdpDisc:         {{7095, 17}},
		ServiceJediserver:      {{2406, 6}, {2406, 17}},
		ServiceJeolNsddp1:      {{6241, 17}},
		ServiceJeolNsddp2:      {{6242, 17}},
		ServiceJeolNsddp3:      {{6243, 17}},
		ServiceJeolNsddp4:      {{6244, 17}},
		ServiceJeolNsdtp1:      {{6241, 6}},
		ServiceJeolNsdtp2:      {{6242, 6}},
		ServiceJeolNsdtp3:      {{6243, 6}},
		ServiceJeolNsdtp4:      {{6244, 6}},
		ServiceJerandLm:        {{1810, 6}, {1810, 17}},
		ServiceJesmsjc:         {{27442, 6}, {27442, 17}},
		ServiceJetcmeserver:    {{1936, 6}, {1936, 17}},
		ServiceJetdirect:       {{9100, 6}},
		ServiceJetform:         {{1706, 6}, {1706, 17}},
		ServiceJetformpreview:  {{2097, 6}, {2097, 17}},
		ServiceJetstream:       {{6901, 6}},
		ServiceJibeEb:          {{3777, 6}, {3777, 17}},
		ServiceJiniDiscovery:   {{4160, 6}, {4160, 17}},
		ServiceJlicelmd:        {{1567, 6}, {1567, 17}},
		ServiceJmact3:          {{6961, 6}, {6961, 17}},
		ServiceJmact5:          {{2957, 6}, {2957, 17}},
		ServiceJmact6:          {{2958, 6}, {2958, 17}},
		ServiceJmbCds1:         {{8900, 6}, {8900, 17}},
		ServiceJmbCds2:         {{8901, 6}, {8901, 17}},
		ServiceJmevt2:          {{6962, 6}, {6962, 17}},
		ServiceJmqDaemon1:      {{3214, 6}, {3214, 17}},
		ServiceJmqDaemon2:      {{3215, 6}, {3215, 17}},
		ServiceJms:             {{5673, 6}, {5673, 17}},
		ServiceJoaJewelSuite:   {{6583, 6}, {6583, 17}},
		ServiceJoltid:          {{3531, 6}, {3531, 17}},
		ServiceJomamqmonitor:   {{4114, 6}, {4114, 17}},
		ServiceJoost:           {{4166, 6}, {4166, 17}},
		ServiceJournee:         {{3042, 6}, {3042, 17}},
		ServiceJpegmpeg:        {{3155, 6}, {3155, 17}},
		ServiceJprinter:        {{5309, 6}, {5309, 17}},
		ServiceJps:             {{2205, 6}, {2205, 17}},
		ServiceJstel:           {{1064, 6}, {1064, 17}},
		ServiceJt400:           {{3470, 6}, {3470, 17}},
		ServiceJt400Ssl:        {{3471, 6}, {3471, 17}},
		ServiceJtagServer:      {{1309, 6}, {1309, 17}},
		ServiceJute:            {{5883, 6}},
		ServiceJuxmlPort:       {{3642, 6}, {3642, 17}},
		ServiceJvclient:        {{1940, 6}, {1940, 17}},
		ServiceJvlMactalk:      {{47100, 17}},
		ServiceJvserver:        {{1939, 6}, {1939, 17}},
		ServiceJwalkserver:     {{1289, 6}, {1289, 17}},
		ServiceJwclient:        {{1938, 6}, {1938, 17}},
		ServiceJwpc:            {{16020, 6}},
		ServiceJwpcBin:         {{16021, 6}},
		ServiceJwserver:        {{1937, 6}, {1937, 17}},
		ServiceK3softwareCli:   {{26263, 6}, {26263, 17}},
		ServiceK3softwareSvr:   {{26262, 6}, {26262, 17}},
		ServiceKBlock:          {{287, 6}, {287, 17}},
		ServiceKa0wuc:          {{2822, 6}, {2822, 17}},
		ServiceKali:            {{2213, 6}, {2213, 17}},
		ServiceKamanda:         {{10081, 6}, {10081, 17}},
		ServiceKana:            {{2656, 6}, {2656, 17}},
		ServiceKar2ouche:       {{4661, 6}, {4661, 17}},
		ServiceKastenchasepad:  {{2918, 6}, {2918, 17}},
		ServiceKastenxpipe:     {{36865, 6}, {36865, 17}},
		ServiceKazaa:           {{1214, 6}, {1214, 17}},
		ServiceKcaService:      {{9878, 17}},
		ServiceKdm:             {{2115, 6}, {2115, 17}},
		ServiceKentroxProt:     {{2502, 6}, {2502, 17}},
		ServiceKerberos:        {{88, 6}, {88, 17}},
		ServiceKerberosAdm:     {{749, 6}, {749, 17}},
		ServiceKerberosIv:      {{750, 17}, {750, 6}},
		ServiceKerberos_master: {{751, 17}, {751, 6}},
		ServiceKermit:          {{1649, 6}, {1649, 17}},
		ServiceKeyserver:       {{584, 6}, {584, 17}},
		ServiceKeyshadow:       {{19315, 6}, {19315, 17}},
		ServiceKeysrvr:         {{19283, 6}, {19283, 17}},
		ServiceKfserver:        {{5343, 6}, {5343, 17}},
		ServiceKftp:            {{6621, 6}, {6621, 17}},
		ServiceKftpData:        {{6620, 6}, {6620, 17}},
		ServiceKfxaclicensing:  {{3581, 6}, {3581, 17}},
		ServiceKingdomsonline:  {{30260, 6}, {30260, 17}},
		ServiceKingfisher:      {{4058, 6}, {4058, 17}},
		ServiceKink:            {{910, 6}, {910, 17}},
		ServiceKiosk:           {{1061, 6}, {1061, 17}},
		ServiceKis:             {{186, 6}, {186, 17}},
		ServiceKitim:           {{35354, 6}},
		ServiceKjtsiteserver:   {{1339, 6}, {1339, 17}},
		ServiceKlio:            {{7697, 6}, {7697, 17}},
		ServiceKlogin:          {{543, 6}, {543, 17}},
		ServiceKmeTrapPort:     {{2081, 6}, {2081, 17}},
		ServiceKmip:            {{5696, 6}},
		ServiceKmscontrol:      {{1773, 6}, {1773, 17}},
		ServiceKnetCmp:         {{157, 6}, {157, 17}},
		ServiceKnetd:           {{2053, 6}},
		ServiceKofaxSvr:        {{2424, 6}, {2424, 17}},
		ServiceKonshusLm:       {{2294, 6}, {2294, 17}},
		ServiceKonspire2b:      {{6085, 6}, {6085, 17}},
		ServiceKopekHttphead:   {{27504, 6}, {27504, 17}},
		ServiceKpasswd:         {{464, 6}, {464, 17}},
		ServiceKpdp:            {{5253, 6}},
		ServiceKpnIcw:          {{3699, 6}, {3699, 17}},
		ServiceKpop:            {{1109, 6}},
		ServiceKrb524:          {{4444, 6}, {4444, 17}},
		ServiceKrb5_prop:       {{754, 6}},
		ServiceKrb5gatekeeper:  {{1318, 6}, {1318, 17}},
		ServiceKrbupdate:       {{760, 6}},
		ServiceKryptolan:       {{398, 6}, {398, 17}},
		ServiceKshell:          {{544, 6}, {544, 17}},
		ServiceKsysguard:       {{3112, 6}, {3112, 17}},
		ServiceKtelnet:         {{6623, 6}, {6623, 17}},
		ServiceKtiIcadSrvr:     {{6701, 6}, {6701, 17}},
		ServiceKvAgent:         {{3361, 6}, {3361, 17}},
		ServiceKvServer:        {{3360, 6}, {3360, 17}},
		ServiceKvmViaIp:        {{1132, 6}, {1132, 17}},
		ServiceKwdbCommn:       {{1127, 17}},
		ServiceKwtc:            {{4566, 6}, {4566, 17}},
		ServiceKyoceranetdev:   {{1063, 6}, {1063, 17}},
		ServiceL2cControl:      {{4371, 6}},
		ServiceL2cData:         {{4372, 6}, {4372, 17}},
		ServiceL2cDisc:         {{4371, 17}},
		ServiceL2tp:            {{1701, 6}, {1701, 17}},
		ServiceL3Exprt:         {{2840, 6}, {2840, 17}},
		ServiceL3Hawk:          {{2842, 6}, {2842, 17}},
		ServiceL3Hbmon:         {{2370, 6}, {2370, 17}},
		ServiceL3Ranger:        {{2841, 6}, {2841, 17}},
		ServiceL3tAtAn:         {{4591, 6}, {4591, 17}},
		ServiceL5nasParchan:    {{9747, 6}, {9747, 17}},
		ServiceLAcoustics:      {{4432, 6}, {4432, 17}},
		ServiceLaMaint:         {{51, 6}, {51, 17}},
		ServiceLabrat:          {{2560, 6}, {2560, 17}},
		ServiceLaesBf:          {{9536, 6}, {9536, 17}},
		ServiceLam:             {{2040, 6}, {2040, 17}},
		ServiceLan900_remote:   {{2395, 6}, {2395, 17}},
		ServiceLandmarks:       {{3969, 6}, {3969, 17}},
		ServiceLanmessenger:    {{2372, 6}, {2372, 17}},
		ServiceLannerLm:        {{4547, 6}, {4547, 17}},
		ServiceLanrevagent:     {{3970, 6}, {3970, 17}},
		ServiceLanrevserver:    {{3971, 6}, {3971, 17}},
		ServiceLanschool:       {{11796, 6}},
		ServiceLanschoolMpt:    {{11796, 17}},
		ServiceLanserver:       {{637, 6}, {637, 17}},
		ServiceLansource:       {{1485, 6}, {1485, 17}},
		ServiceLansurveyor:     {{4347, 6}, {4347, 17}},
		ServiceLansurveyorxml:  {{3815, 6}, {3815, 17}},
		ServiceLanyonLantern:   {{1682, 6}, {1682, 17}},
		ServiceLaplink:         {{1547, 6}, {1547, 17}},
		ServiceLaunchbirdLm:    {{3739, 6}, {3739, 17}},
		ServiceLavenirLm:       {{3373, 6}, {3373, 17}},
		ServiceLazyPtop:        {{7099, 6}, {7099, 17}},
		ServiceLbcControl:      {{2780, 6}, {2780, 17}},
		ServiceLbcMeasure:      {{2815, 6}, {2815, 17}},
		ServiceLbcSync:         {{2779, 6}, {2779, 17}},
		ServiceLbcWatchdog:     {{2816, 6}, {2816, 17}},
		ServiceLbf:             {{2466, 6}, {2466, 17}},
		ServiceLbm:             {{2465, 6}, {2465, 17}},
		ServiceLcmServer:       {{7365, 6}, {7365, 17}},
		ServiceLcsAp:           {{9082, 132}},
		ServiceLdap:            {{389, 6}, {389, 17}},
		ServiceLdapAdmin:       {{3407, 6}, {3407, 17}},
		ServiceLdaps:           {{636, 6}, {636, 17}},
		ServiceLdgateway:       {{9592, 6}, {9592, 17}},
		ServiceLdomsMgmt:       {{6482, 6}, {6482, 17}},
		ServiceLdomsMigr:       {{8101, 6}},
		ServiceLdp:             {{646, 6}, {646, 17}},
		ServiceLdsDistrib:      {{6543, 6}, {6543, 17}},
		ServiceLdsDump:         {{6544, 6}, {6544, 17}},
		ServiceLdss:            {{6087, 6}, {6087, 17}},
		ServiceLdxp:            {{4042, 6}, {4042, 17}},
		ServiceLecroyVicp:      {{1861, 6}, {1861, 17}},
		ServiceLeecoposserver:  {{2212, 6}, {2212, 17}},
		ServiceLegent1:         {{373, 6}, {373, 17}},
		ServiceLegent2:         {{374, 6}, {374, 17}},
		ServiceLeoip:           {{1886, 6}, {1886, 17}},
		ServiceLhtp:            {{1983, 6}, {1983, 17}},
		ServiceLibertyLm:       {{1496, 6}, {1496, 17}},
		ServiceLicensedaemon:   {{1986, 6}, {1986, 17}},
		ServiceLiebDevMgmt_A:   {{3029, 6}, {3029, 17}},
		ServiceLiebDevMgmt_C:   {{3027, 6}, {3027, 17}},
		ServiceLiebDevMgmt_DM:  {{3028, 6}, {3028, 17}},
		ServiceLight:           {{4670, 6}, {4670, 17}},
		ServiceLink:            {{245, 6}, {245, 17}},
		ServiceLinkname:        {{1903, 6}, {1903, 17}},
		ServiceLinktest:        {{3746, 6}, {3746, 17}},
		ServiceLinktestS:       {{3747, 6}, {3747, 17}},
		ServiceLinogridengine:  {{12300, 6}, {12300, 17}},
		ServiceLinx:            {{1361, 6}, {1361, 17}},
		ServiceLionhead:        {{2611, 6}, {2611, 17}},
		ServiceLipsinc:         {{1968, 6}, {1968, 17}},
		ServiceLipsinc1:        {{1969, 6}, {1969, 17}},
		ServiceLispCons:        {{4342, 6}},
		ServiceLispControl:     {{4342, 17}},
		ServiceLispData:        {{4341, 6}, {4341, 17}},
		ServiceLispworksOrb:    {{3672, 6}, {3672, 17}},
		ServiceListcrtPort:     {{3913, 6}, {3913, 17}},
		ServiceListcrtPort2:    {{3914, 6}, {3914, 17}},
		ServiceListmgrPort:     {{3767, 6}, {3767, 17}},
		ServiceLivelan:         {{1555, 6}, {1555, 17}},
		ServiceLivestats:       {{2795, 6}, {2795, 17}},
		ServiceLjkLogin:        {{472, 6}, {472, 17}},
		ServiceLkcmserver:      {{3278, 6}, {3278, 17}},
		ServiceLlmCsv:          {{2814, 6}, {2814, 17}},
		ServiceLlmPass:         {{2813, 6}, {2813, 17}},
		ServiceLlrp:            {{5084, 6}, {5084, 17}},
		ServiceLlsurfupHttp:    {{1183, 6}, {1183, 17}},
		ServiceLlsurfupHttps:   {{1184, 6}, {1184, 17}},
		ServiceLmDta:           {{8206, 6}, {8206, 17}},
		ServiceLmInstmgr:       {{8205, 6}, {8205, 17}},
		ServiceLmMon:           {{31620, 6}, {31620, 17}},
		ServiceLmPerfworks:     {{8204, 6}, {8204, 17}},
		ServiceLmSserver:       {{8207, 6}, {8207, 17}},
		ServiceLmWebwatcher:    {{8208, 6}, {8208, 17}},
		ServiceLmX:             {{6200, 6}, {6200, 17}},
		ServiceLmcs:            {{4877, 6}, {4877, 17}},
		ServiceLmdp:            {{2623, 6}, {2623, 17}},
		ServiceLmp:             {{701, 6}, {701, 17}},
		ServiceLms:             {{4056, 6}, {4056, 17}},
		ServiceLmsocialserver:  {{1111, 6}, {1111, 17}},
		ServiceLmtp:            {{24, 6}, {24, 17}},
		ServiceLnvalarm:        {{2282, 6}, {2282, 17}},
		ServiceLnvconsole:      {{2281, 6}, {2281, 17}},
		ServiceLnvmailmon:      {{2285, 6}, {2285, 17}},
		ServiceLnvmaps:         {{2284, 6}, {2284, 17}},
		ServiceLnvpoller:       {{2280, 6}, {2280, 17}},
		ServiceLnvstatus:       {{2283, 6}, {2283, 17}},
		ServiceLoaprobe:        {{1634, 6}, {1634, 17}},
		ServiceLocalinfosrvr:   {{1487, 6}, {1487, 17}},
		ServiceLockstep:        {{2125, 6}, {2125, 17}},
		ServiceLocusCon:        {{127, 6}, {127, 17}},
		ServiceLocusDisc:       {{5058, 17}},
		ServiceLocusMap:        {{125, 6}, {125, 17}},
		ServiceLofrLm:          {{1752, 6}, {1752, 17}},
		ServiceLogin:           {{513, 6}},
		ServiceLonewolfLm:      {{6146, 6}, {6146, 17}},
		ServiceLontalkNorm:     {{1628, 6}, {1628, 17}},
		ServiceLontalkUrgnt:    {{1629, 6}, {1629, 17}},
		ServiceLonworks:        {{2540, 6}, {2540, 17}},
		ServiceLonworks2:       {{2541, 6}, {2541, 17}},
		ServiceLoricaIn:        {{4080, 6}, {4080, 17}},
		ServiceLoricaInSec:     {{4081, 6}, {4081, 17}},
		ServiceLoricaOut:       {{4082, 6}, {4082, 17}},
		ServiceLoricaOutSec:    {{4083, 6}, {4083, 17}},
		ServiceLot105DsUpd:     {{2053, 17}},
		ServiceLotusmtap:       {{3007, 6}, {3007, 17}},
		ServiceLotusnote:       {{1352, 6}, {1352, 17}},
		ServiceLpcp:            {{1298, 6}, {1298, 17}},
		ServiceLpdg:            {{10805, 6}, {10805, 17}},
		ServiceLpsrecommender:  {{2620, 6}, {2620, 17}},
		ServiceLrp:             {{2090, 6}, {2090, 17}},
		ServiceLrsPaging:       {{3700, 6}, {3700, 17}},
		ServiceLs3:             {{3069, 6}, {3069, 17}},
		ServiceLs3bcast:        {{3068, 6}, {3068, 17}},
		ServiceLsiBobcat:       {{5574, 6}},
		ServiceLsiRaidMgmt:     {{2463, 6}, {2463, 17}},
		ServiceLspPing:         {{3503, 6}, {3503, 17}},
		ServiceLstp:            {{2559, 6}, {2559, 17}},
		ServiceLtctcp:          {{3487, 6}},
		ServiceLtcudp:          {{3487, 17}},
		ServiceLtp:             {{4044, 6}, {4044, 17}},
		ServiceLtpDeepspace:    {{1113, 6}, {1113, 17}},
		ServiceLumimgrd:        {{4741, 6}, {4741, 17}},
		ServiceLupa:            {{1212, 6}, {1212, 17}},
		ServiceLutap:           {{4912, 6}},
		ServiceLutcp:           {{4913, 6}},
		ServiceLvAuth:          {{2147, 6}, {2147, 17}},
		ServiceLvFfx:           {{2144, 6}, {2144, 17}},
		ServiceLvFrontpanel:    {{3079, 6}, {3079, 17}},
		ServiceLvJc:            {{2143, 6}, {2143, 17}},
		ServiceLvNot:           {{2146, 6}, {2146, 17}},
		ServiceLvPici:          {{2145, 6}, {2145, 17}},
		ServiceLvisionLm:       {{6471, 6}, {6471, 17}},
		ServiceLxiEvntsvc:      {{5044, 6}, {5044, 17}},
		ServiceLyskom:          {{4894, 6}, {4894, 17}},
		ServiceM2ap:            {{36443, 132}},
		ServiceM2mservices:     {{8383, 6}, {8383, 17}},
		ServiceM2pa:            {{3565, 6}, {3565, 132}},
		ServiceM2ua:            {{2904, 6}, {2904, 17}, {2904, 132}},
		ServiceM3ap:            {{36444, 132}},
		ServiceM3da:            {{44900, 6}},
		ServiceM3daDisc:        {{44900, 17}},
		ServiceM3ua:            {{2905, 6}, {2905, 132}},
		ServiceM4NetworkAs:     {{4345, 6}, {4345, 17}},
		ServiceMOSAux:          {{10542, 6}, {10542, 17}},
		ServiceMOSLower:        {{10540, 6}, {10540, 17}},
		ServiceMOSSoap:         {{10543, 6}, {10543, 17}},
		ServiceMOSSoapOpt:      {{10544, 6}, {10544, 17}},
		ServiceMOSUpper:        {{10541, 6}, {10541, 17}},
		ServiceMWnn:            {{3732, 6}, {3732, 17}},
		ServiceMacSrvrAdmin:    {{660, 6}, {660, 17}},
		ServiceMacbak:          {{4181, 6}, {4181, 17}},
		ServiceMaconTcp:        {{456, 6}},
		ServiceMaconUdp:        {{456, 17}},
		ServiceMacromediaFcs:   {{1935, 6}, {1935, 17}},
		ServiceMadcap:          {{2535, 6}, {2535, 17}},
		ServiceMadgeLtd:        {{2453, 6}, {2453, 17}},
		ServiceMagayaNetwork:   {{3691, 6}, {3691, 17}},
		ServiceMagbind:         {{3194, 6}, {3194, 17}},
		ServiceMagentaLogic:    {{313, 6}, {313, 17}},
		ServiceMagiccontrol:    {{4902, 6}},
		ServiceMagicnotes:      {{3023, 6}, {3023, 17}},
		ServiceMagicom:         {{2243, 6}, {2243, 17}},
		ServiceMagpie:          {{5092, 17}},
		ServiceMailbox:         {{2004, 6}},
		ServiceMailboxLm:       {{505, 6}, {505, 17}},
		ServiceMailprox:        {{3936, 6}, {3936, 17}},
		ServiceMailq:           {{174, 6}, {174, 17}},
		ServiceMaincontrol:     {{2516, 6}, {2516, 17}},
		ServiceMainsoftLm:      {{1593, 6}, {1593, 17}},
		ServiceMaitrd:          {{997, 6}, {997, 17}},
		ServiceManageExec:      {{2342, 6}, {2342, 17}},
		ServiceMandelspawn:     {{9359, 17}},
		ServiceManet:           {{269, 6}, {269, 17}},
		ServiceManyoneHttp:     {{8910, 6}, {8910, 17}},
		ServiceManyoneXml:      {{8911, 6}, {8911, 17}},
		ServiceMao:             {{2908, 6}, {2908, 17}},
		ServiceMapperMapethd:   {{3985, 6}, {3985, 17}},
		ServiceMapperNodemgr:   {{3984, 6}, {3984, 17}},
		ServiceMapperWs_ethd:   {{3986, 6}, {3986, 17}},
		ServiceMarcamLm:        {{1444, 6}, {1444, 17}},
		ServiceMarkemDcp:       {{3836, 6}, {3836, 17}},
		ServiceMasc:            {{2587, 6}, {2587, 17}},
		ServiceMasqdialer:      {{224, 6}, {224, 17}},
		ServiceMatahari:        {{49000, 6}},
		ServiceMatipTypeA:      {{350, 6}, {350, 17}},
		ServiceMatipTypeB:      {{351, 6}, {351, 17}},
		ServiceMatrix_vnet:     {{4360, 6}},
		ServiceMax:             {{6074, 6}, {6074, 17}},
		ServiceMaximAsics:      {{3276, 6}, {3276, 17}},
		ServiceMaxumSP:         {{4179, 6}, {4179, 17}},
		ServiceMaytagshuffle:   {{2591, 6}, {2591, 17}},
		ServiceMbgCtrl:         {{3569, 6}, {3569, 17}},
		ServiceMblBattd:        {{4153, 6}, {4153, 17}},
		ServiceMbus:            {{47000, 6}, {47000, 17}},
		ServiceMc2studios:      {{1899, 6}, {1899, 17}},
		ServiceMc3ss:           {{3521, 6}, {3521, 17}},
		ServiceMcAppserver:     {{8763, 6}, {8763, 17}},
		ServiceMcBrkSrv:        {{3180, 6}, {3180, 17}},
		ServiceMcClient:        {{1180, 6}, {1180, 17}},
		ServiceMcComm:          {{9632, 17}},
		ServiceMcGtSrv:         {{2180, 6}, {2180, 17}},
		ServiceMcagent:         {{1820, 6}, {1820, 17}},
		ServiceMccwebsvrPort:   {{3570, 6}, {3570, 17}},
		ServiceMcerPort:        {{6510, 6}, {6510, 17}},
		ServiceMcftp:           {{6622, 6}, {6622, 17}},
		ServiceMcidas:          {{112, 6}, {112, 17}},
		ServiceMckIvpip:        {{2698, 6}, {2698, 17}},
		ServiceMcnsSec:         {{638, 6}, {638, 17}},
		ServiceMcnsTelRet:      {{3311, 6}, {3311, 17}},
		ServiceMcntp:           {{5418, 6}, {5418, 17}},
		ServiceMcp:             {{4458, 6}, {4458, 17}},
		ServiceMcpPort:         {{3558, 6}, {3558, 17}},
		ServiceMcreport:        {{8003, 6}, {8003, 17}},
		ServiceMcsCalypsoicf:   {{3330, 6}, {3330, 17}},
		ServiceMcsFastmail:     {{3302, 6}, {3302, 17}},
		ServiceMcsMailsvr:      {{3332, 6}, {3332, 17}},
		ServiceMcsMessaging:    {{3331, 6}, {3331, 17}},
		ServiceMctetGateway:    {{3116, 6}, {3116, 17}},
		ServiceMctetJserv:      {{3117, 6}, {3117, 17}},
		ServiceMctetMaster:     {{3115, 6}, {3115, 17}},
		ServiceMctfeed:         {{5598, 6}, {5598, 17}},
		ServiceMctp:            {{1100, 6}, {1100, 17}},
		ServiceMdCgHttp:        {{2688, 6}, {2688, 17}},
		ServiceMdapPort:        {{3235, 6}, {3235, 17}},
		ServiceMdbs_daemon:     {{800, 6}, {800, 17}},
		ServiceMdcPortmapper:   {{685, 6}, {685, 17}},
		ServiceMdm:             {{7871, 6}},
		ServiceMdns:            {{5353, 6}, {5353, 17}},
		ServiceMdnsresponder:   {{5354, 6}, {5354, 17}},
		ServiceMdqs:            {{666, 6}, {666, 17}},
		ServiceMdtp:            {{3232, 6}, {3232, 17}},
		ServiceMecomm:          {{668, 6}, {668, 17}},
		ServiceMedCi:           {{24005, 6}, {24005, 17}},
		ServiceMedFspRx:        {{24001, 6}, {24001, 17}},
		ServiceMedFspTx:        {{24002, 6}, {24002, 17}},
		ServiceMedLtp:          {{24000, 6}, {24000, 17}},
		ServiceMedNetSvc:       {{24006, 6}, {24006, 17}},
		ServiceMedOvw:          {{24004, 6}, {24004, 17}},
		ServiceMedSupp:         {{24003, 6}, {24003, 17}},
		ServiceMedevolve:       {{13930, 6}},
		ServiceMediaAgent:      {{2789, 6}, {2789, 17}},
		ServiceMediabox:        {{46999, 6}, {46999, 17}},
		ServiceMediacntrlnfsd:  {{2363, 6}, {2363, 17}},
		ServiceMediaspace:      {{3594, 6}, {3594, 17}},
		ServiceMediat:          {{5157, 6}},
		ServiceMediavaultGui:   {{3673, 6}, {3673, 17}},
		ServiceMedimageportal:  {{7720, 6}, {7720, 17}},
		ServiceMegacoH248:      {{2944, 6}, {2944, 17}, {2944, 132}},
		ServiceMegardsvrPort:   {{3571, 6}, {3571, 17}},
		ServiceMegaregsvrport:  {{3572, 6}, {3572, 17}},
		ServiceMemcache:        {{11211, 6}, {11211, 17}},
		ServiceMenandmiceDns:   {{1337, 6}, {1337, 17}},
		ServiceMenandmiceLpm:   {{1231, 6}, {1231, 17}},
		ServiceMenandmiceMon:   {{4552, 6}, {4552, 17}},
		ServiceMenandmiceUpg:   {{4603, 6}},
		ServiceMenandmice_noh:  {{4151, 6}, {4151, 17}},
		ServiceMentaclient:     {{2117, 6}, {2117, 17}},
		ServiceMentaserver:     {{2118, 6}, {2118, 17}},
		ServiceMercantile:      {{3398, 6}, {3398, 17}},
		ServiceMercuryDisc:     {{9596, 6}, {9596, 17}},
		ServiceMeregister:      {{669, 6}, {669, 17}},
		ServiceMesavistaco:     {{1249, 6}, {1249, 17}},
		ServiceMessageasap:     {{6070, 6}, {6070, 17}},
		ServiceMessageservice:  {{2311, 6}, {2311, 17}},
		ServiceMeta5:           {{393, 6}, {393, 17}},
		ServiceMetaCorp:        {{6141, 6}, {6141, 17}},
		ServiceMetaagent:       {{1897, 6}, {1897, 17}},
		ServiceMetaconsole:     {{2850, 6}, {2850, 17}},
		ServiceMetaeditMu:      {{6360, 6}, {6360, 17}},
		ServiceMetaeditSe:      {{6370, 6}, {6370, 17}},
		ServiceMetaeditWs:      {{6390, 6}, {6390, 17}},
		ServiceMetagram:        {{99, 6}, {99, 17}},
		ServiceMetalbend:       {{7172, 6}},
		ServiceMetasage:        {{1207, 6}, {1207, 17}},
		ServiceMetastorm:       {{2511, 6}, {2511, 17}},
		ServiceMetasys:         {{11001, 6}, {11001, 17}},
		ServiceMetatudeMds:     {{6382, 6}, {6382, 17}},
		ServiceMeter:           {{570, 6}, {570, 17}},
		ServiceMetricadbc:      {{2622, 6}, {2622, 17}},
		ServiceMetricsPas:      {{1824, 6}, {1824, 17}},
		ServiceMevent:          {{7900, 6}, {7900, 17}},
		ServiceMfcobol:         {{86, 6}, {86, 17}},
		ServiceMfserver:        {{2266, 6}, {2266, 17}},
		ServiceMftp:            {{349, 6}, {349, 17}},
		ServiceMgcpCallagent:   {{2727, 6}, {2727, 17}},
		ServiceMgcpGateway:     {{2427, 6}, {2427, 17}},
		ServiceMgcsMfpPort:     {{6509, 6}, {6509, 17}},
		ServiceMgemanagement:   {{4680, 6}, {4680, 17}},
		ServiceMgesupervision:  {{4679, 6}, {4679, 17}},
		ServiceMgxswitch:       {{3070, 6}, {3070, 17}},
		ServiceMiamiBcast:      {{6083, 17}},
		ServiceMibStreaming:    {{2292, 6}, {2292, 17}},
		ServiceMice:            {{5022, 6}, {5022, 17}},
		ServiceMicomPfs:        {{490, 6}, {490, 17}},
		ServiceMicrocomSbp:     {{1680, 6}, {1680, 17}},
		ServiceMicromuseLm:     {{1534, 6}, {1534, 17}},
		ServiceMicromuseNcps:   {{7979, 6}, {7979, 17}},
		ServiceMicromuseNcpw:   {{9600, 6}, {9600, 17}},
		ServiceMicrosan:        {{20001, 6}, {20001, 17}},
		ServiceMicrosoftDs:     {{445, 6}, {445, 17}},
		ServiceMicrotalonCom:   {{7014, 6}, {7014, 17}},
		ServiceMicrotalonDis:   {{7013, 6}, {7013, 17}},
		ServiceMidnightTech:    {{3008, 6}, {3008, 17}},
		ServiceMikey:           {{2269, 6}, {2269, 17}},
		ServiceMil204547001:    {{1581, 6}, {1581, 17}},
		ServiceMilesApart:      {{2621, 6}, {2621, 17}},
		ServiceMimer:           {{1360, 6}, {1360, 17}},
		ServiceMindarrayCa:     {{9445, 6}},
		ServiceMindfilesys:     {{7391, 6}, {7391, 17}},
		ServiceMindprint:       {{8033, 6}, {8033, 17}},
		ServiceMinger:          {{4069, 6}, {4069, 17}},
		ServiceMiniSql:         {{1114, 6}, {1114, 17}},
		ServiceMinilock:        {{3798, 6}, {3798, 17}},
		ServiceMinipay:         {{2105, 17}},
		ServiceMinivend:        {{7786, 6}, {7786, 17}},
		ServiceMinotaurSa:      {{5136, 17}},
		ServiceMipv6tls:        {{7872, 17}},
		ServiceMira:            {{3454, 6}, {3454, 17}},
		ServiceMiroconnect:     {{1532, 6}, {1532, 17}},
		ServiceMirrtex:         {{4310, 6}, {4310, 17}},
		ServiceMitDov:          {{91, 6}, {91, 17}},
		ServiceMitMlDev:        {{83, 6}, {83, 17}},
		ServiceMiteksysLm:      {{1482, 6}, {1482, 17}},
		ServiceMivaMqs:         {{1277, 6}, {1277, 17}},
		ServiceMkmDiscovery:    {{3837, 6}, {3837, 17}},
		ServiceMlSvnet:         {{4171, 6}},
		ServiceMle:             {{19788, 17}},
		ServiceMloadd:          {{1427, 6}, {1427, 17}},
		ServiceMlsn:            {{32801, 6}, {32801, 17}},
		ServiceMmaDiscovery:    {{4173, 17}},
		ServiceMmacomm:         {{4667, 6}, {4667, 17}},
		ServiceMmaeds:          {{4668, 6}, {4668, 17}},
		ServiceMmcal:           {{2272, 6}, {2272, 17}},
		ServiceMmcals:          {{2271, 6}, {2271, 17}},
		ServiceMmcc:            {{5050, 6}, {5050, 17}},
		ServiceMmpft:           {{1815, 6}, {1815, 17}},
		ServiceMnetDiscovery:   {{5237, 6}, {5237, 17}},
		ServiceMngsuite:        {{9535, 6}, {9535, 17}},
		ServiceMniProtRout:     {{3764, 6}, {3764, 17}},
		ServiceMnpExchange:     {{2197, 6}, {2197, 17}},
		ServiceMnsMail:         {{2593, 6}, {2593, 17}},
		ServiceMobileFileDl:    {{2926, 6}, {2926, 17}},
		ServiceMobileP2p:       {{4688, 6}, {4688, 17}},
		ServiceMobileanalyzer:  {{7869, 6}},
		ServiceMobileipAgent:   {{434, 6}, {434, 17}},
		ServiceMobilipMn:       {{435, 6}, {435, 17}},
		ServiceMobilitySrv:     {{6997, 6}, {6997, 17}},
		ServiceMobrienChat:     {{2031, 6}, {2031, 17}},
		ServiceMoldflowLm:      {{1576, 6}, {1576, 17}},
		ServiceMolly:           {{1374, 6}, {1374, 17}},
		ServiceMon:             {{2583, 6}, {2583, 17}, {9255, 6}, {9255, 17}},
		ServiceMondex:          {{471, 6}, {471, 17}},
		ServiceMonetra:         {{8665, 6}},
		ServiceMonetraAdmin:    {{8666, 6}},
		ServiceMonitor:         {{561, 6}, {561, 17}},
		ServiceMonkeycom:       {{9898, 6}, {9898, 17}},
		ServiceMonp:            {{3445, 6}, {3445, 17}},
		ServiceMontageLm:       {{6147, 6}, {6147, 17}},
		ServiceMortgageware:    {{367, 6}, {367, 17}},
		ServiceMosaicsyssvc1:   {{1235, 6}, {1235, 17}},
		ServiceMosaixcc:        {{2561, 6}, {2561, 17}},
		ServiceMoshebeeri:      {{2627, 6}, {2627, 17}},
		ServiceMountd:          {{20048, 6}, {20048, 17}},
		ServiceMovazSsc:        {{5252, 6}, {5252, 17}},
		ServiceMoyCorp:         {{2488, 6}, {2488, 17}},
		ServiceMpcLifenet:      {{1213, 6}, {1213, 17}},
		ServiceMpfoncl:         {{2579, 6}, {2579, 17}},
		ServiceMpfwsas:         {{2952, 6}, {2952, 17}},
		ServiceMphlpdmc:        {{9344, 6}, {9344, 17}},
		ServiceMpidcagt:        {{9397, 6}, {9397, 17}},
		ServiceMpidcmgr:        {{9343, 6}, {9343, 17}},
		ServiceMplGprsPort:     {{3924, 6}, {3924, 17}},
		ServiceMpm:             {{45, 6}, {45, 17}},
		ServiceMpmFlags:        {{44, 6}, {44, 17}},
		ServiceMpmSnd:          {{46, 6}, {46, 17}},
		ServiceMpnjsc:          {{1952, 6}, {1952, 17}},
		ServiceMpnjsocl:        {{2685, 6}, {2685, 17}},
		ServiceMpnjsomb:        {{2681, 6}, {2681, 17}},
		ServiceMpnjsomg:        {{2686, 6}, {2686, 17}},
		ServiceMpnjsosv:        {{2684, 6}, {2684, 17}},
		ServiceMpp:             {{218, 6}, {218, 17}},
		ServiceMppolicyMgr:     {{5969, 6}, {5969, 17}},
		ServiceMppolicyV5:      {{5968, 6}, {5968, 17}},
		ServiceMpsRaft:         {{1700, 6}, {1700, 17}},
		ServiceMpshrsv:         {{1261, 6}, {1261, 17}},
		ServiceMpsserver:       {{6106, 6}, {6106, 17}},
		ServiceMpsysrmsvr:      {{3358, 6}, {3358, 17}},
		ServiceMptn:            {{397, 6}, {397, 17}},
		ServiceMqeAgent:        {{3958, 6}, {3958, 17}},
		ServiceMqeBroker:       {{3957, 6}, {3957, 17}},
		ServiceMrip:            {{4986, 6}, {4986, 17}},
		ServiceMrm:             {{679, 6}, {679, 17}},
		ServiceMrssrendezvous:  {{7392, 6}, {7392, 17}},
		ServiceMsAlerter:       {{5359, 6}, {5359, 17}},
		ServiceMsClusterNet:    {{3343, 6}, {3343, 17}},
		ServiceMsIlm:           {{5725, 6}},
		ServiceMsIlmSts:        {{5726, 6}},
		ServiceMsLa:            {{3535, 6}, {3535, 17}},
		ServiceMsLicensing:     {{5720, 6}, {5720, 17}},
		ServiceMsOlap1:         {{2393, 6}, {2393, 17}},
		ServiceMsOlap2:         {{2394, 6}, {2394, 17}},
		ServiceMsOlap3:         {{2382, 6}, {2382, 17}},
		ServiceMsOlap4:         {{2383, 6}, {2383, 17}},
		ServiceMsRome:          {{569, 6}, {569, 17}},
		ServiceMsRuleEngine:    {{3132, 6}, {3132, 17}},
		ServiceMsSSideshow:     {{5361, 6}, {5361, 17}},
		ServiceMsShuttle:       {{568, 6}, {568, 17}},
		ServiceMsSideshow:      {{5360, 6}, {5360, 17}},
		ServiceMsSmlbiz:        {{5356, 6}, {5356, 17}},
		ServiceMsSnaBase:       {{1478, 6}, {1478, 17}},
		ServiceMsSnaServer:     {{1477, 6}, {1477, 17}},
		ServiceMsSqlM:          {{1434, 6}, {1434, 17}},
		ServiceMsSqlS:          {{1433, 6}, {1433, 17}},
		ServiceMsStreaming:     {{1755, 6}, {1755, 17}},
		ServiceMsTheater:       {{2460, 6}, {2460, 17}},
		ServiceMsVWorlds:       {{2525, 6}, {2525, 17}},
		ServiceMsWbtServer:     {{3389, 6}, {3389, 17}},
		ServiceMsdfsr:          {{5722, 6}, {5722, 17}},
		ServiceMsdp:            {{639, 6}, {639, 17}},
		ServiceMsdts1:          {{3882, 6}, {3882, 17}},
		ServiceMsexchRouting:   {{691, 6}, {691, 17}},
		ServiceMsfrs:           {{4554, 6}, {4554, 17}},
		ServiceMsftDpmCert:     {{6076, 6}},
		ServiceMsftGc:          {{3268, 6}, {3268, 17}},
		ServiceMsftGcSsl:       {{3269, 6}, {3269, 17}},
		ServiceMsfwArray:       {{2174, 6}, {2174, 17}},
		ServiceMsfwControl:     {{3847, 6}, {3847, 17}},
		ServiceMsfwReplica:     {{2173, 6}, {2173, 17}},
		ServiceMsfwSStorage:    {{2172, 6}, {2172, 17}},
		ServiceMsfwStorage:     {{2171, 6}, {2171, 17}},
		ServiceMsgAuth:         {{31, 6}, {31, 17}},
		ServiceMsgIcp:          {{29, 6}, {29, 17}},
		ServiceMsgclnt:         {{8786, 6}, {8786, 17}},
		ServiceMsgsrvr:         {{8787, 6}, {8787, 17}},
		ServiceMsgsys:          {{9594, 6}, {9594, 17}},
		ServiceMshvlm:          {{6600, 6}},
		ServiceMsiCpsRm:        {{8675, 6}},
		ServiceMsiCpsRmDisc:    {{8675, 17}},
		ServiceMsiSelectplay:   {{2871, 6}, {2871, 17}},
		ServiceMsiccp:          {{1731, 6}, {1731, 17}},
		ServiceMsims:           {{1582, 6}, {1582, 17}},
		ServiceMsl_lmd:         {{1464, 6}, {1464, 17}},
		ServiceMsmq:            {{1801, 6}, {1801, 17}},
		ServiceMsnp:            {{1863, 6}, {1863, 17}},
		ServiceMsolapPtp2:      {{2725, 6}, {2725, 17}},
		ServiceMsp:             {{18, 6}, {18, 17}},
		ServiceMspOs:           {{4686, 6}, {4686, 17}},
		ServiceMsrPluginPort:   {{3931, 6}, {3931, 17}},
		ServiceMsrp:            {{2855, 6}, {2855, 17}},
		ServiceMsss:            {{7742, 6}},
		ServiceMstmgSstp:       {{6601, 6}},
		ServiceMsync:           {{2072, 6}, {2072, 17}},
		ServiceMtScaleserver:   {{2305, 6}, {2305, 17}},
		ServiceMtcevrunqman:    {{4558, 17}},
		ServiceMtcevrunqss:     {{4557, 17}},
		ServiceMtftp:           {{1759, 17}},
		ServiceMtiTcsComm:      {{2469, 6}, {2469, 17}},
		ServiceMtl8000Matrix:   {{8115, 6}, {8115, 17}},
		ServiceMtn:             {{4691, 6}, {4691, 17}},
		ServiceMtp:             {{1911, 6}, {1911, 17}},
		ServiceMtportRegist:    {{2791, 6}, {2791, 17}},
		ServiceMtportmon:       {{7421, 6}, {7421, 17}},
		ServiceMtqp:            {{1038, 6}, {1038, 17}},
		ServiceMtrgtrans:       {{19398, 6}, {19398, 17}},
		ServiceMtsserver:       {{4602, 6}},
		ServiceMulticastPing:   {{9903, 6}, {9903, 17}},
		ServiceMultilingHttp:   {{777, 6}, {777, 17}},
		ServiceMultipMsg:       {{3733, 6}, {3733, 17}},
		ServiceMultiplex:       {{171, 6}, {171, 17}},
		ServiceMumps:           {{188, 6}, {188, 17}},
		ServiceMunin:           {{4949, 6}, {4949, 17}},
		ServiceMupdate:         {{3905, 6}, {3905, 17}},
		ServiceMurray:          {{1123, 6}, {1123, 17}},
		ServiceMurx:            {{2743, 6}, {2743, 17}},
		ServiceMuse:            {{6888, 6}, {6888, 17}},
		ServiceMusiconline:     {{1806, 6}, {1806, 17}},
		ServiceMustBackplane:   {{3515, 6}, {3515, 17}},
		ServiceMustP2p:         {{3514, 6}, {3514, 17}},
		ServiceMvelLm:          {{1574, 6}, {1574, 17}},
		ServiceMvsCapacity:     {{10007, 6}, {10007, 17}},
		ServiceMvxLm:           {{1510, 6}, {1510, 17}},
		ServiceMxi:             {{8005, 6}, {8005, 17}},
		ServiceMxit:            {{9119, 6}, {9119, 17}},
		ServiceMxodbcConnect:   {{6632, 6}},
		ServiceMxomss:          {{1141, 6}, {1141, 17}},
		ServiceMxxrlogin:       {{1035, 6}, {1035, 17}},
		ServiceMyblast:         {{3795, 6}, {3795, 17}},
		ServiceMylexMapd:       {{467, 6}, {467, 17}},
		ServiceMylxamport:      {{2981, 6}, {2981, 17}},
		ServiceMynahautostart:  {{2388, 6}, {2388, 17}},
		ServiceMyrtle:          {{1831, 6}, {1831, 17}},
		ServiceMysql:           {{3306, 6}, {3306, 17}},
		ServiceMysqlCluster:    {{1186, 6}, {1186, 17}},
		ServiceMysqlCmAgent:    {{1862, 6}, {1862, 17}},
		ServiceMysqlIm:         {{2273, 6}, {2273, 17}},
		ServiceMysqlProxy:      {{6446, 6}, {6446, 17}},
		ServiceMzap:            {{2106, 6}, {2106, 17}},
		ServiceMzcaAction:      {{7282, 6}},
		ServiceMzcaAlert:       {{7282, 17}},
		ServiceN1Fwp:           {{4446, 6}, {4446, 17}},
		ServiceN1Rmgmt:         {{4447, 6}, {4447, 17}},
		ServiceN2h2server:      {{9285, 6}, {9285, 17}},
		ServiceN2nremote:       {{1685, 6}, {1685, 17}},
		ServiceN2receive:       {{9286, 17}},
		ServiceNaErTip:         {{3725, 6}, {3725, 17}},
		ServiceNaLocalise:      {{5062, 6}, {5062, 17}},
		ServiceNaap:            {{1340, 6}, {1340, 17}},
		ServiceNacagent:        {{4407, 6}},
		ServiceNacnl:           {{4361, 17}},
		ServiceNamemunge:       {{3950, 6}, {3950, 17}},
		ServiceNameserver:      {{42, 6}, {42, 17}},
		ServiceNamp:            {{167, 6}, {167, 17}},
		ServiceNani:            {{2236, 6}, {2236, 17}},
		ServiceNas:             {{991, 6}, {991, 17}},
		ServiceNasMetering:     {{2286, 6}, {2286, 17}},
		ServiceNasmanager:      {{1960, 6}, {1960, 17}},
		ServiceNatdataservice:  {{3927, 6}, {3927, 17}},
		ServiceNatiDstp:        {{3015, 6}, {3015, 17}},
		ServiceNatiLogos:       {{2343, 6}, {2343, 17}},
		ServiceNatiSvrloc:      {{3580, 6}, {3580, 17}},
		ServiceNatiViServer:    {{3363, 6}, {3363, 17}},
		ServiceNattyserver:     {{3753, 6}, {3753, 17}},
		ServiceNatuslink:       {{2895, 6}, {2895, 17}},
		ServiceNavData:         {{6317, 17}},
		ServiceNavDataCmd:      {{6317, 6}},
		ServiceNavPort:         {{3859, 6}, {3859, 17}},
		ServiceNavbuddy:        {{1288, 6}, {1288, 17}},
		ServiceNavegawebPort:   {{3159, 6}, {3159, 17}},
		ServiceNavisphere:      {{2162, 6}, {2162, 17}},
		ServiceNavisphereSec:   {{2163, 6}, {2163, 17}},
		ServiceNbd:             {{10809, 6}},
		ServiceNbdb:            {{13785, 6}, {13785, 17}},
		ServiceNbp:             {{2, 6}},
		ServiceNbtPc:           {{5133, 6}, {5133, 17}},
		ServiceNbtWol:          {{6133, 6}, {6133, 17}},
		ServiceNburn_id:        {{20034, 6}, {20034, 17}},
		ServiceNbxAu:           {{2094, 6}, {2094, 17}},
		ServiceNbxCc:           {{2093, 6}, {2093, 17}},
		ServiceNbxDir:          {{2096, 6}, {2096, 17}},
		ServiceNbxSer:          {{2095, 6}, {2095, 17}},
		ServiceNcacnIpTcp:      {{3062, 6}, {3062, 17}},
		ServiceNcadgIpUdp:      {{3063, 6}, {3063, 17}},
		ServiceNcconfig:        {{1888, 6}, {1888, 17}},
		ServiceNcdloadbalance:  {{2683, 6}, {2683, 17}},
		ServiceNcdmirroring:    {{2706, 6}, {2706, 17}},
		ServiceNced:            {{404, 6}, {404, 17}},
		ServiceNcl:             {{2397, 6}, {2397, 17}},
		ServiceNcld:            {{405, 6}, {405, 17}},
		ServiceNcp:             {{524, 6}, {524, 17}},
		ServiceNcpmFt:          {{1744, 6}, {1744, 17}},
		ServiceNcpmHip:         {{1683, 6}, {1683, 17}},
		ServiceNcpmPm:          {{1591, 6}, {1591, 17}},
		ServiceNcr_ccl:         {{2528, 6}, {2528, 17}},
		ServiceNcu1:            {{3195, 6}, {3195, 17}},
		ServiceNcu2:            {{3196, 6}, {3196, 17}},
		ServiceNcubeLm:         {{1521, 6}, {1521, 17}},
		ServiceNcxcp:           {{5681, 6}, {5681, 17}},
		ServiceNdlAas:          {{3128, 17}},
		ServiceNdlAhpSvc:       {{6064, 6}, {6064, 17}},
		ServiceNdlAls:          {{3431, 6}, {3431, 17}},
		ServiceNdlAps:          {{3096, 6}, {3096, 17}},
		ServiceNdlTcpOisGw:     {{2738, 6}, {2738, 17}},
		ServiceNdmAgentPort:    {{43189, 6}, {43189, 17}},
		ServiceNdmRequester:    {{1363, 6}, {1363, 17}},
		ServiceNdmServer:       {{1364, 6}, {1364, 17}},
		ServiceNdmp:            {{10000, 6}, {10000, 17}},
		ServiceNdmps:           {{30000, 6}},
		ServiceNdnp:            {{2883, 6}, {2883, 17}},
		ServiceNds_sso:         {{3024, 6}, {3024, 17}},
		ServiceNdsauth:         {{353, 6}, {353, 17}},
		ServiceNdsconnect:      {{3890, 6}, {3890, 17}},
		ServiceNdsp:            {{2881, 6}, {2881, 17}},
		ServiceNdtp:            {{2882, 6}, {2882, 17}},
		ServiceNecRaidplus:     {{2730, 6}, {2730, 17}},
		ServiceNeckar:          {{37475, 6}, {37475, 17}},
		ServiceNecp:            {{3262, 6}, {3262, 17}},
		ServiceNeiManagement:   {{3886, 6}, {3886, 17}},
		ServiceNeo4j:           {{7474, 6}},
		ServiceNeod1:           {{1047, 6}, {1047, 17}},
		ServiceNeod2:           {{1048, 6}, {1048, 17}},
		ServiceNeoiface:        {{1285, 6}, {1285, 17}},
		ServiceNeon24x7:        {{3213, 6}, {3213, 17}},
		ServiceNerv:            {{1222, 6}, {1222, 17}},
		ServiceNeshBroker:      {{3507, 6}, {3507, 17}},
		ServiceNessus:          {{1241, 6}, {1241, 17}},
		ServiceNestProtocol:    {{489, 6}, {489, 17}},
		ServiceNet2display:     {{9086, 6}, {9086, 17}},
		ServiceNet8Cman:        {{1830, 6}, {1830, 17}},
		ServiceNetAssistant:    {{3283, 6}, {3283, 17}},
		ServiceNetDevice:       {{4350, 6}, {4350, 17}},
		ServiceNetProjection:   {{5363, 6}, {5363, 17}},
		ServiceNetSteward:      {{2128, 6}, {2128, 17}},
		ServiceNetadmin:        {{2450, 6}, {2450, 17}},
		ServiceNetagent:        {{5771, 6}, {5771, 17}},
		ServiceNetangel:        {{2442, 6}, {2442, 17}},
		ServiceNetappIcdata:    {{11105, 6}},
		ServiceNetappIcmgmt:    {{11104, 6}},
		ServiceNetarx:          {{1040, 6}, {1040, 17}},
		ServiceNetaspi:         {{2902, 6}, {2902, 17}},
		ServiceNetattachsdmp:   {{3066, 6}, {3066, 17}},
		ServiceNetbillAuth:     {{1615, 6}, {1615, 17}},
		ServiceNetbillCred:     {{1614, 6}, {1614, 17}},
		ServiceNetbillKeyrep:   {{1613, 6}, {1613, 17}},
		ServiceNetbillProd:     {{1616, 6}, {1616, 17}},
		ServiceNetbillTrans:    {{1612, 6}, {1612, 17}},
		ServiceNetbiosDgm:      {{138, 6}, {138, 17}},
		ServiceNetbiosNs:       {{137, 6}, {137, 17}},
		ServiceNetbiosSsn:      {{139, 6}, {139, 17}},
		ServiceNetblox:         {{4441, 17}},
		ServiceNetbookmark:     {{3131, 6}, {3131, 17}},
		ServiceNetbootPxe:      {{3928, 6}, {3928, 17}},
		ServiceNetcabinetCom:   {{4409, 6}},
		ServiceNetcelera:       {{3701, 6}, {3701, 17}},
		ServiceNetchat:         {{2451, 6}, {2451, 17}},
		ServiceNetcheque:       {{4008, 6}, {4008, 17}},
		ServiceNetclip:         {{2971, 6}, {2971, 17}},
		ServiceNetcomm1:        {{1676, 6}},
		ServiceNetcomm2:        {{1676, 17}},
		ServiceNetconfBeep:     {{831, 6}, {831, 17}},
		ServiceNetconfSsh:      {{830, 6}, {830, 17}},
		ServiceNetconfTls:      {{6513, 6}},
		ServiceNetconfsoapbeep: {{833, 6}, {833, 17}},
		ServiceNetconfsoaphttp: {{832, 6}, {832, 17}},
		ServiceNetcp:           {{395, 6}, {395, 17}},
		ServiceNetdbExport:     {{1329, 6}, {1329, 17}},
		ServiceNeteh:           {{3828, 6}, {3828, 17}},
		ServiceNetehExt:        {{3829, 6}, {3829, 17}},
		ServiceNetgw:           {{741, 6}, {741, 17}},
		ServiceNetinfoLocal:    {{1033, 6}, {1033, 17}},
		ServiceNetiq:           {{2220, 6}, {2220, 17}},
		ServiceNetiqEndpoint:   {{10113, 6}, {10113, 17}},
		ServiceNetiqEndpt:      {{10115, 6}, {10115, 17}},
		ServiceNetiqMc:         {{2735, 6}, {2735, 17}},
		ServiceNetiqNcap:       {{2219, 6}, {2219, 17}},
		ServiceNetiqQcheck:     {{10114, 6}, {10114, 17}},
		ServiceNetiqVoipa:      {{10116, 6}, {10116, 17}},
		ServiceNetlabsLm:       {{1406, 6}, {1406, 17}},
		ServiceNetmagic:        {{1196, 6}, {1196, 17}},
		ServiceNetmap_lm:       {{1493, 6}, {1493, 17}},
		ServiceNetml:           {{2288, 6}, {2288, 17}},
		ServiceNetmoDefault:    {{6841, 6}, {6841, 17}},
		ServiceNetmoHttp:       {{6842, 6}, {6842, 17}},
		ServiceNetmon:          {{2606, 6}, {2606, 17}},
		ServiceNetmount:        {{2061, 6}, {2061, 17}},
		ServiceNetmpi:          {{3827, 6}, {3827, 17}},
		ServiceNetnews:         {{532, 6}, {532, 17}},
		ServiceNetoDcs:         {{3814, 6}, {3814, 17}},
		ServiceNetoWolServer:   {{3812, 6}, {3812, 17}},
		ServiceNetobjects1:     {{2485, 6}, {2485, 17}},
		ServiceNetobjects2:     {{2486, 6}, {2486, 17}},
		ServiceNetopRc:         {{1970, 6}, {1970, 17}},
		ServiceNetopSchool:     {{1971, 6}, {1971, 17}},
		ServiceNetopiaVo1:      {{1839, 6}, {1839, 17}},
		ServiceNetopiaVo2:      {{1840, 6}, {1840, 17}},
		ServiceNetopiaVo3:      {{1841, 6}, {1841, 17}},
		ServiceNetopiaVo4:      {{1842, 6}, {1842, 17}},
		ServiceNetopiaVo5:      {{1843, 6}, {1843, 17}},
		ServiceNetopsBroker:    {{5465, 6}, {5465, 17}},
		ServiceNetperf:         {{12865, 6}},
		ServiceNetplan:         {{2983, 6}, {2983, 17}},
		ServiceNetplayPort1:    {{3640, 6}, {3640, 17}},
		ServiceNetplayPort2:    {{3641, 6}, {3641, 17}},
		ServiceNetportId:       {{3129, 6}, {3129, 17}},
		ServiceNetrcs:          {{742, 6}, {742, 17}},
		ServiceNetrek:          {{2592, 6}, {2592, 17}},
		ServiceNetrisk:         {{1799, 6}, {1799, 17}},
		ServiceNetrixSftm:      {{2328, 6}, {2328, 17}},
		ServiceNetrjs1:         {{71, 6}, {71, 17}},
		ServiceNetrjs2:         {{72, 6}, {72, 17}},
		ServiceNetrjs3:         {{73, 6}, {73, 17}},
		ServiceNetrjs4:         {{74, 6}, {74, 17}},
		ServiceNetrockey6:      {{4425, 6}, {4425, 17}},
		ServiceNetscDev:        {{155, 6}, {155, 17}},
		ServiceNetscProd:       {{154, 6}, {154, 17}},
		ServiceNetscript:       {{4118, 6}, {4118, 17}},
		ServiceNetserialext1:   {{16360, 6}, {16360, 17}},
		ServiceNetserialext2:   {{16361, 6}, {16361, 17}},
		ServiceNetserialext3:   {{16367, 6}, {16367, 17}},
		ServiceNetserialext4:   {{16368, 6}, {16368, 17}},
		ServiceNetspeakAcd:     {{21848, 6}, {21848, 17}},
		ServiceNetspeakCps:     {{21849, 6}, {21849, 17}},
		ServiceNetspeakCs:      {{21847, 6}, {21847, 17}},
		ServiceNetspeakIs:      {{21846, 6}, {21846, 17}},
		ServiceNetstat:         {{15, 6}},
		ServiceNetsteward:      {{2810, 6}, {2810, 17}},
		ServiceNetsupport:      {{5405, 6}, {5405, 17}},
		ServiceNetsupport2:     {{5421, 6}, {5421, 17}},
		ServiceNettest:         {{4138, 6}, {4138, 17}},
		ServiceNettgainNms:     {{1879, 6}, {1879, 17}},
		ServiceNetuitive:       {{1286, 6}, {1286, 17}},
		ServiceNetviewAix1:     {{1661, 6}, {1661, 17}},
		ServiceNetviewAix10:    {{1670, 6}, {1670, 17}},
		ServiceNetviewAix11:    {{1671, 6}, {1671, 17}},
		ServiceNetviewAix12:    {{1672, 6}, {1672, 17}},
		ServiceNetviewAix2:     {{1662, 6}, {1662, 17}},
		ServiceNetviewAix3:     {{1663, 6}, {1663, 17}},
		ServiceNetviewAix4:     {{1664, 6}, {1664, 17}},
		ServiceNetviewAix5:     {{1665, 6}, {1665, 17}},
		ServiceNetviewAix6:     {{1666, 6}, {1666, 17}},
		ServiceNetviewAix7:     {{1667, 6}, {1667, 17}},
		ServiceNetviewAix8:     {{1668, 6}, {1668, 17}},
		ServiceNetviewAix9:     {{1669, 6}, {1669, 17}},
		ServiceNetviewdm1:      {{729, 6}, {729, 17}},
		ServiceNetviewdm2:      {{730, 6}, {730, 17}},
		ServiceNetviewdm3:      {{731, 6}, {731, 17}},
		ServiceNetwall:         {{533, 17}, {533, 6}},
		ServiceNetwareCsp:      {{1366, 6}, {1366, 17}},
		ServiceNetwareIp:       {{396, 6}, {396, 17}},
		ServiceNetwatcherDb:    {{3204, 6}, {3204, 17}},
		ServiceNetwatcherMon:   {{3203, 6}, {3203, 17}},
		ServiceNetwaveApMgmt:   {{2411, 6}, {2411, 17}},
		ServiceNetwkpathengine: {{3209, 6}, {3209, 17}},
		ServiceNetworklens:     {{3409, 6}, {3409, 17}},
		ServiceNetworklenss:    {{3410, 6}, {3410, 17}},
		ServiceNetxAgent:       {{2586, 6}, {2586, 17}},
		ServiceNetxServer:      {{2585, 6}, {2585, 17}},
		ServiceNetxmsAgent:     {{4700, 6}, {4700, 17}},
		ServiceNetxmsMgmt:      {{4701, 6}, {4701, 17}},
		ServiceNetxmsSync:      {{4702, 6}, {4702, 17}},
		ServiceNeveroffline:    {{2614, 6}, {2614, 17}},
		ServiceNewRwho:         {{550, 6}, {550, 17}},
		ServiceNewacct:         {{100, 6}},
		ServiceNewbaySncMc:     {{16900, 6}, {16900, 17}},
		ServiceNewgenpay:       {{3165, 6}, {3165, 17}},
		ServiceNewheights:      {{2114, 6}, {2114, 17}},
		ServiceNewlixconfig:    {{2076, 6}, {2076, 17}},
		ServiceNewlixengine:    {{2075, 6}, {2075, 17}},
		ServiceNewlixreg:       {{2671, 6}, {2671, 17}},
		ServiceNewoak:          {{4001, 6}, {4001, 17}},
		ServiceNews:            {{2009, 6}},
		ServiceNewtonDock:      {{3679, 6}, {3679, 17}},
		ServiceNewwavesearch:   {{2058, 6}, {2058, 17}},
		ServiceNexentamv:       {{8457, 6}},
		ServiceNexgen:          {{6627, 6}, {6627, 17}},
		ServiceNexstorindltd:   {{2360, 6}, {2360, 17}},
		ServiceNextstep:        {{178, 6}, {178, 17}},
		ServiceNexusPortal:     {{4021, 6}, {4021, 17}},
		ServiceNfa:             {{1155, 6}, {1155, 17}},
		ServiceNfoldman:        {{7393, 6}, {7393, 17}},
		ServiceNfs:             {{2049, 6}, {2049, 17}, {2049, 132}},
		ServiceNfsdKeepalive:   {{1110, 17}},
		ServiceNfsrdma:         {{20049, 6}, {20049, 17}, {20049, 132}},
		ServiceNgUmds:          {{1690, 6}, {1690, 17}},
		ServiceNhci:            {{3842, 6}, {3842, 17}},
		ServiceNhserver:        {{2672, 6}, {2672, 17}},
		ServiceNiFtp:           {{47, 6}, {47, 17}},
		ServiceNiMail:          {{61, 6}, {61, 17}},
		ServiceNiVisaRemote:    {{3537, 6}, {3537, 17}},
		ServiceNicelink:        {{1095, 6}, {1095, 17}},
		ServiceNicetecMgmt:     {{2557, 6}, {2557, 17}},
		ServiceNicetecNmsvc:    {{2556, 6}, {2556, 17}},
		ServiceNicname:         {{43, 6}, {43, 17}},
		ServiceNiftyHmi:        {{4134, 6}, {4134, 17}},
		ServiceNilinkanalyst:   {{25902, 6}, {25902, 17}},
		ServiceNim:             {{1058, 6}, {1058, 17}},
		ServiceNimVdrshell:     {{6420, 6}, {6420, 17}},
		ServiceNimWan:          {{6421, 6}, {6421, 17}},
		ServiceNimaux:          {{3902, 6}, {3902, 17}},
		ServiceNimbusdb:        {{48004, 6}},
		ServiceNimbusdbctrl:    {{48005, 6}},
		ServiceNimcontroller:   {{48000, 6}, {48000, 17}},
		ServiceNimgtw:          {{48003, 6}, {48003, 17}},
		ServiceNimhub:          {{48002, 6}, {48002, 17}},
		ServiceNimreg:          {{1059, 6}, {1059, 17}},
		ServiceNimrodAgent:     {{1617, 6}, {1617, 17}},
		ServiceNimsh:           {{3901, 6}, {3901, 17}},
		ServiceNimspooler:      {{48001, 6}, {48001, 17}},
		ServiceNinaf:           {{5627, 6}, {5627, 17}},
		ServiceNinstall:        {{2150, 6}, {2150, 17}},
		ServiceNiobserver:      {{25901, 6}, {25901, 17}},
		ServiceNip:             {{376, 6}, {376, 17}},
		ServiceNiprobe:         {{25903, 6}, {25903, 17}},
		ServiceNirp:            {{4043, 6}, {4043, 17}},
		ServiceNitrogen:        {{7725, 6}, {7725, 17}},
		ServiceNjenetSsl:       {{2252, 6}, {2252, 17}},
		ServiceNkd:             {{1650, 6}, {1650, 17}},
		ServiceNlgData:         {{5299, 6}, {5299, 17}},
		ServiceNlogin:          {{758, 6}, {758, 17}},
		ServiceNlsTl:           {{7549, 6}, {7549, 17}},
		ServiceNmAssesAdmin:    {{3150, 6}, {3150, 17}},
		ServiceNmAssessor:      {{3151, 6}, {3151, 17}},
		ServiceNmGameAdmin:     {{3148, 6}, {3148, 17}},
		ServiceNmGameServer:    {{3149, 6}, {3149, 17}},
		ServiceNmap:            {{689, 6}, {689, 17}},
		ServiceNmasoverip:      {{1242, 6}, {1242, 17}},
		ServiceNmcDisc:         {{10810, 17}},
		ServiceNmea0183:        {{10110, 6}, {10110, 17}},
		ServiceNmeaOnenet:      {{10111, 17}},
		ServiceNmmp:            {{3649, 6}, {3649, 17}},
		ServiceNms:             {{1429, 6}, {1429, 17}},
		ServiceNmsDpnss:        {{2503, 6}, {2503, 17}},
		ServiceNms_topo_serv:   {{1486, 6}, {1486, 17}},
		ServiceNmsd:            {{1239, 6}, {1239, 17}},
		ServiceNmsigport:       {{2817, 6}, {2817, 17}},
		ServiceNmsp:            {{537, 6}, {537, 17}},
		ServiceNmsserver:       {{2244, 6}, {2244, 17}},
		ServiceNnp:             {{3780, 6}, {3780, 17}},
		ServiceNnsp:            {{433, 6}, {433, 17}},
		ServiceNntp:            {{119, 6}, {119, 17}},
		ServiceNntps:           {{563, 6}, {563, 17}},
		ServiceNoaaport:        {{2210, 6}, {2210, 17}},
		ServiceNoadmin:         {{1921, 6}, {1921, 17}},
		ServiceNoagent:         {{1917, 6}, {1917, 17}},
		ServiceNoitTransport:   {{43191, 6}},
		ServiceNokiaAnnCh1:     {{3405, 6}, {3405, 17}},
		ServiceNokiaAnnCh2:     {{3406, 6}, {3406, 17}},
		ServiceNomad:           {{5209, 6}},
		ServiceNomdb:           {{13786, 6}, {13786, 17}},
		ServiceNortonLambert:   {{2338, 6}, {2338, 17}},
		ServiceNotateit:        {{4803, 6}},
		ServiceNotateitDisc:    {{4803, 17}},
		ServiceNoteit:          {{4663, 6}, {4663, 17}},
		ServiceNoteshare:       {{8474, 6}, {8474, 17}},
		ServiceNotify:          {{773, 17}},
		ServiceNotify_srvr:     {{3016, 6}, {3016, 17}},
		ServiceNovarAlarm:      {{23401, 6}, {23401, 17}},
		ServiceNovarDbase:      {{23400, 6}, {23400, 17}},
		ServiceNovarGlobal:     {{23402, 6}, {23402, 17}},
		ServiceNovastorbakcup:  {{308, 6}, {308, 17}},
		ServiceNovation:        {{1322, 6}, {1322, 17}},
		ServiceNovellIpxCmd:    {{2645, 6}, {2645, 17}},
		ServiceNovellLu6Dot2:   {{1416, 6}, {1416, 17}},
		ServiceNovellZen:       {{2544, 6}, {2544, 17}},
		ServiceNowcontact:      {{3167, 6}, {3167, 17}},
		ServiceNpdbgmngr:       {{2293, 6}, {2293, 17}},
		ServiceNpdsTracker:     {{3680, 6}, {3680, 17}},
		ServiceNpepMessaging:   {{2868, 6}, {2868, 17}},
		ServiceNpmp:            {{8450, 6}, {8450, 17}},
		ServiceNpmpGui:         {{611, 6}, {611, 17}},
		ServiceNpmpLocal:       {{610, 6}, {610, 17}},
		ServiceNpmpTrap:        {{609, 6}, {609, 17}},
		ServiceNpp:             {{92, 6}, {92, 17}},
		ServiceNppmp:           {{3476, 6}, {3476, 17}},
		ServiceNpqesTest:       {{4703, 6}},
		ServiceNpsp:            {{4088, 6}},
		ServiceNqs:             {{607, 6}, {607, 17}},
		ServiceNrcabqLm:        {{1458, 6}, {1458, 17}},
		ServiceNs:              {{760, 17}},
		ServiceNsCfgServer:     {{3266, 6}, {3266, 17}},
		ServiceNsServer:        {{5415, 6}, {5415, 17}},
		ServiceNscCcs:          {{2604, 6}, {2604, 17}},
		ServiceNscPosa:         {{2605, 6}, {2605, 17}},
		ServiceNsdeepfreezectl: {{7724, 6}, {7724, 17}},
		ServiceNsesrvr:         {{9988, 6}},
		ServiceNsiiops:         {{261, 6}, {261, 17}},
		ServiceNsjtpCtrl:       {{1687, 6}, {1687, 17}},
		ServiceNsjtpData:       {{1688, 6}, {1688, 17}},
		ServiceNsp:             {{5012, 6}, {5012, 17}},
		ServiceNsrmp:           {{359, 6}, {359, 17}},
		ServiceNsrp:            {{7170, 6}, {7170, 17}},
		ServiceNss:             {{4159, 6}, {4159, 17}},
		ServiceNssRouting:      {{159, 6}, {159, 17}},
		ServiceNssagentmgr:     {{4454, 6}, {4454, 17}},
		ServiceNssalertmgr:     {{4453, 6}, {4453, 17}},
		ServiceNssocketport:    {{3522, 6}, {3522, 17}},
		ServiceNsstp:           {{1036, 6}, {1036, 17}},
		ServiceNst:             {{4687, 6}, {4687, 17}},
		ServiceNswFe:           {{27, 6}, {27, 17}},
		ServiceNsws:            {{3049, 6}, {3049, 17}},
		ServiceNtaDs:           {{7544, 6}, {7544, 17}},
		ServiceNtaUs:           {{7545, 6}, {7545, 17}},
		ServiceNtalk:           {{518, 17}, {518, 6}},
		ServiceNtp:             {{123, 6}, {123, 17}},
		ServiceNuauth:          {{4129, 6}, {4129, 17}},
		ServiceNucleus:         {{1463, 6}, {1463, 17}},
		ServiceNucleusSand:     {{1201, 6}, {1201, 17}},
		ServiceNufw:            {{4128, 6}, {4128, 17}},
		ServiceNupaperSs:       {{12121, 6}, {12121, 17}},
		ServiceNut:             {{3493, 6}, {3493, 17}},
		ServiceNuts_bootp:      {{4133, 6}, {4133, 17}},
		ServiceNuts_dem:        {{4132, 6}, {4132, 17}},
		ServiceNuxsl:           {{5991, 6}, {5991, 17}},
		ServiceNvc:             {{8711, 6}},
		ServiceNvcnet:          {{3999, 6}, {3999, 17}},
		ServiceNvd:             {{2184, 6}, {2184, 17}},
		ServiceNvmsgd:          {{3519, 6}},
		ServiceNwLicense:       {{3697, 6}, {3697, 17}},
		ServiceNxedit:          {{126, 6}, {126, 17}},
		ServiceNxlmd:           {{28000, 6}, {28000, 17}},
		ServiceO2serverPort:    {{1894, 6}, {1894, 17}},
		ServiceOaSystem:        {{8022, 6}, {8022, 17}},
		ServiceObex:            {{650, 6}, {650, 17}},
		ServiceObjcall:         {{94, 6}, {94, 17}},
		ServiceObjectiveDbc:    {{1388, 6}, {1388, 17}},
		ServiceObjectmanager:   {{2038, 6}, {2038, 17}},
		ServiceObrpd:           {{1092, 6}, {1092, 17}},
		ServiceOcLm:            {{1448, 6}, {1448, 17}},
		ServiceOcbinder:        {{183, 6}, {183, 17}},
		ServiceOceSnmpTrap:     {{2697, 6}, {2697, 17}},
		ServiceOceansoftLm:     {{1466, 6}, {1466, 17}},
		ServiceOcs_amu:         {{429, 6}, {429, 17}},
		ServiceOcs_cmu:         {{428, 6}, {428, 17}},
		ServiceOcserver:        {{184, 6}, {184, 17}},
		ServiceOctopus:         {{10008, 6}, {10008, 17}},
		ServiceOdbcpathway:     {{9628, 6}, {9628, 17}},
		ServiceOdetteFtp:       {{3305, 6}, {3305, 17}},
		ServiceOdetteFtps:      {{6619, 6}, {6619, 17}},
		ServiceOdeumservlink:   {{3523, 6}, {3523, 17}},
		ServiceOdiPort:         {{3187, 6}, {3187, 17}},
		ServiceOdmr:            {{366, 6}, {366, 17}},
		ServiceOdnCastraq:      {{2498, 6}, {2498, 17}},
		ServiceOdnsp:           {{9966, 6}, {9966, 17}},
		ServiceOdsi:            {{1308, 6}, {1308, 17}},
		ServiceOemAgent:        {{3872, 6}, {3872, 17}},
		ServiceOemcacaoJmxmp:   {{11172, 6}},
		ServiceOemcacaoRmi:     {{11174, 6}},
		ServiceOemcacaoWebsvc:  {{11175, 6}},
		ServiceOfficeTools:     {{7789, 6}, {7789, 17}},
		ServiceOfficelink2000:  {{3320, 6}, {3320, 17}},
		ServiceOfsd:            {{2322, 6}, {2322, 17}},
		ServiceOgsClient:       {{9007, 17}},
		ServiceOgsServer:       {{9008, 6}},
		ServiceOhimsrv:         {{506, 6}, {506, 17}},
		ServiceOhmtrigger:      {{4732, 17}},
		ServiceOhsc:            {{18186, 6}, {18186, 17}},
		ServiceOi2000:          {{2364, 6}, {2364, 17}},
		ServiceOidocsvc:        {{4142, 6}, {4142, 17}},
		ServiceOidsr:           {{4143, 6}, {4143, 17}},
		ServiceOirtgsvc:        {{4141, 6}, {4141, 17}},
		ServiceOlhost:          {{2661, 6}, {2661, 17}},
		ServiceOlsr:            {{698, 6}, {698, 17}},
		ServiceOlsv:            {{1160, 6}, {1160, 17}},
		ServiceOmaDcdocbs:      {{7278, 6}, {7278, 17}},
		ServiceOmaIlp:          {{7276, 6}, {7276, 17}},
		ServiceOmaIlpS:         {{7277, 6}, {7277, 17}},
		ServiceOmaMlp:          {{9210, 6}, {9210, 17}},
		ServiceOmaMlpS:         {{9211, 6}, {9211, 17}},
		ServiceOmaRlp:          {{7273, 6}, {7273, 17}},
		ServiceOmaRlpS:         {{7274, 6}, {7274, 17}},
		ServiceOmaUlp:          {{7275, 6}, {7275, 17}},
		ServiceOmabcastltkm:    {{4359, 6}, {4359, 17}},
		ServiceOmasgport:       {{4090, 6}, {4090, 17}},
		ServiceOmginitialrefs:  {{900, 6}, {900, 17}},
		ServiceOmhs:            {{5723, 6}, {5723, 17}},
		ServiceOmirr:           {{808, 6}, {808, 17}},
		ServiceOmnilinkPort:    {{3904, 6}, {3904, 17}},
		ServiceOmnisky:         {{2056, 6}, {2056, 17}},
		ServiceOmnivision:      {{1135, 6}, {1135, 17}},
		ServiceOmnivisionesx:   {{4395, 6}, {4395, 17}},
		ServiceOms:             {{4662, 6}, {4662, 17}},
		ServiceOmsNonsecure:    {{5102, 6}, {5102, 17}},
		ServiceOmscontact:      {{4161, 6}, {4161, 17}},
		ServiceOmsdk:           {{5724, 6}, {5724, 17}},
		ServiceOmserv:          {{764, 6}, {764, 17}},
		ServiceOmstopology:     {{4162, 6}, {4162, 17}},
		ServiceOmviagent:       {{4429, 6}},
		ServiceOmviserver:      {{4428, 6}},
		ServiceOnbaseDds:       {{2185, 6}, {2185, 17}},
		ServiceOnehomeHelp:     {{2199, 6}, {2199, 17}},
		ServiceOnehomeRemote:   {{2198, 6}, {2198, 17}},
		ServiceOnesaf:          {{3244, 6}, {3244, 17}},
		ServiceOnmux:           {{417, 6}, {417, 17}},
		ServiceOnpsocket:       {{5014, 17}},
		ServiceOnscreen:        {{5080, 6}, {5080, 17}},
		ServiceOntime:          {{1622, 6}, {1622, 17}},
		ServiceOntobroker:      {{2267, 6}, {2267, 17}},
		ServiceOobWsHttp:       {{623, 6}},
		ServiceOobWsHttps:      {{664, 6}},
		ServiceOpProbe:         {{7030, 6}, {7030, 17}},
		ServiceOpalisRbtIpc:    {{5314, 6}, {5314, 17}},
		ServiceOpalisRdv:       {{536, 6}, {536, 17}},
		ServiceOpalisRobot:     {{314, 6}, {314, 17}},
		ServiceOpcJobStart:     {{423, 6}, {423, 17}},
		ServiceOpcJobTrack:     {{424, 6}, {424, 17}},
		ServiceOpconXps:        {{3100, 6}, {3100, 17}},
		ServiceOpcuaTcp:        {{4840, 6}},
		ServiceOpcuaTls:        {{4843, 6}, {4843, 17}},
		ServiceOpcuaUdp:        {{4840, 17}},
		ServiceOpencm:          {{3434, 6}, {3434, 17}},
		ServiceOpencore:        {{4089, 6}, {4089, 17}},
		ServiceOpendeploy:      {{20014, 6}, {20014, 17}},
		ServiceOpenhpid:        {{4743, 6}, {4743, 17}},
		ServiceOpenmail:        {{5729, 6}, {5729, 17}},
		ServiceOpenmailg:       {{5755, 6}, {5755, 17}},
		ServiceOpenmailns:      {{5766, 6}, {5766, 17}},
		ServiceOpenmailpxy:     {{5768, 6}, {5768, 17}},
		ServiceOpenmath:        {{1473, 6}, {1473, 17}},
		ServiceOpennl:          {{1258, 6}, {1258, 17}},
		ServiceOpennlVoice:     {{1259, 6}, {1259, 17}},
		ServiceOpenport:        {{260, 6}, {260, 17}},
		ServiceOpenqueue:       {{8764, 6}, {8764, 17}},
		ServiceOpenremoteCtrl:  {{8688, 6}},
		ServiceOpenstackId:     {{35357, 6}},
		ServiceOpentable:       {{2368, 6}, {2368, 17}},
		ServiceOpentrac:        {{3855, 6}, {3855, 17}},
		ServiceOpenvmsSysipc:   {{557, 6}, {557, 17}},
		ServiceOpenvpn:         {{1194, 6}, {1194, 17}},
		ServiceOpenwebnet:      {{20005, 6}, {20005, 17}},
		ServiceOpequusServer:   {{2400, 6}, {2400, 17}},
		ServiceOpiSock:         {{7429, 6}, {7429, 17}},
		ServiceOpnetSmp:        {{3433, 6}, {3433, 17}},
		ServiceOpsecCvp:        {{18181, 6}, {18181, 17}},
		ServiceOpsecEla:        {{18187, 6}, {18187, 17}},
		ServiceOpsecLea:        {{18184, 6}, {18184, 17}},
		ServiceOpsecOmi:        {{18185, 6}, {18185, 17}},
		ServiceOpsecSam:        {{18183, 6}, {18183, 17}},
		ServiceOpsecUaa:        {{19191, 6}, {19191, 17}},
		ServiceOpsecUfp:        {{18182, 6}, {18182, 17}},
		ServiceOpsessionClnt:   {{3303, 6}, {3303, 17}},
		ServiceOpsessionPrxy:   {{3307, 6}, {3307, 17}},
		ServiceOpsessionSrvr:   {{3304, 6}, {3304, 17}},
		ServiceOpsmgr:          {{1270, 6}, {1270, 17}},
		ServiceOpsviewEnvoy:    {{4125, 6}, {4125, 17}},
		ServiceOpswagent:       {{3976, 6}, {3976, 17}},
		ServiceOpswmanager:     {{3977, 6}, {3977, 17}},
		ServiceOptechPort1Lm:   {{2237, 6}, {2237, 17}},
		ServiceOptikaEmedia:    {{1829, 6}, {1829, 17}},
		ServiceOptilogic:       {{2435, 6}, {2435, 17}},
		ServiceOptimaVnet:      {{1051, 6}, {1051, 17}},
		ServiceOptiwaveLm:      {{2524, 6}, {2524, 17}},
		ServiceOptocontrol:     {{22001, 6}, {22001, 17}},
		ServiceOptohost002:     {{22002, 6}, {22002, 17}},
		ServiceOptohost003:     {{22003, 6}, {22003, 17}},
		ServiceOptohost004:     {{22004, 6}, {22004, 17}},
		ServiceOptohost005:     {{22005, 6}, {22005, 17}},
		ServiceOpusServices:    {{3718, 6}, {3718, 17}},
		ServiceOraLm:           {{1446, 6}, {1446, 17}},
		ServiceOraOap:          {{5575, 6}},
		ServiceOracle:          {{2005, 17}},
		ServiceOracleEm1:       {{1748, 6}, {1748, 17}},
		ServiceOracleEm2:       {{1754, 6}, {1754, 17}},
		ServiceOracleOms:       {{1159, 6}, {1159, 17}},
		ServiceOracleVp1:       {{1809, 6}, {1809, 17}},
		ServiceOracleVp2:       {{1808, 6}, {1808, 17}},
		ServiceOracleasHttps:   {{7443, 6}, {7443, 17}},
		ServiceOraclenames:     {{1575, 6}, {1575, 17}},
		ServiceOraclenet8cman:  {{1630, 6}, {1630, 17}},
		ServiceOrbiter:         {{2398, 6}, {2398, 17}},
		ServiceOrbixCfgSsl:     {{3078, 6}, {3078, 17}},
		ServiceOrbixConfig:     {{3076, 6}, {3076, 17}},
		ServiceOrbixLocSsl:     {{3077, 6}, {3077, 17}},
		ServiceOrbixLocator:    {{3075, 6}, {3075, 17}},
		ServiceOrbixd:          {{1570, 6}, {1570, 17}},
		ServiceOrbplusIiop:     {{1597, 6}, {1597, 17}},
		ServiceOrdinoxDbase:    {{3355, 6}, {3355, 17}},
		ServiceOrdinoxServer:   {{3274, 6}, {3274, 17}},
		ServiceOrigoNative:     {{3001, 6}},
		ServiceOrigoSync:       {{11103, 6}},
		ServiceOrion:           {{2407, 6}, {2407, 17}},
		ServiceOrionRmiReg:     {{2413, 6}, {2413, 17}},
		ServiceOrtecDisc:       {{40853, 17}},
		ServiceOsLicman:        {{1384, 6}, {1384, 17}},
		ServiceOsaut:           {{6679, 6}, {6679, 17}},
		ServiceOsbSd:           {{400, 6}, {400, 17}},
		ServiceOsdcp:           {{3432, 6}, {3432, 17}},
		ServiceOsmAppsrvr:      {{9990, 6}, {9990, 17}},
		ServiceOsmOev:          {{9991, 6}, {9991, 17}},
		ServiceOsmosisAeea:     {{3034, 6}, {3034, 17}},
		ServiceOsp:             {{5045, 6}},
		ServiceOspfLite:        {{8899, 6}, {8899, 17}},
		ServiceOsuNms:          {{192, 6}, {192, 17}},
		ServiceOtlp:            {{6951, 6}, {6951, 17}},
		ServiceOtmp:            {{29167, 6}, {29167, 17}},
		ServiceOtp:             {{9390, 6}},
		ServiceOtpatch:         {{2936, 6}, {2936, 17}},
		ServiceOtt:             {{2428, 6}, {2428, 17}},
		ServiceOttp:            {{2951, 6}, {2951, 17}},
		ServiceOtv:             {{8472, 6}, {8472, 17}},
		ServiceOutlaws:         {{5310, 6}, {5310, 17}},
		ServiceOvNnmWebsrv:     {{3443, 6}, {3443, 17}},
		ServiceOvalarmsrv:      {{2953, 6}, {2953, 17}},
		ServiceOvalarmsrvCmd:   {{2954, 6}, {2954, 17}},
		ServiceOvbus:           {{7501, 6}, {7501, 17}},
		ServiceOveadmgr:        {{7427, 6}, {7427, 17}},
		ServiceOvhpas:          {{7510, 6}, {7510, 17}},
		ServiceOvladmgr:        {{7428, 6}, {7428, 17}},
		ServiceOvobs:           {{30999, 6}, {30999, 17}},
		ServiceOvrimosdbman:    {{2956, 6}, {2956, 17}},
		ServiceOvsamDAgent:     {{3870, 6}, {3870, 17}},
		ServiceOvsamMgmt:       {{3869, 6}, {3869, 17}},
		ServiceOvsessionmgr:    {{2389, 6}, {2389, 17}},
		ServiceOvtopmd:         {{2532, 6}, {2532, 17}},
		ServiceOvwdb:           {{2447, 6}, {2447, 17}},
		ServiceOwampControl:    {{861, 6}, {861, 17}},
		ServiceOwserver:        {{4304, 6}, {4304, 17}},
		ServiceP25cai:          {{6082, 17}},
		ServiceP2pcommunity:    {{3955, 6}, {3955, 17}},
		ServiceP2pgroup:        {{3587, 6}, {3587, 17}},
		ServiceP2pq:            {{1981, 6}, {1981, 17}},
		ServiceP4pPortal:       {{6671, 6}, {6671, 17}},
		ServiceP6ssmc:          {{4311, 6}},
		ServicePNetLocal:       {{34378, 6}, {34378, 17}},
		ServicePNetRemote:      {{34379, 6}, {34379, 17}},
		ServicePacerforum:      {{1480, 6}, {1480, 17}},
		ServicePacmand:         {{1307, 6}, {1307, 17}},
		ServicePacom:           {{3435, 6}, {3435, 17}},
		ServicePadl2sim:        {{5236, 6}, {5236, 17}},
		ServicePads:            {{7237, 6}},
		ServicePafecLm:         {{7511, 6}, {7511, 17}},
		ServicePagingPort:      {{3771, 6}, {3771, 17}},
		ServicePagoServices1:   {{30001, 6}, {30001, 17}},
		ServicePagoServices2:   {{30002, 6}, {30002, 17}},
		ServicePalace1:         {{9992, 6}, {9992, 17}},
		ServicePalace2:         {{9993, 6}, {9993, 17}},
		ServicePalace3:         {{9994, 6}, {9994, 17}},
		ServicePalace4:         {{9995, 6}, {9995, 17}},
		ServicePalace5:         {{9996, 6}, {9996, 17}},
		ServicePalace6:         {{9997, 6}, {9997, 17}},
		ServicePalcomDisc:      {{6657, 17}},
		ServicePammratc:        {{1632, 6}, {1632, 17}},
		ServicePammrpc:         {{1633, 6}, {1633, 17}},
		ServicePana:            {{716, 17}},
		ServicePanagolinIdent:  {{9021, 6}, {9021, 17}},
		ServicePanasas:         {{3095, 6}, {3095, 17}},
		ServicePandoPub:        {{7680, 6}, {7680, 17}},
		ServicePandoSec:        {{8276, 6}, {8276, 17}},
		ServicePangolinLaser:   {{3348, 6}, {3348, 17}},
		ServiceParadym31port:   {{1864, 6}, {1864, 17}},
		ServiceParagent:        {{9022, 6}, {9022, 17}},
		ServiceParallel:        {{4989, 6}, {4989, 17}},
		ServiceParkAgent:       {{5431, 6}, {5431, 17}},
		ServiceParliant:        {{4681, 6}, {4681, 17}},
		ServiceParsecGame:      {{6582, 6}, {6582, 17}},
		ServiceParsecMaster:    {{6580, 6}, {6580, 17}},
		ServiceParsecPeer:      {{6581, 6}, {6581, 17}},
		ServicePartimage:       {{4025, 6}, {4025, 17}},
		ServicePassgo:          {{511, 6}, {511, 17}},
		ServicePassgoTivoli:    {{627, 6}, {627, 17}},
		ServicePasswd_server:   {{752, 17}},
		ServicePasswordChg:     {{586, 6}, {586, 17}},
		ServicePasswrdPolicy:   {{1333, 6}, {1333, 17}},
		ServicePatrol:          {{8160, 6}, {8160, 17}},
		ServicePatrolColl:      {{6162, 6}, {6162, 17}},
		ServicePatrolIsm:       {{6161, 6}, {6161, 17}},
		ServicePatrolMqGm:      {{2664, 6}, {2664, 17}},
		ServicePatrolMqNm:      {{2665, 6}, {2665, 17}},
		ServicePatrolSnmp:      {{8161, 6}, {8161, 17}},
		ServicePatrolview:      {{4097, 6}, {4097, 17}},
		ServicePawserv:         {{345, 6}, {345, 17}},
		ServicePayPerView:      {{1564, 6}, {1564, 17}},
		ServicePaycashOnline:   {{8128, 6}, {8128, 17}},
		ServicePaycashWbp:      {{8129, 6}, {8129, 17}},
		ServicePayrouter:       {{1246, 6}, {1246, 17}},
		ServicePcMtaAddrmap:    {{2246, 6}, {2246, 17}},
		ServicePcTelecommute:   {{2299, 6}, {2299, 17}},
		ServicePcanywheredata:  {{5631, 6}, {5631, 17}},
		ServicePcanywherestat:  {{5632, 6}, {5632, 17}},
		ServicePccImagePort:    {{3892, 6}, {3892, 17}},
		ServicePccMfp:          {{2256, 6}, {2256, 17}},
		ServicePcep:            {{4189, 6}},
		ServicePciaRxpB:        {{1332, 6}, {1332, 17}},
		ServicePciarray:        {{1552, 6}, {1552, 17}},
		ServicePcihreq:         {{3085, 6}, {3085, 17}},
		ServicePcleInfex:       {{3189, 6}, {3189, 17}},
		ServicePclemultimedia:  {{2558, 6}, {2558, 17}},
		ServicePcmailSrv:       {{158, 6}, {158, 17}},
		ServicePcmkRemote:      {{3121, 6}},
		ServicePcoip:           {{4172, 6}, {4172, 17}},
		ServicePconnectmgr:     {{1562, 6}, {1562, 17}},
		ServicePcp:             {{5350, 17}},
		ServicePcpMulticast:    {{5350, 6}},
		ServicePcptcpservice:   {{4182, 6}, {4182, 17}},
		ServicePcsPcw:          {{2566, 6}, {2566, 17}},
		ServicePcsSfUiMan:      {{6655, 6}},
		ServicePcsyncHttp:      {{8444, 6}, {8444, 17}},
		ServicePcsyncHttps:     {{8443, 6}, {8443, 17}},
		ServicePctrader:        {{3048, 6}, {3048, 17}},
		ServicePcttunnell:      {{2274, 6}, {2274, 17}},
		ServicePdAdmin:         {{9597, 6}, {9597, 17}},
		ServicePdaData:         {{3253, 6}, {3253, 17}},
		ServicePdaGate:         {{4012, 6}, {4012, 17}},
		ServicePdaSys:          {{3254, 6}, {3254, 17}},
		ServicePdap:            {{344, 6}, {344, 17}},
		ServicePdapNp:          {{1526, 6}, {1526, 17}},
		ServicePdb:             {{3033, 6}, {3033, 17}},
		ServicePdefmns:         {{16311, 6}, {16311, 17}},
		ServicePdnet:           {{2843, 6}, {2843, 17}},
		ServicePdp:             {{1675, 6}, {1675, 17}},
		ServicePdps:            {{1314, 6}, {1314, 17}},
		ServicePdrncs:          {{3299, 6}, {3299, 17}},
		ServicePds:             {{9595, 6}, {9595, 17}},
		ServicePdtp:            {{6086, 6}, {6086, 17}},
		ServicePduncs:          {{16310, 6}, {16310, 17}},
		ServicePeMike:          {{1305, 6}, {1305, 17}},
		ServicePearldocXact:    {{1980, 6}, {1980, 17}},
		ServicePeerbookPort:    {{3135, 6}, {3135, 17}},
		ServicePeerwire:        {{9104, 6}, {9104, 17}},
		ServicePegasus:         {{9278, 6}, {9278, 17}},
		ServicePegasusCtl:      {{9279, 6}, {9279, 17}},
		ServicePegboard:        {{1357, 6}, {1357, 17}},
		ServicePehelp:          {{2307, 6}, {2307, 17}},
		ServicePentboxSim:      {{6817, 6}},
		ServicePeocoll:         {{9631, 6}},
		ServicePeoctlr:         {{9630, 6}},
		ServicePeport:          {{1449, 6}, {1449, 17}},
		ServicePerfPort:        {{1995, 6}, {1995, 17}},
		ServicePerfd:           {{5227, 6}, {5227, 17}},
		ServicePerimlan:        {{4075, 6}, {4075, 17}},
		ServicePeriscope:       {{1230, 6}, {1230, 17}},
		ServicePermabitCs:      {{5312, 6}, {5312, 17}},
		ServicePerrla:          {{4313, 6}},
		ServicePersona:         {{1916, 6}, {1916, 17}},
		ServicePersonalAgent:   {{5555, 6}, {5555, 17}},
		ServicePersonalLink:    {{281, 6}, {281, 17}},
		ServicePersonalos001:   {{3557, 6}, {3557, 17}},
		ServicePersonnel:       {{3109, 6}, {3109, 17}},
		ServicePftp:            {{662, 6}, {662, 17}},
		ServicePfuPrcallback:   {{3208, 6}, {3208, 17}},
		ServicePgbouncer:       {{6432, 6}},
		ServicePgpkeyserver:    {{11371, 6}, {11371, 17}},
		ServicePgps:            {{9280, 6}, {9280, 17}},
		ServicePh:              {{481, 6}, {481, 17}},
		ServicePharmasoft:      {{1779, 6}, {1779, 17}},
		ServicePharos:          {{4443, 6}, {4443, 17}},
		ServicePhilipsVc:       {{583, 6}, {583, 17}},
		ServicePhoenixRpc:      {{3347, 6}, {3347, 17}},
		ServicePhonebook:       {{767, 6}, {767, 17}},
		ServicePhonexPort:      {{3177, 6}, {3177, 17}},
		ServicePhoturis:        {{468, 6}, {468, 17}},
		ServicePhrelay:         {{4868, 6}, {4868, 17}},
		ServicePhrelaydbg:      {{4869, 6}, {4869, 17}},
		ServicePiccolo:         {{2787, 6}, {2787, 17}},
		ServicePichat:          {{9009, 6}, {9009, 17}},
		ServicePicknfs:         {{1598, 6}, {1598, 17}},
		ServicePicodbc:         {{1603, 6}, {1603, 17}},
		ServicePictrography:    {{1280, 6}, {1280, 17}},
		ServicePimPort:         {{8471, 6}, {8471, 132}},
		ServicePimRpDisc:       {{496, 6}, {496, 17}},
		ServicePingPong:        {{3010, 17}},
		ServicePinghgl:         {{4306, 6}, {4306, 17}},
		ServicePip:             {{321, 6}, {321, 17}},
		ServicePipe_server:     {{2010, 17}},
		ServicePipes:           {{1465, 6}, {1465, 17}},
		ServicePiranha1:        {{4600, 6}, {4600, 17}},
		ServicePiranha2:        {{4601, 6}, {4601, 17}},
		ServicePirp:            {{553, 6}, {553, 17}},
		ServicePitVpn:          {{2865, 6}, {2865, 17}},
		ServicePjlink:          {{4352, 6}, {4352, 17}},
		ServicePk:              {{5272, 6}, {5272, 17}},
		ServicePkElectronics:   {{2634, 6}, {2634, 17}},
		ServicePkagent:         {{3118, 6}, {3118, 17}},
		ServicePkix3CaRa:       {{829, 6}, {829, 17}},
		ServicePkixCmc:         {{5318, 6}},
		ServicePkixTimestamp:   {{318, 6}, {318, 17}},
		ServicePktKrbIpsec:     {{1293, 6}, {1293, 17}},
		ServicePktcableCops:    {{2126, 6}, {2126, 17}},
		ServicePktcablemmcops:  {{3918, 6}, {3918, 17}},
		ServicePlato:           {{3285, 6}, {3285, 17}},
		ServicePlatoLm:         {{1819, 6}, {1819, 17}},
		ServicePlaysta2App:     {{4658, 6}, {4658, 17}},
		ServicePlaysta2Lob:     {{4659, 6}, {4659, 17}},
		ServicePlbservePort:    {{3933, 6}, {3933, 17}},
		ServicePlcyNetSvcs:     {{4351, 6}, {4351, 17}},
		ServicePlethora:        {{3480, 6}, {3480, 17}},
		ServicePlgproxy:        {{2790, 6}, {2790, 17}},
		ServicePluribus:        {{3469, 6}, {3469, 17}},
		ServicePlysrvHttp:      {{6770, 6}, {6770, 17}},
		ServicePlysrvHttps:     {{6771, 6}, {6771, 17}},
		ServicePmCmdsvr:        {{5112, 6}, {5112, 17}},
		ServicePmas:            {{4066, 6}, {4066, 17}},
		ServicePmcd:            {{44321, 6}, {44321, 17}},
		ServicePmcdproxy:       {{44322, 6}, {44322, 17}},
		ServicePmcp:            {{3821, 6}, {3821, 17}},
		ServicePmcs:            {{6355, 6}, {6355, 17}},
		ServicePmd:             {{7431, 6}, {7431, 17}},
		ServicePmdfmgt:         {{7633, 6}, {7633, 17}},
		ServicePmdmgr:          {{7426, 6}, {7426, 17}},
		ServicePmip6Cntl:       {{5436, 17}},
		ServicePmip6Data:       {{5437, 17}},
		ServicePmsmWebrctl:     {{2972, 6}, {2972, 17}},
		ServicePnRequester:     {{2717, 6}, {2717, 17}},
		ServicePnRequester2:    {{2718, 6}, {2718, 17}},
		ServicePnaconsultLm:    {{2937, 6}, {2937, 17}},
		ServicePnbs:            {{6124, 6}, {6124, 17}},
		ServicePnbscada:        {{3875, 6}, {3875, 17}},
		ServicePnetConn:        {{7797, 6}, {7797, 17}},
		ServicePnetEnc:         {{7798, 6}, {7798, 17}},
		ServicePnrpPort:        {{3540, 6}, {3540, 17}},
		ServicePns:             {{2487, 6}, {2487, 17}},
		ServicePolestar:        {{1060, 6}, {1060, 17}},
		ServicePolicyserver:    {{3055, 6}, {3055, 17}},
		ServicePop2:            {{109, 6}, {109, 17}},
		ServicePop3:            {{110, 6}, {110, 17}},
		ServicePop3s:           {{995, 6}, {995, 17}},
		ServicePoppassd:        {{106, 6}, {106, 17}},
		ServicePopupReminders:  {{7787, 6}, {7787, 17}},
		ServicePortgateAuth:    {{3710, 6}, {3710, 17}},
		ServicePostgres:        {{5432, 6}, {5432, 17}},
		ServicePovRay:          {{494, 6}, {494, 17}},
		ServicePowerAlertNsa:   {{4150, 6}, {4150, 17}},
		ServicePowerburst:      {{485, 6}, {485, 17}},
		ServicePowerclientcsf:  {{2443, 6}, {2443, 17}},
		ServicePowerexchange:   {{2480, 6}, {2480, 17}},
		ServicePowergemplus:    {{2899, 6}, {2899, 17}},
		ServicePowerguardian:   {{1777, 6}, {1777, 17}},
		ServicePoweronnud:      {{3168, 6}, {3168, 17}},
		ServicePowerschool:     {{5071, 6}, {5071, 17}},
		ServicePowwowClient:    {{13223, 6}, {13223, 17}},
		ServicePowwowServer:    {{13224, 6}, {13224, 17}},
		ServicePpactivation:    {{5134, 6}},
		ServicePpcontrol:       {{2505, 6}, {2505, 17}},
		ServicePpsms:           {{3967, 6}, {3967, 17}},
		ServicePpsuitemsg:      {{5863, 6}, {5863, 17}},
		ServicePptconference:   {{1711, 6}, {1711, 17}},
		ServicePptp:            {{1723, 6}, {1723, 17}},
		ServicePqLicMgmt:       {{2687, 6}, {2687, 17}},
		ServicePqsflows:        {{9640, 6}},
		ServicePqsp:            {{28001, 6}},
		ServicePrRegister:      {{4457, 6}, {4457, 17}},
		ServicePra_elmd:        {{1587, 6}, {1587, 17}},
		ServicePrat:            {{1264, 6}, {1264, 17}},
		ServicePrchatServer:    {{4456, 6}, {4456, 17}},
		ServicePrchatUser:      {{4455, 6}, {4455, 17}},
		ServicePreciseComm:     {{5630, 6}, {5630, 17}},
		ServicePreciseI3:       {{3607, 6}, {3607, 17}},
		ServicePreciseSft:      {{2315, 6}, {2315, 17}},
		ServicePreciseVip:      {{2924, 6}, {2924, 17}},
		ServicePredatarComms:   {{1753, 6}},
		ServicePrelude:         {{4690, 6}, {4690, 17}},
		ServicePresence:        {{5298, 6}, {5298, 17}},
		ServicePress:           {{3582, 6}, {3582, 17}},
		ServicePrexTcp:         {{4487, 6}},
		ServicePrgp:            {{7747, 6}, {7747, 17}},
		ServicePrimaserver:     {{6105, 6}, {6105, 17}},
		ServicePrintSrv:        {{170, 6}, {170, 17}},
		ServicePrinter:         {{515, 6}, {515, 17}},
		ServicePrinter_agent:   {{3396, 6}, {3396, 17}},
		ServicePrintopia:       {{10631, 6}},
		ServicePriorityECom:    {{2618, 6}, {2618, 17}},
		ServicePrismDeploy:     {{3133, 6}, {3133, 17}},
		ServicePrismiqPlugin:   {{3650, 6}, {3650, 17}},
		ServicePrivateark:      {{1858, 6}, {1858, 17}},
		ServicePrivatechat:     {{1735, 6}, {1735, 17}},
		ServicePrivatewire:     {{4449, 6}, {4449, 17}},
		ServicePrivilege:       {{2588, 6}, {2588, 17}},
		ServicePrivoxy:         {{8118, 6}, {8118, 17}},
		ServicePrizma:          {{2039, 6}, {2039, 17}},
		ServicePrmNm:           {{409, 6}, {409, 17}},
		ServicePrmNmNp:         {{1403, 6}, {1403, 17}},
		ServicePrmSm:           {{408, 6}, {408, 17}},
		ServicePrmSmNp:         {{1402, 6}, {1402, 17}},
		ServicePrnrequest:      {{3910, 6}, {3910, 17}},
		ServicePrnstatus:       {{3911, 6}, {3911, 17}},
		ServiceProEd:           {{8032, 6}, {8032, 17}},
		ServiceProactivate:     {{24678, 6}, {24678, 17}},
		ServiceProactivesrvr:   {{2722, 6}, {2722, 17}},
		ServiceProaxess:        {{3961, 6}, {3961, 17}},
		ServiceProcosLm:        {{3248, 6}, {3248, 17}},
		ServiceProdigyIntrnet:  {{1778, 6}, {1778, 17}},
		ServiceProductinfo:     {{1283, 6}, {1283, 17}},
		ServiceProfile:         {{136, 6}, {136, 17}},
		ServiceProfilemac:      {{4749, 6}, {4749, 17}},
		ServiceProfinetCm:      {{34964, 6}, {34964, 17}},
		ServiceProfinetRt:      {{34962, 6}, {34962, 17}},
		ServiceProfinetRtm:     {{34963, 6}, {34963, 17}},
		ServiceProgistics:      {{3973, 6}, {3973, 17}},
		ServiceProgrammar:      {{15999, 6}},
		ServiceProlink:         {{1678, 6}, {1678, 17}},
		ServiceProofd:          {{1093, 6}, {1093, 17}},
		ServicePropelMsgsys:    {{1268, 6}, {1268, 17}},
		ServiceProremote:       {{8183, 6}},
		ServiceProshare1:       {{1459, 6}, {1459, 17}},
		ServiceProshare2:       {{1460, 6}, {1460, 17}},
		ServiceProshareMc1:     {{1673, 6}, {1673, 17}},
		ServiceProshareMc2:     {{1674, 6}, {1674, 17}},
		ServiceProshareaudio:   {{5713, 6}, {5713, 17}},
		ServiceProsharedata:    {{5715, 6}, {5715, 17}},
		ServiceProsharenotify:  {{5717, 6}, {5717, 17}},
		ServiceProsharerequest: {{5716, 6}, {5716, 17}},
		ServiceProsharevideo:   {{5714, 6}, {5714, 17}},
		ServiceProspero:        {{191, 6}, {191, 17}},
		ServiceProsperoNp:      {{1525, 6}, {1525, 17}},
		ServiceProxim:          {{1732, 6}, {1732, 17}},
		ServiceProximaLm:       {{1445, 6}, {1445, 17}},
		ServiceProxyGateway:    {{2303, 6}, {2303, 17}},
		ServicePrp:             {{2091, 6}, {2091, 17}},
		ServicePrsvp:           {{3455, 6}, {3455, 17}},
		ServicePsAms:           {{3658, 6}, {3658, 17}},
		ServicePsbserver:       {{2350, 6}, {2350, 17}},
		ServicePsclMgt:         {{4312, 6}},
		ServicePscribe:         {{6163, 6}, {6163, 17}},
		ServicePscupd:          {{3453, 6}, {3453, 17}},
		ServicePsdbserver:      {{2355, 6}, {2355, 17}},
		ServicePserver:         {{3662, 6}, {3662, 17}},
		ServicePsiPtt:          {{4374, 6}},
		ServicePslicser:        {{4168, 6}, {4168, 17}},
		ServicePslserver:       {{2352, 6}, {2352, 17}},
		ServicePsmond:          {{1788, 6}, {1788, 17}},
		ServicePsprserver:      {{2354, 6}, {2354, 17}},
		ServicePspserver:       {{2353, 6}, {2353, 17}},
		ServicePsrserver:       {{2351, 6}, {2351, 17}},
		ServicePss:             {{7880, 6}, {7880, 17}},
		ServicePssc:            {{645, 6}, {645, 17}},
		ServicePt2Discover:     {{1101, 6}, {1101, 17}},
		ServicePtcnameservice:  {{597, 6}, {597, 17}},
		ServicePtkAlink:        {{3089, 6}, {3089, 17}},
		ServicePtp:             {{15740, 6}, {15740, 17}},
		ServicePtpEvent:        {{319, 6}, {319, 17}},
		ServicePtpGeneral:      {{320, 6}, {320, 17}},
		ServicePubliqareSync:   {{4329, 6}},
		ServicePulseaudio:      {{4713, 6}},
		ServicePulsonixnls:     {{6140, 6}, {6140, 17}},
		ServicePuparp:          {{998, 17}},
		ServicePurenoise:       {{663, 6}, {663, 17}},
		ServicePushns:          {{7997, 6}},
		ServicePvaccess:        {{5075, 6}},
		ServicePvsw:            {{2520, 6}, {2520, 17}},
		ServicePvswInet:        {{2441, 6}, {2441, 17}},
		ServicePvuniwien:       {{1081, 6}, {1081, 17}},
		ServicePvxpluscs:       {{4093, 6}, {4093, 17}},
		ServicePvxplusio:       {{4193, 6}},
		ServicePwdgen:          {{129, 6}, {129, 17}},
		ServicePwdis:           {{3735, 6}, {3735, 17}},
		ServicePwgippfax:       {{3951, 6}, {3951, 17}},
		ServicePwgpsi:          {{3800, 6}, {3800, 17}},
		ServicePwgwims:         {{4951, 6}, {4951, 17}},
		ServicePwrsevent:       {{2694, 6}, {2694, 17}},
		ServicePxcEpmap:        {{2434, 6}, {2434, 17}},
		ServicePxcNtfy:         {{3009, 6}, {3009, 17}},
		ServicePxcPin:          {{4005, 6}, {4005, 17}},
		ServicePxcRoid:         {{4004, 6}, {4004, 17}},
		ServicePxcSapxom:       {{2680, 6}, {2680, 17}},
		ServicePxcSplr:         {{4007, 6}, {4007, 17}},
		ServicePxcSplrFt:       {{4003, 6}, {4003, 17}},
		ServicePxcSpvr:         {{4006, 6}, {4006, 17}},
		ServicePxcSpvrFt:       {{4002, 6}, {4002, 17}},
		ServicePxe:             {{4011, 17}},
		ServicePyrrho:          {{5433, 6}, {5433, 17}},
		ServiceQ3ade:           {{7794, 6}, {7794, 17}},
		ServiceQ55Pcc:          {{1253, 6}, {1253, 17}},
		ServiceQadmifevent:     {{2462, 6}, {2462, 17}},
		ServiceQadmifoper:      {{2461, 6}, {2461, 17}},
		ServiceQbDbServer:      {{10160, 6}, {10160, 17}},
		ServiceQbdb:            {{8019, 6}, {8019, 17}},
		ServiceQbikgdp:         {{368, 6}, {368, 17}},
		ServiceQcp:             {{5082, 6}, {5082, 17}},
		ServiceQdb2service:     {{45825, 6}, {45825, 17}},
		ServiceQencp:           {{2120, 6}, {2120, 17}},
		ServiceQfp:             {{5083, 6}, {5083, 17}},
		ServiceQft:             {{189, 6}, {189, 17}},
		ServiceQftestLookup:    {{3543, 6}, {3543, 17}},
		ServiceQipAudup:        {{2765, 6}, {2765, 17}},
		ServiceQipLogin:        {{2366, 6}, {2366, 17}},
		ServiceQipMsgd:         {{2468, 6}, {2468, 17}},
		ServiceQipQdhcp:        {{2490, 6}, {2490, 17}},
		ServiceQkeLlcV3:        {{2523, 6}, {2523, 17}},
		ServiceQmqp:            {{628, 6}, {628, 17}},
		ServiceQmtp:            {{209, 6}, {209, 17}},
		ServiceQmvideo:         {{5689, 6}, {5689, 17}},
		ServiceQntsOrb:         {{1262, 6}, {1262, 17}},
		ServiceQnxnetman:       {{3385, 6}, {3385, 17}},
		ServiceQoSecure:        {{7913, 6}, {7913, 17}},
		ServiceQotd:            {{17, 6}, {17, 17}},
		ServiceQotps:           {{2724, 6}, {2724, 17}},
		ServiceQpasaAgent:      {{2612, 6}, {2612, 17}},
		ServiceQptlmd:          {{10055, 6}},
		ServiceQrh:             {{752, 6}},
		ServiceQsmGui:          {{1165, 6}, {1165, 17}},
		ServiceQsmProxy:        {{1164, 6}, {1164, 17}},
		ServiceQsmRemote:       {{1166, 6}, {1166, 17}},
		ServiceQsnetAssist:     {{4356, 6}, {4356, 17}},
		ServiceQsnetCond:       {{4357, 6}, {4357, 17}},
		ServiceQsnetNucl:       {{4358, 6}, {4358, 17}},
		ServiceQsnetTrans:      {{4354, 6}, {4354, 17}},
		ServiceQsnetWorkst:     {{4355, 6}, {4355, 17}},
		ServiceQsoft:           {{3059, 6}, {3059, 17}},
		ServiceQtServeradmin:   {{1220, 6}, {1220, 17}},
		ServiceQtmsBootstrap:   {{3850, 6}, {3850, 17}},
		ServiceQtp:             {{2935, 6}, {2935, 17}},
		ServiceQuaddb:          {{2497, 6}, {2497, 17}},
		ServiceQuailnet:        {{5464, 6}, {5464, 17}},
		ServiceQuake:           {{26000, 6}, {26000, 17}},
		ServiceQuantastor:      {{8153, 6}},
		ServiceQuartusTcl:      {{2589, 6}, {2589, 17}},
		ServiceQuasarServer:    {{3599, 6}, {3599, 17}},
		ServiceQubes:           {{1341, 6}, {1341, 17}},
		ServiceQuestAgent:      {{3843, 6}, {3843, 17}},
		ServiceQuestDataHub:    {{3566, 6}},
		ServiceQuestDisc:       {{7040, 17}},
		ServiceQuestVista:      {{7980, 6}, {7980, 17}},
		ServiceQuestdb2Lnchr:   {{5677, 6}, {5677, 17}},
		ServiceQuestnotify:     {{3554, 6}, {3554, 17}},
		ServiceQueueadm:        {{2230, 6}, {2230, 17}},
		ServiceQuickbooksrds:   {{3790, 6}, {3790, 17}},
		ServiceQuicksuite:      {{2900, 6}, {2900, 17}},
		ServiceQuosa:           {{4841, 6}, {4841, 17}},
		ServiceQuotad:          {{762, 6}, {762, 17}},
		ServiceQvr:             {{5028, 6}},
		ServiceQwave:           {{2177, 6}, {2177, 17}},
		ServiceRaadmin:         {{5676, 6}, {5676, 17}},
		ServiceRacf:            {{18136, 6}},
		ServiceRadanHttp:       {{8088, 6}, {8088, 17}},
		ServiceRadclientport:   {{3178, 6}, {3178, 17}},
		ServiceRadecCorp:       {{5430, 6}, {5430, 17}},
		ServiceRadio:           {{1595, 6}, {1595, 17}},
		ServiceRadioBc:         {{1596, 17}},
		ServiceRadioSm:         {{1596, 6}},
		ServiceRadius:          {{1812, 6}, {1812, 17}},
		ServiceRadiusAcct:      {{1813, 6}, {1813, 17}},
		ServiceRadiusDynauth:   {{3799, 6}, {3799, 17}},
		ServiceRadix:           {{2872, 6}, {2872, 17}},
		ServiceRadminPort:      {{4899, 6}, {4899, 17}},
		ServiceRadmind:         {{6222, 6}, {6222, 17}},
		ServiceRadpdf:          {{18104, 6}},
		ServiceRads:            {{12302, 6}},
		ServiceRadsec:          {{2083, 6}, {2083, 17}},
		ServiceRadwareRpm:      {{2188, 6}},
		ServiceRadwareRpmS:     {{2189, 6}},
		ServiceRadwizNmsSrv:    {{2736, 6}, {2736, 17}},
		ServiceRaidAc:          {{2012, 17}},
		ServiceRaidAm:          {{2007, 17}, {2013, 6}},
		ServiceRaidCc:          {{2011, 6}},
		ServiceRaidCd:          {{2006, 17}},
		ServiceRaidCs:          {{2015, 17}},
		ServiceRaidSf:          {{2014, 17}},
		ServiceRailgunWebaccl:  {{2408, 6}},
		ServiceRamp:            {{7227, 6}, {7227, 17}},
		ServiceRap:             {{38, 6}, {38, 17}},
		ServiceRapIp:           {{3813, 6}, {3813, 17}},
		ServiceRapListen:       {{1531, 6}, {1531, 17}},
		ServiceRapService:      {{1530, 6}, {1530, 17}},
		ServiceRapi:            {{2176, 6}, {2176, 17}},
		ServiceRapidbase:       {{1953, 6}, {1953, 17}},
		ServiceRapidmqCenter:   {{3093, 6}, {3093, 17}},
		ServiceRapidmqReg:      {{3094, 6}, {3094, 17}},
		ServiceRapidoIp:        {{2457, 6}, {2457, 17}},
		ServiceRaqmonPdu:       {{7744, 6}, {7744, 17}},
		ServiceRasadv:          {{9753, 6}, {9753, 17}},
		ServiceRatioAdp:        {{1108, 6}, {1108, 17}},
		ServiceRatl:            {{2449, 6}, {2449, 17}},
		ServiceRavehd:          {{4037, 6}, {4037, 17}},
		ServiceRavenRdp:        {{3533, 6}, {3533, 17}},
		ServiceRavenRmp:        {{3532, 6}, {3532, 17}},
		ServiceRaventbs:        {{2713, 6}, {2713, 17}},
		ServiceRaventdm:        {{2714, 6}, {2714, 17}},
		ServiceRawSerial:       {{2167, 6}, {2167, 17}},
		ServiceRaxaMgmt:        {{6099, 6}},
		ServiceRazor:           {{3555, 6}, {3555, 17}},
		ServiceRbakcup1:        {{2773, 6}, {2773, 17}},
		ServiceRbakcup2:        {{2774, 6}, {2774, 17}},
		ServiceRblcheckd:       {{3768, 6}, {3768, 17}},
		ServiceRbrDebug:        {{44553, 6}, {44553, 17}},
		ServiceRbrDiscovery:    {{3553, 6}, {3553, 17}},
		ServiceRbsystem:        {{5693, 6}},
		ServiceRbtSmc:          {{7870, 6}},
		ServiceRbtWanopt:       {{7810, 6}, {7810, 17}},
		ServiceRccHost:         {{2332, 6}, {2332, 17}},
		ServiceRcipItu:         {{2225, 6}, {2225, 132}},
		ServiceRcp:             {{469, 6}, {469, 17}},
		ServiceRcst:            {{3467, 6}, {3467, 17}},
		ServiceRcts:            {{2258, 6}, {2258, 17}},
		ServiceRda:             {{630, 6}, {630, 17}},
		ServiceRdbDbsDisp:      {{1571, 6}, {1571, 17}},
		ServiceRdcWhEos:        {{3142, 6}, {3142, 17}},
		ServiceRdlap:           {{2321, 6}, {2321, 17}},
		ServiceRdmTfs:          {{21553, 6}},
		ServiceRdmnetCtrl:      {{5569, 6}},
		ServiceRdmnetDevice:    {{5569, 17}},
		ServiceRdrmshc:         {{1075, 6}, {1075, 17}},
		ServiceRds:             {{1540, 6}, {1540, 17}},
		ServiceRds2:            {{1541, 6}, {1541, 17}},
		ServiceRdsIb:           {{18634, 6}, {18634, 17}},
		ServiceRdsIp:           {{18635, 6}, {18635, 17}},
		ServiceRe101:           {{1343, 6}, {1343, 17}},
		ServiceReConnProto:     {{1306, 6}, {1306, 17}},
		ServiceReMailCk:        {{50, 6}, {50, 17}},
		ServiceReachout:        {{43188, 6}, {43188, 17}},
		ServiceRealmRusd:       {{688, 6}, {688, 17}},
		ServiceRealsecure:      {{2998, 6}, {2998, 17}},
		ServiceRebol:           {{2997, 6}, {2997, 17}},
		ServiceRecipe:          {{2240, 6}, {2240, 17}},
		ServiceRecvrRc:         {{43000, 6}},
		ServiceRecvrRcDisc:     {{43000, 17}},
		ServiceRedstoneCpss:    {{2928, 6}, {2928, 17}},
		ServiceRedstorm_diag:   {{2349, 6}, {2349, 17}},
		ServiceRedstorm_find:   {{2347, 6}, {2347, 17}},
		ServiceRedstorm_info:   {{2348, 6}, {2348, 17}},
		ServiceRedstorm_join:   {{2346, 6}, {2346, 17}},
		ServiceRedwoodChat:     {{3032, 6}, {3032, 17}},
		ServiceReftek:          {{2543, 6}, {2543, 17}},
		ServiceRegistrar:       {{1712, 6}, {1712, 17}},
		ServiceRelief:          {{1353, 6}, {1353, 17}},
		ServiceRellpack:        {{2018, 17}},
		ServiceReloadConfig:    {{6084, 6}},
		ServiceRemcap:          {{4731, 6}},
		ServiceRemctl:          {{4373, 6}, {4373, 17}},
		ServiceRemographlm:     {{2373, 6}},
		ServiceRemoteAs:        {{1053, 6}, {1053, 17}},
		ServiceRemoteCollab:    {{2250, 6}, {2250, 17}},
		ServiceRemoteKis:       {{185, 6}, {185, 17}},
		ServiceRemoteWinsock:   {{1745, 6}, {1745, 17}},
		ServiceRemotedeploy:    {{3789, 6}, {3789, 17}},
		ServiceRemotefs:        {{556, 6}, {556, 17}},
		ServiceRemotewareUn:    {{2999, 6}, {2999, 17}},
		ServiceRepcmd:          {{641, 6}, {641, 17}},
		ServiceRepliweb:        {{2837, 6}, {2837, 17}},
		ServiceRepscmd:         {{653, 6}, {653, 17}},
		ServiceRepsvc:          {{6320, 6}, {6320, 17}},
		ServiceRes:             {{1942, 6}, {1942, 17}},
		ServiceResSap:          {{3163, 6}, {3163, 17}},
		ServiceResacommunity:   {{1154, 6}, {1154, 17}},
		ServiceRescap:          {{283, 6}, {283, 17}},
		ServiceResorcs:         {{4733, 6}},
		ServiceResource_mgr:    {{3019, 6}, {3019, 17}},
		ServiceResponselogic:   {{2886, 6}, {2886, 17}},
		ServiceResponsenet:     {{3045, 6}, {3045, 17}},
		ServiceRetp:            {{32811, 6}},
		ServiceRetrospect:      {{497, 6}, {497, 17}},
		ServiceRets:            {{6103, 6}, {6103, 17}},
		ServiceRetsSsl:         {{12109, 6}, {12109, 17}},
		ServiceReversion:       {{5842, 6}},
		ServiceRexecj:          {{8230, 6}, {8230, 17}},
		ServiceRfa:             {{4672, 6}, {4672, 17}},
		ServiceRfb:             {{5900, 6}, {5900, 17}},
		ServiceRfe:             {{5002, 6}, {5002, 17}},
		ServiceRfidRp1:         {{4684, 6}, {4684, 17}},
		ServiceRfio:            {{3147, 6}, {3147, 17}},
		ServiceRfmp:            {{2249, 6}, {2249, 17}},
		ServiceRfxLm:           {{1497, 6}, {1497, 17}},
		ServiceRgtp:            {{1431, 6}, {1431, 17}},
		ServiceRhpIibp:         {{1912, 6}, {1912, 17}},
		ServiceRibSlm:          {{3296, 6}, {3296, 17}},
		ServiceRicardoLm:       {{1522, 6}, {1522, 17}},
		ServiceRichCp:          {{2057, 6}, {2057, 17}},
		ServiceRid:             {{4590, 6}},
		ServiceRidgeway1:       {{2776, 6}, {2776, 17}},
		ServiceRidgeway2:       {{2777, 6}, {2777, 17}},
		ServiceRimfPs:          {{2209, 6}, {2209, 17}},
		ServiceRimsl:           {{2044, 6}, {2044, 17}},
		ServiceRipng:           {{521, 6}, {521, 17}},
		ServiceRis:             {{180, 6}, {180, 17}},
		ServiceRisCm:           {{748, 6}, {748, 17}},
		ServiceRise:            {{7473, 6}, {7473, 17}},
		ServiceRjcdbVcards:     {{9208, 6}, {9208, 17}},
		ServiceRje:             {{5, 6}, {5, 17}},
		ServiceRkbOscs:         {{1817, 6}, {1817, 17}},
		ServiceRlm:             {{5053, 6}},
		ServiceRlmAdmin:        {{5054, 6}},
		ServiceRlmDisc:         {{5053, 17}},
		ServiceRlp:             {{39, 6}, {39, 17}},
		ServiceRlzdbase:        {{635, 6}, {635, 17}},
		ServiceRmc:             {{657, 6}, {657, 17}},
		ServiceRmiactivation:   {{1098, 6}, {1098, 17}},
		ServiceRmiaux:          {{10990, 6}, {10990, 17}},
		ServiceRmiregistry:     {{1099, 6}, {1099, 17}},
		ServiceRmlnk:           {{2818, 6}, {2818, 17}},
		ServiceRmonitor:        {{560, 6}, {560, 17}},
		ServiceRmonitor_secure: {{5145, 6}, {5145, 17}},
		ServiceRmopagt:         {{2959, 6}, {2959, 17}},
		ServiceRmpp:            {{1121, 6}, {1121, 17}},
		ServiceRmt:             {{411, 6}, {411, 17}},
		ServiceRmtserver:       {{2416, 6}, {2416, 17}},
		ServiceRna:             {{25471, 132}},
		ServiceRndc:            {{953, 6}, {953, 17}},
		ServiceRnm:             {{3844, 6}, {3844, 17}},
		ServiceRnmap:           {{3418, 6}, {3418, 17}},
		ServiceRnrp:            {{2423, 6}, {2423, 17}},
		ServiceRobcadLm:        {{1509, 6}, {1509, 17}},
		ServiceRobix:           {{9599, 6}, {9599, 17}},
		ServiceRoboeda:         {{2920, 6}, {2920, 17}},
		ServiceRoboer:          {{2919, 6}, {2919, 17}},
		ServiceRockwellCsp1:    {{2221, 6}, {2221, 17}},
		ServiceRockwellCsp2:    {{2223, 6}, {2223, 17}},
		ServiceRocrail:         {{8051, 6}},
		ServiceRoketz:          {{1730, 6}, {1730, 17}},
		ServiceRootd:           {{1094, 6}, {1094, 17}},
		ServiceRoutematch:      {{1287, 6}, {1287, 17}},
		ServiceRouter:          {{520, 17}},
		ServiceRoverlog:        {{3677, 6}, {3677, 17}},
		ServiceRpReputation:    {{6568, 17}},
		ServiceRpasswd:         {{774, 6}},
		ServiceRpc2portmap:     {{369, 6}, {369, 17}},
		ServiceRpi:             {{2214, 6}, {2214, 17}},
		ServiceRpkiRtr:         {{323, 6}},
		ServiceRpkiRtrTls:      {{324, 6}},
		ServiceRprt:            {{3064, 6}, {3064, 17}},
		ServiceRquotad:         {{875, 6}, {875, 17}},
		ServiceRrac:            {{5678, 6}, {5678, 17}},
		ServiceRrdp:            {{5313, 6}, {5313, 17}},
		ServiceRrh:             {{753, 6}, {753, 17}},
		ServiceRrifmm:          {{1696, 6}, {1696, 17}},
		ServiceRrilwm:          {{1695, 6}, {1695, 17}},
		ServiceRrimwm:          {{1694, 6}, {1694, 17}},
		ServiceRrirtr:          {{1693, 6}, {1693, 17}},
		ServiceRrisat:          {{1697, 6}, {1697, 17}},
		ServiceRrp:             {{648, 6}, {648, 17}},
		ServiceRsPias:          {{13217, 6}, {13217, 17}},
		ServiceRsRmi:           {{3736, 6}, {3736, 17}},
		ServiceRsap:            {{1647, 6}, {1647, 17}},
		ServiceRscRobot:        {{1793, 6}, {1793, 17}},
		ServiceRscd:            {{5750, 6}, {5750, 17}},
		ServiceRscs:            {{10201, 17}},
		ServiceRsf1:            {{1195, 6}, {1195, 17}},
		ServiceRshSpx:          {{222, 6}, {222, 17}},
		ServiceRsip:            {{4555, 6}, {4555, 17}},
		ServiceRsisysaccess:    {{2752, 6}, {2752, 17}},
		ServiceRsms:            {{10201, 6}},
		ServiceRsmtp:           {{2390, 6}, {2390, 17}},
		ServiceRsom:            {{2889, 6}, {2889, 17}},
		ServiceRsqlserver:      {{4430, 17}},
		ServiceRsvd:            {{168, 6}, {168, 17}},
		ServiceRsvpEncap1:      {{1698, 6}, {1698, 17}},
		ServiceRsvpEncap2:      {{1699, 6}, {1699, 17}},
		ServiceRsvp_tunnel:     {{363, 6}, {363, 17}},
		ServiceRsync:           {{873, 6}, {873, 17}},
		ServiceRtEvent:         {{3706, 6}, {3706, 17}},
		ServiceRtEventS:        {{3707, 6}, {3707, 17}},
		ServiceRtcPmPort:       {{3891, 6}, {3891, 17}},
		ServiceRtcmSc104:       {{2101, 6}, {2101, 17}},
		ServiceRtelnet:         {{107, 6}, {107, 17}},
		ServiceRtip:            {{771, 6}, {771, 17}},
		ServiceRtmp:            {{1, 6}},
		ServiceRtmpPort:        {{3500, 6}, {3500, 17}},
		ServiceRtnt1:           {{3137, 6}, {3137, 17}},
		ServiceRtnt2:           {{3138, 6}, {3138, 17}},
		ServiceRtpsDdMt:        {{7402, 6}, {7402, 17}},
		ServiceRtpsDdUt:        {{7401, 6}, {7401, 17}},
		ServiceRtpsDiscovery:   {{7400, 6}, {7400, 17}},
		ServiceRtraceroute:     {{3765, 6}, {3765, 17}},
		ServiceRtsclient:       {{2501, 6}, {2501, 17}},
		ServiceRtsp:            {{554, 6}, {554, 17}},
		ServiceRtspAlt:         {{8554, 6}, {8554, 17}},
		ServiceRtsps:           {{322, 6}, {322, 17}},
		ServiceRtsserv:         {{2500, 6}, {2500, 17}},
		ServiceRugameonline:    {{5156, 6}},
		ServiceRusbSysPort:     {{3422, 6}, {3422, 17}},
		ServiceRushd:           {{696, 6}, {696, 17}},
		ServiceRvsIsdnDcp:      {{2578, 6}, {2578, 17}},
		ServiceRwhois:          {{4321, 6}, {4321, 17}},
		ServiceRxapi:           {{10010, 6}},
		ServiceRxe:             {{761, 6}, {761, 17}},
		ServiceRxmon:           {{1311, 6}, {1311, 17}},
		ServiceS102:            {{23272, 17}},
		ServiceS1Control:       {{36412, 132}},
		ServiceS3db:            {{2278, 6}, {2278, 17}},
		ServiceS8ClientPort:    {{3153, 6}, {3153, 17}},
		ServiceSNet:            {{166, 6}, {166, 17}},
		ServiceSOpenmail:       {{5767, 6}, {5767, 17}},
		ServiceSaMsgPort:       {{1646, 6}, {1646, 17}},
		ServiceSabams:          {{2760, 6}, {2760, 17}},
		ServiceSabarsd:         {{8401, 6}, {8401, 17}},
		ServiceSabpSignal:      {{3452, 6}, {3452, 17}},
		ServiceSac:             {{8097, 6}, {8097, 17}},
		ServiceSacred:          {{1118, 6}, {1118, 17}},
		ServiceSafetynetp:      {{40000, 6}, {40000, 17}},
		ServiceSaft:            {{487, 6}, {487, 17}},
		ServiceSageBestCom1:    {{14033, 6}, {14033, 17}},
		ServiceSageBestCom2:    {{14034, 6}, {14034, 17}},
		ServiceSagectlpanel:    {{3698, 6}, {3698, 17}},
		ServiceSagxtsds:        {{4952, 6}, {4952, 17}},
		ServiceSahLm:           {{3291, 6}, {3291, 17}},
		ServiceSai_sentlm:      {{2640, 6}, {2640, 17}},
		ServiceSais:            {{1426, 6}, {1426, 17}},
		ServiceSaiscm:          {{1501, 6}, {1501, 17}},
		ServiceSaiseh:          {{1644, 6}, {1644, 17}},
		ServiceSaism:           {{1436, 6}, {1436, 17}},
		ServiceSalientDtasrv:   {{5409, 6}, {5409, 17}},
		ServiceSalientMux:      {{5422, 6}, {5422, 17}},
		ServiceSalientUsrmgr:   {{5410, 6}, {5410, 17}},
		ServiceSamd:            {{3275, 6}, {3275, 17}},
		ServiceSamsungUnidex:   {{4010, 6}, {4010, 17}},
		ServiceSanavigator:     {{4033, 6}, {4033, 17}},
		ServiceSanePort:        {{6566, 6}, {6566, 17}},
		ServiceSanity:          {{643, 6}, {643, 17}},
		ServiceSantakUps:       {{3038, 6}, {3038, 17}},
		ServiceSaphostctrl:     {{1128, 6}, {1128, 17}},
		ServiceSaphostctrls:    {{1129, 6}, {1129, 17}},
		ServiceSapv1:           {{9875, 6}, {9875, 17}},
		ServiceSaratoga:        {{7542, 6}, {7542, 17}},
		ServiceSaris:           {{4442, 6}, {4442, 17}},
		ServiceSasRemoteHlp:    {{3755, 6}, {3755, 17}},
		ServiceSasg:            {{3744, 6}, {3744, 17}},
		ServiceSasggprs:        {{3964, 6}, {3964, 17}},
		ServiceSasp:            {{3860, 6}, {3860, 17}},
		ServiceSauterdongle:    {{25576, 6}},
		ServiceSavant:          {{3391, 6}, {3391, 17}},
		ServiceSbackup:         {{5163, 6}},
		ServiceSbcap:           {{29168, 132}},
		ServiceSbiAgent:        {{3962, 6}, {3962, 17}},
		ServiceSbl:             {{1039, 6}, {1039, 17}},
		ServiceSbook:           {{1349, 6}, {1349, 17}},
		ServiceScanChange:      {{2719, 6}, {2719, 17}},
		ServiceScanstat1:       {{1215, 6}, {1215, 17}},
		ServiceSccSecurity:     {{582, 6}, {582, 17}},
		ServiceSccipMedia:      {{3499, 6}, {3499, 17}},
		ServiceSceanics:        {{5435, 6}, {5435, 17}},
		ServiceScenccs:         {{7129, 6}, {7129, 17}},
		ServiceScenidm:         {{7128, 6}, {7128, 17}},
		ServiceScientiaSdb:     {{1811, 6}, {1811, 17}},
		ServiceScientiaSsdb:    {{2121, 6}, {2121, 17}},
		ServiceScinet:          {{7708, 6}, {7708, 17}},
		ServiceScipticslsrvr:   {{2577, 6}, {2577, 17}},
		ServiceScoAip:          {{5307, 6}, {5307, 17}},
		ServiceScoDtmgr:        {{617, 6}, {617, 17}},
		ServiceScoInetmgr:      {{615, 6}, {615, 17}},
		ServiceScoPeerTta:      {{5427, 6}, {5427, 17}},
		ServiceScoSysmgr:       {{616, 6}, {616, 17}},
		ServiceScoWebsrvrmg3:   {{598, 6}, {598, 17}},
		ServiceScoWebsrvrmgr:   {{620, 6}, {620, 17}},
		ServiceScohelp:         {{457, 6}, {457, 17}},
		ServiceScoi2odialog:    {{360, 6}, {360, 17}},
		ServiceScol:            {{1200, 6}, {1200, 17}},
		ServiceScoremgr:        {{2034, 6}, {2034, 17}},
		ServiceScottyDisc:      {{14002, 17}},
		ServiceScottyFt:        {{14000, 6}, {14000, 17}},
		ServiceScp:             {{3820, 6}, {3820, 17}},
		ServiceScpConfig:       {{10001, 6}, {10001, 17}},
		ServiceScpiRaw:         {{5025, 6}, {5025, 17}},
		ServiceScpiTelnet:      {{5024, 6}, {5024, 17}},
		ServiceScrabble:        {{2026, 6}, {2026, 17}},
		ServiceScreencast:      {{1368, 6}, {1368, 17}},
		ServiceScriptview:      {{7741, 6}, {7741, 17}},
		ServiceScscp:           {{26133, 6}, {26133, 17}},
		ServiceScservp:         {{3637, 6}, {3637, 17}},
		ServiceScte104:         {{5167, 6}, {5167, 17}},
		ServiceScte30:          {{5168, 6}, {5168, 17}},
		ServiceSctpTunneling:   {{9899, 17}},
		ServiceScup:            {{6315, 6}},
		ServiceScupDisc:        {{6315, 17}},
		ServiceScxProxy:        {{470, 6}, {470, 17}},
		ServiceSd:              {{9876, 6}},
		ServiceSdCapacity:      {{2384, 17}},
		ServiceSdData:          {{2385, 6}, {2385, 17}},
		ServiceSdElmd:          {{1681, 6}, {1681, 17}},
		ServiceSdRequest:       {{2384, 6}},
		ServiceSdbproxy:        {{3562, 6}, {3562, 17}},
		ServiceSdclient:        {{2310, 6}, {2310, 17}},
		ServiceSddp:            {{1163, 6}, {1163, 17}},
		ServiceSdeDiscovery:    {{5152, 6}, {5152, 17}},
		ServiceSdfunc:          {{2046, 6}, {2046, 17}},
		ServiceSdhelp:          {{2308, 6}, {2308, 17}},
		ServiceSdlEts:          {{5081, 6}, {5081, 17}},
		ServiceSdmmp:           {{5573, 6}, {5573, 17}},
		ServiceSdnskmp:         {{558, 6}, {558, 17}},
		ServiceSdo:             {{3635, 6}, {3635, 17}},
		ServiceSdoSsh:          {{3897, 6}, {3897, 17}},
		ServiceSdoTls:          {{3896, 6}, {3896, 17}},
		ServiceSdpIdPort:       {{3242, 6}, {3242, 17}},
		ServiceSdpPortmapper:   {{3935, 6}, {3935, 17}},
		ServiceSdproxy:         {{1297, 6}, {1297, 17}},
		ServiceSdr:             {{9010, 6}},
		ServiceSds:             {{5059, 6}, {5059, 17}},
		ServiceSdsAdmin:        {{2705, 6}, {2705, 17}},
		ServiceSdscLm:          {{1537, 6}, {1537, 17}},
		ServiceSdserver:        {{2309, 6}, {2309, 17}},
		ServiceSdt:             {{5568, 6}, {5568, 17}},
		ServiceSdtLmd:          {{3319, 6}, {3319, 17}},
		ServiceSeagullAis:      {{1208, 6}, {1208, 17}},
		ServiceSeagulllms:      {{1291, 6}, {1291, 17}},
		ServiceSeaodbc:         {{2471, 6}, {2471, 17}},
		ServiceSearch:          {{2010, 6}},
		ServiceSearchAgent:     {{1234, 6}, {1234, 17}},
		ServiceSeaview:         {{3143, 6}, {3143, 17}},
		ServiceSecNtbClnt:      {{32635, 6}, {32635, 17}},
		ServiceSecPc2faxSrv:    {{9402, 6}, {9402, 17}},
		ServiceSecT4netClt:     {{9401, 6}, {9401, 17}},
		ServiceSecT4netSrv:     {{9400, 6}, {9400, 17}},
		ServiceSeclayerTcp:     {{3495, 6}, {3495, 17}},
		ServiceSeclayerTls:     {{3496, 6}, {3496, 17}},
		ServiceSecrmmsafecopya: {{38865, 6}},
		ServiceSecureCfgSvr:    {{3978, 6}, {3978, 17}},
		ServiceSecureMqtt:      {{8883, 6}, {8883, 17}},
		ServiceSecureTs:        {{9318, 6}, {9318, 17}},
		ServiceSecuritychase:   {{5399, 6}, {5399, 17}},
		ServiceSeispoc:         {{2254, 6}, {2254, 17}},
		ServiceSemantix:        {{361, 6}, {361, 17}},
		ServiceSemaphore:       {{3255, 6}, {3255, 17}},
		ServiceSend:            {{169, 6}, {169, 17}},
		ServiceSenip:           {{3898, 6}, {3898, 17}},
		ServiceSenomix01:       {{8052, 6}, {8052, 17}},
		ServiceSenomix02:       {{8053, 6}, {8053, 17}},
		ServiceSenomix03:       {{8054, 6}, {8054, 17}},
		ServiceSenomix04:       {{8055, 6}, {8055, 17}},
		ServiceSenomix05:       {{8056, 6}, {8056, 17}},
		ServiceSenomix06:       {{8057, 6}, {8057, 17}},
		ServiceSenomix07:       {{8058, 6}, {8058, 17}},
		ServiceSenomix08:       {{8059, 6}, {8059, 17}},
		ServiceSentLm:          {{2316, 6}, {2316, 17}},
		ServiceSentinel:        {{3588, 6}, {3588, 17}},
		ServiceSentinelEnt:     {{3712, 6}, {3712, 17}},
		ServiceSentinelLm:      {{5093, 6}, {5093, 17}},
		ServiceSentinelsrm:     {{1947, 6}, {1947, 17}},
		ServiceSentlmSrv2srv:   {{5099, 6}, {5099, 17}},
		ServiceSep:             {{2089, 6}, {2089, 17}},
		ServiceSeraph:          {{4076, 6}, {4076, 17}},
		ServiceSercommScadmin:  {{6108, 6}, {6108, 17}},
		ServiceSercommWlink:    {{2235, 6}, {2235, 17}},
		ServiceSerialgateway:   {{1243, 6}, {1243, 17}},
		ServiceServerFind:      {{8351, 6}, {8351, 17}},
		ServiceServergraph:     {{1251, 6}, {1251, 17}},
		ServiceServerstart:     {{9213, 6}, {9213, 17}},
		ServiceServerviewAs:    {{3169, 6}, {3169, 17}},
		ServiceServerviewAsn:   {{3170, 6}, {3170, 17}},
		ServiceServerviewGf:    {{3171, 6}, {3171, 17}},
		ServiceServerviewIcc:   {{3173, 6}, {3173, 17}},
		ServiceServerviewRm:    {{3172, 6}, {3172, 17}},
		ServiceServerviewdbms:  {{9212, 6}, {9212, 17}},
		ServiceServerwsd2:      {{5362, 6}, {5362, 17}},
		ServiceServexec:        {{2021, 6}},
		ServiceServiceCtrl:     {{2367, 6}, {2367, 17}},
		ServiceServicemeter:    {{2603, 6}, {2603, 17}},
		ServiceServicetags:     {{6481, 6}, {6481, 17}},
		ServiceServistaitsm:    {{3636, 6}, {3636, 17}},
		ServiceServserv:        {{2011, 17}},
		ServiceServstat:        {{633, 6}, {633, 17}},
		ServiceSesiLm:          {{1714, 6}, {1714, 17}},
		ServiceSet:             {{257, 6}, {257, 17}},
		ServiceSfLm:            {{4546, 6}, {4546, 17}},
		ServiceSflm:            {{3162, 6}, {3162, 17}},
		ServiceSflow:           {{6343, 6}, {6343, 17}},
		ServiceSfmDbServer:     {{5636, 6}},
		ServiceSfmsso:          {{5635, 6}},
		ServiceSfsConfig:       {{452, 6}, {452, 17}},
		ServiceSfsSmpNet:       {{451, 6}, {451, 17}},
		ServiceSftdstPort:      {{3230, 6}, {3230, 17}},
		ServiceSftp:            {{115, 6}, {115, 17}},
		ServiceSftsrv:          {{1303, 6}, {1303, 17}},
		ServiceSftu:            {{3326, 6}, {3326, 17}},
		ServiceSgLm:            {{1659, 6}, {1659, 17}},
		ServiceSgcip:           {{16950, 6}, {16950, 17}},
		ServiceSgcp:            {{440, 6}, {440, 17}},
		ServiceSge_execd:       {{6445, 6}, {6445, 17}},
		ServiceSge_qmaster:     {{6444, 6}, {6444, 17}},
		ServiceSgiArrayd:       {{5434, 6}, {5434, 17}},
		ServiceSgiDgl:          {{5232, 6}, {5232, 17}},
		ServiceSgiDmfmgr:       {{11109, 6}},
		ServiceSgiEsphttp:      {{5554, 6}, {5554, 17}},
		ServiceSgiEventmond:    {{5553, 6}, {5553, 17}},
		ServiceSgiLk:           {{11106, 6}, {11106, 17}},
		ServiceSgiSoap:         {{11110, 6}},
		ServiceSgiStorman:      {{1178, 17}},
		ServiceSgmp:            {{153, 6}, {153, 17}},
		ServiceSgmpTraps:       {{160, 6}, {160, 17}},
		ServiceSgsap:           {{29118, 132}},
		ServiceShadowserver:    {{2027, 6}, {2027, 17}},
		ServiceShaperai:        {{43210, 6}},
		ServiceShaperaiDisc:    {{43210, 17}},
		ServiceShareapp:        {{3595, 6}, {3595, 17}},
		ServiceSharpServer:     {{3617, 6}, {3617, 17}},
		ServiceShell:           {{514, 6}},
		ServiceShiva_confsrvr:  {{1651, 6}, {1651, 17}},
		ServiceShivadiscovery:  {{1502, 6}, {1502, 17}},
		ServiceShivahose:       {{1549, 6}},
		ServiceShivasound:      {{1549, 17}},
		ServiceShockwave:       {{1626, 6}, {1626, 17}},
		ServiceShockwave2:      {{1257, 6}, {1257, 17}},
		ServiceShofar:          {{4105, 6}, {4105, 17}},
		ServiceShrinkwrap:      {{358, 6}, {358, 17}},
		ServiceSiaCtrlPlane:    {{4787, 6}},
		ServiceSiam:            {{498, 6}, {498, 17}},
		ServiceSicct:           {{4742, 6}},
		ServiceSicctSdp:        {{4742, 17}},
		ServiceSiebelNs:        {{2320, 6}, {2320, 17}},
		ServiceSiemensgsm:      {{28240, 6}, {28240, 17}},
		ServiceSieve:           {{4190, 6}},
		ServiceSieveFilter:     {{2000, 6}, {2000, 17}},
		ServiceSiftUft:         {{608, 6}, {608, 17}},
		ServiceSigmaPort:       {{3614, 6}, {3614, 17}},
		ServiceSignacertAgent:  {{5032, 6}},
		ServiceSignal:          {{2974, 6}, {2974, 17}},
		ServiceSignetCtf:       {{2733, 6}, {2733, 17}},
		ServiceSiipat:          {{1733, 6}, {1733, 17}},
		ServiceSilc:            {{706, 6}, {706, 17}},
		ServiceSilhouette:      {{7500, 6}, {7500, 17}},
		ServiceSilkmeter:       {{5461, 6}, {5461, 17}},
		ServiceSilkp1:          {{2829, 6}, {2829, 17}},
		ServiceSilkp2:          {{2830, 6}, {2830, 17}},
		ServiceSilkp3:          {{2831, 6}, {2831, 17}},
		ServiceSilkp4:          {{2832, 6}, {2832, 17}},
		ServiceSilverpeakcomm:  {{4164, 6}, {4164, 17}},
		ServiceSilverpeakpeer:  {{4163, 6}, {4163, 17}},
		ServiceSilverplatter:   {{416, 6}, {416, 17}},
		ServiceSimControl:      {{3110, 6}, {3110, 17}},
		ServiceSimbaCs:         {{1543, 6}, {1543, 17}},
		ServiceSimbaexpress:    {{1583, 6}, {1583, 17}},
		ServiceSimbaservices:   {{1599, 6}, {1599, 17}},
		ServiceSimco:           {{7626, 6}, {7626, 132}},
		ServiceSimctlp:         {{2857, 6}, {2857, 17}},
		ServiceSimon:           {{4753, 6}},
		ServiceSimonDisc:       {{4753, 17}},
		ServiceSimpAll:         {{1959, 6}, {1959, 17}},
		ServiceSimplePush:      {{3687, 6}, {3687, 17}},
		ServiceSimplePushS:     {{3688, 6}, {3688, 17}},
		ServiceSimpleTxRx:      {{2257, 6}, {2257, 17}},
		ServiceSimplementTie:   {{2756, 6}, {2756, 17}},
		ServiceSimplifymedia:   {{8087, 6}, {8087, 17}},
		ServiceSimslink:        {{2676, 6}, {2676, 17}},
		ServiceSip:             {{5060, 6}, {5060, 17}},
		ServiceSipTls:          {{5061, 6}, {5061, 17}},
		ServiceSisEmt:          {{2545, 6}, {2545, 17}},
		ServiceSitaradir:       {{2631, 6}, {2631, 17}},
		ServiceSitaramgmt:      {{2630, 6}, {2630, 17}},
		ServiceSitaraserver:    {{2629, 6}, {2629, 17}},
		ServiceSitewatch:       {{3792, 6}, {3792, 17}},
		ServiceSixDegrees:      {{3611, 6}, {3611, 17}},
		ServiceSixnetudr:       {{1658, 6}, {1658, 17}},
		ServiceSixtrak:         {{1594, 6}, {1594, 17}},
		ServiceSixxsconfig:     {{3874, 6}, {3874, 17}},
		ServiceSkipCertRecv:    {{6455, 6}, {6455, 17}},
		ServiceSkipCertSend:    {{6456, 6}, {6456, 17}},
		ServiceSkipMcGikreq:    {{1660, 6}, {1660, 17}},
		ServiceSkkserv:         {{1178, 6}},
		ServiceSkronk:          {{460, 6}, {460, 17}},
		ServiceSkyTransport:    {{3556, 6}, {3556, 17}},
		ServiceSkytelnet:       {{1618, 6}, {1618, 17}},
		ServiceSlcCtrlrloops:   {{2827, 6}, {2827, 17}},
		ServiceSlcSystemlog:    {{2826, 6}, {2826, 17}},
		ServiceSlimDevices:     {{3483, 6}, {3483, 17}},
		ServiceSlingshot:       {{1705, 6}, {1705, 17}},
		ServiceSlinkysearch:    {{1225, 6}, {1225, 17}},
		ServiceSlinterbase:     {{3065, 6}, {3065, 17}},
		ServiceSlmApi:          {{1606, 6}, {1606, 17}},
		ServiceSlp:             {{1605, 6}, {1605, 17}},
		ServiceSlpNotify:       {{1847, 6}, {1847, 17}},
		ServiceSlscc:           {{4408, 6}},
		ServiceSlslavemon:      {{3102, 6}, {3102, 17}},
		ServiceSlush:           {{1966, 6}, {1966, 17}},
		ServiceSmDisc:          {{4174, 17}},
		ServiceSmPas1:          {{2938, 6}, {2938, 17}},
		ServiceSmPas2:          {{2939, 6}, {2939, 17}},
		ServiceSmPas3:          {{2940, 6}, {2940, 17}},
		ServiceSmPas4:          {{2941, 6}, {2941, 17}},
		ServiceSmPas5:          {{2942, 6}, {2942, 17}},
		ServiceSmaSpw:          {{9522, 17}},
		ServiceSmaclmgr:        {{4660, 6}, {4660, 17}},
		ServiceSmakynet:        {{122, 6}, {122, 17}},
		ServiceSmap:            {{3731, 6}, {3731, 17}},
		ServiceSmarSePort1:     {{4987, 6}, {4987, 17}},
		ServiceSmarSePort2:     {{4988, 6}, {4988, 17}},
		ServiceSmartDiagnose:   {{2721, 6}, {2721, 17}},
		ServiceSmartInstall:    {{4786, 6}},
		ServiceSmartLm:         {{1608, 6}, {1608, 17}},
		ServiceSmartcardPort:   {{3516, 6}, {3516, 17}},
		ServiceSmartcardTls:    {{4116, 6}, {4116, 17}},
		ServiceSmartpackets:    {{3218, 6}, {3218, 17}},
		ServiceSmartsdp:        {{426, 6}, {426, 17}},
		ServiceSmauthPort:      {{3929, 6}, {3929, 17}},
		ServiceSmbdirect:       {{5445, 6}, {5445, 132}},
		ServiceSmcAdmin:        {{6787, 6}, {6787, 17}},
		ServiceSmcHttp:         {{6788, 6}, {6788, 17}},
		ServiceSmcHttps:        {{6789, 6}, {6789, 17}},
		ServiceSmcJmx:          {{6786, 6}, {6786, 17}},
		ServiceSmcluster:       {{4174, 6}},
		ServiceSmile:           {{3670, 6}, {3670, 17}},
		ServiceSmip:            {{7734, 6}, {7734, 17}},
		ServiceSmntubootstrap:  {{2613, 6}, {2613, 17}},
		ServiceSmpnameres:      {{901, 17}},
		ServiceSmpp:            {{2775, 6}, {2775, 17}},
		ServiceSmpppd:          {{3185, 6}, {3185, 17}},
		ServiceSmpte:           {{420, 6}, {420, 17}},
		ServiceSmsChat:         {{2703, 6}, {2703, 17}},
		ServiceSmsRcinfo:       {{2701, 6}, {2701, 17}},
		ServiceSmsRemctrl:      {{2704, 6}, {2704, 17}},
		ServiceSmsXfer:         {{2702, 6}, {2702, 17}},
		ServiceSmsd:            {{596, 6}, {596, 17}},
		ServiceSmsp:            {{413, 6}, {413, 17}},
		ServiceSmsqp:           {{11201, 6}, {11201, 17}},
		ServiceSmtp:            {{25, 6}, {25, 17}},
		ServiceSmux:            {{199, 6}, {199, 17}},
		ServiceSmwan:           {{3979, 6}, {3979, 17}},
		ServiceSnaCs:           {{1553, 6}, {1553, 17}},
		ServiceSnac:            {{3536, 6}, {3536, 17}},
		ServiceSnagas:          {{108, 6}, {108, 17}},
		ServiceSnap:            {{4752, 6}, {4752, 17}},
		ServiceSnapd:           {{2599, 6}, {2599, 17}},
		ServiceSnapenetio:      {{22000, 6}, {22000, 17}},
		ServiceSnapp:           {{2333, 6}, {2333, 17}},
		ServiceSnare:           {{509, 6}, {509, 17}},
		ServiceSnaresecure:     {{1684, 6}, {1684, 17}},
		ServiceSncp:            {{7560, 6}, {7560, 17}},
		ServiceSnifferclient:   {{2452, 6}, {2452, 17}},
		ServiceSnifferdata:     {{2892, 6}, {2892, 17}},
		ServiceSnifferserver:   {{2533, 6}, {2533, 17}},
		ServiceSnipSlave:       {{33656, 6}, {33656, 17}},
		ServiceSnmp:            {{161, 6}, {161, 17}},
		ServiceSnmpTcpPort:     {{1993, 6}, {1993, 17}},
		ServiceSnmpdtls:        {{10161, 17}},
		ServiceSnmpdtlsTrap:    {{10162, 17}},
		ServiceSnmpssh:         {{5161, 6}},
		ServiceSnmpsshTrap:     {{5162, 6}},
		ServiceSnmptls:         {{10161, 6}},
		ServiceSnmptlsTrap:     {{10162, 6}},
		ServiceSnmptrap:        {{162, 6}, {162, 17}},
		ServiceSnpp:            {{444, 6}, {444, 17}},
		ServiceSnsAdmin:        {{2658, 6}, {2658, 17}},
		ServiceSnsAgent:        {{5417, 6}, {5417, 17}},
		ServiceSnsChannels:     {{3380, 6}, {3380, 17}},
		ServiceSnsDispatcher:   {{2657, 6}, {2657, 17}},
		ServiceSnsGateway:      {{5416, 6}, {5416, 17}},
		ServiceSnsProtocol:     {{2409, 6}, {2409, 17}},
		ServiceSnsQuery:        {{2659, 6}, {2659, 17}},
		ServiceSnsQuote:        {{1967, 6}, {1967, 17}},
		ServiceSnss:            {{11171, 17}},
		ServiceSntlkeyssrvr:    {{9450, 6}, {9450, 17}},
		ServiceSntpHeartbeat:   {{580, 6}, {580, 17}},
		ServiceSoagateway:      {{5250, 6}, {5250, 17}},
		ServiceSoapBeep:        {{605, 6}, {605, 17}},
		ServiceSoapHttp:        {{7627, 6}, {7627, 17}},
		ServiceSocalia:         {{5100, 6}, {5100, 17}},
		ServiceSocialAlarm:     {{5146, 6}},
		ServiceSocks:           {{1080, 6}, {1080, 17}},
		ServiceSocorfs:         {{3379, 6}, {3379, 17}},
		ServiceSocpC:           {{4882, 17}},
		ServiceSocpT:           {{4881, 17}},
		ServiceSoftaudit:       {{3419, 6}, {3419, 17}},
		ServiceSoftcm:          {{6110, 6}, {6110, 17}},
		ServiceSoftdataphone:   {{1621, 6}, {1621, 17}},
		ServiceSoftpc:          {{215, 6}, {215, 17}},
		ServiceSoftrackMeter:   {{3884, 6}, {3884, 17}},
		ServiceSolarisAudit:    {{16162, 6}},
		ServiceSoleraEpmap:     {{2132, 6}, {2132, 17}},
		ServiceSoleraLpn:       {{4738, 6}, {4738, 17}},
		ServiceSolidEEngine:    {{1964, 6}, {1964, 17}},
		ServiceSolidMux:        {{1029, 6}, {1029, 17}},
		ServiceSolve:           {{2636, 6}, {2636, 17}},
		ServiceSonar:           {{572, 6}, {572, 17}},
		ServiceSonardata:       {{2863, 6}, {2863, 17}},
		ServiceSoniqsync:       {{3803, 6}, {3803, 17}},
		ServiceSonus:           {{2653, 6}, {2653, 17}},
		ServiceSonusLogging:    {{2290, 6}, {2290, 17}},
		ServiceSonuscallsig:    {{2569, 6}, {2569, 17}},
		ServiceSophiaLm:        {{1408, 6}, {1408, 17}},
		ServiceSops:            {{3944, 6}, {3944, 17}},
		ServiceSorUpdate:       {{3922, 6}, {3922, 17}},
		ServiceSos:             {{3838, 6}, {3838, 17}},
		ServiceSossdAgent:      {{7982, 6}},
		ServiceSossdCollect:    {{7981, 6}},
		ServiceSossdDisc:       {{7982, 17}},
		ServiceSossecollector:  {{3166, 6}, {3166, 17}},
		ServiceSoundsvirtual:   {{17185, 6}, {17185, 17}},
		ServiceSpRemotetablet:  {{46998, 6}},
		ServiceSpamtrap:        {{2568, 6}, {2568, 17}},
		ServiceSpandataport:    {{3193, 6}, {3193, 17}},
		ServiceSpc:             {{6111, 6}, {6111, 17}},
		ServiceSpcsdlobby:      {{2888, 6}, {2888, 17}},
		ServiceSpdp:            {{5794, 17}},
		ServiceSpdy:            {{6121, 6}},
		ServiceSpearway:        {{2440, 6}, {2440, 17}},
		ServiceSpectardata:     {{3834, 6}, {3834, 17}},
		ServiceSpectardb:       {{3835, 6}, {3835, 17}},
		ServiceSpectraport:     {{3851, 6}, {3851, 17}},
		ServiceSpeedtrace:      {{33334, 6}},
		ServiceSpeedtraceDisc:  {{33334, 17}},
		ServiceSphinxapi:       {{9312, 6}},
		ServiceSphinxql:        {{9306, 6}},
		ServiceSpice:           {{1923, 6}, {1923, 17}},
		ServiceSpike:           {{4683, 6}, {4683, 17}},
		ServiceSpiralAdmin:     {{3438, 6}, {3438, 17}},
		ServiceSplitlock:       {{3606, 6}, {3606, 17}},
		ServiceSplitlockGw:     {{3647, 6}, {3647, 17}},
		ServiceSpmp:            {{656, 6}, {656, 17}},
		ServiceSpock:           {{2507, 6}, {2507, 17}},
		ServiceSpocp:           {{4751, 6}, {4751, 17}},
		ServiceSpramsca:        {{5769, 6}, {5769, 17}},
		ServiceSpramsd:         {{5770, 6}, {5770, 17}},
		ServiceSpsTunnel:       {{2876, 6}, {2876, 17}},
		ServiceSpsc:            {{478, 6}, {478, 17}},
		ServiceSpss:            {{5443, 6}, {5443, 17}},
		ServiceSpssLm:          {{1759, 6}},
		ServiceSptAutomation:   {{5814, 6}, {5814, 17}},
		ServiceSpugna:          {{3807, 6}, {3807, 17}},
		ServiceSpwDialer:       {{3796, 6}, {3796, 17}},
		ServiceSpwDnspreload:   {{3849, 6}, {3849, 17}},
		ServiceSpytechphone:    {{8192, 6}, {8192, 17}},
		ServiceSqdr:            {{2728, 6}, {2728, 17}},
		ServiceSqlNet:          {{66, 6}, {66, 17}, {150, 6}, {150, 17}},
		ServiceSqlexec:         {{9088, 6}, {9088, 17}},
		ServiceSqlexecSsl:      {{9089, 6}, {9089, 17}},
		ServiceSqlserv:         {{118, 6}, {118, 17}},
		ServiceSqlserver:       {{4430, 6}},
		ServiceSqlsrv:          {{156, 6}, {156, 17}},
		ServiceSquid:           {{3128, 6}},
		ServiceSrc:             {{200, 6}, {200, 17}},
		ServiceSrcp:            {{4303, 6}, {4303, 17}},
		ServiceSrdp:            {{3942, 6}, {3942, 17}},
		ServiceSrmp:            {{193, 6}, {193, 17}},
		ServiceSrpFeedback:     {{2737, 6}, {2737, 17}},
		ServiceSrssend:         {{362, 6}, {362, 17}},
		ServiceSruth:           {{38800, 6}},
		ServiceSrvc_registry:   {{3018, 6}, {3018, 17}},
		ServiceSs7ns:           {{477, 6}, {477, 17}},
		ServiceSsIdi:           {{20013, 6}},
		ServiceSsIdiDisc:       {{20012, 17}},
		ServiceSsad:            {{4750, 6}, {4750, 17}},
		ServiceSscAgent:        {{2967, 6}, {2967, 17}},
		ServiceSscan:           {{3853, 6}, {3853, 17}},
		ServiceSsdispatch:      {{3430, 6}, {3430, 17}},
		ServiceSsdp:            {{1900, 6}, {1900, 17}},
		ServiceSsdtp:           {{6071, 6}, {6071, 17}},
		ServiceSseAppConfig:    {{3852, 6}, {3852, 17}},
		ServiceSsh:             {{22, 6}, {22, 17}, {22, 132}},
		ServiceSshMgmt:         {{17235, 6}, {17235, 17}},
		ServiceSshell:          {{614, 6}, {614, 17}},
		ServiceSslp:            {{1750, 6}, {1750, 17}},
		ServiceSsmCssps:        {{2478, 6}, {2478, 17}},
		ServiceSsmCvs:          {{2477, 6}, {2477, 17}},
		ServiceSsmEls:          {{2479, 6}, {2479, 17}},
		ServiceSsmc:            {{2187, 6}},
		ServiceSsmd:            {{2187, 17}},
		ServiceSsmpp:           {{3550, 6}, {3550, 17}},
		ServiceSsoControl:      {{2711, 6}, {2711, 17}},
		ServiceSsoService:      {{2710, 6}, {2710, 17}},
		ServiceSsowatch:        {{3644, 6}, {3644, 17}},
		ServiceSsp:             {{3249, 6}, {3249, 17}},
		ServiceSspClient:       {{7801, 6}, {7801, 17}},
		ServiceSsql:            {{3352, 6}, {3352, 17}},
		ServiceSsrServermgr:    {{45966, 6}, {45966, 17}},
		ServiceSsrip:           {{3318, 6}, {3318, 17}},
		ServiceSsslicMgr:       {{1203, 6}, {1203, 17}},
		ServiceSsslogMgr:       {{1204, 6}, {1204, 17}},
		ServiceSst:             {{266, 6}, {266, 17}},
		ServiceSstp1:           {{7743, 6}, {7743, 17}},
		ServiceSstp2:           {{9801, 6}, {9801, 17}},
		ServiceSstsysLm:        {{1692, 6}, {1692, 17}},
		ServiceStanag5066:      {{5066, 6}, {5066, 17}},
		ServiceStarbot:         {{2838, 6}, {2838, 17}},
		ServiceStarfish:        {{3981, 6}, {3981, 17}},
		ServiceStargatealerts:  {{1654, 6}, {1654, 17}},
		ServiceStarquizPort:    {{3526, 6}, {3526, 17}},
		ServiceStars:           {{4131, 6}, {4131, 17}},
		ServiceStarschool:      {{2270, 6}, {2270, 17}},
		ServiceStartNetwork:    {{3615, 6}, {3615, 17}},
		ServiceStartron:        {{1057, 6}, {1057, 17}},
		ServiceStatCc:          {{4158, 6}, {4158, 17}},
		ServiceStatResults:     {{4156, 6}, {4156, 17}},
		ServiceStatScanner:     {{4157, 6}, {4157, 17}},
		ServiceStatsci1Lm:      {{6144, 6}, {6144, 17}},
		ServiceStatsci2Lm:      {{6145, 6}, {6145, 17}},
		ServiceStatsrv:         {{133, 6}, {133, 17}},
		ServiceStatusd:         {{5414, 6}, {5414, 17}},
		ServiceStdptc:          {{2154, 6}, {2154, 17}},
		ServiceSteSmsc:         {{1836, 6}, {1836, 17}},
		ServiceStgxfws:         {{1226, 6}, {1226, 17}},
		ServiceStiEnvision:     {{1312, 6}, {1312, 17}},
		ServiceStm_pproc:       {{3080, 6}, {3080, 17}},
		ServiceStmf:            {{501, 6}, {501, 17}},
		ServiceStoneDesign1:    {{1492, 6}, {1492, 17}},
		ServiceStonefalls:      {{2986, 6}, {2986, 17}},
		ServiceStorman:         {{4178, 6}, {4178, 17}},
		ServiceStorview:        {{9293, 6}, {9293, 17}},
		ServiceStreamcommDs:    {{9612, 6}, {9612, 17}},
		ServiceStreetStream:    {{1736, 6}, {1736, 17}},
		ServiceStreetperfect:   {{1330, 6}, {1330, 17}},
		ServiceStreettalk:      {{566, 6}, {566, 17}},
		ServiceStresstester:    {{5397, 6}, {5397, 17}},
		ServiceStrexecD:        {{5026, 6}, {5026, 17}},
		ServiceStrexecS:        {{5027, 6}, {5027, 17}},
		ServiceStrykerCom:      {{3854, 6}, {3854, 17}},
		ServiceStss:            {{3090, 6}, {3090, 17}},
		ServiceStt:             {{1607, 6}, {1607, 17}},
		ServiceStun:            {{3478, 6}, {3478, 17}},
		ServiceStunP1:          {{1990, 6}, {1990, 17}},
		ServiceStunP2:          {{1991, 6}, {1991, 17}},
		ServiceStunP3:          {{1992, 6}, {1992, 17}},
		ServiceStunPort:        {{1994, 6}, {1994, 17}},
		ServiceStuns:           {{5349, 6}, {5349, 17}},
		ServiceStvp:            {{3158, 6}, {3158, 17}},
		ServiceStx:             {{527, 6}, {527, 17}},
		ServiceSuMitTg:         {{89, 6}, {89, 17}},
		ServiceSua:             {{14001, 6}, {14001, 17}, {14001, 132}},
		ServiceSubmission:      {{587, 6}, {587, 17}},
		ServiceSubmit:          {{773, 6}},
		ServiceSubmitserver:    {{2028, 6}, {2028, 17}},
		ServiceSubntbcst_tftp:  {{247, 6}, {247, 17}},
		ServiceSugp:            {{1905, 6}, {1905, 17}},
		ServiceSuitcase:        {{2903, 6}, {2903, 17}},
		ServiceSuitjd:          {{3354, 6}, {3354, 17}},
		ServiceSum:             {{6551, 6}, {6551, 17}},
		ServiceSunAsIiops:      {{3708, 6}, {3708, 17}},
		ServiceSunAsIiopsCa:    {{3808, 6}, {3808, 17}},
		ServiceSunAsJmxrmi:     {{8686, 6}, {8686, 17}},
		ServiceSunAsJpda:       {{9191, 6}, {9191, 17}},
		ServiceSunAsNodeagt:    {{4850, 6}, {4850, 17}},
		ServiceSunDr:           {{665, 6}, {665, 17}},
		ServiceSunLm:           {{7588, 6}, {7588, 17}},
		ServiceSunMcGrp:        {{5306, 6}, {5306, 17}},
		ServiceSunSeaPort:      {{16161, 6}, {16161, 17}},
		ServiceSunSrAdmin:      {{6489, 6}, {6489, 17}},
		ServiceSunSrHttp:       {{6480, 6}, {6480, 17}},
		ServiceSunSrHttps:      {{6443, 6}, {6443, 17}},
		ServiceSunSrIiop:       {{6485, 6}, {6485, 17}},
		ServiceSunSrIiopAut:    {{6487, 6}, {6487, 17}},
		ServiceSunSrIiops:      {{6486, 6}, {6486, 17}},
		ServiceSunSrJms:        {{6484, 6}, {6484, 17}},
		ServiceSunSrJmx:        {{6488, 6}, {6488, 17}},
		ServiceSunUserHttps:    {{7677, 6}, {7677, 17}},
		ServiceSunVTSRMI:       {{6483, 6}, {6483, 17}},
		ServiceSuncacaoCsa:     {{11164, 6}, {11164, 17}},
		ServiceSuncacaoJmxmp:   {{11162, 6}, {11162, 17}},
		ServiceSuncacaoRmi:     {{11163, 6}, {11163, 17}},
		ServiceSuncacaoSnmp:    {{11161, 6}, {11161, 17}},
		ServiceSuncacaoWebsvc:  {{11165, 6}, {11165, 17}},
		ServiceSunclustergeo:   {{2084, 6}, {2084, 17}},
		ServiceSunclustermgr:   {{1097, 6}, {1097, 17}},
		ServiceSunfmPort:       {{3934, 6}, {3934, 17}},
		ServiceSunlpsHttp:      {{3816, 6}, {3816, 17}},
		ServiceSunrpc:          {{111, 6}, {111, 17}},
		ServiceSunscalarDns:    {{1870, 6}, {1870, 17}},
		ServiceSunscalarSvc:    {{1860, 6}, {1860, 17}},
		ServiceSunwebadmin:     {{8800, 6}, {8800, 17}},
		ServiceSunwebadmins:    {{8989, 6}, {8989, 17}},
		ServiceSupdup:          {{95, 6}, {95, 17}},
		ServiceSupercell:       {{7967, 6}, {7967, 17}},
		ServiceSupermon:        {{2709, 6}, {2709, 17}},
		ServiceSupfiledbg:      {{1127, 6}},
		ServiceSupfilesrv:      {{871, 6}},
		ServiceSupport:         {{1529, 6}},
		ServiceSurMeas:         {{243, 6}, {243, 17}},
		ServiceSurebox:         {{5453, 6}, {5453, 17}},
		ServiceSurf:            {{1010, 6}, {1010, 17}},
		ServiceSurfcontrolcpa:  {{3909, 6}, {3909, 17}},
		ServiceSurfpass:        {{5030, 6}, {5030, 17}},
		ServiceSurveyinst:      {{3212, 6}, {3212, 17}},
		ServiceSuucp:           {{4031, 6}, {4031, 17}},
		ServiceSvbackup:        {{8405, 6}},
		ServiceSvcloud:         {{8404, 6}},
		ServiceSvdrp:           {{6419, 6}},
		ServiceSvn:             {{3690, 6}, {3690, 17}},
		ServiceSvnet:           {{3413, 6}, {3413, 17}},
		ServiceSvnetworks:      {{2973, 6}, {2973, 17}},
		ServiceSvrloc:          {{427, 6}, {427, 17}},
		ServiceSvsOmagent:      {{1625, 6}, {1625, 17}},
		ServiceSwOrion:         {{17777, 6}},
		ServiceSwa1:            {{9023, 6}, {9023, 17}},
		ServiceSwa2:            {{9024, 6}, {9024, 17}},
		ServiceSwa3:            {{9025, 6}, {9025, 17}},
		ServiceSwa4:            {{9026, 6}, {9026, 17}},
		ServiceSwat:            {{901, 6}},
		ServiceSwdtp:           {{10104, 6}, {10104, 17}},
		ServiceSwdtpSv:         {{10009, 6}, {10009, 17}},
		ServiceSweetwareApps:   {{1221, 6}, {1221, 17}},
		ServiceSwiftRvf:        {{97, 6}, {97, 17}},
		ServiceSwiftnet:        {{1751, 6}, {1751, 17}},
		ServiceSwismgr1:        {{6963, 6}, {6963, 17}},
		ServiceSwismgr2:        {{6964, 6}, {6964, 17}},
		ServiceSwispol:         {{6966, 6}, {6966, 17}},
		ServiceSwistrap:        {{6965, 6}, {6965, 17}},
		ServiceSwldySias:       {{1250, 6}, {1250, 17}},
		ServiceSwrPort:         {{3491, 6}, {3491, 17}},
		ServiceSwrmi:           {{1866, 6}, {1866, 17}},
		ServiceSwtpPort1:       {{9281, 6}, {9281, 17}},
		ServiceSwtpPort2:       {{9282, 6}, {9282, 17}},
		ServiceSwxGate:         {{4538, 6}, {4538, 17}},
		ServiceSwxadmin:        {{5043, 6}, {5043, 17}},
		ServiceSxmp:            {{3273, 6}, {3273, 17}},
		ServiceSxuptp:          {{19540, 6}, {19540, 17}},
		ServiceSyamAgent:       {{3894, 6}, {3894, 17}},
		ServiceSyamSmc:         {{3895, 6}, {3895, 17}},
		ServiceSyamWebserver:   {{3930, 6}, {3930, 17}},
		ServiceSybaseSqlany:    {{1498, 6}, {1498, 17}},
		ServiceSybaseanywhere:  {{2638, 6}, {2638, 17}},
		ServiceSybasedbsynch:   {{2439, 6}, {2439, 17}},
		ServiceSybasesrvmon:    {{4950, 6}, {4950, 17}},
		ServiceSychrond:        {{3723, 6}, {3723, 17}},
		ServiceSymantecSfdb:    {{5629, 6}, {5629, 17}},
		ServiceSymantecSim:     {{3547, 6}, {3547, 17}},
		ServiceSymbSbPort:      {{3923, 6}, {3923, 17}},
		ServiceSymplex:         {{1507, 6}, {1507, 17}},
		ServiceSynapse:         {{2880, 6}, {2880, 17}},
		ServiceSynapseNhttp:    {{8280, 6}, {8280, 17}},
		ServiceSynapseNhttps:   {{8243, 6}, {8243, 17}},
		ServiceSynapsisEdge:    {{5008, 6}, {5008, 17}},
		ServiceSyncEm7:         {{7707, 6}, {7707, 17}},
		ServiceSynchromesh:     {{4548, 6}, {4548, 17}},
		ServiceSynchronetDb:    {{6100, 6}, {6100, 17}},
		ServiceSynchronetRtc:   {{6101, 6}, {6101, 17}},
		ServiceSynchronetUpd:   {{6102, 6}, {6102, 17}},
		ServiceSynchronite:     {{4106, 6}, {4106, 17}},
		ServiceSyncserver:      {{2647, 6}, {2647, 17}},
		ServiceSyncserverssl:   {{2679, 6}, {2679, 17}},
		ServiceSynctest:        {{45045, 6}},
		ServiceSynelData:       {{3734, 6}, {3734, 17}},
		ServiceSynopticsTrap:   {{412, 6}, {412, 17}},
		ServiceSynoticsBroker:  {{392, 6}, {392, 17}},
		ServiceSynoticsRelay:   {{391, 6}, {391, 17}},
		ServiceSypeTransport:   {{9911, 6}, {9911, 17}},
		ServiceSyscomlan:       {{1065, 6}, {1065, 17}},
		ServiceSyserverremote:  {{6418, 6}},
		ServiceSysinfoSp:       {{11967, 6}, {11967, 17}},
		ServiceSyslog:          {{514, 17}},
		ServiceSyslogConn:      {{601, 6}, {601, 17}},
		ServiceSyslogTls:       {{6514, 6}, {6514, 17}, {6514, 33}},
		ServiceSysopt:          {{3281, 6}, {3281, 17}},
		ServiceSysorb:          {{3241, 6}, {3241, 17}},
		ServiceSysrqd:          {{4094, 6}, {4094, 17}},
		ServiceSysscanner:      {{3251, 6}, {3251, 17}},
		ServiceSystat:          {{11, 6}, {11, 17}},
		ServiceSystemMonitor:   {{2609, 6}, {2609, 17}},
		ServiceSystemicsSox:    {{5406, 6}, {5406, 17}},
		ServiceT128Gateway:     {{1627, 6}, {1627, 17}},
		ServiceT1E1OverIp:      {{3175, 6}, {3175, 17}},
		ServiceT1distproc:      {{1274, 6}, {1274, 17}},
		ServiceT1distproc60:    {{32249, 6}, {32249, 17}},
		ServiceT2Brm:           {{7933, 6}, {7933, 17}},
		ServiceT2Drm:           {{7932, 6}, {7932, 17}},
		ServiceT5Straton:       {{11173, 6}},
		ServiceTabula:          {{1437, 6}, {1437, 17}},
		ServiceTacacs:          {{49, 6}, {49, 17}},
		ServiceTacacsDs:        {{65, 6}, {65, 17}},
		ServiceTacnews:         {{98, 6}, {98, 17}},
		ServiceTacticalauth:    {{2392, 6}, {2392, 17}},
		ServiceTaepAsSvc:       {{5111, 6}, {5111, 17}},
		ServiceTagPm:           {{5073, 6}, {5073, 17}},
		ServiceTagUps1:         {{3573, 6}, {3573, 17}},
		ServiceTaiclock:        {{4014, 6}, {4014, 17}},
		ServiceTalPod:          {{6149, 6}, {6149, 17}},
		ServiceTalarianMcast1:  {{4015, 6}, {4015, 17}},
		ServiceTalarianMcast2:  {{4016, 6}, {4016, 17}},
		ServiceTalarianMcast3:  {{4017, 6}, {4017, 17}},
		ServiceTalarianMcast4:  {{4018, 6}, {4018, 17}},
		ServiceTalarianMcast5:  {{4019, 6}, {4019, 17}},
		ServiceTalarianMqs:     {{2493, 6}, {2493, 17}},
		ServiceTalarianTcp:     {{5101, 6}},
		ServiceTalarianUdp:     {{5101, 17}},
		ServiceTaligentLm:      {{1475, 6}, {1475, 17}},
		ServiceTalikaserver:    {{22763, 6}, {22763, 17}},
		ServiceTalk:            {{517, 17}, {517, 6}},
		ServiceTalnet:          {{1838, 6}, {1838, 17}},
		ServiceTalonDisc:       {{7011, 6}, {7011, 17}},
		ServiceTalonEngine:     {{7012, 6}, {7012, 17}},
		ServiceTalonWebserver:  {{7015, 6}, {7015, 17}},
		ServiceTambora:         {{9020, 6}, {9020, 17}},
		ServiceTams:            {{2726, 6}, {2726, 17}},
		ServiceTapestry:        {{1922, 6}, {1922, 17}},
		ServiceTapeware:        {{3817, 6}, {3817, 17}},
		ServiceTappiBoxnet:     {{2306, 6}, {2306, 17}},
		ServiceTarantella:      {{3144, 6}, {3144, 17}},
		ServiceTargusGetdata:   {{5200, 6}, {5200, 17}},
		ServiceTargusGetdata1:  {{5201, 6}, {5201, 17}},
		ServiceTargusGetdata2:  {{5202, 6}, {5202, 17}},
		ServiceTargusGetdata3:  {{5203, 6}, {5203, 17}},
		ServiceTaserver:        {{3552, 6}, {3552, 17}},
		ServiceTaskmanPort:     {{2470, 6}, {2470, 17}},
		ServiceTaskmaster2000:  {{2402, 6}, {2402, 17}},
		ServiceTaspNet:         {{25900, 6}, {25900, 17}},
		ServiceTaurusWh:        {{1610, 6}, {1610, 17}},
		ServiceTbrpf:           {{712, 6}, {712, 17}},
		ServiceTccHttp:         {{24680, 6}, {24680, 17}},
		ServiceTcimControl:     {{2729, 6}, {2729, 17}},
		ServiceTclprodebugger:  {{2576, 6}, {2576, 17}},
		ServiceTcoaddressbook:  {{1977, 6}, {1977, 17}},
		ServiceTcoflashagent:   {{1975, 6}, {1975, 17}},
		ServiceTcoregagent:     {{1976, 6}, {1976, 17}},
		ServiceTcpIdPort:       {{1999, 6}, {1999, 17}},
		ServiceTcpdataserver:   {{3805, 6}, {3805, 17}},
		ServiceTcpmux:          {{1, 6}, {1, 17}},
		ServiceTcpnethaspsrv:   {{475, 6}, {475, 17}},
		ServiceTdPostman:       {{1049, 6}, {1049, 17}},
		ServiceTdReplica:       {{268, 6}, {268, 17}},
		ServiceTdService:       {{267, 6}, {267, 17}},
		ServiceTdaccess:        {{2910, 6}, {2910, 17}},
		ServiceTdmoip:          {{2142, 6}, {2142, 17}},
		ServiceTdpSuite:        {{1814, 6}, {1814, 17}},
		ServiceTeamcoherence:   {{9222, 6}, {9222, 17}},
		ServiceTec5Sdctp:       {{9668, 6}, {9668, 17}},
		ServiceTeedtap:         {{559, 6}, {559, 17}},
		ServiceTekpls:          {{1946, 6}, {1946, 17}},
		ServiceTelaconsole:     {{5428, 6}, {5428, 17}},
		ServiceTelefinder:      {{1474, 6}, {1474, 17}},
		ServiceTelelpathattack: {{5011, 6}, {5011, 17}},
		ServiceTelelpathstart:  {{5010, 6}, {5010, 17}},
		ServiceTeleniumdaemon:  {{2060, 6}, {2060, 17}},
		ServiceTelesisLicman:   {{1380, 6}, {1380, 17}},
		ServiceTelindus:        {{1728, 6}, {1728, 17}},
		ServiceTell:            {{754, 17}},
		ServiceTellumatNms:     {{3549, 6}, {3549, 17}},
		ServiceTelnet:          {{23, 6}, {23, 17}},
		ServiceTelnetcpcd:      {{3696, 6}, {3696, 17}},
		ServiceTelnets:         {{992, 6}, {992, 17}},
		ServiceTelopsLmd:       {{7491, 6}, {7491, 17}},
		ServiceTempestPort:     {{11600, 6}, {11600, 17}},
		ServiceTempo:           {{526, 6}, {526, 17}},
		ServiceTenfold:         {{658, 6}, {658, 17}},
		ServiceTentacle:        {{41121, 6}},
		ServiceTerabase:        {{4000, 6}, {4000, 17}},
		ServiceTeradataordbms:  {{8002, 6}, {8002, 17}},
		ServiceTeredo:          {{3544, 6}, {3544, 17}},
		ServiceTerminaldb:      {{2008, 17}, {2018, 6}},
		ServiceTeslaSysMsg:     {{7631, 6}},
		ServiceTetrinet:        {{31457, 6}, {31457, 17}},
		ServiceTexai:           {{5048, 6}},
		ServiceTexar:           {{333, 6}, {333, 17}},
		ServiceTfido:           {{60177, 6}, {60177, 17}},
		ServiceTftp:            {{69, 6}, {69, 17}},
		ServiceTftpMcast:       {{1758, 6}, {1758, 17}},
		ServiceTftps:           {{3713, 6}, {3713, 17}},
		ServiceTgcconnect:      {{4146, 6}, {4146, 17}},
		ServiceTgp:             {{1223, 6}, {1223, 17}},
		ServiceThermoCalc:      {{6201, 17}},
		ServiceThetaLm:         {{2296, 6}, {2296, 17}},
		ServiceThrp:            {{3963, 6}, {3963, 17}},
		ServiceThrtx:           {{4139, 6}, {4139, 17}},
		ServiceThtTreasure:     {{1832, 6}, {1832, 17}},
		ServiceTicf1:           {{492, 6}, {492, 17}},
		ServiceTicf2:           {{493, 6}, {493, 17}},
		ServiceTickPort:        {{3200, 6}, {3200, 17}},
		ServiceTidp:            {{7548, 6}, {7548, 17}},
		ServiceTig:             {{3943, 6}, {3943, 17}},
		ServiceTigv2:           {{4124, 6}, {4124, 17}},
		ServiceTimbuktu:        {{407, 6}, {407, 17}},
		ServiceTimbuktuSrv1:    {{1417, 6}, {1417, 17}},
		ServiceTimbuktuSrv2:    {{1418, 6}, {1418, 17}},
		ServiceTimbuktuSrv3:    {{1419, 6}, {1419, 17}},
		ServiceTimbuktuSrv4:    {{1420, 6}, {1420, 17}},
		ServiceTime:            {{37, 6}, {37, 17}},
		ServiceTimed:           {{525, 6}, {525, 17}},
		ServiceTimeflies:       {{1362, 6}, {1362, 17}},
		ServiceTimelot:         {{3243, 6}, {3243, 17}},
		ServiceTimestenbroker:  {{3754, 6}, {3754, 17}},
		ServiceTinc:            {{655, 6}, {655, 17}},
		ServiceTinymessage:     {{5104, 17}},
		ServiceTip2:            {{3372, 6}, {3372, 17}},
		ServiceTipAppServer:    {{3160, 6}, {3160, 17}},
		ServiceTipc:            {{6118, 17}},
		ServiceTircproxy:       {{7666, 6}},
		ServiceTivoconnect:     {{2190, 6}, {2190, 17}},
		ServiceTivoliNpm:       {{1965, 6}, {1965, 17}},
		ServiceTksocket:        {{2915, 6}, {2915, 17}},
		ServiceTl1:             {{2361, 6}, {2361, 17}},
		ServiceTl1Lv:           {{3081, 6}, {3081, 17}},
		ServiceTl1Raw:          {{3082, 6}, {3082, 17}},
		ServiceTl1RawSsl:       {{6251, 6}, {6251, 17}},
		ServiceTl1Ssh:          {{6252, 6}, {6252, 17}},
		ServiceTl1Telnet:       {{3083, 6}, {3083, 17}},
		ServiceTlIpcproxy:      {{4176, 6}},
		ServiceTlisrv:          {{1527, 6}, {1527, 17}},
		ServiceTmesisUpshot:    {{2798, 6}, {2798, 17}},
		ServiceTmi:             {{8300, 6}, {8300, 17}},
		ServiceTmoIconSync:     {{5583, 6}, {5583, 17}},
		ServiceTmophl7mts:      {{20046, 6}, {20046, 17}},
		ServiceTmosms0:         {{5580, 6}, {5580, 17}},
		ServiceTmosms1:         {{5581, 6}, {5581, 17}},
		ServiceTnETOS:          {{377, 6}, {377, 17}},
		ServiceTnTiming:        {{2739, 6}, {2739, 17}},
		ServiceTnTlFd1:         {{476, 6}, {476, 17}},
		ServiceTnTlFd2:         {{1584, 6}, {1584, 17}},
		ServiceTnTlR1:          {{1580, 6}},
		ServiceTnTlR2:          {{1580, 17}},
		ServiceTnTlW1:          {{474, 6}},
		ServiceTnTlW2:          {{474, 17}},
		ServiceTnmpv2:          {{3686, 6}, {3686, 17}},
		ServiceTnosDp:          {{7902, 6}, {7902, 17}},
		ServiceTnosDps:         {{7903, 6}, {7903, 17}},
		ServiceTnosSp:          {{7901, 6}, {7901, 17}},
		ServiceTnp:             {{8321, 6}, {8321, 17}},
		ServiceTnp1Port:        {{4024, 6}, {4024, 17}},
		ServiceTnpDiscover:     {{8320, 6}, {8320, 17}},
		ServiceTnsAdv:          {{3309, 6}, {3309, 17}},
		ServiceTnsCml:          {{590, 6}, {590, 17}},
		ServiceTnsServer:       {{3308, 6}, {3308, 17}},
		ServiceToad:            {{2669, 6}, {2669, 17}},
		ServiceTolfab:          {{20167, 6}, {20167, 17}},
		ServiceTolteces:        {{4375, 6}, {4375, 17}},
		ServiceTomatoSprings:   {{3040, 6}, {3040, 17}},
		ServiceTonidods:        {{24465, 6}, {24465, 17}},
		ServiceTopflow:         {{2885, 6}, {2885, 17}},
		ServiceTopflowSsl:      {{3885, 6}, {3885, 17}},
		ServiceTopovistaData:   {{3906, 6}, {3906, 17}},
		ServiceTopx:            {{2436, 6}, {2436, 17}},
		ServiceToruxserver:     {{5153, 6}},
		ServiceTouchnetplus:    {{2158, 6}, {2158, 17}},
		ServiceTpcsrvr:         {{2078, 6}, {2078, 17}},
		ServiceTpdu:            {{1430, 6}, {1430, 17}},
		ServiceTpip:            {{594, 6}, {594, 17}},
		ServiceTpmd:            {{1906, 6}, {1906, 17}},
		ServiceTproxy:          {{8081, 6}, {8081, 17}},
		ServiceTqdata:          {{2700, 6}, {2700, 17}},
		ServiceTrRsrbP1:        {{1987, 6}, {1987, 17}},
		ServiceTrRsrbP2:        {{1988, 6}, {1988, 17}},
		ServiceTrRsrbP3:        {{1989, 6}, {1989, 17}},
		ServiceTrRsrbPort:      {{1996, 6}, {1996, 17}},
		ServiceTraceroute:      {{33434, 6}, {33434, 17}},
		ServiceTrack:           {{20670, 6}, {20670, 17}},
		ServiceTragic:          {{2642, 6}, {2642, 17}},
		ServiceTraingpsdata:    {{9277, 17}},
		ServiceTram:            {{4567, 6}, {4567, 17}},
		ServiceTransact:        {{1869, 6}, {1869, 17}},
		ServiceTransmitPort:    {{5282, 6}, {5282, 17}},
		ServiceTrap:            {{4020, 6}, {4020, 17}},
		ServiceTrapDaemon:      {{3600, 6}, {3600, 17}},
		ServiceTrapPort:        {{3857, 6}, {3857, 17}},
		ServiceTrapPortMom:     {{3858, 6}, {3858, 17}},
		ServiceTraversal:       {{4678, 6}, {4678, 17}},
		ServiceTravsoftIpxT:    {{2644, 6}, {2644, 17}},
		ServiceTrcNetpoll:      {{2405, 6}, {2405, 17}},
		ServiceTreehopper:      {{3959, 6}, {3959, 17}},
		ServiceTrendchipDcp:    {{3608, 6}, {3608, 17}},
		ServiceTributary:       {{2580, 6}, {2580, 17}},
		ServiceTridentData:     {{7727, 6}, {7727, 17}},
		ServiceTrim:            {{1137, 6}, {1137, 17}},
		ServiceTrimEvent:       {{4322, 6}, {4322, 17}},
		ServiceTrimIce:         {{4323, 6}, {4323, 17}},
		ServiceTriomotion:      {{3240, 6}, {3240, 17}},
		ServiceTrip:            {{6069, 6}, {6069, 17}},
		ServiceTripe:           {{4070, 6}, {4070, 17}},
		ServiceTripwire:        {{1169, 6}, {1169, 17}},
		ServiceTriquestLm:      {{1588, 6}, {1588, 17}},
		ServiceTrisoap:         {{10200, 6}, {10200, 17}},
		ServiceTrispenSra:      {{9555, 6}, {9555, 17}},
		ServiceTritiumCan:      {{4876, 6}, {4876, 17}},
		ServiceTrivnet1:        {{8200, 6}, {8200, 17}},
		ServiceTrivnet2:        {{8201, 6}, {8201, 17}},
		ServiceTrnsprntproxy:   {{3346, 6}, {3346, 17}},
		ServiceTroff:           {{2014, 6}},
		ServiceTrp:             {{2156, 6}, {2156, 17}},
		ServiceTruckstar:       {{4725, 6}, {4725, 17}},
		ServiceTruecm:          {{8804, 6}, {8804, 17}},
		ServiceTrustedWeb:      {{3011, 6}, {3011, 17}},
		ServiceTrustestablish:  {{2573, 6}, {2573, 17}},
		ServiceTsa:             {{6689, 6}, {6689, 17}},
		ServiceTsaf:            {{12753, 6}, {12753, 17}},
		ServiceTsb:             {{2741, 6}, {2741, 17}},
		ServiceTsb2:            {{2742, 6}, {2742, 17}},
		ServiceTscchat:         {{2330, 6}, {2330, 17}},
		ServiceTsdos390:        {{1237, 6}, {1237, 17}},
		ServiceTserver:         {{450, 6}, {450, 17}},
		ServiceTsilb:           {{2489, 6}, {2489, 17}},
		ServiceTsp:             {{3653, 6}, {3653, 17}},
		ServiceTsrmagt:         {{2077, 6}, {2077, 17}},
		ServiceTsspmap:         {{1568, 6}, {1568, 17}},
		ServiceTtat3lb:         {{3579, 6}, {3579, 17}},
		ServiceTtc:             {{2483, 6}, {2483, 17}},
		ServiceTtcEtap:         {{2675, 6}, {2675, 17}},
		ServiceTtcEtapDs:       {{2978, 6}, {2978, 17}},
		ServiceTtcEtapNs:       {{2977, 6}, {2977, 17}},
		ServiceTtcSsl:          {{2484, 6}, {2484, 17}},
		ServiceTtcmremotectrl:  {{3468, 6}, {3468, 17}},
		ServiceTtgProtocol:     {{2862, 6}, {2862, 17}},
		ServiceTtlPublisher:    {{5462, 6}, {5462, 17}},
		ServiceTtlpriceproxy:   {{5463, 6}, {5463, 17}},
		ServiceTtnrepository:   {{2943, 6}, {2943, 17}},
		ServiceTtntspauto:      {{3474, 6}, {3474, 17}},
		ServiceTtyinfo:         {{2012, 6}},
		ServiceTunalyzer:       {{5748, 6}, {5748, 17}},
		ServiceTunatic:         {{5747, 6}, {5747, 17}},
		ServiceTungstenHttp:    {{9762, 6}, {9762, 17}},
		ServiceTungstenHttps:   {{9443, 6}, {9443, 17}},
		ServiceTunnel:          {{604, 6}, {604, 17}},
		ServiceTunstallPnc:     {{1846, 6}, {1846, 17}},
		ServiceTurbonote1:      {{39681, 6}, {39681, 17}},
		ServiceTurbonote2:      {{34249, 6}, {34249, 17}},
		ServiceTvbus:           {{2191, 6}, {2191, 17}},
		ServiceTvdumtrayPort:   {{3492, 6}, {3492, 17}},
		ServiceTveAnnounce:     {{2670, 6}, {2670, 17}},
		ServiceTvnetworkvideo:  {{3791, 6}, {3791, 17}},
		ServiceTvpm:            {{21800, 6}, {21800, 17}},
		ServiceTwAuthKey:       {{27999, 6}, {27999, 17}},
		ServiceTwampControl:    {{862, 6}, {862, 17}},
		ServiceTwcss:           {{3428, 6}, {3428, 17}},
		ServiceTwds:            {{8937, 6}},
		ServiceTwrpc:           {{3479, 6}, {3479, 17}},
		ServiceTwsdss:          {{3012, 6}, {3012, 17}},
		ServiceUDbap:           {{3584, 6}, {3584, 17}},
		ServiceUaSecureagent:   {{19194, 6}, {19194, 17}},
		ServiceUaac:            {{145, 6}, {145, 17}},
		ServiceUacs:            {{2768, 6}, {2768, 17}},
		ServiceUadtc:           {{2767, 6}, {2767, 17}},
		ServiceUaiact:          {{1470, 6}, {1470, 17}},
		ServiceUarps:           {{219, 6}, {219, 17}},
		ServiceUbDnsControl:    {{8953, 6}},
		ServiceUbroker:         {{7887, 6}, {7887, 17}},
		ServiceUbxd:            {{4034, 6}, {4034, 17}},
		ServiceUcentricDs:      {{2879, 6}, {2879, 17}},
		ServiceUcontrol:        {{13894, 6}, {13894, 17}},
		ServiceUdpSrPort:       {{1624, 6}, {1624, 17}},
		ServiceUdpradio:        {{1833, 6}, {1833, 17}},
		ServiceUdrawgraph:      {{2542, 6}, {2542, 17}},
		ServiceUdrive:          {{1867, 6}, {1867, 17}},
		ServiceUdt_os:          {{1382, 6}, {1382, 17}},
		ServiceUfastroInstr:    {{3720, 6}, {3720, 17}},
		ServiceUfmp:            {{6306, 6}, {6306, 17}},
		ServiceUis:             {{390, 6}, {390, 17}},
		ServiceUlistproc:       {{372, 6}, {372, 17}},
		ServiceUlp:             {{522, 6}, {522, 17}},
		ServiceUlpnet:          {{483, 6}, {483, 17}},
		ServiceUltimad:         {{1737, 6}, {1737, 17}},
		ServiceUltrabac:        {{1910, 6}, {1910, 17}},
		ServiceUltraseekHttp:   {{8765, 6}, {8765, 17}},
		ServiceUltrex:          {{1327, 6}, {1327, 17}},
		ServiceUma:             {{144, 6}, {144, 17}},
		ServiceUmmPort:         {{3098, 6}, {3098, 17}},
		ServiceUms:             {{2248, 6}, {2248, 17}},
		ServiceUmsp:            {{2110, 6}, {2110, 17}},
		ServiceUnbindCluster:   {{2138, 6}, {2138, 17}},
		ServiceUndoLm:          {{5281, 6}},
		ServiceUnet:            {{1189, 6}, {1189, 17}},
		ServiceUnglue:          {{2655, 6}, {2655, 17}},
		ServiceUnicall:         {{4343, 6}, {4343, 17}},
		ServiceUnicontrol:      {{2437, 6}, {2437, 17}},
		ServiceUnidataLdm:      {{388, 6}, {388, 17}},
		ServiceUnieng:          {{5730, 6}, {5730, 17}},
		ServiceUnify:           {{181, 6}, {181, 17}},
		ServiceUnifyAdapter:    {{1889, 6}, {1889, 17}},
		ServiceUnifyDebug:      {{4867, 6}, {4867, 17}},
		ServiceUnifyadmin:      {{2696, 6}, {2696, 17}},
		ServiceUnihubServer:    {{2357, 6}, {2357, 17}},
		ServiceUnikeypro:       {{4127, 6}, {4127, 17}},
		ServiceUnimobilectrl:   {{2927, 6}, {2927, 17}},
		ServiceUniport:         {{9629, 6}, {9629, 17}},
		ServiceUnisql:          {{1978, 6}, {1978, 17}},
		ServiceUnisqlJava:      {{1979, 6}, {1979, 17}},
		ServiceUnisysEportal:   {{37654, 6}, {37654, 17}},
		ServiceUnisysLm:        {{1823, 6}, {1823, 17}},
		ServiceUnite:           {{3217, 6}, {3217, 17}},
		ServiceUnivAppserver:   {{1233, 6}, {1233, 17}},
		ServiceUniverse_suite:  {{4184, 6}, {4184, 17}},
		ServiceUnivision:       {{2820, 6}, {2820, 17}},
		ServiceUnixStatus:      {{1957, 6}, {1957, 17}},
		ServiceUnizensus:       {{1151, 6}, {1151, 17}},
		ServiceUnot:            {{5055, 6}, {5055, 17}},
		ServiceUohost:          {{3314, 6}, {3314, 17}},
		ServiceUorb:            {{3313, 6}, {3313, 17}},
		ServiceUpgrade:         {{2537, 6}, {2537, 17}},
		ServiceUpnotifyp:       {{4445, 6}, {4445, 17}},
		ServiceUpnotifyps:      {{3356, 6}, {3356, 17}},
		ServiceUps:             {{401, 6}, {401, 17}},
		ServiceUpsEngine:       {{3664, 6}, {3664, 17}},
		ServiceUpsOnlinet:      {{7010, 6}, {7010, 17}},
		ServiceUpsnotifyprot:   {{2648, 6}, {2648, 17}},
		ServiceUpstriggervsw:   {{3786, 6}, {3786, 17}},
		ServiceUrbisnet:        {{2745, 6}, {2745, 17}},
		ServiceUrd:             {{465, 6}},
		ServiceUrldPort:        {{3534, 6}, {3534, 17}},
		ServiceUrm:             {{606, 6}, {606, 17}},
		ServiceUsCli:           {{8082, 6}, {8082, 17}},
		ServiceUsGv:            {{1370, 6}, {1370, 17}},
		ServiceUsSrv:           {{8083, 6}, {8083, 17}},
		ServiceUserManager:     {{3272, 6}, {3272, 17}},
		ServiceUsicontentpush:  {{7998, 17}},
		ServiceUtcd:            {{1506, 6}, {1506, 17}},
		ServiceUtime:           {{519, 6}, {519, 17}},
		ServiceUtmpcd:          {{431, 6}, {431, 17}},
		ServiceUtmpsd:          {{430, 6}, {430, 17}},
		ServiceUtsftp:          {{2529, 6}, {2529, 17}},
		ServiceUucp:            {{540, 6}, {540, 17}},
		ServiceUucpPath:        {{117, 6}, {117, 17}},
		ServiceUucpRlogin:      {{541, 6}, {541, 17}},
		ServiceUuidgen:         {{697, 6}, {697, 17}},
		ServiceV2gSecc:         {{15118, 17}},
		ServiceV5ua:            {{5675, 6}, {5675, 17}, {5675, 132}},
		ServiceVOneSpp:         {{3845, 6}, {3845, 17}},
		ServiceVaPacbase:       {{3676, 6}, {3676, 17}},
		ServiceVacdsmApp:       {{671, 6}, {671, 17}},
		ServiceVacdsmSws:       {{670, 6}, {670, 17}},
		ServiceVad:             {{14154, 6}, {14154, 17}},
		ServiceValisysLm:       {{1457, 6}, {1457, 17}},
		ServiceVantronixMgmt:   {{8034, 6}, {8034, 17}},
		ServiceVaprtm:          {{3654, 6}, {3654, 17}},
		ServiceVaradero0:       {{4837, 6}, {4837, 17}},
		ServiceVaradero1:       {{4838, 6}, {4838, 17}},
		ServiceVaradero2:       {{4839, 6}, {4839, 17}},
		ServiceVat:             {{3456, 6}, {3456, 17}},
		ServiceVatControl:      {{3457, 6}, {3457, 17}},
		ServiceVatata:          {{4188, 6}, {4188, 17}},
		ServiceVatp:            {{690, 6}, {690, 17}},
		ServiceVaultbase:       {{1771, 6}, {1771, 17}},
		ServiceVce:             {{11111, 6}, {11111, 17}},
		ServiceVchat:           {{1168, 6}, {1168, 17}},
		ServiceVcnetLinkV10:    {{2554, 6}, {2554, 17}},
		ServiceVcomTunnel:      {{8001, 6}, {8001, 17}},
		ServiceVcrp:            {{3073, 6}, {3073, 17}},
		ServiceVcsApp:          {{14141, 6}, {14141, 17}},
		ServiceVcscmd:          {{14150, 6}},
		ServiceVdmplay:         {{1707, 6}, {1707, 17}},
		ServiceVemmi:           {{575, 6}, {575, 17}},
		ServiceVenus:           {{2430, 6}, {2430, 17}},
		ServiceVenusSe:         {{2431, 6}, {2431, 17}},
		ServiceVeracity:        {{1062, 6}, {1062, 17}},
		ServiceVergencecm:      {{2771, 6}, {2771, 17}},
		ServiceVerismart:       {{3270, 6}, {3270, 17}},
		ServiceVeritasTcp1:     {{2802, 6}},
		ServiceVeritasUcl:      {{2148, 6}, {2148, 17}},
		ServiceVeritasUdp1:     {{2802, 17}},
		ServiceVeritasVis1:     {{2993, 6}, {2993, 17}},
		ServiceVeritasVis2:     {{2994, 6}, {2994, 17}},
		ServiceVeritas_pbx:     {{1556, 6}, {1556, 17}},
		ServiceVeronica:        {{2770, 6}, {2770, 17}},
		ServiceVersaTek:        {{2610, 6}, {2610, 17}},
		ServiceVersatalk:       {{3738, 6}, {3738, 17}},
		ServiceVersiera:        {{9050, 6}},
		ServiceVettcp:          {{78, 6}, {78, 17}},
		ServiceVfbp:            {{6678, 6}},
		ServiceVfbpDisc:        {{6678, 17}},
		ServiceVfmobile:        {{5646, 6}},
		ServiceVfo:             {{1056, 6}, {1056, 17}},
		ServiceVhd:             {{3802, 6}, {3802, 17}},
		ServiceVid:             {{769, 6}, {769, 17}},
		ServiceVideoActivmail:  {{1398, 6}, {1398, 17}},
		ServiceVideobeans:      {{3058, 6}, {3058, 17}},
		ServiceVideotex:        {{516, 6}, {516, 17}},
		ServiceVideteCipc:      {{1927, 6}, {1927, 17}},
		ServiceVidigo:          {{3231, 6}, {3231, 17}},
		ServiceVidsAvtp:        {{1853, 6}, {1853, 17}},
		ServiceVieoFe:          {{3245, 6}, {3245, 17}},
		ServiceVinainstall:     {{4344, 6}, {4344, 17}},
		ServiceVipera:          {{12012, 6}, {12012, 17}},
		ServiceViperaSsl:       {{12013, 6}, {12013, 17}},
		ServiceVipremoteagent:  {{3752, 6}, {3752, 17}},
		ServiceVirprotLm:       {{7121, 6}, {7121, 17}},
		ServiceVirtualPlaces:   {{1533, 6}, {1533, 17}},
		ServiceVirtualTime:     {{1852, 6}, {1852, 17}},
		ServiceVirtualtape:     {{2386, 6}, {2386, 17}},
		ServiceVirtualuser:     {{5423, 6}, {5423, 17}},
		ServiceVisd:            {{9284, 6}, {9284, 17}},
		ServiceVisicronVs:      {{4307, 6}, {4307, 17}},
		ServiceVisinetGui:      {{3601, 6}, {3601, 17}},
		ServiceVision_elmd:     {{6673, 6}, {6673, 17}},
		ServiceVision_server:   {{6672, 6}, {6672, 17}},
		ServiceVisionpyramid:   {{1247, 6}, {1247, 17}},
		ServiceVisitview:       {{1631, 6}, {1631, 17}},
		ServiceVista4gl:        {{24249, 6}, {24249, 17}},
		ServiceVistiumShare:    {{1545, 6}, {1545, 17}},
		ServiceVitalanalysis:   {{2474, 6}, {2474, 17}},
		ServiceViziblebrowser:  {{1868, 6}, {1868, 17}},
		ServiceVlsiLm:          {{1500, 6}, {1500, 17}},
		ServiceVmnet:           {{175, 6}, {175, 17}},
		ServiceVmodem:          {{3141, 6}, {3141, 17}},
		ServiceVmpwscs:         {{214, 6}, {214, 17}},
		ServiceVmrdp:           {{2179, 6}, {2179, 17}},
		ServiceVmsvc:           {{7024, 6}, {7024, 17}},
		ServiceVmsvc2:          {{7025, 6}, {7025, 17}},
		ServiceVmwareFdm:       {{8182, 6}, {8182, 17}},
		ServiceVnas:            {{577, 6}, {577, 17}},
		ServiceVnetd:           {{13724, 6}, {13724, 17}},
		ServiceVnsTp:           {{7802, 17}},
		ServiceVnsstr:          {{3321, 6}, {3321, 17}},
		ServiceVnwkPrapi:       {{2538, 6}, {2538, 17}},
		ServiceVnyx:            {{8699, 6}, {8699, 17}},
		ServiceVocaltecAdmin:   {{1796, 6}, {1796, 17}},
		ServiceVocaltecGold:    {{6670, 6}, {6670, 17}},
		ServiceVocaltecHos:     {{25793, 6}, {25793, 17}},
		ServiceVocaltecPhone:   {{22555, 17}},
		ServiceVocaltecWconf:   {{22555, 6}},
		ServiceVofrGateway:     {{21590, 6}, {21590, 17}},
		ServiceVoispeedPort:    {{3541, 6}, {3541, 17}},
		ServiceVolley:          {{3625, 6}, {3625, 17}},
		ServiceVop:             {{4433, 6}},
		ServiceVopied:          {{13783, 6}, {13783, 17}},
		ServiceVoxelstorm:      {{28200, 6}, {28200, 17}},
		ServiceVp2p:            {{8473, 6}, {8473, 17}},
		ServiceVpa:             {{5164, 6}},
		ServiceVpaDisc:         {{5164, 17}},
		ServiceVpac:            {{1517, 6}, {1517, 17}},
		ServiceVpad:            {{1516, 6}, {1516, 17}},
		ServiceVpjp:            {{1345, 6}, {1345, 17}},
		ServiceVpmUdp:          {{5046, 17}},
		ServiceVpnz:            {{1224, 6}, {1224, 17}},
		ServiceVpp:             {{677, 6}, {677, 17}},
		ServiceVppsQua:         {{672, 6}, {672, 17}},
		ServiceVppsVia:         {{676, 6}, {676, 17}},
		ServiceVpsipport:       {{2649, 6}, {2649, 17}},
		ServiceVpvc:            {{1519, 6}, {1519, 17}},
		ServiceVpvd:            {{1518, 6}, {1518, 17}},
		ServiceVqp:             {{1589, 6}, {1589, 17}},
		ServiceVrace:           {{9300, 6}, {9300, 17}},
		ServiceVrcommerce:      {{2530, 6}, {2530, 17}},
		ServiceVrpn:            {{3883, 6}, {3883, 17}},
		ServiceVrt:             {{4991, 6}, {4991, 17}},
		ServiceVrtlVmfDs:       {{1956, 6}, {1956, 17}},
		ServiceVrtlVmfSa:       {{2074, 6}, {2074, 17}},
		ServiceVrtp:            {{2255, 6}, {2255, 17}},
		ServiceVrtsAtPort:      {{2821, 6}, {2821, 17}},
		ServiceVrtsAuthPort:    {{4032, 6}, {4032, 17}},
		ServiceVrtsIpcserver:   {{1317, 6}, {1317, 17}},
		ServiceVrtsRegistry:    {{2410, 6}, {2410, 17}},
		ServiceVrtsTdd:         {{14149, 6}, {14149, 17}},
		ServiceVrtstrapserver:  {{1885, 6}, {1885, 17}},
		ServiceVrxpservman:     {{4147, 6}, {4147, 17}},
		ServiceVsServer:        {{3280, 6}, {3280, 17}},
		ServiceVsaiport:        {{3317, 6}, {3317, 17}},
		ServiceVsamredirector:  {{2387, 6}, {2387, 17}},
		ServiceVsatControl:     {{1880, 6}, {1880, 17}},
		ServiceVscp:            {{9598, 6}, {9598, 17}},
		ServiceVseconnector:    {{2893, 6}, {2893, 17}},
		ServiceVsiOmega:        {{7566, 6}, {7566, 17}},
		ServiceVsiadmin:        {{2539, 6}, {2539, 17}},
		ServiceVsinet:          {{996, 6}, {996, 17}},
		ServiceVsixml:          {{2996, 6}, {2996, 17}},
		ServiceVslmp:           {{312, 6}, {312, 17}},
		ServiceVsnmAgent:       {{3375, 6}, {3375, 17}},
		ServiceVspread:         {{2695, 6}, {2695, 17}},
		ServiceVstat:           {{7779, 6}, {7779, 17}},
		ServiceVtSsl:           {{3509, 6}, {3509, 17}},
		ServiceVtp:             {{16666, 17}},
		ServiceVtrEmulator:     {{3122, 6}, {3122, 17}},
		ServiceVtsRpc:          {{5780, 6}},
		ServiceVtsas:           {{5070, 6}, {5070, 17}},
		ServiceVtuComms:        {{2216, 6}, {2216, 17}},
		ServiceVulture:         {{3482, 6}, {3482, 17}},
		ServiceVvrControl:      {{4145, 6}, {4145, 17}},
		ServiceVvrData:         {{8199, 6}, {8199, 17}},
		ServiceVxAuthPort:      {{3207, 6}, {3207, 17}},
		ServiceVxcrnbuport:     {{3652, 6}, {3652, 17}},
		ServiceVytalvaultbrtp:  {{2546, 6}, {2546, 17}},
		ServiceVytalvaultpipe:  {{2548, 6}, {2548, 17}},
		ServiceVytalvaultvsmp:  {{2547, 6}, {2547, 17}},
		ServiceWaascluster:     {{5787, 17}},
		ServiceWacp:            {{3633, 6}, {3633, 17}},
		ServiceWafs:            {{4049, 6}, {4049, 17}},
		ServiceWagService:      {{2608, 6}, {2608, 17}},
		ServiceWagoIoSystem:    {{2455, 6}, {2455, 17}},
		ServiceWagoService:     {{6626, 6}, {6626, 17}},
		ServiceWanscaler:       {{2312, 6}, {2312, 17}},
		ServiceWapPush:         {{2948, 6}, {2948, 17}},
		ServiceWapPushHttp:     {{4035, 6}, {4035, 17}},
		ServiceWapPushHttps:    {{4036, 6}, {4036, 17}},
		ServiceWapPushsecure:   {{2949, 6}, {2949, 17}},
		ServiceWapVcal:         {{9205, 6}, {9205, 17}},
		ServiceWapVcalS:        {{9207, 6}, {9207, 17}},
		ServiceWapVcard:        {{9204, 6}, {9204, 17}},
		ServiceWapVcardS:       {{9206, 6}, {9206, 17}},
		ServiceWapWsp:          {{9200, 6}, {9200, 17}},
		ServiceWapWspS:         {{9202, 6}, {9202, 17}},
		ServiceWapWspWtp:       {{9201, 6}, {9201, 17}},
		ServiceWapWspWtpS:      {{9203, 6}, {9203, 17}},
		ServiceWarehouse:       {{12322, 6}, {12322, 17}},
		ServiceWarehouseSss:    {{12321, 6}, {12321, 17}},
		ServiceWarmspotMgmt:    {{1074, 6}, {1074, 17}},
		ServiceWarmux:          {{3826, 6}, {3826, 17}},
		ServiceWatchdoc:        {{5744, 6}, {5744, 17}},
		ServiceWatchdocPod:     {{5743, 6}, {5743, 17}},
		ServiceWatchdogNt:      {{2723, 6}, {2723, 17}},
		ServiceWatchme7272:     {{7272, 6}, {7272, 17}},
		ServiceWatcomdebug:     {{3563, 6}, {3563, 17}},
		ServiceWatershedLm:     {{6143, 6}, {6143, 17}},
		ServiceWatilapp:        {{1269, 6}, {1269, 17}},
		ServiceWbemExpHttps:    {{5990, 6}, {5990, 17}},
		ServiceWbemHttp:        {{5988, 6}, {5988, 17}},
		ServiceWbemHttps:       {{5989, 6}, {5989, 17}},
		ServiceWbemRmi:         {{5987, 6}, {5987, 17}},
		ServiceWcbackup:        {{8912, 6}, {8912, 17}},
		ServiceWcpp:            {{4185, 6}, {4185, 17}},
		ServiceWcrRemlib:       {{4845, 6}, {4845, 17}},
		ServiceWeb2host:        {{1559, 6}, {1559, 17}},
		ServiceWebaccess:       {{1739, 6}, {1739, 17}},
		ServiceWebadmstart:     {{1110, 6}},
		ServiceWebcache:        {{8080, 6}, {8080, 17}},
		ServiceWebdata:         {{3748, 6}, {3748, 17}},
		ServiceWebemshttp:      {{2851, 6}, {2851, 17}},
		ServiceWeblogin:        {{2054, 6}, {2054, 17}},
		ServiceWebmachine:      {{1963, 6}, {1963, 17}},
		ServiceWebmail2:        {{3511, 6}, {3511, 17}},
		ServiceWebmethodsB2b:   {{2907, 6}, {2907, 17}},
		ServiceWebobjects:      {{1085, 6}, {1085, 17}},
		ServiceWebphone:        {{21845, 6}, {21845, 17}},
		ServiceWebsm:           {{9090, 6}, {9090, 17}},
		ServiceWebsphereSnmp:   {{3427, 6}, {3427, 17}},
		ServiceWebster:         {{765, 6}, {765, 17}},
		ServiceWebtie:          {{3342, 6}, {3342, 17}},
		ServiceWebyast:         {{4984, 6}},
		ServiceWello:           {{4177, 6}, {4177, 17}},
		ServiceWestecConnect:   {{5566, 6}},
		ServiceWestellStats:    {{1875, 6}, {1875, 17}},
		ServiceWfc:             {{4847, 6}, {4847, 17}},
		ServiceWfm:             {{4057, 6}, {4057, 17}},
		ServiceWfremotertm:     {{1046, 6}, {1046, 17}},
		ServiceWgNetforce:      {{3359, 6}, {3359, 17}},
		ServiceWherehoo:        {{5859, 6}, {5859, 17}},
		ServiceWhisker:         {{3233, 6}, {3233, 17}},
		ServiceWho:             {{513, 17}},
		ServiceWhoami:          {{565, 6}, {565, 17}},
		ServiceWhoisPlusPlus:   {{63, 6}, {63, 17}},
		ServiceWhosells:        {{2781, 6}, {2781, 17}},
		ServiceWhosockami:      {{2009, 17}, {2019, 6}},
		ServiceWibuKey:         {{22347, 6}, {22347, 17}},
		ServiceWiegand:         {{4390, 6}, {4390, 17}},
		ServiceWifree:          {{11208, 6}, {11208, 17}},
		ServiceWilkenlistener:  {{1890, 6}, {1890, 17}},
		ServiceWilly:           {{2518, 6}, {2518, 17}},
		ServiceWimaxasncp:      {{2231, 6}, {2231, 17}},
		ServiceWimd:            {{2980, 6}, {2980, 17}},
		ServiceWimsic:          {{1326, 6}, {1326, 17}},
		ServiceWindb:           {{2522, 6}, {2522, 17}},
		ServiceWinddlb:         {{1565, 6}, {1565, 17}},
		ServiceWinddx:          {{1727, 6}, {1727, 17}},
		ServiceWindlm:          {{1785, 6}, {1785, 17}},
		ServiceWindream:        {{534, 6}, {534, 17}},
		ServiceWinfs:           {{5009, 6}, {5009, 17}},
		ServiceWininstallIpc:   {{3674, 6}, {3674, 17}},
		ServiceWinjaserver:     {{1290, 6}, {1290, 17}},
		ServiceWinpcs:          {{5166, 6}, {5166, 17}},
		ServiceWinpharaoh:      {{6065, 6}, {6065, 17}},
		ServiceWinpoplanmess:   {{1152, 6}, {1152, 17}},
		ServiceWinport:         {{3926, 6}, {3926, 17}},
		ServiceWinqedit:        {{7395, 6}, {7395, 17}},
		ServiceWinrm:           {{47001, 6}},
		ServiceWins:            {{1512, 6}, {1512, 17}},
		ServiceWinshadow:       {{3261, 6}, {3261, 17}},
		ServiceWinshadowHd:     {{3861, 6}, {3861, 17}},
		ServiceWipPort:         {{3414, 6}, {3414, 17}},
		ServiceWired:           {{4871, 6}, {4871, 17}},
		ServiceWizard:          {{2001, 17}},
		ServiceWkars:           {{2720, 6}, {2720, 17}},
		ServiceWkstnMon:        {{2991, 6}, {2991, 17}},
		ServiceWlanauth:        {{3810, 6}, {3810, 17}},
		ServiceWlbs:            {{2504, 6}, {2504, 17}},
		ServiceWmcLogSvc:       {{1338, 6}, {1338, 17}},
		ServiceWmedistribution: {{11998, 132}},
		ServiceWmereceiving:    {{11997, 132}},
		ServiceWmereporting:    {{11999, 132}},
		ServiceWmlserver:       {{4883, 6}},
		ServiceWmsMessenger:    {{3219, 6}, {3219, 17}},
		ServiceWnn4_Cn:         {{22289, 6}},
		ServiceWnn4_Kr:         {{22305, 6}},
		ServiceWnn4_Tw:         {{22321, 6}},
		ServiceWnn6:            {{22273, 6}, {22273, 17}},
		ServiceWnn6Ds:          {{26208, 6}, {26208, 17}},
		ServiceWorkflow:        {{3466, 6}, {3466, 17}},
		ServiceWorldLm:         {{1462, 6}, {1462, 17}},
		ServiceWorldfusion1:    {{2595, 6}, {2595, 17}},
		ServiceWorldfusion2:    {{2596, 6}, {2596, 17}},
		ServiceWorldscores:     {{4545, 6}, {4545, 17}},
		ServiceWorldwire:       {{2371, 6}, {2371, 17}},
		ServiceWpages:          {{776, 6}, {776, 17}},
		ServiceWpgs:            {{780, 6}, {780, 17}},
		ServiceWritesrv:        {{1334, 6}, {1334, 17}},
		ServiceWrs_registry:    {{2340, 6}, {2340, 17}},
		ServiceWrspice:         {{6114, 6}},
		ServiceWsDiscovery:     {{3702, 6}, {3702, 17}},
		ServiceWsdapi:          {{5357, 6}, {5357, 17}},
		ServiceWsdapiS:         {{5358, 6}, {5358, 17}},
		ServiceWsdlEvent:       {{4879, 6}},
		ServiceWsicopy:         {{3378, 6}, {3378, 17}},
		ServiceWsmServer:       {{5006, 6}, {5006, 17}},
		ServiceWsmServerSsl:    {{5007, 6}, {5007, 17}},
		ServiceWsman:           {{5985, 6}, {5985, 17}},
		ServiceWsmans:          {{5986, 6}, {5986, 17}},
		ServiceWsmlb:           {{3806, 6}, {3806, 17}},
		ServiceWso2esbConsole:  {{9444, 6}, {9444, 17}},
		ServiceWspipe:          {{4431, 6}},
		ServiceWssauthsvc:      {{4537, 6}, {4537, 17}},
		ServiceWsscomfrmwk:     {{6602, 6}},
		ServiceWsynch:          {{3111, 6}, {3111, 17}},
		ServiceWtaWspS:         {{2805, 6}, {2805, 17}},
		ServiceWtaWspWtpS:      {{2923, 6}, {2923, 17}},
		ServiceWusage:          {{2396, 6}, {2396, 17}},
		ServiceWvCspSms:        {{3590, 6}, {3590, 17}},
		ServiceWvCspSmsCir:     {{3716, 6}, {3716, 17}},
		ServiceWvCspUdpCir:     {{3717, 6}, {3717, 17}},
		ServiceWwiotalk:        {{5413, 6}, {5413, 17}},
		ServiceWwwDev:          {{2784, 6}, {2784, 17}},
		ServiceWwwLdapGw:       {{1760, 6}, {1760, 17}},
		ServiceWxbrief:         {{4368, 6}, {4368, 17}},
		ServiceWysdma:          {{3741, 6}, {3741, 17}},
		ServiceWysdmc:          {{3916, 6}, {3916, 17}},
		ServiceX11:             {{6000, 6}},
		ServiceX11SshOffset:    {{6010, 6}},
		ServiceX25SvcPort:      {{1998, 6}, {1998, 17}},
		ServiceX2Control:       {{36422, 132}},
		ServiceX2eDisc:         {{11877, 17}},
		ServiceX500ms:          {{5757, 6}, {5757, 17}},
		ServiceX9Icue:          {{1145, 6}, {1145, 17}},
		ServiceXBoneApi:        {{2165, 6}, {2165, 17}},
		ServiceXBoneCtl:        {{265, 6}, {265, 17}},
		ServiceXSIPNetwork:     {{1354, 6}, {1354, 17}},
		ServiceXaapi:           {{1934, 6}, {1934, 17}},
		ServiceXactBackup:      {{911, 6}, {911, 17}},
		ServiceXadmin:          {{9105, 6}, {9105, 17}},
		ServiceXandrosCms:      {{4389, 6}, {4389, 17}},
		ServiceXapHa:           {{3639, 6}, {3639, 17}},
		ServiceXbox:            {{3074, 6}, {3074, 17}},
		ServiceXdas:            {{7629, 6}, {7629, 17}},
		ServiceXdmcp:           {{177, 6}, {177, 17}},
		ServiceXds:             {{2130, 6}, {2130, 17}},
		ServiceXdsxdm:          {{6558, 6}, {6558, 17}},
		ServiceXdtp:            {{3088, 6}, {3088, 17}},
		ServiceXecpNode:        {{3940, 6}, {3940, 17}},
		ServiceXfer:            {{82, 6}, {82, 17}},
		ServiceXfr:             {{682, 6}, {682, 17}},
		ServiceXfs:             {{7100, 6}},
		ServiceXgrid:           {{4111, 6}, {4111, 17}},
		ServiceXic:             {{6115, 6}},
		ServiceXiip:            {{1924, 6}, {1924, 17}},
		ServiceXingcsm:         {{2327, 6}, {2327, 17}},
		ServiceXingmpeg:        {{1558, 6}, {1558, 17}},
		ServiceXinuexpansion1:  {{2021, 17}},
		ServiceXinuexpansion2:  {{2022, 17}},
		ServiceXinuexpansion3:  {{2023, 6}, {2023, 17}},
		ServiceXinuexpansion4:  {{2024, 6}, {2024, 17}},
		ServiceXinupageserver:  {{2020, 6}, {2020, 17}},
		ServiceXiostatus:       {{2341, 6}, {2341, 17}},
		ServiceXkotodrcp:       {{5344, 6}, {5344, 17}},
		ServiceXmapi:           {{1933, 6}, {1933, 17}},
		ServiceXmcp:            {{4788, 6}},
		ServiceXmlIpcRegSvc:    {{9092, 6}, {9092, 17}},
		ServiceXmlblaster:      {{3412, 6}, {3412, 17}},
		ServiceXmlinkConnect:   {{3953, 6}, {3953, 17}},
		ServiceXmlrpcBeep:      {{602, 6}, {602, 17}},
		ServiceXmltecXmlmail:   {{9091, 6}, {9091, 17}},
		ServiceXmms2:           {{9667, 6}, {9667, 17}},
		ServiceXmpcrInterface:  {{3877, 6}, {3877, 17}},
		ServiceXmppBosh:        {{5280, 6}},
		ServiceXmppClient:      {{5222, 6}},
		ServiceXmppServer:      {{5269, 6}},
		ServiceXmpv7:           {{7430, 6}, {7430, 17}},
		ServiceXmquery:         {{2279, 6}, {2279, 17}},
		ServiceXmsg:            {{1716, 6}, {1716, 17}},
		ServiceXnds:            {{2157, 6}, {2157, 17}},
		ServiceXnmClearText:    {{3221, 6}, {3221, 17}},
		ServiceXnmSsl:          {{3220, 6}, {3220, 17}},
		ServiceXnmp:            {{1652, 6}, {1652, 17}},
		ServiceXnsAuth:         {{56, 6}, {56, 17}},
		ServiceXnsCh:           {{54, 6}, {54, 17}},
		ServiceXnsCourier:      {{165, 6}, {165, 17}},
		ServiceXnsMail:         {{58, 6}, {58, 17}},
		ServiceXnsTime:         {{52, 6}, {52, 17}},
		ServiceXoWave:          {{3763, 6}, {3763, 17}},
		ServiceXoms:            {{16619, 6}},
		ServiceXoraya:          {{11876, 6}, {11876, 17}},
		ServiceXpanel:          {{3737, 6}},
		ServiceXpilot:          {{15345, 6}, {15345, 17}},
		ServiceXpl:             {{3865, 6}, {3865, 17}},
		ServiceXprintServer:    {{8100, 6}, {8100, 17}},
		ServiceXprtld:          {{5634, 6}, {5634, 17}},
		ServiceXqosd:           {{31416, 6}, {31416, 17}},
		ServiceXribs:           {{2025, 17}},
		ServiceXrl:             {{1104, 6}, {1104, 17}},
		ServiceXrpcRegistry:    {{3651, 6}, {3651, 17}},
		ServiceXsOpenstorage:   {{1619, 6}, {1619, 17}},
		ServiceXserveraid:      {{3722, 6}, {3722, 17}},
		ServiceXsmsvc:          {{6936, 6}, {6936, 17}},
		ServiceXssPort:         {{3510, 6}, {3510, 17}},
		ServiceXssSrvPort:      {{3646, 6}, {3646, 17}},
		ServiceXsync:           {{3721, 6}, {3721, 17}},
		ServiceXtel:            {{1313, 6}},
		ServiceXtgui:           {{4095, 6}, {4095, 17}},
		ServiceXtlserv:         {{6116, 6}},
		ServiceXtreamx:         {{5793, 6}, {5793, 17}},
		ServiceXtrm:            {{3423, 6}, {3423, 17}},
		ServiceXtrms:           {{3424, 6}, {3424, 17}},
		ServiceXvttp:           {{508, 6}, {508, 17}},
		ServiceXxnetserver:     {{3832, 6}, {3832, 17}},
		ServiceXybridRt:        {{9978, 6}},
		ServiceXyplexMux:       {{173, 6}, {173, 17}},
		ServiceYawn:            {{31029, 17}},
		ServiceYoMain:          {{4040, 6}, {4040, 17}},
		ServiceZ39Dot50:        {{210, 6}, {210, 17}},
		ServiceZWave:           {{4123, 6}, {4123, 17}},
		ServiceZWaveS:          {{44123, 6}},
		ServiceZabbixAgent:     {{10050, 6}, {10050, 17}},
		ServiceZabbixTrapper:   {{10051, 6}, {10051, 17}},
		ServiceZannet:          {{317, 6}, {317, 17}},
		ServiceZarkov:          {{2989, 6}, {2989, 17}},
		ServiceZenPawn:         {{7628, 6}, {7628, 17}},
		ServiceZenginkyo1:      {{5020, 6}, {5020, 17}},
		ServiceZenginkyo2:      {{5021, 6}, {5021, 17}},
		ServiceZented:          {{1229, 6}, {1229, 17}},
		ServiceZep:             {{17754, 6}, {17754, 17}},
		ServiceZephyrClt:       {{2103, 6}, {2103, 17}},
		ServiceZephyrHm:        {{2104, 6}, {2104, 17}},
		ServiceZephyrSrv:       {{2102, 6}, {2102, 17}},
		ServiceZfirmShiprush3:  {{3841, 6}, {3841, 17}},
		ServiceZicom:           {{3774, 6}, {3774, 17}},
		ServiceZietoSock:       {{4072, 6}, {4072, 17}},
		ServiceZigbeeIp:        {{17755, 6}, {17755, 17}},
		ServiceZigbeeIps:       {{17756, 6}, {17756, 17}},
		ServiceZionLm:          {{1425, 6}, {1425, 17}},
		ServiceZip:             {{6, 6}},
		ServiceZmp:             {{3925, 6}, {3925, 17}},
		ServiceZreDisc:         {{5670, 17}},
		ServiceZsecure:         {{7173, 6}},
		ServiceZserv:           {{346, 6}, {346, 17}},
		ServiceZymedZpp:        {{2133, 6}, {2133, 17}},
	}
)
