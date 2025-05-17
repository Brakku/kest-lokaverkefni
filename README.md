# kest-lokaverkefni

Linux Infrastructure Setup for DDP ehf

Follow these steps on each machine to set up the ubuntu server (server1) and clients (client1 [Debian] and client2 [CentOS Stream 9]) in the ddp.is domain.
1. Configure Hostnames and Domain

  Set hostnames: On each VM, edit /etc/hostname to set the short hostname (e.g. server1, client1, client2). Then apply it:

    echo "server1" > /etc/hostname
    hostnamectl set-hostname server1

  (Repeat similarly on clients with client1 and client2.) This sets the machine’s hostname
  unix.stackexchange.com
  .
  
  Update hosts file: Add the FQDN and hostname to /etc/hosts. For example, on server1 add:

    127.0.0.1   localhost
    192.168.100.10   server1.ddp.is server1

  On clients, include their own entry (e.g. 192.168.100.11 client1.ddp.is client1). This ensures name resolution if DNS is not yet running
  unix.stackexchange.com
  .

  Set DNS domain: Add the domain name in the resolver config. If using resolvconf, add a line domain ddp.is in /etc/resolvconf/resolv.conf.d/head and run resolvconf -u. Otherwise, add domain ddp.is to /etc/resolv.conf
  unix.stackexchange.com
  . This ensures the system recognizes the local domain for unqualified names.

2. Assign Static IP to server1 and Configure DHCP

  Static IP on server1: Assign the 10th usable IP (i.e. 192.168.100.10/24) to server1. On Debian, edit /etc/network/interfaces (or use NetworkManager) with:

    auto eth0
    iface eth0 inet static
        address 192.168.100.10
        netmask 255.255.255.0
        gateway 192.168.100.1

  This example assumes 192.168.100.1 is the gateway. Restart networking: systemctl restart networking. (On CentOS use /etc/sysconfig/network-scripts/ifcfg-eth0.) The Debian Wiki shows a similar static setup
  wiki.debian.org
  .
  
  Install DHCP server (server1 only):

    Debian: sudo apt update && sudo apt install isc-dhcp-server

    CentOS: sudo dnf install dhcp-server (Enable with systemctl enable dhcpd).

  Set the interface in /etc/default/isc-dhcp-server (Debian) or /etc/sysconfig/dhcpd (CentOS) to listen on eth0.

  Configure DHCP: Edit /etc/dhcp/dhcpd.conf and add (or modify) entries like:

    option domain-name "ddp.is";
    option domain-name-servers 192.168.100.10;  # server1 as DNS
    default-lease-time 600;
    max-lease-time 7200;
    authoritative;

    subnet 192.168.100.0 netmask 255.255.255.0 {
        range 192.168.100.11 192.168.100.50;
        option routers 192.168.100.1;
    }

  This defines the DHCP scope for the LAN, sets 192.168.100.1 as the gateway, and issues DNS and domain info
  wiki.debian.org
  . Restart the DHCP service: systemctl restart isc-dhcp-server.
  
  Client DHCP configuration: On each client, ensure the network interface uses DHCP. For Debian, /etc/network/interfaces might include:

    auto eth0
    iface eth0 inet dhcp

  On CentOS, configure /etc/sysconfig/network-scripts/ifcfg-eth0 with BOOTPROTO=dhcp and ONBOOT=yes. Reboot or restart networking. Verify each client has an IP (ip a) and can ping the gateway. They should also get dns-nameserver 192.168.100.10 and domain-name ddp.is via DHCP.

3. Install and Configure DNS (BIND9) on server1

  Install BIND: On server1: sudo apt install bind9 (or sudo dnf install bind).

  Configure forward zone: Edit /etc/bind/named.conf.local and add:

    zone "ddp.is" {
        type master;
        file "/etc/bind/db.ddp.is";
    };

  Create /etc/bind/db.ddp.is with SOA and A records. Example:

    $TTL 604800
    @   IN SOA ns1.ddp.is. admin.ddp.is. (
              1     ; serial
              604800 ; refresh
              86400  ; retry
              2419200; expire
              604800 ); minimum
    ;
    @       IN NS   ns1.ddp.is.
    ns1     IN A    192.168.100.10
    server1 IN A    192.168.100.10
    client1 IN A    192.168.100.11
    client2 IN A    192.168.100.12

  Replace addresses for client1 and client2 as appropriate (use DHCP or fixed leases).
  
  Configure reverse zone: In named.conf.local also add:

    zone "100.168.192.in-addr.arpa" {
        type master;
        file "/etc/bind/db.192";
    };

  Then create /etc/bind/db.192:

    $TTL 604800
    @ IN SOA ns1.ddp.is. admin.ddp.is. (
            1       ; serial
            604800  ; refresh
            86400   ; retry
            2419200 ; expire
            604800 ) ; minimum
    ;
    @   IN NS ns1.ddp.is.
    10  IN PTR server1.ddp.is.
    11  IN PTR client1.ddp.is.
    12  IN PTR client2.ddp.is.

  Activate DNS: Check configurations (named-checkconf, named-checkzone). Restart BIND: systemctl restart bind9. Now server1 can resolve all hosts in ddp.is. Update clients to use DNS: they should already get 192.168.100.10 via DHCP; verify with nslookup client1.ddp.is on a client.

4. Create User Accounts from users.CSV

  Prepare CSV: Copy the provided users.CSV to the server (e.g. /root/users.csv). It contains columns: Name, FirstName, LastName, Username, Email, Department, EmployeeID.

  Create groups: Create Unix groups for each department and admin roles:

    sudo groupadd Hjalparsveit
    sudo groupadd Framkvaemdadeild
    sudo groupadd StjornDeild
    sudo groupadd Framleidsludeild
    sudo groupadd it
    sudo groupadd management

  Add users: Use a shell loop to read CSV and create users. Example (on server1):

    tail -n +2 users.csv | while IFS=, read Name FirstName LastName Username Email Department EmployeeID; do
        sudo useradd -m -c "$FirstName $LastName" -s /bin/bash "$Username"
        echo "$Username:ChangeMe123!" | sudo chpasswd
        sudo usermod -aG "$Department","it","management" "$Username"
        echo "Created user $Username (Dept: $Department)"
    done

  This creates each user with a home directory, comment (full name), a default password, and adds them to their department group (plus it and management if desired for admins). Adjust password setting as needed. Repeat on clients if you want users on clients, or rely on network authentication.

5. Install and Configure MySQL (HumanResource Database)

    Install MySQL/MariaDB: On server1: sudo apt install mysql-server (Debian) or sudo dnf install mysql-server (CentOS) and start it (systemctl enable --now mysqld).

    Secure MySQL: Run sudo mysql_secure_installation and set a root password.

    Create database and tables: Log into MySQL (mysql -u root -p) and execute:

        CREATE DATABASE HumanResource;
        USE HumanResource;
        CREATE TABLE departments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(50) NOT NULL
        );
        CREATE TABLE jobs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(50) NOT NULL
        );
        CREATE TABLE locations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            address VARCHAR(100) NOT NULL
        );
        CREATE TABLE employees (
            id INT AUTO_INCREMENT PRIMARY KEY,
            first_name VARCHAR(30),
            last_name VARCHAR(30),
            email VARCHAR(50),
            dept_id INT,
            job_id INT,
            loc_id INT,
            FOREIGN KEY (dept_id) REFERENCES departments(id),
            FOREIGN KEY (job_id) REFERENCES jobs(id),
            FOREIGN KEY (loc_id) REFERENCES locations(id)
        );

    This sets up a HumanResource database with employees, departments, jobs, and locations tables. Adjust column types as needed. Populate with INSERTs if desired.

6. Schedule Weekly Backups of Home Directories

    Backup script: Create a backup directory: sudo mkdir -p /backup.

    Cron job: As root, edit the crontab (sudo crontab -e) and add:

        0 0 * * 5 tar -czf /backup/home-$(date +\%F).tar.gz /home

    This runs every Friday at midnight, archiving all home directories into /backup/home-YYYY-MM-DD.tar.gz.

    Verify cron: Ensure the cron service is running. Optionally log output to a file. You can list cron jobs with sudo crontab -l. Older backups will accumulate; consider rotation or pruning as needed.

7. Configure NTP (Chrony) on server1 and Clients

  Install chrony:

      sudo apt install chrony       # Debian/Ubuntu
      sudo dnf install chrony       # CentOS

  Server1 as NTP master: Edit /etc/chrony/chrony.conf on server1 and add:

    allow 192.168.100.0/24
    local stratum 10

  Also ensure there are default server entries (or add your preferred public NTP servers). The allow line lets LAN clients sync to this server. Restart chrony: sudo systemctl restart chrony.
  
  Clients sync to server1: On each client (client1, client2), install chrony and edit /etc/chrony/chrony.conf to point to server1:

    server server1.ddp.is iburst

  Remove or comment out other pool lines if present. Restart chrony on each client. Verify sync status with chronyc sources (it should list server1.ddp.is and say ^* or similar). Chrony is recommended for time sync on modern Linux
  cloudspinx.com
    .

8. Configure Centralized Syslog (rsyslog)

  Server (rsyslog as central collector): On server1, enable UDP reception by editing /etc/rsyslog.conf (or a file in /etc/rsyslog.d/) and add:

    module(load="imudp")
    input(type="imudp" port="514")

  This tells rsyslog to listen on UDP port 514 for incoming logs
  docs.redhat.com
  . Save and restart rsyslog: sudo systemctl restart rsyslog.
  
  Clients (forward logs): On each client (client1, client2), create /etc/rsyslog.d/60-forward.conf with:

    *.* action(type="omfwd" target="server1.ddp.is" port="514" protocol="udp")

  This forwards all log facilities to the server via UDP
  docs.redhat.com
  . Restart rsyslog on each client. The server will now accumulate client logs (by default in /var/log/syslog or /var/log/messages, or split by hostname if configured). You may further customize filtering or create separate log files per host on the server.

9. Set up Postfix and Roundcube (Email Server)

  Install Postfix: On server1:

    sudo apt install postfix

  During install, choose “Internet Site” and set the mail name to ddp.is. This configures Postfix to send/receive mail for the domain.
  
  Basic Postfix config: Edit /etc/postfix/main.cf to ensure:

    myhostname = mail.ddp.is
    mydomain = ddp.is
    inet_interfaces = all
    mydestination = $myhostname, localhost.$mydomain, localhost

  Restart Postfix: sudo systemctl restart postfix. You can test sending mail locally with the mail command or sendmail.
  
  (Optional) Install Dovecot: For IMAP access, install Dovecot: sudo apt install dovecot-imapd. It will use system users. Configure /etc/dovecot/dovecot.conf as needed, then restart.
  
  Install Webmail (Roundcube): Also install Apache/PHP and the Roundcube package:

    sudo apt install apache2 php php-mysql
    sudo apt install roundcube roundcube-core roundcube-mysql

  During Roundcube setup, you’ll be prompted to configure a MySQL database for it; you can create one or let the installer do it. After installation, Roundcube’s config is in /etc/roundcube/config.inc.php. Adjust the $rcmail_config['db_dsnw'] DSN to match your MySQL user. Ensure Apache has Alias /roundcube /var/lib/roundcube and restart Apache: sudo systemctl restart apache2.

  Test Webmail: Access http://server1.ddp.is/roundcube in a browser. You should see a login screen. Use a system user account (created above) to log in. (Roundcube requires Postfix and Dovecot to be set up for full mail functionality
  linuxbabe.com
    .)

10. Configure Shared Printers (CUPS)

  Install CUPS: On server1: sudo apt install cups. Add users to the lpadmin group for printer administration: e.g. sudo usermod -aG lpadmin it management.

  Define printer groups: In /etc/group, ensure each department group is listed (we created these already). In /etc/cups/cupsd.conf, set which groups can administer printers:

    SystemGroup lpadmin it management

  This line (added under the main configuration section) ensures only it and management (and lpadmin) users can manage printers
  cups.org


  Restrict printing by group: For each department printer, edit /etc/cups/printers.conf or an ACL file. For example, for a printer called “DeptPrinter”:
  
      <Printer DeptPrinter>
        AuthType Default
        Require user @Hjalparsveit @it @management
        Order deny,allow
        Deny from all
        Allow from 192.168.100.
      </Printer>  
  
  This allows printing only by members of Hjalparsveit, it, or management. Repeat or adjust for other group printers (replace Hjalparsveit with the appropriate group). You can add printers via CUPS web interface or command line, e.g.:
  
      lpadmin -p DeptPrinter -E -v socket://printer-host -P /path/to/ppd
  
  After configuration, restart CUPS: sudo systemctl restart cups. Ensure port 631 (CUPS) is allowed in the firewall.

11. Secure SSH with RSA Key Authentication

  Generate SSH keys: On your admin workstation (not on the servers), run ssh-keygen -t rsa -b 4096 and do not set a passphrase (or do, for more security). This creates ~/.ssh/id_rsa and ~/.ssh/id_rsa.pub.

  Configure SSHD: On each machine (server and clients), edit /etc/ssh/sshd_config:

    PubkeyAuthentication yes
    PasswordAuthentication no
    PermitRootLogin no

  This forces SSH to use key auth only.
  
  Install public keys: Copy the public key to each user’s ~/.ssh/authorized_keys on the target machines. For example:

    ssh-copy-id user@server1.ddp.is

  Or manually append your id_rsa.pub into /home/user/.ssh/authorized_keys (create the .ssh directory with 700 and the file with 600 permissions). Repeat for all users and machines.

  Restart SSH: sudo systemctl reload sshd. Test by SSHing as a user with your key. Password login should fail. This hardens SSH access.

12. Harden Servers: Close Unused Ports and Verify with NMAP

  Set default DROP policy: It’s best practice to drop all incoming traffic and explicitly allow needed ports
  serverfault.com
  . For example, using iptables on each machine:

    sudo iptables -P INPUT DROP
    sudo iptables -P FORWARD DROP
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    # Allow needed services:
    sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT    # SSH
    sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # HTTP (Roundcube)
    sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT   # HTTPS (if used)
    sudo iptables -A INPUT -p tcp --dport 25 -j ACCEPT    # SMTP (Postfix)
    sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT    # DNS (if remote queries needed)
    sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT    # DNS UDP
    sudo iptables -A INPUT -p tcp --dport 631 -j ACCEPT   # CUPS (if clients need to see printers)
    sudo iptables -A INPUT -p udp --dport 514 -j ACCEPT   # syslog (server only)
    sudo iptables -A INPUT -p udp --dport 67 -j ACCEPT    # DHCP (server only)
    # Drop other ports (mysqld on 3306 is blocked by default):
    sudo iptables -A INPUT -p tcp --dport 3306 -j DROP

  Save the rules (e.g. iptables-save > /etc/iptables/rules.v4 or use a service). This leaves only the listed ports open
  serverfault.com
  .
  
  Verify with nmap: From one machine, scan others to ensure no unintended ports are open. For example:

    nmap -Pn 192.168.100.10

  The output should list only the services you allowed (22, 80, etc.). Repeat for other machines (adjust IP). This confirms the firewall is correctly blocking all unused ports.

Following these steps will fully configure a VM-based Linux network for DDP ehf, with DHCP, DNS, users, database, backups, time sync, centralized logging, mail, printers, SSH hardening, and firewall protection. All configurations are suitable for documentation and can be committed to a GitHub repository for future reference.
