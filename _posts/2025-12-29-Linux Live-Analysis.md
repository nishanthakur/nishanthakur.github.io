---
title: "THM: Linux Live Analysis"
date: 2025-12-29
categories: [Blue-Team, TryHackMe]
tags: [Linux, Forensics, OSquery]
---

## 1. Overview

When a Linux system is suspected to be compromised, time becomes a critical factor. Shutting the system down or immediately pulling disk images can destroy valuable volatile evidence that only exists in memory. This is where **Linux live analysis** plays a crucial role.

In this article, we walk through a **structured approach to performing live forensics on a running Linux host after a suspected compromise**. The primary goal is to demonstrate how defenders and incident responders can **identify malicious activity, understand attacker behavior, and collect actionable evidence** without disrupting the system prematurely.

The investigation focuses on:
- Examining **volatile data** such as running processes, open files, memory-resident artifacts, and active network connections
- Using **native Linux utilities** alongside **osquery** to perform consistent, repeatable, and scalable analysis
- Correlating processes, network activity, and file-system artifacts to uncover attacker TTPs
- Identifying common attacker techniques such as **process masquerading, execution from temporary directories, fileless malware, and suspicious network communication**

This walkthrough is designed for **Blue Team analysts, SOC engineers, and incident responders** who want a practical reference for troubleshooting a compromised Linux system during a live response scenario.

Note: This guide is heavily based on the [Linux Live Analysis](https://tryhackme.com/room/linuxliveanalysis) TryHackMe machine.


## 2. Key Information during Live Forensics

Some of the key types of data that could be of interest from a forensics point of view are explained below: 

**1. Running Processes**

**Explanation:**

- Information about the running processes can be critical for any forensics investigation.
- This includes information about all processes currently running on the system, such as their process IDs (PIDs), command line arguments, owner-user IDs, and parent-child process relationships.

**Forensics Value:**

- This data helps investigators understand what programs and scripts were executing during capture, indicating normal operation or malicious activity.

**2. Open Files**

**Explanation**

- Lists of files that are currently opened by different processes.

**Forensics Value**

- Open files can reveal what data is being accessed or modified, which is essential for understanding the context of an attack or data breach.

**3. In-Memory Data Structures**

**Explanation**

- Kernel structures, process heaps, and stacks that contain system and application state information.

**Forensics Value**

- These structures can contain sensitive information, such as encryption keys, passwords, or evidence of memory corruption exploits.

**4. Network Connections**

**Explanation**

- Details about ongoing network connections, including IP addresses, ports, and the status of the connections (e.g., established, listening, closed).

**Forensics Value**

- This information can reveal connections to suspicious IP addresses or ongoing data exfiltration.

**5. Listening Services**

**Explanation**

- Services that are currently listening for incoming network connections.

**Forensics Value**

- Identifying these services helps determine what network-accessible applications are running, which could include unauthorized backdoors or compromised services.

**6. Logged-in User Sessions**

**Explanation**

- Information about users currently logged into the system, their login times, and the terminals they are using.

**Forensics Value**

- Knowing who is logged in helps correlate user activity with observed events and can indicate unauthorized access.

**7. User Activity**

**Explanation**

- Records of commands executed by users, such as shell history.

**Forensics Value**

- This data helps trace users' actions, potentially revealing steps taken by an attacker or the sequence of actions leading to an incident.

**8. In-Memory Logs**

**Explanation**

- Logs that are temporarily stored in memory before being written to disk.

**Forensics Value**

- These logs can provide a real-time snapshot of system events and application behavior before they are permanently recorded, which might include traces of an attack.

**9. Interface Configurations**

**Explanation**

- Network interfaces' current configurations and operational states, including IP addresses, MAC addresses, and routing information.

**Forensics Value**

- This data helps understand the system's network environment, including any network setting changes that could indicate malicious activity.

**10. Temporary Files and Cache**

**Explanation**

- Files stored in temporary directories like `/tmp` and `/var/tmp`.

**Forensics Value**

- Temporary files can contain transient data from applications, such as temporary copies of sensitive documents or scripts used in an attack.

These are some important details in the Linux environment's volatile memory.

## 3. Using OSQuery

- OSQuery enables us to query the operating system as a relational database.
- Use SQL-like queries to extract detailed and comprehensive information about the system, which can be helpful in the investigation.
- Some of the queries to gather relevant details are as follows:

| Purpose | Query |
| --- | --- |
| User Accounts | `Select username, uid, description from users;` |
| Process Information | `Select pid, name, parent,path from processes;` |

## 4. System and Network Profiling

- Key step in any forensic investigation
- Used to identify and locate important information about the system
- includes information like:
    - System configuration
    - Logged In Users
    - Install Application
    - Hardware Configuration
- Use command below to cary out system and network profiling:
    - `uname -a`
    - `hostnamectl`
    - `uptime`
    - `lscpu`
    - `df -h`
    - `lsblk`
    - `free -h`
    - `dpkg -l` → Look for suspicious packages
    - `apt list --installed | head -n 30`
    - `ip -br a` OR `ifconfig` OR `ip -a`
    - `route`
    - `ss` OR `netstat -nap`

## 5. Hunting for Processes

- identifying `odd-looking` process is crucial form the perspective of forensic.
- Some commands along with their explanation is shown below.

| Command | Explanation |
|-------|-------------|
| `ps` | Provides a snapshot of the current processes.<br>Useful for an overview of running processes and supports options for detailed information. |
| `top` | Offers a dynamic, real-time view of running processes.<br>Monitors system performance and resource usage, showing CPU and memory consumption. |
| `htop` | Similar to `top` but with an improved interface.<br>Allows easier process management and includes color coding for readability. |
| `pstree` | Displays processes in a tree format.<br>Shows parent-child relationships between processes. |
| `pidof` | Finds the process ID (PID) of a running program by name.<br>Useful when you know the process name and need its PID. |
| `pgrep` | Searches for processes based on name and attributes.<br>Helpful for filtering and locating specific processes. |
| `lsof` | Lists open files and the processes using them.<br>Helps identify file, socket, or network usage by processes. |
| `netstat` | Displays network-related information.<br>Includes active connections and listening ports. |
| `strace` | Traces system calls and signals.<br>Useful for debugging and understanding low-level process behavior. |
| `vmstat` | Reports virtual memory statistics.<br>Provides insight into system performance and resource usage. |

### **5.1 Hunting for suspicious Process Using OSQUERY**

- **List running processes**: `SELECT pid, name, path, state FROM processes;`

```bash
osquery> SELECT pid, name, path, state FROM processes;
+------+----------------------+----------------------------------+-------+
| pid  | name                 | path                             | state |
+------+----------------------+----------------------------------+-------+
| 1    | systemd              |                                  | S     |
| 10   | mm_percpu_wq         |                                  | I     |
| 100  | xenwatch             |                                  | S     |
| 101  | nvme-wq              |                                  | I     |
| 102  | nvme-reset-wq        |                                  | I     |
| 1024 | gvfsd                | /usr/libexec/gvfsd               | S     |
| 103  | nvme-delete-wq       |                                  | I     |
| 1034 | gvfsd-fuse           | /usr/libexec/gvfsd-fuse          | S     |
| 104  | scsi_eh_0            |                                  | S     |
| 1047 | at-spi-bus-laun      | /usr/libexec/at-spi-bus-launcher | S     |
| 105  | scsi_tmf_0           |                                  | I     |
| 1053 | dbus-daemon          | /usr/bin/dbus-daemon             | S     |
| 106  | scsi_eh_1            |                                  | S     |
| 107  | scsi_tmf_1           |                                  | I     |
| 109  | vfio-irqfd-clea      |                                  | I     |
| 11   | rcu_tasks_rude_      |                                  | S     |
| 110  | mld                  |                                  | I     |
| 111  | ipv6_addrconf        |                                  | I     |
| 112  | kworker/1:1H-kblockd |                                  | I     |
| 1151 | dconf-service        | /usr/libexec/dconf-service       | S     |
+------+----------------------+----------------------------------+-------+
```

- **Check for processes running from `/tmp` directory**: `SELECT pid, name, path FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/var/tmp/%';`
    - It's very common for an intruder to run malicious programs from the tmp directories to avoid detection. Let's update the query to see if any process is being executed from the tmp directory.

```bash
osquery> SELECT pid, name, path FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/var/tmp/%';
+------+----------------+-------------------------+
| pid  | name           | path                    |
+------+----------------+-------------------------+
| 1057 | .systm_updater | /var/tmp/.systm_updater |
| 567  | sshdd          | /var/tmp/sshdd          |
+------+----------------+-------------------------+
```

- **Hunting for Fileless Malware/Process**: `SELECT pid, name, path, cmdline, start_time FROM processes WHERE on_disk = 0;`
    - Not every process without a presence on disk is malicious and requires further investigation to identify the malicious one(s).
    - Here, `on_disk=0` means no file is present on disk.
    - A fileless malware can have the following characteristics that we can observe:
        - **No Disk Footprint:** It does not leave files on the disk, making it harder to detect using traditional file-based antivirus and security solutions.
        - **Memory-Resident:** Operates entirely in the system's memory.
        - **Persistence:** You might use scheduled tasks or other means to achieve persistence without placing files on the disk.

```bash
osquery> SELECT pid, name, path, cmdline, start_time FROM processes WHERE on_disk = 0;
+------+----------------+-------------------------+-------------------------+------------+
| pid  | name           | path                    | cmdline                 | start_time |
+------+----------------+-------------------------+-------------------------+------------+
| 1057 | .systm_updater | /var/tmp/.systm_updater | /var/tmp/.systm_updater | 1767000293 |
+------+----------------+-------------------------+-------------------------+------------+
```

- **Orphan Processes:** `SELECT pid, name, parent, path FROM processes WHERE parent NOT IN (SELECT pid from processes);`
    - Intruders can create a process that becomes an orphan.
    - Creating orphan process helps attacker hide their activities, maintain persistence, and evade detection.

```bash
osquery> SELECT pid, name, parent, path FROM processes WHERE parent NOT IN (SELECT pid from processes);
+-----+----------+--------+--------------------------+
| pid | name     | parent | path                     |
+-----+----------+--------+--------------------------+
| 1   | systemd  | 0      | /usr/lib/systemd/systemd |
| 2   | kthreadd | 0      |                          |
+-----+----------+--------+--------------------------+
```

- **Finding Processes Launched from User Directories**:
    - Query: `SELECT pid, name, path, cmdline, start_time FROM processes WHERE path LIKE '/home/%' OR path LIKE '/Users/%';`
    - This  query search in the list of running processes and see which process is running from the user directory.

```bash
osquery> SELECT pid, name, path, cmdline, start_time FROM processes WHERE path LIKE '/home/%' OR path LIKE '/Users/%';
+-----+-------------+-------------------------------------------------+-------------------------------------------------+------------+
| pid | name        | path                                            | cmdline                                         | start_time |
+-----+-------------+-------------------------------------------------+-------------------------------------------------+------------+
| 837 | rdp_updater | /home/badactor/storage/.secret_docs/rdp_updater | /home/badactor/storage/.secret_docs/rdp_updater | 1767000290 |
+-----+-------------+-------------------------------------------------+-------------------------------------------------+------------+
```

## 6. Investigating Network Connections

After  investigating running processes and identifying the odd ones, we should look at the network communication or connection initiated on this host, which could be identified as suspicious. To examine the network connections on the Linux host, there are various built-in command-line tools that we can use, as shown below:

| **Command** | **Description** |
|------------|----------------|
| `netstat` | Displays network connections, routing tables, interface statistics, masquerade connections, and multicast memberships.<br>Useful for getting a snapshot of the current network status. |
| `ss` | Similar to `netstat`, but faster and more detailed.<br>Dumps socket statistics and shows active connections and listening ports. |
| `tcpdump` | Captures and analyzes network packets in real time.<br>Packets can be saved to a file or filtered for specific traffic. |
| `iftop` | Provides a real-time display of bandwidth usage on an interface.<br>Useful for identifying high-bandwidth connections. |
| `lsof` | Lists open files, including network connections.<br>Helps identify which processes are using specific ports. |
| `iptables` | Displays, sets up, and maintains IP packet filtering rules.<br>Used for managing firewall rules and monitoring traffic. |
| `nmap` | Scans networks to discover hosts and services.<br>Useful for identifying devices and open ports. |
| `ping` | Tests connectivity by sending ICMP echo requests.<br>Useful for checking whether a host is reachable. |
| `traceroute` | Traces the path packets take to reach a destination.<br>Helps identify network delays or routing issues. |
| `dig` | Queries DNS servers for domain-related information.<br>Commonly used to diagnose DNS issues. |
| `hostname` | Displays or sets the system hostname and associated IP address.<br>Useful for identifying the local system. |
| `ifconfig` | Configures and displays network interfaces.<br>Mostly replaced by `ip`, but still useful for quick checks. |
| `ip` | Modern and versatile replacement for `ifconfig`.<br>Used for interface configuration, routing, and tunnels. |
| `arp` | Displays and modifies the ARP table.<br>Maps IP addresses to MAC addresses. |
| `route` | Displays or modifies the IP routing table.<br>Helps understand how packets are routed. |
| `curl` | Transfers data using various protocols.<br>Useful for testing APIs, connectivity, and downloading data. |
| `wget` | Non-interactive network downloader.<br>Commonly used for downloading files and testing connectivity. |
| `netcat` | Reads and writes data over TCP or UDP connections.<br>Useful for debugging and testing network services. |
| `whois` | Queries WHOIS databases for domain registration details.<br>Useful for reconnaissance and ownership information. |
| `nslookup` | Queries DNS servers for name or IP resolution.<br>Useful for diagnosing DNS configuration issues. |

### 6.1 OSQUERY: **Network Connections**

From an investigation point of view, examining ongoing network communication or past connections can be a vital piece of the puzzle in solving the case. 

**Query:** `SELECT pid, family, remote_address, remote_port, local_address, local_port, state FROM process_open_sockets LIMIT 20;`

**Explanation:** 

- This query retrieves information about network connections established by various processes on the system.
- It selects entries from the `process_open_sockets` table.

```bash
osquery> SELECT pid, family, remote_address, remote_port, local_address, local_port, state FROM process_open_sockets LIMIT 20;
+------+--------+----------------+-------------+---------------+------------+-------------+
| pid  | family | remote_address | remote_port | local_address | local_port | state       |
+------+--------+----------------+-------------+---------------+------------+-------------+
| 1918 | 2      | 0.0.0.0        | 0           | 0.0.0.0       | 25         | LISTEN      |
| 985  | 2      | 0.0.0.0        | 0           | 0.0.0.0       | 80         | LISTEN      |
| 894  | 2      | 0.0.0.0        | 0           | 127.0.0.1     | 5901       | LISTEN      |
| 537  | 2      | 0.0.0.0        | 0           | 127.0.0.53    | 53         | LISTEN      |
| 575  | 2      | 0.0.0.0        | 0           | 127.0.0.1     | 631        | LISTEN      |
| 4097 | 2      | 10.100.2.28    | 53900       | 10.10.26.146  | 80         | ESTABLISHED |
| 894  | 2      | 127.0.0.1      | 58844       | 127.0.0.1     | 5901       | ESTABLISHED |
| 4097 | 2      | 127.0.0.1      | 5901        | 127.0.0.1     | 58844      | ESTABLISHED |
| 1918 | 10     | ::             | 0           | ::            | 25         | LISTEN      |
| 575  | 10     | ::             | 0           | ::1           | 631        | LISTEN      |
| 894  | 10     | ::             | 0           | ::1           | 5901       | LISTEN      |
| 633  | 2      | 0.0.0.0        | 0           | 0.0.0.0       | 631        |             |
| 573  | 2      | 0.0.0.0        | 0           | 0.0.0.0       | 5353       |             |
+------+--------+----------------+-------------+---------------+------------+-------------+
```

The network connections can help identify malicious connections and link them to the processes that have initiated those connections. 

### 6.2 OSQUERY: Remote Connection

The remote network connection established on this host could help identify potential C2 server communication. We will use the following command to list down all the network connections with a remote connection.

**Search Query:** `SELECT pid, fd, socket, local_address,remote_address, local_port, remote_port FROM process_open_sockets WHERE remote_address IS NOT NULL;`

```bash
osquery> SELECT pid, fd, socket, local_address, remote_address, local_port, remote_port FROM process_open_sockets WHERE remote_address IS NOT NULL;
+------+-----+--------+---------------+----------------+------------+-------------+
| pid  | fd  | socket | local_address | remote_address | local_port | remote_port |
+------+-----+--------+---------------+----------------+------------+-------------+
| 547  | 7   | 23406  | 127.0.0.1     | 0.0.0.0        | 631        | 0           |
| 498  | 13  | 20903  | 127.0.0.53    | 0.0.0.0        | 53         | 0           |
| 834  | 3   | 27815  | 0.0.0.0       | 0.0.0.0        | 22         | 0           |
| 925  | 3   | 28472  | 0.0.0.0       | 0.0.0.0        | 80         | 0           |
| 885  | 7   | 29169  | 127.0.0.1     | 0.0.0.0        | 5901       | 0           |
| 885  | 22  | 33531  | 127.0.0.1     | 127.0.0.1      | 5901       | 55186       |
| 1404 | 4   | 33896  | 10.10.18.7    | 10.100.2.28    | 80         | 38648       |
| 1404 | 8   | 33530  | 127.0.0.1     | 127.0.0.1      | 55186      | 5901        |
| 885  | 8   | 29170  | ::1           | ::             | 5901       | 0           |
| 834  | 4   | 27826  | ::            | ::             | 22         | 0           |
```

### 6.3 OSQUERY: **Examining DNS Queries**

Use the following query to retrieve the information about the DNS queries on this host.

**Search Query:** `SELECT * FROM dns_resolvers;`

```bash
osquery> SELECT * FROM dns_resolvers;
+----+------------+----------------------------+---------+----------+
| id | type       | address                    | netmask | options  |
+----+------------+----------------------------+---------+----------+
| 0  | nameserver | 127.0.0.53                 | 32      | 68158145 |
| 0  | search     | eu-west-1.compute.internal |         | 68158145 |
+----+------------+----------------------------+---------+----------+
```

### 6.4 OSQUERY: **Listing Down Network Interfaces**

Use the following query to retrieve the information about the network interface.

**Search Query:** `SELECT * FROM interface_addresses;`

```bash
osquery> SELECT interface, address, mask, broadcast FROM interface_addresses;
+-----------+------------------------------+-----------------------------------------+---------------+
| interface | address                      | mask                                    | broadcast     |
+-----------+------------------------------+-----------------------------------------+---------------+
| lo        | 127.0.0.1                    | 255.0.0.0                               |               |
| eth0      | 10.10.18.7                   | 255.255.0.0                             | 10.10.255.255 |
| lo        | ::1                          | ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff |               |
| eth0      | fe80::7c:7eff:feb4:26c9%eth0 | ffff:ffff:ffff:ffff::                   |               |
+-----------+------------------------------+-----------------------------------------+---------------+
```

### 6.5 **List Network Connections**

Let's use the following command to list down the listening ports.

**Search query:** `SELECT * FROM listening_ports;`

```bash
osquery> SELECT * FROM listening_ports;
+-----+------+----------+--------+------------+----+--------+------+---------------+
| pid | port | protocol | family | address    | fd | socket | path | net_namespace |
+-----+------+----------+--------+------------+----+--------+------+---------------+
| -1  | 25   | 6        | 2      | 0.0.0.0    | -1 | 33899  |      | 0             |
| -1  | 80   | 6        | 2      | 0.0.0.0    | -1 | 28450  |      | 0             |
| 894 | 5901 | 6        | 2      | 127.0.0.1  | 7  | 29108  |      | 0             |
| -1  | 53   | 6        | 2      | 127.0.0.53 | -1 | 21756  |      | 0             |
| -1  | 631  | 6        | 2      | 127.0.0.1  | -1 | 408045 |      | 0             |
| -1  | 25   | 6        | 10     | ::         | -1 | 33900  |      | 0             |
| -1  | 631  | 6        | 10     | ::1        | -1 | 408044 |      | 0             |
| 894 | 5901 | 6        | 10     | ::1        | 8  | 29109  |      | 0             |
| -1  | 631  | 17       | 2      | 0.0.0.0    | -1 | 408066 |      | 0             |
| -1  | 5353 | 17       | 2      | 0.0.0.0    | -1 | 24794  |      | 0             |
+-----+------+----------+--------+------------+----+--------+------+---------------+
```

Explore the network communication established on this host and see if we can find a suspicious connection or open port.

## 7. TTP Footprints on Disks

Now that we have identified the suspicious process and the network connections, it's time to look at some cases where the adversaries would add suspicious files on the disk, modify existing files or binaries to avoid detection, etc.

### 7.1 Open Files

First, Let's use the following query to list all the files opened.

**Search Query:** `SELECT pid, fd, path FROM process_open_files;`

**Explanation:** 

- This query will list all files that have been opened and are associated with some process.
- We can locate them through their respective pid.

```bash
osquery> SELECT pid, fd, path FROM process_open_files;
+------+----+----------------------------------+
| pid  | fd | path                             |
+------+----+----------------------------------+
| 1    | 0  | /dev/null                        |
| 1    | 1  | /dev/null                        |
| 1    | 10 | /proc/1/mountinfo                |
| 1    | 14 | /proc/swaps                      |
| 1    | 2  | /dev/null                        |
| 1    | 26 | /dev/autofs                      |
| 1    | 3  | /dev/kmsg                        |
| 1    | 46 | /run/dmeventd-server             |
| 1    | 47 | /run/dmeventd-client             |
| 1    | 48 | /run/cloud-init/hook-hotplug-cmd |
| 1    | 52 | /run/initctl                     |
| 1    | 59 | /dev/rfkill                      |
| 1    | 7  | /sys/fs/cgroup/unified           |
+------+----+----------------------------------+
```

### 7.2 **Files Being Accessed From the tmp Directory**

We can narrow down the result by filtering the query to only show the files being accessed from the `/tmp/` directory. 

**Search Query:** `SELECT pid, fd, path FROM process_open_files where path LIKE '/tmp/%';`

**Explanation**: 

- This query will search for the processes that have opened files on the system.
- For this query, we only look at the files accessed from the `/tmp/` directory.
- In an actual investigation, we will have to look at various other locations.

```bash
osquery> SELECT pid, fd, path FROM process_open_files where path LIKE '/tmp/%';
+------+----+----------------------+
| pid  | fd | path                 |
+------+----+----------------------+
| 1636 | 15 | /tmp/#5741 (deleted) |
| 1636 | 16 | /tmp/#6542 (deleted) |
| 556  | 4  | /tmp/REDACTED.log    |
| 825  | 1  | /tmp/#1673 (deleted) |
| 825  | 2  | /tmp/#1673 (deleted) |
+------+----+----------------------+
```

From the output, it is clear that one of the files being accessed by process ID `556` looks suspicious, and the file's intended purpose is very clear from 
its name. But what is the name of the process associated with this pid? Let's use another query to identify the process name using this pid, as shown below:

```bash
osquery> select pid, name, path from processes where pid = '557';
+-----+-------+-----------------+
| pid | name  | path            |
+-----+-------+-----------------+
| 557 | cupsd | /usr/sbin/cupsd |
+-----+-------+-----------------+
```

We have identified a process that looks similar to a system file. This could also be a case of suspicious processes masquerading as legitimate system files to avoid detection.

### 7.3 **Hidden Files**

Hiding files on the host is a common practice. However, adversaries may also change the mode of suspicious files to hide if they do not want the user to see them. We will use the following command to look at the root directory for any hidden files or directories.

**Search Query:** `SELECT filename, path, directory, size, type FROM file WHERE path LIKE '/.%';`

**Explanation:** 

- This query will examine the root directory to track down hidden files or folders.
- In a real investigation, we will also need to examine other locations.

Similarly, we can update the query to look at other directories like `/tmp/`, `/etc/`, `/usr/bin/`, etc.

### 7.4 **Recently Modified Files**

**Search Query**:`SELECT filename, path, directory, type, size FROM file WHERE path LIKE '/etc/%' AND (mtime > (strftime('%s', 'now') - 86400));`

```bash
osquery> SELECT filename, path, directory, type, size FROM file WHERE path LIKE '/etc/%' AND (mtime > (strftime('%s', 'now') - 86400));
+----------+------------+-----------+-----------+------+
| filename | path       | directory | type      | size |
+----------+------------+-----------+-----------+------+
| .        | /etc/cups/ | /etc/cups | directory | 4096 |
| mtab     | /etc/mtab  | /etc      | regular   | 0    |
+----------+------------+-----------+-----------+------+
```

This query will look at the modified time (mtime) and list down the recently modified files. During a live investigation, this could be very useful in tracking down the system files or binaries that were recently modified.

### 7.5 Recently Modified Binaries

Similar to files, adversaries tend to modify system binaries and ingest malicious code into them to avoid detection. This query will look at the modification time and see which binary was modified recently.

**Search Query:** `SELECT filename, path, directory, mtime FROM file WHERE path LIKE '/opt/%' OR path LIKE '/bin/' AND (mtime > (strftime('%s', 'now') - 86400));`

```bash
osquery> SELECT filename, path, directory, mtime FROM file WHERE path LIKE '/opt/%' OR path LIKE '/bin/' AND (mtime > (strftime('%s', 'now') - 86400));
+----------+---------------+--------------+------------+
| filename | path          | directory    | mtime      |
+----------+---------------+--------------+------------+
| hh.so    | /opt/hh.so    | /opt         | 1720550772 |
| .        | /opt/ll/      | /opt/ll      | 1720550795 |
| .        | /opt/osquery/ | /opt/osquery | 1719256660 |
+----------+---------------+--------------+------------+
```

The above query only looks at the files and binaries updated in the last 24 hours in the `/opt/` or `/bin/` directories. We can update the time to get the updated results. 

### 7.6 **Finding Suspicious Packages**

Adversaries often install suspicious packages via apt or dpkg to gain and maintain access to compromised Linux systems. These packages can be used for various malicious purposes, such as establishing persistence, capturing data, or maintaining backdoor access.

- **Search for the Latest Installed Packages**
    - Search for the term `install` in the `/var/log/dpkg.log` file, which contains all the information about installed / uninstalled packages.

```bash
ubuntu@cybertees:/home$ grep " install " /var/log/dpkg.log
2024-06-13 06:47:05 install linux-image-5.15.0-1063-aws:amd64 <none> 5.15.0-1063.69~20.04.1
2024-06-13 06:47:06 install linux-aws-5.15-headers-5.15.0-1063:all <none> 5.15.0-1063.69~20.04.1
2024-06-13 06:47:09 install linux-headers-5.15.0-1063-aws:amd64 <none> 5.15.0-1063.69~20.04.1
2024-06-24 19:17:39 install osquery:amd64 <none> 5.12.1-1.linux
2024-06-26 05:54:38 install sysstat:amd64 <none> 12.2.0-2ubuntu0.3
2024-06-26 14:32:05 install REDACTED:amd64 <none> 1.0
```

- **Get Additional Information about installed package**
    - `dpkg -l | grep <package name>`


## 8. Conclusion

Live analysis of a compromised Linux system provides invaluable insight into attacker activity that may never be recovered from disk alone. By carefully inspecting volatile artifacts such as running processes, open files, network connections, and in-memory data, defenders can reconstruct what is happening on the system **in real time**.

Throughout this investigation, we demonstrated how:
- Suspicious processes can be identified through **execution paths, parent-child relationships, and memory-only behavior**
- Network analysis helps reveal **command-and-control communication, lateral movement, or data exfiltration**
- Disk artifacts such as **temporary files, modified binaries, hidden files, and suspicious packages** often leave behind clear indicators of compromise
- **osquery** acts as a powerful ally, enabling defenders to query system state using a consistent and forensic-friendly approach

It is important to note that **live forensics should always be performed carefully**. Actions taken during analysis can alter system state, so every command executed should be intentional and documented. In real-world incidents, findings from live analysis should be preserved and correlated with disk forensics, logs, and threat intelligence to build a complete picture of the attack.

Ultimately, mastering Linux live analysis strengthens a defender’s ability to **detect, contain, and respond to intrusions effectively**. With a structured methodology and the right tooling, even heavily compromised systems can reveal the attacker’s footprint.