---
title: "Analysing Network Traffic using Tshark"
date: 2026-01-04
categories: [Blue-Team, THM]
tags: [Blue Team, Tshark]
---



### **What is TShark?**
TShark is the command-line counterpart to Wireshark, offering powerful packet analysis capabilities for security analysts and network administrators. This guide covers essential TShark commands, filtering techniques, and practical workflows for network traffic investigation from basic packet capture to advanced protocol analysis and artifact extraction. Here are some additional details about this tool:
- CLI version of wireshark
- Developed by the developers of Wireshark
- Preferred for comprehensive packet analysis

**Note: The example demonstrated in this article is based on TryHackMe rooms.**

### 1. **Command-Line Packet Analysis Hints**

| **Tool/Utility** | **Purpose and Benefit** |
| --- | --- |
| **capinfos** | A program that provides details of a specified capture file.<br>It is suggested to view the summary of the capture file before starting an investigation. |
| **grep** | Helps search plain-text data. |
| **cut** | Helps cut parts of lines from a specified data source. |
| **uniq** | Filters repeated lines/values. |
| **nl** | Views the number of shown lines. |
| **sed** | A stream editor. |
| **awk** | Scripting language that helps pattern search and processing. |

### 2. TShark Fundamentals | Main Parameters I

| **Parameter** | **Purpose** |
|---------------|-------------|
| `-h` | Display the help page with the most common features.<br>• `tshark -h` |
| `-v` | Show version information.<br>• `tshark -v` |
| `-D` | List available sniffing interfaces.<br>• `tshark -D` |
| `-i` | Choose an interface to capture live traffic.<br>• `tshark -i 1`<br>• `tshark -i ens55` |
| *(No parameter)* | Sniff traffic similarly to `tcpdump`.<br>• `tshark` |

### 3. TShark Fundamentals | Main Parameters II

- The `-V` option shows details about each packet just like wireshark.
- Analysts should remove the noise first and then perform in-depth analysis using `-V` option.

| **Parameter** | **Purpose** |
|---------------|-------------|
| `-r` | Read input from a capture file.<br>• `tshark -r traffic_analysis.pcapng` |
| `-c` | Packet count.<br>Stop after capturing a specified number of packets (e.g., stop after 10 packets).<br>• `tshark -c 10` |
| `-w` | Write captured traffic to a file.<br>• `tshark -w sample-capture.pcap` |
| `-V` | Verbose mode.<br>Provides detailed information for **each packet**, similar to Wireshark’s **Packet Details** pane.<br>• `tshark -V` |
| `-q` | Silent mode.<br>Suppresses packet output in the terminal.<br>• `tshark -q` |
| `-x` | Display packet bytes.<br>Shows packet details in hexadecimal and ASCII format for each packet.<br>• `tshark -x` |

### 4. TShark Fundamentals II | Capture Conditions

- The `-a` option is used for stopping capture process once the criteria is met. `AUTO STOP`
- The `-b` option is used for running packet capture in `INFINITE LOOP`.
- The capture option `-a and -b` are only available in `capturing/sniffing` mode.
- We can combine both option `-a` and `-b`.

```bash
tshark -b filesize:10000 -b files:5 -w capture.pcap
```

In this example:

- `filesize:10000` means each capture file is limited to 10,000 KB.
- `files:5` means a total of 5 files will be used in the ring buffer. When the `6th` file is needed, the `oldest` file will be `overwritten`.

| **Parameter** | **Purpose** |
|---------------|-------------|
| *(Autostop overview)* | Define capture conditions for a **single run/loop**.<br>Capture **stops** after the condition is met (Autostop). |
| `-a` | **Duration:** Sniff traffic and stop after X seconds. Create a new file and write output to it.<br>• `tshark -w test.pcap -a duration:1`<br><br>**Filesize:** Define the maximum capture file size (KB). Stop after reaching the specified size.<br>• `tshark -w test.pcap -a filesize:10`<br><br>**Files:** Define the maximum number of output files. Stop after X files are created.<br>• `tshark -w test.pcap -a filesize:10 -a files:3` |
| *(Ring buffer overview)* | Ring buffer control options.<br> Define capture conditions for **multiple runs/loops** (**infinite loop** until manually stopped). |
| `-b` | **Duration:** Sniff traffic for X seconds, then create a new file and continue writing output.<br>• `tshark -w test.pcap -b duration:1`<br><br>**Filesize:** Define the maximum capture file size (KB).<br>Create a new file after reaching the specified size.<br>• `tshark -w test.pcap -b filesize:10`<br><br>**Files:** Define the maximum number of output files.<br>Overwrite the oldest file after X files are created.<br>• `tshark -w test.pcap -b filesize:10 -b files:3` |


### 5. TShark Fundamentals III | Packet Filtering Options: Capture vs. Display Filters

- `Capture Filters`
    - Live filtering options.
    - The purpose is to **save** only a specific part of the traffic.
    - It is set before capturing traffic and is not changeable during live capture.
- `Display Filters`
    - Post-capture filtering options.
    - The purpose is to investigate packets by **reducing the number of visible packets**, which is changeable during the investigation.

| **Parameter** | **Purpose** |
|---------------|-------------|
| `-f` | **Capture filters.** Uses BPF syntax, the same as Wireshark capture filters. |
| `-Y` | **Display filters.** Uses the same syntax as Wireshark display filters. |

### 5.1 Capture Filters

**Reference:**

- https://www.wireshark.org/docs/man-pages/pcap-filter.html
- https://gitlab.com/wireshark/wireshark/-/wikis/CaptureFilters#useful-filters

| **Qualifier** | **Details and Available Options** |
|---------------|----------------------------------|
| **Type** | Target match type. You can filter IP addresses, hostnames, IP ranges, and port numbers.<br><br>**Note:** If no qualifier is set, `host` is used by default.<br><br>**Available options:** `host` \| `net` \| `port` \| `portrange`<br><br>• Filtering a host:<br>◦ `tshark -f "host 10.10.10.10"`<br><br>• Filtering a network range:<br>◦ `tshark -f "net 10.10.10.0/24"`<br><br>• Filtering a port:<br>◦ `tshark -f "port 80"`<br><br>• Filtering a port range:<br>◦ `tshark -f "portrange 80-100"` |
| **Direction** | Target traffic direction/flow.<br><br>**Note:** If no direction is specified, it defaults to `either` (both directions).<br><br>**Available options:** `src` \| `dst`<br><br>• Filtering source address:<br>◦ `tshark -f "src host 10.10.10.10"`<br><br>• Filtering destination address:<br>◦ `tshark -f "dst host 10.10.10.10"` |
| **Protocol** | Target protocol.<br><br>**Common options:** `arp` \| `ether` \| `icmp` \| `ip` \| `ip6` \| `tcp` \| `udp`<br><br>• Filtering TCP traffic:<br>◦ `tshark -f "tcp"`<br><br>• Filtering a MAC address:<br>◦ `tshark -f "ether host F8:DB:C5:A2:5D:81"`<br><br>• Filtering by IP protocol number (IANA-assigned):<br>◦ ICMP (Protocol 1):<br>◦ `tshark -f "ip proto 1"`<br><br>Reference: Assigned Internet Protocol Numbers (IANA) |


| **Capture Filter Category** | **Details** |
|-----------------------------|-------------|
| **Host Filtering** | Capture traffic to or from a specific host.<br><br>• Traffic generation using cURL (default HTTP request):<br>◦ `curl tryhackme.com`<br><br>• TShark capture filter for a host:<br>◦ `tshark -f "host tryhackme.com"` |
| **IP Filtering** | Capture traffic to or from a specific IP address.<br><br>• Traffic generation using Netcat (verbose, 5-second timeout):<br>◦ `nc 10.10.10.10 4444 -vw 5`<br><br>• TShark capture filter for a specific IP address:<br>◦ `tshark -f "host 10.10.10.10"` |
| **Port Filtering** | Capture traffic to or from a specific port.<br><br>• Traffic generation using Netcat (verbose, 5-second timeout):<br>◦ `nc 10.10.10.10 4444 -vw 5`<br><br>• TShark capture filter for port 4444:<br>◦ `tshark -f "port 4444"` |
| **Protocol Filtering** | Capture traffic for a specific protocol.<br><br>• Traffic generation using Netcat over UDP (verbose, 5-second timeout):<br>◦ `nc -u 10.10.10.10 4444 -vw 5`<br><br>• TShark capture filter for UDP traffic:<br>◦ `tshark -f "udp"` |


### 5.2 Display Filters

- **Reference:** https://www.wireshark.org/docs/dfref/

| **Display Filter Category** | **Details and Available Options** |
|-----------------------------|----------------------------------|
| **Protocol: IP** | • Filtering an IP without specifying direction:<br>◦ `tshark -Y 'ip.addr == 10.10.10.10'`<br><br>• Filtering a network range:<br>◦ `tshark -Y 'ip.addr == 10.10.10.0/24'`<br><br>• Filtering a source IP:<br>◦ `tshark -Y 'ip.src == 10.10.10.10'`<br><br>• Filtering a destination IP:<br>◦ `tshark -Y 'ip.dst == 10.10.10.10'` |
| **Protocol: TCP** | • Filtering a TCP port:<br>◦ `tshark -Y 'tcp.port == 80'`<br><br>• Filtering a source TCP port:<br>◦ `tshark -Y 'tcp.srcport == 80'` |
| **Protocol: HTTP** | • Filtering HTTP packets:<br>◦ `tshark -Y 'http'`<br><br>• Filtering HTTP packets with response code **200**:<br>◦ `tshark -Y 'http.response.code == 200'` |
| **Protocol: DNS** | • Filtering DNS packets:<br>◦ `tshark -Y 'dns'`<br><br>• Filtering DNS **A** records:<br>◦ `tshark -Y 'dns.qry.type == 1'` |



### 6. Command-Line Wireshark Features I | Statistics I

- The options that we use are applied to all packets in scope unless display filter is provided.
- TShark explains the parameters used at the beginning of the output file.
- For example, you will use the `phs` option to view the protocol hierarchy. Once you use this command, the result will start with the "**P**acket **H**ierarchy **S**tatistics" header.

| **Parameter** | **Purpose** |
|---------------|-------------|
| `--color` | Wireshark-like colourised output.<br>• `tshark --color` |
| `-z` | Statistics options.<br><br>There are multiple sub-options available under this parameter. You can view them using:<br>• `tshark -z help`<br><br>Sample usage:<br>• `tshark -z filter`<br><br>**Notes:**<br>• When using `-z`, packets are shown first, followed by statistics.<br>• Use `-q` to suppress packet output and focus only on statistics.<br>• Do **not** use `-V` when collecting statistics, as it may affect accuracy. |

### **6.1 Protocol Hierarchy**

- Protocol hierarchy helps analysts to see the protocols used, frame numbers, and size of packets in a tree view based on packet numbers.

```bash
           
imnishant@idefend$ tshark -r testing.pcapng -z io,phs -q
===================================================================
Protocol Hierarchy Statistics
Filter: 

  eth                                    frames:43 bytes:25091
    ip                                   frames:43 bytes:25091
      tcp                                frames:41 bytes:24814
        http                             frames:4 bytes:2000
          data-text-lines                frames:1 bytes:214
            tcp.segments                 frames:1 bytes:214
          xml                            frames:1 bytes:478
            tcp.segments                 frames:1 bytes:478
      udp                                frames:2 bytes:277
        dns                              frames:2 bytes:277
===================================================================
```

- We can further drill down the output of above command and only view details of specific protocol.

```bash
           
imnishant@idefend$ tshark -r traffic_analysis.pcapng -z io,phs,udp -q
===================================================================
Protocol Hierarchy Statistics
Filter: udp

  eth                                    frames:2 bytes:277
    ip                                   frames:2 bytes:277
      udp                                frames:2 bytes:277
        dns                              frames:2 bytes:277
===================================================================
```

### **6.2 Packet Lengths Tree**

```bash
           
imnishant@idefend$ tshark -r traffic_analysis.pcapng -z plen,tree -q

=========================================================================================================================
Packet Lengths:
Topic / Item       Count     Average       Min val       Max val     Rate (ms)     Percent     Burst rate    Burst start  
-------------------------------------------------------------------------------------------------------------------------
Packet Lengths     43        583.51        54            1484        0.0014        100         0.0400        2.554        
 0-19              0         -             -             -           0.0000        0.00        -             -            
 20-39             0         -             -             -           0.0000        0.00        -             -            
 40-79             22        54.73         54            62          0.0007        51.16       0.0200        0.911        
 80-159            1         89.00         89            89          0.0000        2.33        0.0100        2.554        
 160-319           2         201.00        188           214         0.0001        4.65        0.0100        2.914        
 320-639           2         505.50        478           533         0.0001        4.65        0.0100        0.911        
 640-1279          1         775.00        775           775         0.0000        2.33        0.0100        2.984        
 1280-2559         15        1440.67       1434          1484        0.0005        34.88       0.0200        2.554        
 2560-5119         0         -             -             -           0.0000        0.00        -             -            
 5120 and greater  0         -             -             -           0.0000        0.00        -             -            
-------------------------------------------------------------------------------------------------------------------------  
```

### **6.3 Endpoints**

- Analysts should analyze the endpoints from `PCAP` file to identify if there is any suspicious endpoints with with frequent communication took place.
- Just like in wireshark, filters could be one of the following.

| **Filter** | **Purpose** |
|------------|-------------|
| `eth` | Ethernet addresses |
| `ip` | IPv4 addresses |
| `ipv6` | IPv6 addresses |
| `tcp` | TCP addresses (valid for both IPv4 and IPv6) |
| `udp` | UDP addresses (valid for both IPv4 and IPv6) |
| `wlan` | IEEE 802.11 addresses |


```bash
           
imnishant@idefend$ tshark -r traffic_analysis.pcapng -z endpoints,ip -q
=================================================================================
IPv4 Endpoints
Filter:
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
145.254.160.237               43         25091         20            2323          23           22768   
65.208.228.223                34         20695         18           19344          16            1351   
216.239.59.99                  7          4119          4            3236           3             883   
145.253.2.203                  2           277          1             188           1              89   
===================================================================================
```

### **6.4 Conversation**

- TShark provides stats on conversation between various devices.

```bash
           
imnishant@idefend$ tshark -r traffic_analysis.pcapng -z conv,ip -q  
================================================================================
IPv4 Conversations
Filter:
                                           |       <-      | |       ->      | |     Total     |    Relative    |   
Duration
                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |             
65.208.228.223   <-> 145.254.160.237           16      1351      18     19344      34     20695     0.000000000        30.3937
145.254.160.237  <-> 216.239.59.99              4      3236       3       883       7      4119     2.984291000         1.7926
145.253.2.203    <-> 145.254.160.237            1        89       1       188       2       277     2.553672000         0.3605
================================================================================

        
```

### **6.5 Expert Info**

```bash
imnishant@idefend$ tshark -r traffic_analysis.pcapng -z expert -q

Notes (3)
=============
   Frequency      Group           Protocol  Summary
           1   Sequence                TCP  This frame is a (suspected) spurious retransmission
           1   Sequence                TCP  This frame is a (suspected) retransmission
           1   Sequence                TCP  Duplicate ACK (#1)

Chats (8)
=============
   Frequency      Group           Protocol  Summary
           1   Sequence                TCP  Connection establish request (SYN): server port 80
           1   Sequence                TCP  Connection establish acknowledge (SYN+ACK): server port 80
           1   Sequence               HTTP  GET /download.html HTTP/1.1\r\n
           1   Sequence               HTTP  GET /pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&lmt=1082467020
           2   Sequence               HTTP  HTTP/1.1 200 OK\r\n
           2   Sequence                TCP  Connection finish (FIN)
```

### **6.6 IPv4 and IPv6**

- This filer option allows us to vizualize the number of packtes associated with specific host which helps in detecting an anomalous host at a glance.

```bash
imnishant@idefend$ tshark -r traffic_analysis.pcapng -z ptype,tree -q==========================================================================================================================
IPv4 Statistics/IP Protocol Types:
Topic / Item       Count         Average       Min val       Max val Rate (ms)     Percent       Burst rate    Burst start
--------------------------------------------------------------------------------------------------------------------------
IP Protocol Types  43                                                0.0014        100          0.0400        2.554
 TCP               41                                                0.0013        95.35        0.0300        0.911
 UDP               2                                                 0.0001        4.65         0.0100        2.554
--------------------------------------------------------------------------------------------------------------------------
```

- **IPv4:** `z ip_hosts,tree -q`
- **IPv6:**  `z ipv6_hosts,tree -q`

```bash
imnishant@idefend$ tshark -r traffic_analysis.pcapng -z ip_hosts,tree -q===========================================================================================================================
IPv4 Statistics/All Addresses:
Topic / Item      Count         Average       Min val       Max val  Rate (ms)     Percent       Burst rate    Burst start
---------------------------------------------------------------------------------------------------------------------------
All Addresses     43                                                 0.0014        100          0.0400        2.554
 145.254.160.237  43                                                 0.0014        100.00       0.0400        2.554
 65.208.228.223   34                                                 0.0011        79.07        0.0300        0.911
---------------------------------------------------------------------------------------------------------------------------
```

- For complex cases and in-depth analysis, you will need to correlate the finding by focusing on the source and destination addresses.
- You can filter all source and destination addresses using the parameters given below.
    - IPv4: `z ip_srcdst,tree -q`
    - IPv6: `z ipv6_srcdst,tree -q`

```bash
imnishant@idefend$ tshark -r traffic_analysis.pcapng -z ip_srcdst,tree -q==========================================================================================================================
IPv4 Statistics/Source and Destination Addresses:
Topic / Item                     Count         Average       Min val       Max val  Rate (ms)     Percent       Burst rate    Burst start
--------------------------------------------------------------------------------------------------------------------------
Source IPv4 Addresses            43                                                 0.0014        100          0.0400
 145.254.160.237                 20                                                 0.0007        46.51        0.0200
 65.208.228.223                  18                                                 0.0006        41.86        0.0200
...
Destination IPv4 Addresses       43                                                 0.0014        100          0.0400
 145.254.160.237                 23                                                 0.0008        53.49        0.0200
 65.208.228.223                  16                                                 0.0005        37.21        0.0200
...
------------------------------------------------------------------------------------------------------------------------
```

- In some cases, you will need to focus on the outgoing traffic to spot the used services and ports.
- You can filter all outgoing traffic by using the parameters given below.
    - IPv4: `z dests,tree -q`
    - IPv6: `z ipv6_dests,tree -q`

```bash
imnishant@idefend$ tshark -r traffic_analysis.pcapng -z dests,tree -q=============================================================================================================================
IPv4 Statistics/Destinations and Ports:
Topic / Item            Count         Average       Min val       Max val       Rate (ms)     Percent       Burst rate    Burst start
-----------------------------------------------------------------------------------------------------------------------------
Destinations and Ports  43                                                      0.0014        100          0.0400        2.554
 145.254.160.237        23                                                      0.0008        53.49        0.0200        2.554
  TCP                   22                                                      0.0007        95.65        0.0200        2.554
   3372                 18                                                      0.0006        81.82        0.0200        2.554
   3371                 4                                                       0.0001        18.18        0.0200        3.916
  UDP                   1                                                       0.0000        4.35         0.0100        2.914
   3009                 1                                                       0.0000        100.00       0.0100        2.914
 65.208.228.223         16                                                      0.0005        37.21        0.0200        0.911
 ...
-----------------------------------------------------------------------------------------------------------------------------
```

### 6.7 Statistics | DNS

```bash
imnishant@idefend$ tshark -r traffic_analysis.pcapng -z dns,tree -q
===========================================================================================================================
DNS:
Topic / Item                   Count         Average       Min val       Max val       Rate (ms)     Percent       Burst rate    Burst start
---------------------------------------------------------------------------------------------------------------------------
Total Packets                  2                                             0.0055        100          0.0100        2.554
 rcode                         2                                             0.0055        100.00       0.0100        2.554
  No error                     2                                             0.0055        100.00       0.0100        2.554
 opcodes                       2                                             0.0055        100.00       0.0100        2.554
  Standard query               2                                             0.0055        100.00       0.0100        2.554
 ...
-------------------------------------------------------------------------------------------------------------------------
```

### 6.8 Statistics | HTTP

- This option provides statistics on HTTP packets by summarising the load distribution, requests, packets, and status info.
- You can filter the packets and view the details using the parameters given below.
    - **Packet and status counter for HTTP:** `z http,tree -q`
    - **Packet and status counter for HTTP2:** `z http2,tree -q`
    - **Load distribution:** `z http_srv,tree -q`
    - **Requests:** `z http_req,tree -q`
    - **Requests and responses:** `z http_seq,tree -q`

```bash
imnishant@idefend$ tshark -r traffic_analysis.pcapng -z http,tree -q
=============================================================================================================================
HTTP/Packet Counter:
Topic / Item            Count         Average       Min val       Max val       Rate (ms)     Percent     Burst rate  Burst start
----------------------------------------------------------------------------------------------------------------------------
Total HTTP Packets      4                                                       0.0010        100          0.0100     0.911
 HTTP Response Packets  2                                                       0.0005        50.00        0.0100     3.956
  2xx: Success          2                                                       0.0005        100.00       0.0100     3.956
   200 OK               2                                                       0.0005        100.00       0.0100     3.956
  ???: broken           0                                                       0.0000        0.00         -          -
  3xx: Redirection      0                                                       0.0000        0.00         -          -
 ...
-----------------------------------------------------------------------------------------------------------------------
```

### 6.9 View Traffic Flow

- It shows entire TCP conversation between two endpoints.

```bash
imnishant@idefend$:~/Desktop/exercise-files$ tshark -r traffic_analysis.pcapng -q -z flow,tcp,standard | head -n 10
Conv.| Time    | 145.254.160.237                       | 216.239.59.99                         |
     |         |                   | 65.208.228.223    |                   
0    |0.000000 |         SYN       |                   |                   |Seq = 0
     |         |(3372)   ------------------>  (80)     |                   |
0    |0.911310 |         SYN, ACK  |                   |                   |Seq = 0 Ack = 1
     |         |(3372)   <------------------  (80)     |                   |
0    |0.911310 |         ACK       |                   |                   |Seq = 1 Ack = 1
     |         |(3372)   ------------------>  (80)     |                   |
0    |0.911310 |         PSH, ACK - Len: 479           |                   |Seq = 1 Ack = 1
     |         |(3372)   ------------------>  (80)     |                   |

```

### 6.10 Follow TCP Stream

- Just like in wireshark, we call follow streams in TShark to see the entire conversation.
- This option helps analysts to follow traffic streams similar to Wireshark. The query structure is explained in the table given below.

| **Main Parameter** | **Protocol** | **View Mode** | **Stream Number** | **Additional Parameter** |
|-------------------|--------------|---------------|-------------------|--------------------------|
| `-z follow` | • TCP<br>• UDP<br>• HTTP<br>• HTTP2 | • HEX<br>• ASCII | 0, 1, 2, 3, … | `-q` |

**Note:** Streams start from "0". You can filter the packets and follow the streams by using the parameters given below.

- **TCP Streams:** `z follow,tcp,ascii,0 -q`
- **UDP Streams:** `z follow,udp,ascii,0 -q`
- **HTTP Streams:** `z follow,http,ascii,0 -q`

```bash
           
imnishant@idefend$ tshark -r traffic_analysis.pcapng -z follow,tcp,ascii,1 -q
===================================================================
**Follow: tcp,ascii
Filter: tcp.stream eq 1**
Node 0: 145.254.160.237:3371
Node 1: 216.239.59.99:80
GET /pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&lmt=1082467020&format=468x60_as&outp...
Host: pagead2.googlesyndication.com
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113
...

HTTP/1.1 200 OK
P3P: policyref="http://www.googleadservices.com/pagead/p3p.xml", CP="NOI DEV PSA PSD IVA PVD OTP OUR OTR IND OTC"
Content-Type: text/html; charset=ISO-8859-1
Content-Encoding: gzip
Server: CAFE/1.0
Cache-control: private, x-gzip-ok=""
Content-length: 1272
Date: Thu, 13 May 2004 10:17:14 GMT

...mmU.x..o....E1...X.l.(.AL.f.....dX..KAh....Q....D...'.!...Bw..{.Y/T...<...GY9J....?;.ww...Ywf..... >6..Ye.X..H_@.X.YM.......#
:.....D..~O..STrt..,4....H9W..!E.....&.X.=..P9..a...<...-.O.l.-m....h..p7.(O?.a..:..-knhie...
..g.A.x..;.M..6./...{..9....H.W.a.qz...O.....B..
=========================================================================

        
```

### 6.11 Export Objects

This option helps analysts to extract files from DICOM, HTTP, IMF, SMB and TFTP. The query structure is explained in the table given below.

| **Main Parameter** | **Protocol** | **Target Folder** | **Additional Parameter** |
|-------------------|--------------|-------------------|--------------------------|
| `--export-objects` | • DICOM<br>• HTTP<br>• IMF<br>• SMB<br>• TFTP | Target directory where extracted files will be saved. | `-q` |

```bash
# Extract the files from HTTP traffic.

imnishant@idefend$ tshark -r traffic_analysis.pcapng --export-objects http,/home/ubuntu/Desktop/extracted-by-tshark -q # view the target folder content.

imnishant@idefend$ ls -l /home/ubuntu/Desktop/extracted-by-tshark/total 24
-rw-r--r-- 1 ubuntu ubuntu  'ads%3fclient=ca-pub-2309191948673629&random=1084443430285&lmt=1082467020&format=468x60_as&o
-rw-r--r-- 1 ubuntu ubuntu download.html
```

### 6.12 Credentials

- This option helps analysts to detect and collect cleartext credentials from FTP, HTTP, IMAP, POP and SMTP. You can filter the packets and find the cleartext credentials using the parameters below.
- `-z credentials -q`

Find cleartext credentials

```bash
imnishant@idefend$ tshark -r credentials.pcap -z credentials -q
===================================================================
Packet     Protocol         Username         Info
------     --------         --------         --------
72         FTP              admin            Username in packet: 37
80         FTP              admin            Username in packet: 47
83         FTP              admin            Username in packet: 54
118        FTP              admin            Username in packet: 93
123        FTP              admin            Username in packet: 97
167        FTP              administrator    Username in packet: 133
207        FTP              administrator    Username in packet: 170
220        FTP              administrator    Username in packet: 184
230        FTP              administrator    Username in packet: 193
....
===================================================================
```

## 7. Advanced Filtering Options

- We should use `matches` and `contains` operators, which are the key to advanced filtering options.

| **Filter** | **Details** |
| --- | --- |
| **Contains** | • Search a value inside packets.<br>• Case sensitive.<br>• Similar to Wireshark's "find" option. |
| **Matches** | • Search a pattern inside packets.<br>• Supports regex.<br>• Case insensitive.<br>• Complex queries have a margin of error. |

**Note:** The `"contains"` and `"matches"` operators cannot be used with fields consisting of `"integer"` values.

**Tip:** Using HEX and regex values instead of ASCII always has a better chance of a match.

### 7.1 Extract Fields

This option helps analysts to extract specific parts of data from the packets. In this way, analysts have the opportunity to collect and correlate various fields from the packets. It also helps analysts manage the query output on the terminal. The query structure is explained in the table given below.

| **Main Filter** | **Target Field** | **Show Field Name** |
|-----------------|-----------------|-------------------|
| `-T fields` | `-e <field name>` | `-E header=y` |

**Note:** You need to use the `-e` parameter for each field you want to display.

You can filter any field by using the field names as shown below.

- `T fields -e ip.src -e ip.dst -E header=y`

```bash
imnishant@idefend$ tshark -r traffic_analysis.pcapng -T fields -e ip.src -e ip.dst -E header=y -c 5         
ip.src	          ip.dst
145.254.160.237	65.208.228.223
65.208.228.223	145.254.160.237
145.254.160.237	65.208.228.223
145.254.160.237	65.208.228.223
65.208.228.223	145.254.160.237
```

### 7.2 Filter: “contains”

| **Filter** | **contains** |
|------------|--------------|
| **Type** | Comparison operator |
| **Description** | Search for a value inside packets. It is **case-sensitive** and functions similarly to Wireshark's "Find" option, focusing on a specific field. |
| **Example** | Find all "Apache" servers. |
| **Workflow** | List all HTTP packets where the `server` field contains the keyword "Apache". |
| **Usage** | `http.server contains "Apache"` |

```bash
           
imnishant@idefend$ tshark -r traffic_analysis.pcapng -Y 'http.server contains "Apache"'                          
   38   4.846969 65.208.228.223 ? 145.254.160.237 HTTP/XML HTTP/1.1 200 OK 

imnishant@idefend$ tshark -r traffic_analysis.pcapng -Y 'http.server contains "Apache"' -T fields -e ip.src -e ip.dst -e http.server -E header=y
ip.src	ip.dst	http.server
65.208.228.223	145.254.160.237	Apache 

        
```

### 7.3 Filter: “matches”

| **Filter** | **matches** |
|------------|-------------|
| **Type** | Comparison operator |
| **Description** | Search using a **regular expression**. It is **case-insensitive**, and complex queries may have a margin of error. |
| **Example** | Find all `.php` and `.html` pages. |
| **Workflow** | List all HTTP packets where the `request.method` field matches the keywords "GET" or "POST". |
| **Usage** | `http.request.method matches "(GET|POST)"` |

```bash
           
imnishant@idefend$ tshark -r traffic_analysis.pcapng -Y 'http.request.method matches "(GET|POST)"'               
    4   0.911310 145.254.160.237 ? 65.208.228.223 HTTP GET /download.html HTTP/1.1 
   18   2.984291 145.254.160.237 ? 216.239.59.99 HTTP GET /pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&

imnishant@idefend$ tshark -r traffic_analysis.pcapng -Y 'http.request.method matches "(GET|POST)"' -T fields -e ip.src -e ip.dst -e http.request.method -E header=y
ip.src	ip.dst	http.request.method
145.254.160.237	65.208.228.223	GET
145.254.160.237	216.239.59.99	GET 
```

## 8. Use Cases | Extract Information

- When investigating a case, a security analyst should know how to extract hostnames, DNS queries, and user agents to hunt low-hanging fruits after viewing the statistics and creating an investigation plan.

### 8.1 Extract Hostname

```bash
           
           
imnishant@idefend$ tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname | awk NF | sort -r | uniq -c | sort -r
     26 202-ac
     18 92-rkd
     14 93-sts-sec
... 
```

| **Query** | **Purpose** |
|-----------|-------------|
| `tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname` | Extract DHCP hostname values from the capture file. |
| `awk NF` | Remove empty lines from the output. |
| `sort -r` | Sort the output in reverse order (descending) before further processing. |
| `uniq -c` | Show **unique values** and count the number of occurrences for each. |
| `sort -r` | Final sort to display results from highest to lowest occurrences. |

### 8.2 Extract DNS Queries

```bash
           
imnishant@idefend$ tshark -r dns-queries.pcap -T fields -e dns.qry.name | awk NF | sort -r | uniq -c | sort -r
     96 connectivity-check.ubuntu.com.rhodes.edu
     94 connectivity-check.ubuntu.com
      8 3.57.20.10.in-addr.arpa
      4 e.9.d.b.c.9.d.7.1.b.0.f.a.2.0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa
      4 0.f.2.5.6.b.e.f.f.f.b.7.2.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa
      2 _ipps._tcp.local,_ipp._tcp.local
      2 84.170.224.35.in-addr.arpa
      2 22.2.10.10.in-addr.arpa
```

### 8.3 Extract User Agents

```bash
           
imnishant@idefend$ tshark -r user-agents.pcap -T fields -e http.user_agent | awk NF | sort -r | uniq -c | sort -r
      6 Mozilla/5.0 (Windows; U; Windows NT 6.4; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.237 Safari/534.10
      5 Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0
      5 Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.32 Safari/537.36
      4 sqlmap/1.4#stable (http://sqlmap.org)
      3 Wfuzz/2.7
      3 Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
```

## 9. Conclusion
Mastering TShark enables efficient command-line packet analysis, making it an essential tool for incident response, threat hunting, and network forensics. By combining capture filters, display filters, and statistical analysis, analysts can quickly identify suspicious traffic patterns, extract IOCs, and streamline their investigation workflows. Practice these techniques on sample PCAPs to build proficiency in real-world scenarios.