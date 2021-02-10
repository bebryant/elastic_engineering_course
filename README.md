# Elastic_Engineering_Notes
http://192.168.2.11:8081/Bryant/Elastic_Engineering_Notes.git


### Suricata
- IDS and IPS - signature based
- is fork of snort
- multithreaded (snort is not, new snort is multithreaded)
- suricata can filter for more services than snort

### zeek
- Zeek is an open-source software framework for analyzing network traffic that is most commonly used to detect behavioral anomalies on a network for cybersecurity purposes
- Zeek is not an active security device, like a firewall or intrusion prevention system. Rather, Zeek sits on a “sensor,” a hardware, software, virtual, or cloud platform that quietly and unobtrusively observes network traffic. Zeek interprets what it sees and creates compact, high-fidelity transaction logs, file content, and fully customized output, suitable for manual review on disk or in a more analyst-friendly tool like a security and information event management (SIEM) system.
- opensource network monitoring tool
- tracks the originator instead of flip floping between both ends as they swap.
- Zeek now has supported binaries for installation instead of having to make from source.


### Suricata and Zeek
- Suricata and Zeek have their own unique strengths, which is why you need both.

- Suricata is far more efficient than Zeek at monitoring traffic for known threats and producing alerts when they are detected. Another benefit is that new threat intelligence is often available first in a format compatible with Suricata.
Zeek delivers the large volumes of high-quality data needed to provide comprehensive network traffic visibility and context, and enable network baselining, host and service profiling, passive inventory collection, policy enforcement, anomaly detection and threat hunting efforts.

### AF-packet
- read ring buffer
- build into linux kernel
- loose less than .001% packets.  PF ring lost 3% packets.
- used on the NIC
- Feeds data to Suricata, Zeek, and Stenographer

### Apache Kafka
- is an open-source stream-processing software platform. The project aims to provide a unified, high-throughput, low-latency platform for handling real-time data feeds
-  it is a data broker that holds the data until Logstash is ready for it
- zookeeper is used with Kafka

# NUC host

### IPv4 Settings for the NUC

|Address    | Netmask | Gateway | DNS Servers:|
|---  |---  |---| ---|
|172.16.30.100 | 255.255.255.0 | 172.16.30.1  | 172.16.30.1 |

## install CentOS7
1. Select `NETWORK & HOST NAME`
  - change `Host name` in `NETWORK & HOST NAME`
  - Select `configure` in `NETWORK & HOST NAME`
    - Select `IPv4 Settings` Tab inside `configure`
    - Change the `IPv4 Settings` to the above table
  - Select `IPv6 Settings` Tab inside `configure`
    - Select `Ignore` on the dropdown menu under `Method:`
      - note: changing the `IPv6 Settings` to ignore wont totally disable IPv6. You will have to disable IPv6 via the terminal later.
    - Select `save` then select `done`
1. Change `DATE & TIME`  to your network time or `UCT`
1. go to `KDUMP`
  - deselect the checkbox of `Enable kdump` then select `done`
1. Select `INSTALLATION DESTINATION`
  - Select the disks to that you have a `black circle with white checkmark`
  - check the box `I would like to make additional space available` under `Other Storage Options`
  - select `done` which will launch the `RECLAIM DISK SPACE` menu
  - select `Delete all` on the `RECLAIM DISK SPACE` menu
  - select `Reclaim space` on the `RECLAIM DISK SPACE` menu. This will send you to the main menu.
1. Select `INSTALLATION DESTINATION` again
  - Select `I will configure  partitioning` under `Other Storage Options`
  - select `done` which will launch the `MANUAL PARTIONING` menu
  - Select `LVM` under the `New mount points will use the following partitioning scheme:` dropdown menu
  - Select the blue link `Click here to create them automatically`
  - Change `\home` and `/` to `1 GiB` in the `Desired Capacity` box. This allows you space to adjust partition capacities.
  - Select `+` button to launch the `ADD A NEW MOUNT POINT` menu
    - type `/data/stenographer` in to the `Mount Point` dropdown box
    - type `1 GiB` into the `Desired Capacity` box
    - Select `Add mount point` button
  - Select `+` button to launch the `ADD A NEW MOUNT POINT` menu
    - type `/data/kafka` in to the `Mount Point` dropdown box
    - type `1 GiB` into the `Desired Capacity` box
    - Select `Add mount point` button
  - Select `+` button to launch the `ADD A NEW MOUNT POINT` menu
    - type `/data/elasticsearch` in to the `Mount Point` dropdown box
    - type `1 GiB` into the `Desired Capacity` box
    - Select `Add mount point` button
  - Select `+` button to launch the `ADD A NEW MOUNT POINT` menu
    - type `/data/suricata` in to the `Mount Point` dropdown box
    - type `1 GiB` into the `Desired Capacity` box
    - Select `Add mount point` button
  - Select `+` button to launch the `ADD A NEW MOUNT POINT` menu
      - type `/var` in to the `Mount Point` dropdown box
      - type `1 GiB` into the `Desired Capacity` box
      - Select `Add mount point` button
  - Select `+` button to launch the `ADD A NEW MOUNT POINT` menu
      - type `/var/log` in to the `Mount Point` dropdown box
      - type `1 GiB` into the `Desired Capacity` box
      - Select `Add mount point` button
  - Select `+` button to launch the `ADD A NEW MOUNT POINT` menu
      - type `/tmp` in to the `Mount Point` dropdown box
      - type `1 GiB` into the `Desired Capacity` box
      - Select `Add mount point` button
  - Select the `/` and then select `Create a new volume group ...` in the `Volume Group` dropdown box. The `CONFIGURE VOLUME GROUP` menu will launch.
    - Type `OS` into the `Name:` box on the `CONFIGURE VOLUME GROUP` menu and then click `save`
  - Select the `/data/elasticsearch` and then select `centos_sg03` in the `Volume Group` dropdown box. Then select the `Modify` button.  The `CONFIGURE VOLUME GROUP` menu will launch.
    - Type `data` into the `Name:` box on the `CONFIGURE VOLUME GROUP` menu and select the larger of the two hard drives, then click `save`
  - Go through all of the different logical volumes under `New CentOS 7 Installation` and assign them either the `OS` or the `data` `Volume Group`      
  - Assign the following `Desired Capacity` to the following logical volumes:

  |Logical Volume | Desired Capacity |
  | :--- | :--- |
  | /home | 100 GiB |
  | /data/kafka | 100 GiB |
  | /var/log | 50 GiB|
  | /data/stenographer | 500 GiB |
  | /data/suricata | 25 GiB |
  |/data/elasticsearch | 300 GiB |
  | /tmp | 5 GiB |
  | /var | 50 GiB|
  | /boot | 1 GiB |
  | /boot/efi | 200 MiB |
  | / | Remaining capacity (see below) |
  | swap | 15.69 GiB|

  - Select `/` logical volume and either blank out or type `9999999999` in the `Desired Capacity` box. This will change the `Desired Capacity` of `/` to the maximum available space left over.
    - Note: blanking out doesn't work for CentOS 8, you have to use `9999999999`.
  - Select `Done` this will launch the `SUMARRY OF CHANGES` menu. Select `Accept Changes`
1. Select `Begin Installion`
    - Select `USER CREATION`
      - type in `Full name` and `User name` will auto fill.
      - select checkbox `Make this user administarator` and `Require a password to use this account`
      - set password for the user you are creating
      - select `Done` button
    - Select `Finish configuration` button  


  navigate to `/etc/sysconfig/network-scripts`

  `cd /etc/sysconfig/network-scripts`

  and type the following

  `sudo vi ifcfg-emo1`

  change `ONBOOT=no` to `ONBOOT=yes`


# pfSense

  1. on the target host, select the `boot menu` and select the proper boot media that you are installing pfsense from. e.g. `boot from UEFI usb`.
  1. `Install pfSense`
  1. `Default Keymat`
  1. `How would you like to partition your disk?`
    - Select `Auto (UFS)`
    - Select `<Entire Disk>` then `<Yes>`
    - Select `GPT` and `<OK>`
    - Select `<Finish>` then `<Commit>`
    - Select `<No>`
    - Select `<Reboot>` and remove the `USB drive`
  1. after Reboot you will go to `option menu`
    - type `1` for `Assign interfaces` and press `enter`
    - type `n` and press `enter`
    - type `em0` for the WAN interface and press `enter`
    - type `em1` for the LAN interface and press `enter`
    - press `enter` without typing anything
    - verify the interfaces and type `y` then press `enter`
    - you will eventually return to your `option menu`
    - type `2` for `Set interface(s) IP addresses` and press `enter`
    - type `1` and press `enter`
    - type `y` and press `enter`
    - type `n` and press `enter`
    - press `enter` without typing anything
    - type `y` and press `enter`
      - Note: if your using certs you will need to configure HTTPS by selecting `n` and pressing `enter`
    - press `enter`
    - type `2` and press `enter`
    - type `2` and press `enter`
    - type the `pfSense/gateway IP` and press `enter`
      - 172.16.20.1
    - type the netmask for the `pfSense/gateway IP` and press `enter`
      - 24  (e.g. 255.255.255.0)
    - press `enter` without typing anything
    - press `enter` again without typing anything
    - type `y` and press `enter`
    - type in your network IP ranges starting IP and press `enter`
      - 172.16.30.101
    - type in your network IP ranges starting IP and press `enter`
      - 172.16.30.254  
    - press `enter` to continue
1. Plug in a computer  via ethernet cable to the `LAN 2` port to configure pfSense.
    - make sure your pc has the fist IP in the range that was configured on the pfSense.
      - open terminal and type `ip a` to see `172.16.30.101`
    - open browser and type `172.16.30.1` in the address bar
    - The user name is `admin` and the password is `pfsense`
     - Select `next` and then `next` again
     - Primary DNS is the edge router `192.168.2.1`
     - Host name is `pfSense-sg3`
     - Select `next` then `next` again
     - On `Wizard/pfSense Setup/Configure WAN Interface`
      - de-select the checkboxes for `Block RFC1918 Private Networks` and `Block bogon networks`
    - Select `next`
    - type `pfsense` in the second password Block and select `next`
    - Select `Reload` then `Finish`
    - Navigate to `Firewall` then `rules` then `add`
      - Change protocol to `any`
      - source to `any`
        - Note: in production you would want to use `LAN net`
    - duplicate the above for `LAN`
    - navigate to `Diagnostics` then `Halt System`.  Select `halt` and confirm.

#  To configure the ethernet port on the CentOS7 NUC that is used for TAP monitoring
1. `ssh stu3@172.16.30.101`
2. `sudo vi ethtoolscript.sh` then paste below code into file and save

~~~bash
#!/bin/bash


for var in $@
do
  echo "Turning off offloading on $var"
  ethtool -K $var tso off gro off lro off gso off rx off sg off rxvlan off txvlan off
  ethtool -N $var rx-flow-hash udp4 sdfn
  ethtool -N $var rx-flow-hash udp6 sdfn
  ethtool -C $var adaptive-rx off
  ethtool -C $var rx-usecs 1000
  ethtool -G $var rx 4096
done
exit 0
~~~
3. Then do the following:
- `sudo chmod +x ethtoolscript.sh`
- `sudo ./ethtoolscript.sh enp5s0`

# Configure `local.repo` file on NUC
- Type the following commands:
  - `cd /etc/yum.repos.d/`
  - `sudo rm *`
  - `sudo vi local.repo`

cut and paste the following and save:
~~~
[local-base]
name=local-base
baseurl=http://192.168.2.11:8008/base/
enabled=1
gpgcheck=0

[local-rocknsm-2.5]
name=local-rocknsm-2.5
baseurl=http://192.168.2.11:8008/rocknsm_2_5/
enabled=1
gpgcheck=0

[local-elasticsearch-7.x]
name=local-elasticsearch-7.x
baseurl=http://192.168.2.11:8008/elasticsearch-7.x/
enabled=1
gpgcheck=0

[local-epel]
name=local-epel
baseurl=http://192.168.2.11:8008/epel/
enabled=1
gpgcheck=0

[local-extras]
name=local-extras
baseurl=http://192.168.2.11:8008/extras/
enabled=1
gpgcheck=0

[local-updates]
name=local-updates
baseurl=http://192.168.2.11:8008/updates/
enabled=1
gpgcheck=0
~~~
- then run `sudo yum makecache`
