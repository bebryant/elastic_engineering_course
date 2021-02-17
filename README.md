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
  - change `Host name` in `NETWORK & HOST NAME` :  `sg03.local.lan`
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
  - Select the disks you are installing to, so that you have a `black circle with white checkmark`
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


  navigate to `/etc/sysconfig/network-scripts` folder.

  `cd /etc/sysconfig/network-scripts`

  and type the following

  `sudo vi ifcfg-eno1`

  vi will open the `ifcfg-eno1` file
  press `I` to insert and use arrow keys to navigate inside document and change `ONBOOT=no` to `ONBOOT=yes`

edit the `/etc/sysctl.conf` file to disable IPv6 for kafka to work properly
- `sudo vim /etc/sysctl.conf`
- add the following three lines to the bottom of the file:

~~~
# sysctl settings are defined through files in
# /usr/lib/sysctl.d/, /run/sysctl.d/, and /etc/sysctl.d/.
#
# Vendors settings live in /usr/lib/sysctl.d/.
# To override a whole file, create a new file with the same in
# /etc/sysctl.d/ and put new settings there. To override
# only specific settings, add a file with a lexically later
# name in /etc/sysctl.d/ and put new settings there.
#
# For more information, see sysctl.conf(5) and sysctl.d(5).
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
~~~

edit the `/etc/hosts` file to disable the localhost IP for IPv6 so that Kafka will function properly
- `sudo vi /etc/hosts`
  - delete the line ::1
- The file will look like the following:

~~~
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
~~~

reset the network:
- `sudo systemctl restart network`

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

# Suricata
1. Install Suricata on the NUC
  - In the terminal, type `sudo yum install suricata`.

2. Make changes to to `suricata.yaml` file
  - type `sudo vi /etc/suricata/suricata.yaml` and press `enter`
    - make the following changes to suricata.yaml

  | Line | Section  | Setting |
  | :--- | :--- |  :--- |
  | | fast: | enabled: no |
  | | eve-log: | enabled: yes |
  | 580 | af-packet:| - interface: enp5s0 |

  - you can use `/` to enter find mode in vi.  e.g. to find `af-packet:` section you would type `/ af-packet` and press enter.
  - For CPU affinity changes to suricata.yaml
    - `sudo cat /proc/cpuinfo | egrep -e 'processor|physical id|core id' | xargs -13`
    - processor core 0 always has affinity to the OS.  NEVER pin CPU affinity on core 0 for anything other than the OS.  Otherwise the system will drastically bog down.

3. Change the `/etc/sysconfig/suricata` configuration file
  - type `sudo vi /etc/sysconfig/suricata` and press `enter`
    - Make the following changes:
      - `OPTIONS="--af-packet=enp5s0 --user suricata"`

/etc/suricata/suricata
~~~yaml      
# -i <network interface device>
# --user <acct name>
# --group <group name>

# Add options to be passed to the daemon
OPTIONS="--af-packet=enp5s0 --user suricata"
~~~

4. Update suricata rules from repo
  - type `sudo suricata-update add-source local-emerging-threats http://192.168.2.11:8009/suricata-5.0/emerging.rules.tar.gz` and press `enter`

~~~bash
[stu3@sg03 sysconfig]$ sudo suricata-update add-source local-emerging-threats http://192.168.2.11:8009/suricata-5.0/emer
ging.rules.tar.gz
11/2/2021 -- 19:07:57 - <Info> -- Using data-directory /var/lib/suricata.
11/2/2021 -- 19:07:57 - <Info> -- Using Suricata configuration /etc/suricata/suricata.yaml
11/2/2021 -- 19:07:57 - <Info> -- Using /usr/share/suricata/rules for Suricata provided rules.
11/2/2021 -- 19:07:57 - <Info> -- Found Suricata version 5.0.1 at /sbin/suricata.
11/2/2021 -- 19:07:57 - <Info> -- Creating directory /var/lib/suricata/update/sources
[stu3@sg03 sysconfig]$
~~~

5. Starting Suricata
- before starting suricata you need to set ownership of the `/data/suricata` folder
  - type `sudo chown -R suricata: /data/suricata` and press `enter`
- type `sudo systemctl restart suricata` and press `enter`

6. Create/edit a logrotate configuration file for suricata
  - type  `sudo vi /etc/logrotate.d/suricata.conf` and press enter
    - paste the folling into the suricata.conf file

~~~
/data/suricata/*.log /data/suricata/*.json
{
  rotate 3
  missingok
  nocompress
  create
  sharedscripts
  postrotate
          /bin/kill -HUP $(cat /var/run/suricata.pid)
  endscript
}
~~~

Install filebeat
- `sudo yum install filebeat`
- `sudo vi /etc/filebeat/filebeat.yml`

add the following at line 16
~~~
- type: log
    enabled: true
    paths:
      - /data/suricata/eve.json
    json.keys_under_root: true
    fields:
      kafka_topic: suricata-raw
    fields_under_root: true
~~~

# Zeek

## Install Zeek
  1. type `sudo yum install zeek zeek-plugin-kafka zeek-plugin-af_packet` and press `enter`
   - confirm the install with `y`

turn off zeek ASCII logs?

`sudo vi /etc/zeek/network.cfg`

local.zeek is where base scripts will load from. this allows you to modify them and not have to worry about updates/upgrades deleting your modifications to base scripts.

`zeek-config` command lets you find the path of the different zeek directories.
~~~
[stu3@sg03 ~]$ zeek-config
Usage: zeek-config [--version] [--build_type] [--prefix] [--script_dir] [--site_dir] [--plugin_dir] [--config_dir] [--python_dir] [--include_dir] [--cmake_dir] [--zeekpath] [--zeek_dist] [--binpac_root] [--caf_root] [--broker_root]
[stu3@sg03 ~]$
~~~

Modify the zeekctl.cfg file
- type `sudo vi /etc/zeek/zeekctl.cfg`
- add the following to the bottom of the config file, save and exit
~~~
# This is a custom field that was added to allow af_packet support
lb_custom.InterfacePrefix=af_packet::
~~~
- see the `zeelctl.cfg` file in the folder `Zeek Files` for an example


Modify the node.cfg file
- Note: worker - 1 core per 250Mbps (but really 100 Mbps)
- type `sudo vi /etc/zeek/node.cfg`
- add a # to the beginning of lines 8-11 to comment them out
- delete the # to un-comment out lines 16-31
- delete lines 33 to 36
- see the `node.cfg` file in the folder `Zeek Files` for an example


create `/usr/share/site` folder and `/usr/share/zeek/site/scripts` folder
create `af_packet.zeek` in `/usr/share/zeek/site/scripts` folder and paste and save the following:
~~~
redef AF_Packet::fanout_id = strcmp(getenv("fanout_id"),"") == 0 ? 0 : to_count(getenv("fanout_id"));
~~~

Create `kafka.zeek` in `/usr/share/zeek/site/scripts` folder and paste and save the following:
~~~
@load Apache/Kafka/logs-to-kafka

redef Kafka::topic_name = "zeek-raw";
redef Kafka::json_timestamps = JSON::TS_ISO8601;
redef Kafka::tag_json = F;
redef Kafka::kafka_conf = table (
  ["metadata.broker.list"] =
   "172.16.30.100:9092"
);


event zeek_init() &priority=-5
{
    for (stream_id in Log::active_streams)
    {
        if (|Kafka::logs_to_send| == 0 || stream_id in Kafka::logs_to_send)
        {
            local filter: Log::Filter = [
                $name = fmt("kafka-%s", stream_id),
                $writer = Log::WRITER_KAFKAWRITER,
                $config = table(["stream_id"] = fmt("%s", stream_id))
            ];

            Log::add_filter(stream_id, filter);
        }
    }
}
~~~
- Note: see the `kafka.zeek` file in the folder `Zeek Files`

Create `extension.zeek` in `/usr/share/zeek/site/scripts` folder and paste and save the following:
~~~
     type Extension: record {
        ## The log stream that this log was written to.
        stream:   string &log;
        ## The name of the system that wrote this log. This
        ## is defined in the  const so that
        ## a system running lots of processes can give the
        ## same value for any process that writes a log.
        system:   string &log;
        ## The name of the process that wrote the log. In
        ## clusters, this will typically be the name of the
        ## worker that wrote the log.
        proc:     string &log;
    };

    function add_log_extension(path: string): Extension
    {
        return Extension($stream = path,
                         $system = "sensor1",
                         $proc   = peer_description);
    }

    redef Log::default_ext_func   = add_log_extension;
    redef Log::default_ext_prefix = "@";
    redef Log::default_scope_sep  = "_";
~~~


open `/usr/share/zeek/site/local.zeek`
append the following to end of the file
~~~
@load ./scripts/kafka.zeek
@load ./scripts/af_packet.zeek
@load ./scripts/extension.zeek
~~~


# Install Stenographer

`sudo yum install stenographer`

`sudo vi /etc/stenographer/config`
cut, paste and save the following:
~~~
{
  "Threads": [
    { "PacketsDirectory": "/data/stenographer/directory"
    , "IndexDirectory": "/data/stenographer/directory"
    , "MaxDirectoryFiles": 30000
    , "DiskFreePercentage": 10
    }
  ]
  , "StenotypePath": "/usr/bin/stenotype"
  , "Interface": "enp5s0"
  , "Port": 1234
  , "Host": "127.0.0.1"
  , "Flags": []
  , "CertPath": "/etc/stenographer/certs"
}
~~~


# Install kafka
- must install zookeeper too.

1. `sudo yum install zookeeper kafka`


1. `sudo vi /etc/kafka/server.properties`

- un-comment 31 add your sensors IP address
  - `listeners=PLAINTEXT://172.16.30.100:9092`
- un-comment line 36 and add  your sensor IP address.
  - `advertised.listeners=PLAINTEXT://172.16.30.100:9092`
- change line 65 to number of partitions you want
  - `num.partitions=3`
- change `log.dirs=` to the location you are storing data too.
  - `log.dirs=/data/kafka`  
- un-comment and change `log.retention.bytes` to close to but less that your size of your hard drive space.
  - `log.retention.bytes=7374182400`
- Note: `broker.id=` is changed if your doing kafka clusters. Assign a different `broker.id=` to each kafka machine in the cluster.  e.g.  `broker.id=1`, `broker.id=2`, `broker.id=3` for 3 kafka cluster.

1. set up firewalld settings to allow ports that Kafka uses.
  - `sudo firewall-cmd --add-port=2181/tcp --permanent`
  - `sudo firewall-cmd --add-port=9092/tcp --permanent`
  -  For a kafka cluster you would need to add port 2182 and port 2183

1. Modify the `/usr/share/kafka/config/producer.properties` file
- change the `bootstrap.servers=` to your IP of your kafka server
  - `bootstrap.servers=172.16.30.100:9092`

1. Modify the `/usr/share/kafka/config/consumer.properties` file  
- change the `bootstrap.servers=` to your IP of your kafka server
  - `bootstrap.servers=172.16.30.100:9092`

run the below script to see the kafka partition/topic stucture.
- `sudo /usr/share/kafka/bin/kafka-topics.sh --bootstrap-server 172.16.30.100:9092 --list`
- `sudo /usr/share/kafka/bin/kafka-topics.sh --bootstrap-server 172.16.30.100:9092 --describe --topic zeek-raw`
- `sudo /usr/share/kafka/bin/kafka-topics.sh --bootstrap-server 172.16.30.100:9092 --describe --topic suricata-raw`



To wipe everything and reset from scratch:
~~~
sudo systemctl stop kafka zookeeper
sudo rm -rf  /var/lib/zookeeper/version-2/
sudo rm -rf  /data/kafka/*
sudo systemctl start zookeeper kafka
~~~

To test kafka data/topics
~~~
 /usr/share/kafka/bin/kafka-console-producer.sh  --broker-list 172.16.30.100:9092 --topic test`
 /usr/share/kafka/bin/kafka-console-consumer.sh  --bootstrap-server 172.16.30.100:9092 --topic test --from-beginning`
~~~



comment out the `Elasticsearch Output` Section

add a kafka output Section at line 182

~~~
output.kafka:
  hosts: ["localhost:9092"]
  topic: '%{[kafka_topic]}'
  required_acks: 1
  compression: gzip
  max_message_bytes: 1000000
~~~


### To create kafka clustser
1. Shutdown kafka and zookeeper
 - `sudo systemctl stop kafka zookeeper`

1. clean up old kafka data and zookeeper data
 - `sudo rm -rf  /var/lib/zookeeper/version-2/`
 - `sudo rm -rf  /data/kafka/*`
1. create `myid` file and type any number to set the id
  - `sudo vim /var/lib/zookeeper/myid`
1. add the following to the bottom of the `/etc/zookeeper/zoo.cfg`
    ~~~
    server.1=172.16.10.100:2182:2183
    server.2=172.16.20.100:2182:2183
    server.3=172.16.30.100:2182:2183
    server.4=172.16.40.100:2182:2183
    server.5=172.16.50.100:2182:2183
    server.6=172.16.60.100:2182:2183
    server.7=172.16.70.100:2182:2183
    ~~~

1. change firewall rules
    - `sudo firewall-cmd --add-port=2182/tcp --permanent`
    - `sudo firewall-cmd --add-port=2183/tcp --permanent`

1. change `/etc/kafka/server.properties`
    - add the cluster IPs to `zookeeper.connect=`

    ~~~
zookeeper.connect=172.16.10.100:2181,172.16.20.100:2181,172.16.30.100:2181,172.16.40.100:2181,172.16.50.100:2181,172.16.60.100:2181,172.16.70.100:2181
    ~~~

## Kafka testing
- `sudo /usr/share/kafka/bin/kafka-topics.sh --bootstrap-server 172.16.30.100:9092 --list`
- `sudo /usr/share/kafka/bin/kafka-console-consumer.sh --bootstrap-server 172.16.30.100:9092 --topic zeek-raw`
- `sudo /usr/share/kafka/bin/kafka-console-consumer.sh --bootstrap-server 172.16.30.100:9092 --topic suricata-raw`

# Logstash
1. install Logstash
  - `sudo yum install logstash -y`
1. modify the `/etc/logstash/startup.options` file
  - un-comment the `JAVACMD=/usr/bin/java` line to allow logstash to use the previously installed java that was installed with kafka.
1. modify HEAP settings in `/etc/logstash/jvm.options`
  - under JVM Configuration header change `-Xms1g` and `-Xmx1g` to a value larger than `1g` based on your production hardware.  Make both values equal to each other.
1. Create file to Filter

  ~~~
sudo /usr/share/kafka/bin/kafka-console-consumer.sh --bootstrap-server 172.16.1.100:9092 --topic zeek-raw --from-begining | grep http > my-http.json
  ~~~

1. create `/etc/logstash/conf.d/000-input.conf` file
  ~~~
######################
### 000-input.conf ###
######################
input {
    file {
        path => "/etc/logstash/conf.d/my-http.json"
        add_field => { "[@metadata][tags]" => "zeek-http" }
        start_position => "beginning"
        sincedb_path => "/dev/null"
    }
}
  ~~~

1. create `/etc/logstash/conf.d/999-output.conf` file
  ~~~
#######################
### 999-output.conf ###
#######################
output{

 stdout {}

 }
 ~~~

1. create `/etc/logstash/conf.d/200-filter.conf` file

  ~~~
#######################
### 200-filter.conf ###
#######################
filter {

  if "zeek-http" in [@metadata][tags] {

    mutate {

      rename => {
                "[id_orig_h]" => "[source][address]"
                "[id_orig_p]" => "[source][port]"
                "[id_resp_h]" => "[destination][address]"
                "[id_resp_p]" => "[source][port]"
                "[status_code]" => "[http][response][status_code]"
                "[version]" => "[http][version]"

                }
           }
                                      }
       }
  ~~~


1. run the following command to filter the my-http.json file
- `sudo /usr/share/logstash/bin/logstash  --path.settings /etc/logstash`

1. stop Logstash
- `sudo systemctl stop logstash`

1. navigate to `conf.d` folder
  - `cd /etc/logstash/conf.d`

1. remove all files in `/conf.d/` folder
  - `ls`
  - `sudo rm *`
  - to verify:
    - `ls`

1. download logstash.tar.gz from class repo
- `cd /etc/logstash/`
- `sudo curl -L -O http://192.168.2.11:8009/logstash.tar.gz`
- extract the file:
  - `sudo tar xvzf logstash.tar.gz`
- validate that the new files are in the `conf.d` folder  
  - `ls conf.d`
- once it's validated that the new files are in that folder, you can delete the tarball.
  - `sudo rm logstash.tar.gz`

1. navigate to `conf.d` folder
  - `cd /etc/logstash/conf.d`

1. remove fsf Files
  - `ls *fsf*`
  - `sudo rm -rf *fsf*`
  - to verify:
    - `ls *fsf*`

1. verify/change settings in `/etc/logstash/conf.d/logstash-100-input-kafka-suricata.conf`
- `sudo vim logstash-100-input-kafka-suricata.conf`
- check topic is correct. e.g. suricata-raw
- change `bootstrap_servers => "127.0.0.1:9092"` to `bootstrap_servers => "172.16.30.100:9092"`

1. verify/change settings in `logstash-100-input-kafka-zeek.conf`
- `sudo vim logstash-100-input-kafka-zeek.conf`
- check topic is correct e.g. zeek-raw
- change `bootstrap_servers => "127.0.0.1:9092"` to `bootstrap_servers => "172.16.30.100:9092"`

1. verify/change settings in `/etc/logstash/conf.d/logstash-9999-output-elasticsearch.conf`
  - `sudo vim logstash-9999-output-elasticsearch.conf`
  - comment out `stdout { codec => json }`
  - change all `hosts => [ "127.0.0.1" ]` to `hosts => [ "172.16.30.100" ]`
    - press `ESC` then `:` and type `:%s/127.0.0.1/172.16.30.100/g`

1. Check logstash config for errors
- `sudo /usr/share/logstash/bin/logstash -t -f /etc/logstash/conf.d/ --path.settings=/etc/logstash`

1. start Logstash
  - `sudo systemctl start logstash`

# Elasticsearch

sudo chown elasticsearch:elasticsearch /data/elasticsearch
sudo chmod 755 /data/elasticsearch

sudo vim /etc/elasticsearch/elasticsearch.yml

- un-comment `#cluster.name: my-application` and change to `cluster.name: sg03`
- un-comment `#node.name: node-1` and change to `node.name: node-sg03`
- change `path.data: /var/lib/elasticsearch` to `path.data: /data/elasticsearch`
- un-comment `#bootstrap.memory_lock: true`
- un-comment `#network.host: 192.168.0.1` and change to `network.host: 172.16.30.100`
- add line `discovery.type: single-node` to the bottome of the `discovery` section

[see Elasticsearch Files/elasticsearch.yml]

1. create directory
- `sudo mkdir /etc/systemd/system/elasticsearch.service.d`
- `sudo chmod 755 /etc/systemd/system/elasticsearch.service.d`

1. Create `/etc/systemd/system/elasticsearch.service.d/override.conf` files
- `sudo vim /etc/systemd/system/elasticsearch.service.d/override.conf`
- add the following to `override.conf`

~~~
[Service]
LimitMEMLOCK=infinity
~~~

- `sudo chmod 644 /etc/systemd/system/elasticsearch.service.d/override.conf`  

1. open `/etc/elasticsearch/jvm.options` file
- `sudo vim /etc/elasticsearch/jvm.options`
- change `-Xms1g` to `-Xms4g`
- change `-Xmx1g` to `-Xmx4g`

1. Change firewall Settings and reload
- `sudo firewall-cmd --add-port={9200,9300}/tcp --permanent`
- `sudo firewall-cmd --reload`
- to verfiy firewall Settings
  - `sudo firewall-cmd --list-all`

1. Start Elasticsearch
- `sudo systemctl start elasticsearch`  

# Kibana
- Note: Kibana stores all the vizualizations/dashboards/canvas' to elasticsearch.  If you delete the data in elasticsearch you will lose your Kibana vizualizations/dashboards/canvas'.

1. Install Kibana
- `sudo yum install kibana -y`

2. create `/etc/kibana/kibana.yml` file
- `sudo vim /etc/kibana/kibana.yml`
- un-comment and change `#server.host: "localhost"` to `server.host: "172.16.30.100"`
- un-comment and change `#server.name: "your-hostname"` to `#server.name: "sg03"`
- un-comment and change `#elasticsearch.hosts: ["http://localhost:9200"]` to `#elasticsearch.hosts: ["http://172.16.30.100:9200"]`

3. Change firewall settings to allow port 5601 for Kibana to function
  - `sudo firewall-cmd --add-port=5601/tcp --permanent`
  - `sudo firewall-cmd --reload`
  - to verfiy firewall Settings
    - `sudo firewall-cmd --list-all`

4. Start kibana and verify is is working
  - `sudo systemctl start kibana`
  - `sudo systemctl status kibana`

5. Go to Kibana on browser
- open browser and type `http://172.16.30.100:5601/`
- disable kibana telemetry
  -  go to `http://172.16.30.100:5601/app/management/kibana/settings`
  - type `"telemetry"` in the search bar
  - toggle `telemetry` to `off`
- go to DEV Tools tab
  - type `GET _cat/indices` and click on the `"play"` button
  - you should have indices for `suricata-raw` and `zeek-raw`

---

- `curl -L -O http://192.168.2.11:8009/ecskibana.tar.gz`
- `tar xzvf esckibana.tar.gz`

modify `/ecs-configuration/elasticsearch/default.json`
- `sudo vim /ecs-configuration/elasticsearch/default.json`
 - change `"order": 0,` to `"order": 5,`

 sudo
