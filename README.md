# Report – Building a Raspberry Pi Captive Portal

# Wi-Fi – IPV6/

## Ahmed Lahmer

## December 2020

## Introduction

As most of us already know, a Wi-Fi hotspot is an open wireless network that
you can use to connect to the Internet. Sometimes these are free, and other
times they require a form of payment. With a normal Wi-Fi network, you just
connect, enter your password, and you’re on the Internet. A captive portal is
one that blocks you from going straight to the Internet, and instead captures
all of your web traffic and redirects you to a web page, where you can agree
to their terms and conditions, and sometimes login and/or provide payment.
Once you’ve performed whatever action is required at the portal page, you can
then access the Internet for some length of time, it can also limit the number of
connection for a given credentials, limit bandwidth ..etc
In this project, we will be building a Raspberry Pi to actually do several of
these functions. First, we will build it to be a regular Wi-Fi access point on top
of Raspberry PI. Then we’ll show how we have implemented a simple ipv4/
portal captive including all required services and their configurations.

## 1 Hardware/Software Requirements

Before we begin, let’s cover exactly what we’ll be using for this project. If we
don’t use these exact parts, we’ll probably be fine, but we will need to make
adjustments and find some solutions along the way.

Hardware

- Raspberry Pi (any model will suffice)
- USB Mouse and Keyboard
- Monitor with HDMI input + HDMI Cable
- RJ45 cable (For the Ethernet connection)


Software

- Python3 + Pip3 (To run the captive portal)
- Radvd (Daemon for stateless ipv6)
- Dnsmasq (Lightweight DNS-caching +DHCP servers)
- Hostapd (service that turns raspberry WI-FI card into an access-point)
- Sudoer user.

## 2 Hardware/Software preparation

In order to make reproducible result of this project, we will discuss all steps
that have been taken in order to prepare raspberry PI.

### 2.1 Hardware preparation

In this section, we describe different hardware that were used in this project.

- Insert the SD memory card with Raspbian installed into the Pi.
- Connect the network cable to the Pi. Make sure it will be able to connect
    to the Internet directly without any special configuration. Technically
    speaking, the network will need to provide DHCP to the Raspberry Pi.
    If the network requires a static IP, it can be affected to ETH0 manually
    (find command in Appendix Section).
- Connect a USB keyboard to the Pi.
- Connect an HDMI cable to your monitor and the Pi. Make sure you switch
    your monitor on and to the correct input.
- Connect the power to the Pi.

### 2.2 Software preparation:

We will now describe the software-preparation side of this project. Three main
Daemons were essentially used: DNSMASQ, HOSTAPD, and RADVD.

Dnsmasq: In order to deploy a fully functioning, dynamic WLAN, we need a
DHCP server and DNS caching server. Dnsmasq is a lightweight DNS-caching
and a DHCP server, simple to configure and maintain. For our dnsmasq config-
uration (conf.1), we simply configured two DNS server to be announced to all
WIFI-clients once they join the network, all clients obtain their IPv4 address
via the DHCP server, these addresses range from 192.168.0.20 to 192.168.0.240,
with a lease time of 12 hours, and a possibility of renewing (IPV6 addresses
management is described in a later section). All these parameters and others


are available to configure via a web user-friendly interface (described in a later
section).

```
Configuration File 1: dnsmasq

#/etc/dnsmasq.conf
server=8.8.8.
server=8.8.4.
dhcp-range=192.168.0.20,192.168.0.240,12h
```

Hostapd: In order to turn Raspberry into a wireless access point, we have
used Hostap daemon to do os. It offers an access point and authentication
servers. It implements IEEE 802.11 access point management, IEEE 802.1X/WPA/WPA2/EAP
Authenticators, RADIUS client which will be later used to communicate the ra-
dius server (listening on 1812) in order to authenticate the client (conf.2).

```
Configuration File 2: hostapd
#/etc/hostapd.conf

interface=wlan
br=br
driver=nl
ctrl_interface=/var/run/hostapd

ssid=IOT-Project-WIFI
wpa_pairwise=CCMP
rsn_pairwise=CCMP
macaddr_acl=

#EAP Config 8021X
own_ip_addr=10.17.0.
ieee8021x=

auth_algs=
wpa=
wpa_key_mgmt=WPA-EAP

nas_identifier=other

#FreeRADIUS Server Config
auth_server_addr=10.17.0.
auth_server_port=
```

Radvd and IPV6 In order to support Only-ipv6 or Ipv4,6 clients without
any state in our WLAN, we have used Radv daemon that implements link-local


advertisements of IPv6 router addresses and IPv6 routing prefixes using the
Neighbor Discovery Protocol (NDP). We have configured (see conf.3) a private
routable prefix for the WLAN, and also Google dns6 servers which will be
advertised to clients once they join the WLAN.

```
Configuration File 3: radvd
#/etc/radvd.conf

interface wlan
{
AdvSendAdvert on;
MinRtrAdvInterval 3;
MaxRtrAdvInterval 10;

#Allocated private prefix for our WLAN
prefix fdff::/
{
AdvOnLink on;
AdvAutonomous on;
AdvRouterAddr off;
AdvPreferredLifetime 120;
AdvValidLifetime 300;
};

# DNS servers to be advertised
RDNSS 2001:4860:4860::8888 2001:4860:4860::
{
AdvRDNSSLifetime 30;
};

};
```


RaspAp In order to provide a user-friendly configuration pannel for our WLAN,
we have installed RaspAp daemon which provides two main functions, it pro-
vides DNS/DHCP configurations via a web interface, secondly, it provides a
graphical view of the network usage in realtime.

## 3 Captive Portal

In this section, we describe how we have implemented a simple captive portal
(code is provided in the Appendix section) as a client authentication/authorization
mechanism. Our CP provides also a web interface for authenticating users,
adding users, viewing all users, and finally viewing connected users. All authen-
tications are done via the same database used for 802.1X, it is deployed using


a simple SQLite database. Our CP is mainly based on the usage of iptables for
clients using ipv4, and ip6tables for clients using ipv6, it is based Flask-python
framework.

Process by default, all communications are allowed, once the CP server is
launched, it starts by appending some rules to reject all packets coming from
WLAN except for DNS, and of course the authentication page. Like that all
clients will be able to perform authentication properly. Once a client enters
his/her correct credentials via secured HTTP, the CP server will push a rule
which allows him/her to access the rest of the internet, by accepting all incoming
packets which have the authenticated client’s IP address. Every client can at
most have 5 connections, if a 6th connection is requested, the server will simply
close the oldest connection. The server run also a thread, whose main function
to detect when an authenticated client quit the WLAN, it periodically ping all
connect clients, if some client does not reply, it will be considered as left, if it is
the case, it will be removed from the connected client list, and authentication
is required once he reconnects.


## A Appendix

# RaspAp quick installer ->
curl -sL https://install.raspap.com | bash

#activate ipv4/ipv6 forwarding on raspberry -->
sysctl -w net.ipv4.ip_forward=
sysctl -w net.ipv4.ip_forward=

#Configure Nat between wlan0 and eth0 -->
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

#Configure ip manually -->
ip address add [IP4]/[pref] dev [INTERFACE=wlan0|eth0]
ip -6 address add [IP6]/[pref=64] dev [INTERFACE=wlan0|eth0]

# RUN CP server
pip install flask
git clone https://github.com/slahmer97/raspberry_simple_captive_portal
python3 captive_portal.py --host [ip] --port [port, default=8000]--ipv [4 | 6, default=4]


