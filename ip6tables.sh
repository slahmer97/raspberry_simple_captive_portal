#ip6tables -t nat -A POSTROUTING -o eth0 -s fdff::/64 -j MASQUERADE
ip -6 address add fdff::1/64 dev wlan0
