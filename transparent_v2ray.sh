#!/bin/bash

FILE_CONFIG="/etc/transparent-v2ray/config.json"
FILE_V2RAY_GEOIP="/usr/local/bin/geoip.dat"
FILE_V2RAY_GEOSITE="/usr/local/bin/geosite.dat"

# https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/lancidr.txt
readonly IPV4_RESERVED_IPADDRS=(
    0.0.0.0/8
    10.0.0.0/8
    100.64.0.0/10
    127.0.0.0/8
    169.254.0.0/16
    172.16.0.0/12
    192.0.0.0/24
    192.0.2.0/24
    192.88.99.0/24
    192.168.0.0/16
    198.18.0.0/15
    198.51.100.0/24
    203.0.113.0/24
    224.0.0.0/4
    240.0.0.0/4
    255.255.255.255/32
)

readonly IPV4_LOCAL_IPADDS=(
)

log_debug() {
    if [ "$DEBUG" == "1" ]; then
        echo -e "[DEBUG] $@"
    fi
}

log_info() {
    echo -e "[INFO] $@"
}

log_error() {
    echo -e "[ERROR] $@"
    exit 1
}

is_ipv4_address() {
    [ $(grep -Ec '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' <<<"$1") -ne 0 ]
}

is_cmd_exists() {
    which $1 > /dev/null
    return $?
}

is_file_exists() {
    if [ "$1" == "" ]; then
        log_error "MUST SPECIAL FILE: $2"
    elif [ ! -f "$1" ]; then
        log_error "$1: not exists"
    fi
}

check_dependencies() {
    readonly dependencies=(
        nslookup
        jq
        wget
        sysctl
        iptables
    )

    for cmd in ${dependencies[*]}
    do
        is_cmd_exists $cmd || log_error "Not found command: $cmd"
    done
}

update_v2ray_geodb() {
    echo "Start update geodb"
    wget https://github.com/v2ray/geoip/raw/release/geoip.dat -O /tmp/geoip.dat || log_error "failed to download geoip"
    cp -f /tmp/geoip.dat $FILE_V2RAY_GEOIP

    wget https://github.com/v2fly/domain-list-community/raw/release/dlc.dat -O /tmp/geosite.dat || log_error "failed to download geosite"
    cp -f /tmp/geosite.dat  $FILE_V2RAY_GEOSITE
}

reroute_ip_list() {
    # skip server ip
    tmp_list=(${SERVER_IP//./ })
    if [[ ${tmp_list[0]} = "127" ]]; then
        log_info "Skipping local address: $SERVER_IP"
    else
        iptables -t $1 -A $2 -d $SERVER_IP -j RETURN
    fi

    # skip local ip list
    for loc_ip in ${IPV4_RESERVED_IPADDRS[*]}
    do
        iptables -t $1 -A $2 -d $loc_ip -j RETURN
    done

    # skip local ip list
    for loc_ip in ${IPV4_LOCAL_IPADDRS[*]}
    do
        #直连局域网，避免 V2Ray 无法启动时无法连网关的 SSH，如果你配置的是其他网段（如 10.x.x.x 等）
        iptables -t $1 -A $2 -d $loc_ip -p tcp -j RETURN
        # 直连局域网，53 端口除外（因为要使用 V2Ray 的
        iptables -t $1 -A $2 -d $loc_ip -p udp ! --dport 53 -j RETURN
    done
}

start_transparent_proxy() {
    sysctl -w "net.ipv4.ip_forward=1" > /dev/null

    eval "$PROXY_START" || log_error "start proxy failed: $?"
    
	# 设置策略路由
	ip rule add fwmark 1 table 100
	ip route add local 0.0.0.0/0 dev lo table 100
	
	# 代理局域网设备
	iptables -t mangle -N V2RAY
    reroute_ip_list "mangle" "V2RAY"
    # 给 UDP 打标记 1，转发至 $LOCAL_PORT 端口
	iptables -t mangle -A V2RAY -p udp -j TPROXY --on-port $LOCAL_PORT --tproxy-mark 0x1/0xff
    # 给 TCP 打标记 1，转发至 $LOCAL_PORT 端口
	iptables -t mangle -A V2RAY -p tcp -j TPROXY --on-port $LOCAL_PORT --tproxy-mark 0x1/0xff
	iptables -t mangle -A PREROUTING -j V2RAY # 应用规则
	
	# 代理网关本机
	iptables -t mangle -N V2RAY_MASK
    reroute_ip_list "mangle" "V2RAY_MASK"
    # 直连 SO_MARK 为 0xff 的流量，此规则目的是避免代理本机(网关)流量出现回环问题
	iptables -t mangle -A V2RAY_MASK -j RETURN -m mark --mark 0xff
    # 给 UDP 打标记,重路由
	iptables -t mangle -A V2RAY_MASK -p udp -j MARK --set-mark 1
    # 给 TCP 打标记，重路由
	iptables -t mangle -A V2RAY_MASK -p tcp -j MARK --set-mark 1
    # 应用规则
	iptables -t mangle -A OUTPUT -j V2RAY_MASK
}

stop_transparent_proxy() {
	parse_config

	ip route del local 0.0.0.0/0 dev lo table 100
	ip rule del fwmark 1 table 100

    iptables -t mangle -D OUTPUT -j V2RAY_MASK
    iptables -t mangle -F V2RAY_MASK
    iptables -t mangle -X V2RAY_MASK

    iptables -t mangle -D PREROUTING -j V2RAY
    iptables -t mangle -F V2RAY
    iptables -t mangle -X V2RAY

    eval "$PROXY_STOP" &>/dev/null
}

nslookup_domain() {
    IP=`nslookup $1|grep Address|awk 'END {print}'|awk -F': ' '{print $2}'`
    if [ $? != "0" ]; then
        log_error "domain nslookup failed: $1"
    fi
    echo "$IP"
}

parse_config() {
    SERVER=`jq -r ".server" $FILE_CONFIG`
    PROXY_START=`jq -r ".proxy_start" $FILE_CONFIG`
    PROXY_STOP=`jq -r ".proxy_stop" $FILE_CONFIG`
    LOCAL_PORT=`jq -r ".local_port" $FILE_CONFIG`

    log_debug "$SERVER\n$MODE\n$PROXY_START\n$PROXY_STOP\n$ENABLE_UDP"
}

check_environment() {
    check_dependencies

    is_file_exists $FILE_CONFIG "CONFIG PATH"
    #is_file_exists $FILE_GEOIP "GEOIP PATH"
    #is_file_exists $FILE_GEOSITE "GEOSITE PATH"

    if [ `id -u` != "0" ]; then
        log_error "MUST BE RUN AS ROOT"
    fi

    parse_config

    is_ipv4_address "$SERVER" && SERVER_IP="$SERVER" || SERVER_IP=$(nslookup_domain "$SERVER")
    log_info "$SERVER: $SERVER_IP"
}

case "$1" in
    start) check_environment && start_transparent_proxy;;
    stop) stop_transparent_proxy;;
    restart) stop_transparent_proxy && start_transparent_proxy;;
    update-v2ray-geodb) update_v2ray_geodb;;
    *) log_info "Unknown command: $1";;
esac
