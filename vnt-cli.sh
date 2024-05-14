#!/bin/sh

sz="$@"

log_ () {
local loge=$1
echo -e "\033[35m`date +%F' '%X ` \033[0m" "\033[32m ${loge} \033[0m"
logger  "${loge}"
}

if [ -z "${sz}" ] ; then
log_ "去除#号可运行"
log_ "输入运行参数-k <虚拟网络名称> --ip <本地虚拟ip> -i <对端网段>/24,<对端虚拟ip> -o 0.0.0.0/0"
test ! -z `pidof vnt-cli` && killall vnt-cli
exit
fi
##vnt-cli 上无参数，退出运行


if [ -f "/etc/storage/started_script.sh" ] ; then
test -n "`ps |grep 'crond'|grep '\-d10'|grep -v grep|awk '{print $1}'`" || (killall crond && /usr/sbin/crond -d10)
fi

if [ -n "$(echo "${sz}"|grep '+p2p')" ] ; then # 系统分钟后位数
MINUTE=$(date +"%M")
LAST_DIGIT=`echo $((MINUTE % 10)) `
if  [[ "$LAST_DIGIT" = 2 ]] || [[ "$LAST_DIGIT" = 4 ]] || [[ "$LAST_DIGIT" = 6 ]] || [[ "$LAST_DIGIT" = 8 ]] || [[ "$LAST_DIGIT" = 0 ]] ; then
## 每隔2分钟执行一遍
vnt_cli_ps="`ps -w |grep vnt-cli | grep -v grep|grep -v '{' | grep -v '\['|awk '{print $5}'`"
${vnt_cli_ps} --route > /tmp/vnt_cli_route.tmp 
count=$(cat /tmp/vnt_cli_route.tmp|grep -v 'Hop' | grep -c '.')
for p in $(seq 1 $count) ; do
    n_1_2=$(cat /tmp/vnt_cli_route.tmp|grep -v 'Hop' | awk 'NR=='"$p"'{print $3}')
    
    if [ "${n_1_2}" = "2" ] ; then
    killall vnt-cli
    fi
done

fi
fi

if [ -n "$(echo "${sz}"|grep '\--nic ')" ] ; then
nic0=`echo ${sz}|awk -F '--nic ' '{print $2}'|awk  '{print $1}'`
nic="--nic ${nic0}"
else
nic0=vnt-tun
nic=""
fi


iptables_ () {
if [  -n "`pidof vnt-cli`" ] ; then
	test -z "`sysctl net.ipv4.ip_forward | grep 'net.ipv4.ip_forward = 1'`" && sysctl -w net.ipv4.ip_forward=1 && log_ "开启系统内核转发功能"  
## 检查是否开启了内核转发，允许外部网络中的计算机(手机、电脑、平板、监控等等)通过padavan等访问路由下的内部设备（也包含没有网关指向padavan的内部设备）
## 关闭后只访问到有指向该网关的内部设备
	if [ -f "/etc/storage/started_script.sh" ] ; then
		[ "`nvram get sw_mode`" = "3" ] && iptables -t nat -C POSTROUTING -j MASQUERADE &>/dev/null || iptables -t nat -I POSTROUTING -j MASQUERADE
## padavan固件ap模式下要开启IP伪装，允许内部网络中的计算机(手机、电脑、平板、监控等等)通过padavan等与Internet通信
		[ "`nvram get sw_mode`" = "1" ] && iptables -t nat -C POSTROUTING -j MASQUERADE &>/dev/null && iptables -t nat -D POSTROUTING -j MASQUERADE
## padavan固件拨号模式下不需要开启IP伪装
	fi
	
	iptables -t nat -C POSTROUTING -o $nic0 -j MASQUERADE &>/dev/null || iptables -t nat -A POSTROUTING -o $nic0 -j MASQUERADE
	iptables -C FORWARD -o $nic0 -j ACCEPT &>/dev/null || iptables -I FORWARD -o $nic0 -j ACCEPT
	iptables -C FORWARD -i $nic0 -j ACCEPT &>/dev/null || iptables -I FORWARD -i $nic0 -j ACCEPT
	iptables -C INPUT -i $nic0 -j ACCEPT &>/dev/null || iptables -I INPUT -i $nic0 -j ACCEPT
	if [ -n "$(echo "${sz}"|grep '\--tcp ')" ] ; then
	vnt_cli_tcp="echo `netstat -ap | grep vnt-cli | grep tcp |awk -F ':::' '{print $2}'|awk  '{print $1}'`"
	iptables -C INPUT -p tcp --dport $vnt_cli_tcp -j ACCEPT &>/dev/null || iptables -C INPUT -p tcp --dport $vnt_cli_tcp -j ACCEPT
	ip6tables -C INPUT -p tcp --dport $vnt_cli_tcp -j ACCEPT &>/dev/null || ip6tables -C INPUT -p tcp --dport $vnt_cli_tcp -j ACCEPT	
	fi

## 检查是否开放对应的端口
fi
}

iptables_

:<<'COMMENT'
if [ -z "$(echo "${sz}"|grep \+s )" ] ; then
## 判断参数中是否无“+s”
s=""
else
	ip4p=`echo "${sz}"|awk -v RS='+'  '{print $0}'|grep 's'|grep -v 'k' |awk '{print $2}'`
# 将参数中的“+”断点进行分行，查找有“s”的行，并排除“k”的行，打印第二列
	eval $(nslookup ${ip4p} 119.29.29.29 | awk '/2001/' |cut -d ':' -f 2-6 | awk -F: '{print "port="$3" ipa="$4" ipb="$5 }')
# 查询域名，并提取出ip4p地址
	port=$((0x$port))
	ip1=$((0x${ipa:0:2}))
	ip2=$((0x${ipa:2:2}))
	ip3=$((0x${ipb:0:2}))
	ip4=$((0x${ipb:2:2}))
	ipv4="${ip1}.${ip2}.${ip3}.${ip4}:${port}"
	lastIP="$(cat /tmp/natmat-vnts-ip4p.txt)"
	#检查ip是否变动
		if [ "$lastIP" != "$ipv4" ] ; then
		killall vnt-cli
		echo ${ip1}.${ip2}.${ip3}.${ip4}:${port} >/tmp/natmat-vnts-ip4p.txt
		ip="${ip1}.${ip2}.${ip3}.${ip4}:${port}"
		fi
	s="-s ${ipv4}"
fi
COMMENT

nslookup_ () {
	nslookup=nslookup
	[ -f "/etc/storage/started_script.sh" ] && { # 判断是否为padavan固件
	[ ! -f "/tmp/nslookup" ] &&  curl  --connect-timeout 3 -#Lko "/tmp/nslookup" http://webd.liaoh.dedyn.io:19213/nslookup_mipsel #不存在nslookup就下载(不支持AAAA记录)
	[ ! -x "/tmp/nslookup" ] && chmod +x "/tmp/nslookup" # 赋予执行权限
	nslookup="/tmp/nslookup"
	}
}

if [ -n "$(echo "${sz}"|grep '+s ')" ] ; then

	ddns=`echo "${sz}"|awk -v RS='+'  '{print $0}'|grep 's'|grep -v 'k' |awk '{print $2}'`
	if [ ! -n "`echo $ddns | grep ':'`" ] && [ ! -z "$ddns" ] ;then

	addr=$(nslookup ${ddns} 119.29.29.29 | grep -o -i  "2001::[0-9a-fA-F:]\+" ) ; [  "$addr" == "" ]  && \
	addr=$(curl -k -s "https://ipw.cn/api/dns/${ddns}/AAAA/all" |  grep -o -i  "2001::[0-9a-fA-F:]\+" | tail -n 1 )   && [  "$addr" = "" ]  # && \
#	addr=$(curl -k -s 'https://myssl.com/api/v1/tools/dns_query?qtype=28&host=${ddns}&qmode=-1'|grep -o -i "2001::[0-9a-fA-F:]\+" | tail -n 1 ) && [  "$addr" == "" ] && \
#	addr=$(curl -k -s "https://mxtoolbox.com/api/v1/Lookup?command=aaaa&argument=${ddns}&resultIndex=1&disableRhsbl=true&format=2"  \
#  -H "tempauthorization: $(curl -s -k 'https://mxtoolbox.com/api/v1/user'|awk '/TempAuthKey/'|awk -F '"' '{print $4}')" | grep -oE '[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){0,7}::[a-f0-9]{0,4}(:[a-f0-9]{1,4}){0,7}' | grep ^2001:: | head -n 1)
	
##	查询域名，并提取出ip4p地址

		if [ ! -z "$(echo "$addr" | grep -o -i  "2001::[0-9a-fA-F:]\+")" ] ; then
			eval $(echo "$addr" | awk '/2001/'|cut -d ':' -f 1-6 | awk -F ':' '{print "port="$3" ipa="$4" ipb="$5 }')
			port=$((0x$port))
			ip1=$((0x${ipa:0:2}))
			ip2=$((0x${ipa:2:2}))
			ip3=$((0x${ipb:0:2}))
			ip4=$((0x${ipb:2:2}))
			ipv4="${ip1}.${ip2}.${ip3}.${ip4}:${port}"
			[ -f "/tmp/natmap_vnts_addr.txt" ] && lastIP="$(tail -n 1 /tmp/natmap_vnts_addr.txt|awk '{print $4}')" || lastIP="" # 检查ip是否变动
			if [ "$lastIP" != "$ipv4" ] ; then
				killall vnt-cli
				echo "$(date "+%G-%m-%d %H:%M:%S") ip4p更新记录: ${ip1}.${ip2}.${ip3}.${ip4}:${port}" >> /tmp/natmap_vnts_addr.txt
			fi
		else
			nslookup_
			ip_port=$($nslookup -type=txt ${ddns} 119.29.29.29 | grep 'text' | awk '{print $4}' | awk -F \" '{print $2 }') ; [ "$ip_port" == "" ] && \
			ip_port=$(curl -k -s "https://ipw.cn/api/dns/${ddns}/TXT/all" |  grep -oE '"Type":"TXT","recordValue":[^,}]*' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | tail -n 1 ) 
			if echo "$ip_port" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$' ; then
				echo "这是有效的IPv4地址:端口格式，（TXT记录）"
				ipv4="${ip_port}"
				echo "${ip_port}"
				[ -f "/tmp/natmap_vnts_addr.txt" ] && lastIP="$(tail -n 1 /tmp/natmap_vnts_addr.txt|awk '{print $4}')" || lastIP="" # 检查ip是否变动
				[ "$lastIP" != "${ip_port}" ] && {
			    	killall vnt-cli
			    	echo "$(date "+%G-%m-%d %H:%M:%S") ip4p更新记录: ${ip_port}"  >> /tmp/natmap_vnts_addr.txt
			    }
			else
				echo "不是有效的IPv4地址:端口格式，请检查下服务地址"
				echo "退出"
				exit 0
			fi
		fi
		s="-s `echo ${ipv4}` "
	else
		s="-s `echo ${ddns}` "
	fi

fi

##增加了支持ip4p地址

if [ -n "$(echo "${sz}"|grep '+t ')" ] ; then

	ddns=`echo "${sz}"|awk -v RS='+'  '{print $0}'|grep 't' | grep -v 'k' |awk '{print $2}'`

	if [ ! -n "`echo $ddns | grep ':'`" ] && [ ! -z "$ddns" ] ;then
		nslookup_
		ip_port=$($nslookup -type=txt ${ddns} 119.29.29.29 | awk '/text/' | awk '{print $4}' | awk -F \" '{print $2 }') ; [ "$ip_port" == "" ] && \
		ip_port=$(curl -k -s "https://ipw.cn/api/dns/${ddns}/TXT/all" |  grep -oE '"Type":"TXT","recordValue":[^,}]*' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | tail -n 1 ) 
			if echo "$ip_port" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$' ; then
				echo "这是有效的IPv4地址:端口格式，（TXT记录）"
				ipv4="${ip_port}"
				echo "${ip_port}"
				[ -f "/tmp/natmap_vnts_addr.txt" ] && lastIP="$(tail -n 1 /tmp/natmap_vnts_addr.txt|awk '{print $4}')" || lastIP="" # 检查ip是否变动
				[ "$lastIP" != "${ip_port}" ] && {
			    	killall vnt-cli
			    	echo "$(date "+%G-%m-%d %H:%M:%S") ip4p更新记录: ${ip_port}"  >> /tmp/natmap_vnts_addr.txt
			    }
			fi
		s="-s `echo ${ipv4}`"
	else
		s="-s `echo ${ddns}`"
	fi

fi

##增加了支持ipv4地址text记录

test -f "/tmp/vnt_tmp" && vnt_tmp2=$(tail -n 1 "/tmp/vnt_tmp") || vnt_tmp2="::"
if [ "${sz}" == "${vnt_tmp2}" ] && [ ! -z `pidof vnt-cli` ]  ; then
exit
fi
##参数相同并在运行中，退出运行

echo "${sz}" >> /tmp/vnt_tmp
##将参数记录到临时文件中

SCRIPT_DIR="$(cd $(dirname $0); pwd)"
echo "脚本所在目录: $SCRIPT_DIR"


if [ -f "${SCRIPT_DIR}/vnt_cli_set_dir.txt" ] && [ -f "$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)/vnt-cli" ] ; then
	vnt="$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)/vnt-cli"
elif [ -f "/tmp/vnt-cli" ] ; then  
	vnt="/tmp/vnt-cli"
elif [ -f "/etc/storage/vnt-cli" ] ; then
	vnt="/etc/storage/vnt-cli"
elif [ -f "/etc/storage/bin/vnt-cli" ] ; then
	vnt="/etc/storage/bin/vnt-cli"
elif [ -f "/etc/vnt-cli" ] ; then
	vnt="/etc/vnt-cli"
elif [ -f "/usr/bin/vnt-cli" ] ; then
	vnt="/usr/bin/vnt-cli"
elif [ -f "/jffs/vnt-cli" ] ; then
	vnt="/jffs/vnt-cli"
else
	vnt=""
	##上述目录都不存在vnt-cli
fi
## 查找vnt-cli文件
test ! -x "${vnt}" && chmod +x "${vnt}"



:<<'COMMENT'

if [ -f "${SCRIPT_DIR}/vnt_cli_set_dir.txt" ] && [ -f "$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)/vnt-cli" ] ; then
	vnt="$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)/vnt-cli"
	 [ ! -x "${vnt}" ] && chmod +x "${vnt}"

if	 [ 3 -gt $(($(${vnt} -h | wc -l))) ] ;then 
 mv "$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)/vnt-cli" "$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)/vnt0-cli" 
vnt="" 
fi
# 检查是否可运行，否则重名，下一步去下载
else
	vnt_path="/tmp /etc /usr /etc/storage"   # 设定多个路径

	for v in ${vnt_path}
	do
		echo "在目录$v查找"
		vnt_cli_tmp=$(find "$v" -type f -name "vnt-cli" )
		yes1=$?
		if [[ ${yes1} = 0 ]] ; then # 判断是否有vnt-cli ，有为0，没有为其他数字
			vnt_cli_psc=$(echo "${vnt_cli_tmp}" | wc -l) # 统计有多少个vnt-cli
			echo "$v目录中有${vnt_cli_psc}个文件（vnt-cli）" 
			for y in $(seq 1 $vnt_cli_psc)
			do
				vnt=$(echo "${vnt_cli_tmp}" | awk 'NR=='"$y"'{print $0}') # 第y行的vnt_cli文件
				[ ! -x "${vnt}" ] && chmod +x "${vnt}" # 判断vnt-cli是否有执行权限
				if [ $(($(${vnt} -h | wc -l))) -gt 3 ]; then # 判断vnt-cli是否可正常运行
					yes=$?
					echo "正常运行" 
					break # 跳出y循环
				fi
			done

			if [[ ${yes1} = 0 ]] &&  [[ ${yes} = 0 ]] ; then
				break  # 跳出v循环
			fi
		fi
	done

fi
echo "${vnt}"

COMMENT


if [ "${vnt}" = "" ] ; then

cputype=$(uname -ms | tr ' ' '_' | tr '[A-Z]' '[a-z]')
[ -n "$(echo $cputype | grep -E "linux.*armv.*")" ] && cpucore="arm"
[ -n "$(echo $cputype | grep -E "linux.*armv.*"| grep ddwrt )" ] && cpucore="ddwrt-arm"
[ -n "$(echo $cputype | grep -E "linux.*armv7.*")" ] && [ -n "$(cat /proc/cpuinfo | grep vfp)" ] && [ ! -d /jffs/clash ] && cpucore="armv7"
[ -n "$(echo $cputype | grep -E "linux.*aarch64.*|linux.*armv8.*")" ] && cpucore="aarch64"
[ -n "$(echo $cputype | grep -E "linux.*86.*")" ] && cpucore="i386"
[ -n "$(echo $cputype | grep -E "linux.*86_64.*")" ] && cpucore="x86_64" 

if [ -n "$(echo $cputype | grep -E "linux.*mips.*")" ] ; then
mipstype=$(echo -n I | hexdump -o 2>/dev/null | awk '{ print substr($2,6,1); exit}') ##通过判断大小端判断mips或mipsle
[ "$mipstype" = "0" ] && cpucore="mips" || cpucore="mipsel"
fi
##判断CPU框架
:<<'!'
[ "$cputype" = "mips" ] && eabi=""
[ "$cputype" = "mipsel" ] && eabi=""
[ "$cpucore" = "ddwrt-arm" ] && eabi="_cortex-a9"
[ "$cputype" = "amd64" ] && eabi="eabihf"
[ "$cpucore" = "armv7" ] && ( [ -n "$(cat /proc/cpuinfo | grep fpu)" ] &&  eabi="eabihf" || eabi="eabi" )
[ "$cpucore" = "arm" ] && ( [ -n "$(cat /proc/cpuinfo | grep fpu)" ] &&  eabi="eabihf" || eabi="eabi" )
!

ip4p_translation_ipv4 () {
local ip4p=$1  # 使用传递进来的变量
	eval $(nslookup ${ip4p} 119.29.29.29 | awk '/2001/'|cut -d ':' -f 2-6 | awk -F: '{print "port="$3" ipa="$4" ipb="$5 }') # 查询域名，并提取出ip4p地址
	port=$((0x$port))
	ip1=$((0x${ipa:0:2}))
	ip2=$((0x${ipa:2:2}))
	ip3=$((0x${ipb:0:2}))
	ip4=$((0x${ipb:2:2}))
	echo "${ip1}.${ip2}.${ip3}.${ip4}:${port}"
}


vnt="/tmp/vnt-cli"


https="
http://$(ip4p_translation_ipv4 liaohc-webd.dns.army )/vnt-cli_${cpucore}
http://$(curl -k -s 'https://ipw.cn/api/dns/webd-t.liaoh.dedyn.io/TXT/all' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | tail -n 1)/vnt-cli_${cpucore}
http://webd.liaoh.dedyn.io:19213/vnt-cli_${cpucore}
"

http_download (){
local tmp=$1
curl="curl --connect-timeout 3 -#Lko "
	for http in $https
	do
#		echo -e "\n尝试使用加速镜像 $SKYBLUE$MIRROR$RESET 下载"
		$curl "$tmp" "$http"
		if [ "$?" = 0 ];then
			if [ $(wc -c < $1) -lt 1024 ];then
				rm -f $tmp
				echo -e "下载文件错误！即将尝试使用下一个网址进行下载 ······" && sleep 2
			else
				url="$http" && break
			fi
		else
			rm -f $tmp
		fi
	done
	[ -f ${vnt} ] && return 0 || return 1
}

http_download "${vnt}"
##下载对应的执行文件



test ! -x "${vnt}" && chmod +x "${vnt}"
 [ $(($(${vnt} -h | wc -l))) -gt 3 ] || rm -rf "${vnt}"
##判断执行文件是否可运行,否则删除


	if [ -f "${SCRIPT_DIR}/vnt_cli_set_dir.txt" ] && [ -d "$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)" ] ; then
		cp "${vnt}" "$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)"
	vnt="$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)/vnt-cli"
	else
	
		if [ -d "/jffs" ] ; then # 华硕固件
			size=`df -k |awk '/\/jffs$/{sub(/K$/,"",$4);print $4}'|tr -d '.'|tr -d 'M'`
			test "${size}" -gt 1000 && cp "${vnt}" /jffs
			
		elif [ -f "/data/etc/crontabs/root" ] ; then # 小米原厂固件
			size=`df -k |awk '/\/overlay$/{sub(/K$/,"",$4);print $4}'`
			test "${size}" -gt 1000 && cp "${vnt}" /data/etc
			
		elif [ -f "/etc/storage/started_script.sh" ] ; then  # 老毛子固件
			size=`df -k |awk '/\/etc$/{sub(/K$/,"",$4);print $4}'|tr -d '.'|tr -d 'M'`
#			test "${size}" -gt 10 && cp "${vnt}" /etc/storage
			
		else ##判断系统是否为openwrt，若是并空间大于1000时就把vnt-cli文件复制到etc目录中
			size=`df -k |awk '/\/overlay$/{sub(/K$/,"",$4);print $4}'`
			test "${size}" -gt 1000 && cp "${vnt}" /etc/
		fi
	fi
fi


test ! -z "`uname -a | tr [A-Z] [a-z]|grep -o wrt`" &&  test -z "`opkg list-installed|grep kmod-tun`" && opkg update && opkg install kmod-tun
## 判断openwrt有无安装tun模块，无就进行安装
test ! -x "${vnt}" && chmod +x "${vnt}"
## 判断文件有无执行权限，无赋予运行权限

if [ -n "$(echo "${sz}"|grep '\-n ')" ] ; then
	n="" # 如果用户用自定义名称就不写
else # 如果用户用不自定义名称，则自动命名

	if [ -n "$(echo $(uname -ms | tr ' ' '_' | tr '[A-Z]' '[a-z]') | grep -E "linux.*mips.*")" ] ; then
		mipstype=$(echo -n I | hexdump -o 2>/dev/null | awk '{ print substr($2,6,1); exit}') ##通过判断大小端判断mips或mipsle
		[ "$mipstype" = "0" ] && n1="-n `uname -ns|tr [\ ] [_]`_mips" || n1="-n `uname -ns|tr [\ ] [_]`_mipsel"
	else
		n1="-n `uname -nms|tr [\ ] [_]`" #设备名称
	fi

n="${n1}"
fi
## 判断设备名称

if [ -n "$(echo "${sz}"|grep '\-d ')" ] ; then
d=""
else
#d1="-d `echo "${sz}"|awk -v RS='-'  '{print $0}'|grep ip |awk '{print $2}'|awk -F'.' '{print $4}'`"
d1="-d `echo "${sz}"|awk -v RS='-'  '{print $0}'|grep ip |awk '{print $2}'|tr [.] [_]`"
d="${d1}"
fi
## 判断参数上有无-d,无则用ip最后数字


[  -n "`pidof vnt-cli`" ] && "${vnt}" --stop && killall vnt-cli
## 先退出旧运行参数的进程
sleep 1

[ ! -d "/tmp/log/" ] &&  mkdir "/tmp/log/"

log4rs_yaml_dir=$(dirname "${vnt}") # 返回执行文件所在的目录
if [ ! -f "${log4rs_yaml_dir}/log4rs.yaml" ] ; then
cat <<'EOF'> "${log4rs_yaml_dir}/log4rs.yaml"
refresh_rate: 30 seconds
appenders:
  rolling_file:
    kind: rolling_file
    path: /tmp/log/vnt-cli.log
    append: true
    encoder:
      pattern: "{d(%Y-%m-%d %H:%M:%S )} [{f}:{L}] {h({l})} {M}:{m}{n}"
   
    policy:
      kind: compound
      trigger:
        kind: size
        limit: 1 mb
      roller:
        kind: fixed_window
        pattern: /tmp/log/vnt-cli.{}.log
        base: 1
        count: 5

root:
  level: info
  appenders:
    - rolling_file
EOF
log_ "开启了日志"
log_ "生成的日志文件在/tmp/log目录中"
fi

echo "${log4rs_yaml_dir}/vnt-cli" > /tmp/vnt_cli_dir


#log4rs_yaml_dir="/etc"
env_ () { 
 [ -d "/tmp/env" ] || mkdir "/tmp/env"
 [ "${log4rs_yaml_dir}" = "/tmp" ] || {
  [ -h "${log4rs_yaml_dir}/env" ] || ( rm -rf "${log4rs_yaml_dir}/env" ; ln -s "/tmp/env" "${log4rs_yaml_dir}/env" )
  }
}

env_

cd ${log4rs_yaml_dir} && ./vnt-cli $@ ${d} ${n} ${s} ${nic} >/tmp/vnt_cli.txt 2>&1  &
# "${vnt}" $@ ${d} ${n} ${s} >/tmp/vnt_cli.txt 2>&1  &
## 这是个脚本的核心
sleep 1

echo  -n "$(date +%s)" > /tmp/start_timestamp_vnt_cli

iptables_

[  -z `pidof vnt-cli` ] && log_ "运行失败" || log_ "${vnt} ${d} ${sz} ${n} ${s} ${nic} --no-proxy & 运行成功"

