#!/bin/sh

#sz="-k <虚拟网络名称> --ip <虚拟ip> -i <对端网段>/24,<对端虚拟ip> -o 0.0.0.0/0 --no-proxy"

sz="$@"

log_ () {
local loge=$1
echo -e "\033[35m`date +%F' '%X ` \033[0m" "\033[32m ${loge} \033[0m"
logger  "${loge}"
}


[ -n "$(echo "${sz}"|grep '\--nic ')" ] && {
nic0=`echo ${sz}|awk -F '--nic ' '{print $2}'|awk  '{print $1}'`
#nic="--nic ${nic0}"
nic=""
} || {
nic0="vnt-tun"
nic="--nic vnt-tun"
}

pidof_ (){

[ -n "$(echo "${sz}"|grep '\--nic ')" ] && {
ps -w | grep vnt-cli | grep "\--nic $nic0" | grep -v "vnt-cli\.sh" |grep -v grep |awk '{print $1}'
} || {
ps -w | grep vnt-cli | grep "\--nic vnt-tun" | grep -v "vnt-cli\.sh" |grep -v grep |awk '{print $1}'
}

}

[ -f "/etc/storage/started_script.sh" ] && {
[ -n "`ps |grep 'crond'|grep '\-d10'|grep -v grep|awk '{print $1}'`" ] || (killall crond && /usr/sbin/crond -d10)
}



[ -z "${sz}" ] && {
log_ "去除#号可运行"
log_ "输入运行参数--nic <自定义网卡> -k <虚拟网络名称> --ip <本地虚拟ip> -i <对端网段>/24,<对端虚拟ip> -o 0.0.0.0/0"
[ -n "$(pidof_)" ] && killall "$(pidof_)"
exit 0
}
# vnt-cli 上无参数，退出运行

[ "$1" = "0" ] && {

[ -n "$(pidof_)" ] && kill "$(pidof_)"
[ -n "$(pidof_)" ] && log_ "杀掉$(pidof_)进程"

exit 0

}


iptables_ () {

if [  -n "`pidof vnt-cli`" ] ; then
	test -z "`sysctl net.ipv4.ip_forward | grep 'net.ipv4.ip_forward = 1'`" && sysctl -w net.ipv4.ip_forward=1 && log_ "开启系统内核转发功能"  
# 检查是否开启了内核转发，允许外部网络中的计算机(手机、电脑、平板、监控等等)通过padavan等访问路由下的内部设备（也包含没有网关指向padavan的内部设备）

# 关闭后只访问到有指向该网关的内部设备
	if [ -f "/etc/storage/started_script.sh" ] ; then
		[ "`nvram get sw_mode`" = "3" ] && iptables -t nat -C POSTROUTING -j MASQUERADE &>/dev/null || iptables -t nat -I POSTROUTING -j MASQUERADE
# padavan固件ap模式下要开启IP伪装，允许内部网络中的计算机(手机、电脑、平板、监控等等)通过padavan等与Internet通信
		[ "`nvram get sw_mode`" = "1" ] && iptables -t nat -C POSTROUTING -j MASQUERADE &>/dev/null && iptables -t nat -D POSTROUTING -j MASQUERADE
# padavan固件拨号模式下不需要开启IP伪装
	fi
	if [ -f "`which nft`" ] ; then
	nft_list="$(nft list ruleset)"
	echo "$nft_list" | grep "$nic0" >/dev/null || {
	 
	nft add table inet vnt_table 
	nft add chain inet vnt_table forward { type filter hook forward priority 0\; } >/dev/null
		nft insert rule inet vnt_table forward oifname "$nic0" accept
		nft insert rule inet vnt_table forward iifname "$nic0" accept
		
	nft add chain inet vnt_table INPUT { type filter hook input priority filter \; policy accept \; } >/dev/null
		nft insert rule inet vnt_table INPUT iifname "$nic0" accept
		
	nft add table ip vnt_nat
	nft add chain ip vnt_nat postrouting { type nat hook postrouting priority 100 \; } >/dev/null
		nft insert rule ip vnt_nat postrouting oifname != "$nic0"  masquerade

	}
	
	if [ -n "$(echo "${sz}"|grep '\--tcp ')" ] ; then
		vnt_cli_tcp="echo `netstat -ap | grep vnt-cli | grep tcp |awk -F ':::' '{print $2}'|awk  '{print $1}'`"
		echo "$nft_list" | grep "tcp dport ${vnt_cli_tcp}}" >/dev/null || {
		nft add rule inet vnt_table INPUT tcp dport ${vnt_cli_tcp} accept
	}
	fi
	
# 要删除整个规则集，请使用 nft flush ruleset 命令

	else
		if [ -f "/etc/storage/started_script.sh" ] ; then 
			iptables -t nat -C POSTROUTING ! -o $nic0 -j MASQUERADE &>/dev/null || iptables -t nat -A POSTROUTING ! -o $nic0 -j MASQUERADE
		else
			iptables -t nat -C POSTROUTING -o $nic0 -j MASQUERADE &>/dev/null || iptables -t nat -A POSTROUTING -o $nic0 -j MASQUERADE
		fi
		
		iptables -C FORWARD -o $nic0 -j ACCEPT &>/dev/null || iptables -I FORWARD -o $nic0 -j ACCEPT
		iptables -C FORWARD -i $nic0 -j ACCEPT &>/dev/null || iptables -I FORWARD -i $nic0 -j ACCEPT
		iptables -C INPUT -i $nic0 -j ACCEPT &>/dev/null || iptables -I INPUT -i $nic0 -j ACCEPT
	if [ -n "$(echo "${sz}"|grep '\--tcp ')" ] ; then
		vnt_cli_tcp="echo `netstat -ap | grep vnt-cli | grep tcp |awk -F ':::' '{print $2}'|awk  '{print $1}'`"
		iptables -C INPUT -p tcp --dport $vnt_cli_tcp -j ACCEPT &>/dev/null || iptables -C INPUT -p tcp --dport $vnt_cli_tcp -j ACCEPT
		ip6tables -C INPUT -p tcp --dport $vnt_cli_tcp -j ACCEPT &>/dev/null || ip6tables -C INPUT -p tcp --dport $vnt_cli_tcp -j ACCEPT
	fi
	fi
# 检查是否开放对应的端口

fi

}

iptables_

if [ -n "$(echo "${sz}"|grep '+s ')" ] ; then

	natmap_addr="/tmp/natmap_vnts_${nic0}_addr.txt"
	ddns=`echo "${sz}"|awk -v RS='+'  '{print $0}'|grep 's' |awk '{print $2}'`
	cas="$(echo $ddns | grep -oE '/|:')"
	case ${cas} in
	":" ) s="-s `echo ${ddns}`"
	
	;;
	"/" ) ipv4=`curl $ddns` 
		[ -z "$ipv4" ] && ipv4=`curl -i $ddns | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' |head -n 1`
   
   				[ -f "${natmap_addr}" ] && lastIP="$(tail -n 1 ${natmap_addr}|awk '{print $4}')" || lastIP="" # 检查ip是否变动
				[ "$lastIP" != "${ipv4}" ] && {
					[ -n "$(pidof_)" ] && killall "$(pidof_)"
					echo "$(date "+%G-%m-%d %H:%M:%S") vnts服务地址更新记录: ${ipv4}"  >> "${natmap_addr}"
					}
	s="-s `echo ${ipv4}`"
	
	;;
	* ) addr=$(curl -k -s "https://ipw.cn/api/dns/${ddns}/AAAA/all" |  grep -o -i  "2001::[0-9a-fA-F:]\+" | head -n 1 ) && [ -z "$addr" ] 
	
		if [ ! -z "$(echo "$addr" | grep -o -i  "2001::[0-9a-fA-F:]\+")" ] ; then
			eval $(echo "$addr" | awk '/2001/'|cut -d ':' -f 1-6 | awk -F ':' '{print "port="$3" ipa="$4" ipb="$5 }')
			port=$((0x$port))
			ip1=$((0x${ipa:0:2}))
			ip2=$((0x${ipa:2:2}))
			ip3=$((0x${ipb:0:2}))
			ip4=$((0x${ipb:2:2}))
			ipv4="${ip1}.${ip2}.${ip3}.${ip4}:${port}"
			[ -f "${natmap_addr}" ] && lastIP="$(tail -n 1 ${natmap_addr}|awk '{print $4}')" || lastIP="" # 检查ip是否变动
			[ "$lastIP" != "$ipv4" ] && {
				[ -n "$(pidof_)" ] && killall "$(pidof_)"
				echo "$(date "+%G-%m-%d %H:%M:%S") vnts服务地址更新记录: ${ip1}.${ip2}.${ip3}.${ip4}:${port}" >> "${natmap_addr}"
				sleep 2
			}
		else
			ip_port=$(curl -k -s "https://ipw.cn/api/dns/${ddns}/TXT/all" |  grep -oE '"Type":"TXT","recordValue":[^,}]*' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -n 1 ) 
			if echo "$ip_port" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$' &>/dev/null 2>&1 ; then

				ipv4="${ip_port}"

				[ -f "${natmap_addr}" ] && lastIP="$(tail -n 1 ${natmap_addr}|awk '{print $4}')" || lastIP="" # 检查ip是否变动
				[ "$lastIP" != "${ip_port}" ] && {
					[ -n "$(pidof_)" ] && killall "$(pidof_)"
					echo "$(date "+%G-%m-%d %H:%M:%S") vnts服务地址更新记录: ${ip_port}"  >> "${natmap_addr}"
					sleep 2
				}
			else
				echo "不是有效的IPv4地址:端口格式，请检查下服务地址"
				echo "退出"
				exit 0
			fi
		fi
		s="-s `echo ${ipv4}` "
	
	;;
	esac

fi

:<<'!'

if [ -n "$(echo "${sz}"|grep '+s ')" ] ; then
	natmap_addr="/tmp/natmap_vnts_${nic0}_addr.txt"
	ddns=`echo "${sz}"|awk -v RS='+'  '{print $0}'|grep 's'|grep -v 'k' |awk '{print $2}'`

	if [ ! -n "`echo $ddns | grep ':'`" ] && [ ! -z "$ddns" ] ; then
	addr=$(curl -k -s "https://ipw.cn/api/dns/${ddns}/AAAA/all" |  grep -o -i  "2001::[0-9a-fA-F:]\+" | head -n 1 ) && [ -z "$addr" ]  # && \
#	addr=$(curl -k -s 'https://myssl.com/api/v1/tools/dns_query?qtype=28&host=${ddns}&qmode=-1'|grep -o -i "2001::[0-9a-fA-F:]\+" | head -n 1 ) && [ -z "$addr" ] && \
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
			[ -f "${natmap_addr}" ] && lastIP="$(tail -n 1 ${natmap_addr}|awk '{print $4}')" || lastIP="" # 检查ip是否变动
			[ "$lastIP" != "$ipv4" ] && {
				[ -n "$(pidof_)" ] && killall "$(pidof_)"
				echo "$(date "+%G-%m-%d %H:%M:%S") vnts服务地址更新记录: ${ip1}.${ip2}.${ip3}.${ip4}:${port}" >> "${natmap_addr}"
				sleep 2
			}
		else
			ip_port=$(curl -k -s "https://ipw.cn/api/dns/${ddns}/TXT/all" |  grep -oE '"Type":"TXT","recordValue":[^,}]*' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -n 1 ) 
			if echo "$ip_port" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$' &>/dev/null 2>&1 ; then

				ipv4="${ip_port}"

				[ -f "${natmap_addr}" ] && lastIP="$(tail -n 1 ${natmap_addr}|awk '{print $4}')" || lastIP="" # 检查ip是否变动
				[ "$lastIP" != "${ip_port}" ] && {
					[ -n "$(pidof_)" ] && killall "$(pidof_)"
					echo "$(date "+%G-%m-%d %H:%M:%S") vnts服务地址更新记录: ${ip_port}"  >> "${natmap_addr}"
					sleep 2
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

!

##增加了支持ip4p地址

if [ -n "$(echo "${sz}"|grep '+t ')" ] ; then
	natmap_addr="/tmp/natmap_vnts_${nic0}_addr.txt"
	ddns=`echo "${sz}"|awk -v RS='+'  '{print $0}'|grep 't' | grep -v 'k' |awk '{print $2}'`

	if [ ! -n "`echo $ddns | grep ':'`" ] && [ ! -z "$ddns" ] ; then

		ip_port=$(curl -k -s "https://ipw.cn/api/dns/${ddns}/TXT/all" |  grep -oE '"Type":"TXT","recordValue":[^,}]*' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -n 1 ) 
			if echo "$ip_port" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$' &>/dev/null 2>&1 ; then
#				echo "这是有效的IPv4地址:端口格式，（TXT记录）"
				ipv4="${ip_port}"
#				echo "${ip_port}"
				[ -f "${natmap_addr}" ] && lastIP="$(tail -n 1 ${natmap_addr}|awk '{print $4}')" || lastIP="" # 检查ip是否变动
				if [ "$lastIP" != "${ip_port}" ] ; then
					[ -n "$(pidof_)" ] && killall "$(pidof_)"
					echo "$(date "+%G-%m-%d %H:%M:%S") vnts服务地址更新记录: ${ip_port}"  >> "${natmap_addr}"
					sleep 2
				fi
			fi
		s="-s `echo ${ipv4}`"
	else
		s="-s `echo ${ddns}`"
	fi

fi

##增加了支持ipv4地址txt记录

[ -f "/tmp/vnt_${nic0}_tmp" ] && vnt_tmp2=$(head -n 1 "/tmp/vnt_${nic0}_tmp") || vnt_tmp2="::"
( [ "${sz}" = "${vnt_tmp2}" ] && [ ! -z "$(pidof_)" ] ) && {
exit 0
}
##参数相同并在运行中，退出运行

echo "${sz}" > "/tmp/vnt_${nic0}_tmp"
##将参数记录到临时文件中

SCRIPT_DIR="$(cd $(dirname $0); pwd)"
# echo "脚本所在目录: $SCRIPT_DIR"


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

webd_t (){
curl -k -s 'https://ipw.cn/api/dns/webd-t.liaoh.dedyn.io/TXT/all' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -n 1

}


vnt="/tmp/vnt-cli"

github_download_ () {


vnt_tar="/tmp/vnt.tar.gz"


tag="$( curl -#k --connect-timeout 3 --user-agent "user_agent" https://api.github.com/repos/vnt-dev/vnt/releases/latest  | awk -F 'html_url' '{print $2}' | awk -F '/' '{print $8}' | awk -F '"' '{print $1}'|head -n 1)"
[ -z "$tag" ] && tag="$( curl -#ksL --connect-timeout 3 --user-agent "user_agent"  https://api.github.com/repos/vnt-dev/vnt/releases/latest | awk -F 'html_url' '{print $2}' | awk -F '/' '{print $8}' | awk -F '"' '{print $1}' |head -n 1 )"
[ -z "$tag" ] && tag="v1.2.12"

curl="curl --connect-timeout 3 -#fLkso "
jiashu="
https://gh.ddlc.top/
https://gh.llkk.cc/
https://github.moeyy.xyz/
https://mirror.ghproxy.com/
https://ghproxy.net/
"
https="https://github.com/vnt-dev/vnt/releases/download/$tag"
for_in_ () {
for k in $jiashu
do
	${curl} ${vnt_tar} "${k}${url}"  &>/dev/null
	log_ "使用 $k加速下载......"
if	[ "$?" = 0 ] ; then
	[ -f "${vnt_tar}" ] && log_ "下载成功！"
	[ -f "${vnt_tar}" ] && tar -zxvf ${vnt_tar} -C /tmp vnt-cli
	[ -f "${vnt}" ] && [ ! -x "${vnt}" ] && chmod +x "${vnt}"
	if [ $(($(${vnt} -h | wc -l))) -gt 3 ] ; then
			log_ "程序与系统匹配！"
	[ -f "${vnt_tar}" ] && rm -f "${vnt_tar}"
   log_ "从$k下载的与设备匹配"
      break
  else
      log_ "程序与系统不匹配！"
			[ -f "$vnt" ] && rm "$vnt"  && log_ "正在删除！" 
			
			sleep 2 
			echo -e "\n\n"
			log_ "准备下一个地址下载..."
	fi

fi
done



}

case "${cpucore}" in 
	"mipsel") url="${https}/vnt-${cpucore}-unknown-linux-musl-$tag.tar.gz" # && log_ "vnt_${cpucore}-unknown-linux-musl-$tag.tar.gz下载成功"
	;;
	"mips")  url="${https}/vnt-${cpucore}-unknown-linux-musl-$tag.tar.gz" # && log_ "vnt_${cpucore}-unknown-linux-musl-$tag.tar.gz下载成功"
	;;
	"x86_64")  url="${https}/vnt-${cpucore}-unknown-linux-musl-$tag.tar.gz" # && log_ "vnt_${cpucore}-unknown-linux-musl-$tag.tar.gz下载成功"
	;;
	"i386") url="${https}/vnt-${cpucore}-unknown-linux-musl-$tag.tar.gz" # && log_ "vnt_${cpucore}-unknown-linux-musl-$tag.tar.gz下载成功"
	;;
	"arm")  url="${https}/vnt-${cpucore}-unknown-linux-${musl_eabi_hf}-$tag.tar.gz" # && log_ "vnt_${cpucore}-unknown-linux-musl-$tag.tar.gz下载成功"
	;;
	"armv7")  url="${https}/vnt-${cpucore}-unknown-linux-${musl_eabi_hf}-$tag.tar.gz" # && log_ "vnt_${cpucore}-unknown-linux-musl-$tag.tar.gz下载成功"
	;;
	"aarch64")  url="${https}/vnt-${cpucore}-unknown-linux-musl-$tag.tar.gz" # && log_ "vnt_${cpucore}-unknown-linux-musl-$tag.tar.gz下载成功"
	;;
esac

for_in_

}

github_download_ 

if [ ! -f "${vnt}" ] ; then

https="
http://$(webd_t)/vnt-cli_${cpucore}
http://webd.liaoh.dedyn.io:19213/vnt-cli_${cpucore}
http://liaoh.web3v.vip/vnt/vnt-cli_${cpucore}.jpg
"

http_download (){
local tmp=$1
curl="curl --connect-timeout 3 -#fLko "
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
 [ $(($(${vnt} -h | wc -l))) -gt 3 ] || {
 rm -rf "${vnt}"
 exit 1
 }
##判断执行文件是否可运行,否则删除

fi

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
		#	test "${size}" -gt 1000 && cp "${vnt}" /etc/
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
		mipstype=$(echo -n I | hexdump -o 2>/dev/null | awk '{ print substr($2,6,1); exit}') ##通过判断大小端判断mips或mipsel
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
## 判断参数上有无-d,无则用ip作为ID值


[ -n "$(pidof_)" ] && kill "$(pidof_)"
## 先退出旧运行参数的进程
sleep 1

[ ! -d "/tmp/log/" ] && mkdir "/tmp/log/" # 判断是否存在log目录，否则新建

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
	[ -h "${log4rs_yaml_dir}/env" ] || {
		rm -rf "${log4rs_yaml_dir}/env"
		ln -s "/tmp/env" "${log4rs_yaml_dir}/env"
	}
  }
}
## 将/tmp/env目录软链接到程序所在的目录
env_

nohup=$(which nohup)

cd ${log4rs_yaml_dir} && ${nohup} ./vnt-cli ${nic} $@ ${d} ${n} ${s}  >/tmp/vnt_cli.txt 2>&1  &
# "${vnt}" ${nic} $@ ${d} ${n} ${s} >/tmp/vnt_cli.txt 2>&1  &
# 这是个脚本的核心
sleep 1

echo -n "$(date +%s)" > /tmp/start_timestamp_vnt_cli
## 截取当时运行时间

iptables_

[ -z "$(pidof_)" ] && log_ "运行失败" || log_ "${vnt} ${d} ${sz} ${n} ${s} ${nic} & 运行成功"

exit 0
