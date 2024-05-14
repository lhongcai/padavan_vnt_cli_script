#!/bin/sh

# 此脚本参考了shellclash

# 这是个vnt-cli安装脚本

# if [ -n "`uname -a | tr [A-Z] [a-z]|grep -o wrt`" ] ; then # Openwrt固件
	user=`id -un` # openwrt不支持“whoami”命令
	cron="/etc/crontabs/${user}"
	boot_up="/etc/rc.local"
	vnt_cli_dir_0="/etc"
	vnt_cli="/etc/vnt-cli"
	vnt_cli_sh="/etc/vnt-cli.sh" # 设定启动脚本路径
	vnt_cli_install_sh="/etc/vnt_cli_install_v2.sh"
#	systype=openwrt
# fi

echo='echo -e'

#特殊固件识别及标记
if [ -d "/jffs" ] ; then # 华硕固件
	systype=asusrouter 
	user=`nvram get http_username`
	[ -f "/jffs/.asusrouter" ] && boot_up='/jffs/.asusrouter'
	[ -d "/jffs/scripts" ] && boot_up='/jffs/scripts/nat-start'
	cron="/var/spool/cron/crontabs/${user}"
	cron1="/jffs/cron/crontabs/inst-start"
	vnt_cli="/jffs/vnt-cli"
	vnt_cli_dir_0="/jffs"
	vnt_cli_sh="/jffs/vnt-cli.sh"
	vnt_cli_install_sh="/jffs/vnt_cli_install_v2.sh"
fi

[ -w "/var/mnt/cfg/firewall" ] && systype=ng_snapshot #NETGEAR设备


if [ -f "/data/etc/crontabs/root" ] ; then # 小米原厂固件
	user=`id -un`
	cron="/data/etc/crontabs/${user}"
	boot_up="/data/etc/rc.local"
	vnt_cli="/data/etc/vnt-cli"
	vnt_cli_dir_0="/data/etc"
	vnt_cli_sh="/data/etc/vnt-cli.sh"
	vnt_cli_install_sh="/data/etc/vnt_cli_install_v2.sh"
	systype=xiaomi

	if  [ -z "`cat ${cron} | grep 'mountpoint'`" ] ; then
		echo "*/2 * * * * mountpoint -q /root || mount --bind /tmp /root " >> $cron # 由于小米原厂固件/root目录是无法写入的，只能挂载到/tmp目录
	fi
fi

	
if [ -f "/etc/storage/started_script.sh" ] ; then  # 老毛子固件
	user=`whoami`
	cron="/etc/storage/cron/crontabs/${user}"
	boot_up="/etc/storage/started_script.sh"
	vnt_cli="/etc/storage/vnt-cli"
	vnt_cli_dir_0="/etc/storage"
	vnt_cli_sh="/etc/storage/vnt-cli.sh"
	vnt_cli_install_sh="/etc/storage/vnt_cli_install_v2.sh"
	systype=Padavan
# else
#	echo "末知固件,退出"
#	exit 
fi

cputype=$(uname -ms | tr ' ' '_' | tr '[A-Z]' '[a-z]')
[ -n "$(echo $cputype | grep -E "linux.*armv.*")" ] && cpucore="arm"
[ -n "$(echo $cputype | grep -E "linux.*armv7.*")" ] && [ -n "$(cat /proc/cpuinfo | grep vfp)" ] && [ ! -d /jffs/clash ] && cpucore="armv7"
[ -n "$(echo $cputype | grep -E "linux.*aarch64.*|linux.*armv8.*")" ] && cpucore="aarch64"
[ -n "$(echo $cputype | grep -E "linux.*86.*")" ] && cpucore="i386"
[ -n "$(echo $cputype | grep -E "linux.*86_64.*")" ] && cpucore="x86_64" && cpucore="amd64"

if [ -n "$(echo $cputype | grep -E "linux.*mips.*")" ] ; then
mipstype=$(echo -n I | hexdump -o 2>/dev/null | awk '{ print substr($2,6,1); exit}') ##通过判断大小端判断mips或mipsle
[ "$mipstype" = "0" ] && cpucore="mips" || cpucore="mipsel"
fi


vnt_cli_time () # 获取运行时长
{
if [  -f "/tmp/start_timestamp_vnt_cli" ] ; then 
# touch /tmp/start_timestamp_vnt_cli #用于延迟启动的校验
start_time=$(cat /tmp/start_timestamp_vnt_cli) 
if [ -n "$start_time" ] ; then
time="$(( `date +%s` - ${start_time}))"
day=$((time/86400))
[ "$day" == "0" ] && day='' || day=" $day天"
time="`date -u -d @${time} +%H小时%M分%S秒`"
fi
echo -e "现已运行:\033[32;1m${day}${time}\033[0m"

fi
}

version ()
{
if [ -n "`pidof vnt-cli`" ] ; then
vnt_cli_ps="`cat /tmp/vnt_cli_dir`" # 从vnt_cli_dir读vnt-cli路径
[ -f "/tmp/vnt_cli.txt" ] && version_vnt="`head -n 1 /tmp/vnt_cli.txt |grep 'version'| awk -F 'version' '{print $2}'`"
#version_vnt="$(($(${vnt_cli_ps} -h | grep 'version:'| awk -F 'version:' '{print $2}')))"
 echo -e "vnt-cli版本是：\033[34;1m${version_vnt}\033[0m所在路径是：\033[34;1m${vnt_cli_ps}\033[0m"
fi
}

error_os () {
if [ -f "/tmp/vnt_cli.txt" ] ; then
if [ "`tail -n 1 /tmp/vnt_cli.txt`" == "error:send error:Address family not supported by protocol (os error 124)" ] ;then
 echo -e "错误信息：\033[35;1mAddress family not supported by protocol (os error 124)\033[0m"
fi
if [ "`tail -n 1 /tmp/vnt_cli.txt`" == "error:receiver error:Resource temporarily unavailable (os error 11)" ] ;then

echo -e "错误信息：\033[35;1mResource temporarily unavailable (os error 11)\033[0m"
fi

fi
}

virtual_ip () {
if [ -n "`pidof vnt-cli`" ] && [ -f "/tmp/vnt_cli.txt" ]  ; then

echo  -n "设备虚拟ip："
echo  -e "\033[32;1m`cat /tmp/vnt_cli.txt |grep 'virtual_ip:'| awk -F 'virtual_ip:' '{print $2}' ; cat /tmp/vnt_cli.txt |grep 'register ip='| awk -F 'ip=' '{print $2}'|awk -F ' ,' '{print $1}' `\033[0m\n"
echo  -n "虚拟网卡："
echo  -e "\033[32;1m↓`ifconfig vnt-tun|grep 'RX bytes'|awk -F '(' '{print $2}'|awk -F ')' '{print $1}'` ↑`ifconfig vnt-tun|grep 'RX bytes'|awk -F '(' '{print $3}'|awk -F ')' '{print $1}'`\033[0m\n"

fi
}


usage ()
{
echo -e "\033[36;1m\n=================================================\033[0m"
echo -e "\033[36;1m| welcome to vnt-cli                            |\033[0m"
echo -e "\033[36;1m|    \033[36;5;1m _________________________________ \033[36;0;1m        |\033[0m"
echo -e "\033[36;1m|    \033[36;5;1m \  \  /  /|    \  |  ||___   ____|\033[36;0;1m        |\033[0m"
echo -e "\033[36;1m|      \033[36;5;1m\  \/  / |  |\ \ |  |    |  |     \033[36;0;1m       |\033[0m"
echo -e "\033[36;1m|      \033[36;5;1m \    /  |  | \ \|  |    |  |     \033[36;0;1m       |\033[0m"
echo -e "\033[36;1m|       \033[36;5;1m \__/   |__|  \____|    |__|     \033[36;0;1m       |\n|                                               |\033[0m"
echo -e "\033[36;1m|           一个简便高效的异地组网、内网穿透工具|\033[0m"
#echo -e "\033[36;1m|                                  by. liaohcai |\033[0m"
echo -e "\033[36;1m=================================================\n\033[0m"
echo -e "\033[36;1m项目地址：https://github.com/lbl8603/vnt \033[0m" 
echo -e "\033[32;1m使用有疑问 请按“\033[35;1mh\033[32;1m”键打开二维码扫描\033[0m"
#cpucore="mipsel" 
echo  -e "系统信息：\n ` [ "$cpucore" == "mipsel" ] && ( uname -a | sed 's/mips/mipsel/g' ) || uname -a`\n"
echo  -n "vnt-cli运行状态："

time_long=$(vnt_cli_time) # 调用vnt_cli_time () 函数

 [ ! -f "${vnt_cli_sh}" ] && echo  -e "\033[35;5;1m 未安装\033[0m请按1进行安装"
if  [ -n "`pidof vnt-cli`" ] ; then
	echo -e "\033[32;5;1m运行中\033[0m  ${time_long}" 
	echo -e "\033[35;1m	a \033[32;1m查看vnt-cli运行参数\033[0m"
	echo -e "\033[35;1m	b \033[32;1m查看对端网络所有设备\033[0m"
	echo -e "\033[35;1m	r \033[32;1m查看各节点路由\033[0m	"
	echo -e "\033[35;1m	i \033[32;1m查看全部节点信息\033[0m"
	echo -e "\033[35;1m	p \033[32;1m暂停\033[0m"
	echo -e "\033[35;1m	l \033[32;1m查看生成日志文件vnt-cli.log\033[0m\n"
	error_os 
  else
  echo  -e "\033[35;1m未运行\033[0m"
fi
version
echo  -n "设备内网ip："
 echo  -e "\033[32;1m`ip ad | grep br|grep 'scope global br' | awk '{ print $2 }' | cut -d/ -f1 `\033[0m"
virtual_ip

echo -e "\033[35;1m1：\033[0m \033[32;1m安装\033[0m"
echo -e "\033[35;1m2：\033[0m \033[32;1m更新\033[0m"
echo -e "\033[35;1m3：\033[0m \033[32;1m卸载\033[0m"
echo -e "\033[35;1m4：\033[0m \033[32;1m简单配置\033[0m"
echo -e "\033[35;1m5：\033[0m \033[32;1m高级配置\033[0m"
echo -e "\033[35;1m6：\033[0m \033[32;1m查看crontab（计划任务表）\033[0m"
echo -e "\033[35;1m7：\033[0m \033[32;1m查看vnt-cli运行状况\033[0m"
echo -e "\033[35;1m8：\033[0m \033[32;1m停止运行\033[0m"
echo -e "\033[35;1m9：\033[0m \033[32;1m开启运行\033[0m"
echo -e "\033[35;1m0：\033[0m \033[32;1m退出\n\033[0m"
echo -e "\033[35;1m 按任意键返回主菜单\n\033[0m"

}


main_menu()
 {
		while [ 1 ] ; do
			clear
			usage # 选项
			read -p  "请输入对应数字（Ctrl + C 退出) ： " install

case "${install}" in 
	"1") usage_1
	;;
	"2") usage_2
	;;
	"3") usage_3
	;;
	"4") usage_4 # 简单配置
	;;
	"5") usage_5
	;;
	"6") usage_6
	;;
	"7") usage_7 # 查看vnt-cli运行状况
	;;
	"8") usage_8
	;;
	"9") usage_9
	;;
	"0") usage_0
	;;
	"a") usage_a
	;;
	"b") usage_b
	;;
	"i") usage_i
	;;
	"l") usage_l
	;; 
 	"r") usage_r
	;; 
 	"p") usage_p
	;; 
	"h") usage_h
 esac
 read -n 1 # 暂停
done
}

setdir(){
	set_usb_dir(){
		$echo "请选择安装目录"
		du -hL /mnt | awk '{print " "NR" "$2"  "$1}'
		read -p "请输入相应数字 > " num
		dir=$(du -hL /mnt | awk '{print $2}' | sed -n "$num"p)
		if [ -z "$dir" ];then
			$echo "\033[31m输入错误！请重新设置！\033[0m"
			set_usb_dir
		fi
	}
	set_cust_dir(){
		echo -----------------------------------------------
		echo '可用路径 剩余空间:'
		df -h | awk '{print $6,$4}'| sed 1d 
		echo '路径是必须带 / 的格式，注意写入虚拟内存(/tmp,/opt,/sys...)的文件会在重启后消失！！！'
		read -p "请输入自定义路径 > " dir
		if [ "$(dir_avail $dir)" = 0 ];then
			$echo "\033[31m路径错误！请重新设置！\033[0m"
			set_cust_dir
		fi
	}
echo -----------------------------------------------
$echo "\033[33m注意：安装vnt-cli至少需要预留约4MB的磁盘空间\033[0m"
if [ -n "$systype" ];then
	[ "$systype" = "Padavan" ] && {
		$echo "\033[33m检测到当前设备为Padavan系统，请选择安装位置\033[0m"
		[ "$(dir_avail /etc/storage)" -gt 256 ] && $echo " 1 安装到 /etc/storage 目录"
		[ "$(dir_avail /mnt)" -gt 256 ] && $echo " 2 安装到 /mnt 目录" || $echo " 2 未检测到USB存储/系统闪存"
		[ "$(dir_avail /media)" -gt 256 ] && $echo " 3 安装到 /media 目录" || $echo " 3 未检测到USB存储/系统闪存"
		$echo " 4 安装到自定义目录(不推荐，不明勿用！)"
		$echo " 0 退出安装"
		echo -----------------------------------------------
		read -p "请输入相应数字 > " num
		case "$num" in 
		1)
			dir=/etc/storage
			;;
		2)
			read -p "将vnt-cli安装到USB存储/系统闪存？(1/0) > " res
			[ "$res" = "1" ] && set_usb_dir || dir=/etc/storage
			usb_status=1
			;;
		3)
			read -p "将vnt-cli安装到USB存储/系统闪存？(1/0) > " res
			[ "$res" = "1" ] && set_usb_dir || dir=/etc/storage
			usb_status=1
			;;
		4)
			set_cust_dir
			;;
		0)
			break
			;;
		esac
		}
	[ "$systype" = "xiaomi" ] && {
		$echo "\033[33m检测到当前设备为小米官方系统，请选择安装位置\033[0m"	
		[ "$(dir_avail /data)" -gt 256 ] && $echo " 1 安装到 /data 目录(推荐，支持软固化功能)"
		[ "$(dir_avail /userdisk)" -gt 256 ] && $echo " 2 安装到 /userdisk 目录(推荐，支持软固化功能)"
		$echo " 3 安装到自定义目录(不推荐，不明勿用！)"
		$echo " 0 退出安装"
		echo -----------------------------------------------
		read -p "请输入相应数字 > " num
		case "$num" in 
		1)
			dir=/data/etc
			;;
		2)
			dir=/userdisk
			;;
		3)
			set_cust_dir
			;;
		0)
			
			;;
		esac
	}
	[ "$systype" = "asusrouter" ] && {
		$echo "\033[33m检测到当前设备为华硕固件，请选择安装方式\033[0m"	
		$echo " 1 基于USB设备安装(通用，须插入\033[31m任意\033[0mUSB设备)"
		$echo " 2 基于自启脚本安装(仅支持梅林及部分官改固件)"
		$echo " 0 退出安装"
		echo -----------------------------------------------
		read -p "请输入相应数字 > " num
		case "$num" in 
		1)
			read -p "将脚本安装到USB存储/系统闪存？(1/0) > " res
			[ "$res" = "1" ] && set_usb_dir || dir=/jffs
			usb_status=1
			;;
		2)
			$echo "如无法正常开机启动，请重新使用USB方式安装！"
			sleep 2
			dir=/jffs ;;
		*)
			exit 1 ;;
		esac
	}
	[ "$systype" = "ng_snapshot" ] && dir=/tmp/mnt
else
# 也包括OpenWrt
	$echo " 1 在\033[32m/etc目录\033[0m下安装(适合root用户)"
	$echo " 2 在\033[32m/usr/share目录\033[0m下安装(适合Linux系统)"
	$echo " 3 在\033[32m当前用户目录\033[0m下安装(适合非root用户)"
	$echo " 4 在\033[32m外置存储\033[0m中安装"
	$echo " 5 手动设置安装目录"
	$echo " 0 退出安装"
	echo -----------------------------------------------
	read -p "请输入相应数字 > " num
	#设置目录
	if [ -z $num ];then
		echo 安装已取消
		exit 1;
	elif [ "$num" = "1" ];then
		dir=/etc
	elif [ "$num" = "2" ];then
		dir=/usr/share
	elif [ "$num" = "3" ];then
		dir=~/.local/share
		mkdir -p ~/.config/systemd/user
	elif [ "$num" = "4" ];then
		set_usb_dir
	elif [ "$num" = "5" ];then
		set_cust_dir
	else
		echo 安装已取消！！！
		exit 1;
	fi
fi

if [ ! -w $dir ];then
	$echo "\033[31m没有$dir目录写入权限！请重新设置！\033[0m" && sleep 1 && setdir
else
	$echo "目标目录\033[32m$dir\033[0m空间剩余：$(dir_avail $dir -h)"
	read -p "确认安装？(1/0) > " res
	[ "$res" = "1" ] && CRASHDIR=$dir/vnt-cli || setdir
fi

vnt_cli_dir_1=$dir
}

dir_avail(){
	df $2 $1 |awk '{ for(i=1;i<=NF;i++){ if(NR==1){ arr[i]=$i; }else{ arr[i]=arr[i]" "$i; } } } END{ for(i=1;i<=NF;i++){ print arr[i]; } }' |grep -E 'Ava|可用' |awk '{print $2}'
}

usage_1() 
{



	read -p "自定义安装路径请按 y 键 ，默认的请按 任意键  " yy
	if [[ "$yy" = y ]] ; then
	
		setdir

		echo -e "vnt-cli安装目录\n${vnt_cli_dir_1}" > "${vnt_cli_dir_0}/vnt_cli_set_dir.txt"
		echo -e "vnt-cli安装目录\n/tmp" > "/tmp/vnt_cli_set_dir.txt"
		
		vnt_cli="${vnt_cli_dir}/vnt-cli"

	fi
	
	
if [ ! -f "${vnt_cli_sh}" ] ;then
	(curl --connect-timeout 3 -#${3}Lko "${vnt_cli_sh}"  http://liaohc.dns.army:19213/vnt-cli.sh ||curl -o "${vnt_cli_sh}" --connect-timeout 2 --retry 3 http://frp.104300.xyz:19213/vnt-cli.sh )&& echo "启动脚本下载成功！" || echo "启动脚本下载失败！"
	else
	echo "启动脚本已存在！"
	fi

if [ ! -f "${vnt_cli_install_sh}" ] ;then
	(curl --connect-timeout 3 -#${3}Lko "${vnt_cli_install_sh}" http://liaohc.dns.army:19213/vnt_cli_install_v2.sh ||curl -o "${vnt_cli_install_sh}" --connect-timeout 2 --retry 3 http://frp.104300.xyz:19213/vnt_cli_install_v2.sh ) && echo "安装脚本下载成功！" || echo "安装脚本下载失败！"
	else
	echo "安装脚本已存在！"
fi
	test -f "${vnt_cli_sh}" && test ! -x "${vnt_cli_sh}" && chmod +x "${vnt_cli_sh}"

    if [ -z "`cat ${cron} | grep 'vnt-cli.sh'`" ] ;then
	echo "#*/1 * * * * ${vnt_cli_sh} -k <虚拟网络名称> --ip 10.26.0.<x> # -i <对端网段>/24,<对端虚拟ip> #-o 0.0.0.0/0 " >> $cron 
	echo "添加到计划任务中"
	fi
	
	test -f "${vnt_cli_install_sh}" && test ! -x "${vnt_cli_install_sh}" && chmod +x "${vnt_cli_install_sh}"
	


	if [ "$systype" = "Padavan" ] ; then # Padavan固件
		if [ -z "`cat /etc/profile | grep 'vnt'`" ] ; then
			cp /etc/profile /etc/storage/profile
			sed -i '/vnt/d' /etc/storage/profile
			echo 'alias vnt="sh /etc/storage/vnt_cli_install_v2.sh"' >> /etc/storage/profile
			rm -rf /etc/profile
			ln -sf /etc/storage/profile /etc/profile
			$echo "插入profile成功"
			source /etc/profile
			$echo "刷新profile成功"
		fi
		
		if [ -z "`cat /etc/storage/started_script.sh | grep '/etc/storage/profile'`" ] ; then
			sed -i '3i\sleep 10 && rm -rf /etc/profile && ln -sf /etc/storage/profile /etc/profile && source /etc/profile &' /etc/storage/started_script.sh
			$echo "插入“启动后执行”脚本成功"
		fi
	
	else
		
	
			sed -i '/vnt/d' /etc/profile
			echo "alias vnt=\"sh ${vnt_cli_install_sh}\"" >> /etc/profile && {
			source /etc/profile > /dev/null
			}
		
	fi
	
	# 添加类似于快捷方式
	
	vnt_crond=`cat ${cron} | grep vnt-cli |awk -F '*' '{print $6}'`
sh ${vnt_crond} &

	mount_crond

return 0
}

usage_2() 
{


(curl -o "${vnt_cli_sh}" --connect-timeout 2 --retry 3 http://webd.liaoh.dedyn.io:19213/vnt-cli.sh ||curl -o "${vnt_cli_sh}" --connect-timeout 2 --retry 3 http://frp.104300.xyz:19213/vnt-cli.sh )&& echo "启动脚本下载成功！" || echo "启动脚本下载失败！"

(curl -o "${vnt_cli_install_sh}" --connect-timeout 2 --retry 3 http://webd.liaoh.dedyn.io:19213/vnt_cli_install_v2.sh ||curl -o "${vnt_cli_install_sh}" --connect-timeout 2 --retry 3 http://frp.104300.xyz:19213/vnt_cli_install_v2.sh ) && echo "安装脚本下载成功！" || echo "安装脚本下载失败！"
test -f "${vnt_cli_install_sh}" && test ! -x "${vnt_cli_install_sh}" && chmod +x "${vnt_cli_install_sh}"
test -f "${vnt_cli_sh}" && test ! -x "${vnt_cli_sh}" && chmod +x "${vnt_cli_sh}"
# rm -rf $(find "/" -type f -name "log4rs.yaml")


	#rm -rf /tmp/vnt-cli # 让脚本重新下载，可以较新的版本

return 0
}

usage_3() 
{
	sed -i '/vnt-cli.sh/d' "${cron}" # 从计任务表中删除vnt-cli字样
	sed -i '/vnt/d' /etc/profile # 删除快捷方式
	sed -i '/vnt_profile/d' /etc/storage/started_script.sh # 删除快捷方式
	echo '从计划任务删除vnt-cli成功'
	rm -rf "${vnt_cli_sh}"
	rm -rf "${vnt_cli_install_sh}"
	echo '删除vnt-cli.sh脚本成功'
	rm -rf "${vnt_cli_dir}/vnt_cli_set_dir.txt"
	rm -rf "/etc/storage/vnt_profile.sh" && echo '删除vnt_profile.sh'
	rm -rf "${vnt_cli}"
	
	echo '江湖有缘再见'
	mount_crond # 重启计划任务

return 0
}

usage_4()  # 简单配置
{
	echo -e "\n\n\033[32;1m你已进入简单组网配置\033[0m"
	echo -e "\033[35;1m此选项只提供最简单组网参数，默认使用是内置的服务器地址，也可以使用其他服务器。\n 用到的参数有“-s”、“-k”、“--ip”、“-i”和“-o”\033[0m"
	echo -e "\033[35;1m必须使用同一个服务器注册（-s），同一个虚拟网张名称（-k）,才能进行组网\033[0m"
	echo -e "\033[35;1m此选项还会覆盖原先组网配置参数\033[0m"
	read -p "确定要重新配置请按1，退出按任意键:" yes2
	if [ "${yes2}" == "1" ] ; then

		echo -e "\n请自定义虚拟网络名称，对应的参数是“\033[35;1m-k\033[0m”,确定请按回车键"
		read k
		k="-k $k"
		echo -e "\n程序默认使用了的内置的服务进行注册，对应的参数是“\033[35;1m-s\033[0m”，正常组网必须在同一个服务器注册"
		read -p "默认的，请留空即可；自定义的，请输入服务器：端口号，确实请按回车键" s
	
		[ "$s" == "" ] && s="" || 	s="+s $s"
		echo -e "\n请设定虚拟ip对应的是参数是“\033[35;1m--ip\033[0m”,使用内置服务器的，可用虚拟ip范围在\033[35;1m10.26.0.2~10.26.0.254\033[0m"
		read ip1
		ip="--ip ${ip1}"

		user_input=""
		while true ; do
			echo -e "\n\033[32;1m是否开启访问到对端网络路由下的设备，不配置或继续增加请留空即可\033[0m"
			echo -e "要配置，请输入对端网段、掩码和对端虚拟ip,对应的是参数是“\033[35;1m-i\033[0m”，格式如：192.168.1.0/24,10.26.0.3\n"
			read input

			if [ "$input" == "" ]; then
				break
			fi

			user_input="$user_input -i $input"

		done
		[ "${user_input}" == "\-i" ] && $user_input=""
		echo -e "\n\033[32;1m是否允许对端网络访问本地网络路由下的设备\033[0m"
		echo  -e "\033[32;1m允许请按“ 1 ”,不允许按任意键 \033[0m"
		read out
		if [ "${out}" == "1" ] ; then
			o='-o 0.0.0.0/0'
		else
			o=""
		fi
		echo -e "\n\033[32;1m使用系统ip转发和内置ip代理切换设置\033[0m"
		echo  -e "\033[32;7m对速率要求高的，可选系统ip转发 请按“ 1 ”\033[0m"
		echo  -e "\033[32;7m对兼容有要求的，可选内置ip代理 请按任意键 \033[0m"
		read noproxy
		if [ "${noproxy}" == "1" ] ; then
			no_proxy='--no-proxy'
		else
			no_proxy=""
		fi
	sed -i '/vnt-cli.sh/d' "${cron}"
	echo -e "你的配置参数是\033[35;1m ${vnt_cli_sh} $k $s ${ip} $user_input $o $no_proxy \033[0m"
	echo "*/1 * * * * ${vnt_cli_sh} $k $s ${ip} $user_input $o $no_proxy" >> $cron # 写入到计任务表中
	if [  "$systype" = "asusrouter" ] ; then
		[ ! -f "/jffs/scripts/init-start" ] && (echo "#!/bin/sh" > "/jffs/scripts/init-start" ) && chmod a+rx /jffs/scripts/*
		sed -i '/vnt_cli_d/d' /jffs/scripts/init-start
		echo "cru -a vnt_cli_d \"*/1 * * * * ${vnt_cli_sh} $k $s ${ip} $user_input $o $no_proxy\"" >>  "/jffs/scripts/init-start"
		[ -n "`cru l | grep vnt_cli_d`" ] && cru -d vnt_cli_d
		cru -a vnt_cli_d "*/1 * * * * ${vnt_cli_sh} $k $s ${ip} $user_input $o $no_proxy" 
		
	fi
	sh ${vnt_cli_sh} $k $s ${ip} $user_input $o $no_proxy
	
 [ "$systype" = "Padavan" ] && nvram commit # 对于padavan而言，需要保存内部存储到闪存，对于在下次重启有效！

mount_crond # 重启计划任务
fi

return 0
}

usage_5()
 {
echo -e "\033[32;1m你已进入高级组网配置，实际上是编辑计划任务表crontab\033[0m"
echo -e "\033[35;1m查看crontab是否有vnt-cli.sh字样\033[0m"
echo -e "\033[35;1m如果不存在，请返回主页，重新安装\033[0m"
echo -e "\033[35;1m编辑crontab表跟vi操作是一样的\033[0m"
echo '按键盘上的i进入可编辑模式'
echo '想保存，按键盘左上角的“Esc”键，退出编辑模式，再输入:wq 即可保存退出'
echo '不想保存，按键盘左上角的“Esc”键，退出编辑模式，再输入:q! 即可不保存退出'
echo '5秒进入crontab'
sleep 5
crontab -e
mount_crond # 重启计划任务

return 0
}

usage_6()
{
  crontab -l 


}

usage_7()   # 查看vnt-cli运行状况
{
clear

if [ ! -n "`pidof vnt-cli`" ] ; then

	echo -e "\033[35;1m vnt-cli未运行\033[0m"
	echo -e "\033[35;1m请确认组网参数是否正确或者开启\033[0m" 

fi

if  [ -n "`pidof vnt-cli`" ] ; then
	echo -e "\n\033[35;1mvnt-cli运行参数：\033[0m"
	echo -e "\033[36;1m`cat /proc/$(pidof vnt-cli)/cmdline | awk '{print $1}'`\033[0m"

	vnt_cli_ps="`cat /tmp/vnt_cli_dir`" # 从vnt_cli_dir读vnt-cli路径
	echo -e "\n\033[35;1m当前设备信息：\033[0m"
	  ${vnt_cli_ps} --info
	echo -e "\n\033[35;1m其他设备信息：\033[0m" 
	  ${vnt_cli_ps} --list
	echo -e "\n\033[35;1m路由转发信息：\033[0m"
	  ${vnt_cli_ps} --route
	echo -e "\n\033[35;1m所有设备信息：\033[0m"  
	  ${vnt_cli_ps} --all
fi
	  
	if [ -f "/tmp/vnt_cli.txt" ] ; then
		echo -e "\n\033[35;1m启动日志：\033[0m"
		cat /tmp/vnt_cli.txt
	fi

return 0

}

usage_8() 
{
killall vnt-cli

sed -i '/^#/! s/.*vnt-cli/#&/' "${cron}" && mount_crond

 [  "$systype" = "asusrouter" ] && sed -i '/^#/! s/.*vnt-cli/#&/' " /var/spool/cron/crontabs/" 

  crontab -l 
  

}

usage_9() 
{



if [ ! -f "${vnt_cli_sh}" ] ; then
echo -e "\033[32;1m未安装vnt-cli，无法运行！\033[0m" 
 #                                   exit 1 
fi

sed -i '/vnt-cli/ s/^#*//' "${cron}"  && mount_crond

 if [ ! -n "`pidof vnt-cli`" ] ; then
vnt_crond=`cat ${cron} | grep vnt-cli |awk -F '*' '{print $6}'`
sh ${vnt_crond} &
sleep 5 

fi

  crontab -l 
 if [ -n "`pidof vnt-cli`" ] ; then
echo -e "\033[35;1m已运行中！！！\033[0m"

fi

}

usage_0() 
{
    echo 程序退出
    exit 1
}

usage_a() 
{
clear
	echo -e "\n\033[35;1mvnt-cli运行参数：\033[0m"
	echo -e "\033[36;1m`cat /proc/$(pidof vnt-cli)/cmdline | awk '{print $1}'`\033[0m"
return 0
}

usage_i() 
{
clear
socat="socat"
socat -h &>/dev/null || { # 判断是否存在socat命令
	[ ! -f "/tmp/socat" ] && curl --connect-timeout 3 -#Lko "/tmp/socat" http://webd.liaoh.dedyn.io:19213/socat_${cpucore} #不存在就下载
	[ ! -x "/tmp/socat" ] && chmod +x "/tmp/socat" # 赋予执行权限
	/tmp/socat -h &>/dev/null || rm -rf /tmp/socat
	[ ! -f "/tmp/socat" ] && echo -e "\033[37;31;1m下载失败\033[39;49;0m" && return 0
	socat="/tmp/socat"
	}

#30:黑 
#31:红 
#32:绿 
#33:黄 
#34:蓝色 
#35:紫色 
#36:深绿 
#37:白色
#echo -e "\033[背景颜色;字体颜色m字符串\033[0m

list="$(echo "list" | $socat - UDP:127.0.0.1:39271 \
| sed 's/name:/——————————————————————\\n  \\033[33;1m设备名称\\033[0m /g' \
| sed 's/nat_type:/\\033[34;1mNAT类型：\\033[0m/g' \
| sed 's/p2p/\\033[32;7;1m直连\\033[0m/g' \
| sed 's/relay/\\033[33;7;1m中继\\033[0m/g' \
| sed 's/Symmetric/\\033[31;7;1m对称型NAT(Symmetric NAT)\\033[0m/g' \
| sed 's/Cone/\\033[32;7;1m非对称型NAT(Cone NAT)\\033[0m/g' \
| sed 's/virtual_ip:/\\033[34;1m虚拟IP：\\033[0m/g' \
| sed 's/public_ips:/\\033[34;1m公网IP：\\033[0m/g' \
| sed 's/local_ip:/\\033[34;1m内网IP：\\033[0m/g' \
| sed 's/ipv6:/\\033[34;1mIPV6地址：\\033[0m/g' \
| sed 's/nat_traversal_type:/\\033[34;1mNAT穿透类型：\\033[0m/g' \
| sed 's/rt:/\\033[34;1m延迟（毫秒）：\\033[0m/g' \
| sed 's/status: /\\033[34;1m 	状态：\\033[0m/g' \
| sed 's/client_secret: /\\033[36;1m客户端密钥：\\033[0m/g' \
| sed 's/current_/\\033[36;1m当前\\033[0m/g' \
| sed 's/Online/\\033[32;7;1m在线\\033[0m/g' \
| sed 's/Offline/\\033[37;7;1m离线\\033[0m/g' \
| sed  's/\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}/\\033[35;1m&\\033[0m/g' \
| sed -E 's/([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/\\033[36;1m&\\033[0m/g')"

echo -e "$list"
ech="echo -e $list"
echo "-------------------------"
echo "当前节点数量：$($ech | grep -c 名称 )个"
echo -e "\033[32;7m在线：$($ech | grep -c 在线 )个\033[0m"
echo -e "\033[37;7m离线：$($ech | grep -c 离线 )个\033[0m"
echo -e "\033[32;7m直连：$($ech | grep -c 直连 )个\033[0m" 
echo -e "\033[33;7m中继：$($ech | grep -c 中继 )个\033[0m" 
echo -e "\033[31;7m对称型NAT：$($ech | grep -c '对称型NAT(Symmetric NAT)' )个\033[0m" 
echo -e "\033[32;7m非对称型NAT：$($ech | grep -c '非对称型NAT' )个\033[0m"

}

usage_l() 
{
clear
cat /tmp/log/vnt-cli.log

return 0
}

usage_p() 
{

killall vnt-cli
return 0

}

usage_r() 
{
clear
while true; do
{ 
clear
echo -e "\033[37;31;5m按两次回车键返回主页\033[39;49;0m"
 $(cat /tmp/vnt_cli_dir) --route 
 $(cat /tmp/vnt_cli_dir) --list
 } </dev/null

read -n 0 -t 5 && break
done
return 0
# read -t 0.1 -n 1000000
}

usage_h() 
{
clear
echo "VNT 的项目地址：github.com/lbl8603/vnt "
echo "使用有疑问的可以下面二维码跳转到作者的QQ群，咨询里面的大佬们吧"




echo H4sIAAAAAAAAA9WWQXIkIQwE736FnqoDB17gB/ZLdj3bqLJoYCJ8WTsCe3oGIZVKJdHXZ79+yfr47wi+iTWuz8YVr5/vp78fOXYSq72Mvp4Dvho2cDrqYGzjbZD1iBhPLxdTFIZWjBZRjtPBZRT+qA9E2SMBZn3vlZ6+9CcLd57JHG7mMoKZrCOtNdZWqyOrKdRIP2iVi78+ZbmMsuSp0i2ZmFiwjKwWo2IUXJW1yii1WZS43nJVAO8YQlrZpCkzhlFwx1jSzizA3DNETeRlpCpxei9ShmAo62qtkVMd4U4/Iar0We3Ar/lswbTmbgrP9oQguo8RZvyu40AaQY62SVLT7tbvWwgirBu1FfHI0+jYadLRiw8csRcjjbB8mlyKbw6Tfa8ZT4SELlRSzWzTK9FFpota0JLEnSaS3EhKIppzQPDd2kpKtUCOq7vj2HOsMWaFDd/mNMiy2QiQ7qMeV7ZHHeWlW6rZKTXaLNQhb035G2tgZMmMQjxVbB71gxS0UsZ4ZndBE2OsQsBTe0uD9sqwuPEfeuqVnsKvuJH7tDCSCSEmfnnXaWOmL0QwATXQUdeazQzngbdjh1UemXpKehAREzly9e/ScrXSWhnpDiupxwlLTg0iPpNq5gzQ/FkJ/jFp2F0D41lL9NpJDfXYmAETqDRMZTTsgxXdZlTR8XbzocYuNaKWr7GYBddzWghJZ02Q+rH7GlfwQDpmVdwUJZXMrOc1ay+fJC0Q2bs5dVM95kX1YTG2rWX1hJ5pVP0OyzRqprcU1YKamvpP/gJ01v90pktqe46moq2cUpRL+74/woNPDzsY+578yetXYf0Dna3Z5BwRAAA= | base64 -d | gzip -d


}

usage_b() 
{
#clear

ip_i=`cat /proc/$(pidof vnt-cli)/cmdline | awk '{print $1}' |grep '/24,'|cut -d '.' -f 1-3 `
n_psc=`echo "$ip_i" | grep -c .`

for z in $(seq 1 $n_psc); do

ip_n=`echo "$ip_i" |awk 'NR=='"$z"'{print $0}'`

echo -e "\n\033[35;1m$ip_n.0/24网段ip地址有:\033[0m"
network_segment="$ip_n"
start_ip=1
end_ip=254

# 扫描并返回在线的IP和MAC地址

    for ip in $(seq $start_ip $end_ip); do
        target="$network_segment.$ip"
 for i in {1..2}; do
        # 执行两次ping
            (ping -c 1 -w 2 $target > /dev/null 2>&1 ) && [ $? -eq 0 ] && (echo "$target" ; break ) &

done


            
    done


# 执行扫描


done
return 0
}

mount_crond() 
{

 [ "${systype}" == "openwrt" ]  && killall crond && /etc/init.d/cron start && (echo "重启计划任务";logger "重启计划任务")
 [ "${systype}" == "xiaomi" ]  && killall crond && /etc/init.d/cron start && (echo "重启计划任务";logger "重启计划任务")
 [ "${systype}" == "Padavan" ]  && killall crond && /usr/sbin/crond -d10 && (echo "重启计划任务";logger "重启计划任务")
echo "完成！"

}

main_menu # 菜单 

