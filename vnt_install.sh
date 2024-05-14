#!/bin/sh
#####使用方法
##a在计划任务中添加*/1 * * * * curl http://liaohc.dns.army:19213/vnt_install.sh |sh
##2在ssh终端或者在控制台中运行curl http://liaohc.dns.army:19213/vnt_install.sh |sh
##3在计划任务中，修改你自己的！！

os=`uname -a | tr [A-Z] [a-z]|grep -o wrt`
if [ -z "${os}" ] ; then
user=`whoami`
cron="/etc/storage/cron/crontabs/${user}"
boot_up="/etc/storage/started_script.sh"
vnt_cli_sh="/etc/storage/vnt-cli.sh"
else
user=`id -un`
##openwrt不支持“whoami”命令
cron="/etc/crontabs/${user}"
boot_up="/etc/rc.local"
vnt_cli_sh="/etc/vnt-cli.sh"
fi

test -f "${vnt_cli_sh}" && (echo "vnt-cli.sh脚本更新中"；logger "vnt-cli.sh脚本更新中")
if [ ! -f "${vnt_cli_sh}" ] ;then
 echo "vnt-cli.sh脚本安装中"
 logger "vnt-cli.sh脚本安装中"
 fi
 
curl -o "${vnt_cli_sh}" --connect-timeout 10 --retry 3 http://liaohc.dns.army:19213/vnt_install.sh


test ! -x "${vnt_cli_sh}" && chmod +x "${vnt_cli_sh}"

sed -i '/vnt.sh/d' "${cron}"

if [ -z "`cat ${cron} | grep 'vnt-cli.sh'`" ] ;then
echo "#*/1 * * * * ${vnt_cli_sh} #-k <虚拟网络名称> --ip 10.26.0.<x> #-i <对端网段>/24,<对端虚拟ip> #-o 0.0.0.0/0 #--no-proxy" >> $cron 
echo "添加到计划任务中"
logger "添加到计划任务中"
fi
test ! -z "${os}"  && killall crond && (echo "重启计划任务";logger "重启计划任务")
