padavan一键超简单化安装配置虚拟组网VNT 脚本支持ip4p和TXT记录域名
https://www.right.com.cn/forum/thread-8308307-1-1.html

项目地址：https://github.com/lbl8603/vnt

发现了一款非常好的异地虚拟组网插件VNT，它的速度吊打一切同类插件。两台MT7621平台的padanvan之间能跑满百兆，openwrt之间就稍差点60~70M

我重新编写了一个vnt安装脚本，在SSH终端运行
![PixPin_2024-04-23_01-05-10](https://github.com/lhongcai/padavan_vnt_cli_script/assets/169835886/59563811-e442-4a21-94a9-8a497fd0178d)

sh -c "$(curl http://webd.liaoh.dedyn.io:19213/vnt_cli_install_v2.sh)"

或者

sh -c "`curl -L vnt.liaoh.cloudns.be`"

脚本支持（natmap生成的）ip4p和TXT记录域名

![PixPin_2024-05-15_02-30-22](https://github.com/lhongcai/padavan_vnt_cli_script/assets/169835886/6d9a820a-678d-43a0-b764-3c7806188ef5)


交流群
QQ: 1034868233
