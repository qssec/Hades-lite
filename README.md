# hades-lite
## 项目介绍

## 使用说明
1.给内核网卡驱动打补丁，目前适用内核4.4.104版本

`patch -p1 < ${SRC_DIR}/ixgbe-4.4.104.patch`

2.将ddos.c 放入如下内核目录中：/linux/linux/drivers/net/ethernet/intel/ixgbe/

3.编译内核
