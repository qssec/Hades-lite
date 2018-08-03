# Hades-lite

## 项目介绍

1、技术背景：

分布式拒绝服务 DDoS ，由于攻击简单、容易达到目的、难于防止和追查，逐渐成为常见的攻击方式，其目的是使计算机或网络无法提供正常的服务。随着网络资源的丰富以及带宽的增长，任何人都可能有能力影响网络服务的正常使用。

   由于传统x86服务器架构io处理性能问题，导致大流量的ddos攻击发生时，服务处于阻塞或者宕机状态。使得原本通用防护方案的短板凸显出来。传统厂商的防护方案在此又显得笨重昂贵，如果能有一种轻量级的方案，并且兼顾下一代防火墙的优势，使得所有IDC都纳入到防御体系中，将会是一种非常好的解决方案。

2、技术原理：

由于ddos flood 流量大部分为异常流量，为减轻内核处理负载，直接将非法流量在驱动层面直接丢弃。驱动按照NUMA 统一map内存表项分配到不通CPU上面，然后将每core对应的内存从NUMA中进行划分。防止remote memory access。
  
core0 为物理CPU1，core1为物理CPU2，core2为物理CPU3，core3为物理CPU4。服务器将每颗CPU引出的物理内存作为localMemory，访问时采用访问本地内存优先的策略，阻止CPU之间交互报文。同时为阻止CPU之间进行报文交互，PCIE Local Node需要将会话进行隔离。NIC侧内核需要将queue与指定的node进行绑定。申请内存做DMA保证内存访问一致性。
  
  
3、 使用说明

A.给内核网卡驱动打补丁，目前适用内核4.4.104版本   

patch -p1 < ${SRC_DIR}/ixgbe-4.4.104.patch`

B.将ddos.c 放入如下内核目录中

/linux/linux/drivers/net/ethernet/intel/ixgbe/

C.编译内核

4、物理环境及性能

CPU ：4 cores  ， Memery：16G ， NIC：Intel 82599 10G

Performance ：64bit 7G
