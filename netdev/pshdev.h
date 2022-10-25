#ifndef MPSHDEV_H
#define MPSHDEV_H

#include <linux/netdevice.h>
#include <linux/types.h>

#define PSHDEV_RX_INTR 0x0001
#define PSHDEV_TX_INTR 0x0002

int static psh_init(struct net_device *dev);
void static psh_uninit(struct net_device *dev);
netdev_tx_t static psh_start_xmit(struct sk_buff *skb, struct net_device *dev);
void static psh_tx_timeout(struct net_device *dev, unsigned int txqueue);

#endif