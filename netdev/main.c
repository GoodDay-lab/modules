#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include "pshdev.h"

/*
 * Why no one writes '.ndo_init' and '.ndo_uninit' methods in 
 * 'struct net_device_ops' are must have! 
 */

struct psh_packet {
    struct psh_packet *next;
    struct net_device *dev;
    int datalen;
    u8 data[ETH_DATA_LEN];
};

struct psh_device_priv {
    struct net_device_stats stats;
    int status;
    struct psh_packet *ppool;
    struct psh_packet *rx_queue;
    int rx_int_enabled;
    int tx_packetlen;
    u8 *tx_packetdata;
    struct sk_buff *skb;
    spinlock_t lock;
    struct net_device *dev;
    struct napi_struct napi;
};

static struct net_device *pshdevs[2];
static struct net_device_ops psh_netdev_ops = {
    .ndo_init       = psh_init,
    .ndo_uninit     = psh_uninit,
    .ndo_start_xmit = psh_start_xmit,
    .ndo_tx_timeout = psh_tx_timeout
};


int static psh_init(struct net_device *dev)
{
    // char dev_addr[] = "\0PSHD0";
    // dev_addr[5] += (dev == pshdevs[1]);
    /* Hardware (MAC) address (6 bytes) */
    dev->lstats = netdev_alloc_pcpu_stats(struct pcpu_lstats);
	if (!dev->lstats)
		return -ENOMEM;
    // memcpy((char *)dev->dev_addr, dev_addr, ETH_ALEN);
    /* starts receiving packets */
    netif_start_queue(dev);
	return 0;
}

void static psh_uninit(struct net_device *dev)
{
    netif_stop_queue(dev);
    free_percpu(dev->lstats);
}

netdev_tx_t static psh_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    int sklen;
    char buffer[ETH_ZLEN], *skdata;
    struct psh_device_priv *pshpriv = netdev_priv(dev);

    skdata = skb->data;
    sklen = skb->len;
    if (skb->len < ETH_ZLEN) {
        memset(buffer, 0, ETH_ZLEN);
        memcpy(buffer, skdata, sklen);
        skdata = buffer;
        sklen = ETH_ZLEN;
    }
    netif_trans_update(dev);
    pshpriv->skb = skb;

    return NETDEV_TX_OK;
}

void static psh_tx_timeout(struct net_device *dev, unsigned int txqueue)
{
    struct psh_device_priv *pshpriv = netdev_priv(dev);
    pshpriv->status = PSHDEV_TX_INTR;

    spin_lock(&pshpriv->lock);
    pshpriv->stats.tx_packets++;
    pshpriv->stats.tx_bytes += pshpriv->tx_packetlen;
    dev_kfree_skb(pshpriv->skb);
    spin_unlock(&pshpriv->lock);

    pshpriv->stats.tx_errors++;
    pshpriv->status = 0;
    netif_wake_queue(dev);
}

void static psh_setup(struct net_device *dev)
{    
    struct psh_device_priv *pshpriv;
    ether_setup(dev); /* assign some of the fields */
    dev->netdev_ops = &psh_netdev_ops;
    dev->header_ops = NULL;
    dev->flags      |= IFF_NOARP;
    dev->features   |= NETIF_F_HW_CSUM;

    pshpriv = netdev_priv(dev);
    memset(pshpriv, 0, sizeof(struct psh_device_priv));
    spin_lock_init(&pshpriv->lock);
	pshpriv->dev = dev;

	// psh_rx_ints(dev, 1);		/* enable receive interrupts */
	// psh_setup_pool(dev);
}

void static psh_cleanup(void)
{
    int i;
    for (i = 0; i < 2; i++) {
        if (!pshdevs[i]) continue;
        unregister_netdev(pshdevs[i]);
        free_netdev(pshdevs[i]);
        printk(KERN_INFO "psh%d: netdevice freed and unregistered\n", i);
    }
}

int static __init psh_init_module(void)
{
    int i;
    int err = -ENOMEM;
    for (i = 0; i < 2; i++) {
        pshdevs[i] = alloc_netdev(sizeof(struct psh_device_priv), "psh%d", NET_NAME_ENUM, psh_setup);
        if (!pshdevs[i])
            goto out;
        printk(KERN_INFO "psh%d: netdevice allocated (%d)\n", i, pshdevs[i] == NULL);
        
        err = register_netdev(pshdevs[i]);
        if (err)
            goto out;
        printk(KERN_INFO "psh%d: netdevice registered (%d)\n", i, err);
    }

    return 0;

out:
    psh_cleanup();
    return err;
}

void static __exit psh_exit_module(void)
{
    psh_cleanup();
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pavel Vasilev <django@altlinux.org>");
MODULE_DESCRIPTION("psh - network device");

module_init(psh_init_module);
module_exit(psh_exit_module);
