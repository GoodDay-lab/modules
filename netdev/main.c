#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <linux/ip.h>
#include <linux/tcp.h>

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
    .ndo_open       = psh_init,
    .ndo_stop       = psh_uninit,
    .ndo_start_xmit = psh_start_xmit,
    .ndo_tx_timeout = psh_tx_timeout
};

static struct psh_packet *psh_get_tx_buffer(struct net_device *dev)
{
    struct psh_device_priv *pshpriv = netdev_priv(dev);
    struct psh_packet *pshpkt;
    unsigned long flags;

    spin_lock_irqsave(&pshpriv->lock, flags);
    pshpkt = pshpriv->ppool;
    if (!pshpkt) return pshpkt;

    pshpriv->ppool = pshpkt->next;
    if (!pshpriv->ppool) {
        netif_stop_queue(dev);
    }
    spin_unlock_irqrestore(&pshpriv->lock, flags);
    return pshpkt;
}

void static psh_release_tx_buffer(struct psh_packet *pshpkt)
{
    struct psh_device_priv *pshpriv = netdev_priv(pshpkt->dev);
    unsigned long flags;

    /* I am paranoid.. */
    if (!pshpkt) return;

    spin_lock_irqsave(&pshpriv->lock, flags);
    pshpkt->next = pshpriv->ppool;
    pshpriv->ppool = pshpkt;
    spin_unlock_irqrestore(&pshpriv->lock, flags);
    if (netif_queue_stopped(pshpkt->dev) && !pshpkt->next)
        netif_wake_queue(pshpkt->dev);
}

void static psh_enqueue_buffer(struct net_device *dev, struct psh_packet *pshpkt)
{
    struct psh_device_priv *pshpriv = netdev_priv(dev);
    unsigned long flags;

    spin_lock_irqsave(&pshpriv->lock, flags);
    pshpkt->next = pshpriv->rx_queue;
    pshpriv->rx_queue = pshpkt;
    spin_unlock_irqrestore(&pshpriv->lock, flags);
}

/*
static struct psh_packet *psh_dequeue_buffer(struct net_device *dev)
{
    struct psh_device_priv *pshpriv = netdev_priv(dev);
    struct psh_packet *pshpkt;
    unsigned int flags;

    spin_lock_irqsave(&pshpriv->lock, flags);
    pshpkt = pshpriv->rx_queue;
    if (pshpkt)
        pshpriv->rx_queue = pshpkt->next;
    spin_unlock_irqrestore(&pshpriv->lock, flags);
    return pshpkt;
}
*/

void static psh_init_packet_pool(struct net_device *dev)
{
    struct psh_device_priv *pshpriv = netdev_priv(dev);
    struct psh_packet *pshpkt;
    int i;

    pshpriv->ppool = NULL;
    for (i = 0; i < 10; i++) {
        pshpkt = kmalloc(sizeof(struct psh_packet), GFP_KERNEL);
        if (pshpkt == NULL)
            return;
        pshpkt->dev = dev;
        pshpkt->next = pshpriv->ppool;
        pshpriv->ppool = pshpkt;
    }
}

void static psh_reset_packet_pool(struct net_device *dev)
{
    struct psh_device_priv *pshpriv = netdev_priv(dev);
    struct psh_packet *pshpkt;

    while ((pshpkt = pshpriv->ppool)) {
        pshpriv->ppool = pshpkt->next;
        kfree(pshpkt);
    }
}

int static psh_init(struct net_device *dev)
{
    dev->lstats = netdev_alloc_pcpu_stats(struct pcpu_lstats);
	if (!dev->lstats)
		return -ENOMEM;
    netif_start_queue(dev);
	return 0;
}

int static psh_uninit(struct net_device *dev)
{
    netif_stop_queue(dev);
    free_percpu(dev->lstats);
    return 0;
}

void static psh_rx(struct net_device *dev, struct psh_packet *pkt)
{
    struct sk_buff *pshskb;
    struct psh_device_priv *pshpriv = netdev_priv(dev);

    pshskb = dev_alloc_skb(pkt->datalen + 2);
    if (pshskb == NULL) {
        if (printk_ratelimit()) {
            PSH_DEBUG("psh_rx(): not created socket (%d)\n", !pshskb);
        }
        pshpriv->stats.rx_dropped++;
        return;
    }    
    skb_reserve(pshskb, 2);
    memcpy(skb_put(pshskb, pkt->datalen), pkt->data, pkt->datalen);
    PSH_DEBUG("psh_rx(): created socket  (%d)\n"
              "          socket length:   %u\n", !pshskb, pshskb->len);

    pshskb->dev = dev;
    pshskb->protocol = eth_type_trans(pshskb, dev);
    pshskb->ip_summed = CHECKSUM_UNNECESSARY;
    pshpriv->stats.rx_packets++;
    pshpriv->stats.rx_bytes += pkt->datalen;
    netif_rx(pshskb);
}

void static psh_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    /* Это иммитация hardware прерываний, но на уровне приложения */

    int statusword;
    struct psh_device_priv *pshpriv;
    struct psh_packet *pshpkt = NULL;
    struct net_device *dev = (struct net_device *)dev_id;

    if (!dev)
        return;
    pshpriv = netdev_priv(dev);
    spin_lock(&pshpriv->lock);  /* Входим в контекст */

    /* Обновляем статус устройства */
    pshpriv = netdev_priv(dev);
    statusword = pshpriv->status;
    pshpriv->status = 0;

    if (statusword & PSHDEV_RX_INTR) {
        PSH_DEBUG("software interrupt:  RX_INTR\n");
        pshpkt = pshpriv->rx_queue;
        if (pshpkt) {
            pshpriv->rx_queue = pshpkt->next;
            psh_rx(dev, pshpkt);
        }
    } else if (statusword & PSHDEV_TX_INTR) {
        PSH_DEBUG("software interrupt:  TX_INTR\n");
        pshpriv->stats.tx_packets++;
        pshpriv->stats.tx_bytes += pshpriv->tx_packetlen;
        dev_kfree_skb(pshpriv->skb);
    }

    spin_unlock(&pshpriv->lock);
    if (pshpkt) psh_release_tx_buffer(pshpkt);
}

void static psh_hw_tx(struct net_device *dev, char *buf, int len)
{
    	/*
	 * This function deals with hw details. This interface loops
	 * back the packet to the other snull interface (if any).
	 * In other words, this function implements the snull behaviour,
	 * while all other procedures are rather device-independent
	 */
	struct iphdr *ih;
	struct net_device *dest;
	struct psh_device_priv *priv;
	u32 *saddr, *daddr;
	struct psh_packet *tx_buffer;

    len = (len < 0 ? -len : len);
    len = (len > ETH_DATA_LEN ? ETH_DATA_LEN : len);
    
	/* I am paranoid. Ain't I? */
	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		PSH_DEBUG("Hmm... packet too short (%i octets)\n", len);
		return;
	}

	if (0) { /* enable this conditional to look at the data */
		int i;
		PSH_DEBUG("len is %i\n" KERN_DEBUG "data:",len);
		for (i=14 ; i<len; i++)
			printk(" %02x",buf[i]&0xff);
		printk("\n");
	}
	/*
	 * Ethhdr is 14 bytes, but the kernel arranges for iphdr
	 * to be aligned (i.e., ethhdr is unaligned)
	 */
	ih = (struct iphdr *)(buf+sizeof(struct ethhdr));
	saddr = &ih->saddr;
	daddr = &ih->daddr;

	((u8 *)saddr)[2] ^= 1; /* change the third octet (class C) */
	((u8 *)daddr)[2] ^= 1;

	ih->check = 0;         /* and rebuild the checksum (ip needs it) */
	ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);

	if (dev == pshdevs[0])
		PSH_DEBUG("%08x:%05i --> %08x:%05i\n",
				ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source),
				ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest));
	else
		PSH_DEBUG("%08x:%05i <-- %08x:%05i\n",
				ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest),
				ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source));

	/*
	 * Ok, now the packet is ready for transmission: first simulate a
	 * receive interrupt on the twin device, then  a
	 * transmission-done on the transmitting device
	 */
	dest = pshdevs[dev == pshdevs[0] ? 1 : 0];
	priv = netdev_priv(dest);
	tx_buffer = psh_get_tx_buffer(dev);

	if(!tx_buffer) {
		PSH_DEBUG("Out of tx buffer, len is %i\n",len);
		return;
	}

	tx_buffer->datalen = len;
	memcpy(tx_buffer->data, buf, len);
	psh_enqueue_buffer(dest, tx_buffer);
	if (priv->rx_int_enabled) {
		priv->status |= PSHDEV_RX_INTR;
		psh_regular_interrupt(0, dest, NULL);
	}

	priv = netdev_priv(dev);
	priv->tx_packetlen = len;
	priv->tx_packetdata = buf;
	priv->status |= PSHDEV_TX_INTR;
	if (PSHDEV_LOCKUP && ((priv->stats.tx_packets + 1) % PSHDEV_LOCKUP) == 0) {
        	/* Simulate a dropped transmit interrupt */
		netif_stop_queue(dev);
		PSH_DEBUG("Simulate lockup at %ld, txp %ld\n", jiffies,
				(unsigned long) priv->stats.tx_packets);
	}
	else
		psh_regular_interrupt(0, dev, NULL);
}

netdev_tx_t static psh_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    int sklen;
    char buffer[ETH_ZLEN], *skdata;
    struct psh_device_priv *pshpriv = netdev_priv(dev);

    skdata = skb->data;
    sklen = skb->len;
    PSH_DEBUG("send packet:  length: %d\n", sklen);
    if (skb->len < ETH_ZLEN) {
        memset(buffer, 0, ETH_ZLEN);
        memcpy(buffer, skdata, sklen);
        skdata = buffer;
        sklen = ETH_ZLEN;
    }
    netif_trans_update(dev);
    pshpriv->skb = skb;

    psh_hw_tx(dev, skdata, sklen);

    return NETDEV_TX_OK;
}

void static psh_tx_timeout(struct net_device *dev, unsigned int txqueue)
{
    struct psh_device_priv *pshpriv = netdev_priv(dev);
    struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);

    pshpriv->status |= PSHDEV_TX_INTR;
    PSH_DEBUG("Transmit timeout at %ld, latency %ld\n", jiffies,
			jiffies - txq->trans_start);

    psh_regular_interrupt(0, dev, NULL);
    pshpriv->stats.tx_errors++;
    pshpriv->status = 0;

    spin_lock(&pshpriv->lock);
    psh_reset_packet_pool(dev);
    psh_init_packet_pool(dev);
    spin_unlock(&pshpriv->lock);

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
    pshpriv->rx_int_enabled = 1;

	// psh_rx_ints(dev, 1);		/* enable receive interrupts */
	psh_init_packet_pool(dev);
}

void static psh_cleanup(void)
{
    int i;
    for (i = 0; i < 2; i++) {
        if (!pshdevs[i]) continue;
        unregister_netdev(pshdevs[i]);
        free_netdev(pshdevs[i]);
        PSH_DEBUG("netdevice freed and unregistered\n");
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
        PSH_DEBUG("netdevice allocated (%d)\n", pshdevs[i] == NULL);
        
        err = register_netdev(pshdevs[i]);
        if (err)
            goto out;
        PSH_DEBUG("netdevice registered (%d)\n", err);
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
