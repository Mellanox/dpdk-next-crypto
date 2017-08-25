/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2017 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *	 * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in
 *	 the documentation and/or other materials provided with the
 *	 distribution.
 *	 * Neither the name of Intel Corporation nor the names of its
 *	 contributors may be used to endorse or promote products derived
 *	 from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <rte_ethdev.h>
#include <rte_ethdev_pci.h>
#include <rte_security.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_cryptodev_pmd.h>

#include "base/ixgbe_type.h"
#include "base/ixgbe_api.h"
#include "ixgbe_ethdev.h"
#include "ixgbe_ipsec.h"


#define IXGBE_WAIT_RW(__reg, __rw)			\
{							\
	IXGBE_WRITE_REG(hw, (__reg), reg);		\
	while ((IXGBE_READ_REG(hw, (__reg))) & (__rw))	\
	;						\
}
#define IXGBE_WAIT_RREAD  IXGBE_WAIT_RW(IXGBE_IPSRXIDX, IPSRXIDX_READ)
#define IXGBE_WAIT_RWRITE IXGBE_WAIT_RW(IXGBE_IPSRXIDX, IPSRXIDX_WRITE)
#define IXGBE_WAIT_TREAD  IXGBE_WAIT_RW(IXGBE_IPSTXIDX, IPSRXIDX_READ)
#define IXGBE_WAIT_TWRITE IXGBE_WAIT_RW(IXGBE_IPSTXIDX, IPSRXIDX_WRITE)

#define CMP_IP(a, b)	\
		((a).ipv6[0] == (b).ipv6[0] && (a).ipv6[1] == (b).ipv6[1] && \
		(a).ipv6[2] == (b).ipv6[2] && (a).ipv6[3] == (b).ipv6[3])


static void
ixgbe_crypto_clear_ipsec_tables(struct rte_eth_dev *dev)
{
	struct ixgbe_hw *hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	int i = 0;

	/* clear Rx IP table*/
	for (i = 0; i < IPSEC_MAX_RX_IP_COUNT; i++) {
		uint16_t index = i << 3;
		uint32_t reg = IPSRXIDX_WRITE | IPSRXIDX_TABLE_IP | index;
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(0), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(1), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(2), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(3), 0);
		IXGBE_WAIT_RWRITE;
	}

	/* clear Rx SPI and Rx/Tx SA tables*/
	for (i = 0; i < IPSEC_MAX_SA_COUNT; i++) {
		uint32_t index = i << 3;
		uint32_t reg = IPSRXIDX_WRITE | IPSRXIDX_TABLE_SPI | index;
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXSPI, 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPIDX, 0);
		IXGBE_WAIT_RWRITE;
		reg = IPSRXIDX_WRITE | IPSRXIDX_TABLE_KEY | index;
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXKEY(0), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXKEY(1), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXKEY(2), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXKEY(3), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXSALT, 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXMOD, 0);
		IXGBE_WAIT_RWRITE;
		reg = IPSRXIDX_WRITE | index;
		IXGBE_WRITE_REG(hw, IXGBE_IPSTXKEY(0), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSTXKEY(1), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSTXKEY(2), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSTXKEY(3), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSTXSALT, 0);
		IXGBE_WAIT_TWRITE;
	}
}

static int
ixgbe_crypto_enable_ipsec(struct rte_eth_dev *dev)
{
	struct ixgbe_hw *hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct rte_eth_link link;
	uint32_t reg;

	/* Halt the data paths */
	reg = IXGBE_SECTXCTRL_TX_DIS;
	IXGBE_WRITE_REG(hw, IXGBE_SECTXCTRL, reg);
	reg = IXGBE_SECRXCTRL_RX_DIS;
	IXGBE_WRITE_REG(hw, IXGBE_SECRXCTRL, reg);

	/* Wait for Tx path to empty */
	do {
		rte_eth_link_get_nowait(dev->data->port_id, &link);
		if (link.link_status != ETH_LINK_UP) {
			/* Fix for HSD:4426139
			 * If the Tx FIFO has data but no link,
			 * we can't clear the Tx Sec block. So set MAC
			 * loopback before block clear
			 */
			reg = IXGBE_READ_REG(hw, IXGBE_MACC);
			reg |= IXGBE_MACC_FLU;
			IXGBE_WRITE_REG(hw, IXGBE_MACC, reg);

			reg = IXGBE_READ_REG(hw, IXGBE_HLREG0);
			reg |= IXGBE_HLREG0_LPBK;
			IXGBE_WRITE_REG(hw, IXGBE_HLREG0, reg);
			struct timespec time;
			time.tv_sec = 0;
			time.tv_nsec = 1000000 * 3;
			nanosleep(&time, NULL);
		}

		reg = IXGBE_READ_REG(hw, IXGBE_SECTXSTAT);

		rte_eth_link_get_nowait(dev->data->port_id, &link);
		if (link.link_status != ETH_LINK_UP) {
			reg = IXGBE_READ_REG(hw, IXGBE_MACC);
			reg &= ~(IXGBE_MACC_FLU);
			IXGBE_WRITE_REG(hw, IXGBE_MACC, reg);

			reg = IXGBE_READ_REG(hw, IXGBE_HLREG0);
			reg &= ~(IXGBE_HLREG0_LPBK);
			IXGBE_WRITE_REG(hw, IXGBE_HLREG0, reg);
		}
	} while (!(reg & IXGBE_SECTXSTAT_SECTX_RDY));

	/* Wait for Rx path to empty*/
	do {
		reg = IXGBE_READ_REG(hw, IXGBE_SECRXSTAT);
	} while (!(reg & IXGBE_SECRXSTAT_SECRX_RDY));

	/* Set IXGBE_SECTXBUFFAF to 0x15 as required in the datasheet*/
	IXGBE_WRITE_REG(hw, IXGBE_SECTXBUFFAF, 0x15);

	/* IFG needs to be set to 3 when we are using security. Otherwise a Tx
	 * hang will occur with heavy traffic.
	 */
	reg = IXGBE_READ_REG(hw, IXGBE_SECTXMINIFG);
	reg = (reg & 0xFFFFFFF0) | 0x3;
	IXGBE_WRITE_REG(hw, IXGBE_SECTXMINIFG, reg);

	reg = IXGBE_READ_REG(hw, IXGBE_HLREG0);
	reg |= IXGBE_HLREG0_TXCRCEN | IXGBE_HLREG0_RXCRCSTRP;
	IXGBE_WRITE_REG(hw, IXGBE_HLREG0, reg);

	/* Enable the Tx crypto engine and restart the Tx data path;
	 * set the STORE_FORWARD bit for IPSec.
	 */
	IXGBE_WRITE_REG(hw, IXGBE_SECTXCTRL, IXGBE_SECTXCTRL_STORE_FORWARD);

	/* Enable the Rx crypto engine and restart the Rx data path*/
	IXGBE_WRITE_REG(hw, IXGBE_SECRXCTRL, 0);

	/* Test if crypto was enabled */
	reg = IXGBE_READ_REG(hw, IXGBE_SECTXCTRL);
	if (reg != IXGBE_SECTXCTRL_STORE_FORWARD) {
		PMD_DRV_LOG(ERR, "Error enabling Tx Crypto");
		return -1;
	}
	reg = IXGBE_READ_REG(hw, IXGBE_SECRXCTRL);
	if (reg != 0) {
		PMD_DRV_LOG(ERR, "Error enabling Rx Crypto");
		return -1;
	}

	ixgbe_crypto_clear_ipsec_tables(dev);

	/* create hash table*/
	{
		struct ixgbe_ipsec *internals = IXGBE_DEV_PRIVATE_TO_IPSEC(
				dev->data->dev_private);
		struct rte_hash_parameters params = { 0 };
		params.entries = IPSEC_MAX_SA_COUNT;
		params.key_len = sizeof(uint32_t);
		params.hash_func = rte_jhash;
		params.hash_func_init_val = 0;
		params.socket_id = rte_socket_id();
		params.name = "tx_spi_sai_hash";
		internals->tx_spi_sai_hash = rte_hash_create(&params);
	}

	return 0;
}


static int
ixgbe_crypto_add_sa(struct ixgbe_crypto_session *sess)
{
	struct rte_eth_dev *dev = sess->dev;
	struct ixgbe_hw *hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct ixgbe_ipsec *priv = IXGBE_DEV_PRIVATE_TO_IPSEC(
			dev->data->dev_private);
	uint32_t reg;
	int sa_index = -1;

	if (!(priv->flags & IS_INITIALIZED)) {
		if (ixgbe_crypto_enable_ipsec(dev) == 0)
			priv->flags |= IS_INITIALIZED;
	}

	if (sess->op == IXGBE_OP_AUTHENTICATED_DECRYPTION) {
		int i, ip_index = -1;

		/* Find a match in the IP table*/
		for (i = 0; i < IPSEC_MAX_RX_IP_COUNT; i++) {
			if (CMP_IP(priv->rx_ip_table[i].ip,
				 sess->dst_ip)) {
				ip_index = i;
				break;
			}
		}
		/* If no match, find a free entry in the IP table*/
		if (ip_index < 0) {
			for (i = 0; i < IPSEC_MAX_RX_IP_COUNT; i++) {
				if (priv->rx_ip_table[i].ref_count == 0) {
					ip_index = i;
					break;
				}
			}
		}

		/* Fail if no match and no free entries*/
		if (ip_index < 0) {
			PMD_DRV_LOG(ERR, "No free entry left "
					"in the Rx IP table\n");
			return -1;
		}

		/* Find a free entry in the SA table*/
		for (i = 0; i < IPSEC_MAX_SA_COUNT; i++) {
			if (priv->rx_sa_table[i].used == 0) {
				sa_index = i;
				break;
			}
		}
		/* Fail if no free entries*/
		if (sa_index < 0) {
			PMD_DRV_LOG(ERR, "No free entry left in "
					"the Rx SA table\n");
			return -1;
		}

		priv->rx_ip_table[ip_index].ip.ipv6[0] =
				rte_cpu_to_be_32(sess->dst_ip.ipv6[0]);
		priv->rx_ip_table[ip_index].ip.ipv6[1] =
				rte_cpu_to_be_32(sess->dst_ip.ipv6[1]);
		priv->rx_ip_table[ip_index].ip.ipv6[2] =
				rte_cpu_to_be_32(sess->dst_ip.ipv6[2]);
		priv->rx_ip_table[ip_index].ip.ipv6[3] =
				rte_cpu_to_be_32(sess->dst_ip.ipv6[3]);
		priv->rx_ip_table[ip_index].ref_count++;

		priv->rx_sa_table[sa_index].spi =
				rte_cpu_to_be_32(sess->spi);
		priv->rx_sa_table[sa_index].ip_index = ip_index;
		priv->rx_sa_table[sa_index].key[3] =
				rte_cpu_to_be_32(*(uint32_t *)&sess->key[0]);
		priv->rx_sa_table[sa_index].key[2] =
				rte_cpu_to_be_32(*(uint32_t *)&sess->key[4]);
		priv->rx_sa_table[sa_index].key[1] =
				rte_cpu_to_be_32(*(uint32_t *)&sess->key[8]);
		priv->rx_sa_table[sa_index].key[0] =
				rte_cpu_to_be_32(*(uint32_t *)&sess->key[12]);
		priv->rx_sa_table[sa_index].salt =
				rte_cpu_to_be_32(sess->salt);
		priv->rx_sa_table[sa_index].mode = IPSRXMOD_VALID;
		if (sess->op == IXGBE_OP_AUTHENTICATED_DECRYPTION)
			priv->rx_sa_table[sa_index].mode |=
					(IPSRXMOD_PROTO | IPSRXMOD_DECRYPT);
		if (sess->dst_ip.type == IPv6)
			priv->rx_sa_table[sa_index].mode |= IPSRXMOD_IPV6;
		priv->rx_sa_table[sa_index].used = 1;

		/* write IP table entry*/
		reg = IPSRXIDX_RX_EN | IPSRXIDX_WRITE
				| IPSRXIDX_TABLE_IP | (ip_index << 3);
		if (priv->rx_ip_table[ip_index].ip.type == IPv4) {
			IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(0), 0);
			IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(1), 0);
			IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(2), 0);
			IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(3),
					priv->rx_ip_table[ip_index].ip.ipv4);
		} else {
			IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(0),
					priv->rx_ip_table[ip_index].ip.ipv6[0]);
			IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(1),
					priv->rx_ip_table[ip_index].ip.ipv6[1]);
			IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(2),
					priv->rx_ip_table[ip_index].ip.ipv6[2]);
			IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(3),
					priv->rx_ip_table[ip_index].ip.ipv6[3]);
		}
		IXGBE_WAIT_RWRITE;

		/* write SPI table entry*/
		reg = IPSRXIDX_RX_EN | IPSRXIDX_WRITE
				| IPSRXIDX_TABLE_SPI | (sa_index << 3);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXSPI,
				priv->rx_sa_table[sa_index].spi);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPIDX,
				priv->rx_sa_table[sa_index].ip_index);
		IXGBE_WAIT_RWRITE;

		/* write Key table entry*/
		reg = IPSRXIDX_RX_EN | IPSRXIDX_WRITE
				| IPSRXIDX_TABLE_KEY | (sa_index << 3);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXKEY(0),
				priv->rx_sa_table[sa_index].key[0]);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXKEY(1),
				priv->rx_sa_table[sa_index].key[1]);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXKEY(2),
				priv->rx_sa_table[sa_index].key[2]);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXKEY(3),
				priv->rx_sa_table[sa_index].key[3]);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXSALT,
				priv->rx_sa_table[sa_index].salt);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXMOD,
				priv->rx_sa_table[sa_index].mode);
		IXGBE_WAIT_RWRITE;

	} else { /* sess->dir == RTE_CRYPTO_OUTBOUND */
		int i;

		/* Find a free entry in the SA table*/
		for (i = 0; i < IPSEC_MAX_SA_COUNT; i++) {
			if (priv->tx_sa_table[i].used == 0) {
				sa_index = i;
				break;
			}
		}
		/* Fail if no free entries*/
		if (sa_index < 0) {
			PMD_DRV_LOG(ERR, "No free entry left in "
					"the Tx SA table\n");
			return -1;
		}

		priv->tx_sa_table[sa_index].spi =
				rte_cpu_to_be_32(sess->spi);
		priv->tx_sa_table[sa_index].key[3] =
				rte_cpu_to_be_32(*(uint32_t *)&sess->key[0]);
		priv->tx_sa_table[sa_index].key[2] =
				rte_cpu_to_be_32(*(uint32_t *)&sess->key[4]);
		priv->tx_sa_table[sa_index].key[1] =
				rte_cpu_to_be_32(*(uint32_t *)&sess->key[8]);
		priv->tx_sa_table[sa_index].key[0] =
				rte_cpu_to_be_32(*(uint32_t *)&sess->key[12]);
		priv->tx_sa_table[sa_index].salt =
				rte_cpu_to_be_32(sess->salt);

		reg = IPSRXIDX_RX_EN | IPSRXIDX_WRITE | (sa_index << 3);
		IXGBE_WRITE_REG(hw, IXGBE_IPSTXKEY(0),
				priv->tx_sa_table[sa_index].key[0]);
		IXGBE_WRITE_REG(hw, IXGBE_IPSTXKEY(1),
				priv->tx_sa_table[sa_index].key[1]);
		IXGBE_WRITE_REG(hw, IXGBE_IPSTXKEY(2),
				priv->tx_sa_table[sa_index].key[2]);
		IXGBE_WRITE_REG(hw, IXGBE_IPSTXKEY(3),
				priv->tx_sa_table[sa_index].key[3]);
		IXGBE_WRITE_REG(hw, IXGBE_IPSTXSALT,
				priv->tx_sa_table[sa_index].salt);
		IXGBE_WAIT_TWRITE;

		rte_hash_add_key_data(priv->tx_spi_sai_hash,
				&priv->tx_sa_table[sa_index].spi,
				(void *)(uint64_t)sa_index);
		priv->tx_sa_table[i].used = 1;
		sess->sa_index = sa_index;
	}

	return sa_index;
}

static int
ixgbe_crypto_remove_sa(struct rte_eth_dev *dev,
		     struct ixgbe_crypto_session *sess)
{
	struct ixgbe_hw *hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct ixgbe_ipsec *priv = IXGBE_DEV_PRIVATE_TO_IPSEC(
			dev->data->dev_private);
	uint32_t reg;
	int sa_index = -1;

	if (sess->op == IXGBE_OP_AUTHENTICATED_DECRYPTION) {
		int i, ip_index = -1;

		/* Find a match in the IP table*/
		for (i = 0; i < IPSEC_MAX_RX_IP_COUNT; i++) {
			if (CMP_IP(priv->rx_ip_table[i].ip, sess->dst_ip)) {
				ip_index = i;
				break;
			}
		}

		/* Fail if no match*/
		if (ip_index < 0) {
			PMD_DRV_LOG(ERR, "Entry not found in the Rx IP table\n");
			return -1;
		}

		/* Find a free entry in the SA table*/
		for (i = 0; i < IPSEC_MAX_SA_COUNT; i++) {
			if (priv->rx_sa_table[i].spi ==
					rte_cpu_to_be_32(sess->spi)) {
				sa_index = i;
				break;
			}
		}
		/* Fail if no match*/
		if (sa_index < 0) {
			PMD_DRV_LOG(ERR, "Entry not found in the Rx SA table\n");
			return -1;
		}

		/* Disable and clear Rx SPI and key table table entryes*/
		reg = IPSRXIDX_WRITE | IPSRXIDX_TABLE_SPI | (sa_index << 3);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXSPI, 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPIDX, 0);
		IXGBE_WAIT_RWRITE;
		reg = IPSRXIDX_WRITE | IPSRXIDX_TABLE_KEY | (sa_index << 3);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXKEY(0), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXKEY(1), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXKEY(2), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXKEY(3), 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXSALT, 0);
		IXGBE_WRITE_REG(hw, IXGBE_IPSRXMOD, 0);
		IXGBE_WAIT_RWRITE;
		priv->rx_sa_table[sa_index].used = 0;

		/* If last used then clear the IP table entry*/
		priv->rx_ip_table[ip_index].ref_count--;
		if (priv->rx_ip_table[ip_index].ref_count == 0) {
			reg = IPSRXIDX_WRITE | IPSRXIDX_TABLE_IP
					| (ip_index << 3);
			IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(0), 0);
			IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(1), 0);
			IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(2), 0);
			IXGBE_WRITE_REG(hw, IXGBE_IPSRXIPADDR(3), 0);
		}
		} else { /* sess->dir == RTE_CRYPTO_OUTBOUND */
			int i;

			/* Find a match in the SA table*/
			for (i = 0; i < IPSEC_MAX_SA_COUNT; i++) {
				if (priv->tx_sa_table[i].spi ==
						rte_cpu_to_be_32(sess->spi)) {
					sa_index = i;
					break;
				}
			}
			/* Fail if no match entries*/
			if (sa_index < 0) {
				PMD_DRV_LOG(ERR, "Entry not found in the "
						"Tx SA table\n");
				return -1;
			}
			reg = IPSRXIDX_WRITE | (sa_index << 3);
			IXGBE_WRITE_REG(hw, IXGBE_IPSTXKEY(0), 0);
			IXGBE_WRITE_REG(hw, IXGBE_IPSTXKEY(1), 0);
			IXGBE_WRITE_REG(hw, IXGBE_IPSTXKEY(2), 0);
			IXGBE_WRITE_REG(hw, IXGBE_IPSTXKEY(3), 0);
			IXGBE_WRITE_REG(hw, IXGBE_IPSTXSALT, 0);
			IXGBE_WAIT_TWRITE;

			priv->tx_sa_table[sa_index].used = 0;
			rte_hash_del_key(priv->tx_spi_sai_hash,
					&priv->tx_sa_table[sa_index].spi);
		}

	return 0;
}

static int
ixgbe_crypto_create_session(void *dev,
		struct rte_security_sess_conf *sess_conf,
		struct rte_security_session *sess,
		struct rte_mempool *mempool)
{
	struct ixgbe_crypto_session *session = NULL;
	struct rte_security_ipsec_xform *ipsec_xform = sess_conf->ipsec_xform;

	if (rte_mempool_get(mempool, (void **)&session)) {
		PMD_DRV_LOG(ERR, "Cannot get object from session mempool");
		return -ENOMEM;
	}
	if (ipsec_xform->aead_alg != RTE_CRYPTO_AEAD_AES_GCM) {
		PMD_DRV_LOG(ERR, "Unsupported IPsec mode\n");
		return -ENOTSUP;
	}

	session->op = (ipsec_xform->op == RTE_SECURITY_IPSEC_OP_DECAP) ?
			IXGBE_OP_AUTHENTICATED_DECRYPTION :
			IXGBE_OP_AUTHENTICATED_ENCRYPTION;
	session->key = ipsec_xform->aead_key.data;
	memcpy(&session->salt,
	     &ipsec_xform->aead_key.data[ipsec_xform->aead_key.length], 4);
	session->spi = ipsec_xform->spi;

	if (ipsec_xform->tunnel.type == RTE_SECURITY_IPSEC_TUNNEL_IPV4) {
		uint32_t sip = ipsec_xform->tunnel.ipv4.src_ip.s_addr;
		uint32_t dip = ipsec_xform->tunnel.ipv4.dst_ip.s_addr;
		session->src_ip.type = IPv4;
		session->dst_ip.type = IPv4;
		session->src_ip.ipv4 = rte_cpu_to_be_32(sip);
		session->dst_ip.ipv4 = rte_cpu_to_be_32(dip);

	} else {
		uint32_t *sip = (uint32_t *)&ipsec_xform->tunnel.ipv6.src_addr;
		uint32_t *dip = (uint32_t *)&ipsec_xform->tunnel.ipv6.dst_addr;
		session->src_ip.type = IPv6;
		session->dst_ip.type = IPv6;
		session->src_ip.ipv6[0] = rte_cpu_to_be_32(sip[0]);
		session->src_ip.ipv6[1] = rte_cpu_to_be_32(sip[1]);
		session->src_ip.ipv6[2] = rte_cpu_to_be_32(sip[2]);
		session->src_ip.ipv6[3] = rte_cpu_to_be_32(sip[3]);
		session->dst_ip.ipv6[0] = rte_cpu_to_be_32(dip[0]);
		session->dst_ip.ipv6[1] = rte_cpu_to_be_32(dip[1]);
		session->dst_ip.ipv6[2] = rte_cpu_to_be_32(dip[2]);
		session->dst_ip.ipv6[3] = rte_cpu_to_be_32(dip[3]);
	}

	session->dev = (struct rte_eth_dev *)dev;
	set_sec_session_private_data(sess, 0, session);

	if (ixgbe_crypto_add_sa(session)) {
		PMD_DRV_LOG(ERR, "Failed to add SA\n");
		return -EPERM;
	}

	return 0;
}

static void
ixgbe_crypto_remove_session(void *dev,
		struct rte_security_session *session)
{
	struct ixgbe_crypto_session *sess =
		(struct ixgbe_crypto_session *)
		get_sec_session_private_data(session, 0);
	if (dev != sess->dev) {
		PMD_DRV_LOG(ERR, "Session not bound to this device\n");
		return;
	}

	if (ixgbe_crypto_remove_sa(dev, sess)) {
		PMD_DRV_LOG(ERR, "Failed to remove session\n");
		return;
	}

	rte_free(session);
}

uint64_t
ixgbe_crypto_get_txdesc_flags(uint16_t port_id, struct rte_mbuf *mb) {
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct ixgbe_ipsec *priv =
			IXGBE_DEV_PRIVATE_TO_IPSEC(dev->data->dev_private);
	struct ipv4_hdr *ip4 =
			rte_pktmbuf_mtod_offset(mb, struct ipv4_hdr*,
						sizeof(struct ether_hdr));
	uint32_t spi = 0;
	uintptr_t sa_index;
	struct ixgbe_crypto_tx_desc_metadata mdata = {0};

	if (ip4->version_ihl == 0x45)
		spi = *rte_pktmbuf_mtod_offset(mb, uint32_t*,
					sizeof(struct ether_hdr) +
					sizeof(struct ipv4_hdr));
	else
		spi = *rte_pktmbuf_mtod_offset(mb, uint32_t*,
					sizeof(struct ether_hdr) +
					sizeof(struct ipv6_hdr));

	if (priv->tx_spi_sai_hash &&
			rte_hash_lookup_data(priv->tx_spi_sai_hash, &spi,
					(void **)&sa_index) == 0) {
		mdata.enc = 1;
		mdata.sa_idx = (uint32_t)sa_index;
		mdata.pad_len = *rte_pktmbuf_mtod_offset(mb, uint8_t *,
					rte_pktmbuf_pkt_len(mb) - 18);
	}

	return mdata.data;
}


struct rte_security_ops ixgbe_security_ops = {
		.session_configure = ixgbe_crypto_create_session,
		.session_clear = ixgbe_crypto_remove_session,
};
