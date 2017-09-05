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
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
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

#ifndef IXGBE_IPSEC_H_
#define IXGBE_IPSEC_H_

#include <rte_security.h>

#define IPSRXIDX_RX_EN                                    0x00000001
#define IPSRXIDX_TABLE_IP                                 0x00000002
#define IPSRXIDX_TABLE_SPI                                0x00000004
#define IPSRXIDX_TABLE_KEY                                0x00000006
#define IPSRXIDX_WRITE                                    0x80000000
#define IPSRXIDX_READ                                     0x40000000
#define IPSRXMOD_VALID                                    0x00000001
#define IPSRXMOD_PROTO                                    0x00000004
#define IPSRXMOD_DECRYPT                                  0x00000008
#define IPSRXMOD_IPV6                                     0x00000010
#define IXGBE_ADVTXD_POPTS_IPSEC                          0x00000400
#define IXGBE_ADVTXD_TUCMD_IPSEC_TYPE_ESP                 0x00002000
#define IXGBE_ADVTXD_TUCMD_IPSEC_ENCRYPT_EN               0x00004000
#define IXGBE_RXDADV_IPSEC_STATUS_SECP                    0x00020000
#define IXGBE_RXDADV_IPSEC_ERROR_BIT_MASK                 0x18000000
#define IXGBE_RXDADV_IPSEC_ERROR_INVALID_PROTOCOL         0x08000000
#define IXGBE_RXDADV_IPSEC_ERROR_INVALID_LENGTH           0x10000000
#define IXGBE_RXDADV_IPSEC_ERROR_AUTHENTICATION_FAILED    0x18000000

#define IPSEC_MAX_RX_IP_COUNT           128
#define IPSEC_MAX_SA_COUNT              1024

enum ixgbe_operation {
	IXGBE_OP_AUTHENTICATED_ENCRYPTION, IXGBE_OP_AUTHENTICATED_DECRYPTION
};

enum ixgbe_gcm_key {
	IXGBE_GCM_KEY_128, IXGBE_GCM_KEY_256
};

/**
 * Generic IP address structure
 * TODO: Find better location for this rte_net.h possibly.
 **/
struct ipaddr {
	enum ipaddr_type {
		IPv4, IPv6
	} type;
	/**< IP Address Type - IPv4/IPv6 */

	union {
		uint32_t ipv4;
		uint32_t ipv6[4];
	};
};

/** inline crypto crypto private session structure */
struct ixgbe_crypto_session {
	enum ixgbe_operation op;
	uint8_t *key;
	uint32_t salt;
	uint32_t sa_index;
	uint32_t spi;
	struct ipaddr src_ip;
	struct ipaddr dst_ip;
	struct rte_eth_dev *dev;
} __rte_cache_aligned;

struct ixgbe_crypto_rx_ip_table {
	struct ipaddr ip;
	uint16_t ref_count;
};
struct ixgbe_crypto_rx_sa_table {
	uint32_t spi;
	uint32_t ip_index;
	uint32_t key[4];
	uint32_t salt;
	uint8_t mode;
	uint8_t used;
};

struct ixgbe_crypto_tx_sa_table {
	uint32_t spi;
	uint32_t key[4];
	uint32_t salt;
	uint8_t used;
};

struct ixgbe_crypto_tx_desc_metadata {
	union {
		uint64_t data;
		struct {
			uint32_t sa_idx;
			uint8_t pad_len;
			uint8_t enc;
		};
	};
};

struct ixgbe_ipsec {
#define IS_INITIALIZED (1 << 0)
	uint8_t flags;
	struct ixgbe_crypto_rx_ip_table rx_ip_table[IPSEC_MAX_RX_IP_COUNT];
	struct ixgbe_crypto_rx_sa_table rx_sa_table[IPSEC_MAX_SA_COUNT];
	struct ixgbe_crypto_tx_sa_table tx_sa_table[IPSEC_MAX_SA_COUNT];
	struct rte_hash *tx_spi_sai_hash;
};

extern struct rte_security_ops ixgbe_security_ops;

uint64_t ixgbe_crypto_get_txdesc_flags(uint16_t port_id, struct rte_mbuf *mb);


#endif /*IXGBE_IPSEC_H_*/