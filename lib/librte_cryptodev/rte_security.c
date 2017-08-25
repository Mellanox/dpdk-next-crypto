/*-
 *   BSD LICENSE
 *
 *   Copyright 2017 NXP.
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
 *     * Neither the name of NXP nor the names of its
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

#include <rte_log.h>
#include <rte_debug.h>
#include <rte_dev.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_launch.h>
#include <rte_common.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_errno.h>

#include "rte_crypto.h"
#include "rte_cryptodev_pmd.h"
#include "rte_security.h"
#include "rte_ethdev.h"
#include "rte_cryptodev.h"


struct rte_security_session *
rte_security_session_create(struct rte_mempool *mp)
{
	struct rte_security_session *sess;

	/* Allocate a session structure from the session pool */
	if (rte_mempool_get(mp, (void *)&sess)) {
		CDEV_LOG_ERR("couldn't get object from session mempool");
		return NULL;
	}

	/* Clear device session pointer */
	memset(sess, 0, (sizeof(void *) *
		RTE_MAX(rte_eth_dev_count(), rte_cryptodev_count())));

	return sess;
}

int
rte_security_session_init(uint16_t dev_id,
			  struct rte_security_session *sess,
			  struct rte_security_sess_conf *conf,
			  struct rte_mempool *mp)
{
	struct rte_cryptodev *cdev = NULL;
	struct rte_eth_dev *dev = NULL;
	uint8_t index;
	int ret;

	if (sess == NULL || conf == NULL)
		return -EINVAL;

	switch (conf->action_type) {
	case RTE_SECURITY_SESS_CRYPTO_PROTO_OFFLOAD:
		if (!rte_cryptodev_pmd_is_valid_dev(dev_id))
			return -EINVAL;
		cdev = rte_cryptodev_pmd_get_dev(dev_id);
		index = cdev->driver_id;
		if (cdev == NULL || sess == NULL || cdev->sec_ops == NULL
				|| cdev->sec_ops->session_configure == NULL)
			return -EINVAL;
		if (sess->sess_private_data[index] == NULL) {
			ret = cdev->sec_ops->session_configure((void *)cdev,
					conf, sess, mp);
			if (ret < 0) {
				CDEV_LOG_ERR(
					"cdev_id %d failed to configure session details",
					dev_id);
				return ret;
			}
		}
		break;
	case RTE_SECURITY_SESS_ETH_INLINE_CRYPTO:
	case RTE_SECURITY_SESS_ETH_PROTO_OFFLOAD:
		dev = &rte_eth_devices[dev_id];
		index = dev->data->port_id;
		if (dev == NULL || sess == NULL || dev->sec_ops == NULL
				|| dev->sec_ops->session_configure == NULL)
			return -EINVAL;
		if (sess->sess_private_data[index] == NULL) {
			ret = dev->sec_ops->session_configure((void *)dev,
					conf, sess, mp);
			if (ret < 0) {
				CDEV_LOG_ERR(
					"dev_id %d failed to configure session details",
					dev_id);
				return ret;
			}
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int
rte_security_session_free(struct rte_security_session *sess)
{
	uint8_t i, nb_drivers = RTE_MAX(rte_eth_dev_count(),
					rte_cryptodev_count());
	void *sess_priv;
	struct rte_mempool *sess_mp;

	if (sess == NULL)
		return -EINVAL;

	/* Check that all device private data has been freed */
	for (i = 0; i < nb_drivers; i++) {
		sess_priv = get_sec_session_private_data(sess, i);
		if (sess_priv != NULL)
			return -EBUSY;
	}

	/* Return session to mempool */
	sess_mp = rte_mempool_from_obj(sess);
	rte_mempool_put(sess_mp, sess);

	return 0;
}

int
rte_security_session_clear(uint8_t dev_id,
		enum rte_security_session_action_type action_type,
		struct rte_security_session *sess)
{
	struct rte_cryptodev *cdev = NULL;
	struct rte_eth_dev *dev = NULL;
	switch (action_type) {
	case RTE_SECURITY_SESS_CRYPTO_PROTO_OFFLOAD:
		cdev =  rte_cryptodev_pmd_get_dev(dev_id);
		if (cdev == NULL || sess == NULL || cdev->sec_ops == NULL
				|| cdev->sec_ops->session_clear == NULL)
			return -EINVAL;
		cdev->sec_ops->session_clear((void *)cdev, sess);
		break;
	case RTE_SECURITY_SESS_ETH_INLINE_CRYPTO:
	case RTE_SECURITY_SESS_ETH_PROTO_OFFLOAD:
		dev = &rte_eth_devices[dev_id];
		if (dev == NULL || sess == NULL || dev->sec_ops == NULL
				|| dev->sec_ops->session_clear == NULL)
		dev->sec_ops->session_clear((void *)dev, sess);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}
