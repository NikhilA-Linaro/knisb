/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE

#include <sys/socket.h>
#include <vlib/vlib.h>
#include <dpdk/device/dpdk.h>

#ifndef __KNI_H__
#define __KNI_H__

#define KNI_DEBUG_LOG 0


#if KNI_DEBUG_LOG == 1
#define DBG_KNI(args...) clib_warning(args);
#else
#define DBG_KNI(args...)
#endif



#define MAX_SEND 256
#define MAX_RECV 256

#define NB_MBUF_KNI   (2048)

#define foreach_kni_error                            \
  /* Must be first. */                                  \
 _(NONE, "no error")                                    \
 _(READ, "read error")                                  \
 _(BUFFER_ALLOCATION, "buffer allocation error")	\
 _(UNKNOWN, "unknown error")

#define kni_vlib_buffer_from_rte_mbuf(x) ((vlib_buffer_t *)(x+1))
#define kni_rte_mbuf_from_vlib_buffer(x) (((struct rte_mbuf *)x) - 1)

typedef enum {
#define _(sym,str) KNI_ERROR_##sym,
  foreach_kni_error
#undef _
   KNI_N_ERROR,
 } kni_error_t;

typedef struct {
  u32 sw_if_index;              /* for counters */
  u32 hw_if_index;
  u32 eth_sw_if_index;              /* for counters */
  u32 eth_hw_if_index;
  struct rte_kni *kni;
  u32 is_promisc;
  u32 per_interface_next_index;
  u8 active;                    /* for delete */

  char mac_addr[ETHER_ADDR_LEN]; /* MAC address assigned to KNI */

  struct rte_mbuf *rx_vector[MAX_RECV];
  struct rte_mbuf *tx_vector[MAX_SEND];
} kni_interface_t;

typedef struct {
  /* Vector of VLIB rx buffers to use. */
  u32 * rx_buffers;

  /* record and put back unused rx buffers */
  u32 * unused_buffer_list;

  /*  Default MTU for newly created kni interface. */
  u32 mtu_bytes;

  /* Number of kni interfaces */
  u32 num_kni_interfaces;

  /* Vector of kni interfaces */
  kni_interface_t * kni_interfaces;

  /* Bitmap of kni interfaces with pending reads */
  uword * pending_read_bitmap;

  /* Hash table to find kni interface given hw_if_index */
  uword * kni_interface_index_by_sw_if_index;

  /* Hash table to find kni interface given ethernet */
  uword * kni_interface_index_by_eth_index;

  /* renumbering table */
  u32 * show_dev_instance_by_real_dev_instance;

    /* mempool */
  struct rte_mempool **pktmbuf_pools;

  /* 1 => disable CLI */
  int is_disabled;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
//  dpdk_main_t * dpdk_main;
} kni_main_t;

typedef struct
{
  /* must be first */
  struct rte_pktmbuf_pool_private mbp_priv;
  u8 buffer_pool_index;
} kni_mempool_private_t;




extern vnet_device_class_t kni_dev_class;
extern vlib_node_registration_t kni_input_node;
extern kni_main_t kni_main;

#endif
