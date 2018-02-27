/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#define _GNU_SOURCE

#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>            /* for iovec */
#include <netinet/in.h>

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>

#if DPDK == 1
#include <vnet/devices/dpdk/dpdk.h>
#endif

#include "kni.h"

vnet_device_class_t kni_dev_class;

static u8 * format_kni_interface_name (u8 * s, va_list * args)
{ 
  u32 i = va_arg (*args, u32);
  u32 show_dev_instance = ~0;
  kni_main_t * km = &kni_main;
  
  if (i < vec_len (km->show_dev_instance_by_real_dev_instance))
    show_dev_instance = km->show_dev_instance_by_real_dev_instance[i];
  
  if (show_dev_instance != ~0)
    i = show_dev_instance;
  
  s = format (s, "kni-%d", i);
  return s;
}

static void kni_set_interface_next_node (vnet_main_t *vnm,
                                            u32 hw_if_index,
                                            u32 node_index)
{
  kni_main_t *km = &kni_main;
  kni_interface_t *ki;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);

  ki = vec_elt_at_index (km->kni_interfaces, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      ki->per_interface_next_index = node_index;
      return;
    }

  ki->per_interface_next_index =
    vlib_node_add_next (km->vlib_main, kni_input_node.index, node_index);
}

static_always_inline uword
kni_tx_iface(vlib_main_t * vm,
                vlib_node_runtime_t * node,
                vlib_frame_t * frame,
                kni_interface_t * ki)
{
  u32 * buffers = vlib_frame_args (frame);
  uword n_packets = frame->n_vectors;
  vlib_buffer_t * b;
  u32 n_successful_tx = 0;
  struct rte_mbuf *mb;
  int i = 0;
  u32 total_bytes = 0;

#if 0
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnet_get_main(), ki->sw_if_index);
  if (PREDICT_FALSE(!(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))) {
    //Drop if interface is down
    DBG_KNI ("sw_if_index %d", __LINE__);
    vlib_buffer_free(vm, vlib_frame_vector_args(frame), frame->n_vectors);
    return 0;
  }
#endif
  u32 n_tx = (n_packets > MAX_SEND)?MAX_SEND:n_packets;
  for (i = 0; i < n_tx; i++) {
    struct iovec * iov;
    b = vlib_get_buffer(vm, buffers[i]);

    DBG_KNI ("sw_if_index %d", __LINE__);
    mb = kni_rte_mbuf_from_vlib_buffer (b);
    ki->tx_vector[i] = mb;
  }
    DBG_KNI ("sw_if_index %d", __LINE__);
    n_successful_tx = rte_kni_tx_burst(ki->kni,ki->tx_vector,n_tx);
       if(n_successful_tx < n_tx)
        {
           DBG_KNI ("Only able to TX [%d] out of [%d] ",n_successful_tx, n_tx);
        }
/*
  if (n_tx) {
    int tx;
    if ((tx = sendmmsg(ki->sock_fd, ki->tx_msg, n_tx, MSG_DONTWAIT)) < 1) {
      vlib_increment_simple_counter
      (vnet_main.interface_main.sw_if_counters
       + VNET_INTERFACE_COUNTER_TX_ERROR, os_get_cpu_number(),
       ki->sw_if_index, n_tx);
    } else {
      vlib_increment_combined_counter(
          vnet_main.interface_main.combined_sw_if_counters
          + VNET_INTERFACE_COUNTER_TX,
          os_get_cpu_number(), ki->sw_if_index,
          tx, total_bytes);
    }
  }
*/
  vlib_buffer_free(vm, vlib_frame_vector_args(frame), frame->n_vectors);
  return n_packets;
}

/*
 * kni_tx
 */
static uword
kni_tx (vlib_main_t * vm,
           vlib_node_runtime_t * node,
           vlib_frame_t * frame)
{
  u32 * buffers = vlib_frame_args (frame);
  kni_main_t * km = &kni_main;
  kni_interface_t * ki = NULL;
  u32 tx_hw_if_index = 0;
  vnet_sw_interface_t *sw = NULL;
  vnet_hw_interface_t *hw = NULL;
  u8 *ki_index = NULL;
  if (!frame->n_vectors)
    return 0;

  vlib_buffer_t *b = vlib_get_buffer(vm, buffers[0]);
  u32 tx_sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_TX];
  if (tx_sw_if_index == (u32)~0)
    tx_sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_RX];

  ASSERT(tx_sw_if_index != (u32)~0);

    ki_index = hash_get(km->kni_interface_index_by_sw_if_index,tx_sw_if_index);
    ki = vec_elt_at_index (km->kni_interfaces, *ki_index);
     DBG_KNI("check index tx_sw_if_index[%d] *ki_index[%d] ", tx_sw_if_index,
							*ki_index);
   if(ki)
     return kni_tx_iface(vm, node, frame, ki);
   else{
     DBG_KNI("Error index [%d] ", tx_sw_if_index);
     return 0;
       }
}

VLIB_REGISTER_NODE (kni_tx_node,static) = {
  .function = kni_tx,
  .name = "kni-tx",
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = 4,
};

static clib_error_t *
kni_interface_add_del_function(vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
	DBG_KNI ("Calling kni_interface_add_del_function hw_if_index[%d] ",hw_if_index);
	return 0;

}
/* 
 * Mainly exists to set link_state == admin_state
 * otherwise, e.g. ip6 neighbor discovery breaks
 */
static clib_error_t *
kni_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  DBG_KNI ("Calling kni_admin_up_down_function hw_if_index[%d] ",hw_if_index);
  uword is_admin_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  u32 hw_flags;
  u32 speed_duplex = VNET_HW_INTERFACE_FLAG_FULL_DUPLEX
    | VNET_HW_INTERFACE_FLAG_SPEED_40G;

  if (is_admin_up)
    hw_flags = VNET_HW_INTERFACE_FLAG_LINK_UP | speed_duplex;
  else
    hw_flags = speed_duplex;

  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);
  return 0;
}

VNET_DEVICE_CLASS (kni_dev_class) = {
  .name = "kni",
  .tx_function = kni_tx,
  .format_device_name = format_kni_interface_name,
  .rx_redirect_to_node = kni_set_interface_next_node,
  .admin_up_down_function = kni_interface_admin_up_down,
  .interface_add_del_function= kni_interface_add_del_function,
};

