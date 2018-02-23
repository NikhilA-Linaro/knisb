/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>

#include <vnet/ip/ip.h>

#if DPDK == 1
#include <vnet/devices/dpdk/dpdk.h>
#endif

#include <kni/kni.h>

vlib_node_registration_t kni_input_node;

enum {
  KNI_RX_NEXT_INTERFACE_OUTPUT,
  KNI_RX_N_NEXT,
};

typedef struct {
  u16 sw_if_index;
} kni_input_trace_t;

u8 * format_kni_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  vnet_main_t * vnm = vnet_get_main();
  kni_input_trace_t * t = va_arg (*va, kni_input_trace_t *);
  s = format (s, "%U", format_vnet_sw_if_index_name,
                vnm, t->sw_if_index);
  return s;
}

always_inline void
buffer_add_to_chain(vlib_main_t *vm, u32 bi, u32 first_bi, u32 prev_bi)
{
  vlib_buffer_t * b = vlib_get_buffer (vm, bi);
  vlib_buffer_t * first_b = vlib_get_buffer (vm, first_bi);
  vlib_buffer_t * prev_b = vlib_get_buffer (vm, prev_bi);

  /* update first buffer */
  first_b->total_length_not_including_first_buffer +=  b->current_length;

  /* update previous buffer */
  prev_b->next_buffer = bi;
  prev_b->flags |= VLIB_BUFFER_NEXT_PRESENT;

  /* update current buffer */
  b->next_buffer = 0;

#if DPDK > 0
  struct rte_mbuf * mbuf = rte_mbuf_from_vlib_buffer(b);
  struct rte_mbuf * first_mbuf = rte_mbuf_from_vlib_buffer(first_b);
  struct rte_mbuf * prev_mbuf = rte_mbuf_from_vlib_buffer(prev_b);
  first_mbuf->nb_segs++;
  prev_mbuf->next = mbuf;
  mbuf->data_len = b->current_length;
  mbuf->data_off = RTE_PKTMBUF_HEADROOM + b->current_data;
  mbuf->next = 0;
#endif
}
static inline u32
kni_input_burst(kni_interface_t * ki)
{
  u32 n_buffers;
  u32 n_left;
  u32 n_this_chunk;

  n_left = MAX_RECV;
  n_buffers = 0;

      while (n_left)
        {
          n_this_chunk = rte_kni_rx_burst(ki->kni, ki->rx_vector + n_buffers, n_left);
          n_buffers += n_this_chunk;
          n_left -= n_this_chunk;
        //   rte_kni_handle_request(xd->kni);
          /* Empirically, DPDK r1.8 produces vectors w/ 32 or fewer elts */
          if (n_this_chunk < 32)
            break;
        }
  return n_buffers;
}

static uword
kni_input_iface(vlib_main_t * vm,
           vlib_node_runtime_t * node,
           kni_interface_t * ki)
{
	kni_main_t * km = &kni_main;
	u32 n_buffers;
	unsigned num;
	u32 mb_index;
	uword n_rx_bytes = 0;
        rte_kni_handle_request(ki->kni);

	//  const uword buffer_size = vlib_buffer_free_list_buffer_size ( vm,
	//                                VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
	/*  u32 n_trace = vlib_get_trace_count (vm, node);
	    u8 set_trace = 0;
	    */
	vnet_main_t *vnm;
	vnet_sw_interface_t * si;
	u8 admin_down;
	uword len = 0;
	u32 next_index =  KNI_RX_NEXT_INTERFACE_OUTPUT;
	u32 n_left_to_next, *to_next;
	vlib_buffer_free_list_t *fl;
	 //clib_warning ("Entering kni_input_iface");
	vnm = vnet_get_main();

	n_buffers = kni_input_burst(ki);

	if (n_buffers == 0)
	{
		return 0;
	}

	fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

	/* Update buffer template */
	//vnet_buffer (bt)->sw_if_index[VLIB_RX] = ki->sw_if_index;

	while (n_buffers > 0 )
	{
		vlib_buffer_t *b0;
		u32 bi0, next0;
		u8 error0;
		i16 offset0;

		vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
		while (n_buffers > 0 && n_left_to_next > 0)
		{
			struct rte_mbuf *mb0 = ki->rx_vector[mb_index];

			ASSERT (mb0);

			b0 = kni_vlib_buffer_from_rte_mbuf (mb0);
			clib_warning("RX hw_if_index[VLIB_RX] [%d] Tx hw_if_index[VLIB_TX] [%d]",ki->hw_if_index,
								ki->eth_hw_if_index);
			vnet_buffer (b0)->sw_if_index[VLIB_RX] = ki->hw_if_index;
			vnet_buffer (b0)->sw_if_index[VLIB_TX] = ki->eth_hw_if_index;
			//b0->buffer_pool_index =;/*TODO*/
			/* Prefetch one next segment if it exists. */

			bi0 = vlib_get_buffer_index (vm, b0);

			to_next[0] = bi0;
			to_next++;
			n_left_to_next--;

			next0 = KNI_RX_NEXT_INTERFACE_OUTPUT;

			b0->current_data = mb0->data_off - RTE_PKTMBUF_HEADROOM;
			b0->flags |= 0;
			b0->current_length = mb0->data_len;
			n_rx_bytes += mb0->pkt_len;

			VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

			/* Do we have any driver RX features configured on the interface? */
//			vnet_feature_start_device_input_x1 (xd->vlib_sw_if_index, &next0,
//			                                     b0);

			vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					to_next, n_left_to_next,
					bi0, next0);
			n_buffers--;
			mb_index++;
		}
		vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	}

	return mb_index;

}

static uword
kni_input (vlib_main_t * vm,
           vlib_node_runtime_t * node,
           vlib_frame_t * frame)
{
  kni_main_t * km = &kni_main;
  kni_interface_t * ki;
  int i;
  u32 total_count = 0;

  for (i = 0; i < vec_len(km->kni_interfaces); i++)
    {

      ki = vec_elt_at_index (km->kni_interfaces, i);
      total_count += kni_input_iface(vm, node, ki);
    }
  return total_count; //This might return more than 256.

/*  static u32 * ready_interface_indices;

  vec_reset_length (ready_interface_indices);
  clib_bitmap_foreach (i, km->pending_read_bitmap,
  ({
    vec_add1 (ready_interface_indices, i);
  }));

  if (vec_len (ready_interface_indices) == 0)
    return 0;

  for (i = 0; i < vec_len(ready_interface_indices); i++)
    {
      km->pending_read_bitmap =
        clib_bitmap_set (km->pending_read_bitmap,
                         ready_interface_indices[i], 0);

      ki = vec_elt_at_index (km->kni_interfaces, ready_interface_indices[i]);
      total_count += kni_input_iface(vm, node, ki);
    }
  return total_count; //This might return more than 256.
*/
}

static char * kni_input_error_strings[] = {
#define _(sym,string) string,
  foreach_kni_error
#undef _
};

VLIB_REGISTER_NODE (kni_input_node) = {
  .function = kni_input,
  .name = "kni-rx",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
  .vector_size = 4,
  .n_errors = KNI_N_ERROR,
  .error_strings = kni_input_error_strings,
  .format_trace = format_kni_input_trace,

  .n_next_nodes = KNI_RX_N_NEXT,
  .next_nodes = {
    [KNI_RX_NEXT_INTERFACE_OUTPUT] = "interface-output",
  },
};

