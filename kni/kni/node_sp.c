/*
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/plugin/plugin.h>
#include "kni.h"
typedef struct {
  u32 next_index;
  u32 sw_if_index;
  u32 kni_if_index;
} slowpath_trace_t;

/* packet trace format function */
static u8 * format_slowpath_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  slowpath_trace_t * t = va_arg (*args, slowpath_trace_t *);
  
  s = format (s, "SLOWPATH: sw_if_index %d, next index %d\n",
              t->sw_if_index, t->next_index);
  s = format (s, " outgoing KNI interface index %d",
              t->kni_if_index);

  return s;
}

vlib_node_registration_t slowpath_node;

#define foreach_slowpath_error \
_(KNI, "packets processed")

typedef enum {
#define _(sym,str) SLOWPATH_ERROR_##sym,
  foreach_slowpath_error
#undef _
  SLOWPATH_N_ERROR,
} slowpath_error_t;

static char * slowpath_error_strings[] = {
#define _(sym,string) string,
  foreach_slowpath_error
#undef _
};

typedef enum {
  SLOWPATH_NEXT_INTERFACE_OUTPUT,
  SLOWPATH_NEXT_ETHERNET_INTPUT,
  SLOWPATH_N_NEXT,
} slowpath_next_t;

static uword
slowpath_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  kni_main_t * km = &kni_main;
  u32 n_left_from, * from, * to_next;
  slowpath_next_t next_index;
  u32 pkts_frwrded = 0;
  //clib_warning ("Returning from slowpath_node_fn ");
  //return 0;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);
#if 0
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 next0 = SLOWPATH_NEXT_INTERFACE_OUTPUT;
          u32 next1 = SLOWPATH_NEXT_INTERFACE_OUTPUT;
          u32 sw_if_index0, sw_if_index1;
	  u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
	  u8 *pbi0 , *pbi1;
          

          /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = b0 = from[0];
	  to_next[1] = b1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

          ASSERT (b0->current_data == 0);
          ASSERT (b1->current_data == 0);
          
          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
	  clib_warning("Value of sw_if_index0 [%d],sw_if_index1[%d]",sw_if_index0,sw_if_index1);
	  pbi0 = hash_get(km->kni_interface_index_by_sw_if_index,sw_if_index0);
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = *pbi0;
	  pbi1 = hash_get(km->kni_interface_index_by_sw_if_index,sw_if_index1);
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = *pbi1;
	  clib_warning("Value of sw_if_index0 [%d],pbi0[%p]",sw_if_index0,pbi0);
	  clib_warning("Value of sw_if_index0 [%d],*pbi0[%d]",sw_if_index0,*pbi0);
     
          /* Send pkt back out the RX interface */

          pkts_frwrded += 2;

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    slowpath_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                    t->kni_if_index = *pbi0; //next0;
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    slowpath_trace_t *t = 
                      vlib_add_trace (vm, node, b1, sizeof (*t));
                    t->sw_if_index = sw_if_index1;
                    t->next_index = next1;
                    t->kni_if_index =*pbi1; //next0;
                  }
              }
            
            /* verify speculative enqueues, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, bi1, next0, next1);
        }
#endif
      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0 = SLOWPATH_NEXT_INTERFACE_OUTPUT;
          u32 sw_if_index0;
	 u8 *pbi0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  if(unlikely(!sw_if_index0)) {
		next0 = SLOWPATH_NEXT_ETHERNET_INTPUT;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
           continue;
	}
	  clib_warning("Value of sw_if_index0 [%d]",sw_if_index0);
	  pbi0 = hash_get(km->kni_interface_index_by_sw_if_index,sw_if_index0);
	  clib_warning("Value of sw_if_index0 [%d],pbi0[%p]",sw_if_index0,pbi0);
	  clib_warning("Value of sw_if_index0 [%d],*pbi0[%d]",sw_if_index0,*pbi0);
          /* Send pkt back out the RX interface */
          //vnet_buffer(b0)->sw_if_index[VLIB_TX] = *pbi0;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = 3;/*FIXME*/

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            slowpath_trace_t *t = 
               vlib_add_trace (vm, node, b0, sizeof (*t));
            t->sw_if_index = sw_if_index0;
            t->next_index = next0;
            t->kni_if_index = *pbi0; //next0;
            }
            
          pkts_frwrded += 1;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, slowpath_node.index, 
                               SLOWPATH_ERROR_KNI, pkts_frwrded);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (slowpath_node) = {
  .function = slowpath_node_fn,
  .name = "slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_slowpath_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(slowpath_error_strings),
  .error_strings = slowpath_error_strings,

  .n_next_nodes = SLOWPATH_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [SLOWPATH_NEXT_INTERFACE_OUTPUT] = "interface-output",
        [SLOWPATH_NEXT_ETHERNET_INTPUT] = "ethernet-input",
  },
};


/**
 *  * @brief Hook the slowpath plugin into the VPP graph hierarchy.
 *   */
VNET_FEATURE_INIT (slowpath, static) =
{
  .arc_name = "device-input",
  .node_name = "slowpath",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

