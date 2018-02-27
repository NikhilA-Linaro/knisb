/* 
 *------------------------------------------------------------------
 * kni.c - KNI based slowpath.
 *
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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <vnet/ip/ip.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include "kni.h"
#include <rte_config.h>
#include <rte_kni.h>

/*KNI MAIN database*/
kni_main_t kni_main;

static uword
kni_process(vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
	clib_error_t * error = 0;
	u32 i=0;
	DBG_KNI ("Returning from kni_process");
	return error;
#if 0
	u32 i =0;
	struct rte_kni_conf conf;
	kni_main_t * km = &kni_main;
	dpdk_main_t * dm = &dpdk_main;
	kni_interface_t *ki = NULL;
	  struct rte_kni_ops ops;
	//  struct rte_eth_dev_info dev_info;


	km->vlib_main = vm;
	km->vnet_main = vnet_get_main();
	km->unix_main = &unix_main;
	km->dpdk_main = &dpdk_main;
	km->kni_interface_index_by_sw_if_index = hash_create (0, sizeof(uword));
	km->kni_interface_index_by_eth_index = hash_create (0, sizeof (uword));
	km->num_kni_interfaces=0;
	vnet_hw_interface_t *hi;
	pool_foreach (hi, dm->vnet_main->interface_main.hw_interfaces, ({

	vec_add2 (km->kni_interfaces, ki, 1);
	ki->sw_if_index = ki - km->kni_interfaces ;
	ki->eth_sw_if_index = hi->sw_if_index;
	ki->eth_hw_if_index = hi->hw_if_index;
	DBG_KNI ("hw_if_index %d sw_if_index %d",hi->hw_if_index,
					hi->sw_if_index);
	hash_set(km->kni_interface_index_by_sw_if_index,hi->sw_if_index,ki->sw_if_index);
	hash_set(km->kni_interface_index_by_eth_index,ki->sw_if_index,hi->sw_if_index);/*FIXME: Name of the has needs to be change to ethInterfaceByKniInterface*/

	km->num_kni_interfaces++;

	}));

	rte_kni_init(km->num_kni_interfaces);
	for (i = 0; i< km->num_kni_interfaces; i++)
	{
		memset(&ops, 0, sizeof(ops));
		ops.port_id = i;
		ops.change_mtu = kni_change_mtu;
	        DBG_KNI ("Registering kni_config_network_interface");
        	ops.config_network_if = kni_config_network_interface;

		ki = vec_elt_at_index(km->kni_interfaces, i);
		memset(&conf, 0, sizeof(conf));
		snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", i);
		conf.group_id = i;
		conf.mbuf_size = 2048;
		ki->kni = rte_kni_alloc(dm->pktmbuf_pools[0], &conf,  NULL);
		u8 hw_addr[6];
		{/*Generating dummy Mac Address*/
			f64 now = vlib_time_now (vm);
			u32 rnd;
			rnd = (u32) (now * 1e6);
			rnd = random_u32 (&rnd);
			memcpy (hw_addr + 2, &rnd, sizeof (rnd));
			hw_addr[0] = 2;
			hw_addr[1] = 0xfe;
		}
		error = ethernet_register_interface
			(km->vnet_main,
			 kni_dev_class.index,
			 ki - km->kni_interfaces /* device instance */,
			 hw_addr /* ethernet address */,
			 &ki->hw_if_index, kni_flag_change);
		DBG_KNI ("Called ethernet_register_interface ,ret [%d] got hw_if_index [%d] ",
				error,
				ki->hw_if_index);


	}
	/*	uword *event_data=0;
		uword event_type;
		while(1)
		{
		DBG_KNI ("Waiting for the event");
		vlib_process_wait_for_event (vm);
		event_type = vlib_process_get_events(vm,&event_data);
		DBG_KNI ("event_type[%d] event_data[%d]", event_type,event_data[0]);
		}
		*/
#endif
	return error;

}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (kni_process_node,static) = {
    .function = kni_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "kni-process",
};
/* *INDENT-ON* */





clib_error_t *kni_init(vlib_main_t *vm)
{
	clib_error_t * error = 0;
	kni_main_t * km = &kni_main;
//	dpdk_main_t * dm = &dpdk_main;
	u32 i = 0;
	km->vlib_main = vm;
	km->vnet_main = vnet_get_main();
//	km->dpdk_main = &dpdk_main;
	km->is_disabled = 1;
	DBG_KNI("\n Entered \n");
	/* main thread 1st */

	return error;
}
VLIB_INIT_FUNCTION(kni_init);
/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = "KNI.1.0",
    .description = "KNI SLOWPATH (KNI)",
};
/* *INDENT-ON* */
