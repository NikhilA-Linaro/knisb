/* 
 *------------------------------------------------------------------
 * turbotap.c - fast dynamic tap interface hookup
 *
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

//#include <fcntl.h>              /* for open */
//#include <sys/ioctl.h>
//#include <sys/socket.h>
//#include <sys/stat.h>
//#include <sys/types.h>
//#include <sys/uio.h>            /* for iovec */
//#include <netinet/in.h>

//#include <linux/if_arp.h>
//#include <linux/if_tun.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <vnet/ip/ip.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include "kni.h"
#include <rte_config.h>
#include <rte_kni.h>


kni_main_t kni_main;
static void
turbotap_nopunt_frame (vlib_main_t * vm,
                   vlib_node_runtime_t * node,
                   vlib_frame_t * frame)
{
  u32 * buffers = vlib_frame_args (frame);
  uword n_packets = frame->n_vectors;
  vlib_buffer_free (vm, buffers, n_packets);
  vlib_frame_free (vm, node, frame);
}

#if 0
/* Gets called when file descriptor is ready from epoll. */
static clib_error_t * turbotap_read_ready (unix_file_t * uf)
{
  vlib_main_t * vm = vlib_get_main();
  kni_main_t * km = &kni_main;
  uword * p;

  /* Schedule the rx node */
  vlib_node_set_interrupt_pending (vm, turbotap_rx_node.index);

  p = hash_get (km->turbotap_interface_index_by_unix_fd, uf->file_descriptor);

  /* Mark the specific tap interface ready-to-read */
  if (p)
    km->pending_read_bitmap = clib_bitmap_set (km->pending_read_bitmap,
                                               p[0], 1);
  else
    clib_warning ("fd %d not in hash table", uf->file_descriptor);

  return 0;
}

static clib_error_t *
turbotap_config (vlib_main_t * vm, unformat_input_t * input)
{ 
  kni_main_t *km = &kni_main;
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    { 
      if (unformat (input, "mtu %d", &km->mtu_bytes))
        ;
      else if (unformat (input, "disable"))
        km->is_disabled = 1;
      else
          return clib_error_return (0, "unknown input `%U'",
                                    format_unformat_error, input);
    }
  
  if (km->is_disabled)
    return 0;
  
  if (geteuid())
    { 
      clib_warning ("turbotap disabled: must be superuser");
      km->is_disabled = 1;
      return 0;
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (turbotap_config, "turbotap");

static u32 turbotap_flag_change (vnet_main_t * vnm,
                               vnet_hw_interface_t * hw,
                               u32 flags)
{ 
  kni_main_t *km = &kni_main;
  kni_interface_t *ti;
   
   ti = vec_elt_at_index (km->kni_interfaces, hw->dev_instance);
  
  if (flags & ETHERNET_INTERFACE_FLAG_MTU)
    { 
      const uword buffer_size = vlib_buffer_free_list_buffer_size ( vlib_get_main(),
                                    VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
      ti->mtu_bytes = hw->max_packet_bytes;
      ti->mtu_buffers = (hw->max_packet_bytes + (buffer_size - 1)) / buffer_size;
    }
   else
    { 
      skmuct ifreq ifr;
      u32 want_promisc;
      
      memcpy (&ifr, &ti->ifr, sizeof (ifr));
      
      /* get flags, modify to bring up interface... */ 
      if (ioctl (ti->provision_fd, SIOCGIFFLAGS, &ifr) < 0)
        { 
          clib_unix_warning ("Couldn't get interface flags for %s", hw->name);
          return 0;
        }
      
      want_promisc = (flags & ETHERNET_INTERFACE_FLAG_ACCEPT_ALL) != 0;
      
      if (want_promisc == ti->is_promisc)
        return 0;
      
      if (flags & ETHERNET_INTERFACE_FLAG_ACCEPT_ALL)
        ifr.ifr_flags |= IFF_PROMISC;
      else
        ifr.ifr_flags &= ~(IFF_PROMISC);
      
      /* get flags, modify to bring up interface... */ 
      if (ioctl (ti->provision_fd, SIOCSIFFLAGS, &ifr) < 0)
        { 
          clib_unix_warning ("Couldn't set interface flags for %s", hw->name);
          return 0;
        }
      
      ti->is_promisc = want_promisc;
    }
  
  return 0;
}

/* get tap interface from inactive interfaces or create new */
static kni_interface_t *turbotap_get_new_tapif()
{ 
  kni_main_t * km = &kni_main;
  kni_interface_t *ti = NULL;
  
  int inactive_cnt = vec_len(km->turbotap_inactive_interfaces);
  // if there are any inactive ifaces
  if (inactive_cnt > 0) {
    // take last
    u32 ti_idx = km->turbotap_inactive_interfaces[inactive_cnt - 1];
    if (vec_len(km->kni_interfaces) > ti_idx) {
      ti = vec_elt_at_index (km->kni_interfaces, ti_idx);
      clib_warning("reusing tap interface");
    }
    // "remove" from inactive list
    _vec_len(km->turbotap_inactive_interfaces) -= 1;
  }

  // ti was not rekmieved from inactive ifaces - create new
  if (!ti)
    {
      vec_add2 (km->kni_interfaces, ti, 1);
      u32 i;

      for (i = 0; i < MAX_RECV; i++)
        {
          ti->rx_msg[i].msg_hdr.msg_name = NULL;
          ti->rx_msg[i].msg_hdr.msg_namelen = 0;
          ti->rx_msg[i].msg_hdr.msg_control = NULL;
          ti->rx_msg[i].msg_hdr.msg_controllen = 0;
        }
    }
  return ti;
}

int vnet_turbotap_connect (vlib_main_t * vm, u8 * intfc_name, u8 *hwaddr_arg,
                      u32 * sw_if_indexp)
{
  kni_main_t * tr = &kni_main;
  kni_interface_t * ti = NULL;
  struct ifreq ifr;
  int flags;
  int dev_net_tun_fd;
  int dev_tap_fd = -1;
  int turbotap_fd = -1;
  int sock_fd = -1;
  clib_error_t * error;
  u8 hwaddr [6];
  int rv = 0;

  if (tr->is_disabled)
    {
      return VNET_API_ERROR_FEATURE_DISABLED;
    }

  flags = IFF_TAP | IFF_NO_PI;

  if ((turbotap_fd = open ("/dev/net/turbotap", O_RDWR)) < 0)
      return VNET_API_ERROR_SYSCALL_ERROR_1;

  if ((dev_net_tun_fd = open ("/dev/net/tun", O_RDWR)) < 0)
    return VNET_API_ERROR_SYSCALL_ERROR_1;

  memset (&ifr, 0, sizeof (ifr));
  strncpy(ifr.ifr_name, (char *) intfc_name, sizeof (ifr.ifr_name)-1);
  ifr.ifr_flags = flags;
  if (ioctl (dev_net_tun_fd, TUNSETIFF, (void *)&ifr) < 0)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      goto error;
    }

  /* Open a provisioning socket */
  if ((dev_tap_fd = socket(PF_PACKET, SOCK_RAW,
                           htons(ETH_P_ALL))) < 0 )
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_3;
      goto error;
    }

  /* Find the interface index. */
  {
    struct ifreq ifr;
    struct sockaddr_ll sll;

    memset (&ifr, 0, sizeof(ifr));
    strncpy (ifr.ifr_name, (char *) intfc_name, sizeof (ifr.ifr_name)-1);
    if (ioctl (dev_tap_fd, SIOCGIFINDEX, &ifr) < 0 )
      {
        rv = VNET_API_ERROR_SYSCALL_ERROR_4;
        goto error;
      }

    /* Bind the provisioning socket to the interface. */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(dev_tap_fd, (struct sockaddr*) &sll, sizeof(sll)) < 0)
      {
        rv = VNET_API_ERROR_SYSCALL_ERROR_5;
        goto error;
      }
  }

  /* non-blocking I/O on /dev/tapX */
  {
    int one = 1;
    if (ioctl (dev_net_tun_fd, FIONBIO, &one) < 0)
      {
        rv = VNET_API_ERROR_SYSCALL_ERROR_6;
        goto error;
      }
  }
  ifr.ifr_mtu = tr->mtu_bytes;
  if (ioctl (dev_tap_fd, SIOCSIFMTU, &ifr) < 0)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_7;
      goto error;
    }

  /* get flags, modify to bring up interface... */
  if (ioctl (dev_tap_fd, SIOCGIFFLAGS, &ifr) < 0)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_8;
      goto error;
    }

  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

  if (ioctl (dev_tap_fd, SIOCSIFFLAGS, &ifr) < 0)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_9;
      goto error;
    }

  ti = turbotap_get_new_tapif();
  ti->per_interface_next_index = ~0;

  if (hwaddr_arg != 0)
    clib_memcpy(hwaddr, hwaddr_arg, 6);
  else
    {
      f64 now = vlib_time_now(vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      memcpy (hwaddr+2, &rnd, sizeof(rnd));
      hwaddr[0] = 2;
      hwaddr[1] = 0xfe;
    }

  if ((sock_fd = ioctl (turbotap_fd, TUNGETSOCKFD, (void *)&dev_net_tun_fd) ) < 0)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      goto error;
    } 

  error = ethernet_register_interface
        (tr->vnet_main,
         turbotap_dev_class.index,
         ti - tr->kni_interfaces /* device instance */,
         hwaddr /* ethernet address */,
         &ti->hw_if_index,
         turbotap_flag_change);

  if (error)
    {
      clib_error_report (error);
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto error;
    }

  {
    const uword buffer_size = vlib_buffer_free_list_buffer_size ( vlib_get_main(),
                                     VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
    unix_file_t template = {0};
    template.read_function = turbotap_read_ready;
    template.file_descriptor = dev_net_tun_fd;
    ti->unix_file_index = unix_file_add (&unix_main, &template);
    ti->unix_fd = dev_net_tun_fd;
    ti->provision_fd = dev_tap_fd;
    ti->turbotap_fd = turbotap_fd;
    ti->sock_fd = sock_fd;
    ti->rx_ready = MAX_RECV;
    ti->mtu_bytes = tr->mtu_bytes;
    ti->mtu_buffers = (tr->mtu_bytes + (buffer_size - 1)) / buffer_size;
    clib_memcpy (&ti->ifr, &ifr, sizeof (ifr));
  }

  {
    vnet_hw_interface_t * hw;
    hw = vnet_get_hw_interface (tr->vnet_main, ti->hw_if_index);
    hw->min_supported_packet_bytes = TAP_MTU_MIN;
    hw->max_supported_packet_bytes = TAP_MTU_MAX;
    hw->max_packet_bytes = ti->mtu_bytes;
    hw->max_l3_packet_bytes[VLIB_RX] = hw->max_l3_packet_bytes[VLIB_TX] = hw->max_supported_packet_bytes - sizeof(ethernet_header_t);
    ti->sw_if_index = hw->sw_if_index;
    if (sw_if_indexp)
      *sw_if_indexp = hw->sw_if_index;
  }

  ti->active = 1;

  hash_set (tr->turbotap_interface_index_by_sw_if_index, ti->sw_if_index,
            ti - tr->kni_interfaces);

  hash_set (tr->turbotap_interface_index_by_unix_fd, ti->unix_fd,
            ti - tr->kni_interfaces);

  return rv;

 error:
  close (dev_net_tun_fd);
  close (dev_tap_fd);
  close (turbotap_fd);
  close (sock_fd);

  return rv;
}

static int turbotap_tap_disconnect (kni_interface_t *ti)
{
  int rv = 0;
  kni_main_t * tr = &kni_main;
  vnet_main_t * vnm = tr->vnet_main;
  u32 sw_if_index = ti->sw_if_index;

  // bring interface down
  vnet_sw_interface_set_flags (vnm, sw_if_index, 0);

  if (ti->unix_file_index != ~0) {
    unix_file_del (&unix_main, unix_main.file_pool + ti->unix_file_index);
    ti->unix_file_index = ~0;
  }

  hash_unset (tr->turbotap_interface_index_by_unix_fd, ti->unix_fd);
  hash_unset (tr->turbotap_interface_index_by_sw_if_index, ti->sw_if_index);
  close(ti->unix_fd);
  close(ti->provision_fd);
  close(ti->turbotap_fd);
  close(ti->sock_fd);
  ti->unix_fd = -1;
  ti->provision_fd = -1;
  ti->turbotap_fd = -1;
  ti->sock_fd = -1;

  return rv;
}

int vnet_turbotap_delete(vlib_main_t *vm, u32 sw_if_index)
{
  int rv = 0;
  kni_main_t * tr = &kni_main;
  kni_interface_t *ti;
  uword *p = NULL;
 
  p = hash_get (tr->turbotap_interface_index_by_sw_if_index,
                sw_if_index);
  if (p == 0) {
    clib_warning ("sw_if_index %d unknown", sw_if_index);
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  }
  ti = vec_elt_at_index (tr->kni_interfaces, p[0]);

  // inactive
  ti->active = 0;
  turbotap_tap_disconnect(ti);
  // add to inactive list
  vec_add1(tr->turbotap_inactive_interfaces, ti - tr->kni_interfaces);

  // reset renumbered iface
  if (p[0] < vec_len (tr->show_dev_instance_by_real_dev_instance))
    tr->show_dev_instance_by_real_dev_instance[p[0]] = ~0;

  ethernet_delete_interface (tr->vnet_main, ti->hw_if_index);
  return rv;
}

clib_error_t *
vlib_plugin_register(vlib_main_t *m, vnet_plugin_handoff_t *h, int f)
{
  clib_error_t * error = 0;
  return error;
}
#endif


static uword
kni_process(vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
	clib_error_t * error = 0;
	u32 i =0;
	struct rte_kni_conf conf;
	kni_main_t * km = &kni_main;
	dpdk_main_t * dm = &dpdk_main;
	kni_interface_t *ki = NULL;
	//  struct rte_kni_ops ops;
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
				clib_warning ("hw_if_index %d sw_if_index %d",hi->hw_if_index,
					hi->sw_if_index);
				hash_set(km->kni_interface_index_by_sw_if_index,hi->sw_if_index,km->kni_interfaces);
				km->num_kni_interfaces++;

				}));

	rte_kni_init(km->num_kni_interfaces);
	for (i = 0; i< km->num_kni_interfaces; i++)
	{
		//ki->hw_if_index =i;
		ki = vec_elt_at_index(km->kni_interfaces, i);
		memset(&conf, 0, sizeof(conf));
		snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", i);
		conf.group_id = i;
		conf.mbuf_size = 2048;
		ki->kni = rte_kni_alloc(dm->pktmbuf_pools[0], &conf,  NULL);


	}
	return error;

}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (kni_process_node,static) = {
    .function = kni_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "kni-process",
    .process_log2_n_stack_bytes = 17,
};
/* *INDENT-ON* */




clib_error_t *kni_init(vlib_main_t *vm)
{
	clib_error_t * error = 0;

	return error;
}
VLIB_INIT_FUNCTION(kni_init);
/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = "KNI.1.0",
    .description = "KNI SLOWPATH (KNI)",
};
/* *INDENT-ON* */


/*	  ops.port_id = port_id;
	  memset(&ops, 0, sizeof(ops));
	  ops.change_mtu = kni_change_mtu;
	  clib_warning ("Registering kni_config_network_interface");
	  ops.config_network_if = kni_config_network_interface;
	  ki->kni = rte_kni_alloc(dm->pktmbuf_pools[0], &conf,  &ops);
*/
	  /*		error = ethernet_register_interface
			(km->vnet_main,
			km->kni_interfaces,
			ki - km->kni_interfaces /|* device instance *|/,
			/|*Fixme MacAddr*|/0 /|* ethernet address *|/,
			&ki->hw_if_index, NULL);

			if (error)
			{
			clib_error_report (error);
			return error;
			}
			*/
