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
#include <fcntl.h>              /* for open */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>            /* for iovec */
#include <netinet/in.h>

#include <linux/socket.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>

#if DPDK == 1
#include <vnet/devices/dpdk/dpdk.h>
#endif
#include "kni.h"
#include <rte_config.h>
#include <rte_kni.h>
/* Options for configuring ethernet port */
static struct rte_eth_conf port_conf = {
        .rxmode = {
                .header_split = 0,      /* Header Split disabled */
                .hw_ip_checksum = 0,    /* IP checksum offload disabled */
                .hw_vlan_filter = 0,    /* VLAN filtering disabled */
                .jumbo_frame = 0,       /* Jumbo Frame Support disabled */
                .hw_strip_crc = 1,      /* CRC stripped by hardware */
        },
        .txmode = {
                .mq_mode = ETH_MQ_TX_NONE,
        },
};


/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14
/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4


static int kni_change_mtu(uint16_t port_id, unsigned int new_mtu);
static int kni_config_network_interface(uint16_t port_id, uint8_t if_up);

/*

static clib_error_t *
kni_delete_command_fn (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  kni_main_t * tr = &kni_main;
  u32 sw_if_index = ~0;

  if (tr->is_disabled)
    {
      return clib_error_return (0, "device disabled...");
    }

  if (unformat (input, "%U", unformat_vnet_sw_interface, tr->vnet_main,
                &sw_if_index))
      ;
  else
    return clib_error_return (0, "unknown input `%U'",
                              format_unformat_error, input);

  int rc = vnet_kni_delete (vm, sw_if_index);

  if (!rc) {
    vlib_cli_output (vm, "Deleted.");
  } else {
    vlib_cli_output (vm, "Error during deletion of tap interface. (rc: %d)", rc);
  }

  return 0;
}

VLIB_CLI_COMMAND (kni_delete_command, static) = {
  .path = "kni delete",
  .short_help = "kni delete <vpp-tap-intfc-name>",
  .function = kni_delete_command_fn,
};

static clib_error_t *
kni_connect_command_fn (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  u8 * intfc_name;
  kni_main_t * tr = &kni_main;
  u8 hwaddr[6];
  u8 *hwaddr_arg = 0;
  u32 sw_if_index;

  if (tr->is_disabled)
    {
      return clib_error_return (0, "device disabled...");
    }

  if (unformat (input, "%s", &intfc_name))
    ;
  else
    return clib_error_return (0, "unknown input `%U'",
                              format_unformat_error, input);

  if (unformat(input, "hwaddr %U", unformat_ethernet_address,
               &hwaddr))
    hwaddr_arg = hwaddr;

  int rv = vnet_kni_connect(vm, intfc_name, hwaddr_arg, &sw_if_index);
  if (rv) {
    switch (rv) {
    case VNET_API_ERROR_SYSCALL_ERROR_1:
      vlib_cli_output (vm, "Couldn't open /dev/net/kni");
      break;

    case VNET_API_ERROR_SYSCALL_ERROR_2:
      vlib_cli_output (vm, "Error setting flags on '%s'", intfc_name);
      break;

    case VNET_API_ERROR_SYSCALL_ERROR_3:
      vlib_cli_output (vm, "Couldn't open provisioning socket");
      break;

    case VNET_API_ERROR_SYSCALL_ERROR_4:
      vlib_cli_output (vm, "Couldn't get if_index");
      break;

    case VNET_API_ERROR_SYSCALL_ERROR_5:
      vlib_cli_output (vm, "Couldn't bind provisioning socket");
      break;

    case VNET_API_ERROR_SYSCALL_ERROR_6:
      vlib_cli_output (0, "Couldn't set device non-blocking flag");
      break;

    case VNET_API_ERROR_SYSCALL_ERROR_7:
      vlib_cli_output (0, "Couldn't set device MTU");
      break;

    case VNET_API_ERROR_SYSCALL_ERROR_8:
      vlib_cli_output (0, "Couldn't get interface flags");
      break;
    case VNET_API_ERROR_SYSCALL_ERROR_9:
      vlib_cli_output (0, "Couldn't set intfc admin state up");
      break;

    case VNET_API_ERROR_INVALID_REGISTRATION:
      vlib_cli_output (0, "Invalid registration");
      break;
    default:
      vlib_cli_output (0, "Unknown error: %d", rv);
      break;
    }
    return 0;
  }

  vlib_cli_output(vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main(), sw_if_index);
  return 0;
}

VLIB_CLI_COMMAND (kni_connect_command, static) = {
    .path = "kni connect",
    .short_help = "kni connect <intfc-name> [hwaddr <addr>]",
    .function = kni_connect_command_fn,
};
*/
/* Callback for request of changing MTU */
static int
kni_change_mtu(uint16_t port_id, unsigned int new_mtu)
{
        int ret;
        struct rte_eth_conf conf;

        if (port_id >= rte_eth_dev_count()) {
                clib_warning("Invalid port id %d\n", port_id);
                return -EINVAL;
        }

        clib_warning("Change MTU of port %d to %u\n", port_id, new_mtu);

        /* Stop specific port */
        rte_eth_dev_stop(port_id);

        memcpy(&conf, &port_conf, sizeof(conf));
        /* Set new MTU */
        if (new_mtu > ETHER_MAX_LEN)
                conf.rxmode.jumbo_frame = 1;
        else
                conf.rxmode.jumbo_frame = 0;

        /* mtu + length of header + length of FCS = max pkt length */
        conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
                                                        KNI_ENET_FCS_SIZE;
        ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
        if (ret < 0) {
                clib_warning("Fail to reconfigure port %d\n", port_id);
                return ret;
        }
        /* Restart specific port */
        ret = rte_eth_dev_start(port_id);
        if (ret < 0) {
                clib_warning("Fail to restart port %d\n", port_id);
                return ret;
        }

        return 0;
}
static u32
kni_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi, u32 flags)
{
  dpdk_main_t *dm = &dpdk_main;
  uword *p;
  kni_main_t * km = &kni_main;
//  vnet_hw_interface_t * l_hi;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hi->dev_instance);
  u32 old = 0;
  clib_warning ("Entering kni_flag_change hw_if_index[%d] sw_if_index[%d] ",hi->hw_if_index,
							hi->sw_if_index );
   
  if (ETHERNET_INTERFACE_FLAG_CONFIG_PROMISC (flags))
    {
      old = (xd->flags & DPDK_DEVICE_FLAG_PROMISC) != 0;

      if (flags & ETHERNET_INTERFACE_FLAG_ACCEPT_ALL)
        xd->flags |= DPDK_DEVICE_FLAG_PROMISC;
      else
        xd->flags &= ~DPDK_DEVICE_FLAG_PROMISC;

      if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
        {
          if (xd->flags & DPDK_DEVICE_FLAG_PROMISC)
            rte_eth_promiscuous_enable (xd->device_index);
          else
            rte_eth_promiscuous_disable (xd->device_index);
        }
    }
  else if (ETHERNET_INTERFACE_FLAG_CONFIG_MTU (flags))
    {
      xd->port_conf.rxmode.max_rx_pkt_len = hi->max_packet_bytes;
      dpdk_device_setup (xd);
    }
  return old;
}

/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
        int ret = 0;

        if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
                clib_warning("Invalid port id %d\n", port_id);
                return -EINVAL;
        }

        clib_warning("Configure network interface of %d %s\n",
                                        port_id, if_up ? "up" : "down");

        if (if_up != 0) { /* Configure network interface up */
                rte_eth_dev_stop(port_id);
                ret = rte_eth_dev_start(port_id);
        } else /* Configure network interface down */
                rte_eth_dev_stop(port_id);

        if (ret < 0)
                clib_warning("Failed to start port %d\n", port_id);

        return ret;
}

/**
 *  * @brief Enable/disable thekni plugin.
 *   *
 *    * Action function shared between message handler and debug CLI.
 *     */

int kni_enable (vlib_main_t * vm,
			   kni_main_t * km,
                           int enable_disable)
{
  	int rv = 0;
        clib_error_t * error = 0;
        u32 i =0;
        struct rte_kni_conf conf;
        dpdk_main_t * dm = &dpdk_main;
        kni_interface_t *ki = NULL;
          struct rte_kni_ops ops;
        //  struct rte_eth_dev_info dev_info;


        km->num_kni_interfaces=0;
        vnet_hw_interface_t *hi;
        pool_foreach (hi, dm->vnet_main->interface_main.hw_interfaces, ({
	if(0 == hi->hw_if_index)
	{
		clib_warning("Ignoring Loopback for Kji interface");
	
	}
	else
	{
	vec_add2 (km->kni_interfaces, ki, 1);
	ki->sw_if_index = ki - km->kni_interfaces ;
	vnet_sw_interface_t *sw;
	sw = vnet_get_hw_sw_interface (dm->vnet_main, hi->hw_if_index); 
	ki->eth_sw_if_index  = sw->sw_if_index; 
//	ki->eth_sw_if_index = hi->sw_if_index;
	ki->eth_hw_if_index = hi->hw_if_index;
	clib_warning ("hw_if_index %d sw_if_index %d",hi->hw_if_index,
		hi->sw_if_index);
	hash_set(km->kni_interface_index_by_sw_if_index,hi->sw_if_index,ki->sw_if_index);
	hash_set(km->kni_interface_index_by_eth_index,ki->sw_if_index,hi->sw_if_index);/*FIXME: Name of the has needs to be change to ethInterfaceByKniInterface*/

	km->num_kni_interfaces++;
	}
        }));

        rte_kni_init(km->num_kni_interfaces);
        for (i = 0; i< km->num_kni_interfaces; i++)
        {
                memset(&ops, 0, sizeof(ops));
                ops.port_id = i;
                ops.change_mtu = kni_change_mtu;
                clib_warning ("Registering kni_config_network_interface");
                ops.config_network_if = kni_config_network_interface;

                ki = vec_elt_at_index(km->kni_interfaces, i);
                memset(&conf, 0, sizeof(conf));
                snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", i);
                conf.group_id = i;
                conf.mbuf_size = 2048;
                ki->kni = rte_kni_alloc(dm->pktmbuf_pools[0], &conf,  &ops);
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
                clib_warning ("Called ethernet_register_interface ,ret [%d] got hw_if_index [%d] ",
                                error,
                                ki->hw_if_index);
        clib_warning ("ki_hw_if_index %d ki_sw_if_index %d dpdk_hw_if_index [%d] dpdk_sw_if_index[%d]",ki->hw_if_index,
												ki->sw_if_index,
												ki->eth_hw_if_index ,
                                        							ki->eth_sw_if_index);
  	vnet_feature_enable_disable ("device-input", "slowpath",
                               ki->eth_sw_if_index, enable_disable, 0, 0);


        }



  return rv;
}


static clib_error_t *
kni_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  kni_main_t * km = &kni_main;
  int enable_disable = 1;

  int rv;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "disable"))
      enable_disable = 0;
    else
      break;
  }

  if(!km->is_disabled)
    return clib_error_return (0, "Kni already enabled ");

  if(enable_disable )
      rv = kni_enable (vm, km, enable_disable);

 switch(rv) {
  case 0:
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Cli not implemented ");
    break;

  default:
    return clib_error_return (0, "kni_enable_disable returned %d",
                              rv);
  }
  return 0;

}

/**
 *  * @brief CLI command to enable/disable the kni plugin.
 *   */
VLIB_CLI_COMMAND (sr_content_command, static) = {
    .path = "kni ",
    .short_help =
    "kni [disable]",
    .function = kni_enable_disable_command_fn,
};



clib_error_t *
kni_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (kni_cli_init);
