/*
 * srv6_t_m_gtp4_d.c
 *
 * Copyright (c) 2019 Arrcus Inc and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/adj/adj.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <srv6-mobile/mobile.h>

extern ip6_address_t sr_pr_encaps_src;
extern u8 sr_pr_encaps_hop_limit;

srv6_t_main_v4_decap_t srv6_t_main_v4_decap;

static void
clb_dpo_lock_srv6_t_m_gtp4_d (dpo_id_t * dpo)
{
}

static void
clb_dpo_unlock_srv6_t_m_gtp4_d (dpo_id_t * dpo)
{
}

static u8 *
clb_dpo_format_srv6_t_m_gtp4_d (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: dynamic_proxy_index:[%u]", index));
}

const static dpo_vft_t dpo_vft = {
  .dv_lock = clb_dpo_lock_srv6_t_m_gtp4_d,
  .dv_unlock = clb_dpo_unlock_srv6_t_m_gtp4_d,
  .dv_format = clb_dpo_format_srv6_t_m_gtp4_d,
};

const static char *const srv6_t_m_gtp4_d_nodes[] = {
  "srv6-t-m-gtp4-d",
  NULL,
};

const static char *const srv6_t_m_gtp4_d_v6_nodes[] = {
  "error-drop",
  NULL,
};

const static char *const *const dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_t_m_gtp4_d_v6_nodes,
  [DPO_PROTO_IP4] = srv6_t_m_gtp4_d_nodes,
};

static u8 fn_name[] = "SRv6-T.M.GTP4.D-plugin";
static u8 keyword_str[] = "t.m.gtp4.d";
static u8 def_str[] =
  "Transit function with decapsulation for IPv4/GTP tunnel";
static u8 param_str[] =
  "<sr-prefix>/<sr-prefixlen> v6src_prefix <v6src_prefix>/<prefixlen> [nhtype "
  "<nhtype>] fib-table <id> teid <teid>/<length> sid <sid>";

static u8 *
clb_format_srv6_t_m_gtp4_d (u8 * s, va_list * args)
{
  srv6_end_gtp4_d_param_t *ls_mem = va_arg (*args, void *);

  s = format (s, "SRv6 T.M.GTP4.D\n\t");

  s =
    format (s, "SR Prefix: %U/%d, ", format_ip6_address, &ls_mem->sr_prefix,
	    ls_mem->sr_prefixlen);

  s =
    format (s, "v6src Prefix: %U/%d", format_ip6_address,
	    &ls_mem->v6src_prefix, ls_mem->v6src_prefixlen);

  if (ls_mem->nhtype != SRV6_NHTYPE_NONE)
    {
      if (ls_mem->nhtype == SRV6_NHTYPE_IPV4)
	s = format (s, ", NHType IPv4");
      else if (ls_mem->nhtype == SRV6_NHTYPE_IPV6)
	s = format (s, ", NHType IPv6");
      else if (ls_mem->nhtype == SRV6_NHTYPE_NON_IP)
	s = format (s, ", NHType Non-IP");
      else
	s = format (s, ", NHType Unknow(%d)", ls_mem->nhtype);
    }

  s = format (s, ", FIB table %d", ls_mem->fib_table);

  s = format (s, ", SID %U", format_ip6_address, &ls_mem->sid);

  s = format (s, ", Drop In %d\n", ls_mem->drop_in);

  return s;
}

u32
alloc_param_srv6_t_m_gtp4_d (void **plugin_mem_p, const void *v6src_prefix,
			     const u32 v6src_prefixlen, const void *sr_prefix,
			     const u32 sr_prefixlen, const u32 fib_table,
			     const u8 nhtype, const bool drop_in,
			     const bool is_sid, const void *lsid,
			     const bool is_teid, u32 teid, const u32 teid_len)
{
  srv6_end_gtp4_d_param_t *ls_mem=0, *p_mem=0;
  ip6_header_t *iph = 0;
  ip6_address_t sid;
  struct sr_table_node *node=0;
  memcpy (&sid, lsid, sizeof (ip6_address_t));

  if (is_teid == false)
    {
      // ls_mem = clib_mem_alloc_aligned_at_offset (sizeof *ls_mem, 0, 0, 1);
      ls_mem = clib_mem_alloc (sizeof *ls_mem);

      clib_memset (ls_mem, 0, sizeof *ls_mem);
      *plugin_mem_p = ls_mem;

      memcpy (&ls_mem->sr_prefix, sr_prefix, sizeof (ip6_address_t));
      ls_mem->sr_prefixlen = sr_prefixlen;

      memcpy (&ls_mem->v6src_prefix, v6src_prefix, sizeof (ip6_address_t));
      ls_mem->v6src_prefixlen = v6src_prefixlen;

      ls_mem->nhtype = nhtype;

      ls_mem->drop_in = drop_in;

      ls_mem->sid_present = is_sid;
      ls_mem->sid = sid;
      ls_mem->tedb = NULL;
      if (is_sid)
	{
	  iph = &ls_mem->ip;
	  iph->ip_version_traffic_class_and_flow_label =
	    clib_host_to_net_u32 (0 | ((6 & 0xF) << 28));
	  iph->src_address.as_u64[0] = sr_pr_encaps_src.as_u64[0];
	  iph->src_address.as_u64[1] = sr_pr_encaps_src.as_u64[1];
	  iph->dst_address.as_u64[0] = sid.as_u64[0];
	  iph->dst_address.as_u64[1] = sid.as_u64[1];
	  iph->hop_limit = sr_pr_encaps_hop_limit;
	}

      ls_mem->fib_table = fib_table;
      ls_mem->fib4_index = ip4_fib_index_from_table_id (fib_table);
      ls_mem->fib6_index = ip6_fib_index_from_table_id (fib_table);
    }
  else
    {
      ls_mem = *plugin_mem_p;
      if (ls_mem == NULL)
	{
    ls_mem = clib_mem_alloc (sizeof *ls_mem);
	  // ls_mem = clib_mem_alloc_aligned_at_offset (sizeof *ls_mem, 0, 0, 1);
	  clib_memset (ls_mem, 0, sizeof *ls_mem);
	  *plugin_mem_p = ls_mem;
	}

      if (ls_mem->tedb == NULL)
	{
	  ls_mem->tedb = sr_table_new (AF_INET, 32, NULL);
	  if (ls_mem->tedb == NULL)
	    {
	      return 0;
	    }
	}

      teid = clib_host_to_net_u32 (teid);
      node = sr_table_node_get (ls_mem->tedb, (u8 *) &teid, teid_len);
      if (!node)
	{
	  return 0;
	}
      p_mem = sr_table_node_get_data (node);
      if (p_mem == NULL)
	{
	  // p_mem = clib_mem_alloc_aligned_at_offset (sizeof *p_mem, 0, 0, 1);
    p_mem = clib_mem_alloc (sizeof *p_mem);
	  clib_memset (p_mem, 0, sizeof *p_mem);
	  sr_table_node_set_data (node, p_mem);
	}

      memcpy (&p_mem->sr_prefix, sr_prefix, sizeof (ip6_address_t));
      p_mem->sr_prefixlen = sr_prefixlen;

      memcpy (&p_mem->v6src_prefix, v6src_prefix, sizeof (ip6_address_t));
      p_mem->v6src_prefixlen = v6src_prefixlen;

      p_mem->nhtype = nhtype;
      p_mem->drop_in = drop_in;

      p_mem->sid_present = is_sid;

      if (is_sid)
	{
	  iph = &p_mem->ip;
	  iph->ip_version_traffic_class_and_flow_label =
	    clib_host_to_net_u32 (0 | ((6 & 0xF) << 28));
	  iph->src_address.as_u64[0] = sr_pr_encaps_src.as_u64[0];
	  iph->src_address.as_u64[1] = sr_pr_encaps_src.as_u64[1];
	  iph->dst_address.as_u64[0] = sid.as_u64[0];
	  iph->dst_address.as_u64[1] = sid.as_u64[1];
	  iph->hop_limit = sr_pr_encaps_hop_limit;
	}

      p_mem->fib_table = fib_table;
      p_mem->fib4_index = ip4_fib_index_from_table_id (fib_table);
      p_mem->fib6_index = ip6_fib_index_from_table_id (fib_table);
    }
  
  struct sr_table_node *n1=0;
  printf("loookup start\n");
  n1 = sr_table_node_match (ls_mem->tedb, (u8 *) &teid, 32);
  printf("match do\n");
  if (n1 != NULL)
  {
    printf("loookup succ\n");
  }
  return 1;
}

static uword
clb_unformat_srv6_t_m_gtp4_d (unformat_input_t * input, va_list * args)
{
  void **plugin_mem_p = va_arg (*args, void **);
  ip6_address_t sr_prefix;
  u32 sr_prefixlen;
  ip6_address_t v6src_prefix;
  ip6_address_t sid;
  u32 v6src_prefixlen;
  u32 fib_table = 0;
  u32 teid = 0;
  u32 teid_len = 0;
  bool drop_in = false;
  bool is_sid = false;
  bool is_teid = false;
  u8 nhtype = SRV6_NHTYPE_NONE;
  bool config = false;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (
	    input,
	    "t.m.gtp4.d %U/%d v6src_prefix %U/%d nhtype ipv4 fib-table %d",
	    unformat_ip6_address, &sr_prefix, &sr_prefixlen,
	    unformat_ip6_address, &v6src_prefix, &v6src_prefixlen, &fib_table))
	{
	  config = true;
	  nhtype = SRV6_NHTYPE_IPV4;
	}
      else if (unformat (input,
			 "t.m.gtp4.d %U/%d v6src_prefix %U/%d nhtype ipv6 "
			 "fib-table %d",
			 unformat_ip6_address, &sr_prefix, &sr_prefixlen,
			 unformat_ip6_address, &v6src_prefix, &v6src_prefixlen,
			 &fib_table))
	{
	  config = true;
	  nhtype = SRV6_NHTYPE_IPV6;
	}
      else if (unformat (
		 input, "t.m.gtp4.d %U/%d v6src_prefix %U/%d nhtype non-ip",
		 unformat_ip6_address, &sr_prefix, &sr_prefixlen,
		 unformat_ip6_address, &v6src_prefix, &v6src_prefixlen))
	{
	  config = true;
	  nhtype = SRV6_NHTYPE_NON_IP;
	}
      else if (unformat (input,
			 "t.m.gtp4.d %U/%d v6src_prefix %U/%d fib-table %d",
			 unformat_ip6_address, &sr_prefix, &sr_prefixlen,
			 unformat_ip6_address, &v6src_prefix, &v6src_prefixlen,
			 &fib_table))
	{
	  config = true;
	  nhtype = SRV6_NHTYPE_NONE;
	}
      else if (unformat (input, "t.m.gtp4.d %U/%d v6src_prefix %U/%d",
			 unformat_ip6_address, &sr_prefix, &sr_prefixlen,
			 unformat_ip6_address, &v6src_prefix,
			 &v6src_prefixlen))
	{
	  config = true;
	  nhtype = SRV6_NHTYPE_NONE;
	}
      else if (unformat (input, "teid %d/%d", &teid, &teid_len))
	{
	  is_teid = true;
	}
      else if (unformat (input, "sid %U", unformat_ip6_address, &sid))
	{
	  is_sid = true;
	}
      else if (unformat (input, "drop-in"))
	{
	  drop_in = true;
	}
      else
	{
	  return 0;
	}
    }

  if (!config)
    {
      return 0;
    }

  return alloc_param_srv6_t_m_gtp4_d (
    plugin_mem_p, &v6src_prefix, v6src_prefixlen, &sr_prefix, sr_prefixlen,
    fib_table, nhtype, drop_in, is_sid, &sid, is_teid, teid, teid_len);
}

static int
clb_creation_srv6_t_m_gtp4_d (ip6_sr_policy_t * sr_policy)
{
  return 0;
}

static int
clb_removal_srv6_t_m_gtp4_d (ip6_sr_policy_t * sr_policy)
{
  srv6_end_gtp4_d_param_t *ls_mem;

  ls_mem = (srv6_end_gtp4_d_param_t *) sr_policy->plugin_mem;

  clib_mem_free (ls_mem);

  return 0;
}

static clib_error_t *
srv6_t_m_gtp4_d_init (vlib_main_t * vm)
{
  srv6_t_main_v4_decap_t *sm = &srv6_t_main_v4_decap;
  ip6_header_t *ip6;
  dpo_type_t dpo_type;
  vlib_node_t *node;
  int rc;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  node = vlib_get_node_by_name (vm, (u8 *) "srv6-t-m-gtp4-d");
  sm->t_m_gtp4_d_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  sm->error_node_index = node->index;

  ip6 = &sm->cache_hdr;

  clib_memset_u8 (ip6, 0, sizeof (ip6_header_t));

  // IPv6 header (default)
  ip6->ip_version_traffic_class_and_flow_label = 0x60;
  ip6->hop_limit = 64;
  ip6->protocol = IP_PROTOCOL_IPV6;

  dpo_type = dpo_register_new_type (&dpo_vft, dpo_nodes);

  rc = sr_policy_register_function (vm, fn_name, keyword_str, def_str, param_str, 128,	//prefix len
				    &dpo_type,
				    clb_format_srv6_t_m_gtp4_d,
				    clb_unformat_srv6_t_m_gtp4_d,
				    clb_creation_srv6_t_m_gtp4_d,
				    clb_removal_srv6_t_m_gtp4_d);
  if (rc < 0)
    clib_error_return (0, "SRv6 Transit GTP4.D Policy function"
		       "couldn't be registered");
  return 0;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT (srv6_t_m_gtp4_d, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "srv6-t-m-gtp4-d",
  .runs_before = 0,
};

VLIB_INIT_FUNCTION (srv6_t_m_gtp4_d_init);
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
