// SPDX-License-Identifier: MIT OR Apache-2.0

//! nf_tables' numbers, retyped from the UAPI headers ADR 0128 allows
//! (Fedora's kernel-headers 7.2.4): each group names its header and enum.

// netlink(7): the message header's types and flags.
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_MULTI: u16 = 0x2;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_ECHO: u16 = 0x8;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;
/// The attribute type's nested flag (NLA_F_NESTED), which nft sets on
/// nested attributes and Linux's dumps leave clear (observed on the host,
/// ADR 0128); the two bits above the type are flags.
pub const NLA_F_NESTED: u16 = 0x8000;
pub const NLA_TYPE_MASK: u16 = 0x3FFF;

// linux/netfilter/nfnetlink.h: subsystems, the batch messages and their
// attribute, the nf_tables multicast group.
pub const NFNL_SUBSYS_NFTABLES: u16 = 10;
pub const NFNL_MSG_BATCH_BEGIN: u16 = 16;
pub const NFNL_MSG_BATCH_END: u16 = 17;
pub const NFNL_BATCH_GENID: u16 = 1;
pub const NFNLGRP_NFTABLES: u32 = 7;

// linux/netfilter.h: families (NFPROTO_*), hooks (enum nf_inet_hooks) and
// verdicts.
pub const NFPROTO_UNSPEC: u8 = 0;
pub const NFPROTO_INET: u8 = 1;
pub const NFPROTO_IPV4: u8 = 2;
pub const NFPROTO_IPV6: u8 = 10;
pub const NF_INET_PRE_ROUTING: u32 = 0;
pub const NF_INET_LOCAL_IN: u32 = 1;
pub const NF_INET_FORWARD: u32 = 2;
pub const NF_INET_LOCAL_OUT: u32 = 3;
pub const NF_INET_POST_ROUTING: u32 = 4;
pub const NF_DROP: i32 = 0;
pub const NF_ACCEPT: i32 = 1;

// linux/netfilter/nf_tables.h, enum nf_tables_msg_types.
pub const NFT_MSG_NEWTABLE: u16 = 0;
pub const NFT_MSG_GETTABLE: u16 = 1;
pub const NFT_MSG_DELTABLE: u16 = 2;
pub const NFT_MSG_NEWCHAIN: u16 = 3;
pub const NFT_MSG_GETCHAIN: u16 = 4;
pub const NFT_MSG_DELCHAIN: u16 = 5;
pub const NFT_MSG_NEWRULE: u16 = 6;
pub const NFT_MSG_GETRULE: u16 = 7;
pub const NFT_MSG_DELRULE: u16 = 8;
pub const NFT_MSG_NEWSET: u16 = 9;
pub const NFT_MSG_GETSET: u16 = 10;
pub const NFT_MSG_DELSET: u16 = 11;
pub const NFT_MSG_NEWSETELEM: u16 = 12;
pub const NFT_MSG_GETSETELEM: u16 = 13;
pub const NFT_MSG_DELSETELEM: u16 = 14;
pub const NFT_MSG_NEWGEN: u16 = 15;
pub const NFT_MSG_GETGEN: u16 = 16;
pub const NFT_MSG_GETOBJ: u16 = 19;
pub const NFT_MSG_GETFLOWTABLE: u16 = 23;
pub const NFT_MSG_DESTROYTABLE: u16 = 26;
pub const NFT_MSG_DESTROYCHAIN: u16 = 27;
pub const NFT_MSG_DESTROYRULE: u16 = 28;
pub const NFT_MSG_DESTROYSET: u16 = 29;
pub const NFT_MSG_DESTROYSETELEM: u16 = 30;

// enum nft_registers and enum nft_verdicts.
pub const NFT_REG_VERDICT: u32 = 0;
pub const NFT_REG32_00: u32 = 8;
pub const NFT_REG32_15: u32 = 23;
pub const NFT_CONTINUE: i32 = -1;
pub const NFT_BREAK: i32 = -2;
pub const NFT_JUMP: i32 = -3;
pub const NFT_GOTO: i32 = -4;
pub const NFT_RETURN: i32 = -5;

// enum nft_hook_attributes.
pub const NFTA_HOOK_HOOKNUM: u16 = 1;
pub const NFTA_HOOK_PRIORITY: u16 = 2;
pub const NFTA_HOOK_DEV: u16 = 3;

// enum nft_table_attributes and nft_table_flags.
pub const NFTA_TABLE_NAME: u16 = 1;
pub const NFTA_TABLE_FLAGS: u16 = 2;
pub const NFTA_TABLE_USE: u16 = 3;
pub const NFTA_TABLE_HANDLE: u16 = 4;
pub const NFTA_TABLE_USERDATA: u16 = 6;
pub const NFT_TABLE_F_DORMANT: u32 = 0x1;

// enum nft_chain_attributes and nft_chain_flags.
pub const NFTA_CHAIN_TABLE: u16 = 1;
pub const NFTA_CHAIN_HANDLE: u16 = 2;
pub const NFTA_CHAIN_NAME: u16 = 3;
pub const NFTA_CHAIN_HOOK: u16 = 4;
pub const NFTA_CHAIN_POLICY: u16 = 5;
pub const NFTA_CHAIN_USE: u16 = 6;
pub const NFTA_CHAIN_TYPE: u16 = 7;
pub const NFTA_CHAIN_COUNTERS: u16 = 8;
pub const NFTA_CHAIN_FLAGS: u16 = 10;
pub const NFTA_CHAIN_ID: u16 = 11;
pub const NFTA_CHAIN_USERDATA: u16 = 12;
pub const NFT_CHAIN_BASE: u32 = 0x1;

// enum nft_rule_attributes.
pub const NFTA_RULE_TABLE: u16 = 1;
pub const NFTA_RULE_CHAIN: u16 = 2;
pub const NFTA_RULE_HANDLE: u16 = 3;
pub const NFTA_RULE_EXPRESSIONS: u16 = 4;
pub const NFTA_RULE_POSITION: u16 = 6;
pub const NFTA_RULE_USERDATA: u16 = 7;
pub const NFTA_RULE_ID: u16 = 9;
pub const NFTA_RULE_POSITION_ID: u16 = 10;
pub const NFTA_RULE_CHAIN_ID: u16 = 11;

// enum nft_set_flags, nft_set_attributes, nft_set_desc_attributes.
pub const NFT_SET_ANONYMOUS: u32 = 0x1;
pub const NFT_SET_CONSTANT: u32 = 0x2;
pub const NFT_SET_INTERVAL: u32 = 0x4;
pub const NFT_SET_MAP: u32 = 0x8;
pub const NFT_SET_TIMEOUT: u32 = 0x10;
pub const NFT_SET_CONCAT: u32 = 0x80;
pub const NFTA_SET_TABLE: u16 = 1;
pub const NFTA_SET_NAME: u16 = 2;
pub const NFTA_SET_FLAGS: u16 = 3;
pub const NFTA_SET_KEY_TYPE: u16 = 4;
pub const NFTA_SET_KEY_LEN: u16 = 5;
pub const NFTA_SET_DATA_TYPE: u16 = 6;
pub const NFTA_SET_DATA_LEN: u16 = 7;
pub const NFTA_SET_POLICY: u16 = 8;
pub const NFTA_SET_DESC: u16 = 9;
pub const NFTA_SET_ID: u16 = 10;
pub const NFTA_SET_TIMEOUT: u16 = 11;
pub const NFTA_SET_GC_INTERVAL: u16 = 12;
pub const NFTA_SET_USERDATA: u16 = 13;
pub const NFTA_SET_HANDLE: u16 = 16;
pub const NFTA_SET_TYPE: u16 = 19;
pub const NFTA_SET_COUNT: u16 = 20;

// enum nft_set_elem_flags, nft_set_elem_attributes and
// nft_set_elem_list_attributes; enum nft_list_attributes.
pub const NFT_SET_ELEM_INTERVAL_END: u32 = 0x1;
pub const NFTA_SET_ELEM_KEY: u16 = 1;
pub const NFTA_SET_ELEM_DATA: u16 = 2;
pub const NFTA_SET_ELEM_FLAGS: u16 = 3;
pub const NFTA_SET_ELEM_USERDATA: u16 = 6;
pub const NFTA_SET_ELEM_KEY_END: u16 = 10;
pub const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
pub const NFTA_SET_ELEM_LIST_SET: u16 = 2;
pub const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
pub const NFTA_SET_ELEM_LIST_SET_ID: u16 = 4;
pub const NFTA_LIST_ELEM: u16 = 1;

// enum nft_data_types, nft_data_attributes, nft_verdict_attributes.
pub const NFT_DATA_VERDICT: u32 = 0xFFFF_FF00;
pub const NFTA_DATA_VALUE: u16 = 1;
pub const NFTA_DATA_VERDICT: u16 = 2;
pub const NFTA_VERDICT_CODE: u16 = 1;
pub const NFTA_VERDICT_CHAIN: u16 = 2;
pub const NFTA_VERDICT_CHAIN_ID: u16 = 3;

// enum nft_expr_attributes, and each expression's attributes.
pub const NFTA_EXPR_NAME: u16 = 1;
pub const NFTA_EXPR_DATA: u16 = 2;
pub const NFTA_IMMEDIATE_DREG: u16 = 1;
pub const NFTA_IMMEDIATE_DATA: u16 = 2;
pub const NFTA_CMP_SREG: u16 = 1;
pub const NFTA_CMP_OP: u16 = 2;
pub const NFTA_CMP_DATA: u16 = 3;
pub const NFTA_RANGE_SREG: u16 = 1;
pub const NFTA_RANGE_OP: u16 = 2;
pub const NFTA_RANGE_FROM_DATA: u16 = 3;
pub const NFTA_RANGE_TO_DATA: u16 = 4;
pub const NFTA_BITWISE_SREG: u16 = 1;
pub const NFTA_BITWISE_DREG: u16 = 2;
pub const NFTA_BITWISE_LEN: u16 = 3;
pub const NFTA_BITWISE_MASK: u16 = 4;
pub const NFTA_BITWISE_XOR: u16 = 5;
pub const NFTA_BITWISE_OP: u16 = 6;
pub const NFTA_BITWISE_DATA: u16 = 7;
pub const NFT_BITWISE_MASK_XOR: u32 = 0;
pub const NFT_BITWISE_LSHIFT: u32 = 1;
pub const NFT_BITWISE_RSHIFT: u32 = 2;
pub const NFTA_LOOKUP_SET: u16 = 1;
pub const NFTA_LOOKUP_SREG: u16 = 2;
pub const NFTA_LOOKUP_DREG: u16 = 3;
pub const NFTA_LOOKUP_SET_ID: u16 = 4;
pub const NFTA_LOOKUP_FLAGS: u16 = 5;
pub const NFT_LOOKUP_F_INV: u32 = 0x1;
pub const NFTA_PAYLOAD_DREG: u16 = 1;
pub const NFTA_PAYLOAD_BASE: u16 = 2;
pub const NFTA_PAYLOAD_OFFSET: u16 = 3;
pub const NFTA_PAYLOAD_LEN: u16 = 4;
pub const NFTA_PAYLOAD_SREG: u16 = 5;
pub const NFT_PAYLOAD_LL_HEADER: u32 = 0;
pub const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
pub const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
pub const NFTA_META_DREG: u16 = 1;
pub const NFTA_META_KEY: u16 = 2;
pub const NFTA_META_SREG: u16 = 3;
pub const NFTA_CT_DREG: u16 = 1;
pub const NFTA_CT_KEY: u16 = 2;
pub const NFTA_CT_DIRECTION: u16 = 3;
pub const NFTA_CT_SREG: u16 = 4;
pub const NFTA_COUNTER_BYTES: u16 = 1;
pub const NFTA_COUNTER_PACKETS: u16 = 2;
pub const NFTA_REJECT_TYPE: u16 = 1;
pub const NFTA_REJECT_ICMP_CODE: u16 = 2;
pub const NFTA_GEN_ID: u16 = 1;
pub const NFTA_GEN_PROC_PID: u16 = 2;
pub const NFTA_GEN_PROC_NAME: u16 = 3;

// enum nft_cmp_ops and nft_range_ops.
pub const NFT_CMP_EQ: u32 = 0;
pub const NFT_CMP_NEQ: u32 = 1;
pub const NFT_CMP_LT: u32 = 2;
pub const NFT_CMP_LTE: u32 = 3;
pub const NFT_CMP_GT: u32 = 4;
pub const NFT_CMP_GTE: u32 = 5;
pub const NFT_RANGE_EQ: u32 = 0;

// enum nft_meta_keys.
pub const NFT_META_LEN: u32 = 0;
pub const NFT_META_PROTOCOL: u32 = 1;
pub const NFT_META_MARK: u32 = 3;
pub const NFT_META_IIF: u32 = 4;
pub const NFT_META_OIF: u32 = 5;
pub const NFT_META_IIFNAME: u32 = 6;
pub const NFT_META_OIFNAME: u32 = 7;
pub const NFT_META_IIFTYPE: u32 = 8;
pub const NFT_META_OIFTYPE: u32 = 9;
pub const NFT_META_SKUID: u32 = 10;
pub const NFT_META_SKGID: u32 = 11;
pub const NFT_META_NFPROTO: u32 = 15;
pub const NFT_META_L4PROTO: u32 = 16;
pub const NFT_META_PKTTYPE: u32 = 19;

// enum nft_ct_keys; linux/netfilter/nf_conntrack_common.h's state bits
// (NF_CT_STATE_BIT(ctinfo) = 1 << (ctinfo + 1), enum ip_conntrack_info:
// established 0, related 1, new 2) and IP_CT_DIR_ORIGINAL/REPLY.
pub const NFT_CT_STATE: u32 = 0;
pub const NFT_CT_DIRECTION: u32 = 1;
pub const NFT_CT_MARK: u32 = 3;
pub const NF_CT_STATE_INVALID_BIT: u32 = 1 << 0;
pub const NF_CT_STATE_ESTABLISHED: u32 = 1 << 1;
pub const NF_CT_STATE_RELATED: u32 = 1 << 2;
pub const NF_CT_STATE_NEW: u32 = 1 << 3;
pub const NF_CT_STATE_UNTRACKED_BIT: u32 = 1 << 6;

// enum nft_reject_types and nft_reject_inet_code.
pub const NFT_REJECT_ICMP_UNREACH: u32 = 0;
pub const NFT_REJECT_TCP_RST: u32 = 1;
pub const NFT_REJECT_ICMPX_UNREACH: u32 = 2;
pub const NFT_REJECT_ICMPX_NO_ROUTE: u8 = 0;
pub const NFT_REJECT_ICMPX_PORT_UNREACH: u8 = 1;
pub const NFT_REJECT_ICMPX_HOST_UNREACH: u8 = 2;
pub const NFT_REJECT_ICMPX_ADMIN_PROHIBITED: u8 = 3;

// linux/netfilter/nf_tables.h: the nat, masq and redir expressions' attributes
// (enum nft_nat_attributes, nft_masq_attributes, nft_redir_attributes) and
// enum nft_nat_types.
pub const NFTA_NAT_TYPE: u16 = 1;
pub const NFTA_NAT_FAMILY: u16 = 2;
pub const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
pub const NFTA_NAT_REG_ADDR_MAX: u16 = 4;
pub const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
pub const NFTA_NAT_REG_PROTO_MAX: u16 = 6;
pub const NFTA_NAT_FLAGS: u16 = 7;
pub const NFTA_MASQ_FLAGS: u16 = 1;
pub const NFTA_MASQ_REG_PROTO_MIN: u16 = 2;
pub const NFTA_MASQ_REG_PROTO_MAX: u16 = 3;
pub const NFTA_REDIR_REG_PROTO_MIN: u16 = 1;
pub const NFTA_REDIR_REG_PROTO_MAX: u16 = 2;
pub const NFTA_REDIR_FLAGS: u16 = 3;
pub const NFT_NAT_SNAT: u32 = 0;
pub const NFT_NAT_DNAT: u32 = 1;

// linux/netfilter/nf_nat.h: NF_NAT_RANGE_* flags.
pub const NF_NAT_RANGE_MAP_IPS: u32 = 1 << 0;
pub const NF_NAT_RANGE_PROTO_SPECIFIED: u32 = 1 << 1;
pub const NF_NAT_RANGE_PROTO_RANDOM: u32 = 1 << 2;
pub const NF_NAT_RANGE_PERSISTENT: u32 = 1 << 3;
pub const NF_NAT_RANGE_PROTO_RANDOM_FULLY: u32 = 1 << 4;
/// Every flag Linux knows (NF_NAT_RANGE_MASK: up to NETMAP, 1 << 6).
pub const NF_NAT_RANGE_MASK: u32 = 0x7F;

// linux/netfilter/nf_tables_compat.h (ADR 0133): the compat subsystem's
// message and attributes, the match and target expressions' attributes;
// nf_tables.h: a rule's NFTA_RULE_COMPAT and its nest.
pub const NFNL_SUBSYS_NFT_COMPAT: u16 = 11;
pub const NFNL_MSG_COMPAT_GET: u16 = 0;
pub const NFTA_COMPAT_NAME: u16 = 1;
pub const NFTA_COMPAT_REV: u16 = 2;
pub const NFTA_COMPAT_TYPE: u16 = 3;
pub const NFTA_MATCH_NAME: u16 = 1;
pub const NFTA_MATCH_REV: u16 = 2;
pub const NFTA_MATCH_INFO: u16 = 3;
pub const NFTA_RULE_COMPAT: u16 = 5;
