/* packet-fortinet-ha.c
 * Routines for Fortinet HA header disassembly
 * Copyright 2015, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>

#define ETHERTYPE_FORTINET_HA1   0x8890
#define ETHERTYPE_FORTINET_HA2   0x8890
#define ETHERTYPE_FORTINET_HA8893   0x8893
#define UDP_FORTINET_HA703   703
#define MAGIC_fortinet_ha       0x2900

void proto_register_fortinet_ha(void);
void proto_reg_handoff_fortinet_ha(void);

static int proto_fortinet_ha = -1;
static gint ett_fortinet_ha  = -1;
static gint ett_fortinet_ha_debug = -1;

static int hf_fortinet_ha_magic = -1;
static int hf_fortinet_ha_type = -1;
static int hf_fortinet_ha_ip = -1;
static int hf_fortinet_ha_length  = -1;
static int hf_fortinet_ha_sn = -1;
static int hf_fortinet_ha_port = -1;
static int hf_fortinet_ha_unknown_uint = -1;
static int hf_fortinet_ha_unknown_bytes = -1;

static dissector_handle_t ip;

static int
dissect_fortinet_debug(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_, int offset)
{
    proto_tree *ti;
    proto_tree *fortinet_ha_tree;
    int doffset = offset;

    while(doffset + 4  < (int)tvb_reported_length(tvb)){
        
        ti = proto_tree_add_debug_text(tree, "Debug: ");
        fortinet_ha_tree = proto_item_add_subtree(ti, ett_fortinet_ha_debug);

        proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, doffset, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "%d (0x%x)", tvb_get_guint8(tvb, doffset), tvb_get_guint8(tvb, doffset));
        proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, doffset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, doffset, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, doffset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_ip, tvb, doffset, 4, ENC_BIG_ENDIAN);
        doffset += 1;
    }
    return doffset;
}

static int
dissect_fortinet_ha703(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *ti;
    proto_tree *fortinet_ha_tree;
    int offset = 0;

    ti = proto_tree_add_item(tree, proto_fortinet_ha, tvb, offset, -1, ENC_NA);
    fortinet_ha_tree = proto_item_add_subtree(ti, ett_fortinet_ha);

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    dissect_fortinet_debug(tvb, pinfo, tree, NULL, offset);
    return tvb_reported_length(tvb);
}

static int
dissect_fortinet_ha8893(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /* there is a 2 (unused) octets + 2 octets (type IPv4 => 0x8000 ?) before IP */
    tvb = tvb_new_subset(tvb, 4, -1, -1);
    call_dissector(ip, tvb, pinfo, tree);

    return tvb_reported_length(tvb);
}

static int
dissect_fortinet_ha8890(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *ti;
    proto_tree *fortinet_ha_tree;
    guint16 magic;
    int offset = 0;


    magic = tvb_get_ntohs(tvb, offset);

    if(magic != MAGIC_fortinet_ha)
    {
        return 0;
    }


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Fortinet HA");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_fortinet_ha, tvb, offset, -1, ENC_NA);
    fortinet_ha_tree = proto_item_add_subtree(ti, ett_fortinet_ha);

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_magic, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_sn, tvb, offset, 16, ENC_BIG_ENDIAN);
    offset += 16;

    //proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_bytes, tvb, offset, , ENC_BIG_ENDIAN);
    dissect_fortinet_debug(tvb, pinfo, tree, NULL, offset);

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(fortinet_ha_tree, hf_fortinet_ha_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return tvb_reported_length(tvb);
}

void
proto_register_fortinet_ha(void)
{
    static hf_register_info hf[] = {
        { &hf_fortinet_ha_magic,
        { "Magic", "fortinet_ha.magic", FT_UINT16, BASE_HEX, NULL,0x0,
        "Magic Number of fortinet_ha trafic (Always 0x2900)", HFILL}},

        { &hf_fortinet_ha_type,
        { "Type (?)", "fortinet_ha.type", FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        "May type field...", HFILL}},

        { &hf_fortinet_ha_ip,
        { "IP", "fortinet_ha.ip", FT_IPv4, BASE_NONE, NULL, 0x0,
        "Address IP of fortinet_ha", HFILL}},

        { &hf_fortinet_ha_length,
        { "Length ???", "fortinet_ha.length", FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length of Packet ", HFILL}},

        { &hf_fortinet_ha_sn,
        { "Serial Number", "fortinet_ha.sn", FT_STRING, BASE_NONE, NULL, 0x0,
        "Serial Number of Fortigate", HFILL}},

        { &hf_fortinet_ha_port,
        { "Port HA", "fortinet_ha.port", FT_STRING, BASE_NONE, NULL, 0x0,
        "Serial Number of Fortigate", HFILL}},

        { &hf_fortinet_ha_unknown_bytes,
        { "Unknown", "fortinet_ha.unknown.bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown Data...", HFILL}},

        { &hf_fortinet_ha_unknown_uint,
        { "Unknown", "fortinet_ha.unknown.uint", FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        "Unknown (UINT) Data...", HFILL}},


    };

    static gint *ett[] = {
        &ett_fortinet_ha,
        &ett_fortinet_ha_debug,
    };

    proto_fortinet_ha = proto_register_protocol("Fortinet HA Protocol",
                    "fortinet_ha", "fortinet_ha");
    proto_register_field_array(proto_fortinet_ha, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_fortinet_ha(void)
{
    dissector_handle_t fortinet_ha_handle8890, fortinet_ha_handle8893, fortinet_ha_handle703;

    ip = find_dissector("ip");

    fortinet_ha_handle8890 = new_create_dissector_handle(dissect_fortinet_ha8890, proto_fortinet_ha);
    dissector_add_uint("ethertype", ETHERTYPE_FORTINET_HA1, fortinet_ha_handle8890);

    fortinet_ha_handle8893 = new_create_dissector_handle(dissect_fortinet_ha8893, proto_fortinet_ha);
    dissector_add_uint("ethertype", ETHERTYPE_FORTINET_HA8893, fortinet_ha_handle8893);

    fortinet_ha_handle703 = new_create_dissector_handle(dissect_fortinet_ha703, proto_fortinet_ha);
    dissector_add_uint("udp.port", UDP_FORTINET_HA703, fortinet_ha_handle703);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
