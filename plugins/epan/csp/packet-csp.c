#include "config.h"
#include <epan/packet.h>

static int proto_csp = -1;

static int hf_csp_priority = -1;
static int hf_csp_source = -1;
static int hf_csp_destination = -1;
static int hf_csp_destination_port = -1;
static int hf_csp_source_port = -1;
static int hf_csp_reserved = -1;
static int hf_csp_hmac = -1;
static int hf_csp_xtea = -1;
static int hf_csp_rdp = -1;
static int hf_csp_crc = -1;
static int hf_csp_payload = -1;

static gint ett_csp = -1;
static gint ett_csp_header = -1;
static gint ett_csp_payload = -1;

static int
dissect_csp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CSP");
    col_clear(pinfo->cinfo, COL_INFO);

    uint32_t hdr = tvb_get_guint32(tvb, 0, ENC_BIG_ENDIAN);
    int src = (hdr >> 25) & 0x1f;
    int dst = (hdr >> 20) & 0x1f;
    int dst_port = (hdr >> 14) & 0x3f;
    int src_port = (hdr >> 8) & 0x3f;

    col_add_fstr(pinfo->cinfo, COL_INFO, "Src %d (Port %d) -> Dst %d (Port %d)", src, src_port, dst, dst_port);

    proto_item *ti = proto_tree_add_item(tree, proto_csp, tvb, 0, -1, ENC_NA);
    proto_tree *csp_tree = proto_item_add_subtree(ti, ett_csp);

    proto_tree *csp_header_tree = proto_tree_add_subtree(csp_tree, tvb, 0, 4, ett_csp_header, NULL,
        "CSP Header");

    proto_tree_add_item(csp_header_tree, hf_csp_priority, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(csp_header_tree, hf_csp_source, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(csp_header_tree, hf_csp_destination, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(csp_header_tree, hf_csp_destination_port, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(csp_header_tree, hf_csp_source_port, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(csp_header_tree, hf_csp_reserved, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(csp_header_tree, hf_csp_hmac, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(csp_header_tree, hf_csp_xtea, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(csp_header_tree, hf_csp_rdp, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(csp_header_tree, hf_csp_crc, tvb, 0, 4, ENC_BIG_ENDIAN);

    proto_tree *csp_payload_tree = proto_tree_add_subtree(csp_tree, tvb, 4, -1, ett_csp_header, NULL,
        "CSP Payload");
    proto_tree_add_item(csp_payload_tree, hf_csp_payload, tvb, 4, tvb_reported_length(tvb) - 4, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

void
proto_register_csp(void)
{
    proto_csp = proto_register_protocol (
        "Cubesat Space Protocol", /* name        */
        "CSP",          /* short_name  */
        "csp"           /* filter_name */
        );

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_csp,
        &ett_csp_header,
        &ett_csp_payload
    };

    static hf_register_info hf[] = {
        { &hf_csp_priority,
            { "Priority", "csp.priority",
            FT_UINT32, BASE_DEC,
            NULL, 0xc0000000,
            NULL, HFILL }
        },
        { &hf_csp_source,
            { "Source", "csp.source",
            FT_UINT32, BASE_DEC,
            NULL, 0x3e000000,
            NULL, HFILL }
        },
        { &hf_csp_destination,
            { "Destination", "csp.destination",
            FT_UINT32, BASE_DEC,
            NULL, 0x01f00000,
            NULL, HFILL }
        },
        { &hf_csp_destination_port,
            { "Destination Port", "csp.destination_port",
            FT_UINT32, BASE_DEC,
            NULL, 0x000FC000,
            NULL, HFILL }
        },
        { &hf_csp_source_port,
            { "Source Port", "csp.source_port",
            FT_UINT32, BASE_DEC,
            NULL,0x00003f00,
            NULL, HFILL }
        },
        { &hf_csp_reserved,
            { "Reserved", "csp.reserved",
            FT_UINT32, BASE_DEC,
            NULL, 0x000000f0,
            NULL, HFILL }
        },
        { &hf_csp_hmac,
            { "Reserved Spare", "csp.hmac",
            FT_UINT32, BASE_DEC,
            NULL, 0x00000008,
            NULL, HFILL }
        },
        { &hf_csp_xtea,
            { "XTEA", "csp.xtea",
            FT_UINT32, BASE_DEC,
            NULL, 0x00000004,
            NULL, HFILL }
        },
        { &hf_csp_rdp,
            { "RDP", "csp.rdp",
            FT_UINT32, BASE_DEC,
            NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_csp_crc,
            { "CRC", "csp.crc",
            FT_UINT32, BASE_DEC,
            NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_csp_payload,
            { "Payload", "csp.payload",
            FT_BYTES, SEP_SPACE,
            NULL, 0x00,
            NULL, HFILL }
        }
    };

    proto_register_field_array(proto_csp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_csp(void)
{
    static dissector_handle_t csp_handle;

    csp_handle = create_dissector_handle(dissect_csp, proto_csp);
    dissector_add_uint("udp.port", 9600, csp_handle);
}