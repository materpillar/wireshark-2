#include "config.h"
#include <epan/packet.h>

static int proto_kna_rf = -1;

static int hf_kna_rf_length = -1;
static int hf_kna_rf_version = -1;
static int hf_kna_rf_type_reserved = -1;
static int hf_kna_rf_type_noack = -1;
static int hf_kna_rf_type_packet_type = -1;
static int hf_kna_rf_type_reserved2 = -1;
static int hf_kna_rf_type_encryption = -1;
static int hf_kna_rf_rf_addr = -1;
static int hf_kna_rf_seq0 = -1;
static int hf_kna_rf_seq1 = -1;
static int hf_kna_rf_seq2 = -1;
static int hf_kna_rf_payload = -1;

static gint ett_kna_rf = -1;
static gint ett_kna_rf_header = -1;
static gint ett_kna_rf_type = -1;
static gint ett_kna_rf_payload = -1;

static dissector_handle_t csp_handle;

static int
dissect_kna_rf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "KNA RF");
    col_clear(pinfo->cinfo, COL_INFO);

    uint16_t length = tvb_get_guint16(tvb, 0, ENC_BIG_ENDIAN);
    uint16_t rf_addr = tvb_get_guint16(tvb, 4, ENC_BIG_ENDIAN);
    uint16_t seq0 = tvb_get_guint8(tvb, 7);
    uint16_t seq1 = tvb_get_guint8(tvb, 8);
    uint16_t seq2 = tvb_get_guint8(tvb, 9);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Length %d, RFAddr %d, Seq %d (%d/%d)", length, rf_addr, seq0, seq1, seq2);

    proto_item *ti = proto_tree_add_item(tree, proto_kna_rf, tvb, 0, -1, ENC_NA);
    proto_tree *kna_rf_tree = proto_item_add_subtree(ti, ett_kna_rf);

    proto_tree *kna_rf_header_tree = proto_tree_add_subtree(kna_rf_tree, tvb, 0, 4, ett_kna_rf_header, NULL,"Header");
    proto_tree_add_item(kna_rf_header_tree, hf_kna_rf_length, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(kna_rf_header_tree, hf_kna_rf_version, tvb, 2, 1, ENC_BIG_ENDIAN);
    
    proto_tree *kna_rf_type_tree = proto_tree_add_subtree(kna_rf_header_tree, tvb, 3, 1, ett_kna_rf_type, NULL, "Type");
    proto_tree_add_item(kna_rf_type_tree, hf_kna_rf_type_reserved, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(kna_rf_type_tree, hf_kna_rf_type_noack, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(kna_rf_type_tree, hf_kna_rf_type_packet_type, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(kna_rf_type_tree, hf_kna_rf_type_reserved2, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(kna_rf_type_tree, hf_kna_rf_type_encryption, tvb, 0, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(kna_rf_header_tree, hf_kna_rf_rf_addr, tvb, 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(kna_rf_header_tree, hf_kna_rf_seq0, tvb, 6, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(kna_rf_header_tree, hf_kna_rf_seq1, tvb, 7, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(kna_rf_header_tree, hf_kna_rf_seq2, tvb, 8, 1, ENC_BIG_ENDIAN);

    tvbuff_t* next_tvb = tvb_new_subset_remaining(tvb, 9);
    call_dissector(csp_handle, next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

void
proto_register_kna_rf(void)
{
    proto_kna_rf = proto_register_protocol (
        "NanoAvionics RF Protocol", /* name        */
        "KNA RF",          /* short_name  */
        "kna_rf"           /* filter_name */
        );

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_kna_rf,
        &ett_kna_rf_header,
        &ett_kna_rf_type,
        &ett_kna_rf_payload
    };

    static const value_string packettypenames[] = {
        { 0, "Data" },
        { 1, "Reserved" },
        { 2, "Service" },
        { 3, NULL }
    };

    static hf_register_info hf[] = {
        { &hf_kna_rf_length,
            { "Length", "kna_rf.length",
            FT_UINT16, BASE_DEC,
            NULL, 0xffff,
            NULL, HFILL }
        },
        { &hf_kna_rf_version,
            { "Version", "kna_rf.version",
            FT_UINT8, BASE_DEC,
            NULL, 0xff,
            NULL, HFILL }
        },
        { &hf_kna_rf_type_reserved,
            { "Reserved", "kna_rf.type.reserved",
            FT_UINT8, BASE_DEC,
            NULL, 0xc0,
            NULL, HFILL }
        },
        { &hf_kna_rf_type_noack,
            { "NoAck", "kna_rf.type.noack",
            FT_UINT8, BASE_DEC,
            NULL, 0x020,
            NULL, HFILL }
        },
        { &hf_kna_rf_type_packet_type,
            { "Packet Type", "kna_rf.type.packet_type",
            FT_UINT8, BASE_DEC,
            VALS(packettypenames), 0x018,
            NULL, HFILL }
        },
        { &hf_kna_rf_type_reserved2,
            { "Reserved (2)", "kna_rf.type.reserved2",
            FT_UINT8, BASE_DEC,
            NULL, 0x06,
            NULL, HFILL }
        },
        { &hf_kna_rf_type_encryption,
            { "Encryption", "kna_rf.type.encryption",
            FT_UINT8, BASE_DEC,
            NULL, 0x01,
            NULL, HFILL }
        }, 
        { &hf_kna_rf_rf_addr,
            { "RF Address", "kna_rf.rf_addr",
            FT_UINT16, BASE_DEC,
            NULL, 0xffff,
            NULL, HFILL }
        }, 
        { &hf_kna_rf_seq0,
            { "Sequence 0 (packet sequence ID)", "kna_rf.seq0",
            FT_UINT8, BASE_DEC,
            NULL, 0xff,
            NULL, HFILL }
        }, 
        { &hf_kna_rf_seq1,
            { "Sequence 1 (quantity of packets)", "kna_rf.seq1",
            FT_UINT8, BASE_DEC,
            NULL, 0xff,
            NULL, HFILL }
        }, 
        { &hf_kna_rf_seq2,
            { "Sequence 2 (number of current packet in the sequence)", "kna_rf.seq2",
            FT_UINT8, BASE_DEC,
            NULL, 0xff,
            NULL, HFILL }
        },
        { &hf_kna_rf_payload,
            { "Payload", "kna_rf.payload",
            FT_BYTES, SEP_SPACE,
            NULL, 0x00,
            NULL, HFILL }
        }
    };

    proto_register_field_array(proto_kna_rf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_kna_rf(void)
{
    static dissector_handle_t kna_rf_handle;

    csp_handle = find_dissector("csp");

    kna_rf_handle = create_dissector_handle(dissect_kna_rf, proto_kna_rf);
    dissector_add_uint("udp.port", 9601, kna_rf_handle);
}