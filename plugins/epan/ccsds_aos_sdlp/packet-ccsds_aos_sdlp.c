#include "config.h"
#include <epan/packet.h>
#include <wiretap/wtap.h>

static int proto_aos_sdlp = -1;

static int hf_aos_sdlp_transfer_frame_version_number = -1;
static int hf_aos_sdlp_spacecraft_id = -1;
static int hf_aos_sdlp_virtual_channel_id = -1;
static int hf_aos_sdlp_virtual_channel_frame_count = -1;
static int hf_aos_sdlp_replay_flag = -1;
static int hf_aos_sdlp_virtual_channel_frame_count_cycle_use_flag = -1;
static int hf_aos_sdlp_reserved_spare = -1;
static int hf_aos_sdlp_virtual_channel_frame_count_cycle = -1;
static int hf_aos_sdlp_m_pdu_reserved_spare = -1;
static int hf_aos_sdlp_m_pdu_first_header_pointer = -1;
static int hf_aos_sdlp_m_pdu_packet_zone = -1;
static int hf_aos_sdlp_frame_error_control_field= -1;

static gint ett_aos_sdlp = -1;
static gint ett_primary_header = -1;
static gint ett_master_channel_id = -1;
static gint ett_signaling_field = -1;
static gint ett_data_field = -1;
static gint ett_trailer = -1;
static gint ett_m_pdu_header = -1;

static int
dissect_aos_sdlp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AOS-SDLP");
    col_clear(pinfo->cinfo, COL_INFO);

    int head = tvb_get_guint16(tvb, 0, ENC_BIG_ENDIAN);
    int scid = (head >> 6) & 0xff;
    int vcid = head & 0x003f;
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "SC %d, VC %d", scid, vcid);

    int frame_count = tvb_get_guint24(tvb, 2, ENC_BIG_ENDIAN);
    int frame_count_cycle = tvb_get_guint8(tvb, 5) & 0x0f;
    col_add_fstr(pinfo->cinfo, COL_INFO, "VC Frame Count %d (Cycle %d)", frame_count, frame_count_cycle);

    proto_item *ti = proto_tree_add_item(tree, proto_aos_sdlp, tvb, 0, -1, ENC_NA);
    proto_tree *aos_sdlp_tree = proto_item_add_subtree(ti, ett_aos_sdlp);

    proto_tree *primary_header_tree = proto_tree_add_subtree(aos_sdlp_tree, tvb, 0, 6, ett_primary_header, NULL,
        "Transfer Frame Primary Header");
    proto_tree *master_channel_id_tree = proto_tree_add_subtree(primary_header_tree, tvb, 0, 6, ett_master_channel_id, NULL,
        "Master Channel Id");
    proto_tree_add_item(master_channel_id_tree, hf_aos_sdlp_transfer_frame_version_number, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(master_channel_id_tree, hf_aos_sdlp_spacecraft_id, tvb, 0, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(primary_header_tree, hf_aos_sdlp_virtual_channel_id, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(primary_header_tree, hf_aos_sdlp_virtual_channel_frame_count, tvb, 2, 3, ENC_BIG_ENDIAN);

    proto_tree *signaling_field_tree = proto_tree_add_subtree(primary_header_tree, tvb, 0, 6, ett_signaling_field, NULL,
        "Signaling Field");
    proto_tree_add_item(signaling_field_tree, hf_aos_sdlp_replay_flag, tvb, 5, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(signaling_field_tree, hf_aos_sdlp_virtual_channel_frame_count_cycle_use_flag, tvb, 5, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(signaling_field_tree, hf_aos_sdlp_reserved_spare, tvb, 5, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(signaling_field_tree, hf_aos_sdlp_virtual_channel_frame_count_cycle, tvb, 5, 1, ENC_BIG_ENDIAN);

    proto_tree *data_field_tree = proto_tree_add_subtree(aos_sdlp_tree, tvb, 0, 6, ett_data_field, NULL,
        "Transfer Frame Data Field");
    proto_tree *m_pdu_header_tree = proto_tree_add_subtree(data_field_tree, tvb, 0, 6, ett_m_pdu_header, NULL,
        "M_PDU Header");
    proto_tree_add_item(m_pdu_header_tree, hf_aos_sdlp_m_pdu_reserved_spare, tvb, 6, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(m_pdu_header_tree, hf_aos_sdlp_m_pdu_first_header_pointer, tvb, 6, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(data_field_tree, hf_aos_sdlp_m_pdu_packet_zone, tvb, 8, tvb_reported_length(tvb) - 10, ENC_BIG_ENDIAN);

    proto_tree *trailer_tree = proto_tree_add_subtree(aos_sdlp_tree, tvb, 0, 6, ett_trailer, NULL,
        "Transfer Frame Trailer");
    proto_tree_add_item(trailer_tree, hf_aos_sdlp_frame_error_control_field, tvb, tvb_reported_length(tvb) - 2, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

void
proto_register_aos_sdlp(void)
{
    proto_aos_sdlp = proto_register_protocol (
        "CCSDS Advanced Orbiting Systems - Space Data Link Protocol", /* name        */
        "AOS-SDLP",          /* short_name  */
        "aos_sdlp"           /* filter_name */
        );

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_aos_sdlp,
        &ett_primary_header,
        &ett_master_channel_id,
        &ett_signaling_field,
        &ett_data_field,
        &ett_trailer,
        &ett_m_pdu_header
    };

    static hf_register_info hf[] = {
        { &hf_aos_sdlp_transfer_frame_version_number,
            { "Transfer Frame Version Number", "aos_sdlp.transfer_frame_version_number",
            FT_UINT16, BASE_DEC,
            NULL, 0xc000,
            NULL, HFILL }
        },
        { &hf_aos_sdlp_spacecraft_id,
            { "Spacecraft Id", "aos_sdlp.spacecraft_id",
            FT_UINT16, BASE_DEC,
            NULL, 0x3fc0,
            NULL, HFILL }
        },
        { &hf_aos_sdlp_virtual_channel_id,
            { "Virtual Channel Id", "aos_sdlp.virtual_channel_id",
            FT_UINT16, BASE_DEC,
            NULL, 0x003f,
            NULL, HFILL }
        },
        { &hf_aos_sdlp_virtual_channel_frame_count,
            { "Virtual Channel Frame Count", "aos_sdlp.virtual_channel_frame_count",
            FT_UINT24, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_aos_sdlp_replay_flag,
            { "Replay Flag", "aos_sdlp.replay_flag",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_aos_sdlp_virtual_channel_frame_count_cycle_use_flag,
            { "Virtual Channel Frame Count Cycle Use Flag", "aos_sdlp.virtual_channel_frame_count_cycle_use_flag",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_aos_sdlp_reserved_spare,
            { "Reserved Spare", "aos_sdlp.reserved_spare",
            FT_UINT8, BASE_DEC,
            NULL, 0x30,
            NULL, HFILL }
        },
        { &hf_aos_sdlp_virtual_channel_frame_count_cycle,
            { "Virtual Channel Frame Count Cycle", "aos_sdlp.virtual_channel_frame_count_cycle",
            FT_UINT8, BASE_DEC,
            NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_aos_sdlp_m_pdu_reserved_spare,
            { "Reserved Spare", "aos_sdlp.m_pdu_reserved_spare",
            FT_UINT16, BASE_DEC,
            NULL, 0xf800,
            NULL, HFILL }
        },
        { &hf_aos_sdlp_m_pdu_first_header_pointer,
            { "First Header Pointer", "aos_sdlp.m_pdu_first_header_pointer",
            FT_UINT16, BASE_HEX,
            NULL, 0x07ff,
            NULL, HFILL }
        },
        { &hf_aos_sdlp_m_pdu_packet_zone,
            { "M_PDU Packet Zone", "aos_sdlp.m_pdu_packet_zone",
            FT_BYTES, SEP_SPACE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_aos_sdlp_frame_error_control_field,
            { "Frame Error Control Field", "aos_sdlp.frame_error_control_field",
            FT_BYTES, SEP_SPACE,
            NULL, 0x00,
            NULL, HFILL }
        }
    };

    proto_register_field_array(proto_aos_sdlp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aos_sdlp(void)
{
    static dissector_handle_t aos_sdlp_handle;

    aos_sdlp_handle = create_dissector_handle(dissect_aos_sdlp, proto_aos_sdlp);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER0, aos_sdlp_handle);
}