/* packet-ubx-udp.c
 *
 * Dissector for UBX protocol packets carried over UDP (port 26423).
 * Delegates full UBX frame dissection to Wireshark's built-in ubx dissector.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>

#define UBX_UDP_PORT 26423

static int proto_ubx_udp = -1;
static dissector_handle_t ubx_udp_handle;
static dissector_handle_t ubx_handle;

static int
dissect_ubx_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* Hand off the entire UDP payload to the built-in UBX dissector. */
    return call_dissector_with_data(ubx_handle, tvb, pinfo, tree, data);
}

void
proto_register_ubx_udp(void)
{
    proto_ubx_udp = proto_register_protocol(
        "UBX over UDP",  /* full name */
        "UBX-UDP",       /* short name */
        "ubx_udp"        /* filter name */
    );

    ubx_udp_handle = create_dissector_handle(dissect_ubx_udp, proto_ubx_udp);
}

void
proto_reg_handoff_ubx_udp(void)
{
    /* Locate the built-in UBX dissector registered by packet-ubx.c. */
    ubx_handle = find_dissector("ubx");

    /* Register this dissector for UDP port 26423. */
    dissector_add_uint("udp.port", UBX_UDP_PORT, ubx_udp_handle);
}
