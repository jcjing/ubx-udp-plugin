/* packet-ubx-ext.c
 *
 * Additional UBX message dissectors not yet covered by Wireshark's built-in
 * packet-ubx.c dissector.  These dissectors register themselves into the same
 * "ubx.msg_class_id" dissector table so they are automatically invoked when
 * the built-in UBX framing dissector encounters these message class/IDs.
 *
 * Messages implemented:
 *   UBX-NAV-ATT    (0x0105) - Vehicle Attitude Solution
 *   UBX-ESF-ALG    (0x1014) - IMU Alignment Information
 *   UBX-ESF-INS    (0x1015) - Vehicle Dynamics Information
 *   UBX-ESF-MEAS   (0x1002) - External Sensor Fusion Measurements
 *   UBX-ESF-RAW    (0x1003) - Raw Sensor Measurements
 *   UBX-ESF-STATUS (0x1010) - External Sensor Fusion Status
 *   UBX-NAV-SIG    (0x0143) - Signal Information  (gen-9+ firmware)
 *
 * Reference: u-blox M8/M9/F9 Interface Descriptions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>

/*
 * Local copies of WS_DLL_PUBLIC symbols used in static hf[] initializers.
 * MSVC cannot use the address of a __declspec(dllimport) symbol as a
 * compile-time constant (it is resolved via the import address table at
 * load time). Defining module-local copies with the same values works
 * around this restriction.
 */
static const true_false_string tfs_local_yes_no = { "Yes", "No" };
static const unit_name_string  units_local_ms   = { "ms",    NULL };
static const unit_name_string  units_local_hz   = { "Hz",    NULL };
static const unit_name_string  units_local_dbhz = { " dB-Hz", NULL };

/* -- message class/ID constants ------------------------------------------- */
#define UBX_NAV_ATT    0x0105
#define UBX_ESF_ALG    0x1014
#define UBX_ESF_INS    0x1015
#define UBX_ESF_MEAS   0x1002
#define UBX_ESF_RAW    0x1003
#define UBX_ESF_STATUS 0x1010
#define UBX_NAV_SIG    0x0143   /* not in packet-ubx.h (gen-9 message) */

/* -- protocol handles ------------------------------------------------------ */
static int proto_ubx_ext = -1;

/* -- ett (expand/collapse subtree) handles --------------------------------- */
static int ett_ubx_nav_att           = -1;
static int ett_ubx_esf_alg           = -1;
static int ett_ubx_esf_ins           = -1;
static int ett_ubx_esf_meas          = -1;
static int ett_ubx_esf_meas_data     = -1;
static int ett_ubx_esf_raw           = -1;
static int ett_ubx_esf_raw_data      = -1;
static int ett_ubx_esf_status        = -1;
static int ett_ubx_esf_status_sensor = -1;
static int ett_ubx_nav_sig           = -1;
static int ett_ubx_nav_sig_sv        = -1;

/* ===================== UBX-NAV-ATT fields ================================= */
static int hf_ubx_nav_att;          /* top-level subtree item (FT_NONE) */
static int hf_ubx_nav_att_itow;
static int hf_ubx_nav_att_version;
static int hf_ubx_nav_att_reserved0;
static int hf_ubx_nav_att_roll;
static int hf_ubx_nav_att_pitch;
static int hf_ubx_nav_att_heading;
static int hf_ubx_nav_att_acc_roll;
static int hf_ubx_nav_att_acc_pitch;
static int hf_ubx_nav_att_acc_heading;

/* ===================== UBX-ESF-ALG fields ================================= */
static int hf_ubx_esf_alg;
static int hf_ubx_esf_alg_itow;
static int hf_ubx_esf_alg_version;
/* bitfield flags at byte 4 */
static int hf_ubx_esf_alg_flags;
static int hf_ubx_esf_alg_auto_mntalg_on;
static int hf_ubx_esf_alg_status;
static int hf_ubx_esf_alg_tilt_align_err;
static int hf_ubx_esf_alg_yaw_align_err;
static int hf_ubx_esf_alg_angle_err;
static int hf_ubx_esf_alg_yaw;
static int hf_ubx_esf_alg_pitch;
static int hf_ubx_esf_alg_roll;

/* ===================== UBX-ESF-INS fields ================================= */
static int hf_ubx_esf_ins;
static int hf_ubx_esf_ins_bitfield0;
static int hf_ubx_esf_ins_version;
static int hf_ubx_esf_ins_xangrate_valid;
static int hf_ubx_esf_ins_yangrate_valid;
static int hf_ubx_esf_ins_zangrate_valid;
static int hf_ubx_esf_ins_xaccel_valid;
static int hf_ubx_esf_ins_yaccel_valid;
static int hf_ubx_esf_ins_zaccel_valid;
static int hf_ubx_esf_ins_itow;
static int hf_ubx_esf_ins_xangrate;
static int hf_ubx_esf_ins_yangrate;
static int hf_ubx_esf_ins_zangrate;
static int hf_ubx_esf_ins_xaccel;
static int hf_ubx_esf_ins_yaccel;
static int hf_ubx_esf_ins_zaccel;

/* ===================== UBX-ESF-MEAS fields ================================ */
static int hf_ubx_esf_meas;
static int hf_ubx_esf_meas_time_tag;
static int hf_ubx_esf_meas_flags;
static int hf_ubx_esf_meas_time_mark_sent;
static int hf_ubx_esf_meas_time_mark_edge;
static int hf_ubx_esf_meas_calib_ttag_valid;
static int hf_ubx_esf_meas_id;
static int hf_ubx_esf_meas_data_field;
static int hf_ubx_esf_meas_data_type;
static int hf_ubx_esf_meas_data_value;
static int hf_ubx_esf_meas_calib_ttag;

/* ===================== UBX-ESF-RAW fields ================================= */
static int hf_ubx_esf_raw;
static int hf_ubx_esf_raw_data_field;
static int hf_ubx_esf_raw_data_type;
static int hf_ubx_esf_raw_data_value;
static int hf_ubx_esf_raw_sens_time_tag;

/* ===================== UBX-ESF-STATUS fields ============================== */
static int hf_ubx_esf_status;       /* top-level subtree item (FT_NONE) */
static int hf_ubx_esf_status_itow;
static int hf_ubx_esf_status_version;
static int hf_ubx_esf_status_fusion_mode;
static int hf_ubx_esf_status_num_sens;
/* per-sensor */
static int hf_ubx_esf_status_sens_type;
static int hf_ubx_esf_status_sens_used;
static int hf_ubx_esf_status_sens_ready;
static int hf_ubx_esf_status_sens_calib_status;
static int hf_ubx_esf_status_sens_time_status;
static int hf_ubx_esf_status_sens_freq;
static int hf_ubx_esf_status_sens_bad_meas;
static int hf_ubx_esf_status_sens_bad_ttag;
static int hf_ubx_esf_status_sens_missing_meas;
static int hf_ubx_esf_status_sens_noisy_meas;

/* ===================== UBX-NAV-SIG fields ================================= */
static int hf_ubx_nav_sig;          /* top-level subtree item (FT_NONE) */
static int hf_ubx_nav_sig_itow;
static int hf_ubx_nav_sig_version;
static int hf_ubx_nav_sig_num_sigs;
/* per-signal */
static int hf_ubx_nav_sig_gnss_id;
static int hf_ubx_nav_sig_sv_id;
static int hf_ubx_nav_sig_sig_id;
static int hf_ubx_nav_sig_freq_id;
static int hf_ubx_nav_sig_pr_res;
static int hf_ubx_nav_sig_cno;
static int hf_ubx_nav_sig_quality_ind;
static int hf_ubx_nav_sig_corr_source;
static int hf_ubx_nav_sig_iono_model;
static int hf_ubx_nav_sig_sig_flags;  /* parent bitmask word */
static int hf_ubx_nav_sig_health;
static int hf_ubx_nav_sig_pr_smoothed;
static int hf_ubx_nav_sig_pr_used;
static int hf_ubx_nav_sig_cr_used;
static int hf_ubx_nav_sig_do_used;
static int hf_ubx_nav_sig_pr_corr_used;
static int hf_ubx_nav_sig_cr_corr_used;
static int hf_ubx_nav_sig_do_corr_used;

/* -- value_string tables --------------------------------------------------- */

static const value_string ubx_esf_alg_status[] = {
    { 0, "User-defined" },
    { 1, "Roll/pitch initializing" },
    { 2, "Roll/pitch/yaw initializing" },
    { 3, "Coarse alignment" },
    { 4, "Fine alignment" },
    { 0, NULL }
};

static const value_string ubx_esf_time_mark_sent[] = {
    { 0, "None" },
    { 1, "On rising edge of extint0" },
    { 2, "On rising edge of extint1" },
    { 0, NULL }
};

static const value_string ubx_esf_fusion_mode[] = {
    { 0, "Initialization mode" },
    { 1, "Fusion mode" },
    { 2, "Suspended fusion mode" },
    { 3, "Disabled" },
    { 0, NULL }
};

static const value_string ubx_esf_sensor_type[] = {
    {  0, "(none)" },
    {  5, "Z-axis gyroscope" },
    {  6, "Front-left wheel-tick speed" },
    {  7, "Front-right wheel-tick speed" },
    {  8, "Rear-left wheel-tick speed" },
    {  9, "Rear-right wheel-tick speed" },
    { 10, "Single-tick speed" },
    { 11, "Speed" },
    { 12, "Gyroscope temperature" },
    { 13, "Y-axis gyroscope" },
    { 14, "X-axis gyroscope" },
    { 16, "X-axis accelerometer" },
    { 17, "Y-axis accelerometer" },
    { 18, "Z-axis accelerometer" },
    { 0, NULL }
};

static const value_string ubx_esf_calib_status[] = {
    { 0, "Not calibrated" },
    { 1, "Calibrating" },
    { 2, "Calibrated (coarse)" },
    { 3, "Calibrated (fine)" },
    { 0, NULL }
};

static const value_string ubx_esf_time_status[] = {
    { 0, "No data" },
    { 1, "First byte" },
    { 2, "Event input" },
    { 3, "Time-tagged" },
    { 0, NULL }
};

static const value_string ubx_nav_sig_gnss_id[] = {
    { 0, "GPS" },
    { 1, "SBAS" },
    { 2, "Galileo" },
    { 3, "BeiDou" },
    { 4, "IMES" },
    { 5, "QZSS" },
    { 6, "GLONASS" },
    { 0, NULL }
};

static const value_string ubx_nav_sig_quality_ind[] = {
    { 0, "No signal" },
    { 1, "Searching signal" },
    { 2, "Signal acquired" },
    { 3, "Signal detected, unusable" },
    { 4, "Code locked, time sync'd" },
    { 5, "Code+carrier locked, time sync'd" },
    { 6, "Code+carrier locked, time sync'd" },
    { 7, "Code+carrier locked, time sync'd" },
    { 0, NULL }
};

static const value_string ubx_nav_sig_corr_source[] = {
    { 0, "No corrections" },
    { 1, "SBAS corrections" },
    { 2, "BeiDou corrections" },
    { 3, "RTCM2 corrections" },
    { 4, "RTCM3 OSR corrections" },
    { 5, "RTCM3 SSR corrections" },
    { 6, "QZSS SLAS corrections" },
    { 0, NULL }
};

static const value_string ubx_nav_sig_iono_model[] = {
    { 0, "No model" },
    { 1, "Klobuchar GPS" },
    { 2, "SBAS" },
    { 3, "Klobuchar BeiDou" },
    { 8, "Dual-frequency estimate" },
    { 0, NULL }
};

static const value_string ubx_nav_sig_health[] = {
    { 0, "Unknown" },
    { 1, "Healthy" },
    { 2, "Unhealthy" },
    { 0, NULL }
};

/* signed 1e-2 deg for ESF-ALG yaw/pitch/roll */
static void fmt_angle_1e2_deg(char *label, uint32_t raw)
{
    int32_t v = (int32_t)raw;
    if (v < 0) { v = -v; snprintf(label, ITEM_LABEL_LENGTH, "-%d.%02d deg", v/100, v%100); }
    else        {         snprintf(label, ITEM_LABEL_LENGTH,  "%d.%02d deg", v/100, v%100); }
}

/* signed 1e-3 deg/s for ESF-INS angular rates */
static void fmt_ang_rate_1e3(char *label, uint32_t raw)
{
    int32_t v = (int32_t)raw;
    if (v < 0) { v = -v; snprintf(label, ITEM_LABEL_LENGTH, "-%d.%03d deg/s", v/1000, v%1000); }
    else        {         snprintf(label, ITEM_LABEL_LENGTH,  "%d.%03d deg/s", v/1000, v%1000); }
}

/* signed 1e-2 m/s^2 for ESF-INS accelerations */
static void fmt_accel_1e2(char *label, uint32_t raw)
{
    int32_t v = (int32_t)raw;
    if (v < 0) { v = -v; snprintf(label, ITEM_LABEL_LENGTH, "-%d.%02d m/s^2", v/100, v%100); }
    else        {         snprintf(label, ITEM_LABEL_LENGTH,  "%d.%02d m/s^2", v/100, v%100); }
}

/* -- custom formatter: signed angle in 1e-5 deg units --------------------- */
static void fmt_angle_1e5_deg(char *label, uint32_t raw)
{
    int32_t v = (int32_t)raw;
    if (v < 0) {
        v = -v;
        snprintf(label, ITEM_LABEL_LENGTH, "-%d.%05d deg", v / 100000, v % 100000);
    } else {
        snprintf(label, ITEM_LABEL_LENGTH, "%d.%05d deg", v / 100000, v % 100000);
    }
}

/* same formatter reused for unsigned accuracy fields */
static void fmt_acc_1e5_deg(char *label, uint32_t raw)
{
    snprintf(label, ITEM_LABEL_LENGTH, "%d.%05d deg", raw / 100000, raw % 100000);
}

/* pseudorange residual: signed, 0.1 m units */
static void fmt_pr_res_0p1m(char *label, uint32_t raw)
{
    int32_t v = (int32_t)(int16_t)(uint16_t)raw;   /* sign-extend 16-bit */
    if (v < 0) {
        v = -v;
        snprintf(label, ITEM_LABEL_LENGTH, "-%d.%01d m", v / 10, v % 10);
    } else {
        snprintf(label, ITEM_LABEL_LENGTH, "%d.%01d m", v / 10, v % 10);
    }
}

/* ===========================================================================
 * ESF-ALG flags bitmask fields
 * =========================================================================== */
static int * const ubx_esf_alg_flags_fields[] = {
    &hf_ubx_esf_alg_auto_mntalg_on,
    &hf_ubx_esf_alg_status,
    &hf_ubx_esf_alg_tilt_align_err,
    &hf_ubx_esf_alg_yaw_align_err,
    &hf_ubx_esf_alg_angle_err,
    NULL
};

/* ===========================================================================
 * ESF-INS bitfield0 fields
 * =========================================================================== */
static int * const ubx_esf_ins_bitfield0_fields[] = {
    &hf_ubx_esf_ins_version,
    &hf_ubx_esf_ins_xangrate_valid,
    &hf_ubx_esf_ins_yangrate_valid,
    &hf_ubx_esf_ins_zangrate_valid,
    &hf_ubx_esf_ins_xaccel_valid,
    &hf_ubx_esf_ins_yaccel_valid,
    &hf_ubx_esf_ins_zaccel_valid,
    NULL
};

/* ===========================================================================
 * ESF-MEAS flags bitmask fields
 * =========================================================================== */
static int * const ubx_esf_meas_flags_fields[] = {
    &hf_ubx_esf_meas_time_mark_sent,
    &hf_ubx_esf_meas_time_mark_edge,
    &hf_ubx_esf_meas_calib_ttag_valid,
    NULL
};

/* ===========================================================================
 * UBX-NAV-ATT dissector (32 bytes)
 * =========================================================================== */
static int
dissect_ubx_nav_att(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-ATT");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_att, tvb, 0, 32, ENC_NA);
    proto_tree *att_tree = proto_item_add_subtree(ti, ett_ubx_nav_att);

    proto_tree_add_item(att_tree, hf_ubx_nav_att_itow,     tvb,  0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(att_tree, hf_ubx_nav_att_version,  tvb,  4, 1, ENC_NA);
    proto_tree_add_item(att_tree, hf_ubx_nav_att_reserved0,tvb,  5, 3, ENC_NA);
    proto_tree_add_item(att_tree, hf_ubx_nav_att_roll,     tvb,  8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(att_tree, hf_ubx_nav_att_pitch,    tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(att_tree, hf_ubx_nav_att_heading,  tvb, 16, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(att_tree, hf_ubx_nav_att_acc_roll, tvb, 20, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(att_tree, hf_ubx_nav_att_acc_pitch,tvb, 24, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(att_tree, hf_ubx_nav_att_acc_heading, tvb, 28, 4, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

/* ===========================================================================
 * UBX-ESF-ALG dissector (16 bytes)
 * =========================================================================== */
static int
dissect_ubx_esf_alg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-ESF-ALG");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_esf_alg, tvb, 0, 16, ENC_NA);
    proto_tree *alg_tree = proto_item_add_subtree(ti, ett_ubx_esf_alg);

    proto_tree_add_item(alg_tree, hf_ubx_esf_alg_itow,    tvb,  0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(alg_tree, hf_ubx_esf_alg_version, tvb,  4, 1, ENC_NA);
    proto_tree_add_bitmask(alg_tree, tvb, 5, hf_ubx_esf_alg_flags,
                           ett_ubx_esf_alg, ubx_esf_alg_flags_fields,
                           ENC_LITTLE_ENDIAN);
    /* reserved bytes 6..7 */
    proto_tree_add_item(alg_tree, hf_ubx_esf_alg_yaw,   tvb,  8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(alg_tree, hf_ubx_esf_alg_pitch, tvb, 12, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(alg_tree, hf_ubx_esf_alg_roll,  tvb, 14, 2, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

/* ===========================================================================
 * UBX-ESF-INS dissector (36 bytes)
 * =========================================================================== */
static int
dissect_ubx_esf_ins(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-ESF-INS");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_esf_ins, tvb, 0, 36, ENC_NA);
    proto_tree *ins_tree = proto_item_add_subtree(ti, ett_ubx_esf_ins);

    proto_tree_add_bitmask(ins_tree, tvb, 0, hf_ubx_esf_ins_bitfield0,
                           ett_ubx_esf_ins, ubx_esf_ins_bitfield0_fields,
                           ENC_LITTLE_ENDIAN);
    /* reserved bytes 4..7 */
    proto_tree_add_item(ins_tree, hf_ubx_esf_ins_itow,      tvb,  8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ins_tree, hf_ubx_esf_ins_xangrate,  tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ins_tree, hf_ubx_esf_ins_yangrate,  tvb, 16, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ins_tree, hf_ubx_esf_ins_zangrate,  tvb, 20, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ins_tree, hf_ubx_esf_ins_xaccel,    tvb, 24, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ins_tree, hf_ubx_esf_ins_yaccel,    tvb, 28, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ins_tree, hf_ubx_esf_ins_zaccel,    tvb, 32, 4, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

/* ===========================================================================
 * UBX-ESF-MEAS dissector (variable: 8 + 4*N [+ 4 calib ttag])
 * =========================================================================== */
static int
dissect_ubx_esf_meas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-ESF-MEAS");
    col_clear(pinfo->cinfo, COL_INFO);

    uint32_t payload_len = tvb_reported_length(tvb);
    proto_item *ti = proto_tree_add_item(tree, hf_ubx_esf_meas, tvb, 0, payload_len, ENC_NA);
    proto_tree *meas_tree = proto_item_add_subtree(ti, ett_ubx_esf_meas);

    proto_tree_add_item(meas_tree, hf_ubx_esf_meas_time_tag, tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(meas_tree, tvb, 4, hf_ubx_esf_meas_flags,
                           ett_ubx_esf_meas, ubx_esf_meas_flags_fields,
                           ENC_LITTLE_ENDIAN);
    proto_tree_add_item(meas_tree, hf_ubx_esf_meas_id, tvb, 6, 2, ENC_LITTLE_ENDIAN);

    /* Determine number of data words (each 4 bytes). */
    /* calibTtag present when calib_ttag_valid flag (bit 3 of flags byte) set */
    uint16_t flags16      = tvb_get_letohs(tvb, 4);
    bool     calib_valid  = (flags16 & 0x0008) != 0;
    uint32_t data_bytes   = payload_len - 8 - (calib_valid ? 4 : 0);
    uint32_t num_data     = data_bytes / 4;

    for (uint32_t i = 0; i < num_data; i++) {
        uint32_t off     = 8 + 4 * i;
        uint32_t word    = tvb_get_letohl(tvb, off);
        uint8_t  type    = (word >> 24) & 0x3F;
        uint32_t raw_u24 = word & 0x00FFFFFF;
        /* sign-extend 24-bit to 32-bit */
        int32_t  raw24   = (raw_u24 & 0x800000) ?
                           (int32_t)(raw_u24 | 0xFF000000) :
                           (int32_t)raw_u24;

        proto_tree *d_tree = proto_tree_add_subtree_format(meas_tree, tvb,
                off, 4, ett_ubx_esf_meas_data, NULL,
                "Data %u: type=%u (%s)", i, type,
                val_to_str_const(type, ubx_esf_sensor_type, "Unknown"));

        char val_str[64];
        if (type == 16 || type == 17 || type == 18) {
            /* accelerometer: signed 24-bit, scaled by 2^-10 = 1/1024, m/s^2 */
            snprintf(val_str, sizeof(val_str), "%d (%.6f m/s^2)", raw24, raw24 / 1024.0);
        } else if (type == 5 || type == 13 || type == 14) {
            /* gyroscope: signed 24-bit, scaled by 2^-12 = 1/4096, deg/s */
            snprintf(val_str, sizeof(val_str), "%d (%.6f deg/s)", raw24, raw24 / 4096.0);
        } else if (type == 12) {
            /* gyro temperature: signed 24-bit, scaled by 1e-2, deg C */
            snprintf(val_str, sizeof(val_str), "%d (%.2f deg C)", raw24, raw24 / 100.0);
        } else if (type == 11) {
            /* speed: signed 24-bit, scaled by 1e-3, m/s */
            snprintf(val_str, sizeof(val_str), "%d (%.3f m/s)", raw24, raw24 / 1000.0);
        } else {
            snprintf(val_str, sizeof(val_str), "%d", raw24);
        }
        proto_tree_add_uint_format_value(d_tree, hf_ubx_esf_meas_data_value,
                tvb, off, 4, raw_u24, "%s", val_str);
        proto_tree_add_item(d_tree, hf_ubx_esf_meas_data_type,  tvb, off, 4, ENC_LITTLE_ENDIAN);
    }

    if (calib_valid) {
        proto_tree_add_item(meas_tree, hf_ubx_esf_meas_calib_ttag,
                            tvb, payload_len - 4, 4, ENC_LITTLE_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

/* ===========================================================================
 * UBX-ESF-RAW dissector (4 reserved + 8*N bytes)
 * =========================================================================== */
static int
dissect_ubx_esf_raw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-ESF-RAW");
    col_clear(pinfo->cinfo, COL_INFO);

    uint32_t payload_len = tvb_reported_length(tvb);
    proto_item *ti = proto_tree_add_item(tree, hf_ubx_esf_raw, tvb, 0, payload_len, ENC_NA);
    proto_tree *raw_tree = proto_item_add_subtree(ti, ett_ubx_esf_raw);

    /* 4 reserved bytes at offset 0 */
    uint32_t num_meas = (payload_len - 4) / 8;
    for (uint32_t i = 0; i < num_meas; i++) {
        uint32_t off  = 4 + 8 * i;
        uint32_t word = tvb_get_letohl(tvb, off);
        uint8_t  type = (word >> 24) & 0x3F;

        proto_tree *d_tree = proto_tree_add_subtree_format(raw_tree, tvb,
                off, 8, ett_ubx_esf_raw_data, NULL,
                "Meas %u: type=%u (%s)", i, type,
                val_to_str_const(type, ubx_esf_sensor_type, "Unknown"));
        proto_tree_add_item(d_tree, hf_ubx_esf_raw_data_value,    tvb, off,   4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(d_tree, hf_ubx_esf_raw_data_type,     tvb, off,   4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(d_tree, hf_ubx_esf_raw_sens_time_tag, tvb, off+4, 4, ENC_LITTLE_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

/* ===========================================================================
 * UBX-ESF-STATUS dissector (16 + 4*numSens bytes)
 * =========================================================================== */
static int
dissect_ubx_esf_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-ESF-STATUS");
    col_clear(pinfo->cinfo, COL_INFO);

    uint8_t num_sens = tvb_get_uint8(tvb, 15);
    uint32_t total_len = 16 + 4u * num_sens;

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_esf_status,
                                         tvb, 0, total_len, ENC_NA);
    proto_tree *esf_tree = proto_item_add_subtree(ti, ett_ubx_esf_status);

    proto_tree_add_item(esf_tree, hf_ubx_esf_status_itow,        tvb,  0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(esf_tree, hf_ubx_esf_status_version,     tvb,  4, 1, ENC_NA);
    /* reserved1 bytes 5..11 - show as raw bytes */
    proto_tree_add_item(esf_tree, hf_ubx_esf_status_fusion_mode, tvb, 12, 1, ENC_NA);
    /* reserved2 bytes 13..14 */
    proto_tree_add_item(esf_tree, hf_ubx_esf_status_num_sens,    tvb, 15, 1, ENC_NA);

    for (uint8_t i = 0; i < num_sens; i++) {
        uint32_t off = 16 + 4u * i;
        uint8_t  ss1  = tvb_get_uint8(tvb, off);
        uint8_t  type = ss1 & 0x3F;

        proto_tree *sens_tree = proto_tree_add_subtree_format(esf_tree, tvb,
                off, 4, ett_ubx_esf_status_sensor, NULL,
                "Sensor %u: %s", i,
                val_to_str_const(type, ubx_esf_sensor_type, "Unknown"));

        proto_tree_add_item(sens_tree, hf_ubx_esf_status_sens_type,        tvb, off,   1, ENC_NA);
        proto_tree_add_item(sens_tree, hf_ubx_esf_status_sens_used,        tvb, off,   1, ENC_NA);
        proto_tree_add_item(sens_tree, hf_ubx_esf_status_sens_ready,       tvb, off,   1, ENC_NA);
        proto_tree_add_item(sens_tree, hf_ubx_esf_status_sens_calib_status,tvb, off+1, 1, ENC_NA);
        proto_tree_add_item(sens_tree, hf_ubx_esf_status_sens_time_status, tvb, off+1, 1, ENC_NA);
        proto_tree_add_item(sens_tree, hf_ubx_esf_status_sens_freq,        tvb, off+2, 1, ENC_NA);
        proto_tree_add_item(sens_tree, hf_ubx_esf_status_sens_bad_meas,    tvb, off+3, 1, ENC_NA);
        proto_tree_add_item(sens_tree, hf_ubx_esf_status_sens_bad_ttag,    tvb, off+3, 1, ENC_NA);
        proto_tree_add_item(sens_tree, hf_ubx_esf_status_sens_missing_meas,tvb, off+3, 1, ENC_NA);
        proto_tree_add_item(sens_tree, hf_ubx_esf_status_sens_noisy_meas,  tvb, off+3, 1, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

/* ===========================================================================
 * UBX-NAV-SIG dissector (8 + 16*numSigs bytes)
 * =========================================================================== */

/* sigFlags bit-field sub-fields (parent is hf_ubx_nav_sig_sig_flags) */
static int * const ubx_nav_sig_flags_fields[] = {
    &hf_ubx_nav_sig_health,
    &hf_ubx_nav_sig_pr_smoothed,
    &hf_ubx_nav_sig_pr_used,
    &hf_ubx_nav_sig_cr_used,
    &hf_ubx_nav_sig_do_used,
    &hf_ubx_nav_sig_pr_corr_used,
    &hf_ubx_nav_sig_cr_corr_used,
    &hf_ubx_nav_sig_do_corr_used,
    NULL
};

static int
dissect_ubx_nav_sig(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-SIG");
    col_clear(pinfo->cinfo, COL_INFO);

    uint8_t  num_sigs  = tvb_get_uint8(tvb, 5);
    uint32_t total_len = 8 + 16u * num_sigs;

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_sig, tvb, 0, total_len, ENC_NA);
    proto_tree *sig_tree = proto_item_add_subtree(ti, ett_ubx_nav_sig);

    proto_tree_add_item(sig_tree, hf_ubx_nav_sig_itow,     tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(sig_tree, hf_ubx_nav_sig_version,  tvb, 4, 1, ENC_NA);
    proto_tree_add_item(sig_tree, hf_ubx_nav_sig_num_sigs, tvb, 5, 1, ENC_NA);
    /* reserved0 bytes 6..7 */

    for (uint8_t i = 0; i < num_sigs; i++) {
        uint32_t off     = 8 + 16u * i;
        uint8_t  gnss_id = tvb_get_uint8(tvb, off);
        uint8_t  sv_id   = tvb_get_uint8(tvb, off + 1);

        proto_tree *sv_tree = proto_tree_add_subtree_format(sig_tree, tvb,
                off, 16, ett_ubx_nav_sig_sv, NULL,
                "Signal %u: %s SV %u",
                i,
                val_to_str_const(gnss_id, ubx_nav_sig_gnss_id, "Unknown"),
                sv_id);

        proto_tree_add_item(sv_tree, hf_ubx_nav_sig_gnss_id,    tvb, off,    1, ENC_NA);
        proto_tree_add_item(sv_tree, hf_ubx_nav_sig_sv_id,      tvb, off+1,  1, ENC_NA);
        proto_tree_add_item(sv_tree, hf_ubx_nav_sig_sig_id,     tvb, off+2,  1, ENC_NA);
        proto_tree_add_item(sv_tree, hf_ubx_nav_sig_freq_id,    tvb, off+3,  1, ENC_NA);
        proto_tree_add_item(sv_tree, hf_ubx_nav_sig_pr_res,     tvb, off+4,  2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_tree, hf_ubx_nav_sig_cno,        tvb, off+6,  1, ENC_NA);
        proto_tree_add_item(sv_tree, hf_ubx_nav_sig_quality_ind,tvb, off+7,  1, ENC_NA);
        proto_tree_add_item(sv_tree, hf_ubx_nav_sig_corr_source,tvb, off+8,  1, ENC_NA);
        proto_tree_add_item(sv_tree, hf_ubx_nav_sig_iono_model, tvb, off+9,  1, ENC_NA);
        proto_tree_add_bitmask(sv_tree, tvb, off+10,
                hf_ubx_nav_sig_sig_flags,
                ett_ubx_nav_sig_sv,
                ubx_nav_sig_flags_fields,
                ENC_LITTLE_ENDIAN);
        /* reserved1 bytes off+12..off+15 */
    }

    return tvb_captured_length(tvb);
}

/* ===========================================================================
 * Protocol registration
 * =========================================================================== */

void
proto_register_ubx_ext(void)
{
    static hf_register_info hf[] = {

        /* -- UBX-NAV-ATT ------------------------------------------------- */
        { &hf_ubx_nav_att,
          { "UBX-NAV-ATT", "ubx.nav.att",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_nav_att_itow,
          { "iTOW", "ubx.nav.att.itow",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&units_local_ms),
            0x0, "GPS time of week", HFILL }},
        { &hf_ubx_nav_att_version,
          { "Version", "ubx.nav.att.version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_nav_att_reserved0,
          { "Reserved", "ubx.nav.att.reserved0",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_nav_att_roll,
          { "Vehicle Roll", "ubx.nav.att.roll",
            FT_INT32, BASE_CUSTOM, CF_FUNC(fmt_angle_1e5_deg), 0x0,
            "Vehicle roll angle (1e-5 deg)", HFILL }},
        { &hf_ubx_nav_att_pitch,
          { "Vehicle Pitch", "ubx.nav.att.pitch",
            FT_INT32, BASE_CUSTOM, CF_FUNC(fmt_angle_1e5_deg), 0x0,
            "Vehicle pitch angle (1e-5 deg)", HFILL }},
        { &hf_ubx_nav_att_heading,
          { "Vehicle Heading", "ubx.nav.att.heading",
            FT_INT32, BASE_CUSTOM, CF_FUNC(fmt_angle_1e5_deg), 0x0,
            "Vehicle heading angle (1e-5 deg)", HFILL }},
        { &hf_ubx_nav_att_acc_roll,
          { "Roll Accuracy (1-sigma)", "ubx.nav.att.acc_roll",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(fmt_acc_1e5_deg), 0x0,
            "Vehicle roll accuracy 1-sigma (1e-5 deg)", HFILL }},
        { &hf_ubx_nav_att_acc_pitch,
          { "Pitch Accuracy (1-sigma)", "ubx.nav.att.acc_pitch",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(fmt_acc_1e5_deg), 0x0,
            "Vehicle pitch accuracy 1-sigma (1e-5 deg)", HFILL }},
        { &hf_ubx_nav_att_acc_heading,
          { "Heading Accuracy (1-sigma)", "ubx.nav.att.acc_heading",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(fmt_acc_1e5_deg), 0x0,
            "Vehicle heading accuracy 1-sigma (1e-5 deg)", HFILL }},

        /* -- UBX-ESF-ALG ------------------------------------------------- */
        { &hf_ubx_esf_alg,
          { "UBX-ESF-ALG", "ubx.esf.alg",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_alg_itow,
          { "iTOW", "ubx.esf.alg.itow",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&units_local_ms),
            0x0, "GPS time of week", HFILL }},
        { &hf_ubx_esf_alg_version,
          { "Version", "ubx.esf.alg.version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_alg_flags,
          { "Flags", "ubx.esf.alg.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_alg_auto_mntalg_on,
          { "autoMntAlgOn", "ubx.esf.alg.auto_mntalg_on",
            FT_BOOLEAN, 8, TFS(&tfs_local_yes_no), 0x01,
            "Automatic IMU-mount alignment on", HFILL }},
        { &hf_ubx_esf_alg_status,
          { "IMU-mount alignment status", "ubx.esf.alg.status",
            FT_UINT8, BASE_DEC, VALS(ubx_esf_alg_status), 0x0E, NULL, HFILL }},
        { &hf_ubx_esf_alg_tilt_align_err,
          { "Tilt alignment error", "ubx.esf.alg.tilt_align_err",
            FT_BOOLEAN, 8, TFS(&tfs_local_yes_no), 0x10, NULL, HFILL }},
        { &hf_ubx_esf_alg_yaw_align_err,
          { "Yaw alignment error", "ubx.esf.alg.yaw_align_err",
            FT_BOOLEAN, 8, TFS(&tfs_local_yes_no), 0x20, NULL, HFILL }},
        { &hf_ubx_esf_alg_angle_err,
          { "IMU-mount angle determination error", "ubx.esf.alg.angle_err",
            FT_BOOLEAN, 8, TFS(&tfs_local_yes_no), 0x40, NULL, HFILL }},
        { &hf_ubx_esf_alg_yaw,
          { "IMU-mount yaw angle", "ubx.esf.alg.yaw",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(fmt_angle_1e2_deg), 0x0,
            "Yaw angle (0 = north, 0..36000, 1e-2 deg)", HFILL }},
        { &hf_ubx_esf_alg_pitch,
          { "IMU-mount pitch angle", "ubx.esf.alg.pitch",
            FT_INT16, BASE_CUSTOM, CF_FUNC(fmt_angle_1e2_deg), 0x0,
            "Pitch angle (-9000..9000, 1e-2 deg)", HFILL }},
        { &hf_ubx_esf_alg_roll,
          { "IMU-mount roll angle", "ubx.esf.alg.roll",
            FT_INT16, BASE_CUSTOM, CF_FUNC(fmt_angle_1e2_deg), 0x0,
            "Roll angle (-18000..18000, 1e-2 deg)", HFILL }},

        /* -- UBX-ESF-INS ------------------------------------------------- */
        { &hf_ubx_esf_ins,
          { "UBX-ESF-INS", "ubx.esf.ins",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_ins_bitfield0,
          { "Validity flags", "ubx.esf.ins.bitfield0",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_ins_version,
          { "bitfield0 version", "ubx.esf.ins.version",
            FT_UINT32, BASE_DEC, NULL, 0x000000FF, NULL, HFILL }},
        { &hf_ubx_esf_ins_xangrate_valid,
          { "xAngRate valid", "ubx.esf.ins.xangrate_valid",
            FT_BOOLEAN, 32, TFS(&tfs_local_yes_no), 0x00000100, NULL, HFILL }},
        { &hf_ubx_esf_ins_yangrate_valid,
          { "yAngRate valid", "ubx.esf.ins.yangrate_valid",
            FT_BOOLEAN, 32, TFS(&tfs_local_yes_no), 0x00000200, NULL, HFILL }},
        { &hf_ubx_esf_ins_zangrate_valid,
          { "zAngRate valid", "ubx.esf.ins.zangrate_valid",
            FT_BOOLEAN, 32, TFS(&tfs_local_yes_no), 0x00000400, NULL, HFILL }},
        { &hf_ubx_esf_ins_xaccel_valid,
          { "xAccel valid", "ubx.esf.ins.xaccel_valid",
            FT_BOOLEAN, 32, TFS(&tfs_local_yes_no), 0x00000800, NULL, HFILL }},
        { &hf_ubx_esf_ins_yaccel_valid,
          { "yAccel valid", "ubx.esf.ins.yaccel_valid",
            FT_BOOLEAN, 32, TFS(&tfs_local_yes_no), 0x00001000, NULL, HFILL }},
        { &hf_ubx_esf_ins_zaccel_valid,
          { "zAccel valid", "ubx.esf.ins.zaccel_valid",
            FT_BOOLEAN, 32, TFS(&tfs_local_yes_no), 0x00002000, NULL, HFILL }},
        { &hf_ubx_esf_ins_itow,
          { "iTOW", "ubx.esf.ins.itow",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&units_local_ms),
            0x0, "GPS time of week", HFILL }},
        { &hf_ubx_esf_ins_xangrate,
          { "X angular rate", "ubx.esf.ins.xangrate",
            FT_INT32, BASE_CUSTOM, CF_FUNC(fmt_ang_rate_1e3), 0x0,
            "X-axis angular rate (1e-3 deg/s)", HFILL }},
        { &hf_ubx_esf_ins_yangrate,
          { "Y angular rate", "ubx.esf.ins.yangrate",
            FT_INT32, BASE_CUSTOM, CF_FUNC(fmt_ang_rate_1e3), 0x0,
            "Y-axis angular rate (1e-3 deg/s)", HFILL }},
        { &hf_ubx_esf_ins_zangrate,
          { "Z angular rate", "ubx.esf.ins.zangrate",
            FT_INT32, BASE_CUSTOM, CF_FUNC(fmt_ang_rate_1e3), 0x0,
            "Z-axis angular rate (1e-3 deg/s)", HFILL }},
        { &hf_ubx_esf_ins_xaccel,
          { "X acceleration", "ubx.esf.ins.xaccel",
            FT_INT32, BASE_CUSTOM, CF_FUNC(fmt_accel_1e2), 0x0,
            "X-axis specific force (1e-2 m/s^2)", HFILL }},
        { &hf_ubx_esf_ins_yaccel,
          { "Y acceleration", "ubx.esf.ins.yaccel",
            FT_INT32, BASE_CUSTOM, CF_FUNC(fmt_accel_1e2), 0x0,
            "Y-axis specific force (1e-2 m/s^2)", HFILL }},
        { &hf_ubx_esf_ins_zaccel,
          { "Z acceleration", "ubx.esf.ins.zaccel",
            FT_INT32, BASE_CUSTOM, CF_FUNC(fmt_accel_1e2), 0x0,
            "Z-axis specific force (1e-2 m/s^2)", HFILL }},

        /* -- UBX-ESF-MEAS ----------------------------------------------- */
        { &hf_ubx_esf_meas,
          { "UBX-ESF-MEAS", "ubx.esf.meas",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_meas_time_tag,
          { "Time tag", "ubx.esf.meas.time_tag",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&units_local_ms),
            0x0, "Time since device startup", HFILL }},
        { &hf_ubx_esf_meas_flags,
          { "Flags", "ubx.esf.meas.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_meas_time_mark_sent,
          { "Time mark sent", "ubx.esf.meas.time_mark_sent",
            FT_UINT16, BASE_DEC, VALS(ubx_esf_time_mark_sent), 0x0003, NULL, HFILL }},
        { &hf_ubx_esf_meas_time_mark_edge,
          { "Time mark on rising edge", "ubx.esf.meas.time_mark_edge",
            FT_BOOLEAN, 16, TFS(&tfs_local_yes_no), 0x0004, NULL, HFILL }},
        { &hf_ubx_esf_meas_calib_ttag_valid,
          { "calibTtag valid", "ubx.esf.meas.calib_ttag_valid",
            FT_BOOLEAN, 16, TFS(&tfs_local_yes_no), 0x0008, NULL, HFILL }},
        { &hf_ubx_esf_meas_id,
          { "Receiver ID", "ubx.esf.meas.id",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_meas_data_field,
          { "Data word", "ubx.esf.meas.data",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_meas_data_type,
          { "Data type", "ubx.esf.meas.data.type",
            FT_UINT32, BASE_DEC, VALS(ubx_esf_sensor_type), 0xFF000000, NULL, HFILL }},
        { &hf_ubx_esf_meas_data_value,
          { "Data value", "ubx.esf.meas.data.value",
            FT_UINT32, BASE_DEC, NULL, 0x00FFFFFF, NULL, HFILL }},
        { &hf_ubx_esf_meas_calib_ttag,
          { "Calibration time tag", "ubx.esf.meas.calib_ttag",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&units_local_ms),
            0x0, "GNSS time of the calibration ttag", HFILL }},

        /* -- UBX-ESF-RAW ------------------------------------------------- */
        { &hf_ubx_esf_raw,
          { "UBX-ESF-RAW", "ubx.esf.raw",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_raw_data_field,
          { "Data word", "ubx.esf.raw.data",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_raw_data_type,
          { "Data type", "ubx.esf.raw.data.type",
            FT_UINT32, BASE_DEC, VALS(ubx_esf_sensor_type), 0xFF000000, NULL, HFILL }},
        { &hf_ubx_esf_raw_data_value,
          { "Data value", "ubx.esf.raw.data.value",
            FT_UINT32, BASE_DEC, NULL, 0x00FFFFFF, NULL, HFILL }},
        { &hf_ubx_esf_raw_sens_time_tag,
          { "Sensor time tag", "ubx.esf.raw.sens_time_tag",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&units_local_ms),
            0x0, "Time tag of sensor data", HFILL }},

        /* -- UBX-ESF-STATUS ----------------------------------------------- */
        { &hf_ubx_esf_status,
          { "UBX-ESF-STATUS", "ubx.esf.status",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_status_itow,
          { "iTOW", "ubx.esf.status.itow",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&units_local_ms),
            0x0, "GPS time of week", HFILL }},
        { &hf_ubx_esf_status_version,
          { "Version", "ubx.esf.status.version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_esf_status_fusion_mode,
          { "Fusion Mode", "ubx.esf.status.fusion_mode",
            FT_UINT8, BASE_DEC, VALS(ubx_esf_fusion_mode), 0x0, NULL, HFILL }},
        { &hf_ubx_esf_status_num_sens,
          { "Number of sensors", "ubx.esf.status.num_sens",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        /* sensor status1 */
        { &hf_ubx_esf_status_sens_type,
          { "Sensor type", "ubx.esf.status.sens.type",
            FT_UINT8, BASE_DEC, VALS(ubx_esf_sensor_type), 0x3F, NULL, HFILL }},
        { &hf_ubx_esf_status_sens_used,
          { "Used", "ubx.esf.status.sens.used",
            FT_BOOLEAN, 8, TFS(&tfs_local_yes_no), 0x40, "Sensor data used in fusion", HFILL }},
        { &hf_ubx_esf_status_sens_ready,
          { "Ready", "ubx.esf.status.sens.ready",
            FT_BOOLEAN, 8, TFS(&tfs_local_yes_no), 0x80, "Sensor is ready", HFILL }},
        /* sensor status2 */
        { &hf_ubx_esf_status_sens_calib_status,
          { "Calibration status", "ubx.esf.status.sens.calib_status",
            FT_UINT8, BASE_DEC, VALS(ubx_esf_calib_status), 0x03, NULL, HFILL }},
        { &hf_ubx_esf_status_sens_time_status,
          { "Time tag status", "ubx.esf.status.sens.time_status",
            FT_UINT8, BASE_DEC, VALS(ubx_esf_time_status), 0x0C, NULL, HFILL }},
        /* freq */
        { &hf_ubx_esf_status_sens_freq,
          { "Measurement frequency", "ubx.esf.status.sens.freq",
            FT_UINT8, BASE_DEC | BASE_UNIT_STRING, UNS(&units_local_hz),
            0x0, NULL, HFILL }},
        /* faults */
        { &hf_ubx_esf_status_sens_bad_meas,
          { "Bad measurements", "ubx.esf.status.sens.bad_meas",
            FT_BOOLEAN, 8, TFS(&tfs_local_yes_no), 0x01, NULL, HFILL }},
        { &hf_ubx_esf_status_sens_bad_ttag,
          { "Bad time tags", "ubx.esf.status.sens.bad_ttag",
            FT_BOOLEAN, 8, TFS(&tfs_local_yes_no), 0x02, NULL, HFILL }},
        { &hf_ubx_esf_status_sens_missing_meas,
          { "Missing measurements", "ubx.esf.status.sens.missing_meas",
            FT_BOOLEAN, 8, TFS(&tfs_local_yes_no), 0x04, NULL, HFILL }},
        { &hf_ubx_esf_status_sens_noisy_meas,
          { "Noisy measurements", "ubx.esf.status.sens.noisy_meas",
            FT_BOOLEAN, 8, TFS(&tfs_local_yes_no), 0x08, NULL, HFILL }},

        /* -- UBX-NAV-SIG -------------------------------------------------- */
        { &hf_ubx_nav_sig,
          { "UBX-NAV-SIG", "ubx.nav.sig",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_nav_sig_itow,
          { "iTOW", "ubx.nav.sig.itow",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&units_local_ms),
            0x0, "GPS time of week", HFILL }},
        { &hf_ubx_nav_sig_version,
          { "Version", "ubx.nav.sig.version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_nav_sig_num_sigs,
          { "Number of signals", "ubx.nav.sig.num_sigs",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        /* per-signal */
        { &hf_ubx_nav_sig_gnss_id,
          { "GNSS ID", "ubx.nav.sig.gnss_id",
            FT_UINT8, BASE_DEC, VALS(ubx_nav_sig_gnss_id), 0x0, NULL, HFILL }},
        { &hf_ubx_nav_sig_sv_id,
          { "SV ID", "ubx.nav.sig.sv_id",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubx_nav_sig_sig_id,
          { "Signal ID", "ubx.nav.sig.sig_id",
            FT_UINT8, BASE_DEC, NULL, 0x0, "Signal type within constellation", HFILL }},
        { &hf_ubx_nav_sig_freq_id,
          { "Frequency slot (GLONASS)", "ubx.nav.sig.freq_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "GLONASS frequency slot (255 if not applicable)", HFILL }},
        { &hf_ubx_nav_sig_pr_res,
          { "Pseudorange residual", "ubx.nav.sig.pr_res",
            FT_INT16, BASE_CUSTOM, CF_FUNC(fmt_pr_res_0p1m), 0x0,
            "PR residual (0.1 m)", HFILL }},
        { &hf_ubx_nav_sig_cno,
          { "C/N0", "ubx.nav.sig.cno",
            FT_UINT8, BASE_DEC | BASE_UNIT_STRING, UNS(&units_local_dbhz),
            0x0, "Carrier-to-noise density ratio", HFILL }},
        { &hf_ubx_nav_sig_quality_ind,
          { "Signal quality", "ubx.nav.sig.quality_ind",
            FT_UINT8, BASE_DEC, VALS(ubx_nav_sig_quality_ind), 0x07, NULL, HFILL }},
        { &hf_ubx_nav_sig_corr_source,
          { "Correction source", "ubx.nav.sig.corr_source",
            FT_UINT8, BASE_DEC, VALS(ubx_nav_sig_corr_source), 0x0, NULL, HFILL }},
        { &hf_ubx_nav_sig_iono_model,
          { "Ionospheric model", "ubx.nav.sig.iono_model",
            FT_UINT8, BASE_DEC, VALS(ubx_nav_sig_iono_model), 0x07, NULL, HFILL }},
        /* sigFlags: parent word then individual sub-fields */
        { &hf_ubx_nav_sig_sig_flags,
          { "Signal flags", "ubx.nav.sig.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Signal-related flags word (sigFlags)", HFILL }},
        { &hf_ubx_nav_sig_health,
          { "Health", "ubx.nav.sig.flags.health",
            FT_UINT16, BASE_DEC, VALS(ubx_nav_sig_health), 0x0003, NULL, HFILL }},
        { &hf_ubx_nav_sig_pr_smoothed,
          { "PR smoothed", "ubx.nav.sig.pr_smoothed",
            FT_BOOLEAN, 16, TFS(&tfs_local_yes_no), 0x0004, NULL, HFILL }},
        { &hf_ubx_nav_sig_pr_used,
          { "PR used", "ubx.nav.sig.pr_used",
            FT_BOOLEAN, 16, TFS(&tfs_local_yes_no), 0x0008, NULL, HFILL }},
        { &hf_ubx_nav_sig_cr_used,
          { "CR used", "ubx.nav.sig.cr_used",
            FT_BOOLEAN, 16, TFS(&tfs_local_yes_no), 0x0010, NULL, HFILL }},
        { &hf_ubx_nav_sig_do_used,
          { "Doppler used", "ubx.nav.sig.do_used",
            FT_BOOLEAN, 16, TFS(&tfs_local_yes_no), 0x0020, NULL, HFILL }},
        { &hf_ubx_nav_sig_pr_corr_used,
          { "PR corrections used", "ubx.nav.sig.pr_corr_used",
            FT_BOOLEAN, 16, TFS(&tfs_local_yes_no), 0x0040, NULL, HFILL }},
        { &hf_ubx_nav_sig_cr_corr_used,
          { "CR corrections used", "ubx.nav.sig.cr_corr_used",
            FT_BOOLEAN, 16, TFS(&tfs_local_yes_no), 0x0080, NULL, HFILL }},
        { &hf_ubx_nav_sig_do_corr_used,
          { "Doppler corrections used", "ubx.nav.sig.do_corr_used",
            FT_BOOLEAN, 16, TFS(&tfs_local_yes_no), 0x0100, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_ubx_nav_att,
        &ett_ubx_esf_alg,
        &ett_ubx_esf_ins,
        &ett_ubx_esf_meas,
        &ett_ubx_esf_meas_data,
        &ett_ubx_esf_raw,
        &ett_ubx_esf_raw_data,
        &ett_ubx_esf_status,
        &ett_ubx_esf_status_sensor,
        &ett_ubx_nav_sig,
        &ett_ubx_nav_sig_sv,
    };

    proto_ubx_ext = proto_register_protocol(
        "UBX Extended Dissectors",  /* full name  */
        "UBX-Ext",                  /* short name */
        "ubx_ext"                   /* filter     */
    );

    proto_register_field_array(proto_ubx_ext, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ubx_ext(void)
{
    /* Hook each dissector into the built-in "ubx.msg_class_id" table. */
    dissector_add_uint("ubx.msg_class_id", UBX_NAV_ATT,
        create_dissector_handle(dissect_ubx_nav_att,    proto_ubx_ext));
    dissector_add_uint("ubx.msg_class_id", UBX_ESF_ALG,
        create_dissector_handle(dissect_ubx_esf_alg,    proto_ubx_ext));
    dissector_add_uint("ubx.msg_class_id", UBX_ESF_INS,
        create_dissector_handle(dissect_ubx_esf_ins,    proto_ubx_ext));
    dissector_add_uint("ubx.msg_class_id", UBX_ESF_MEAS,
        create_dissector_handle(dissect_ubx_esf_meas,   proto_ubx_ext));
    dissector_add_uint("ubx.msg_class_id", UBX_ESF_RAW,
        create_dissector_handle(dissect_ubx_esf_raw,    proto_ubx_ext));
    dissector_add_uint("ubx.msg_class_id", UBX_ESF_STATUS,
        create_dissector_handle(dissect_ubx_esf_status, proto_ubx_ext));
    dissector_add_uint("ubx.msg_class_id", UBX_NAV_SIG,
        create_dissector_handle(dissect_ubx_nav_sig,    proto_ubx_ext));
}
