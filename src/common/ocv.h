/*
 * Operating Channel Validation (OCV)
 * Copyright (c) 2018, Mathy Vanhoef
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef OCV_H
#define OCV_H

struct wpa_channel_info;

struct oci_info {
	/* Values in the OCI element */
	u8 op_class;
	u8 channel;
	u8 seg1_idx;

	/* Derived values for easier verification */
	int freq;
	int sec_channel;
	int chanwidth;
};

#define OCV_OCI_LEN		3
#define OCV_OCI_EXTENDED_LEN	(3 + OCV_OCI_LEN)
#define OCV_OCI_KDE_LEN		(2 + RSN_SELECTOR_LEN + OCV_OCI_LEN)

extern char ocv_errorstr[256];

int ocv_derive_all_parameters(struct oci_info *oci);
int ocv_insert_oci(struct wpa_channel_info *ci, u8 **argpos);
int ocv_insert_oci_kde(struct wpa_channel_info *ci, u8 **argpos);
int ocv_insert_extended_oci(struct wpa_channel_info *ci, u8 *pos);

#endif /* OCV_H */
