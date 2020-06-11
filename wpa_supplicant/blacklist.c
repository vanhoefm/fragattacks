/*
 * wpa_supplicant - Temporary BSSID blacklist
 * Copyright (c) 2003-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "wpa_supplicant_i.h"
#include "blacklist.h"

/**
 * wpa_blacklist_get - Get the blacklist entry for a BSSID
 * @wpa_s: Pointer to wpa_supplicant data
 * @bssid: BSSID
 * Returns: Matching blacklist entry for the BSSID or %NULL if not found
 */
struct wpa_blacklist * wpa_blacklist_get(struct wpa_supplicant *wpa_s,
					 const u8 *bssid)
{
	struct wpa_blacklist *e;

	if (wpa_s == NULL || bssid == NULL)
		return NULL;

	if (wpa_s->current_ssid &&
	    wpa_s->current_ssid->was_recently_reconfigured) {
		wpa_blacklist_clear(wpa_s);
		wpa_s->current_ssid->was_recently_reconfigured = false;
		return NULL;
	}

	wpa_blacklist_update(wpa_s);

	e = wpa_s->blacklist;
	while (e) {
		if (os_memcmp(e->bssid, bssid, ETH_ALEN) == 0)
			return e;
		e = e->next;
	}

	return NULL;
}


/**
 * wpa_blacklist_add - Add an BSSID to the blacklist
 * @wpa_s: Pointer to wpa_supplicant data
 * @bssid: BSSID to be added to the blacklist
 * Returns: Current blacklist count on success, -1 on failure
 *
 * This function adds the specified BSSID to the blacklist or increases the
 * blacklist count if the BSSID was already listed. It should be called when
 * an association attempt fails either due to the selected BSS rejecting
 * association or due to timeout.
 *
 * This blacklist is used to force %wpa_supplicant to go through all available
 * BSSes before retrying to associate with an BSS that rejected or timed out
 * association. It does not prevent the listed BSS from being used; it only
 * changes the order in which they are tried.
 */
int wpa_blacklist_add(struct wpa_supplicant *wpa_s, const u8 *bssid)
{
	struct wpa_blacklist *e;
	struct os_reltime now;

	if (wpa_s == NULL || bssid == NULL)
		return -1;

	e = wpa_blacklist_get(wpa_s, bssid);
	os_get_reltime(&now);
	if (e) {
		e->blacklist_start = now;
		e->count++;
		if (e->count > 5)
			e->timeout_secs = 1800;
		else if (e->count == 5)
			e->timeout_secs = 600;
		else if (e->count == 4)
			e->timeout_secs = 120;
		else if (e->count == 3)
			e->timeout_secs = 60;
		else
			e->timeout_secs = 10;
		wpa_printf(MSG_INFO, "BSSID " MACSTR
			   " blacklist count incremented to %d, blacklisting for %d seconds",
			   MAC2STR(bssid), e->count, e->timeout_secs);
		return e->count;
	}

	e = os_zalloc(sizeof(*e));
	if (e == NULL)
		return -1;
	os_memcpy(e->bssid, bssid, ETH_ALEN);
	e->count = 1;
	e->timeout_secs = 10;
	e->blacklist_start = now;
	e->next = wpa_s->blacklist;
	wpa_s->blacklist = e;
	wpa_printf(MSG_DEBUG, "Added BSSID " MACSTR
		   " into blacklist, blacklisting for %d seconds",
		   MAC2STR(bssid), e->timeout_secs);

	return e->count;
}


/**
 * wpa_blacklist_del - Remove an BSSID from the blacklist
 * @wpa_s: Pointer to wpa_supplicant data
 * @bssid: BSSID to be removed from the blacklist
 * Returns: 0 on success, -1 on failure
 */
int wpa_blacklist_del(struct wpa_supplicant *wpa_s, const u8 *bssid)
{
	struct wpa_blacklist *e, *prev = NULL;

	if (wpa_s == NULL || bssid == NULL)
		return -1;

	e = wpa_s->blacklist;
	while (e) {
		if (os_memcmp(e->bssid, bssid, ETH_ALEN) == 0) {
			if (prev == NULL) {
				wpa_s->blacklist = e->next;
			} else {
				prev->next = e->next;
			}
			wpa_printf(MSG_DEBUG, "Removed BSSID " MACSTR " from "
				   "blacklist", MAC2STR(bssid));
			os_free(e);
			return 0;
		}
		prev = e;
		e = e->next;
	}
	return -1;
}


/**
 * wpa_blacklist_is_blacklisted - Check the blacklist status of a BSS
 * @wpa_s: Pointer to wpa_supplicant data
 * @bssid: BSSID to be checked
 * Returns: count if BSS is currently considered to be blacklisted, 0 otherwise
 */
int wpa_blacklist_is_blacklisted(struct wpa_supplicant *wpa_s, const u8 *bssid)
{
	struct wpa_blacklist *e;
	struct os_reltime now;

	e = wpa_blacklist_get(wpa_s, bssid);
	if (!e)
		return 0;
	os_get_reltime(&now);
	if (os_reltime_expired(&now, &e->blacklist_start, e->timeout_secs))
		return 0;
	return e->count;
}


/**
 * wpa_blacklist_clear - Clear the blacklist of all entries
 * @wpa_s: Pointer to wpa_supplicant data
 */
void wpa_blacklist_clear(struct wpa_supplicant *wpa_s)
{
	struct wpa_blacklist *e, *prev;

	e = wpa_s->blacklist;
	wpa_s->blacklist = NULL;
	while (e) {
		prev = e;
		e = e->next;
		wpa_printf(MSG_DEBUG, "Removed BSSID " MACSTR " from "
			   "blacklist (clear)", MAC2STR(prev->bssid));
		os_free(prev);
	}
}


/**
 * wpa_blacklist_update - Update the entries in the blacklist,
 * deleting entries that have been expired for over an hour.
 * @wpa_s: Pointer to wpa_supplicant data
 */
void wpa_blacklist_update(struct wpa_supplicant *wpa_s)
{
	struct wpa_blacklist *e, *prev = NULL;
	struct os_reltime now;

	if (!wpa_s)
		return;

	e = wpa_s->blacklist;
	os_get_reltime(&now);
	while (e) {
		if (os_reltime_expired(&now, &e->blacklist_start,
				       e->timeout_secs + 3600)) {
			struct wpa_blacklist *to_delete = e;

			if (prev) {
				prev->next = e->next;
				e = prev->next;
			} else {
				wpa_s->blacklist = e->next;
				e = wpa_s->blacklist;
			}
			wpa_printf(MSG_INFO, "Removed BSSID " MACSTR
				   " from blacklist (expired)",
				   MAC2STR(to_delete->bssid));
			os_free(to_delete);
		} else {
			prev = e;
			e = e->next;
		}
	}
}
