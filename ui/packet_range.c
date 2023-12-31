/* packet_range.c
 * Packet range routines (save, print, ...)
 *
 * Dick Gooris <gooris@lucent.com>
 * Ulf Lamping <ulf.lamping@web.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include <epan/frame_data.h>

#include "packet_range.h"

#include <wsutil/ws_assert.h>

/* (re-)calculate the packet counts (except the user specified range) */
static void packet_range_calc(packet_range_t *range) {
    guint32       framenum;
    guint32       mark_low;
    guint32       mark_high;
    guint32       displayed_mark_low;
    guint32       displayed_mark_high;
    frame_data    *packet;



    mark_low                                = 0;
    mark_high                               = 0;
    range->mark_range_cnt                   = 0;
    range->ignored_cnt                      = 0;
    range->ignored_selection_range_cnt      = 0;
    range->ignored_marked_cnt               = 0;
    range->ignored_mark_range_cnt           = 0;
    range->ignored_user_range_cnt           = 0;

    displayed_mark_low                      = 0;
    displayed_mark_high                     = 0;

    range->displayed_cnt                    = 0;
    range->displayed_marked_cnt             = 0;
    range->displayed_mark_range_cnt         = 0;
    range->displayed_plus_dependents_cnt    = 0;
    range->displayed_plus_dependents_mark_range_cnt  = 0;
    range->displayed_ignored_cnt            = 0;
    range->displayed_ignored_selection_range_cnt  = 0;
    range->displayed_ignored_marked_cnt     = 0;
    range->displayed_ignored_mark_range_cnt = 0;
    range->displayed_ignored_user_range_cnt = 0;

    ws_assert(range->cf != NULL);

    /* XXX - this doesn't work unless you have a full set of frame_data
     * structures for all packets in the capture, which is not,
     * for example, the case when TShark is doing a one-pass
     * read of a file or a live capture.
     *
     * It's also horribly slow on large captures, causing it to
     * take a long time for the Save As dialog to pop up, for
     * example.  We should really keep these statistics in
     * the capture_file structure, updating them whenever we
     * filter the display, etc..
     */
    if (range->cf->provider.frames != NULL) {
        /* The next for-loop is used to obtain the amount of packets
         * to be processed and is used to present the information in
         * the Save/Print As widget.
         * We have different types of ranges: All the packets, the number
         * of packets of a marked range, a single packet, and a user specified
         * packet range. The last one is not calculated here since this
         * data must be entered in the widget by the user.
         */

        for(framenum = 1; framenum <= range->cf->count; framenum++) {
            packet = frame_data_sequence_find(range->cf->provider.frames, framenum);

            if (range->cf->current_frame == packet && range->selection_range == NULL ) {
                range_add_value(NULL, &(range->selection_range), framenum);
            }
            if (packet->passed_dfilter) {
                range->displayed_cnt++;
            }
            if (packet->passed_dfilter ||
                packet->dependent_of_displayed) {
                range->displayed_plus_dependents_cnt++;
            }
            if (packet->marked) {
                if (packet->ignored) {
                    range->ignored_marked_cnt++;
                }
                if (packet->passed_dfilter) {
                    range->displayed_marked_cnt++;
                    if (packet->ignored) {
                        range->displayed_ignored_marked_cnt++;
                    }
                    if (displayed_mark_low == 0) {
                       displayed_mark_low = framenum;
                    }
                    if (framenum > displayed_mark_high) {
                       displayed_mark_high = framenum;
                    }
                }

                if (mark_low == 0) {
                   mark_low = framenum;
                }
                if (framenum > mark_high) {
                   mark_high = framenum;
                }
            }
            if (packet->ignored) {
                range->ignored_cnt++;
                if (packet->passed_dfilter) {
                    range->displayed_ignored_cnt++;
                }
            }
        }

        for(framenum = 1; framenum <= range->cf->count; framenum++) {
            packet = frame_data_sequence_find(range->cf->provider.frames, framenum);

            if (framenum >= mark_low &&
                framenum <= mark_high)
            {
                range->mark_range_cnt++;
                if (packet->ignored) {
                    range->ignored_mark_range_cnt++;
                }
            }

            if (framenum >= displayed_mark_low &&
                framenum <= displayed_mark_high)
            {
                if (packet->passed_dfilter) {
                    range->displayed_mark_range_cnt++;
                    if (packet->ignored) {
                        range->displayed_ignored_mark_range_cnt++;
                    }
                }
                if (packet->passed_dfilter ||
                    packet->dependent_of_displayed) {
                    range->displayed_plus_dependents_mark_range_cnt++;
                }
            }
        }

    }
}


/* (re-)calculate the user specified packet range counts */
static void packet_range_calc_user(packet_range_t *range) {
    guint32       framenum;
    frame_data    *packet;

    range->user_range_cnt                   = 0;
    range->ignored_user_range_cnt           = 0;
    range->displayed_user_range_cnt         = 0;
    range->displayed_plus_dependents_user_range_cnt = 0;
    range->displayed_ignored_user_range_cnt = 0;

    ws_assert(range->cf != NULL);

    /* XXX - this doesn't work unless you have a full set of frame_data
     * structures for all packets in the capture, which is not,
     * for example, the case when TShark is doing a one-pass
     * read of a file or a live capture.
     *
     * It's also horribly slow on large captures, causing it to
     * take a long time for the Save As dialog to pop up, for
     * example.  This obviously can't be kept in the capture_file
     * structure and recalculated whenever we filter the display
     * or mark frames as ignored, as the results of this depend
     * on what the user specifies.  In some cases, limiting the
     * frame_data structures at which we look to the ones specified
     * by the user might help, but if most of the frames are in
     * the range, that won't help.  In that case, if we could
     * examine the *complement* of the range, and *subtract* them
     * from the statistics for the capture as a whole, that might
     * help, but if the user specified about *half* the packets in
     * the range, that won't help, either.
     */
    if (range->cf->provider.frames != NULL) {
        for(framenum = 1; framenum <= range->cf->count; framenum++) {
            packet = frame_data_sequence_find(range->cf->provider.frames, framenum);

            if (value_is_in_range(range->user_range, framenum)) {
                range->user_range_cnt++;
                if (packet->ignored) {
                    range->ignored_user_range_cnt++;
                }
                if (packet->passed_dfilter) {
                    range->displayed_user_range_cnt++;
                    if (packet->ignored) {
                        range->displayed_ignored_user_range_cnt++;
                    }
                }
                if (packet->passed_dfilter ||
                    packet->dependent_of_displayed) {
                    range->displayed_plus_dependents_user_range_cnt++;
                }
            }
        }
    }
}

static void packet_range_calc_selection(packet_range_t *range) {
    guint32       framenum;
    frame_data    *packet;

    range->selection_range_cnt                   = 0;
    range->ignored_selection_range_cnt           = 0;
    range->displayed_selection_range_cnt         = 0;
    range->displayed_ignored_selection_range_cnt = 0;

    ws_assert(range->cf != NULL);

    if (range->cf->provider.frames != NULL) {
        for (framenum = 1; framenum <= range->cf->count; framenum++) {
            packet = frame_data_sequence_find(range->cf->provider.frames, framenum);

            if (value_is_in_range(range->selection_range, framenum)) {
                range->selection_range_cnt++;
                if (packet->ignored) {
                    range->ignored_selection_range_cnt++;
                }
                if (packet->passed_dfilter) {
                    range->displayed_selection_range_cnt++;
                    if (packet->ignored) {
                        range->displayed_ignored_selection_range_cnt++;
                    }
                }
            }
        }
    }
}


/* init the range struct */
void packet_range_init(packet_range_t *range, capture_file *cf) {

    memset(range, 0, sizeof(packet_range_t));
    range->process    = range_process_all;
    range->user_range = NULL;
    range->selection_range = NULL;
    range->cf         = cf;

    /* calculate all packet range counters */
    packet_range_calc(range);
    packet_range_calc_user(range);
    packet_range_calc_selection(range);
}

void packet_range_cleanup(packet_range_t *range) {
    wmem_free(NULL, range->user_range);
    wmem_free(NULL, range->selection_range);
}

/* check whether the packet range is OK */
convert_ret_t packet_range_check(packet_range_t *range) {
    if (range->process == range_process_user_range && range->user_range == NULL) {
        /* Not valid - return the error. */
        return range->user_range_status;
    }
    if (range->process == range_process_selected && range->selection_range == NULL) {
        return range->selection_range_status;
    }

    return CVT_NO_ERROR;
}

/* init the processing run */
void packet_range_process_init(packet_range_t *range) {
    /* Check that, if an explicit range was selected, it's valid. */
    /* "enumeration" values */
    range->marked_range_active    = FALSE;
    range->selected_done          = FALSE;

    if (range->process_filtered == FALSE) {
        range->marked_range_left = range->mark_range_cnt;
    } else {
        range->marked_range_left = range->displayed_mark_range_cnt;
    }
}

/* do we have to process all packets? */
gboolean packet_range_process_all(packet_range_t *range) {
    return range->process == range_process_all && !range->process_filtered && !range->remove_ignored;
}

/* do we have to process this packet? */
range_process_e packet_range_process_packet(packet_range_t *range, frame_data *fdata) {

    if (range->remove_ignored && fdata->ignored) {
        return range_process_next;
    }

    ws_assert(range->cf != NULL);

    switch(range->process) {
    case(range_process_all):
        break;
    case(range_process_selected):
        if (value_is_in_range(range->selection_range, fdata->num) == FALSE) {
          return range_process_next;
        }
        break;
    case(range_process_marked):
        if (fdata->marked == FALSE) {
          return range_process_next;
        }
        break;
    case(range_process_marked_range):
        if (range->marked_range_left == 0) {
          return range_processing_finished;
        }
        if (fdata->marked == TRUE) {
          range->marked_range_active = TRUE;
        }
        if (range->marked_range_active == FALSE ) {
          return range_process_next;
        }
        if (!range->process_filtered ||
          (range->process_filtered && fdata->passed_dfilter == TRUE))
        {
          range->marked_range_left--;
        }
        break;
    case(range_process_user_range):
        if (value_is_in_range(range->user_range, fdata->num) == FALSE) {
          return range_process_next;
        }
        break;
    default:
        ws_assert_not_reached();
    }

    /* This packet has to pass the display filter but didn't?
     * Try next, but only if we're not including dependent packets and this
     * packet happens to be a dependency on something that is displayed.
     */
    /* XXX: We only track if a frame is depended upon by some displayed frame,
     * not which of the other frames depend on it.
     * For Selected and Marked frames, we never include depended upon packets,
     * because we already returned above if the frame wasn't selected or
     * marked.
     * For Marked Range and User Range, we include packets in the range that
     * any frame displayed, not just ones in the range, depend upon.
     * We also don't include any frames outside the range that frames in the
     * range depend upon. So we don't include some depended on frames we
     * should, but include some unnecessary ones, with the problems mostly
     * occuring at the beginning and end of the ranges.
     * For ignored packets, since we don't dissect them, we don't know
     * anything about packets they depend upon, which is helpful as we
     * don't have to calculate more counts based on interaction terms. If
     * someone wants to include those, then don't ignore the packet.
     */
    if ((range->process_filtered && fdata->passed_dfilter == FALSE) &&
        !(range->include_dependents && fdata->dependent_of_displayed)) {
        return range_process_next;
    }

    /* We fell through the conditions above, so we accept this packet */
    return range_process_this;
}


/******************** Range Entry Parser *********************************/

/* Converts a range string to a user range.
 * The parameter 'es' points to the string to be converted, and is defined in
 * the Save/Print-As widget.
 */

void packet_range_convert_str(packet_range_t *range, const gchar *es)
{
    range_t *new_range;
    convert_ret_t ret;

    if (range->user_range != NULL)
        wmem_free(NULL, range->user_range);

    ws_assert(range->cf != NULL);

    ret = range_convert_str(NULL, &new_range, es, range->cf->count);
    if (ret != CVT_NO_ERROR) {
        /* range isn't valid */
        range->user_range                       = NULL;
        range->user_range_status                = ret;
        range->user_range_cnt                   = 0;
        range->ignored_user_range_cnt           = 0;
        range->displayed_user_range_cnt         = 0;
        range->displayed_ignored_user_range_cnt = 0;
        return;
    }
    range->user_range = new_range;

    /* calculate new user specified packet range counts */
    packet_range_calc_user(range);
} /* packet_range_convert_str */

void packet_range_convert_selection_str(packet_range_t *range, const char *es)
{
    range_t *new_range;
    convert_ret_t ret;

    if (range->selection_range != NULL)
        wmem_free(NULL, range->selection_range);

    ws_assert(range->cf != NULL);

    ret = range_convert_str(NULL, &new_range, es, range->cf->count);
    if (ret != CVT_NO_ERROR) {
        /* range isn't valid */
        range->selection_range                       = NULL;
        range->selection_range_status                = ret;
        range->selection_range_cnt                   = 0;
        range->ignored_selection_range_cnt           = 0;
        range->displayed_selection_range_cnt         = 0;
        range->displayed_ignored_selection_range_cnt = 0;
        return;
    }
    range->selection_range = new_range;

    /* calculate new user specified packet range counts */
    packet_range_calc_selection(range);
}
