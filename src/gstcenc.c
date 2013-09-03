/* GStreamer MPEG TS Time Shifting
 * Copyright (C) 2011 Fluendo S.A. <support@fluendo.com>
 * Copyright (C) 2013 YouView TV Ltd. <william.manley@youview.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Suite 500,
 * Boston, MA 02110-1335, USA.
 */

/**
 * SECTION:element-gsttsindexer
 *
 * Populates a time/byte offset index for MPEG-TS streams based upon PCR
 * information.  An index to populate should be passed in as the "index"
 * property.
 *
 * This element is used by tsshifterbin to create an index for timeshifting.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gst/gst.h>
#include <gst/gstelement.h>
#include <gst/base/gstbasetransform.h>
#include "gsttsindexer.h"

GST_DEBUG_CATEGORY_STATIC (gst_ts_indexer_debug_category);
#define GST_CAT_DEFAULT gst_ts_indexer_debug_category

#define DEFAULT_DELTA           500

#define TS_PACKET_SYNC_CODE     0x47
#define TS_MIN_PACKET_SIZE      188
#define TS_MAX_PACKET_SIZE      208
#define INVALID_PID             -1

#define CLOCK_BASE 9LL
#define CLOCK_FREQ (CLOCK_BASE * 10000)

#define MPEGTIME_TO_GSTTIME(time) (gst_util_uint64_scale ((time), \
            GST_MSECOND/10, CLOCK_BASE))
#define GSTTIME_TO_MPEGTIME(time) (gst_util_uint64_scale ((time), \
            CLOCK_BASE, GST_MSECOND/10))

/* prototypes */


static void gst_ts_indexer_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);
static void gst_ts_indexer_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gst_ts_indexer_dispose (GObject * object);
static void gst_ts_indexer_finalize (GObject * object);

static gboolean gst_ts_indexer_start (GstBaseTransform * trans);
static gboolean gst_ts_indexer_stop (GstBaseTransform * trans);
static GstFlowReturn
gst_ts_indexer_transform_ip (GstBaseTransform * trans, GstBuffer * buf);
static void gst_ts_indexer_replace_index (GstTSIndexer *
    base, GstIndex * new_index, gboolean own);
static void gst_ts_indexer_collect_time (GstTSIndexer *
    base, guint8 * data, gsize size);


enum
{
  PROP_0,
  PROP_INDEX,
  PROP_PCR_PID,
  PROP_DELTA
};

/* pad templates */

static GstStaticPadTemplate gst_ts_indexer_sink_template =
GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("video/mpegts")
    );

static GstStaticPadTemplate gst_ts_indexer_src_template =
GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("video/mpegts")
    );


/* class initialization */

G_DEFINE_TYPE (GstTSIndexer, gst_ts_indexer, GST_TYPE_BASE_TRANSFORM);
#define parent_class gst_ts_indexer_parent_class

static void
gst_ts_indexer_class_init (GstTSIndexerClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstBaseTransformClass *base_transform_class =
      GST_BASE_TRANSFORM_CLASS (klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);

  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&gst_ts_indexer_sink_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&gst_ts_indexer_src_template));

  gst_element_class_set_static_metadata (element_class,
      "Indexer for MPEG-TS streams", "Generic",
      "Generates an index for mapping from time to bytes and vice-versa for "
      "MPEG-TS streams based upon MPEG-TS PCR.",
      "Fluendo S.A. <support@fluendo.com>, "
      "William Manley <will@williammanley.net>");

  GST_DEBUG_CATEGORY_INIT (gst_ts_indexer_debug_category,
      "gst_ts_indexer", 0, "Indexer for MPEG-TS streams");


  gobject_class->set_property = gst_ts_indexer_set_property;
  gobject_class->get_property = gst_ts_indexer_get_property;
  gobject_class->dispose = gst_ts_indexer_dispose;
  gobject_class->finalize = gst_ts_indexer_finalize;
  base_transform_class->start = GST_DEBUG_FUNCPTR (gst_ts_indexer_start);
  base_transform_class->stop = GST_DEBUG_FUNCPTR (gst_ts_indexer_stop);
  base_transform_class->transform_ip =
      GST_DEBUG_FUNCPTR (gst_ts_indexer_transform_ip);

  g_object_class_install_property (gobject_class, PROP_INDEX,
      g_param_spec_object ("index", "Index",
          "The index into which to write indexing information",
          GST_TYPE_INDEX, (G_PARAM_READABLE | G_PARAM_WRITABLE)));
  g_object_class_install_property (gobject_class, PROP_PCR_PID,
      g_param_spec_int ("pcr-pid", "PCR pid",
          "Defines the PCR pid to collect the time (-1 = undefined)",
          INVALID_PID, 0x1fff, INVALID_PID,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_DELTA,
      g_param_spec_int ("delta", "Delta",
          "Delta time between index entries in miliseconds "
          "(-1 = use random access flag)",
          -1, 10000, DEFAULT_DELTA,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static void
gst_ts_indexer_init (GstTSIndexer * indexer)
{
  GstBaseTransform *base = GST_BASE_TRANSFORM (indexer);
  gst_base_transform_set_passthrough (base, TRUE);

  indexer->pcr_pid = INVALID_PID;
  indexer->delta = DEFAULT_DELTA;

  indexer->base_time = GST_CLOCK_TIME_NONE;
  indexer->last_pcr = 0;
  indexer->last_time = GST_CLOCK_TIME_NONE;
  indexer->current_offset = 0;
}

static void
gst_ts_indexer_replace_index (GstTSIndexer * base,
    GstIndex * new_index, gboolean own)
{
  if (base->index) {
    gst_object_unref (base->index);
    base->index = NULL;
  }
  if (new_index) {
    gst_object_ref (new_index);
    base->index = new_index;
    base->own_index = own;
  }
}

void
gst_ts_indexer_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec)
{
  GstTSIndexer *indexer = GST_TS_INDEXER (object);

  switch (property_id) {
    case PROP_INDEX:
      gst_ts_indexer_replace_index (indexer, g_value_dup_object (value), FALSE);
      break;
    case PROP_PCR_PID:
      indexer->pcr_pid = g_value_get_int (value);
      GST_INFO_OBJECT (indexer, "configured pcr-pid: %d(%x)",
          indexer->pcr_pid, indexer->pcr_pid);
      break;
    case PROP_DELTA:
      indexer->delta = g_value_get_int (value);
      if (indexer->delta != -1) {
        indexer->delta *= GST_MSECOND;
      }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

void
gst_ts_indexer_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec)
{
  GstTSIndexer *indexer = GST_TS_INDEXER (object);

  switch (property_id) {
    case PROP_INDEX:
      g_value_set_object (value, indexer->index);
      break;
    case PROP_PCR_PID:
      g_value_set_int (value, indexer->pcr_pid);
      break;
    case PROP_DELTA:
      if (indexer->delta != -1) {
        g_value_set_int (value, indexer->delta / GST_MSECOND);
      } else {
        g_value_set_int (value, -1);
      }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

void
gst_ts_indexer_dispose (GObject * object)
{
  GstTSIndexer *indexer = GST_TS_INDEXER (object);

  /* clean up as possible.  may be called multiple times */
  gst_ts_indexer_replace_index (indexer, NULL, FALSE);

  G_OBJECT_CLASS (parent_class)->dispose (object);
}

void
gst_ts_indexer_finalize (GObject * object)
{
  /* GstTSIndexer *indexer = GST_TS_INDEXER (object); */

  /* clean up object here */

  G_OBJECT_CLASS (parent_class)->finalize (object);
}

static gboolean
gst_ts_indexer_start (GstBaseTransform * trans)
{
  GstTSIndexer *indexer = GST_TS_INDEXER (trans);

  /* If this is our own index destroy it as the old entries might be wrong */
  if (indexer->own_index) {
    gst_ts_indexer_replace_index (indexer, NULL, FALSE);
  }

  /* If no index was created, generate one */
  if (G_UNLIKELY (!indexer->index)) {
    GST_DEBUG_OBJECT (indexer, "no index provided creating our own");
    gst_ts_indexer_replace_index (indexer,
        gst_index_factory_make ("memindex"), FALSE);
  }

  return TRUE;
}

static gboolean
gst_ts_indexer_stop (GstBaseTransform * trans)
{

  return TRUE;
}

static GstFlowReturn
gst_ts_indexer_transform_ip (GstBaseTransform * trans, GstBuffer * buf)
{
  GstTSIndexer *indexer = GST_TS_INDEXER (trans);

  GstFlowReturn ret = GST_FLOW_OK;
  GstMapInfo map;

  /* collect time info from that buffer */
  if (!gst_buffer_map (buf, &map, GST_MAP_READ)) {
    ret = GST_FLOW_NOT_SUPPORTED;
    goto out;
  }

  gst_ts_indexer_collect_time (indexer, map.data, map.size);

  gst_buffer_unmap (buf, &map);

out:
  return ret;
}

static gboolean
is_next_sync_valid (const guint8 * in_data, guint size, guint offset)
{
  static const guint packet_sizes[] = { 188, 192, 204, 208 };
  gint i;

  for (i = 0; i < 4 && (offset + packet_sizes[i]) < size; i++) {
    if (in_data[offset + packet_sizes[i]] == TS_PACKET_SYNC_CODE) {
      return TRUE;
    }
  }
  return FALSE;
}

static inline void
add_index_entry (GstTSIndexer * base, GstClockTime time, guint64 offset)
{
  GstIndexAssociation associations[2];

  GST_LOG_OBJECT (base, "adding association %" GST_TIME_FORMAT "-> %"
      G_GUINT64_FORMAT, GST_TIME_ARGS (time), offset);
  associations[0].format = GST_FORMAT_TIME;
  associations[0].value = time;
  associations[1].format = GST_FORMAT_BYTES;
  associations[1].value = offset;

  gst_index_add_associationv (base->index, GST_ASSOCIATION_FLAG_NONE, 2,
      (const GstIndexAssociation *) &associations);
}

static inline guint64
gst_ts_indexer_parse_pcr (GstTSIndexer * ts, guint8 * data)
{
  guint16 pid;
  guint32 pcr1;
  guint16 pcr2;
  guint64 pcr = (guint64) - 1, pcr_ext;

  if (TS_PACKET_SYNC_CODE == data[0]) {
    /* Check Adaptation field, if it == b10 or b11 */
    if (data[3] & 0x20) {
      /* Check PID Match */
      pid = GST_READ_UINT16_BE (data + 1);
      pid &= 0x1fff;

      if (pid == (guint16) ts->pcr_pid) {
        /* Check Adaptation field size */
        if (data[4]) {
          /* Check if random access flag is present */
          if (ts->delta == -1 && GST_CLOCK_TIME_IS_VALID (ts->base_time) &&
              !(data[5] & 0x40)) {
            /* random access flag not set just skip after first PCR */
            goto beach;
          }
          /* Check if PCR is present */
          if (data[5] & 0x10) {
            pcr1 = GST_READ_UINT32_BE (data + 6);
            pcr2 = GST_READ_UINT16_BE (data + 10);
            pcr = ((guint64) pcr1) << 1;
            pcr |= (pcr2 & 0x8000) >> 15;
            pcr_ext = (pcr2 & 0x01ff);
            if (pcr_ext)
              pcr = (pcr * 300 + pcr_ext % 300) / 300;
          }
        }
      }
    }
  }

beach:
  return pcr;
}

static inline guint64
gst_ts_indexer_get_pcr (GstTSIndexer * ts,
    guint8 ** in_data, gsize * in_size, guint64 * offset)
{
  guint64 pcr = (guint64) - 1;
  gint i = 0;
  guint8 *data = *in_data;
  gsize size = *in_size;

  /* mpegtsparse pushes PES packet buffers so this case must be handled
   * without checking for next SYNC code */
  if (size >= TS_MIN_PACKET_SIZE && size <= TS_MAX_PACKET_SIZE) {
    pcr = gst_ts_indexer_parse_pcr (ts, data);
  } else {
    while ((i + TS_MAX_PACKET_SIZE) < size) {
      if (TS_PACKET_SYNC_CODE == data[i]) {
        /* Check the next SYNC byte for all packets except the last packet
         * in a buffer... */
        if (G_LIKELY (is_next_sync_valid (data, size, i))) {
          pcr = gst_ts_indexer_parse_pcr (ts, data + i);
          if (pcr == -1) {
            /* Skip to start of next TSPacket (pre-subract for the i++ later) */
            i += (TS_MIN_PACKET_SIZE - 1);
          } else {
            *in_data += i;
            *in_size -= i;
            *offset += i;
            break;
          }
        }
      }
      i++;                      /* next byte in buffer until we find sync */
    }
  }
  return pcr;
}

static void
gst_ts_indexer_collect_time (GstTSIndexer * base, guint8 * data, gsize size)
{

  GstTSIndexer *ts = GST_TS_INDEXER (base);
  GstClockTime time;
  gsize remaining = size;
  guint64 pcr, offset;

  /* We can read PCR data only if we know which PCR pid to track */
  if (G_UNLIKELY (ts->pcr_pid == INVALID_PID)) {
    goto beach;
  }

  offset = ts->current_offset;
  while (remaining >= TS_MIN_PACKET_SIZE) {
    pcr = gst_ts_indexer_get_pcr (ts, &data, &remaining, &offset);
    if (pcr != (guint64) - 1) {
      /* FIXME: handle wraparounds */
      if (!GST_CLOCK_TIME_IS_VALID (ts->base_time)) {
        /* First time we receive is time zero */
        ts->base_time = MPEGTIME_TO_GSTTIME (pcr);
      }
      time = MPEGTIME_TO_GSTTIME (pcr) - ts->base_time;

      GST_LOG_OBJECT (ts, "found PCR %" G_GUINT64_FORMAT
          "(%" GST_TIME_FORMAT ") at offset %" G_GUINT64_FORMAT
          " and last pcr was %" G_GUINT64_FORMAT "(%" GST_TIME_FORMAT
          ")", pcr, GST_TIME_ARGS (time), offset, ts->last_pcr,
          GST_TIME_ARGS (MPEGTIME_TO_GSTTIME (ts->last_pcr)));
      ts->last_pcr = pcr;

      if (!GST_CLOCK_TIME_IS_VALID (ts->last_time)) {
        add_index_entry (base, time, offset);
        ts->last_time = time;
        goto beach;
      } else if (ts->delta == -1) {
        add_index_entry (base, time, offset);
        ts->last_time = time;
        goto beach;
      } else if (ts->delta != -1 &&
          GST_CLOCK_DIFF (ts->last_time, time) >= ts->delta) {
        add_index_entry (base, time, offset);
        ts->last_time = time;
        goto beach;
      }
      if (remaining) {
        remaining--;
        data++;
        offset++;
      }
    } else {
      goto beach;
    }
  }

beach:
  ts->current_offset += size;
}
