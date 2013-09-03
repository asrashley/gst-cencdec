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
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifndef _GST_TS_INDEXER_H_
#define _GST_TS_INDEXER_H_

#include <gst/base/gstbasetransform.h>
#include "tsindex.h"

G_BEGIN_DECLS
#define GST_TYPE_TS_INDEXER   (gst_ts_indexer_get_type())
#define GST_TS_INDEXER(obj)   (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_TS_INDEXER,GstTSIndexer))
#define GST_TS_INDEXER_CLASS(klass)   (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_TS_INDEXER,GstTSIndexerClass))
#define GST_IS_TS_INDEXER(obj)   (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_TS_INDEXER))
#define GST_IS_TS_INDEXER_CLASS(obj)   (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_TS_INDEXER))
typedef struct _GstTSIndexer GstTSIndexer;
typedef struct _GstTSIndexerClass GstTSIndexerClass;

struct _GstTSIndexer
{
  GstBaseTransform base_ts_indexer;

  /* Generated Index */
  GstIndex *index;
  gboolean own_index;

  /* Properties */
  gint16 pcr_pid;
  GstClockTimeDiff delta;

  /* PCR tracking */
  guint64 last_pcr;
  guint64 current_offset;
  GstClockTime base_time;
  GstClockTime last_time;
};

struct _GstTSIndexerClass
{
  GstBaseTransformClass base_ts_indexer_class;
};

GType gst_ts_indexer_get_type (void);

G_END_DECLS
#endif
