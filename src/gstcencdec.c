/* GStreamer ISO MPEG DASH common encryption decryptor
 * Copyright (C) 2013 YouView TV Ltd. <alex.ashley@youview.com>
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
 * SECTION:element-gstcencdecrypt
 *
 * Decrypts media that has been encrypted using the MPEG DASH common
 * encryption standard.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <gst/gst.h>
#include <gst/gstelement.h>
#include <gst/base/gstbasetransform.h>
#include <gst/base/gstbytereader.h>
#include <gst/cenc/cenc.h>
#include <gst/gstaesctr.h>

#include "gstcencdec.h"

GST_DEBUG_CATEGORY_STATIC (gst_cenc_decrypt_debug_category);
#define GST_CAT_DEFAULT gst_cenc_decrypt_debug_category


struct _GstCencDecrypt
{
  GstBaseTransform parent;
  GBytes *key;
};

struct _GstCencDecryptClass
{
  GstBaseTransformClass parent_class;
};

/* prototypes */
static void gst_cenc_decrypt_dispose (GObject * object);
static void gst_cenc_decrypt_finalize (GObject * object);

static gboolean gst_cenc_decrypt_start (GstBaseTransform * trans);
static gboolean gst_cenc_decrypt_stop (GstBaseTransform * trans);
static GstCaps* gst_cenc_decrypt_transform_caps (GstBaseTransform * base,
    GstPadDirection direction, GstCaps * caps, GstCaps * filter);

static GstFlowReturn gst_cenc_decrypt_transform_ip (GstBaseTransform * trans,
    GstBuffer * buf);
static GBytes *gst_cenc_decrypt_lookup_key (GstCencDecrypt *self, GBytes *kid);
static gboolean gst_cenc_decrypt_sink_event_handler (GstBaseTransform * trans,
    GstEvent * event);

enum
{
  PROP_0
};

/* pad templates */

static GstStaticPadTemplate gst_cenc_decrypt_sink_template =
GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("application/x-cenc, original-media-type=(string)video/x-h264, protection-system-id-69f908af-4816-46ea-910c-cd5dcccb0a3a=(boolean)true; application/x-cenc, original-media-type=(string)audio/mpeg, protection-system-id-69f908af-4816-46ea-910c-cd5dcccb0a3a=(boolean)true")
    );

static GstStaticPadTemplate gst_cenc_decrypt_src_template =
GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("video/x-h264; audio/mpeg")
    );


/* class initialization */

#define gst_cenc_decrypt_parent_class parent_class
G_DEFINE_TYPE (GstCencDecrypt, gst_cenc_decrypt, GST_TYPE_BASE_TRANSFORM);

static void
gst_cenc_decrypt_class_init (GstCencDecryptClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstBaseTransformClass *base_transform_class =
      GST_BASE_TRANSFORM_CLASS (klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);

  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&gst_cenc_decrypt_sink_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&gst_cenc_decrypt_src_template));

  gst_element_class_set_static_metadata (element_class,
      "Decrypt MPEG-DASH encrypted content",
      "Decoder/Video/Audio",
      "Decrypts media that has been encrypted using ISO MPEG-DASH common "
      "encryption.",
      "Alex Ashley <alex.ashley@youview.com>");

  GST_DEBUG_CATEGORY_INIT (gst_cenc_decrypt_debug_category,
         "cencdec", 0, "CENC decryptor");

  gobject_class->dispose = gst_cenc_decrypt_dispose;
  gobject_class->finalize = gst_cenc_decrypt_finalize;
  base_transform_class->start = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_start);
  base_transform_class->stop = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_stop);
  base_transform_class->transform_ip =
    GST_DEBUG_FUNCPTR (gst_cenc_decrypt_transform_ip);
  base_transform_class->transform_caps =
    GST_DEBUG_FUNCPTR (gst_cenc_decrypt_transform_caps);
  base_transform_class->sink_event =
    GST_DEBUG_FUNCPTR (gst_cenc_decrypt_sink_event_handler);
  base_transform_class->transform_ip_on_passthrough = FALSE;
}

static void
gst_cenc_decrypt_init (GstCencDecrypt * self)
{
  GstBaseTransform *base = GST_BASE_TRANSFORM (self);

  gst_base_transform_set_in_place (base, TRUE);
  gst_base_transform_set_passthrough (base, FALSE);
  gst_base_transform_set_gap_aware (GST_BASE_TRANSFORM (self), FALSE);

  self->key = NULL;
}

void
gst_cenc_decrypt_dispose (GObject * object)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (object);

  /* clean up as possible.  might be called multiple times */
  if (self->key) {
    g_bytes_unref (self->key);
    self->key = NULL;
  }

  G_OBJECT_CLASS (parent_class)->dispose (object);
}

void
gst_cenc_decrypt_finalize (GObject * object)
{
  /* GstCencDecrypt *self = GST_CENC_DECRYPT (object); */

  /* clean up object here */

  G_OBJECT_CLASS (parent_class)->finalize (object);
}

static gboolean
gst_cenc_decrypt_start (GstBaseTransform * trans)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (trans);
  GST_DEBUG_OBJECT (self, "start");
  return TRUE;
}

static gboolean
gst_cenc_decrypt_stop (GstBaseTransform * trans)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (trans);
  GST_DEBUG_OBJECT (self, "stop");
  return TRUE;
}

static GstCaps*
gst_cenc_decrypt_transform_caps (GstBaseTransform * base,
    GstPadDirection direction, GstCaps * caps, GstCaps * filter)
{
  GstCaps *res = NULL;
  gint i;

  g_return_val_if_fail (direction != GST_PAD_UNKNOWN, NULL);
  res = gst_caps_new_empty ();

  GST_DEBUG_OBJECT (base, "direction: %s   caps: %" GST_PTR_FORMAT "   filter:"
      " %" GST_PTR_FORMAT, (direction == GST_PAD_SRC) ? "Src" : "Sink",
      caps, filter);

  for (i = 0; i < gst_caps_get_size (caps); ++i) {
    GstStructure *in = gst_caps_get_structure (caps, i);
    GstStructure *out = NULL;

    if (direction == GST_PAD_SINK) {
      if (!gst_structure_has_field (in, "original-media-type"))
        continue;

      out = gst_structure_copy (in);

      gst_structure_set_name (out,
          gst_structure_get_string (out, "original-media-type"));

      gst_structure_remove_fields (out,
          "protection-system-id-69f908af-4816-46ea-910c-cd5dcccb0a3a",
          "protection-system-data",
          "original-media-type", NULL);
    } else {      /* GST_PAD_SRC */
      out = gst_structure_copy (in);

      gst_structure_set (out,
          "protection-system-id-69f908af-4816-46ea-910c-cd5dcccb0a3a",
          G_TYPE_BOOLEAN, TRUE, "original-media-type", G_TYPE_STRING,
          gst_structure_get_name (in), NULL);

      gst_structure_set_name (out, "application/x-cenc");
    }

    gst_caps_append_structure (res, out);
  }

  if (filter) {
    GstCaps *intersection;

    GST_DEBUG_OBJECT (base, "Using filter caps %" GST_PTR_FORMAT, filter);
    intersection =
      gst_caps_intersect_full (filter, res, GST_CAPS_INTERSECT_FIRST);
    gst_caps_unref (res);
    res = intersection;
  }

  GST_DEBUG_OBJECT (base, "returning %" GST_PTR_FORMAT, res);
  return res;
}

static GBytes *
gst_cenc_decrypt_get_key (const GBytes * key_id)
{
  guint8 key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                   0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
  return g_bytes_new (key, 16);
}

static gchar *
gst_cenc_create_uuid_string (gconstpointer uuid_bytes)
{
  const guint8 *uuid = (const guint8 *) uuid_bytes;
  const gsize uuid_string_length = 37;  /* Length of UUID string */
  gchar *uuid_string = g_malloc0 (uuid_string_length);

  g_snprintf (uuid_string, uuid_string_length,
      "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
      "%02x%02x-%02x%02x%02x%02x%02x%02x",
      uuid[0], uuid[1], uuid[2], uuid[3],
      uuid[4], uuid[5], uuid[6], uuid[7],
      uuid[8], uuid[9], uuid[10], uuid[11],
      uuid[12], uuid[13], uuid[14], uuid[15]);

  return uuid_string;
}

static GBytes *
gst_cenc_decrypt_lookup_key (GstCencDecrypt * self, GBytes * kid)
{
  gchar *id_string;

  GST_DEBUG_OBJECT (self, "Key ID length: %d", g_bytes_get_size (kid));
  id_string = gst_cenc_create_uuid_string (g_bytes_get_data (kid, NULL));
  GST_DEBUG_OBJECT (self, "Key ID: %s", id_string);
  g_free (id_string);

  if (self->key) {
    g_bytes_ref (self->key);
    return self->key;
  }

  self->key = gst_cenc_decrypt_get_key (kid);
  g_bytes_ref (self->key);
  return self->key;
}

static GstFlowReturn
gst_cenc_decrypt_transform_ip (GstBaseTransform * base, GstBuffer * buf)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (base);
  GstFlowReturn ret = GST_FLOW_OK;
  GstMapInfo map;
  GBytes *key = NULL;
  const GstCencMeta *sample_info = NULL;
  int pos = 0;
  int sample_index = 0;
  AesCtrState *state = NULL;

  GST_DEBUG_OBJECT (self, "decrypt in-place");
  sample_info = gst_buffer_get_cenc_meta (buf);
  if (!sample_info || !buf) {
    if (!sample_info) {
      GST_ERROR_OBJECT (self, "Failed to get sample_info metadata from buffer");
    }
    if (!buf) {
      GST_ERROR_OBJECT (self, "Failed to get writable buffer");
    }
    ret = GST_FLOW_NOT_SUPPORTED;
    goto out;
  }

  if (!gst_buffer_map (buf, &map, GST_MAP_READWRITE)) {
    GST_ERROR_OBJECT (self,"Failed to map buffer");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }

  GST_DEBUG_OBJECT (self, "decrypt sample %d", map.size);
  if (sample_info->properties->iv_size == 0
      || !sample_info->properties->is_encrypted) {
    /* sample is not encrypted */
    goto beach;
  }

  key = gst_cenc_decrypt_lookup_key (self,
      gst_cenc_sample_properties_get_key_id (sample_info->properties));

  if (!key) {
    GST_ERROR_OBJECT (self, "Failed to lookup key");
    GST_MEMDUMP_OBJECT (self, "Key ID:",
        g_bytes_get_data (
          gst_cenc_sample_properties_get_key_id (sample_info->properties),
          NULL), 16);
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }

  state = gst_aes_ctr_decrypt_new (key,
      gst_cenc_sample_crypto_info_get_iv (sample_info->crypto_info));

  if (!state) {
    GST_ERROR_OBJECT (self, "Failed to init AES cipher");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  g_bytes_unref (key);

  while (pos<map.size) {
    GstCencSubsampleInfo *run;
    guint16 n_bytes_clear = 0;
    guint32 n_bytes_encrypted = 0;

    if (sample_index <
        gst_cenc_sample_crypto_info_get_subsample_count (
          sample_info->crypto_info)) {
      run = gst_cenc_sample_crypto_info_get_subsample_info (
          sample_info->crypto_info, sample_index);
      n_bytes_clear = run->n_bytes_clear;
      n_bytes_encrypted = run->n_bytes_encrypted;
      sample_index++;
    }
    else {
      n_bytes_clear = 0;
      n_bytes_encrypted = map.size - pos;
    }
    GST_TRACE_OBJECT (self, "%d bytes clear (todo=%d)", n_bytes_clear,
          map.size - pos);
    pos += n_bytes_clear;
    if (n_bytes_encrypted) {
      GST_TRACE_OBJECT (self, "%d bytes encrypted (todo=%d)",
      n_bytes_encrypted,
      map.size - pos);
      gst_aes_ctr_decrypt_ip (state, map.data + pos, n_bytes_encrypted);
      pos += n_bytes_encrypted;
    }
  }

beach:
  gst_buffer_unmap (buf, &map);
  if (state) {
    gst_aes_ctr_decrypt_unref (state);
  }
release:
  if (sample_info) {
    gst_buffer_remove_meta (buf, (GstMeta*)sample_info);
  }
out:
  return ret;
}

static void
gst_cenc_decrypt_parse_pssh (GstCencDecrypt * self, GstBuffer * pssh)
{
  GstMapInfo info;
  GstByteReader br;
  guint8 version;
  guint32 data_size;

  gst_buffer_map (pssh, &info, GST_MAP_READ);
  gst_byte_reader_init (&br, info.data, info.size);

  gst_byte_reader_skip_unchecked (&br, 8);
  version = gst_byte_reader_get_uint8_unchecked (&br);
  GST_DEBUG_OBJECT (self, "pssh version: %u", version);
  gst_byte_reader_skip_unchecked (&br, 19);

  if (version > 0) {
    /* Parse KeyIDs */
    guint32 key_id_count = 0;
    const guint8 *key_id_data = NULL;
    const guint key_id_size = 16;

    key_id_count = gst_byte_reader_get_uint32_be_unchecked (&br);
    GST_DEBUG_OBJECT (self, "there are %u key IDs", key_id_count);
    key_id_data = gst_byte_reader_get_data_unchecked (&br, key_id_count * 16);

    while (key_id_count > 0) {
      gchar *key_id_string = gst_cenc_create_uuid_string (key_id_data);
      GST_DEBUG_OBJECT (self, "key_id: %s", key_id_string);
      g_free (key_id_string);
      key_id_data += key_id_size;
      --key_id_count;
    }
  }

  /* Parse Data */
  data_size = gst_byte_reader_get_uint32_be_unchecked (&br);
  GST_DEBUG_OBJECT (self, "pssh data size: %u", data_size);

  if (data_size > 0U) {
    gpointer data =
        g_memdup (gst_byte_reader_get_data_unchecked (&br, data_size),
        data_size);
    GstBuffer *buf = gst_buffer_new_wrapped (data, data_size);
    GST_DEBUG_OBJECT (self, "cenc protection system data size: %"
        G_GSIZE_FORMAT, gst_buffer_get_size (buf));
    gst_buffer_unref (buf);
  }
}

static gboolean
gst_cenc_decrypt_sink_event_handler (GstBaseTransform * trans, GstEvent * event)
{
  gboolean ret = TRUE;
  const gchar *system_id;
  GstBuffer *pssh = NULL;
  gboolean init;
  GstCencDecrypt *self = GST_CENC_DECRYPT (trans);

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_CUSTOM_DOWNSTREAM_STICKY:
      GST_DEBUG_OBJECT (self, "received custom sticky event");
      if (gst_cenc_event_is_pssh (event)) {
        gst_cenc_event_parse_pssh (event, &system_id, &pssh, &init);
        if (init)
          GST_DEBUG_OBJECT (self, "event carries initial pssh data");
        else
          GST_DEBUG_OBJECT (self, "event carries non-initial pssh data");

        GST_DEBUG_OBJECT (self, "system_id: %s", system_id);
        gst_cenc_decrypt_parse_pssh (self, pssh);
        gst_event_unref (event);
      } else {  /* Chain up */
        ret =
          GST_BASE_TRANSFORM_CLASS (parent_class)->sink_event (trans, event);
      }
      break;

    default:
      ret = GST_BASE_TRANSFORM_CLASS (parent_class)->sink_event (trans, event);
      break;
  }

  return ret;
}

