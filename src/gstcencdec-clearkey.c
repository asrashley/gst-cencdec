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
 * Decrypts media that has been encrypted using the ISOBMFF Common
 * Encryption standard.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include <gst/gst.h>
#include <gst/gstelement.h>
#include <gst/base/gstbasetransform.h>
#include <gst/base/gstbytereader.h>
#include <gst/cenc/cenc.h>
#include <gst/gstaesctr.h>
#include <gst/uridownloader/gstfragment.h>
#include <gst/uridownloader/gsturidownloader.h>

#include "gstcencdec-clearkey.h"

GST_DEBUG_CATEGORY_STATIC (gst_cenc_decrypt_clearkey_debug_category);
#define GST_CAT_DEFAULT gst_cenc_decrypt_clearkey_debug_category

struct _GstCencDecryptClearkey
{
  GstBaseTransform parent;
  GHashTable *keystore;
  GMutex keystore_mutex;
  GstUriDownloader *downloader;
};

struct _GstCencDecryptClearkeyClass
{
  GstBaseTransformClass parent_class;
};

/* prototypes */
static void gst_cenc_decrypt_clearkey_dispose (GObject * object);
static void gst_cenc_decrypt_clearkey_finalize (GObject * object);

static gboolean gst_cenc_decrypt_clearkey_start (GstBaseTransform * trans);
static gboolean gst_cenc_decrypt_clearkey_stop (GstBaseTransform * trans);
static GstCaps* gst_cenc_decrypt_clearkey_transform_caps (GstBaseTransform * base,
    GstPadDirection direction,
    GstCaps * caps, GstCaps * filter);

static GstFlowReturn gst_cenc_decrypt_clearkey_transform_ip (
    GstBaseTransform * trans, GstBuffer * buf);
static gboolean gst_cenc_decrypt_clearkey_sink_event_handler (
    GstBaseTransform * trans, GstEvent * event);

static void gst_cenc_decrypt_clearkey_add_key (GstCencDecryptClearkey * self,
    GBytes *key_id, GBytes *key);
static GBytes *gst_cenc_decrypt_clearkey_get_key (GstCencDecryptClearkey * self,
    const GBytes *key_id);
static gboolean gst_cenc_decrypt_clearkey_have_key_id (
    GstCencDecryptClearkey * self, const GBytes *key_id);
static gboolean gst_cenc_decrypt_clearkey_acquire_key (
    GstCencDecryptClearkey * self, GBytes *key_id, const gchar *url);

enum
{
  PROP_0
};

/* pad templates */
static GstStaticPadTemplate gst_cenc_decrypt_clearkey_sink_template =
GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("application/x-cenc, original-media-type=(string)video/x-h264; application/x-cenc, original-media-type=(string)audio/mpeg")
    );

static GstStaticPadTemplate gst_cenc_decrypt_clearkey_src_template =
GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("video/x-h264; audio/mpeg")
    );


#define gst_cenc_decrypt_clearkey_parent_class parent_class
G_DEFINE_TYPE (GstCencDecryptClearkey, gst_cenc_decrypt_clearkey, GST_TYPE_BASE_TRANSFORM);

/* class initialization */
static void
gst_cenc_decrypt_clearkey_class_init (GstCencDecryptClearkeyClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstBaseTransformClass *base_transform_class =
      GST_BASE_TRANSFORM_CLASS (klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);

  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&gst_cenc_decrypt_clearkey_sink_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&gst_cenc_decrypt_clearkey_src_template));

  gst_element_class_set_static_metadata (element_class,
      "Decrypt content protected by ISOBMFF Common Encryption",
      "Decoder/Video/Audio",
      "Decrypts media that has been encrypted using ISOBMFF Common Encryption.",
      "Alex Ashley <alex.ashley@youview.com>, "
      "Chris Bass <floobleflam@gmail.com>");

  GST_DEBUG_CATEGORY_INIT (gst_cenc_decrypt_clearkey_debug_category,
         "cencdec", 0, "CENC decryptor");

  gobject_class->dispose = gst_cenc_decrypt_clearkey_dispose;
  gobject_class->finalize = gst_cenc_decrypt_clearkey_finalize;
  base_transform_class->start = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_clearkey_start);
  base_transform_class->stop = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_clearkey_stop);
  base_transform_class->transform_ip =
    GST_DEBUG_FUNCPTR (gst_cenc_decrypt_clearkey_transform_ip);
  base_transform_class->transform_caps =
    GST_DEBUG_FUNCPTR (gst_cenc_decrypt_clearkey_transform_caps);
  base_transform_class->sink_event =
    GST_DEBUG_FUNCPTR (gst_cenc_decrypt_clearkey_sink_event_handler);

  base_transform_class->transform_ip_on_passthrough = FALSE;
}

static void
gst_cenc_decrypt_clearkey_init (GstCencDecryptClearkey * self)
{
  GstBaseTransform *base = GST_BASE_TRANSFORM (self);

  gst_base_transform_set_in_place (base, TRUE);
  gst_base_transform_set_passthrough (base, FALSE);
  gst_base_transform_set_gap_aware (GST_BASE_TRANSFORM (self), FALSE);

  self->keystore = g_hash_table_new_full (
      (GHashFunc) g_bytes_hash,
      (GEqualFunc) g_bytes_equal,
      (GDestroyNotify) g_bytes_unref,
      (GDestroyNotify) g_bytes_unref);
  self->downloader = gst_uri_downloader_new ();
}

void
gst_cenc_decrypt_clearkey_dispose (GObject * object)
{
  GstCencDecryptClearkey *self = GST_CENC_DECRYPT_CLEARKEY (object);

  g_mutex_lock (&self->keystore_mutex);
  g_hash_table_destroy (self->keystore);
  g_mutex_unlock (&self->keystore_mutex);

  G_OBJECT_CLASS (parent_class)->dispose (object);
}

void
gst_cenc_decrypt_clearkey_finalize (GObject * object)
{
  /* GstCencDecryptClearkey *self = GST_CENC_DECRYPT_CLEARKEY (object); */

  /* clean up object here */

  G_OBJECT_CLASS (parent_class)->finalize (object);
}

static gboolean
gst_cenc_decrypt_clearkey_start (GstBaseTransform * trans)
{
  GstCencDecryptClearkey *self = GST_CENC_DECRYPT_CLEARKEY (trans);
  GST_DEBUG_OBJECT (self, "start");
  return TRUE;
}

static gboolean
gst_cenc_decrypt_clearkey_stop (GstBaseTransform * trans)
{
  GstCencDecryptClearkey *self = GST_CENC_DECRYPT_CLEARKEY (trans);
  GST_DEBUG_OBJECT (self, "stop");
  return TRUE;
}


static GstCaps*
gst_cenc_decrypt_clearkey_transform_caps (GstBaseTransform * base,
    GstPadDirection direction,
    GstCaps * caps, GstCaps * filter)
{
  GstCaps *res = NULL;
  gint i;

  g_return_val_if_fail (direction != GST_PAD_UNKNOWN, NULL);
  res = gst_caps_new_empty ();

  GST_DEBUG_OBJECT (base, "direction: %s   caps: %" GST_PTR_FORMAT
      "   filter: %" GST_PTR_FORMAT,
      (direction == GST_PAD_SRC)?"Src":"Sink", caps, filter);

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
          "protection-system-id-78f32170-d883-11e0-9572-0800200c9a66",
          "protection-system-data",
          "original-media-type", NULL);
    } else {      /* GST_PAD_SRC */
      out = gst_structure_copy (in);

      gst_structure_set (out,
          "original-media-type", G_TYPE_STRING,
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

static gchar *
_create_uuid_string (gconstpointer uuid_bytes)
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

static GstFlowReturn
gst_cenc_decrypt_clearkey_transform_ip (GstBaseTransform * base, GstBuffer * buf)
{
  GstCencDecryptClearkey *self = GST_CENC_DECRYPT_CLEARKEY (base);
  GstFlowReturn ret = GST_FLOW_OK;
  GstMapInfo map;
  GBytes *key = NULL;
  const GstCencMeta *sample_info = NULL;
  int pos = 0;
  int sample_index = 0;
  AesCtrState *state = NULL;

  GST_LOG_OBJECT (self, "decrypt in-place");
  sample_info = gst_buffer_get_cenc_meta (buf);
  if (!sample_info || !buf) {
    if (!sample_info)
      GST_ERROR_OBJECT (self, "Failed to get sample_info metadata from buffer");
    if (!buf)
      GST_ERROR_OBJECT (self, "Failed to get writable buffer");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto out;
  }

  if (!gst_buffer_map (buf, &map, GST_MAP_READWRITE)) {
    GST_ERROR_OBJECT (self,"Failed to map buffer");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }

  GST_LOG_OBJECT (self, "decrypt sample %d", map.size);
  if (sample_info->properties->iv_size == 0
      || !sample_info->properties->is_encrypted) {
    /* sample is not encrypted */
    goto beach;
  }

  key = gst_cenc_decrypt_clearkey_get_key (self,
      gst_cenc_sample_properties_get_key_id (sample_info->properties));

  if (!key) {
    GST_ERROR_OBJECT (self, "Failed to lookup key");
    GST_MEMDUMP_OBJECT (self, "Key ID:",
        g_bytes_get_data (gst_cenc_sample_properties_get_key_id (
            sample_info->properties), NULL), 16);
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

  while (pos < map.size) {
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
      ++sample_index;
    } else {
      n_bytes_clear = 0;
      n_bytes_encrypted = map.size - pos;
    }

    GST_TRACE_OBJECT (self, "%d bytes clear (todo=%d)", n_bytes_clear,
          map.size-pos);
    pos += n_bytes_clear;

    if (n_bytes_encrypted) {
      GST_TRACE_OBJECT (self, "%d bytes encrypted (todo=%d)",
          n_bytes_encrypted, map.size-pos);
      gst_aes_ctr_decrypt_ip (state, map.data + pos, n_bytes_encrypted);
      pos += n_bytes_encrypted;
    }
  }

beach:
  gst_buffer_unmap (buf, &map);
  if (state)
    gst_aes_ctr_decrypt_unref (state);
release:
  if (sample_info)
    gst_buffer_remove_meta (buf, (GstMeta*)sample_info);
out:
  return ret;
}

static void
gst_cenc_decrypt_clearkey_parse_pssh (GstCencDecryptClearkey * self, GstBuffer * pssh)
{
  GstMapInfo info;
  GstByteReader br;
  guint8 version;
  guint32 data_size;
  guint32 key_id_count = 0;
  GPtrArray *key_ids;
  GPtrArray *urls;
  gint i;

  key_ids = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  urls = g_ptr_array_new_with_free_func ((GDestroyNotify) g_free);

  gst_buffer_map (pssh, &info, GST_MAP_READ);
  gst_byte_reader_init (&br, info.data, info.size);

  gst_byte_reader_skip_unchecked (&br, 8);
  version = gst_byte_reader_get_uint8_unchecked (&br);
  GST_DEBUG_OBJECT (self, "pssh version: %u", version);
  gst_byte_reader_skip_unchecked (&br, 19);

  if (version > 0) {
    /* Parse KeyIDs */
    const guint key_id_size = 16;

    key_id_count = gst_byte_reader_get_uint32_be_unchecked (&br);
    GST_DEBUG_OBJECT (self, "there are %u key IDs", key_id_count);

    for (i = 0; i < key_id_count; ++i) {
      const guint8 *key_id_data =
        gst_byte_reader_get_data_unchecked (&br, key_id_size);
      GBytes *key_id = g_bytes_new (key_id_data, key_id_size);
      gchar *key_id_string = _create_uuid_string (key_id_data);
      GST_DEBUG_OBJECT (self, "key_id: %s", key_id_string);
      g_free (key_id_string);
      g_ptr_array_add (key_ids, key_id);
    }
  }

  /* Parse Data */
  data_size = gst_byte_reader_get_uint32_be_unchecked (&br);
  GST_DEBUG_OBJECT (self, "pssh data size: %u", data_size);

  if (data_size > 0U) {
    for (i = 0; i < key_id_count; ++i) {
      guint8 url_length = gst_byte_reader_get_uint8_unchecked (&br);
      gchar *url =
        g_strndup ((const gchar *) gst_byte_reader_get_data_unchecked (&br,
            url_length), url_length);
      GST_DEBUG_OBJECT (self, "URL [%d] is %u bytes long.", i, url_length);
      GST_DEBUG_OBJECT (self, "URL [%d]: %s", i, url);
      g_ptr_array_add (urls, url);
    }
  }

  g_assert (key_ids->len == urls->len);

  /* For each key_id, check if we already have the corresponding key in the
   * keystore; if not, fetch the key using its associated URL. */
  for (i = 0; i < key_ids->len; ++i) {
    GBytes *id = g_ptr_array_index (key_ids, i);
    if (!gst_cenc_decrypt_clearkey_have_key_id (self, id)) {
      gchar *url = g_ptr_array_index (urls, i);
      GST_DEBUG_OBJECT (self, "new key: acquiring and adding to keystore.");
      if (!gst_cenc_decrypt_clearkey_acquire_key (self, id, url))
        GST_ERROR_OBJECT (self, "failed to acquire key!");
    }
  }

  g_ptr_array_free (key_ids, TRUE);
  g_ptr_array_free (urls, TRUE);
}

static gboolean
gst_cenc_decrypt_clearkey_sink_event_handler (GstBaseTransform * trans, GstEvent * event)
{
  gboolean ret = TRUE;
  const gchar *system_id;
  GstBuffer *pssi = NULL;
  GstCencPssiOrigin origin;
  GstCencDecryptClearkey *self = GST_CENC_DECRYPT_CLEARKEY (trans);

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_CUSTOM_DOWNSTREAM_STICKY:
      GST_DEBUG_OBJECT (self, "received custom sticky event");
      if (gst_cenc_event_is_pssi (event)) {
        gst_cenc_event_parse_pssi (event, &system_id, &pssi, &origin);

        switch (origin) {
          case GST_CENC_PSSI_ORIGIN_MOOV:
            GST_DEBUG_OBJECT (self, "event carries pssh data from a moov box");
            break;

          case GST_CENC_PSSI_ORIGIN_MOOF:
            GST_DEBUG_OBJECT (self, "event carries pssh data from a moof box");
            break;

          case GST_CENC_PSSI_ORIGIN_MPD:
            GST_DEBUG_OBJECT (self, "event carries data from a DASH MPD");
            break;
        }

        GST_DEBUG_OBJECT (self, "system_id: %s", system_id);

        if (origin == GST_CENC_PSSI_ORIGIN_MOOV
            || origin == GST_CENC_PSSI_ORIGIN_MOOF)
          gst_cenc_decrypt_clearkey_parse_pssh (self, pssi);
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

static void
gst_cenc_decrypt_clearkey_add_key (GstCencDecryptClearkey * self,
    GBytes * key_id, GBytes * key)
{
  gchar * id_string;

  g_return_if_fail (key_id != NULL);
  g_return_if_fail (key != NULL);

  id_string = _create_uuid_string (g_bytes_get_data (key_id, NULL));
  GST_DEBUG_OBJECT (self, "Adding key with ID %s", id_string);
  g_free (id_string);

  g_bytes_ref (key_id); /* Ensure key_id is not deleted while it's used as a
                           key in the hash table. */
  g_mutex_lock (&self->keystore_mutex);
  g_hash_table_insert (self->keystore, key_id, key);
  g_mutex_unlock (&self->keystore_mutex);
}

static GBytes *
gst_cenc_decrypt_clearkey_get_key (GstCencDecryptClearkey * self,
    const GBytes * key_id)
{
  GBytes *ret = NULL;

  g_return_val_if_fail (key_id != NULL, NULL);
  g_mutex_lock (&self->keystore_mutex);
  ret = (GBytes *) g_hash_table_lookup (self->keystore, key_id);
  g_mutex_unlock (&self->keystore_mutex);
  return ret;
}

static gboolean
gst_cenc_decrypt_clearkey_have_key_id (GstCencDecryptClearkey * self,
    const GBytes * key_id)
{
  gboolean ret = FALSE;

  g_return_val_if_fail (key_id != NULL, FALSE);
  g_mutex_lock (&self->keystore_mutex);
  ret = g_hash_table_contains (self->keystore, key_id);
  g_mutex_unlock (&self->keystore_mutex);
  return ret;
}

static gboolean
gst_cenc_decrypt_clearkey_acquire_key (GstCencDecryptClearkey * self,
    GBytes * key_id, const gchar * url)
{
  GstFragment *download;
  guint8 *keydata;
  gchar hexbyte[3] = { '\0', '\0', '\0' };
  gchar *hexdata;
  gint i;

  download = gst_uri_downloader_fetch_uri (self->downloader, url, FALSE, FALSE,
          FALSE, FALSE, NULL);

  if (download) {
    GstMapInfo mapinfo;
    GBytes *key;
    GstBuffer *data = gst_fragment_get_buffer (download);

    g_object_unref (download);
    g_return_val_if_fail (data != NULL, FALSE);
    gst_buffer_map (data, &mapinfo, GST_MAP_READ);
    if (mapinfo.size != 32) {
      GST_ERROR_OBJECT (self, "invalid key size of %u", mapinfo.size);
      gst_buffer_unmap (data, &mapinfo);
      return FALSE;
    }
    hexdata = (gchar *) mapinfo.data;
    keydata = (guint8 *) g_malloc0 (mapinfo.size >> 1);

    /* Read key into allocated memory */
    for (i = 0; i < 16; ++i, hexdata += 2) {
      hexbyte[0] = hexdata[0];
      hexbyte[1] = hexdata[1];

      keydata[i] = (guint8) strtoul ((const char *) hexbyte, NULL, 16);
      GST_DEBUG_OBJECT (self, "keydata[%d] = %#02x", i, keydata[i]);
    }
    gst_buffer_unmap (data, &mapinfo);
    gst_buffer_unref (data);

    /* Wrap key in a GBytes */
    key = g_bytes_new_take (keydata, 16);

    /* Store key in keystore */
    gst_cenc_decrypt_clearkey_add_key (self, key_id, key);
    return TRUE;
  } else {
    GST_ERROR_OBJECT (self, "failed to download key");
    return FALSE;
  }

  return TRUE;
}
