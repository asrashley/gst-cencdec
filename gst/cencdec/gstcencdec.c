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
 * Decrypts media that has been encrypted using the ISOBMFF Common Encryption
 * standard.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>

#include <gst/gst.h>
#include <gst/gstelement.h>
#include <gst/base/gstbasetransform.h>
#include <gst/base/gstbytereader.h>
#include <gst/gstprotection.h>
#include <gst/cencdrm/gstaesctr.h>
#include <gst/cencdrm/gstcencdrm.h>

#include <glib.h>

#include "gstcencdec.h"
#include "gstdrm_stub.h"

GST_DEBUG_CATEGORY (gst_cenc_decrypt_debug_category);
#define GST_CAT_DEFAULT gst_cenc_decrypt_debug_category

struct _GstCencDecrypt
{
  GstBaseTransform parent;
  GstCencDRM *drm;
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
static gboolean gst_cenc_decrypt_append_if_not_duplicate (GstCaps * dest,
    GstStructure * new_struct);
static GstCaps *gst_cenc_decrypt_transform_caps (GstBaseTransform * base,
    GstPadDirection direction, GstCaps * caps, GstCaps * filter);

static GstFlowReturn gst_cenc_decrypt_transform_ip (GstBaseTransform * trans,
    GstBuffer * buf);

static gboolean gst_cenc_decrypt_sink_event_handler (GstBaseTransform * trans,
    GstEvent * event);

/* pad templates */

static GstStaticPadTemplate gst_cenc_decrypt_sink_template =
    GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS
    ("application/x-cenc, protection-system=(string)" CLEARKEY_PROTECTION_ID
        "; " "application/x-cenc, protection-system=(string)"
        PLAYREADY_PROTECTION_ID "; "
        "application/x-cenc, protection-system=(string)"
        MARLIN_MPD_PROTECTION_ID "; "
        "application/x-cenc, protection-system=(string)"
        MARLIN_PSSH_PROTECTION_ID)
    );

static GstStaticPadTemplate gst_cenc_decrypt_src_template =
GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);


static const gchar *gst_cenc_decrypt_protection_ids[] = {
  CLEARKEY_PROTECTION_ID,
  MARLIN_MPD_PROTECTION_ID,
  MARLIN_PSSH_PROTECTION_ID,
  NULL
};

/* class initialization */

#define gst_cenc_decrypt_parent_class parent_class

G_DEFINE_TYPE (GstCencDecrypt, gst_cenc_decrypt, GST_TYPE_BASE_TRANSFORM)
     static void gst_cenc_decrypt_class_init (GstCencDecryptClass * klass)
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
      "Decrypt content encrypted using ISOBMFF Common Encryption",
      GST_ELEMENT_FACTORY_KLASS_DECRYPTOR,
      "Decrypts media that has been encrypted using ISOBMFF Common Encryption.",
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

  GST_PAD_SET_ACCEPT_TEMPLATE (GST_BASE_TRANSFORM_SINK_PAD (self));

  gst_base_transform_set_in_place (base, TRUE);
  gst_base_transform_set_passthrough (base, FALSE);
  gst_base_transform_set_gap_aware (GST_BASE_TRANSFORM (self), FALSE);
  self->drm = NULL;
}

void
gst_cenc_decrypt_dispose (GObject * object)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (object);

  if (self->drm) {
    g_object_unref (self->drm);
    self->drm = NULL;
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

/*
  Append new_structure to dest, but only if it does not already exist in res.
  This function takes ownership of new_structure.
*/
static gboolean
gst_cenc_decrypt_append_if_not_duplicate (GstCaps * dest,
    GstStructure * new_struct)
{
  gboolean duplicate = FALSE;
  guint j;

  for (j = 0; !duplicate && j < gst_caps_get_size (dest); ++j) {
    GstStructure *s = gst_caps_get_structure (dest, j);
    if (gst_structure_is_equal (s, new_struct)) {
      duplicate = TRUE;
    }
  }
  if (!duplicate) {
    gst_caps_append_structure (dest, new_struct);
  } else {
    gst_structure_free (new_struct);
  }
  return duplicate;
}

/* filter out the audio and video related fields from the up-stream caps,
   because they are not relevant to the input caps of this element and
   can cause caps negotiation failures with adaptive bitrate streams */
static void
gst_cenc_remove_codec_fields (GstStructure * gs)
{
  gint j, n_fields = gst_structure_n_fields (gs);
  for (j = n_fields - 1; j >= 0; --j) {
    const gchar *field_name;

    field_name = gst_structure_nth_field_name (gs, j);
    GST_TRACE ("Check field \"%s\" for removal", field_name);

    if (g_strcmp0 (field_name, "base-profile") == 0 ||
        g_strcmp0 (field_name, "codec_data") == 0 ||
        g_strcmp0 (field_name, "height") == 0 ||
        g_strcmp0 (field_name, "framerate") == 0 ||
        g_strcmp0 (field_name, "level") == 0 ||
        g_strcmp0 (field_name, "pixel-aspect-ratio") == 0 ||
        g_strcmp0 (field_name, "profile") == 0 ||
        g_strcmp0 (field_name, "rate") == 0 ||
        g_strcmp0 (field_name, "width") == 0) {
      gst_structure_remove_field (gs, field_name);
      GST_TRACE ("Removing field %s", field_name);
    }
  }
}

/*
  Given the pad in this direction and the given caps, what caps are allowed on
  the other pad in this element ?
*/
static GstCaps *
gst_cenc_decrypt_transform_caps (GstBaseTransform * base,
    GstPadDirection direction, GstCaps * caps, GstCaps * filter)
{
  GstCaps *res = NULL;
  guint i;
  gint j;

  g_return_val_if_fail (direction != GST_PAD_UNKNOWN, NULL);

  GST_DEBUG_OBJECT (base, "direction: %s   caps: %" GST_PTR_FORMAT "   filter:"
      " %" GST_PTR_FORMAT, (direction == GST_PAD_SRC) ? "Src" : "Sink",
      caps, filter);

  if (direction == GST_PAD_SRC && gst_caps_is_any (caps)) {
    res = gst_pad_get_pad_template_caps (GST_BASE_TRANSFORM_SINK_PAD (base));
    goto filter;
  }

  res = gst_caps_new_empty ();

  for (i = 0; i < gst_caps_get_size (caps); ++i) {
    GstStructure *in = gst_caps_get_structure (caps, i);
    GstStructure *out = NULL;

    if (direction == GST_PAD_SINK) {
      gint n_fields;

      if (!gst_structure_has_field (in, "original-media-type"))
        continue;

      out = gst_structure_copy (in);
      n_fields = gst_structure_n_fields (in);

      gst_structure_set_name (out,
          gst_structure_get_string (out, "original-media-type"));

      /* filter out the DRM related fields from the down-stream caps */
      for (j = n_fields - 1; j >= 0; --j) {
        const gchar *field_name;

        field_name = gst_structure_nth_field_name (in, j);

        if (g_str_has_prefix (field_name, "protection-system") ||
            g_str_has_prefix (field_name, "original-media-type")) {
          gst_structure_remove_field (out, field_name);
        }
      }
      gst_cenc_decrypt_append_if_not_duplicate (res, out);
    } else {                    /* GST_PAD_SRC */
      /*gint n_fields; */
      GstStructure *tmp = NULL;
      guint p;
      tmp = gst_structure_copy (in);
      gst_cenc_remove_codec_fields (tmp);
      for (p = 0; gst_cenc_decrypt_protection_ids[p]; ++p) {
        /* filter out the audio/video related fields from the down-stream
           caps, because they are not relevant to the input caps of this
           element and they can cause caps negotiation failures with
           adaptive bitrate streams */
        out = gst_structure_copy (tmp);
        gst_structure_set (out,
            "protection-system", G_TYPE_STRING,
            gst_cenc_decrypt_protection_ids[p], "original-media-type",
            G_TYPE_STRING, gst_structure_get_name (in), NULL);
        gst_structure_set_name (out, "application/x-cenc");
        gst_cenc_decrypt_append_if_not_duplicate (res, out);
      }
      gst_structure_free (tmp);
    }
  }
  if (direction == GST_PAD_SINK && gst_caps_get_size (res) == 0) {
    gst_caps_unref (res);
    res = gst_caps_new_any ();
  }
filter:
  if (filter) {
    GstCaps *intersection;

    GST_DEBUG_OBJECT (base, "Using filter caps %" GST_PTR_FORMAT, filter);
    intersection =
        gst_caps_intersect_full (res, filter, GST_CAPS_INTERSECT_FIRST);
    gst_caps_unref (res);
    res = intersection;
  }

  GST_DEBUG_OBJECT (base, "returning %" GST_PTR_FORMAT, res);
  return res;
}



static GstFlowReturn
gst_cenc_decrypt_transform_ip (GstBaseTransform * base, GstBuffer * buf)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (base);
  GstFlowReturn ret = GST_FLOW_OK;
  GstMapInfo map, iv_map;
  const GstProtectionMeta *prot_meta = NULL;
  guint pos = 0;
  guint sample_index = 0;
  guint subsample_count;
  AesCtrState *state = NULL;
  guint iv_size;
  gboolean encrypted;
  const GValue *value;
  GstBuffer *key_id = NULL;
  GstBuffer *iv_buf = NULL;
  GBytes *iv_bytes = NULL;
  GstBuffer *subsamples_buf = NULL;
  GstMapInfo subsamples_map;
  GstByteReader *reader = NULL;

  GST_TRACE_OBJECT (self, "decrypt in-place");
  prot_meta = (GstProtectionMeta *) gst_buffer_get_protection_meta (buf);
  if (!prot_meta || !buf) {
    if (!prot_meta) {
      GST_ERROR_OBJECT (self,
          "Failed to get GstProtection metadata from buffer");
    }
    if (!buf) {
      GST_ERROR_OBJECT (self, "Failed to get writable buffer");
    }
    ret = GST_FLOW_NOT_SUPPORTED;
    goto out;
  }

  if (!gst_buffer_map (buf, &map, GST_MAP_READWRITE)) {
    GST_ERROR_OBJECT (self, "Failed to map buffer");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }

  GST_TRACE_OBJECT (self, "decrypt sample %d", (gint) map.size);
  if (!gst_structure_get_uint (prot_meta->info, "iv_size", &iv_size)) {
    GST_ERROR_OBJECT (self, "failed to get iv_size");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  if (!gst_structure_get_boolean (prot_meta->info, "encrypted", &encrypted)) {
    GST_ERROR_OBJECT (self, "failed to get encrypted flag");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  if (iv_size == 0 || !encrypted) {
    /* sample is not encrypted */
    goto beach;
  }
  GST_TRACE_OBJECT (base, "protection meta: %" GST_PTR_FORMAT, prot_meta->info);
  if (!gst_structure_get_uint (prot_meta->info, "subsample_count",
          &subsample_count)) {
    GST_ERROR_OBJECT (self, "failed to get subsample_count");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  value = gst_structure_get_value (prot_meta->info, "kid");
  if (!value) {
    GST_ERROR_OBJECT (self, "Failed to get KID for sample");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  key_id = gst_value_get_buffer (value);

  value = gst_structure_get_value (prot_meta->info, "iv");
  if (!value) {
    GST_ERROR_OBJECT (self, "Failed to get IV for sample");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  iv_buf = gst_value_get_buffer (value);
  if (!gst_buffer_map (iv_buf, &iv_map, GST_MAP_READ)) {
    GST_ERROR_OBJECT (self, "Failed to map IV");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  iv_bytes = g_bytes_new (iv_map.data, iv_map.size);
  gst_buffer_unmap (iv_buf, &iv_map);
  if (subsample_count) {
    value = gst_structure_get_value (prot_meta->info, "subsamples");
    if (!value) {
      GST_ERROR_OBJECT (self, "Failed to get subsamples");
      ret = GST_FLOW_NOT_SUPPORTED;
      goto release;
    }
    subsamples_buf = gst_value_get_buffer (value);
    if (!gst_buffer_map (subsamples_buf, &subsamples_map, GST_MAP_READ)) {
      GST_ERROR_OBJECT (self, "Failed to map subsample buffer");
      ret = GST_FLOW_NOT_SUPPORTED;
      goto release;
    }
  }

  if (!self->drm) {
    GST_ERROR_OBJECT (self, "No DRM instance has been configured");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }

  state =
      GST_CENC_DRM_GET_CLASS (self->drm)->create_decrypt (self->drm, key_id,
      iv_bytes);

  if (!state) {
    GST_ERROR_OBJECT (self, "Failed to create AES cipher for key");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }

  if (subsample_count) {
    reader = gst_byte_reader_new (subsamples_map.data, subsamples_map.size);
    if (!reader) {
      GST_ERROR_OBJECT (self, "Failed to allocate subsample reader");
      ret = GST_FLOW_NOT_SUPPORTED;
      goto release;
    }
  }

  while (pos < map.size) {
    guint16 n_bytes_clear = 0;
    guint32 n_bytes_encrypted = 0;

    if (sample_index < subsample_count) {
      if (!gst_byte_reader_get_uint16_be (reader, &n_bytes_clear)
          || !gst_byte_reader_get_uint32_be (reader, &n_bytes_encrypted)) {
        ret = GST_FLOW_NOT_SUPPORTED;
        goto release;
      }
      sample_index++;
    } else {
      n_bytes_clear = 0;
      n_bytes_encrypted = map.size - pos;
    }
    GST_TRACE_OBJECT (self, "%u bytes clear (todo=%d)", n_bytes_clear,
        (gint) map.size - pos);
    pos += n_bytes_clear;
    if (n_bytes_encrypted) {
      GST_TRACE_OBJECT (self, "%u bytes encrypted (todo=%d)",
          n_bytes_encrypted, (gint) map.size - pos);
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
  if (reader) {
    gst_byte_reader_free (reader);
  }
  if (subsamples_buf) {
    gst_buffer_unmap (subsamples_buf, &subsamples_map);
  }
  if (prot_meta) {
    gst_buffer_remove_meta (buf, (GstMeta *) prot_meta);
  }
  if (iv_bytes) {
    g_bytes_unref (iv_bytes);
  }
out:
  return ret;
}

static gboolean
gst_cenc_decrypt_sink_event_handler (GstBaseTransform * trans, GstEvent * event)
{
  gboolean ret = TRUE;
  const gchar *system_id;
  GstBuffer *pssi = NULL;
  const gchar *loc;
  GstCencDecrypt *self = GST_CENC_DECRYPT (trans);
  GstCencDrmStatus drm_status;

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_PROTECTION:
      GST_DEBUG_OBJECT (self, "received protection event");
      gst_event_parse_protection (event, &system_id, &pssi, &loc);
      GST_DEBUG_OBJECT (self, "system_id: %s  loc: %s", system_id, loc);
      if (self->drm == NULL) {
        self->drm = gst_cenc_drm_stub_factory (event);
      } else {
        if (gst_buffer_memcmp (self->drm->system_id, 0, system_id,
                SYSTEM_ID_LENGTH) == 0) {
          drm_status =
              gst_cenc_drm_process_content_protection_event (self->drm, event);
          if (drm_status != GST_DRM_OK) {
            GST_ERROR_OBJECT (self,
                "Error processing content protection event: %u", drm_status);
            ret = FALSE;
          }
        } else {
          GST_DEBUG_OBJECT (self,
              "Skipping protection event as not for configured DRM instance");
        }
      }
      gst_event_unref (event);
      break;

    default:
      ret = GST_BASE_TRANSFORM_CLASS (parent_class)->sink_event (trans, event);
      break;
  }

  return ret;
}
