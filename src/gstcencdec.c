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
#include <gst/gstaesctr.h>

#include <glib.h>

#include <openssl/sha.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "gstcencdec.h"

GST_DEBUG_CATEGORY_STATIC (gst_cenc_decrypt_debug_category);
#define GST_CAT_DEFAULT gst_cenc_decrypt_debug_category

#define KID_LENGTH 16
#define KEY_LENGTH 16

typedef struct _GstCencKeyPair 
{
  GBytes *key_id;
  gchar *content_id;
  GBytes *key;
} GstCencKeyPair;

struct _GstCencDecrypt
{
  GstBaseTransform parent;
  GPtrArray *keys; /* array of GstCencKeyPair objects */
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
static gboolean gst_cenc_decrypt_append_if_not_duplicate(GstCaps *dest, GstStructure *new_struct);
static GstCaps *gst_cenc_decrypt_transform_caps (GstBaseTransform * base,
    GstPadDirection direction, GstCaps * caps, GstCaps * filter);

static GstFlowReturn gst_cenc_decrypt_transform_ip (GstBaseTransform * trans,
    GstBuffer * buf);
static const GstCencKeyPair* gst_cenc_decrypt_lookup_key (GstCencDecrypt * self,
    GstBuffer * kid);
static GstCencKeyPair* gst_cenc_decrypt_get_key (GstCencDecrypt * self, GstBuffer * kid);
static gboolean gst_cenc_decrypt_sink_event_handler (GstBaseTransform * trans,
    GstEvent * event);
static gchar* gst_cenc_create_uuid_string (gconstpointer uuid_bytes);

enum
{
  PROP_0
};

/* pad templates */

static GstStaticPadTemplate gst_cenc_decrypt_sink_template =
    GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS
    ("application/x-cenc, original-media-type=(string)video/x-h264, protection-system=(string)69f908af-4816-46ea-910c-cd5dcccb0a3a; "
        "application/x-cenc, original-media-type=(string)video/x-h264, protection-system=(string)5e629af5-38da-4063-8977-97ffbd9902d4; "
        "application/x-cenc, original-media-type=(string)audio/mpeg, protection-system=(string)69f908af-4816-46ea-910c-cd5dcccb0a3a; "
        "application/x-cenc, original-media-type=(string)audio/mpeg, protection-system=(string)5e629af5-38da-4063-8977-97ffbd9902d4")
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

static void gst_cenc_keypair_destroy (gpointer data);

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

  gst_base_transform_set_in_place (base, TRUE);
  gst_base_transform_set_passthrough (base, FALSE);
  gst_base_transform_set_gap_aware (GST_BASE_TRANSFORM (self), FALSE);
  self->keys = g_ptr_array_new_with_free_func (gst_cenc_keypair_destroy);
}

void
gst_cenc_decrypt_dispose (GObject * object)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (object);

  if (self->keys) {
    g_ptr_array_unref (self->keys);
    self->keys = NULL;
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
gst_cenc_decrypt_append_if_not_duplicate(GstCaps *dest, GstStructure *new_struct)
{
  gboolean duplicate=FALSE;
  gint j;

  for (j = 0; !duplicate && j < gst_caps_get_size (dest); ++j) {
    GstStructure *s = gst_caps_get_structure (dest, j);
    if(gst_structure_is_equal (s,new_struct)){
      duplicate=TRUE;
    }
  }
  if(!duplicate){
    gst_caps_append_structure (dest, new_struct);
  }
  else{
    gst_structure_free (new_struct);
  }
  return duplicate;
}

/* filter out the audio and video related fields from the up-stream caps,
   because they are not relevant to the input caps of this element and
   can cause caps negotiation failures with adaptive bitrate streams */
static void
gst_cenc_remove_codec_fields (GstStructure *gs)
{
  gint j, n_fields = gst_structure_n_fields (gs);
  for(j=n_fields-1; j>=0; --j){
    const gchar *field_name;

    field_name = gst_structure_nth_field_name (gs, j);
    GST_TRACE ("Check field \"%s\" for removal", field_name);

    if( g_strcmp0 (field_name, "base-profile")==0 ||
        g_strcmp0 (field_name, "codec_data")==0 ||
        g_strcmp0 (field_name, "height")==0 ||
        g_strcmp0 (field_name, "framerate")==0 ||
        g_strcmp0 (field_name, "level")==0 ||
        g_strcmp0 (field_name, "pixel-aspect-ratio")==0 ||
        g_strcmp0 (field_name, "profile")==0 ||
        g_strcmp0 (field_name, "rate")==0 ||
        g_strcmp0 (field_name, "width")==0 ){
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
  gint i, j;

  g_return_val_if_fail (direction != GST_PAD_UNKNOWN, NULL);
  res = gst_caps_new_empty ();

  GST_DEBUG_OBJECT (base, "direction: %s   caps: %" GST_PTR_FORMAT "   filter:"
      " %" GST_PTR_FORMAT, (direction == GST_PAD_SRC) ? "Src" : "Sink",
      caps, filter);

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
      for(j=0; j<n_fields; ++j){
          const gchar *field_name;

          field_name = gst_structure_nth_field_name (in, j);

          if( g_str_has_prefix(field_name, "protection-system") ||
              g_str_has_prefix(field_name, "original-media-type") ){
              gst_structure_remove_field (out, field_name);
          }
      }
    } else {                    /* GST_PAD_SRC */
      gint n_fields;
      GstStructure *tmp = NULL;
      /* filter out the video related fields from the up-stream caps,
       because they are not relevant to the input caps of this element and
       can cause caps negotiation failures with adaptive bitrate streams */
      tmp = gst_structure_copy (in);
      gst_cenc_remove_codec_fields (tmp);

      out = gst_structure_copy (tmp);
      gst_structure_set (out,
          "protection-system", G_TYPE_STRING, "69f908af-4816-46ea-910c-cd5dcccb0a3a",
          "original-media-type", G_TYPE_STRING, gst_structure_get_name (in),
          NULL);

      gst_structure_set_name (out, "application/x-cenc");
      gst_cenc_decrypt_append_if_not_duplicate(res, out);

      out = gst_structure_copy (tmp);
      gst_structure_set (out,
          "protection-system", G_TYPE_STRING, "5e629af5-38da-4063-8977-97ffbd9902d4",
          "original-media-type", G_TYPE_STRING, gst_structure_get_name (in),
          NULL);

      gst_structure_set_name (out, "application/x-cenc");

      gst_structure_free (tmp);
    }
    gst_cenc_decrypt_append_if_not_duplicate(res, out);
  }

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

static gchar *
gst_cenc_bytes_to_string (gconstpointer bytes, guint length)
{
  const guint8 *data = (const guint8 *) bytes;
  gchar *string = g_malloc0 ((2 * length) + 1);
  guint i;

  for (i = 0; i < length; ++i) {
    g_snprintf (string + (2 * i), 3, "%02x", data[i]);
  }

  return string;
}

static gchar *
gst_cenc_create_content_id (gconstpointer key_id)
{
  const guint8 *id = (const guint8 *) key_id;
  const gsize id_string_length = 48;    /* Length of Content ID string */
  gchar *id_string = g_malloc0 (id_string_length);

  g_snprintf (id_string, id_string_length,
      "urn:marlin:kid:%02x%02x%02x%02x%02x%02x%02x%02x"
      "%02x%02x%02x%02x%02x%02x%02x%02x",
      id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7],
      id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]);

  return id_string;
}

static GstBuffer*
gst_cenc_decrypt_key_id_from_content_id(GstCencDecrypt * self, const gchar *content_id)
{
  GstBuffer *kid;
  GstMapInfo map;
  gboolean failed=FALSE;
  guint i,pos;
  /*gchar *id_string;*/

  if(!g_str_has_prefix (content_id, "urn:marlin:kid:")){
    return NULL;
  }
  kid = gst_buffer_new_allocate (NULL, KID_LENGTH, NULL);
  gst_buffer_map (kid, &map, GST_MAP_READWRITE);
  for(i=0, pos=strlen("urn:marlin:kid:"); i<KID_LENGTH; ++i){
    guint b;
    if(!sscanf(&content_id[pos], "%02x", &b)){
      failed=TRUE;
      break;
    }
    map.data[i] = b;
    pos += 2;
  }
  /*id_string = gst_cenc_create_uuid_string (map.data);
  GST_DEBUG_OBJECT (self, "content_id=%s  key=%s", content_id, id_string);
  g_free (id_string);*/
  gst_buffer_unmap (kid, &map);
  if(failed){
    gst_buffer_unref (kid);
    kid=NULL;
  }
  return kid;
}

static GstCencKeyPair *
gst_cenc_decrypt_get_key (GstCencDecrypt * self, GstBuffer * key_id)
{
  guint8 key[KEY_LENGTH] = { 0 };
  guint8 hash[SHA_DIGEST_LENGTH] = { 0 };
  gchar *hash_string;
  gchar *path;
  size_t bytes_read = 0;
  FILE *key_file = NULL;
  GstMapInfo info;
  GstCencKeyPair *kp;

  if(!gst_buffer_map(key_id, &info, GST_MAP_READ))
    return NULL;
  kp = g_new0 (GstCencKeyPair, 1);
  kp->key_id = g_bytes_new (info.data, KEY_LENGTH);
  kp->content_id = gst_cenc_create_content_id (info.data);
  gst_buffer_unmap(key_id, &info);

  GST_DEBUG_OBJECT (self, "Content ID: %s", kp->content_id);

  /* Perform sha1 hash of content id. */
  SHA1 ((const unsigned char *) kp->content_id, 47, hash);
  hash_string = gst_cenc_bytes_to_string (hash, SHA_DIGEST_LENGTH);
  GST_DEBUG_OBJECT (self, "Hash: %s", hash_string);
  /*  g_free (content_id);*/

  /* Read contents of file with the hash as its name. */
  path = g_strconcat ("/tmp/", hash_string, ".key", NULL);
  g_free (hash_string);
  GST_DEBUG_OBJECT (self, "Opening file: %s", path);
  key_file = fopen (path, "rb");

  if (!key_file) {
    GST_ERROR_OBJECT (self, "Failed to open keyfile: %s", path);
    goto error;
  }

  bytes_read = fread (key, 1, KEY_LENGTH, key_file);
  fclose (key_file);

  if (bytes_read != KEY_LENGTH) {
    GST_ERROR_OBJECT (self, "Failed to read key from file %s", path);
    goto error;
  }
  g_free (path);

  kp->key = g_bytes_new (key, KEY_LENGTH);
  g_ptr_array_add (self->keys, kp);

  return kp;
error:
  g_free (path);
  gst_cenc_keypair_destroy (kp);
  return NULL;
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

static const GstCencKeyPair*
gst_cenc_decrypt_lookup_key (GstCencDecrypt * self, GstBuffer * kid)
{
  GstMapInfo info;
  const GstCencKeyPair *kp=NULL;
  int i;
  gsize sz;

  /*
    GstMapInfo info;
    gchar *id_string;
    gst_buffer_map (kid, &info, GST_MAP_READ);
    id_string = gst_cenc_create_uuid_string (info.data);
    GST_DEBUG_OBJECT (self, "Looking up key ID: %s", id_string);
    g_free (id_string);
    gst_buffer_unmap (kid, &info);
  */
  for (i = 0; kp==NULL && i < self->keys->len; ++i) {
    const GstCencKeyPair *k;
    k = g_ptr_array_index (self->keys, i);
    if(gst_buffer_memcmp (kid, 0, g_bytes_get_data (k->key_id, NULL), KEY_LENGTH)==0){
      kp=k;
    }
  }
  if (!kp) {
    kp = gst_cenc_decrypt_get_key (self, kid);
  }

  return kp;
}

static GstFlowReturn
gst_cenc_decrypt_transform_ip (GstBaseTransform * base, GstBuffer * buf)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (base);
  GstFlowReturn ret = GST_FLOW_OK;
  GstMapInfo map, iv_map;
  const GstCencKeyPair *keypair;
  const GstProtectionMeta *prot_meta = NULL;
  int pos = 0;
  int sample_index = 0;
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
  GstByteReader *reader=NULL;

  GST_TRACE_OBJECT (self, "decrypt in-place");
  prot_meta = (GstProtectionMeta*) gst_buffer_get_protection_meta (buf);
  if (!prot_meta || !buf) {
    if (!prot_meta) {
      GST_ERROR_OBJECT (self, "Failed to get GstProtection metadata from buffer");
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

  GST_TRACE_OBJECT (self, "decrypt sample %d", map.size);
  if(!gst_structure_get_uint(prot_meta->info,"iv_size",&iv_size)){
    GST_ERROR_OBJECT (self, "failed to get iv_size");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  if(!gst_structure_get_boolean(prot_meta->info,"encrypted",&encrypted)){
    GST_ERROR_OBJECT (self, "failed to get encrypted flag");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  if (iv_size == 0 || !encrypted) {
    /* sample is not encrypted */
    goto beach;
  }
  GST_DEBUG_OBJECT (base, "protection meta: %" GST_PTR_FORMAT, prot_meta->info);
  if(!gst_structure_get_uint(prot_meta->info,"subsample_count",&subsample_count)){
    GST_ERROR_OBJECT (self, "failed to get subsample_count");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  value = gst_structure_get_value (prot_meta->info, "kid");
  if(!value){
    GST_ERROR_OBJECT (self, "Failed to get KID for sample");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  key_id = gst_value_get_buffer (value);

  value = gst_structure_get_value (prot_meta->info, "iv");
  if(!value){
    GST_ERROR_OBJECT (self, "Failed to get IV for sample");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  iv_buf = gst_value_get_buffer (value);
  if(!gst_buffer_map (iv_buf, &iv_map, GST_MAP_READ)){
    GST_ERROR_OBJECT (self, "Failed to map IV");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  iv_bytes = g_bytes_new (iv_map.data, iv_map.size);
  gst_buffer_unmap (iv_buf, &iv_map);
  if(subsample_count){
    value = gst_structure_get_value (prot_meta->info, "subsamples");
    if(!value){
      GST_ERROR_OBJECT (self, "Failed to get subsamples");
      ret = GST_FLOW_NOT_SUPPORTED;
      goto release;
    }
    subsamples_buf = gst_value_get_buffer (value);
    if(!gst_buffer_map (subsamples_buf, &subsamples_map, GST_MAP_READ)){
      GST_ERROR_OBJECT (self, "Failed to map subsample buffer");
      ret = GST_FLOW_NOT_SUPPORTED;
      goto release;
    }
  }

  keypair = gst_cenc_decrypt_lookup_key (self,key_id);

  if (!keypair) {
    gsize sz;
    GST_ERROR_OBJECT (self, "Failed to lookup key");
    GST_MEMDUMP_OBJECT (self, "Key ID:", 
                        g_bytes_get_data (keypair->key_id, &sz),
                        sz);
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }

  state = gst_aes_ctr_decrypt_new (keypair->key, iv_bytes);

  if (!state) {
    GST_ERROR_OBJECT (self, "Failed to init AES cipher");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }

  reader = gst_byte_reader_new (subsamples_map.data, subsamples_map.size);
  if(!reader){
    GST_ERROR_OBJECT (self, "Failed to allocate subsample reader");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
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
    GST_TRACE_OBJECT (self, "%d bytes clear (todo=%d)", n_bytes_clear,
        map.size - pos);
    pos += n_bytes_clear;
    if (n_bytes_encrypted) {
      GST_TRACE_OBJECT (self, "%d bytes encrypted (todo=%d)",
          n_bytes_encrypted, map.size - pos);
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
  if (reader){
    gst_byte_reader_free (reader);
  }
  if(subsamples_buf){
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

static void
gst_cenc_decrypt_parse_pssh_box (GstCencDecrypt * self, GstBuffer * pssh)
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
  gst_buffer_unmap (pssh, &info);
}

static gboolean
gst_cenc_decrypt_parse_content_protection_element (GstCencDecrypt * self,
    GstBuffer * pssi)
{
  GstMapInfo info;
  guint32 data_size;
  xmlDocPtr doc;
  xmlNode *root_element = NULL;
  gboolean ret = TRUE;
  xmlNode *cur_node;

  gst_buffer_map (pssi, &info, GST_MAP_READ);

  /* this initialize the library and check potential ABI mismatches
   * between the version it was compiled for and the actual shared
   * library used
   */
  LIBXML_TEST_VERSION
  /* parse "data" into a document (which is a libxml2 tree structure xmlDoc) */
  doc =
    xmlReadMemory (info.data, info.size, "ContentProtection.xml", NULL, XML_PARSE_NONET);
  if (!doc) {
    ret = FALSE;
    GST_ERROR_OBJECT (self, "Failed to parse XML from pssi event");
    goto beach;
  }
  root_element = xmlDocGetRootElement (doc);

  if (root_element->type != XML_ELEMENT_NODE
      || xmlStrcmp (root_element->name, (xmlChar *) "ContentProtection") != 0) {
    GST_ERROR_OBJECT (self, "Failed to find ContentProtection element");
    ret = FALSE;
    goto beach;
  }

  /* Parse KeyIDs */
  for (cur_node = root_element->children; cur_node; cur_node = cur_node->next) {
    xmlNode *k_node;
    if (cur_node->type != XML_ELEMENT_NODE ||
        !g_str_has_suffix ((const gchar *)cur_node->name,"MarlinContentIds"))
      continue;
    for (k_node = cur_node->children; k_node; k_node = k_node->next) {
      xmlChar *node_content;
      GstBuffer *kid;
      GstMapInfo map;
      if (k_node->type != XML_ELEMENT_NODE ||
          !g_str_has_suffix ((const gchar*)k_node->name, "MarlinContentId"))
        continue;
      node_content = xmlNodeGetContent (k_node);
      if (!node_content)
        continue;
      GST_DEBUG_OBJECT (self, "ContentId: %s", node_content);
      kid = gst_cenc_decrypt_key_id_from_content_id(self, node_content);
      /* pre-fetch the key */
      if(kid && !gst_cenc_decrypt_get_key (self, kid)){
        GST_ERROR_OBJECT (self, "Failed to get key for content ID %s", node_content);
      }
      if(kid)
        gst_buffer_unref (kid);
      xmlFree (node_content);
    }
  }

beach:
  gst_buffer_unmap (pssi, &info);
  if (doc)
    xmlFreeDoc (doc);
  return (ret);
}

static gboolean
gst_cenc_decrypt_sink_event_handler (GstBaseTransform * trans, GstEvent * event)
{
  gboolean ret = TRUE;
  const gchar *system_id;
  GstBuffer *pssi = NULL;
  const gchar *loc;
  GstCencDecrypt *self = GST_CENC_DECRYPT (trans);

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_PROTECTION:
        GST_DEBUG_OBJECT (self, "received protection event");
        gst_event_parse_protection (event, &system_id, &pssi, &loc);
        GST_DEBUG_OBJECT (self, "system_id: %s  loc: %s", system_id, loc);
        if(g_ascii_strcasecmp(loc, "dash/mpd")==0 && g_ascii_strcasecmp(system_id, "5e629af5-38da-4063-8977-97ffbd9902d4")==0){
            GST_DEBUG_OBJECT (self, "event carries MPD pssi data");
            gst_cenc_decrypt_parse_content_protection_element (self, pssi);
        }
        else if(g_str_has_prefix (loc, "isobmff/") && g_ascii_strcasecmp(system_id, "69f908af-4816-46ea-910c-cd5dcccb0a3a")==0){
          GST_DEBUG_OBJECT (self, "event carries pssh data from qtdemux");
          gst_cenc_decrypt_parse_pssh_box (self, pssi);
        }
        gst_event_unref (event);
      break;

    default:
      ret = GST_BASE_TRANSFORM_CLASS (parent_class)->sink_event (trans, event);
      break;
  }

  return ret;
}

static void gst_cenc_keypair_destroy (gpointer data)
{
  GstCencKeyPair *key_pair = (GstCencKeyPair*)data;
  g_bytes_unref (key_pair->key_id);
  g_free (key_pair->content_id);
  g_bytes_unref (key_pair->key);
  g_free (key_pair);
}

