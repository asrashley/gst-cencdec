/*
 * Copyright (c) <2019> Alex Ashley <alex@digital-video.org.uk>
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

#include <gst/base/gstbytereader.h>
#include <gst/cencdrm/gstcencdrm.h>

#include <json-glib/json-glib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <curl/curl.h>

#include <stdio.h>

#include "gstdrm_stub.h"

GST_DEBUG_CATEGORY_EXTERN (gst_cenc_decrypt_debug_category);
#define GST_CAT_DEFAULT gst_cenc_decrypt_debug_category

typedef struct _StubKeyPair
{
  GstCencKeyPair parent;
  gchar *content_id;
  gchar *filename;
} StubKeyPair;

typedef struct _GstCencDRMStubClass
{
  GstCencDRMClass parent_class;
} GstCencDRMStubClass;

typedef struct _GstCencDRMStub
{
  GstCencDRM parent;

  GPtrArray *keys;              /* array of GstCencKeyPair objects */
  gchar *la_url;
} GstCencDRMStub;

typedef struct _StubHttpPost
{
  guint8 *payload;
  guint payload_size;
  guint payload_rpos;
  GByteArray *response;
} StubHttpPost;

enum
{
  DRM_STUB_PLAYREADY_MPD_PSSH = GST_DRM_IDENTIFIER_PRIVATE,
  DRM_STUB_PLAYREADY_MPD_PRO = GST_DRM_IDENTIFIER_PRIVATE + 1,
  DRM_STUB_MARLIN_MPD_CONTENT_IDS = GST_DRM_IDENTIFIER_PRIVATE + 2,
  DRM_STUB_MARLIN_MPD_CONTENT_ID = GST_DRM_IDENTIFIER_PRIVATE + 3,
  DRM_STUB_CLEARKEY_LAURL = GST_DRM_IDENTIFIER_PRIVATE + 4,
};

#define gst_cenc_drm_stub_parent_class parent_class

#define GST_TYPE_CENC_DRM_STUB                       \
  (gst_cenc_drm_stub_get_type())
#define GST_CENC_DRM_STUB(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_CENC_DRM_STUB,GstCencDRMStub))
#define GST_CENC_DRM_STUB_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_CENC_DRM_STUB,GstCencDRMStubClass))
#define GST_CENC_DRM_STUB_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS((obj),GST_TYPE_CENC_DRM_STUB,GstCencDRMStubClass))
#define GST_IS_CENC_DRM_STUB(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_CENC_DRM_STUB))
#define GST_IS_CENC_DRM_STUB_CLASS(obj) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_CENC_DRM_STUB))
#define GST_CENC_DRM_STUB_CAST(obj) ((GstCencDRMStub *)obj)

G_DEFINE_TYPE (GstCencDRMStub, gst_cenc_drm_stub, GST_TYPE_CENC_DRM);

static void gst_cenc_drm_stub_dispose (GObject * obj);
static GstCencDrmProcessing gst_cenc_drm_stub_should_process_node (GstCencDRM *,
    const gchar * namespace, const gchar * element, guint * identifier);
static GstCencDrmStatus gst_cenc_drm_stub_configure (GstCencDRM * self,
    guint identifier, GstBuffer * data);
static GstCencDrmStatus
gst_cenc_drm_stub_add_kid (GstCencDRM * self, GstBuffer * kid);
static AesCtrState *gst_cenc_drm_stub_create_decrypt (GstCencDRM *,
    GstBuffer * kid, GBytes * iv);
static StubKeyPair *gst_cenc_drm_stub_keypair_new (GstCencDRMStub * self,
    GstBuffer * key_id);
static void gst_cenc_drm_stub_keypair_dispose (GstCencDRM * self,
    GstCencKeyPair * key_pair);
static StubKeyPair *gst_cenc_drm_stub_lookup_key (GstCencDRMStub * self,
    GstBuffer * kid);
static GstCencDrmStatus gst_cenc_drm_stub_add_base64url_key (GstCencDRMStub *,
    const gchar * b64kid, const gchar * b64key);
static GstCencDrmStatus gst_cenc_drm_stub_fetch_key (GstCencDRMStub * self,
    StubKeyPair * key_pair);
static GstCencDrmStatus gst_cenc_drm_stub_fetch_key_from_file (GstCencDRMStub *
    self, StubKeyPair * kp);
static GstCencDrmStatus gst_cenc_drm_stub_fetch_key_from_url (GstCencDRMStub *
    self, StubKeyPair * kp);
static GstBuffer
    * gst_cenc_drm_stub_key_id_from_marlin_content_id (GstCencDRMStub * self,
    GstBuffer * content_id);
static gchar *gst_cenc_drm_stub_create_content_id (GstCencDRMStub * self,
    GstBuffer * kid);
static GstCencDrmStatus
gst_cenc_drm_stub_process_playready_pro_element (GstCencDRMStub *, GstBuffer *);
static GstCencDrmStatus
gst_cenc_drm_stub_process_clearkey_laurl_element (GstCencDRMStub *,
    GstBuffer *);
static GstCencDrmStatus
gst_cenc_drm_stub_process_playready_pssh_element (GstCencDRMStub *,
    GstBuffer *);
static GstCencDrmStatus
gst_cenc_drm_stub_process_marlin_content_id_element (GstCencDRMStub *,
    GstBuffer *);
static GstCencDrmStatus gst_cenc_drm_stub_process_pssh_data (GstCencDRMStub *
    self, GstBuffer * data);

static void
gst_cenc_drm_stub_class_init (GstCencDRMStubClass * klass)
{
  GObjectClass *gobject_class;
  GstCencDRMClass *gst_drm_class;

  gobject_class = (GObjectClass *) klass;
  gst_drm_class = (GstCencDRMClass *) klass;

  /*gobject_class->set_property = gst_cenc_drm_stub_set_property;
     gobject_class->get_property = gst_cenc_drm_stub_get_property; */
  gobject_class->dispose = gst_cenc_drm_stub_dispose;

  gst_drm_class->should_process_node = gst_cenc_drm_stub_should_process_node;
  gst_drm_class->configure = gst_cenc_drm_stub_configure;
  gst_drm_class->add_kid = gst_cenc_drm_stub_add_kid;
  gst_drm_class->create_decrypt = gst_cenc_drm_stub_create_decrypt;
  gst_drm_class->keypair_dispose = gst_cenc_drm_stub_keypair_dispose;
}

static void
gst_cenc_drm_stub_init (GstCencDRMStub * self)
{
  self->la_url = NULL;
  self->keys = g_ptr_array_new_with_free_func ((GDestroyNotify)
      gst_cenc_drm_keypair_unref);
}

static void
gst_cenc_drm_stub_dispose (GObject * obj)
{
  GstCencDRMStub *self = GST_CENC_DRM_STUB (obj);

  if (self->keys) {
    g_ptr_array_unref (self->keys);
    self->keys = NULL;
  }
  g_free (self->la_url);
  self->la_url = NULL;
  G_OBJECT_CLASS (parent_class)->dispose (obj);
}

GstCencDRM *
gst_cenc_drm_stub_factory (GstEvent * event)
{
  GstCencDRM *drm = NULL;
  const gchar *system_id = NULL;
  GstBuffer *pssi = NULL;
  const gchar *loc = NULL;
  GstCencDrmStatus rv;

  gst_event_parse_protection (event, &system_id, &pssi, &loc);
  if (g_ascii_strcasecmp (system_id, MARLIN_MPD_PROTECTION_ID) == 0 ||
      g_ascii_strcasecmp (system_id, MARLIN_PSSH_PROTECTION_ID) == 0) {
    drm = g_object_new (GST_TYPE_CENC_DRM_STUB, NULL);
    drm->drm_type = GST_DRM_MARLIN;
  } else if (g_ascii_strcasecmp (system_id, PLAYREADY_PROTECTION_ID) == 0) {
    drm = g_object_new (GST_TYPE_CENC_DRM_STUB, NULL);
    drm->drm_type = GST_DRM_PLAYREADY;
  } else if (g_ascii_strcasecmp (system_id, CLEARKEY_PROTECTION_ID) == 0) {
    drm = g_object_new (GST_TYPE_CENC_DRM_STUB, NULL);
    drm->drm_type = GST_DRM_CLEARKEY;
  } else if (g_ascii_strcasecmp (system_id, W3C_EME_PROTECTION_ID) == 0) {
    drm = g_object_new (GST_TYPE_CENC_DRM_STUB, NULL);
    drm->drm_type = GST_DRM_CLEARKEY;
  }
  if (drm) {
    drm->system_id = gst_cenc_drm_urn_string_to_raw (drm, system_id);
    rv = gst_cenc_drm_process_content_protection_event (drm, event);
    if (rv != GST_DRM_OK) {
      GST_DEBUG ("Processing of content protection event for %s failed: 0x%x",
          system_id, rv);
      g_object_unref (drm);
      drm = NULL;
    }
  }
  return drm;
}

static GstCencDrmProcessing
gst_cenc_drm_stub_should_process_node (GstCencDRM * drm,
    const gchar * namespace, const gchar * element, guint * identifier)
{
  GstCencDRMStub *self = GST_CENC_DRM_STUB (drm);

  GST_DEBUG_OBJECT (self, "check node %s %s", namespace, element);

  if (strcmp (namespace, "urn:mpeg:cenc:2013") == 0 &&
      strcmp (element, "pssh") == 0) {
    *identifier = DRM_STUB_PLAYREADY_MPD_PSSH;
    return GST_DRM_PROCESS_BASE64;
  } else if (strcmp (namespace, "urn:microsoft:playready") == 0 &&
      strcmp (element, "pro") == 0) {
    *identifier = DRM_STUB_PLAYREADY_MPD_PRO;
    return GST_DRM_PROCESS_BASE64;
  } else if (strcmp (namespace, "urn:marlin:mas:1-0:services:schemas:mpd") == 0
      && strcmp (element, "MarlinContentIds") == 0) {
    *identifier = DRM_STUB_MARLIN_MPD_CONTENT_IDS;
    return GST_DRM_PROCESS_CHILDREN;
  } else if (strcmp (namespace, "urn:marlin:mas:1-0:services:schemas:mpd") == 0
      && strcmp (element, "MarlinContentId") == 0) {
    *identifier = DRM_STUB_MARLIN_MPD_CONTENT_ID;
    return GST_DRM_PROCESS_RAW;
  } else if (strcmp (namespace, "http://dashif.org/guidelines/clearKey") == 0
      && strcmp (element, "Laurl") == 0) {
    *identifier = DRM_STUB_CLEARKEY_LAURL;
    return GST_DRM_PROCESS_RAW;
  }
  return GST_DRM_SKIP;
}

static GstCencDrmStatus
gst_cenc_drm_stub_configure (GstCencDRM * drm, guint identifier,
    GstBuffer * data)
{
  GstCencDrmStatus ret = GST_DRM_ERROR_NOT_IMPLEMENTED;
  GstCencDRMStub *self = GST_CENC_DRM_STUB (drm);

  GST_DEBUG_OBJECT (self, "configure %u", identifier);
  switch (identifier) {
    case DRM_STUB_MARLIN_MPD_CONTENT_ID:
      ret = gst_cenc_drm_stub_process_marlin_content_id_element (self, data);
      break;
    case DRM_STUB_PLAYREADY_MPD_PSSH:
      ret = gst_cenc_drm_stub_process_playready_pssh_element (self, data);
      break;
    case DRM_STUB_PLAYREADY_MPD_PRO:
      ret = gst_cenc_drm_stub_process_playready_pro_element (self, data);
      break;
    case GST_DRM_IDENTIFIER_PSSH_PAYLOAD:
      ret = gst_cenc_drm_stub_process_pssh_data (self, data);
      break;
    case DRM_STUB_CLEARKEY_LAURL:
      ret = gst_cenc_drm_stub_process_clearkey_laurl_element (self, data);
      break;
    default:
      GST_ERROR_OBJECT (self, "Unknown identifier %d", identifier);
      ret = GST_DRM_ERROR_OTHER;
  }
  return ret;
}

static GstCencDrmStatus
gst_cenc_drm_stub_add_kid (GstCencDRM * drm, GstBuffer * kid)
{
  GstCencDRMStub *self = GST_CENC_DRM_STUB (drm);
  StubKeyPair *key_pair;

  key_pair = gst_cenc_drm_stub_lookup_key (self, kid);
  if (!key_pair) {
    key_pair = gst_cenc_drm_stub_keypair_new (self, kid);
    g_ptr_array_add (self->keys, key_pair);
  } else {
    gst_cenc_drm_keypair_unref ((GstCencKeyPair *) key_pair);
  }
  return GST_DRM_OK;
}


static AesCtrState *
gst_cenc_drm_stub_create_decrypt (GstCencDRM * drm,
    GstBuffer * kid, GBytes * iv)
{
  GstCencDRMStub *self = GST_CENC_DRM_STUB (drm);
  StubKeyPair *key_pair;
  AesCtrState *aes_state = NULL;

  g_return_val_if_fail (kid != NULL, NULL);
  g_return_val_if_fail (iv != NULL, NULL);

  key_pair = gst_cenc_drm_stub_lookup_key (self, kid);
  if (!key_pair) {
    GST_DEBUG_OBJECT (self, "Request for unknown KID %" GST_PTR_FORMAT, kid);
    if (gst_cenc_drm_stub_add_kid (drm, kid) != GST_DRM_OK) {
      GST_ERROR_OBJECT (self, "Failed to add KID %" GST_PTR_FORMAT, kid);
      return NULL;
    }
    key_pair = gst_cenc_drm_stub_lookup_key (self, kid);
  }
  g_assert (key_pair != NULL);
  if (key_pair->parent.key == NULL) {
    if (gst_cenc_drm_stub_fetch_key (self, key_pair) != GST_DRM_OK) {
      GST_ERROR_OBJECT (self, "Failed to fetch key %" GST_PTR_FORMAT,
          key_pair->parent.key_id);
      gst_cenc_drm_keypair_unref ((GstCencKeyPair *) key_pair);
      return NULL;
    }
    if (key_pair->parent.key == NULL) {
      gst_cenc_drm_keypair_unref ((GstCencKeyPair *) key_pair);
      return NULL;
    }
  }
  aes_state = gst_aes_ctr_decrypt_new (key_pair->parent.key, iv);
  if (!aes_state) {
    GST_ERROR_OBJECT (self, "Failed to init AES cipher");
  }
  gst_cenc_drm_keypair_unref ((GstCencKeyPair *) key_pair);
  return aes_state;
}

static gchar *
gst_cenc_drm_stub_create_content_id (GstCencDRMStub * self, GstBuffer * kid)
{
  GstCencDRM *parent = GST_CENC_DRM (self);
  GstMapInfo map;
  const guint8 *id;
  const gsize id_string_length = 48;    /* Length of Content ID string */
  gchar *id_string = g_malloc0 (id_string_length);
  const gchar *prefix =
      (parent->drm_type == GST_DRM_MARLIN) ? "urn:marlin:kid:" : "";

  gst_buffer_map (kid, &map, GST_MAP_READ);
  id = map.data;
  g_assert_true (map.size == 16);
  g_snprintf (id_string, id_string_length,
      "%s%02x%02x%02x%02x%02x%02x%02x%02x"
      "%02x%02x%02x%02x%02x%02x%02x%02x",
      prefix,
      id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7],
      id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]);

  gst_buffer_unmap (kid, &map);
  return id_string;
}

static GstBuffer *
gst_cenc_drm_stub_key_id_from_marlin_content_id (GstCencDRMStub * self,
    GstBuffer * buf)
{
  const gchar prefix[] = "urn:marlin:kid:";
  GstBuffer *kid;
  GstMapInfo map;
  gboolean failed = FALSE;
  guint i, pos;
  GstMapInfo content_id;

  if (!gst_buffer_map (buf, &content_id, GST_MAP_READ)) {
    GST_WARNING_OBJECT (self, "Failed to map content ID buffer");
    return NULL;
  }
  if (content_id.size <= sizeof (prefix) ||
      !g_str_has_prefix ((const gchar *) content_id.data, prefix)) {
    gst_buffer_unmap (buf, &content_id);
    return NULL;
  }
  kid = gst_buffer_new_allocate (NULL, KID_LENGTH, NULL);
  gst_buffer_map (kid, &map, GST_MAP_READWRITE);
  for (i = 0, pos = sizeof (prefix); i < KID_LENGTH && pos < content_id.size;
      ++i) {
    guint b;
    if (!sscanf ((const char *) &content_id.data[pos], "%02x", &b)) {
      failed = TRUE;
      break;
    }
    map.data[i] = b;
    pos += 2;
  }
  gst_buffer_unmap (buf, &content_id);
  gst_buffer_unmap (kid, &map);
  if (failed) {
    gst_buffer_unref (kid);
    kid = NULL;
  }
  return kid;
}

static GstCencDrmStatus
gst_cenc_drm_stub_fetch_key (GstCencDRMStub * self, StubKeyPair * kp)
{
  if (GST_CENC_DRM (self)->drm_type == GST_DRM_CLEARKEY) {
    return gst_cenc_drm_stub_fetch_key_from_url (self, kp);
  }
  return gst_cenc_drm_stub_fetch_key_from_file (self, kp);
}

static GstCencDrmStatus
gst_cenc_drm_stub_fetch_key_from_file (GstCencDRMStub * self, StubKeyPair * kp)
{
  guint8 *key = NULL;
  size_t bytes_read = 0;
  FILE *key_file = NULL;


  GST_DEBUG_OBJECT (self, "Opening file: %s", kp->filename);
  key_file = fopen (kp->filename, "rb");
  if (!key_file) {
    GST_ERROR_OBJECT (self, "Failed to open keyfile: %s", kp->filename);
    goto error;
  }
  key = g_malloc (KEY_LENGTH);
  bytes_read = fread (key, 1, KEY_LENGTH, key_file);
  fclose (key_file);

  if (bytes_read != KEY_LENGTH) {
    GST_ERROR_OBJECT (self, "Failed to read key from file %s", kp->filename);
    goto error;
  }
  kp->parent.key = g_bytes_new_take (key, KEY_LENGTH);

  return GST_DRM_OK;
error:
  g_free (key);
  return GST_DRM_ERROR_MISSING_KEY;
}

static size_t
gst_cenc_drm_stub_read_callback (void *dest, size_t size, size_t nmemb,
    void *user)
{
  StubHttpPost *post = (StubHttpPost *) user;
  size_t buffer_size = size * nmemb;
  size_t todo = post->payload_size - post->payload_rpos;

  if (todo <= 0) {
    return 0;
  }
  if (todo > buffer_size) {
    todo = buffer_size;
  }
  memcpy (dest, &post->payload[post->payload_rpos], todo);
  post->payload_rpos += todo;
  return todo;
}

static size_t
gst_cenc_drm_stub_write_callback (char *ptr, size_t size, size_t nmemb,
    void *user)
{
  StubHttpPost *post = (StubHttpPost *) user;
  size_t len = size * nmemb;

  if (post->response == NULL) {
    post->response = g_byte_array_new ();
  }
  post->response =
      g_byte_array_append (post->response, (const guint8 *) ptr, len);
  return len;
}

static GstCencDrmStatus
gst_cenc_drm_stub_add_base64url_key (GstCencDRMStub * self,
    const gchar * b64kid, const gchar * b64key)
{
  GstCencDRM *parent = GST_CENC_DRM (self);
  GstBuffer *buf;
  StubKeyPair *pair;
  GBytes *kid, *key;

  GST_DEBUG_OBJECT (self, "KID: %s, Key: %s", b64kid, b64key);
  kid = gst_cenc_drm_base64url_decode (parent, b64kid);
  key = gst_cenc_drm_base64url_decode (parent, b64key);
  buf = gst_buffer_new_wrapped_bytes (kid);
  pair = gst_cenc_drm_stub_lookup_key (self, buf);
  gst_buffer_unref (buf);
  if (pair) {
    if (pair->parent.key) {
      g_bytes_unref (pair->parent.key);
    }
    pair->parent.key = g_bytes_ref (key);
    gst_cenc_drm_keypair_unref ((GstCencKeyPair *) pair);
  }
  g_bytes_unref (kid);
  g_bytes_unref (key);
  return GST_DRM_OK;
}

static GstCencDrmStatus
gst_cenc_drm_stub_parse_clearkey_json (GstCencDRMStub * self, GBytes * bytes)
{
  /*  GstCencDRM *parent = GST_CENC_DRM (self); */
  GstCencDrmStatus rv = GST_DRM_OK;
  JsonParser *parser = NULL;
  JsonReader *reader = NULL;
  const guint8 *data;
  gsize data_size;
  guint i;
  gint num_keys;

  data = g_bytes_get_data (bytes, &data_size);
  GST_DEBUG_OBJECT (self, "Response: %s", data);

  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, (const gchar *) data, data_size,
          NULL)) {
    GST_ERROR_OBJECT (self, "Failed to parse JSON response");
    rv = GST_DRM_ERROR_SERVER_RESPONSE;
    goto quit;
  }
  reader = json_reader_new (json_parser_get_root (parser));
  if (!json_reader_read_member (reader, "keys")) {
    rv = GST_DRM_ERROR_SERVER_RESPONSE;
    goto quit;
  }
  if (!json_reader_is_array (reader)) {
    GST_ERROR_OBJECT (self, "Expected \"keys\" property to be an array");
    rv = GST_DRM_ERROR_SERVER_RESPONSE;
    goto quit;
  }
  num_keys = json_reader_count_elements (reader);
  GST_DEBUG_OBJECT (self, "Response contains %d keys", num_keys);
  for (i = 0; i < num_keys; i++) {
    const gchar *b64key, *b64kid;

    json_reader_read_element (reader, i);
    json_reader_read_member (reader, "k");
    b64key = json_reader_get_string_value (reader);
    json_reader_end_element (reader);   /*  "k" */
    json_reader_read_member (reader, "kid");
    b64kid = json_reader_get_string_value (reader);
    json_reader_end_element (reader);   /*  "kid" */
    json_reader_end_element (reader);   /* array index */
    gst_cenc_drm_stub_add_base64url_key (self, b64kid, b64key);
  }
  json_reader_end_element (reader);     /*  "keys" */
quit:
  if (reader)
    g_object_unref (reader);
  if (parser)
    g_object_unref (parser);
  return rv;
}

static GstCencDrmStatus
gst_cenc_drm_stub_fetch_key_from_url (GstCencDRMStub * self, StubKeyPair * kp)
{
  GstCencDrmStatus rv = GST_DRM_OK;
  GString *request;
  guint i;
  gboolean first = TRUE;
  StubHttpPost post;
  CURL *curl = NULL;
  CURLcode res;
  struct curl_slist *headers = NULL;

  memset (&post, 0, sizeof (post));
  if (self->la_url == NULL) {
    GST_ERROR_OBJECT (self, "License acquisition URL not set");
    return GST_DRM_ERROR_NO_LAURL;
  }
  request = g_string_new ("{\"kids\":[");
  for (i = 0; i < self->keys->len; ++i) {
    StubKeyPair *k;
    gchar *b64kid;

    k = g_ptr_array_index (self->keys, i);
    if (k->parent.key != NULL) {
      continue;
    }
    b64kid = gst_cenc_drm_base64url_encode (GST_CENC_DRM (self),
        k->parent.key_id);
    if (!first) {
      request = g_string_append_c (request, ',');
    }
    request = g_string_append_c (request, '"');
    request = g_string_append (request, b64kid);
    request = g_string_append_c (request, '"');
    g_free (b64kid);
    first = FALSE;
  }
  if (first) {
    GST_WARNING_OBJECT (self, "Request with no key IDs!");
    rv = GST_DRM_ERROR_OTHER;
    goto quit;
  }
  request = g_string_append (request, "],\"type\":\"temporary\"}");
  post.payload = (guint8 *) g_string_free (request, FALSE);
  request = NULL;
  post.payload_size = (guint) strlen ((const gchar *) post.payload);
  post.payload_rpos = 0;
  post.response = NULL;

  GST_DEBUG_OBJECT (self, "JSON request:\n %s", post.payload);

  curl = curl_easy_init ();
  if (!curl) {
    GST_ERROR_OBJECT (self, "curl_easy_init() failed");
    rv = GST_DRM_ERROR_OTHER;
    goto quit;
  }
  headers = curl_slist_append (headers, "Content-Type: application/json");
  curl_easy_setopt (curl, CURLOPT_URL, self->la_url);
  curl_easy_setopt (curl, CURLOPT_POST, 1L);
  curl_easy_setopt (curl, CURLOPT_READFUNCTION,
      gst_cenc_drm_stub_read_callback);
  curl_easy_setopt (curl, CURLOPT_READDATA, &post);
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION,
      gst_cenc_drm_stub_write_callback);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, &post);
  /*curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); */
  curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, (long) post.payload_size);

  GST_DEBUG_OBJECT (self, "Making POST request to: %s", self->la_url);
  res = curl_easy_perform (curl);
  if (res != CURLE_OK) {
    GST_ERROR_OBJECT (self, "curl_easy_perform() failed: %s\n",
        curl_easy_strerror (res));
    rv = GST_DRM_ERROR_SERVER_CONNECTION;
  } else {
    GBytes *response;

    response = g_byte_array_free_to_bytes (post.response);
    post.response = NULL;
    rv = gst_cenc_drm_stub_parse_clearkey_json (self, response);
    g_bytes_unref (response);
  }
quit:
  if (headers) {
    curl_slist_free_all (headers);
  }
  if (request) {
    g_string_free (request, TRUE);
  }
  if (curl) {
    curl_easy_cleanup (curl);
  }
  g_free (post.payload);
  if (post.response) {
    g_byte_array_free (post.response, TRUE);
  }
  return rv;
}

static StubKeyPair *
gst_cenc_drm_stub_lookup_key (GstCencDRMStub * self, GstBuffer * kid)
{
  guint i;

  for (i = 0; i < self->keys->len; ++i) {
    StubKeyPair *k;
    k = g_ptr_array_index (self->keys, i);
    if (gst_buffer_memcmp (kid, 0, g_bytes_get_data (k->parent.key_id, NULL),
            KEY_LENGTH) == 0) {
      return (StubKeyPair *) gst_cenc_drm_keypair_ref ((GstCencKeyPair *) k);
    }
  }
  return NULL;
}

static gchar *
gst_cenc_drm_stub_to_hexstring (guint8 * data, guint length)
{
  gchar *string = g_malloc0 ((2 * length) + 1);
  guint i;

  for (i = 0; i < length; ++i) {
    g_snprintf (string + (2 * i), 3, "%02x", data[i]);
  }

  return string;
}

static StubKeyPair *
gst_cenc_drm_stub_keypair_new (GstCencDRMStub * self, GstBuffer * key_id)
{
  StubKeyPair *kp;
  GstMapInfo info;
  gchar *filename;

  if (!gst_buffer_map (key_id, &info, GST_MAP_READ))
    return NULL;
  kp = g_new0 (StubKeyPair, 1);
  kp->parent.ref_count = 1;
  kp->parent.owner = GST_CENC_DRM (self);
  kp->parent.key_id = g_bytes_new (info.data, KID_LENGTH);
  gst_buffer_unmap (key_id, &info);
  kp->content_id = gst_cenc_drm_stub_create_content_id (self, key_id);
  GST_DEBUG_OBJECT (self, "Content ID: %s", kp->content_id);

  if (GST_CENC_DRM (self)->drm_type == GST_DRM_MARLIN) {
    guint8 *hash;

    /* Perform sha1 hash of content id. */
    hash = g_malloc0 (SHA_DIGEST_LENGTH);
    SHA1 ((const unsigned char *) kp->content_id, 47, hash);
    filename = gst_cenc_drm_stub_to_hexstring (hash, SHA_DIGEST_LENGTH);
    g_free (hash);
  } else {
    filename = g_strdup (kp->content_id);
  }
  kp->filename = g_strconcat ("/tmp/", filename, ".key", NULL);
  g_free (filename);
  return kp;
}


static void
gst_cenc_drm_stub_keypair_dispose (GstCencDRM * drm, GstCencKeyPair * kp)
{
  StubKeyPair *key_pair = (StubKeyPair *) kp;
  GST_DEBUG ("keypair_dispose %p %p", drm, kp);
  g_free (key_pair->content_id);
  key_pair->content_id = NULL;
  g_free (key_pair->filename);
  key_pair->filename = NULL;
  GST_CENC_DRM_CLASS (parent_class)->keypair_dispose (drm, kp);
}

static GstCencDrmStatus
gst_cenc_drm_stub_process_marlin_content_id_element (GstCencDRMStub * self,
    GstBuffer * data)
{
  GstCencDRMClass *klass = GST_CENC_DRM_GET_CLASS (self);
  GstBuffer *kid;
  StubKeyPair *kp;

  kid = gst_cenc_drm_stub_key_id_from_marlin_content_id (self, data);
  if (!kid) {
    GST_ERROR_OBJECT (self, "Failed to parse KID %" GST_PTR_FORMAT, data);
    return GST_DRM_ERROR_INVALID_MPD;
  }
  kp = gst_cenc_drm_stub_lookup_key (self, kid);
  if (!kp) {
    klass->add_kid (GST_CENC_DRM (self), kid);
  } else {
    gst_cenc_drm_keypair_unref ((GstCencKeyPair *) kp);
  }
  gst_buffer_unref (kid);
  return GST_DRM_OK;
}

static GstCencDrmStatus
gst_cenc_drm_stub_process_playready_pssh_element (GstCencDRMStub * self,
    GstBuffer * data)
{
  return gst_cenc_drm_parse_pssh_box (GST_CENC_DRM (self), data);
}

#define PRO_CHECK(a) {if (!(a)) { goto quit; } }

/* See https://docs.microsoft.com/en-us/playready/specifications/playready-header-specification */
static GstCencDrmStatus
gst_cenc_drm_stub_process_playready_pro_element (GstCencDRMStub * self,
    GstBuffer * data)
{
  GstMapInfo map;
  GstByteReader br;
  guint32 pro_length;
  guint16 i, num_records;

  gst_buffer_map (data, &map, GST_MAP_READ);
  gst_byte_reader_init (&br, map.data, map.size);
  PRO_CHECK (gst_byte_reader_get_uint32_le (&br, &pro_length));
  if (pro_length != map.size) {
    GST_ERROR_OBJECT (self, "Invalid mspr:pro size %u, expected %lu",
        pro_length, map.size);
    goto quit;
  }
  PRO_CHECK (gst_byte_reader_get_uint16_le (&br, &num_records));
  GST_DEBUG_OBJECT (self, "Found %d PlayReady records", num_records);
  for (i = 0; i < num_records; ++i) {
    guint16 record_type, record_length;
    const guint8 *record_value = NULL;
    PRO_CHECK (gst_byte_reader_get_uint16_le (&br, &record_type));
    PRO_CHECK (gst_byte_reader_get_uint16_le (&br, &record_length));
    GST_DEBUG_OBJECT (self, "Record 0x%04x length %d", record_type,
        record_length);
    if (record_length > 0) {
      PRO_CHECK (gst_byte_reader_get_data (&br, record_length, &record_value));
    }
    if (record_type == 1) {
      gchar *xml;
      xml =
          g_utf16_to_utf8 ((const gunichar2 *) record_value, record_length,
          NULL, NULL, NULL);
      GST_DEBUG_OBJECT (self, "%02x %02x PRO=%s", (guint8) xml[0],
          (guint8) xml[1], (const gchar *) xml);
      g_free (xml);
    }
  }
quit:
  gst_buffer_unmap (data, &map);

  /*  gst_cenc_drm_stub_add_base64url_key (self, "nrQFDeRLSAKTLifXUIPiZg",
     "FmY0xnWCPCNaSpRG-tUuTQ"); */

  return GST_DRM_OK;
  /*  return GST_DRM_ERROR_NOT_IMPLEMENTED; */
}

/* @data will contain the license URL */
static GstCencDrmStatus
gst_cenc_drm_stub_process_clearkey_laurl_element (GstCencDRMStub * self,
    GstBuffer * data)
{
  GstMapInfo map;

  if (!gst_buffer_map (data, &map, GST_MAP_READ)) {
    GST_ERROR_OBJECT (self, "Failed to map Laurl element");
    return GST_DRM_ERROR_OTHER;
  }
  if (self->la_url == NULL) {
    self->la_url = g_strdup ((gchar *) map.data);
  }
  gst_buffer_unmap (data, &map);
  return GST_DRM_OK;
}

static GstCencDrmStatus
gst_cenc_drm_stub_process_pssh_data (GstCencDRMStub * self, GstBuffer * data)
{
  if (self->parent.drm_type == GST_DRM_PLAYREADY) {
    return gst_cenc_drm_stub_process_playready_pro_element (self, data);
  }
  return GST_DRM_ERROR_NOT_IMPLEMENTED;
}
