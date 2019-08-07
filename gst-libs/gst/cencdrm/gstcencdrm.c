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

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/evp.h>

#include "gstcencdrm.h"

GST_DEBUG_CATEGORY_STATIC (gst_cenc_drm_debug_category);
#define GST_CAT_DEFAULT gst_cenc_drm_debug_category


#define gst_cenc_drm_parent_class parent_class

#define DASH_CENC_XML_NS ((const xmlChar *) "urn:mpeg:cenc:2013")
#define DEFAULT_KID_NODE ((const xmlChar *) "default_KID")

/*static void gst_cenc_keypair_dispose (GObject * object);*/
/*static void gst_cenc_keypair_finalize (GObject * object); */

static void gst_cenc_drm_dispose (GObject * object);
static void gst_cenc_drm_finalize (GObject * object);
static void gst_cenc_drm_clear (GstCencDRM * self);

static GstCencDrmProcessing gst_cenc_drm_should_process_node (GstCencDRM * self,
    const gchar * namespace, const gchar * element, guint * identifier);
static GstCencDrmStatus gst_cenc_drm_configure (GstCencDRM *,
    guint identifier, GstBuffer * data);
static GstCencDrmStatus gst_cenc_drm_add_kid (GstCencDRM *, GstBuffer * kid);
static GstCencDrmStatus
gst_cenc_drm_parse_content_protection_xml_element (GstCencDRM *,
    const gchar * system_id, GstBuffer * pssi);
static void gst_cenc_drm_keypair_dispose (GstCencDRM *, GstCencKeyPair *);

G_DEFINE_TYPE (GstCencDRM, gst_cenc_drm, G_TYPE_OBJECT);

static void
gst_cenc_drm_class_init (GstCencDRMClass * klass)
{
  GObjectClass *object = G_OBJECT_CLASS (klass);

  object->dispose = gst_cenc_drm_dispose;
  object->finalize = gst_cenc_drm_finalize;
  klass->should_process_node = gst_cenc_drm_should_process_node;
  klass->configure = gst_cenc_drm_configure;
  klass->add_kid = gst_cenc_drm_add_kid;
  klass->keypair_dispose = gst_cenc_drm_keypair_dispose;

  GST_DEBUG_CATEGORY_INIT (gst_cenc_drm_debug_category, "cencdrm", 0,
      "DASH CENC library");
}

static void
gst_cenc_drm_init (GstCencDRM * self)
{
  /*  g_rec_mutex_init (&self->test_task_lock);
     g_mutex_init (&self->test_task_state_lock);
     g_cond_init (&self->test_task_state_cond); */
  gst_cenc_drm_clear (self);
}

static void
gst_cenc_drm_clear (GstCencDRM * self)
{
  self->drm_type = GST_DRM_UNKNOWN;
  if (self->system_id) {
    gst_buffer_unref (self->system_id);
    self->system_id = NULL;
  }
  g_free (self->default_kid);
  self->default_kid = NULL;
}

static void
gst_cenc_drm_dispose (GObject * object)
{
  GstCencDRM *self = GST_CENC_DRM (object);

  gst_cenc_drm_clear (self);

  GST_CALL_PARENT (G_OBJECT_CLASS, dispose, (object));
}

static void
gst_cenc_drm_finalize (GObject * object)
{
  /*  GstCencDRM *self = GST_CENC_DRM (object); */

  GST_CALL_PARENT (G_OBJECT_CLASS, finalize, (object));
}

static void
gst_cenc_drm_hexdump_raw (GstCencDRM * self, const char *name,
    const guint8 * data, const gsize size)
{
  gsize i;

  if (data == NULL) {
    GST_DEBUG_OBJECT (self, "%s: NULL", name);
    return;
  }
  GST_DEBUG_OBJECT (self, "%s: length=%lu", name, size);

  for (i = 0; i < size; i++) {
    if ((i & 0x1f) == 0) {
      g_print ("%04lx: ", i);
    }
    g_print ("%02x ", data[i]);
    if ((i & 0x1f) == 0x1f) {
      g_print ("\n");
    }
  }
  g_print ("\n");
}

static void
gst_cenc_drm_hexdump_buffer (GstCencDRM * self, const char *name,
    GstBuffer * buffer)
{
  GstMapInfo info;

  if (buffer == NULL) {
    GST_DEBUG_OBJECT (self, "%s: NULL", name);
    return;
  }
  gst_buffer_map (buffer, &info, GST_MAP_READ);
  gst_cenc_drm_hexdump_raw (self, name, info.data, info.size);
  gst_buffer_unmap (buffer, &info);
}

static GstCencDrmProcessing
gst_cenc_drm_should_process_node (GstCencDRM * self,
    const gchar * namespace, const gchar * element, guint * identifier)
{
  return GST_DRM_SKIP;
}

static GstCencDrmStatus
gst_cenc_drm_configure (GstCencDRM * self, guint identifier, GstBuffer * data)
{
  return GST_DRM_ERROR_NOT_IMPLEMENTED;
}

static GstCencDrmStatus
gst_cenc_drm_add_kid (GstCencDRM * self, GstBuffer * kid)
{
  return GST_DRM_ERROR_NOT_IMPLEMENTED;
}

GstCencDrmStatus
gst_cenc_drm_process_content_protection_event (GstCencDRM * self,
    GstEvent * event)
{
  const gchar *system_id = NULL;
  GstBuffer *pssi = NULL;
  const gchar *loc = NULL;
  GstCencDrmStatus ret = GST_DRM_ERROR_OTHER;

  GST_DEBUG ("protection event %" GST_PTR_FORMAT, event);
  gst_event_parse_protection (event, &system_id, &pssi, &loc);
  if (g_ascii_strcasecmp (loc, "dash/mpd") == 0) {
    ret =
        gst_cenc_drm_parse_content_protection_xml_element (self, system_id,
        pssi);
  } else if (g_str_has_prefix (loc, "isobmff/")) {
    ret = gst_cenc_drm_parse_pssh_box (self, pssi);
  }
  return ret;
}

static GstBuffer *
gst_cenc_drm_buffer_from_raw_node (GstCencDRM * self, xmlNode * node)
{
  GBytes *bytes;
  GstBuffer *buf = NULL;
  xmlChar *node_content;

  node_content = xmlNodeGetContent (node);
  if (node_content) {
    bytes =
        g_bytes_new (node_content,
        (gsize) strlen ((const char *) node_content));
    buf = gst_buffer_new_wrapped_bytes (bytes);
    g_bytes_unref (bytes);
    xmlFree (node_content);
  }
  return buf;
}

static GstBuffer *
gst_cenc_drm_buffer_from_base64_node (GstCencDRM * self, xmlNode * node)
{
  GBytes *bytes = NULL;
  GstBuffer *buf = NULL;
  xmlChar *node_content;

  node_content = xmlNodeGetContent (node);
  if (!node_content) {
    return NULL;
  }
  bytes = gst_cenc_drm_base64_decode (self, (const gchar *) node_content);
  xmlFree (node_content);
  if (bytes) {
    buf = gst_buffer_new_wrapped_bytes (bytes);
    g_bytes_unref (bytes);
  }
  return buf;
}

static GstBuffer *
gst_cenc_drm_buffer_from_hex_node (GstCencDRM * self, xmlNode * node)
{
  GBytes *bytes = NULL;
  GstBuffer *buf = NULL;
  xmlChar *node_content;

  node_content = xmlNodeGetContent (node);
  if (!node_content) {
    return NULL;
  }
  bytes = gst_cenc_drm_hex_decode (self, (const gchar *) node_content);
  xmlFree (node_content);
  if (bytes) {
    buf = gst_buffer_new_wrapped_bytes (bytes);
    g_bytes_unref (bytes);
  }
  return buf;
}

static GstCencDrmStatus
gst_cenc_drm_walk_xml_nodes (GstCencDRM * self, xmlNode * root)
{
  GstCencDRMClass *klass = GST_CENC_DRM_GET_CLASS (self);
  xmlNode *node;
  GstCencDrmStatus ret = GST_DRM_NOT_FOUND;
  gboolean done = FALSE;

  /* Walk child elements  */
  for (node = root->children; node && !done; node = node->next) {
    guint identifier = 0;
    GstCencDrmProcessing processing;
    GstBuffer *buf = NULL;

    if (node->type != XML_ELEMENT_NODE)
      continue;

    processing = klass->should_process_node (self,
        (const gchar *) node->ns->href,
        (const gchar *) node->name, &identifier);

    switch (processing) {
      case GST_DRM_SKIP:
        break;
      case GST_DRM_PROCESS_RAW:
        buf = gst_cenc_drm_buffer_from_raw_node (self, node);
        if (buf) {
          ret = klass->configure (self, identifier, buf);
          done = TRUE;
        }
        break;
      case GST_DRM_PROCESS_BASE64:
        buf = gst_cenc_drm_buffer_from_base64_node (self, node);
        if (buf) {
          ret = klass->configure (self, identifier, buf);
          done = TRUE;
        }
        break;
      case GST_DRM_PROCESS_HEX:
        buf = gst_cenc_drm_buffer_from_hex_node (self, node);
        if (buf) {
          ret = klass->configure (self, identifier, buf);
          done = TRUE;
        }
        break;
      case GST_DRM_PROCESS_CHILDREN:
        ret = gst_cenc_drm_walk_xml_nodes (self, node);
        done = TRUE;
        break;
    }
    if (buf) {
      gst_buffer_unref (buf);
    }
  }
  return ret;
}


static GstCencDrmStatus
gst_cenc_drm_parse_content_protection_xml_element (GstCencDRM * self,
    const gchar * system_id, GstBuffer * pssi)
{
  GstMapInfo info;
  /*  guint32 data_size; */
  xmlDocPtr doc;
  xmlNode *root_element = NULL;
  GstCencDrmStatus ret = GST_DRM_NOT_FOUND;
  /*   xmlNode *node; */
  xmlChar *default_kid = NULL;
  /* int i; */

  gst_buffer_map (pssi, &info, GST_MAP_READ);

  /* this initialize the library and check potential ABI mismatches
   * between the version it was compiled for and the actual shared
   * library used
   */
  LIBXML_TEST_VERSION;

  GST_DEBUG ("XML = %s", info.data);

  doc =
      xmlReadMemory ((const char *) info.data, info.size,
      "ContentProtection.xml", NULL, XML_PARSE_NONET);
  if (!doc) {
    ret = GST_DRM_ERROR_INVALID_MPD;
    GST_ERROR_OBJECT (self,
        "Failed to parse XML from content protection event");
    goto beach;
  }
  root_element = xmlDocGetRootElement (doc);

  if (root_element->type != XML_ELEMENT_NODE
      || xmlStrcmp (root_element->name, (xmlChar *) "ContentProtection") != 0) {
    GST_ERROR_OBJECT (self, "Failed to find ContentProtection element");
    ret = GST_DRM_ERROR_INVALID_MPD;
    goto beach;
  }
  default_kid = xmlGetNsProp (root_element, DEFAULT_KID_NODE, DASH_CENC_XML_NS);
  GST_DEBUG_OBJECT (self, "Default kid: %s",
      default_kid ? (const gchar *) default_kid : "NULL");
  if (default_kid && !self->default_kid) {
    self->default_kid = g_strdup ((const gchar *) default_kid);
  }

  ret = gst_cenc_drm_walk_xml_nodes (self, root_element);

beach:
  if (default_kid)
    xmlFree (default_kid);
  if (doc)
    xmlFreeDoc (doc);
  gst_buffer_unmap (pssi, &info);
  return ret;
}

#define PSSH_CHECK(a) {if (!(a)) { ret=GST_DRM_ERROR_INVALID_PSSH; goto beach; } }

GstCencDrmStatus
gst_cenc_drm_parse_pssh_box (GstCencDRM * self, GstBuffer * pssh)
{
  GstCencDRMClass *klass = GST_CENC_DRM_GET_CLASS (self);
  GstMapInfo info;
  GstByteReader br;
  guint8 version;
  guint32 pssh_length;
  guint32 data_size;
  GstCencDrmStatus ret = GST_DRM_OK;
  const guint8 *system_id;

  gst_buffer_map (pssh, &info, GST_MAP_READ);
  gst_byte_reader_init (&br, info.data, info.size);

  PSSH_CHECK (gst_byte_reader_get_uint32_be (&br, &pssh_length));
  if (pssh_length != info.size) {
    GST_WARNING_OBJECT (self, "Invalid PSSH length. Expected %lu got %u",
        info.size, pssh_length);
    goto beach;

  }
  gst_byte_reader_skip_unchecked (&br, 4);      /* 'PSSH' */
  PSSH_CHECK (gst_byte_reader_get_uint8 (&br, &version));
  GST_DEBUG_OBJECT (self, "pssh version: %u", version);
  gst_byte_reader_skip_unchecked (&br, 3);      /* FullBox flags */
  PSSH_CHECK (gst_byte_reader_get_data (&br, SYSTEM_ID_LENGTH, &system_id));

  if (gst_buffer_memcmp (self->system_id, 0, system_id, SYSTEM_ID_LENGTH) != 0) {
    GST_DEBUG_OBJECT (self, "Skipping PSSH as not for this DRM system");
    gst_cenc_drm_hexdump_raw (self, "got system_id", system_id,
        SYSTEM_ID_LENGTH);
    gst_cenc_drm_hexdump_buffer (self, "self->system_id", self->system_id);
    ret = GST_DRM_OK;
    goto beach;
  }
  if (version > 0) {
    /* Parse KeyIDs */
    guint32 kid_count = 0;

    PSSH_CHECK (gst_byte_reader_get_uint32_be (&br, &kid_count));
    GST_DEBUG_OBJECT (self, "there are %u key IDs", kid_count);
    if (gst_byte_reader_get_remaining (&br) < KID_LENGTH * kid_count) {
      ret = GST_DRM_ERROR_INVALID_PSSH;
      goto beach;
    }
    while (kid_count > 0) {
      GBytes *kid_bytes;
      GstBuffer *kid_buf;

      kid_bytes =
          g_bytes_new (gst_byte_reader_get_data_unchecked (&br, KID_LENGTH),
          KID_LENGTH);
      kid_buf = gst_buffer_new_wrapped_bytes (kid_bytes);
      klass->add_kid (self, kid_buf);
      gst_buffer_unref (kid_buf);
      g_bytes_unref (kid_bytes);
      --kid_count;
    }
  }

  /* Parse Data */
  PSSH_CHECK (gst_byte_reader_get_uint32_be (&br, &data_size));
  GST_DEBUG_OBJECT (self, "pssh data size: %u", data_size);

  if (data_size > 0U) {
    GBytes *bytes;
    GstBuffer *buffer;

    GST_DEBUG_OBJECT (self, "cenc protection system data size: %u", data_size);
    bytes = g_bytes_new (gst_byte_reader_get_data_unchecked (&br, data_size),
        data_size);
    buffer = gst_buffer_new_wrapped_bytes (bytes);
    ret = klass->configure (self, GST_DRM_IDENTIFIER_PSSH_PAYLOAD, buffer);
    gst_buffer_unref (buffer);
    g_bytes_unref (bytes);
  }
beach:
  gst_buffer_unmap (pssh, &info);
  return ret;
}


GstCencKeyPair *
gst_cenc_drm_keypair_ref (GstCencKeyPair * kp)
{
  kp->ref_count++;
  return kp;
}

void
gst_cenc_drm_keypair_unref (GstCencKeyPair * kp)
{
  g_return_if_fail (kp != NULL);
  kp->ref_count--;
  if (kp->ref_count == 0) {
    if (kp->owner) {
      GST_CENC_DRM_GET_CLASS (kp->owner)->keypair_dispose (kp->owner, kp);
    } else {
      g_free (kp);
    }
  }
}

static void
gst_cenc_drm_keypair_dispose (GstCencDRM * self, GstCencKeyPair * key_pair)
{
  if (key_pair->key_id) {
    g_bytes_unref (key_pair->key_id);
  }
  if (key_pair->key) {
    g_bytes_unref (key_pair->key);
  }
  g_free (key_pair);
}

GBytes *
gst_cenc_drm_hex_decode (GstCencDRM * self, const gchar * encoded)
{
  gint a;
  size_t i, len;
  gchar *decoded;
  guint pos = 0;

  g_return_val_if_fail (encoded != NULL, NULL);

  if ((len = strlen (encoded)) & 1) {
    GST_ERROR_OBJECT (self,
        "A hex string should have an even number of characters");
    return NULL;
  }

  decoded = (gchar *) g_malloc (len >> 1);
  for (i = 0; i < len; i++) {
    a = g_ascii_xdigit_value (encoded[i]);
    if (a < 0) {
      break;
    }
    if (i & 1) {
      decoded[pos] |= a;
      pos++;
    } else {
      decoded[pos] = a << 4;
    }
  }
  if (i < len) {
    free (decoded);
    GST_ERROR_OBJECT (self, "Failed to parse hex string at position %ld", i);
    return NULL;
  }
  return g_bytes_new_take (decoded, len);
}

GBytes *
gst_cenc_drm_base64_decode (GstCencDRM * self, const gchar * encoded)
{
  gsize decoded_len = 0;
  guchar *decoded;

  decoded = g_base64_decode (encoded, &decoded_len);
  if (decoded == NULL) {
    GST_ERROR_OBJECT (self, "Failed base64 decode");
    return NULL;
  }

  return g_bytes_new_take (decoded, decoded_len);
}

/**
 * gst_cenc_drm_base64url_encode:
 * @data the data to encode
 *
 * Returns: a base64url encoded string
 */
gchar *
gst_cenc_drm_base64url_encode (GstCencDRM * self, GBytes * bytes)
{
  guint j, blen;
  gchar *encoded;
  const guint8 *data;
  gsize data_size;

  data = g_bytes_get_data (bytes, &data_size);
  if (!data || data_size == 0) {
    return NULL;
  }
  encoded = g_base64_encode (data, data_size);
  blen = strlen (encoded);
  for (j = 0; j < blen; ++j) {
    if (encoded[j] == '+') {
      encoded[j] = '-';
    } else if (encoded[j] == '/') {
      encoded[j] = '_';
    } else if (encoded[j] == '=') {
      encoded[j] = '\0';
    }
  }
  return encoded;
}

GBytes *
gst_cenc_drm_base64url_decode (GstCencDRM * self, const gchar * data)
{
  gchar *tmp;
  /*  guchar *decoded; */
  gsize decoded_len = 0;
  guint data_size;
  guint padding;
  guint i;

  data_size = strlen (data);
  tmp = g_malloc (data_size + 3);
  memcpy (tmp, data, data_size + 1);
  for (i = 0; i < data_size; ++i) {
    if (tmp[i] == '-') {
      tmp[i] = '+';
    } else if (tmp[i] == '_') {
      tmp[i] = '/';
    }
  }
  padding = data_size % 4;
  if (padding == 2) {
    tmp[data_size] = '=';
    tmp[data_size + 1] = '=';
    tmp[data_size + 2] = '\0';
  } else if (padding == 3) {
    tmp[data_size] = '=';
    tmp[data_size + 1] = '\0';
  }
  /* tmp is now a valid base64 string */
  g_base64_decode_inplace (tmp, &decoded_len);
  GST_DEBUG_OBJECT (self, "Decoded base64url to %lu bytes", decoded_len);
  return g_bytes_new_take (tmp, decoded_len);
}


GstBuffer *
gst_cenc_drm_urn_string_to_raw (GstCencDRM * self, const gchar * urn)
{
  const gchar prefix[] = "urn:uuid:";
  GstBuffer *rv;
  GstMapInfo map;
  gboolean failed = FALSE;
  guint i, pos = 0, length;

  GST_DEBUG_OBJECT (self, "URN: %s", urn);
  if (g_ascii_strncasecmp (prefix, urn, sizeof (prefix)) == 0) {
    pos = sizeof (prefix);
  }
  length = strlen (urn);
  rv = gst_buffer_new_allocate (NULL, SYSTEM_ID_LENGTH, NULL);
  if (!gst_buffer_map (rv, &map, GST_MAP_WRITE)) {
    gst_buffer_unref (rv);
    GST_ERROR_OBJECT (self, "Failed to map buffer");
    return NULL;
  }
  for (i = 0; i < SYSTEM_ID_LENGTH && pos < length; ++i) {
    if (urn[pos] == '-') {
      pos++;
    }
    if ((pos + 1) >= length) {
      GST_DEBUG_OBJECT (self, "pos %u > length %u", pos, length);
      failed = TRUE;
      break;
    }
    if (!g_ascii_isxdigit (urn[pos]) || !g_ascii_isxdigit (urn[pos + 1])) {
      GST_DEBUG_OBJECT (self, "%d Not hex %c %c", pos, urn[pos], urn[pos + 1]);
      failed = TRUE;
      break;
    }
    map.data[i] = (g_ascii_xdigit_value (urn[pos]) << 4) +
        g_ascii_xdigit_value (urn[pos + 1]);
    pos += 2;
  }
  gst_buffer_unmap (rv, &map);
  if (failed) {
    gst_buffer_unref (rv);
    rv = NULL;
  }
  gst_cenc_drm_hexdump_buffer (self, "decoded URN", rv);
  return rv;
}
