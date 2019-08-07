/*
 * A base class for content protection (DRM) implementations
 * that can be used by the cencdec element.
 *
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

#ifndef __GST_CENC_DRM_H__
#define __GST_CENC_DRM_H__

#include <gst/gst.h>
#include "gstaesctr.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef GST_CENCDRM_API
# ifdef BUILDING_GST_CENCDRM
#  define GST_CENCDRM_API GST_API_EXPORT         /* from config.h */
# else
#  define GST_CENCDRM_API GST_API_IMPORT
# endif
#endif

G_BEGIN_DECLS
#define KID_LENGTH 16
#define KEY_LENGTH 16
#define SYSTEM_ID_LENGTH 16

#define MARLIN_MPD_PROTECTION_ID "5e629af5-38da-4063-8977-97ffbd9902d4"
#define MARLIN_PSSH_PROTECTION_ID "69f908af-4816-46ea-910c-cd5dcccb0a3a"
#define CLEARKEY_PROTECTION_ID "e2719d58-a985-b3c9-781a-b030af78d30e"
#define W3C_EME_PROTECTION_ID "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b"
#define PLAYREADY_PROTECTION_ID     "9a04f079-9840-4286-ab92-e65be0885f95"

#define GST_TYPE_CENC_DRM \
  (gst_cenc_drm_get_type())
#define GST_CENC_DRM(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_CENC_DRM,GstCencDRM))
#define GST_CENC_DRM_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_CENC_DRM,GstCencDRMClass))
#define GST_CENC_DRM_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS((obj),GST_TYPE_CENC_DRM,GstCencDRMClass))
#define GST_IS_CENC_DRM(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_CENC_DRM))
#define GST_IS_CENC_DRM_CLASS(obj) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_CENC_DRM))
#define GST_CENC_DRM_CAST(obj) ((GstCencDRM *)obj)

typedef struct _GstCencDRM GstCencDRM;

typedef enum
{
  GST_DRM_MARLIN,
  GST_DRM_CLEARKEY,
  GST_DRM_PLAYREADY,
  GST_DRM_UNKNOWN = -1
} GstCencDrmType;

typedef enum
{
  GST_DRM_OK                       = 0x0000,
  GST_DRM_NOT_FOUND                = 0x0001,
  GST_DRM_ERROR_NOT_IMPLEMENTED    = 0x1000,
  GST_DRM_ERROR_NO_LAURL           = 0x1001,
  GST_DRM_ERROR_MISSING_KEY        = 0x1002,
  GST_DRM_ERROR_INVALID_MPD        = 0x1003,
  GST_DRM_ERROR_INVALID_PSSH       = 0x1004,
  GST_DRM_ERROR_SERVER_CONNECTION  = 0x1005,
  GST_DRM_ERROR_SERVER_RESPONSE    = 0x1006,
  GST_DRM_ERROR_OTHER              = 0x1FFF,
} GstCencDrmStatus;

typedef enum
{
  GST_DRM_SKIP,
  GST_DRM_PROCESS_RAW,
  GST_DRM_PROCESS_BASE64,
  GST_DRM_PROCESS_HEX,
  GST_DRM_PROCESS_CHILDREN,
} GstCencDrmProcessing;

enum
{
  GST_DRM_IDENTIFIER_PSSH_PAYLOAD = 0x101,
  GST_DRM_IDENTIFIER_PRIVATE = 0x200,
};

typedef struct _GstCencDRMClass GstCencDRMClass;
typedef struct _GstCencKeyPair GstCencKeyPair;

struct _GstCencKeyPair
{
  GstCencDRM *owner;
  gint ref_count;
  GBytes *key_id;
  GBytes *key;
};

typedef struct _GstCencDRMClass
{
  GObjectClass parent_class;

  /**
   * should_process_node:
   * @drm: #GstCencDRM
   * @namespace: The URN of the XML namespace
   * @element: The name of the XML element
   * @identifier: (out) used to signal an ID that is used when configure
   *  is called
   *
   * should_process_node will be called for every XML element inside
   * a ContentProtection element. It is esed to check if an XML element
   * should be processed. If it is to be processed, this function
   * allows an ID to be provided that will be passed to a subsequent
   * call to configure()
   *
   * Returns: if this XML node should be processed or skipped
   */
    GstCencDrmProcessing (*should_process_node) (GstCencDRM *drm,
      const gchar * namespace, const gchar * element, guint * identifier);

  /**
   * configure:
   * @drm: #GstCencDRM
   * @identifier: identifier returned by should_process_node() or
   * GST_DRM_IDENTIFIER_PSSH_PAYLOAD if the data has some from a PSSH
   * box.
   * @data: DRM specific data
   * @default_kid: (allow none) the default KID, if known
   *
   * This function is used to provide DRM specific information that has
   * been extracted from the stream to be passed to the DRM instance.
   *
   * Returns: status of processing DRM data
   */
  GstCencDrmStatus (*configure) (GstCencDRM *drm, guint identifier,
      GstBuffer * data);

  /**
   * add_kid:
   * @drm: #GstCencDRM
   * @kid: The key ID
   *
   * Notifies the class extended from #GstCencDRM that the
   * key ID in @kid will be used.
   *
   * Returns: status of processing KID
   */
  GstCencDrmStatus (*add_kid)(GstCencDRM *, GstBuffer * kid);

  /**
   * create_decrypt:
   * @drm: #GstCencDRM
   * @kid: The key ID
   * @iv: The IV
   *
   * This function is used to produce an #AesCtrState object that has
   * been configured with the specified @kid and @iv.
   *
   * Returns: A new #AesCtrState or NULL if @kid not found
   */
  AesCtrState *(*create_decrypt) (GstCencDRM * drm, GstBuffer * kid,
      GBytes * iv);

  void (*keypair_dispose) (GstCencDRM *, GstCencKeyPair *);

} GstCencDRMClass;

struct _GstCencDRM
{
  GObject parent;

  GstCencDrmType drm_type;
  GstBuffer *system_id;
  gchar * default_kid;
};

GST_CENCDRM_API
GType gst_cenc_drm_get_type (void);

/**
 * gst_cenc_drm_factory:
 * @protection_event: a #GST_EVENT_PROTECTION event.
 *
 * Creates new #GstCencDRM object that supports
 * the DRM system specified by the content protection event.
 *
 * Returns: an #GstCencDRM object or NULL if DRM system is not supported
 * Use #g_object_unref to free.
 */
typedef GstCencDRM *(*gst_cenc_drm_factory) (GstEvent * protection_event);

GST_CENCDRM_API
GstCencDrmStatus gst_cenc_drm_process_content_protection_event (GstCencDRM *,
    GstEvent * event);

GST_CENCDRM_API
GstCencDrmStatus gst_cenc_drm_parse_pssh_box (GstCencDRM *, GstBuffer * pssh);

GST_CENCDRM_API
GstCencKeyPair *gst_cenc_drm_keypair_ref (GstCencKeyPair *);

GST_CENCDRM_API
void gst_cenc_drm_keypair_unref (GstCencKeyPair *);

GST_CENCDRM_API
GstBuffer* gst_cenc_drm_urn_string_to_raw(GstCencDRM * self, const gchar *urn);

GST_CENCDRM_API
GBytes * gst_cenc_drm_hex_decode (GstCencDRM * self, const gchar * encoded);

GST_CENCDRM_API
GBytes * gst_cenc_drm_base64_decode (GstCencDRM * self, const gchar * encoded);

GST_CENCDRM_API
gchar * gst_cenc_drm_base64url_encode (GstCencDRM * self, GBytes * data);

GST_CENCDRM_API
GBytes * gst_cenc_drm_base64url_decode (GstCencDRM * self, const gchar * data);

G_END_DECLS
#endif /* __GST_CENC_DRM_H__ */
