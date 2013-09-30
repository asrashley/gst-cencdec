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
#include <gst/isomp4/gstcenc.h>
#include <gst/gstaesctr.h>

#include "gstcencdec.h"

GST_DEBUG_CATEGORY_STATIC (gst_cenc_decrypt_debug_category);
#define GST_CAT_DEFAULT gst_cenc_decrypt_debug_category

enum CencDecryptContentType
{
	CTVideoElementaryStream,
	CTAudioElementaryStream
};

struct _GstCencDecrypt
{
  GstBaseTransform parent;
  enum CencDecryptContentType content_type;
  int iv_size; /* 8 or 16 */
};

struct _GstCencDecryptClass
{
  GstBaseTransformClass base_cenc_decrypt_class;
};

/* prototypes */
static void gst_cenc_decrypt_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);
static void gst_cenc_decrypt_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gst_cenc_decrypt_dispose (GObject * object);
static void gst_cenc_decrypt_finalize (GObject * object);

static gboolean gst_cenc_decrypt_start (GstBaseTransform * trans);
static gboolean gst_cenc_decrypt_stop (GstBaseTransform * trans);
static GstCaps* gst_cenc_decrypt_transform_caps (GstBaseTransform * base,
		GstPadDirection direction,
		GstCaps * caps, GstCaps * filter);
static GstCaps* gst_cenc_decrypt_fixate_caps (GstBaseTransform *base,
                                   GstPadDirection direction, GstCaps *caps,
                                   GstCaps *othercaps);
static GstCaps* gst_cenc_decrypt_create_src_caps(GstCencDecrypt* self);

static GstFlowReturn gst_cenc_decrypt_transform_ip (GstBaseTransform * trans, GstBuffer * buf);
static GstBuffer *gst_cenc_decrypt_lookup_key(GstCencDecrypt *self, const GBytes *kid);
static gboolean gst_cenc_decrypt_filter_meta(GstBaseTransform *trans, GstQuery *query, GType api, const GstStructure *params);

enum
{
  PROP_0
};

/* pad templates */

static GstStaticPadTemplate gst_cenc_decrypt_sink_template =
GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("video/x-cenc; audio/x-cenc")
    );

static GstStaticPadTemplate gst_cenc_decrypt_src_template =
GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("video/x-h264; audio/mpeg")
    );


/* class initialization */

G_DEFINE_TYPE (GstCencDecrypt, gst_cenc_decrypt, GST_TYPE_BASE_TRANSFORM);
#define parent_class gst_cenc_decrypt_parent_class

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
      "Decrypt MPEG-DASH encrypted content", "Codec/Parser/Converter",
      "Decrypts media that has been encrypted using ISO MPEG-DASH common "
      "encryption.",
      "Alex Ashley <alex.ashley@youview.com>");

  GST_DEBUG_CATEGORY_INIT (gst_cenc_decrypt_debug_category,
      "gst_cenc_decrypt", 0, "CENC decryptor");


  gobject_class->set_property = gst_cenc_decrypt_set_property;
  gobject_class->get_property = gst_cenc_decrypt_get_property;
  gobject_class->dispose = gst_cenc_decrypt_dispose;
  gobject_class->finalize = gst_cenc_decrypt_finalize;
  base_transform_class->start = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_start);
  base_transform_class->stop = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_stop);
  base_transform_class->transform_ip =
      GST_DEBUG_FUNCPTR (gst_cenc_decrypt_transform_ip);
  base_transform_class->transform_caps = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_transform_caps);
  base_transform_class->filter_meta = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_filter_meta);
}

static void
gst_cenc_decrypt_init (GstCencDecrypt * self)
{
  GstBaseTransform *base = GST_BASE_TRANSFORM (self);

  gst_base_transform_set_in_place(base, TRUE);
  gst_base_transform_set_passthrough(base, FALSE);
  self->content_type = CTVideoElementaryStream;
  self->iv_size=0;
}

void
gst_cenc_decrypt_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (object);

  switch (property_id) {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

void
gst_cenc_decrypt_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (object);

  switch (property_id) {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

void
gst_cenc_decrypt_dispose (GObject * object)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (object);

  /* clean up as possible.  might be called multiple times */

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
		GstPadDirection direction,
		GstCaps * caps, GstCaps * filter)
{
  GstCencDecrypt* self = GST_CENC_DECRYPT(base);
  GstCaps *res;
  GstStructure *structure;
  gint i;

  if (direction == GST_PAD_SRC) {
        GST_DEBUG_OBJECT (base, "Src caps: %" GST_PTR_FORMAT, caps);
        res = gst_static_pad_template_get_caps (&gst_cenc_decrypt_sink_template);
  }
  else{
        GST_DEBUG_OBJECT (base, "Sink caps: %" GST_PTR_FORMAT, caps);
        res = gst_cenc_decrypt_create_src_caps(self);
  }
  GST_DEBUG_OBJECT (base, "transformed caps %" GST_PTR_FORMAT, res);

  if (filter) {
    GstCaps *intersection;

    GST_DEBUG_OBJECT (base, "Using filter caps %" GST_PTR_FORMAT, filter);
    intersection =
          gst_caps_intersect_full (filter, res, GST_CAPS_INTERSECT_FIRST);
    gst_caps_unref (res);
    res = intersection;
    GST_DEBUG_OBJECT (base, "Intersection %" GST_PTR_FORMAT, res);
  }

  return res;
}

static GstCaps* gst_cenc_decrypt_fixate_caps (GstBaseTransform *base,
                                   GstPadDirection direction, GstCaps *caps,
                                   GstCaps *othercaps)
{
  GstCencDecrypt* self = GST_CENC_DECRYPT(base);
  GstStructure* structure = gst_caps_get_structure( caps, 0 );

  GST_DEBUG_OBJECT (self, "trying to fixate othercaps %" GST_PTR_FORMAT
		    " based on caps %" GST_PTR_FORMAT, othercaps, caps);

  if( gst_structure_has_name (structure, "original-caps") ){
  }
}

static GstBuffer *
gst_cenc_decrypt_lookup_key(GstCencDecrypt *self, const GBytes *kid)
{
  gsize length=0;
  const unsigned char *kbytes = g_bytes_get_data((GBytes*)kid,&length);
  g_assert(length==16);
  GstBuffer *key = gst_buffer_new_allocate (NULL,16,NULL);
  if(key){
    gst_buffer_fill (key, 0, kbytes, 16);
  }
  else{
    GST_ERROR_OBJECT (self,"Failed to allocate buffer for key");
  }
  return key;
}


static GstFlowReturn
gst_cenc_decrypt_transform_ip (GstBaseTransform * base, GstBuffer * buf)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (base);
  GstFlowReturn ret = GST_FLOW_OK;
  GstMapInfo map;
  GstBuffer *wbuf=NULL;
  GstBuffer *key=NULL;
  const GstCencMeta *sample_info=NULL;
  int pos=0;
  int sample_index=0;
  AesCtrState *state=NULL;

  GST_DEBUG_OBJECT (self, "decrypt in-place");
  sample_info = gst_buffer_get_cenc_meta(buf);
  wbuf = gst_buffer_make_writable(buf);
  if(!sample_info || !wbuf){
    if(!sample_info){
      GST_ERROR_OBJECT (self, "Failed to get sample_info metadata from buffer");
    }
    if(!wbuf){
      GST_ERROR_OBJECT (self, "Failed to get writable buffer");
    }
    ret = GST_FLOW_NOT_SUPPORTED;
    goto out;
  }  
  //TODO: change to use map_range
  if (!gst_buffer_map (wbuf, &map, GST_MAP_READWRITE)) {
    GST_ERROR_OBJECT (self,"Failed to map buffer");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  if(sample_info->properties.iv_size==0 || !sample_info->properties.is_encrypted){
    /* sample is not encrypted */
    goto beach;
  }
  key = gst_cenc_decrypt_lookup_key(self, sample_info->properties.key_id);
  if(!key){
    GST_ERROR_OBJECT (self, "Failed to lookup key");
    GST_MEMDUMP_OBJECT (self, "Key ID:", g_bytes_get_data(sample_info->properties.key_id,NULL), 16);
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  state = gst_aes_ctr_decrypt_new(key, sample_info->crypto_info.iv);
  if(!state){
    GST_ERROR_OBJECT (self, "Failed to init AES cipher");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  gst_buffer_unref(key);
    
  while(pos<map.size){
    CencSubsampleInfo remainder = { 0, map.size-pos };
    CencSubsampleInfo *run;
    if(sample_index<sample_info->crypto_info.n_subsamples){
      run = &g_array_index(sample_info->crypto_info.subsample_info,
			  CencSubsampleInfo,
			  sample_index);
      sample_index++;
    }
    else{
      run = &remainder;
    }
    GST_TRACE_OBJECT (self, "%d bytes clear", run->n_bytes_clear);
    pos += run->n_bytes_clear;
    if(run->n_bytes_encrypted){
      GST_TRACE_OBJECT (self, "%d bytes encrypted", run->n_bytes_encrypted);
      gst_aes_ctr_decrypt_ip(state, map.data+pos, run->n_bytes_encrypted);
      pos += run->n_bytes_encrypted;
    }
  }

beach:
  gst_buffer_unmap (wbuf, &map);
  if(state){
    gst_aes_ctr_decrypt_unref(state);
  }
release:
  if(wbuf){
    gst_buffer_unref(wbuf);
  }
out:
  return ret;
}

static GstCaps*
gst_cenc_decrypt_create_src_caps(GstCencDecrypt* self)
{
  GstCaps *new_caps;
  if(self->content_type==CTAudioElementaryStream){
	  new_caps = gst_caps_new_simple (
			  "audio/mpeg",
			  "mpegversion", G_TYPE_INT, 4,
			  NULL);
  }
  else{
        new_caps = gst_caps_new_simple (
        		"video/x-h264",
        		"alignment", G_TYPE_STRING, "au",
        		NULL);
  }
  return new_caps;
}

static gboolean
gst_cenc_decrypt_filter_meta(GstBaseTransform *trans, 
			     GstQuery *query,
			     GType api, 
			     const GstStructure *params)
{
  /* propose all metadata */
  return TRUE;
}

