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
  GstBuffer *key;
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

static GstFlowReturn gst_cenc_decrypt_transform_ip (GstBaseTransform * trans, GstBuffer * buf);
static GstBuffer *gst_cenc_decrypt_lookup_key(GstCencDecrypt *self, const GBytes *kid);
static gboolean gst_cenc_decrypt_search_mimetype(GQuark field_id,
						 const GValue *value,
						 gpointer user_data);

enum
{
  PROP_0, PROP_KEY
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
			   "cencdec", 0, "CENC decryptor");

  gobject_class->set_property = gst_cenc_decrypt_set_property;
  gobject_class->get_property = gst_cenc_decrypt_get_property;
  gobject_class->dispose = gst_cenc_decrypt_dispose;
  gobject_class->finalize = gst_cenc_decrypt_finalize;
  base_transform_class->start = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_start);
  base_transform_class->stop = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_stop);
  base_transform_class->transform_ip =
      GST_DEBUG_FUNCPTR (gst_cenc_decrypt_transform_ip);
  base_transform_class->transform_caps = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_transform_caps);
  base_transform_class->fixate_caps = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_fixate_caps);
  //base_transform_class->filter_meta = GST_DEBUG_FUNCPTR (gst_cenc_decrypt_filter_meta);

  g_object_class_install_property( gobject_class, PROP_KEY,
				   g_param_spec_string( "key", 
							"KEY", 
							"The hex key to use for decryption",
							"",
							G_PARAM_READWRITE) );
  base_transform_class->transform_ip_on_passthrough = FALSE;
}

static void
gst_cenc_decrypt_init (GstCencDecrypt * self)
{
  GstBaseTransform *base = GST_BASE_TRANSFORM (self);

  gst_base_transform_set_in_place(base, TRUE);
  gst_base_transform_set_passthrough(base, FALSE);
  gst_base_transform_set_gap_aware (GST_BASE_TRANSFORM (self), FALSE);

  self->content_type = CTVideoElementaryStream;
  self->iv_size=0;
  self->key=NULL;
}

void
gst_cenc_decrypt_set_property (GObject * object,
			       guint property_id,
			       const GValue * value, 
			       GParamSpec * pspec)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (object);

  switch (property_id) {
  case PROP_KEY: {
    GstBuffer *key;
    GstMapInfo info;
    int i, len;
    const gchar* keyString = g_value_get_string( value );
    char hex[3] = { '0','0',0 };

    if(!keyString){
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      return;
    }
    len = strlen(keyString);
    if(len!=32){ 
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      return;
    }
    key = gst_buffer_new_allocate (NULL,16,NULL);
    if(key){
      gst_buffer_map (key, &info, GST_MAP_WRITE);
      for(i=0; i<16; ++i){
	if (!isxdigit ((int) keyString[i * 2]) || !isxdigit ((int) keyString[i * 2 + 1])) {
	  gst_buffer_unmap(key,&info);
	  gst_buffer_unref (key);
	  G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
	  return;
	}
	hex[0] = keyString[i * 2 + 0];
	hex[1] = keyString[i * 2 + 1];
	info.data[i] = (guint8) strtoul (hex, NULL, 16);
      }
      gst_buffer_unmap(key,&info);
      self->key = key;
    }
  }
    break;
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
  case PROP_KEY: 
    if(self->key){
      GString *keyString = g_string_sized_new(33);
      GstMapInfo info;
      int i;
      for(i=0; i<16; ++i){
	g_string_append_printf(keyString,"%0x2",info.data[i]);
      }
      g_value_take_string(value, g_string_free(keyString,FALSE));
    }
    break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

void
gst_cenc_decrypt_dispose (GObject * object)
{
  GstCencDecrypt *self = GST_CENC_DECRYPT (object);

  if(self->key){
    gst_buffer_unref(self->key);
    self->key=NULL;
  }
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
  static const char *vid_mime_type="video/x-cenc";
  static const char *aud_mime_type="audio/x-cenc";
  GstCencDecrypt* self = GST_CENC_DECRYPT(base);
  GstCaps *res=NULL;
  gint i;
  GstStructure *structure;

  GST_DEBUG_OBJECT (base, "%s caps: %" GST_PTR_FORMAT, 
		    (direction == GST_PAD_SRC)?"Src":"Sink",
		    caps);

  res = gst_caps_new_empty();
  for(i=0; i<gst_caps_get_size(caps); ++i){
    structure = gst_caps_get_structure( caps, i);
    g_assert(structure!=NULL);

    if (direction == GST_PAD_SRC) {
      const char *src_mime_type;
      const char *sink_mime_type;
      GstStructure *sink_structure;
      GstCaps *src_cap;

      src_mime_type = gst_structure_get_name(structure);
      if(src_mime_type && strncasecmp("video/",src_mime_type,6)==0){
	sink_mime_type = vid_mime_type;
      }
      else{
	sink_mime_type = aud_mime_type;
      }
      src_cap = gst_caps_new_full(gst_structure_copy(structure),NULL);

      sink_structure = gst_structure_new_empty(sink_mime_type);

      /* Can't use original-caps, because that causes caps_can_intersect
	 to fail to find a src->sink match.
	sink_structure = gst_structure_new(sink_mime_type,
					 "original-caps", 
					 GST_TYPE_CAPS, 
					 src_cap,
					 NULL); */
      gst_caps_append_structure(res,sink_structure);
    }
    else{ /* direction==SINK */
      GstCaps *src_cap=NULL;
      if(gst_structure_get(structure,"original-caps",GST_TYPE_CAPS,&src_cap,
			   NULL)){
	src_cap = gst_caps_copy(src_cap);
      }
      else{
	if( gst_structure_has_name (structure, "video/x-cenc") ){
	  src_cap = gst_caps_new_simple (
					 "video/x-h264",
					 "alignment", G_TYPE_STRING, "au",
					 NULL);
	}
	else{
	  src_cap = gst_caps_new_simple (
					 "audio/mpeg",
					 "mpegversion", G_TYPE_INT, 4,
					 NULL);
	}
      }
      if(src_cap){
	gst_caps_append(res,src_cap);
	//gst_caps_unref(src_cap);
      }
    }
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

static gboolean
gst_cenc_decrypt_search_mimetype(GQuark field_id,
				 const GValue *value,
				 gpointer user_data)
{
  const gchar *field_name = g_quark_to_string(field_id);
  GString *dest = (GString*)user_data;

  GST_DEBUG ("field_name = %s",field_name);
  if(field_name && strncasecmp("video/",field_name,6)==0){
    g_string_append(dest,"video/x-cenc");
  }
  else if(field_name && strncasecmp("audio/",field_name,6)==0){
    g_string_append(dest,"audio/x-cenc");
  }
  return TRUE;
}

static GstCaps* gst_cenc_decrypt_fixate_caps (GstBaseTransform *base,
					      GstPadDirection direction, 
					      GstCaps *caps,
					      GstCaps *other)
{
  GstCencDecrypt* self = GST_CENC_DECRYPT(base);
  GstStructure* structure = gst_caps_get_structure( caps, 0 );
  guint i;
  GstCaps *origCaps=NULL;
  GstCaps *othercaps;

  GST_DEBUG_OBJECT (self, "trying to fixate othercaps %" GST_PTR_FORMAT
		    " based on caps %" GST_PTR_FORMAT, other, caps);

  othercaps = gst_caps_make_writable (other);

    /*if(self->content_type==CTAudioElementaryStream){ */

  if (direction == GST_PAD_SRC) {
    GString *mime_type = g_string_new("");
    gst_structure_foreach(structure,gst_cenc_decrypt_search_mimetype,&mime_type);
    othercaps = gst_caps_new_simple (mime_type->str,
				     /*"protection-system-id", G_TYPE_STRING,
				     qtdemux->cenc_system_id,
				     "protection-system-data", GST_TYPE_BUFFER,
				     qtdemux->cenc_system_data,*/
				     "original-caps", GST_TYPE_CAPS, caps, NULL);

    g_string_free(mime_type,TRUE);
  }
  else{
    if(gst_structure_get(structure,"original-caps",GST_TYPE_CAPS,&origCaps,NULL)){
      gst_caps_replace(&othercaps,origCaps);
      gst_caps_unref(origCaps);
    }
  }
  //othercaps = gst_caps_fixate(othercaps);
  GST_DEBUG_OBJECT (self, "fixated caps %" GST_PTR_FORMAT, othercaps);
  return othercaps;
}

static GstBuffer *
gst_cenc_decrypt_lookup_key(GstCencDecrypt *self, const GBytes *kid)
{
  GstBuffer *key;
  gsize length=0;
  const unsigned char *kbytes;
  
  if(self->key){
    gst_buffer_ref(self->key);
    return self->key;
  }
  kbytes = g_bytes_get_data((GBytes*)kid,&length);
  g_assert(length==16);
  key = gst_buffer_new_allocate (NULL,16,NULL);
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
  GstBuffer *key=NULL;
  const GstCencMeta *sample_info=NULL;
  int pos=0;
  int sample_index=0;
  AesCtrState *state=NULL;

  GST_DEBUG_OBJECT (self, "decrypt in-place");
  sample_info = gst_buffer_get_cenc_meta(buf);
  if(!sample_info || !buf){
    if(!sample_info){
      GST_ERROR_OBJECT (self, "Failed to get sample_info metadata from buffer");
    }
    if(!buf){
      GST_ERROR_OBJECT (self, "Failed to get writable buffer");
    }
    ret = GST_FLOW_NOT_SUPPORTED;
    goto out;
  }  
  //TODO: change to use map_range
  if (!gst_buffer_map (buf, &map, GST_MAP_READWRITE)) {
    GST_ERROR_OBJECT (self,"Failed to map buffer");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }
  GST_DEBUG_OBJECT (self, "decrypt sample %d", map.size);
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
    GST_TRACE_OBJECT (self, "%d bytes clear (todo=%d)", run->n_bytes_clear,
		      map.size-pos);
    pos += run->n_bytes_clear;
    if(run->n_bytes_encrypted){
      GST_TRACE_OBJECT (self, "%d bytes encrypted (todo=%d)", 
			run->n_bytes_encrypted,
			map.size-pos);
      gst_aes_ctr_decrypt_ip(state, map.data+pos, run->n_bytes_encrypted);
      pos += run->n_bytes_encrypted;
    }
  }

beach:
  //GST_TRACE_OBJECT (self, "Done, unmap buffer");
  gst_buffer_unmap (buf, &map);
  if(state){
    //GST_TRACE_OBJECT (self, "Free aes_ctr");
    gst_aes_ctr_decrypt_unref(state);
  }
release:
  if(sample_info){
    //GST_TRACE_OBJECT (self, "Free GstMeta");
    gst_buffer_remove_meta (buf, (GstMeta*)sample_info);
  }
out:
  //GST_TRACE_OBJECT (self, "transform_ip done");
  return ret;
}


