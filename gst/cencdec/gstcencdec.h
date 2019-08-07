/* GStreamer ISO MPEG-DASH common encryption decryption
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
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifndef _GST_CENC_DECRYPT_H_
#define _GST_CENC_DECRYPT_H_

#include <gst/base/gstbasetransform.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef GST_CENCDEC_API
# ifdef BUILDING_GST_CENCDEC
#  define GST_CENCDEC_API GST_API_EXPORT         /* from config.h */
# else
#  define GST_CENCDEC_API GST_API_IMPORT
# endif
#endif

G_BEGIN_DECLS

#define GST_TYPE_CENC_DECRYPT   (gst_cenc_decrypt_get_type())
#define GST_CENC_DECRYPT(obj)   (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_CENC_DECRYPT,GstCencDecrypt))
#define GST_CENC_DECRYPT_CLASS(klass)   (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_CENC_DECRYPT,GstCencDecryptClass))
#define GST_IS_CENC_DECRYPT(obj)   (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_CENC_DECRYPT))
#define GST_IS_CENC_DECRYPT_CLASS(obj)   (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_CENC_DECRYPT))
typedef struct _GstCencDecrypt GstCencDecrypt;
typedef struct _GstCencDecryptClass GstCencDecryptClass;

GST_CENCDEC_API
GType gst_cenc_decrypt_get_type (void);

G_END_DECLS
#endif
