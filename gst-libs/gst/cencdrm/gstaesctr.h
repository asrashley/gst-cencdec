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

#ifndef _GST_AES_CTR_DECRYPT_H_
#define _GST_AES_CTR_DECRYPT_H_

#include <glib.h>
#include <gst/gst.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

G_BEGIN_DECLS

#ifndef GST_CENCDRM_API
# ifdef BUILDING_GST_CENCDRM
#  define GST_CENCDRM_API GST_API_EXPORT         /* from config.h */
# else
#  define GST_CENCDRM_API GST_API_IMPORT
# endif
#endif

typedef struct _AesCtrState AesCtrState;

GST_CENCDRM_API
AesCtrState * gst_aes_ctr_decrypt_new(GBytes *key, GBytes *iv);

GST_CENCDRM_API
AesCtrState * gst_aes_ctr_decrypt_ref(AesCtrState *state);

GST_CENCDRM_API
void gst_aes_ctr_decrypt_unref(AesCtrState *state);

GST_CENCDRM_API
void gst_aes_ctr_decrypt_ip(AesCtrState *state,
                            unsigned char *data,
                            int length);

GST_CENCDRM_API
GType gst_aes_ctr_get_type (void);

G_END_DECLS

#endif /* _GST_AES_CTR_DECRYPT_H_ */
