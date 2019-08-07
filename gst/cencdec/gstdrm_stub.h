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

#ifndef __GST_CENC_DRM_STUB_H__
#define __GST_CENC_DRM_STUB_H__

#include <gst/cencdrm/gstcencdrm.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef GST_CENCDRMSTUB_API
# if defined(BUILDING_GST_CENCDRM) || defined(BUILDING_GST_CENCDEC)
#  define GST_CENCDRMSTUB_API GST_API_EXPORT         /* from config.h */
# else
#  define GST_CENCDRMSTUB_API GST_API_IMPORT
# endif
#endif

G_BEGIN_DECLS

GST_CENCDRMSTUB_API
GstCencDRM* gst_cenc_drm_stub_factory(GstEvent *protection_event);

GST_CENCDRMSTUB_API
GType gst_cenc_drm_stub_get_type (void);

G_END_DECLS
#endif /* __GST_CENC_DRM_STUB_H__ */
