gst_cencdrm_headers = [
  'gstaesctr.h',
  'gstcencdrm.h',
]

gst_cencdrm_sources = [
  'gstaesctr.c',
  'gstcencdrm.c',
]

install_headers(gst_cencdrm_headers, subdir : 'gstreamer-1.0/gst/cencdrm')

gst_cencdrm_dependencies = [gst_dep, gst_base_dep, libxml2_dep, openssl_dep]

gst_cencdrm = static_library('gstcencdrm-@0@'.format(apiversion),
  gst_cencdrm_sources,
  c_args : gst_c_args + ['-DGST_USE_UNSTABLE_API', '-DBUILDING_GST_CENCDRM'],
  dependencies : gst_cencdrm_dependencies,
  install : true,
)

gst_cencdrm_dep = declare_dependency(link_with : gst_cencdrm,
  dependencies : gst_cencdrm_dependencies,
  include_directories : [libsinc],
)
