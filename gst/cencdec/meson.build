gst_cencdec_elements_sources = [
  'gstcencdec.c',
  'gstplugin.c',
  'gstdrm_stub.c',
]

gst_cencdec = library('gstcencdec',
  gst_cencdec_elements_sources,
  dependencies : [gst_dep, gst_base_dep, gst_cencdrm_dep, curl_dep, json_dep, openssl_dep, libxml2_dep],
  include_directories : [configinc],
  c_args : gst_c_args + ['-DGST_USE_UNSTABLE_API', '-DBUILDING_GST_CENCDRM'],
  install : true,
  install_dir : plugins_install_dir)
