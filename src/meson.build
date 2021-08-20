gst_cencdec_elements_sources = [
  'gstcencdec.c',
  'gstcencelements.c'
]

gst_cencdec = library('gstcencdec',
  gst_cencdec_elements_sources,
  dependencies : [gst_dep, gst_base_dep, gst_aesctr_dep, libxml2_dep],
  include_directories : [configinc],
  c_args : gst_c_args,
  install : true,
  install_dir : plugins_install_dir)
