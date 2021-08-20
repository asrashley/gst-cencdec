gst_aesctr = static_library('gstaesctr-@0@'.format(apiversion),
  ['gstaesctr.c'],
  dependencies : [gst_dep],
  install : false
)

gst_aesctr_dep = declare_dependency(link_with : gst_aesctr,
  dependencies : [openssl_dep],
  include_directories : [include_directories('..')]
)
