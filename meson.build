project('gst-cencdec', 'c',
  version : '0.1.0',
  default_options : [ 'warning_level=3',
                      'buildtype=debugoptimized' ])

gst_req = '>= 1.8.0'
apiversion = '1.0'

gst_cencdec_version = meson.project_version()

glib_dep = dependency('glib-2.0')
gst_dep = dependency('gstreamer-1.0', version : gst_req)
gst_base_dep = dependency('gstreamer-base-1.0', version : gst_req)
gst_check_dep = dependency('gstreamer-check-1.0', version : gst_req)

gst_c_args = ['-DHAVE_CONFIG_H']
configinc = include_directories('.')
libsinc = include_directories('gst-libs')

plugins_install_dir = join_paths(get_option('libdir'), 'gstreamer-1.0')

core_conf = configuration_data()

core_conf.set_quoted('VERSION', gst_cencdec_version)
core_conf.set_quoted('PACKAGE_NAME', 'gst-cencdec')
core_conf.set_quoted('PACKAGE', 'gst-cencdec')

cc = meson.get_compiler('c')

# Symbol visibility
if cc.get_id() == 'msvc'
  export_define = '__declspec(dllexport) extern'
elif cc.has_argument('-fvisibility=hidden')
  add_project_arguments('-fvisibility=hidden', language: 'c')
  export_define = 'extern __attribute__ ((visibility ("default")))'
else
  export_define = 'extern'
endif

core_conf.set('GST_API_EXPORT', export_define)

configure_file(output : 'config.h', configuration : core_conf)

curl_dep = dependency('libcurl', version : '>= 7.35.0', required : get_option('clearkey'))

json_dep = dependency('json-glib-1.0',
    fallback : ['json-glib', 'json_glib_dep'])

libxml2_dep = dependency('libxml-2.0', required : true)

openssl_dep = dependency('openssl', version: '>= 1.0.0g', required : true)

subdir('gst-libs')
subdir('gst')
subdir('tests')
