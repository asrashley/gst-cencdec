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

configinc = include_directories('.')

plugins_install_dir = join_paths(get_option('libdir'), 'gstreamer-1.0')

core_conf = configuration_data()
core_conf.set_quoted('VERSION', gst_cencdec_version)
core_conf.set_quoted('PACKAGE_NAME', 'gst-cencdec')
core_conf.set_quoted('PACKAGE', 'gst-cencdec')

gst_c_args = ['-DHAVE_CONFIG_H']

configure_file(output : 'config.h', configuration : core_conf)

libxml2_dep = dependency('libxml-2.0', required : true)
openssl_dep = dependency('openssl', version: '>= 1.0.0g', required : true)

subdir('gst-libs')
subdir('src')
subdir('tests')