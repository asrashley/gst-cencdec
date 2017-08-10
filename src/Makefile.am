plugin_LTLIBRARIES = libgstcencdec.la

# Directory where the gstreamer plugins have been compiled
GST_PLUGINS_GOOD_BASEDIR = $(firstword $(subst :, ,$(GST_PLUGINS_BASE_DIR)))/..
GST_PLUGINS_BASE_BUILD_DIR=$(GST_PLUGINS_BASE_BASEDIR)

GST_PLUGINS_BASE_GST_LIBS = $(GST_PLUGINS_BASE_BUILD_DIR)/gst-libs
GST_PLUGINS_BASE_GST_INCLUDE = -I$(GST_PLUGINS_BASE_GST_LIBS) 

# sources used to compile this plugin
libgstcencdec_la_SOURCES = \
  gstcencdec.c \
  gstcencelements.c 

libgstcencdec_la_CFLAGS = \
 -I$(top_srcdir)/common \
 -I$(top_srcdir)/gst-libs \
  $(OPENSSL_CFLAGS) \
  $(LIBXML2_CFLAGS) \
  $(GST_CFLAGS) \
  $(GST_BASE_CFLAGS) \
  $(GST_PLUGINS_BASE_CFLAGS) \
  $(GST_PLUGINS_BASE_GST_INCLUDE)

#libgstcencdec_la_LDFLAGS = \
#  $(GST_PLUGIN_LDFLAGS) \
#  -Wl,-rpath=$(GST_PLUGINS_DIR)/.. \
#  -no-undefined

libgstcencdec_la_LIBADD = \
  $(top_builddir)/gst-libs/gst/libgstaesctr-@GST_API_VERSION@.la \
  $(GST_PLUGINS_BASE_LIBS) \
  $(GST_BASE_LIBS) \
  $(GST_LIBS) \
  $(LIBXML2_LIBS) \
  $(OPENSSL_LIBS)

libgstcencdec_la_LDFLAGS = $(GST_PLUGIN_LDFLAGS)
libgstcencdec_la_LIBTOOLFLAGS = $(GST_PLUGIN_LIBTOOLFLAGS)

# headers we need but don't want installed
noinst_HEADERS = \
  gstcencdec.h
