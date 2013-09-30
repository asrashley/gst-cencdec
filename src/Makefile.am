plugin_LTLIBRARIES = libgstcenccrypto.la

GST_PLUGINS_GOOD_BASEDIR = $(firstword $(subst :, ,$(GST_PLUGINS_GOOD_DIR)))/..
GST_PLUGINS_GOOD_GST_LIBS = $(GST_PLUGINS_GOOD_BASEDIR)/gst-libs
#GST_ISOMP4_DIR = $(wildcard $(foreach DIR, $(subst :, ,$(GST_PLUGINS_GOOD_DIR)), $(DIR)/isomp4/.libs ))

# sources used to compile this plugin
libgstcenccrypto_la_SOURCES = \
  gstcencdec.c \
  gstcencelements.c 

libgstcenccrypto_la_CFLAGS = \
 -I$(top_srcdir)/common \
 -I$(top_srcdir)/gst-libs \
  $(OPENSSL_CFLAGS) \
  $(GST_CFLAGS) \
  $(GST_BASE_CFLAGS) \
  $(GST_PLUGINS_GOOD_CFLAGS) \
  -I$(GST_PLUGINS_GOOD_GST_LIBS) \
  $(CPU_TUNE_CFLAGS)

libgstcenccrypto_la_LDFLAGS = \
  $(GST_PLUGIN_LDFLAGS) \
  -no-undefined

libgstcenccrypto_la_LIBADD = \
  $(GST_PLUGINS_GOOD_GST_LIBS)/gst/isomp4/libgstcenc-$(GST_API_VERSION).la \
  $(top_srcdir)/gst-libs/gst/libgstaesctr-$(GST_API_VERSION).la \
  $(GST_PLUGINS_GOOD_LIBS) \
  $(GST_PLUGINS_BASE_LIBS) \
  $(GST_BASE_LIBS) \
  $(GST_LIBS) \
  $(OPENSSL_LIBS)

libgstcenccrypto_la_LIBTOOLFLAGS = $(GST_PLUGIN_LIBTOOLFLAGS)

# headers we need but don't want installed
noinst_HEADERS = \
  gstcencdec.h
