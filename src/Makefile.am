plugin_LTLIBRARIES = libgstcenccrypto.la

# Directory where the gstreamer plugins have been compiled
GST_PLUGINS_GOOD_BASEDIR = $(firstword $(subst :, ,$(GST_PLUGINS_BASE_DIR)))/..
GST_PLUGINS_BASE_BUILD_DIR=$(GST_PLUGINS_BASE_BASEDIR)

if ZINCBUILD
GST_PLUGINS_BASE_BASEDIR = $(PLUGINDIR)/..
GST_BUILD_DIR = $(ZINC_BUILD_ROOT)/$(ZINC_BUILD_TYPE)-$(ZINC_HOST_CFG)/Zinc/Zinc.3rdPartyStack/build/$(ZINC_HOST_CFG)
GST_PLUGINS_BASE_BUILD_DIR = $(GST_BUILD_DIR)/gst_plugins_good
endif

GST_PLUGINS_BASE_GST_LIBS = $(GST_PLUGINS_BASE_BUILD_DIR)/gst-libs
GST_PLUGINS_BASE_GST_INCLUDE = -I$(GST_PLUGINS_BASE_GST_LIBS) 

if ZINCBUILD
GST_PLUGINS_BASE_GST_INCLUDE = -I$(PLUGINDIR)/..
endif

# sources used to compile this plugin
libgstcenccrypto_la_SOURCES = \
  gstcencdec.c \
  gstcencelements.c 

libgstcenccrypto_la_CFLAGS = \
 -I$(top_srcdir)/common \
 -I$(top_srcdir)/gst-libs \
  $(OPENSSL_CFLAGS) \
  $(LIBXML2_CFLAGS) \
  $(GST_CFLAGS) \
  $(GST_BASE_CFLAGS) \
  $(GST_PLUGINS_BASE_CFLAGS) \
  $(GST_PLUGINS_BASE_GST_INCLUDE) \
  $(CPU_TUNE_CFLAGS)

libgstcenccrypto_la_LDFLAGS = \
  $(GST_PLUGIN_LDFLAGS) \
  -Wl,-rpath=$(GST_PLUGINS_DIR)/.. \
  -no-undefined

libgstcenccrypto_la_LIBADD = \
  $(top_srcdir)/gst-libs/gst/libgstaesctr-$(GST_API_VERSION).la \
  $(GST_PLUGINS_BASE_LIBS) \
  -lgstcenc-@GST_API_VERSION@ \
  $(GST_BASE_LIBS) \
  $(GST_LIBS) \
  $(LIBXML2_LIBS) \
  $(OPENSSL_LIBS)

libgstcenccrypto_la_LIBTOOLFLAGS = $(GST_PLUGIN_LIBTOOLFLAGS)

# headers we need but don't want installed
noinst_HEADERS = \
  gstcencdec.h
