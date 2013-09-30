lib_LTLIBRARIES = libgstaesctr-@GST_API_VERSION@.la

libgstaesctr_@GST_API_VERSION@_la_SOURCES = \
	gstaesctr.c

libgstaesctr_@GST_API_VERSION@includedir = \
	$(includedir)/gstreamer-@GST_API_VERSION@/gst

noinst_HEADERS = 

libgstaesctr_@GST_API_VERSION@include_HEADERS = \
	gstaesctr.h

libgstaesctr_@GST_API_VERSION@_la_CFLAGS = \
	$(GST_PLUGINS_BASE_CFLAGS) \
	-DGST_USE_UNSTABLE_API \
	$(GST_CFLAGS)

libgstaesctr_@GST_API_VERSION@_la_LIBADD = \
	$(GST_BASE_LIBS) \
	$(GST_LIBS)

libgstaesctr_@GST_API_VERSION@_la_LDFLAGS = \
	$(GST_LIB_LDFLAGS) \
	$(GST_ALL_LDFLAGS) \
	$(GST_LT_LDFLAGS)

Android.mk:  $(BUILT_SOURCES) Makefile.am
	androgenizer -:PROJECT libgstaesctr -:STATIC libgstaesctr-@GST_API_VERSION@ \
	 -:TAGS eng debug \
         -:REL_TOP $(top_srcdir) -:ABS_TOP $(abs_top_srcdir) \
	 -:SOURCES $(libgstaesctr_@GST_API_VERSION@_la_SOURCES) \
         $(built_sources) \
	 -:CFLAGS $(DEFS) $(libgstaesctr_@GST_API_VERSION@_la_CFLAGS) \
	 -:LDFLAGS $(libgstaesctr_@GST_API_VERSION@_la_LDFLAGS) \
	           $(libgstaesctr@GST_API_VERSION@_la_LIBADD) \
	           -ldl \
	 -:HEADER_TARGET gstreamer-@GST_API_VERSION@/gst \
	 -:HEADERS $(libgstaesctrinclude_HEADERS) \
         $(built_headers) \
	 -:PASSTHROUGH LOCAL_ARM_MODE:=arm \
	> $@

include $(top_srcdir)/common/gst-glib-gen.mak
