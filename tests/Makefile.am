include $(top_srcdir)/common/check.mak

CHECK_REGISTRY = $(top_builddir)/tests/check/test-registry.reg

REGISTRY_ENVIRONMENT = \
	GST_REGISTRY_1_0=$(CHECK_REGISTRY)

TESTS_ENVIRONMENT = \
	$(REGISTRY_ENVIRONMENT)					\
	GST_PLUGIN_SYSTEM_PATH_1_0=				\
	GST_PLUGIN_PATH_1_0=$(top_builddir)/gst:$(top_builddir)/ext:$(top_builddir)/sys:$(GSTPB_PLUGINS_DIR):$(GST_PLUGINS_DIR)			\
	GST_PLUGIN_LOADING_WHITELIST="gstreamer@$(GST_PLUGINS_DIR):gst-plugins-base@$(GSTPB_PLUGINS_DIR):gst-plugins-good@$(top_builddir)"	\
	GST_STATE_IGNORE_ELEMENTS="aasink autoaudiosrc autoaudiosink autovideosrc autovideosink \
		cacasink cairotextoverlay \
		halaudiosrc halaudiosink jackaudiosrc jackaudiosink \
		osssrc osssink osxaudiosink osxaudiosrc osxvideosrc osxvideosink \
		pulsesink pulsesrc pulsemixer v4l2src"


# the core dumps of some machines have PIDs appended
CLEANFILES = core.* test-registry.*

clean-local: clean-local-check
# distclean-local: distclean-local-check

check_PROGRAMS = aesctr/decrypt

TESTS = $(check_PROGRAMS)

AM_CFLAGS = $(GST_OBJ_CFLAGS) $(GST_CHECK_CFLAGS) $(CHECK_CFLAGS) \
	-I$(top_srcdir)/gst-libs \
	$(GST_OPTION_CFLAGS) $(GST_CFLAGS) \
	-UG_DISABLE_ASSERT -UG_DISABLE_CAST_CHECKS
LDADD = $(GST_OBJ_LIBS) $(GST_CHECK_LIBS) $(CHECK_LIBS)

# valgrind testing
VALGRIND_TESTS_DISABLE = 

SUPPRESSIONS = $(top_srcdir)/common/gst.supp

aesctr_decrypt_CFLAGS =  -I$(top_srcdir)/gst-libs \
	$(GST_PLUGINS_BASE_CFLAGS) $(CFLAGS) $(AM_CFLAGS)
aesctr_decrypt_LDADD = \
	$(top_srcdir)/gst-libs/gst/libgstaesctr-$(GST_API_VERSION).la \
	$(GST_PLUGINS_BASE_LIBS) \
	$(LDADD) \
	$(OPENSSL_LIBS)

#	-lgstaesctr-$(GST_API_VERSION) 
EXTRA_DIST = 
