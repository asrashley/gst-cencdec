AC_PREREQ([2.68])

dnl please read gstreamer/docs/random/autotools before changing this file

dnl initialize autoconf
dnl fill in your package name and version here
dnl the fourth (nano) number should be 0 for a release, 1 for CVS,
dnl and 2... for a prerelease
dnl releases only do -Wall, cvs and prerelease does -Werror too
AC_INIT(GStreamer cenc element, 0.0.1,,
    gst-cenc)

AG_GST_INIT

dnl initialize automake
AM_INIT_AUTOMAKE

dnl define PACKAGE_VERSION_* variables
AS_VERSION

dnl check if this is a release version
AS_NANO(GST_CVS="no", GST_CVS="yes")

dnl define the output header for config
AM_CONFIG_HEADER([config.h])

dnl AM_MAINTAINER_MODE only provides the option to configure to enable it
AM_MAINTAINER_MODE

dnl sets host_* variables
AC_CANONICAL_HOST

dnl make aclocal work in maintainer mode
AC_SUBST(ACLOCAL_AMFLAGS, "-I common/m4")

dnl *** check for arguments to configure ***

AG_GST_ARG_DEBUG
AG_GST_ARG_PROFILING
AG_GST_ARG_VALGRIND
AG_GST_ARG_GCOV

dnl *** checks for platform ***

dnl check for fseeko()
AC_FUNC_FSEEKO

dnl * hardware/architecture *
dnl common/m4/gst-arch.m4

dnl check CPU type
AG_GST_ARCH

dnl Determine endianness
AC_C_BIGENDIAN

dnl *** checks for programs ***

AC_PROG_CC
AM_PROG_CC_C_O dnl to compile with per-target flag
AC_PROG_LIBTOOL
AM_PROG_AS

AC_PATH_PROG(VALGRIND_PATH, valgrind, no)
AM_CONDITIONAL(HAVE_VALGRIND, test ! "x$VALGRIND_PATH" = "xno")

dnl define an ERROR_CFLAGS Makefile variable
AG_GST_SET_ERROR_CFLAGS($GST_CVS)

dnl Check for pkgconfig first
AC_CHECK_PROG(HAVE_PKGCONFIG, pkg-config, yes, no)

dnl Give error and exit if we don't have pkgconfig
if test "x$HAVE_PKGCONFIG" = "xno"; then
  AC_MSG_ERROR(you need to have pkgconfig installed !)
fi

dnl *** required versions of GStreamer stuff ***
GST_API_VERSION=1.0
AC_SUBST(GST_API_VERSION)
AC_DEFINE_UNQUOTED(GST_API_VERSION, "$GST_API_VERSION",
  [GStreamer API Version])
AG_GST_LIBTOOL_PREPARE

GST_REQ=1.2.0
GSTPB_REQ=1.2.0

PKG_CHECK_MODULES([OPENSSL], [ openssl >= 1.0.0g ], [ HAVE_OPENSSL="yes" ], [ HAVE_OPENSSL="no" ])

PKG_CHECK_MODULES(LIBXML2, libxml-2.0 >= 2.4, [HAVE_LIBXML2="yes"], [HAVE_LIBXML2="no"])
AM_CONDITIONAL(HAVE_LIBXML2, test "x$HAVE_LIBXML2" = "xyes")
AC_SUBST(LIBXML2_CFLAGS)
AC_SUBST(LIBXML2_LIBS)

dnl checks for gstreamer
dnl uninstalled is selected preferentially -- see pkg-config(1)
AG_GST_CHECK_GST($GST_API_VERSION, [$GST_REQ], yes)
AG_GST_CHECK_GST_BASE($GST_API_VERSION, [$GST_REQ], yes)
AG_GST_CHECK_GST_CHECK($GST_API_VERSION, [$GST_REQ], no)
AG_GST_CHECK_GST_CONTROLLER($GST_API_VERSION, [$GST_REQ], yes)
AM_CONDITIONAL(HAVE_GST_CHECK, test "x$HAVE_GST_CHECK" = "xyes")

AG_GST_CHECK_GST_PLUGINS_BASE($GST_API_VERSION, [$GSTPB_REQ], yes)
AG_GST_CHECK_GST_PLUGINS_GOOD($GST_API_VERSION, [$GSTPB_REQ], yes)

dnl check for uninstalled plugin directories for unit tests
AG_GST_CHECK_UNINSTALLED_SETUP([
  AG_GST_CHECK_GST_PLUGINS_GOOD($GST_API_VERSION, [$GST_REQ])
dnl  AG_GST_CHECK_GST_PLUGINS_BAD($GST_API_VERSION, [$GST_REQ])
  AG_GST_CHECK_GST_PLUGINS_LIBAV($GST_API_VERSION, [$GST_REQ])
])

dnl Now we're ready to ask for gstreamer libs and cflags
dnl And we can also ask for the right version of gstreamer
dnl AG_GST_DETECT_VERSION([1.0.0])
dnl AG_GST_CHECK_GST($GST_MAJORMINOR, [$GST_REQ])
dnl AG_GST_CHECK_GST_BASE($GST_MAJORMINOR, [$GST_REQ])
dnl AG_GST_CHECK_GST_PLUGINS_BASE($GST_MAJORMINOR, [$GST_REQ])
dnl GSTPB_PLUGINS_DIR=${libdir}/gstreamer-${GST_MAJORMINOR}

AM_CONDITIONAL(ZINCBUILD, [test x$ZINC_BUILD_ROOT != x])

dnl make GST_MAJORMINOR available in Makefile.am
AC_SUBST(GST_MAJORMINOR)

dnl define CPU_TUNE_CFLAGS and CPU_TUNE_CCASFLAGS
dnl AG_GST_CPU_TUNE

AG_GST_SET_PLUGINDIR

GST_CFLAGS="$GST_CFLAGS $ERROR_CFLAGS"

dnl set proper LDFLAGS for plugins
GST_PLUGIN_LDFLAGS='-module -avoid-version -export-symbols-regex [_]*\(gst_\|Gst\|GST_\).*'
AC_SUBST(GST_PLUGIN_LDFLAGS)

AC_OUTPUT(
Makefile
gst-libs/Makefile
gst-libs/gst/Makefile
src/Makefile
common/Makefile
common/m4/Makefile
tests/Makefile
gst-cenc.spec
)

echo "
$PACKAGE-$VERSION

        prefix:                           ${prefix}
        compiler:                         ${CC}
        Building for GStreamer-${GST_MAJORMINOR}
"
