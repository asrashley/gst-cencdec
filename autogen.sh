#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

ORIGDIR=`pwd`
cd "$srcdir"

DIE=0
package=gst-cenc
srcfile=src/gstcencelements.c

# Make sure we have common
if test ! -f common/gst-autogen.sh;
then
  echo "+ Setting up common submodule"
  git submodule init
fi
git submodule update

# source helper functions
if test ! -f common/gst-autogen.sh;
then
    echo There is something wrong with your source tree.
    echo You are missing common/gst-autogen.sh
    exit 1
fi
. common/gst-autogen.sh

CONFIGURE_DEF_OPT='--enable-maintainer-mode'

autogen_options $@

echo -n "+ check for build tools"
if test ! -z "$NOCHECK"; then echo ": skipped version checks"; else  echo; fi
version_check "autoconf" "$AUTOCONF autoconf autoconf270 autoconf269 autoconf268 " \
              "ftp://ftp.gnu.org/pub/gnu/autoconf/" 2 68 || DIE=1
version_check "automake" "$AUTOMAKE automake automake-1.11" \
              "ftp://ftp.gnu.org/pub/gnu/automake/" 1 11 || DIE=1
version_check "autopoint" "autopoint" \
              "ftp://ftp.gnu.org/pub/gnu/gettext/" 0 17 || DIE=1
version_check "libtoolize" "$LIBTOOLIZE libtoolize glibtoolize" \
              "ftp://ftp.gnu.org/pub/gnu/libtool/" 2 2 6 || DIE=1
version_check "pkg-config" "" \
              "http://www.freedesktop.org/software/pkgconfig" 0 8 0 || DIE=1

die_check $DIE

aclocal_check || DIE=1
autoheader_check || DIE=1

die_check $DIE

# if no arguments specified then this will be printed
if test -z "$*"; then
  echo "+ checking for autogen.sh options"
  echo "  This autogen script will automatically run ./configure as:"
  echo "  ./configure $CONFIGURE_DEF_OPT"
  echo "  To pass any additional options, please specify them on the $0"
  echo "  command line."
fi

toplevel_check $srcfile

# aclocal
if test -f acinclude.m4; then rm acinclude.m4; fi

tool_run "$libtoolize" "--copy --force"
tool_run "$aclocal" "-I common/m4 $ACLOCAL_FLAGS"
tool_run "$autoheader"

# touch the stamp-h.in build stamp so we don't re-run autoheader in maintainer mode -- wingo
echo timestamp > stamp-h.in 2> /dev/null

tool_run "$autoconf"
debug "automake: $automake"
tool_run "$automake" "--add-missing --copy"

test -n "$NOCONFIGURE" && {
  echo "skipping configure stage for package $package, as requested."
  echo "autogen.sh done."
  exit 0
}

echo "+ running configure ... "
test ! -z "$CONFIGURE_DEF_OPT" && echo "  ./configure default flags: $CONFIGURE_DEF_OPT"
test ! -z "$CONFIGURE_EXT_OPT" && echo "  ./configure external flags: $CONFIGURE_EXT_OPT"
echo

cd ${ORIGDIR}

echo $srcdir/configure $CONFIGURE_DEF_OPT $CONFIGURE_EXT_OPT $@
$srcdir/configure $CONFIGURE_DEF_OPT $CONFIGURE_EXT_OPT $@ || {
        echo "  configure failed"
        exit 1
}

echo "Now type 'make' to compile $package."

