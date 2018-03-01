
AC_INIT
AC_CONFIG_SRCDIR([gzsig.c])
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE(gzsig, 0.1)
AM_CONFIG_HEADER(config.h)

dnl Initialize prefix.
if test "$prefix" = "NONE"; then
   prefix="/usr/local"
fi

dnl Checks for programs.
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S

dnl Checks for libraries.
AC_MSG_CHECKING(for KeyNote)
AC_ARG_WITH(keynote,
[  --with-keynote=DIR      use KeyNote in DIR],
[ case "$withval" in
  yes|no)
    AC_MSG_RESULT(no)
    ;;
  *)
    AC_MSG_RESULT($withval)
    if test -f $withval/include/keynote.h -a -f $withval/lib/libkeynote.a; then
	owd=`pwd`
	if cd $withval; then withval=`pwd`; cd $owd; fi
	KNINC="-I$withval/include"
	KNLIB="-L$withval/lib -lkeynote"
    elif test -f $withval/keynote.h -a -f $withval/libkeynote.a; then
	KNINC="-I$withval"
	KNLIB="-L$withval -lkeynote"
    else
	AC_MSG_ERROR(keynote.h or libkeynote.a not found in $withval)
    fi
    have_keynote=yes
    ;;
  esac ],
[ if test -f ${prefix}/include/keynote.h -a -f ${prefix}/lib/libkeynote.a; then
    KNINC="-I${prefix}/include"
    KNLIB="-L${prefix}/lib -lkeynote"
    AC_MSG_RESULT(yes)
    have_keynote=yes
  elif test -f /usr/include/keynote.h -a -f /usr/lib/libkeynote.a; then
    KNLIB="-lkeynote"
    AC_MSG_RESULT(yes)
    have_keynote=yes
  else
    AC_MSG_RESULT(no)
  fi
])
AC_SUBST(KNINC)
AC_SUBST(KNLIB)

if test "$have_keynote" = "yes"; then
    AC_DEFINE(HAVE_KEYNOTE, 1, [Define if you have KeyNote])
    LIBOBJS="$LIBOBJS kn.o"
    AC_SUBST(LIBOBJS)
fi

AX_CHECK_OPENSSL([
    AC_SUBST(OPENSSL_INCLUDES)
    AC_SUBST(OPENSSL_LIBS)
],
[
    AC_MSG_RESULT(no)
    AC_MSG_ERROR(OpenSSL not found)
])

LT_INIT([dlopen])

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h unistd.h arpa/nameser_compat.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_PROG_GCC_TRADITIONAL
if test "$GCC" = yes; then
   CFLAGS="$CFLAGS -Wall"
fi

dnl Checks for library functions.
AC_CHECK_LIB(m, pow)
AC_REPLACE_FUNCS(err)

AX_CREATE_STDINT_H(gzsig-int.h)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
