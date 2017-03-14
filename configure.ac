##
## Configure template file for Quagga.
## autoconf will generate configure script.
##
##  Copyright (c) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
##  Portions Copyright (c) 2003 Paul Jakma <paul@dishone.st>
##  Portions Copyright (c) 2016 6WIND
##
AC_PREREQ(2.60)

AC_INIT(ZRPCD, 0.2)
CONFIG_ARGS="$*"
AC_SUBST(CONFIG_ARGS)

dnl -----------------------------------
dnl Get hostname and other information.
dnl -----------------------------------
AC_CANONICAL_BUILD()
AC_CANONICAL_HOST()
AC_CANONICAL_TARGET()

# Disable portability warnings -- our automake code (in particular
# common.am) uses some constructs specific to gmake.
AM_INIT_AUTOMAKE([1.6 -Wno-portability])
AC_CONFIG_MACRO_DIR([m4])

m4_ifndef([AM_SILENT_RULES], [m4_define([AM_SILENT_RULES],[])])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS(config.h)

AC_PATH_PROG(PERL, perl)

dnl default is to match previous behavior
exampledir=${sysconfdir}

dnl default is to match previous behavior
pkgsrcrcdir=""
pkgsrcdir=""
AC_ARG_ENABLE([pkgsrcrcdir],
	  AS_HELP_STRING([--enable-pkgsrcrcdir],
			 [specify directory for rc.d scripts]),
			 pkgsrcrcdir="$enableval"; pkgsrcdir="pkgsrc",)
dnl XXX add --pkgsrcrcdir to autoconf standard directory list somehow
AC_SUBST(pkgsrcdir)
AC_SUBST(pkgsrcrcdir)

dnl ------------
dnl Check CFLAGS
dnl ------------
AC_ARG_WITH(cflags,
[  --with-cflags           Set CFLAGS for use in compilation.])
if test "x$with_cflags" != "x" ; then
  CFLAGS="$with_cflags" ; cflags_specified=yes ;
elif test -n "$CFLAGS" ; then
  cflags_specified=yes ;
fi

dnl --------------------
dnl Check CC and friends
dnl --------------------
AC_LANG([C])
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
AC_PROG_RANLIB
AC_PROG_EGREP

dnl autoconf 2.59 appears not to support AC_PROG_SED
dnl AC_PROG_SED
AC_CHECK_PROG([SED],[sed],[sed],[/bin/false])

if test "x${GCC}" != "xyes" ; then
  AC_MSG_CHECKING([whether we are using SunPro compiler])
  AC_EGREP_CPP([^__SUNPRO_C.*0x5(7|8|9)], ["__SUNPRO_C" __SUNPRO_C],
      [AC_MSG_RESULT([no])],
      [COMPILER="SUNPRO"
       AC_MSG_RESULT([yes])]
  )
fi

dnl ---------------------------------------------
dnl If CLFAGS doesn\'t exist set default value
dnl AC_PROG_CC will have set minimal default
dnl already, eg "-O2 -g" for gcc, "-g" for others
dnl (Wall is gcc specific... have to make sure
dnl  gcc is being used before setting it)
dnl
dnl Sun Studio 10 / SunPro 5.7 is also supported,
dnl so lets set some sane CFLAGS for it.
dnl ---------------------------------------------

AC_USE_SYSTEM_EXTENSIONS()
AC_DEFUN([AC_C_FLAG], [{
	AC_LANG_PUSH(C)
	ac_c_flag_save="$CFLAGS"
	CFLAGS="$CFLAGS $1"
	AC_MSG_CHECKING([[whether $CC supports $1]])
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM([[]])],
		[
			AC_MSG_RESULT([yes])
			m4_if([$3], [], [], [
				CFLAGS="$ac_c_flag_save"
				$3
			])
		], [
			CFLAGS="$ac_c_flag_save"
			AC_MSG_RESULT([no])
			$2
		])
	AC_LANG_POP(C)
	}])

AC_MSG_CHECKING([whether to set a default CFLAGS])
if test "x${cflags_specified}" = "x" ; then
  case ${COMPILER} in
    "SUNPRO")
        CFLAGS="-xO4 -v -g -xspace -xcode=pic32 -xstrconst -xc99"
        AC_MSG_RESULT([SunPro default])
        ;;
    *)
        AC_MSG_RESULT([autodetecting])

        AC_C_FLAG([-std=gnu99])
        AC_C_FLAG([-g])
        AC_C_FLAG([-Os], [
          AC_C_FLAG([-O2])
        ])
        AC_C_FLAG([-fpie])
        AC_C_FLAG([-fno-omit-frame-pointer])
        AC_C_FLAG([-Wall])
        AC_C_FLAG([-Wextra])
        AC_C_FLAG([-Wmissing-prototypes])
        AC_C_FLAG([-Wmissing-declarations])
        AC_C_FLAG([-Wpointer-arith])
        AC_C_FLAG([-Wbad-function-cast])
        AC_C_FLAG([-Wwrite-strings])
        if test x"${enable_gcc_ultra_verbose}" = x"yes" ; then
          AC_C_FLAG([-Wcast-qual])
          AC_C_FLAG([-Wstrict-prototypes])
          AC_C_FLAG([-Wmissing-noreturn])
          AC_C_FLAG([-Wmissing-format-attribute])
          AC_C_FLAG([-Wunreachable-code])
          AC_C_FLAG([-Wpacked])
          AC_C_FLAG([-Wpadded])
        else
          AC_C_FLAG([-Wno-unused-result])
        fi
        AC_C_FLAG([-Wno-unused-parameter])
        AC_C_FLAG([-Wno-missing-field-initializers])
        # ICC emits a broken warning for const char *x = a ? "b" : "c";
        # for some reason the string consts get 'promoted' to char *,
        # triggering a const to non-const conversion warning.
        AC_C_FLAG([-diag-disable 3179])
        ;;
  esac
else
  AC_MSG_RESULT([CFLAGS supplied by user])
fi

if test x"${enable_werror}" = x"yes" ; then
  WERROR="-Werror"
fi
AC_SUBST(WERROR)

dnl --------------
dnl Check programs
dnl --------------
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_CHECK_TOOL(AR, ar)

dnl ---------------------------
dnl We, perhaps unfortunately,
dnl depend on GNU Make specific
dnl constructs.
dnl Give the user a warning if
dnl not GNU Make.
dnl ---------------------------
AC_CACHE_CHECK([if ${MAKE-make} is GNU make], [quagga_cv_gnu_make],
	[quagga_cv_gnu_make=no
	 if ${MAKE-make} --version 2>/dev/null | \
	 	grep '^GNU Make ' >/dev/null ; then
	 	quagga_cv_gnu_make=yes;
	 fi
	]
)

dnl -----------------
dnl System extensions
dnl -----------------
AC_GNU_SOURCE

dnl -------
dnl libtool
dnl -------
LT_INIT

dnl ----------------------
dnl Packages configuration
dnl ----------------------
AC_ARG_ENABLE(user,
  AS_HELP_STRING([--enable-user=USER], [user to run Quagga suite as (default quagga)]))
AC_ARG_ENABLE(group,
  AS_HELP_STRING([--enable-group=GROUP], [group to run Quagga suite as (default quagga)]))
AC_ARG_ENABLE(vty_group,
  AS_HELP_STRING([--enable-vty-group=ARG], [set vty sockets to have specified group as owner]))

if test "${enable_user}" = "yes" || test x"${enable_user}" = x""; then
  enable_user="quagga"
elif test "${enable_user}" = "no"; then
  enable_user="root"
fi

if test "${enable_group}" = "yes" || test x"${enable_group}" = x""; then
  enable_group="quagga"
elif test "${enable_group}" = "no"; then
  enable_group="root"
fi

if test x"${enable_vty_group}" = x"yes" ; then
  AC_MSG_ERROR([--enable-vty-group requires a group as argument, not yes])
elif test x"${enable_vty_group}" != x""; then
  if test x"${enable_vty_group}" != x"no"; then
    AC_DEFINE_UNQUOTED(VTY_GROUP, "${enable_vty_group}", VTY Sockets Group)
  fi
fi

AC_SUBST([enable_user])
AC_SUBST([enable_group])
AC_SUBST([enable_vty_group])
AC_DEFINE_UNQUOTED(QUAGGA_ZRPC_USER, "${enable_user}", Quagga User)
AC_DEFINE_UNQUOTED(QUAGGA_ZRPC_GROUP, "${enable_group}", Quagga Group)

enable_configfile_mask=${enable_configfile_mask:-0600}
AC_DEFINE_UNQUOTED(CONFIGFILE_MASK, ${enable_configfile_mask}, Mask for config files)

enable_logfile_mask=${enable_logfile_mask:-0600}
AC_DEFINE_UNQUOTED(LOGFILE_MASK, ${enable_logfile_mask}, Mask for log files)

dnl ------------------------------------
dnl Check C keywords and standard  types
dnl ------------------------------------
AC_C_CONST
AC_C_INLINE
AC_C_RESTRICT
AC_C_VOLATILE
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_SYS_WAIT
AC_HEADER_STDBOOL
dnl AC_TYPE_PID_T
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_STRUCT_TM

dnl -------------------------
dnl Check other header files.
dnl -------------------------
AC_CHECK_HEADERS([stropts.h sys/ksym.h sys/times.h sys/select.h \
	sys/types.h linux/version.h netdb.h asm/types.h \
	sys/cdefs.h sys/param.h limits.h signal.h \
	sys/socket.h netinet/in.h time.h sys/time.h features.h])

dnl Utility macro to avoid retyping includes all the time
m4_define([QUAGGA_INCLUDES],
[#ifdef SUNOS_5
#define _XPG4_2
#define __EXTENSIONS__
#endif
#include <stdio.h>
#if STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# if HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
/* sys/conf.h depends on param.h on FBSD at least */
#if HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
/* Required for MAXSIG */
#if HAVE_SIGNAL_H
# include <signal.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef __APPLE__
# define __APPLE_USE_RFC_3542
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif /* TIME_WITH_SYS_TIME */
])dnl

AC_CHECK_HEADERS([sys/un.h netinet/in_systm.h netinet/in_var.h \
	net/if_dl.h net/netopt.h net/route.h \
	inet/nd.h arpa/inet.h netinet/ip_icmp.h \
	fcntl.h stddef.h sys/ioctl.h syslog.h wchar.h wctype.h \
	sys/sysctl.h sys/sockio.h kvm.h sys/conf.h],
	[], [], QUAGGA_INCLUDES)

AC_CHECK_HEADERS([ucontext.h], [], [],
[#ifndef __USE_GNU
#define __USE_GNU
#endif /* __USE_GNU */
QUAGGA_INCLUDES
])

m4_define([UCONTEXT_INCLUDES],
[#include <ucontext.h>])dnl

AC_CHECK_MEMBERS([ucontext_t.uc_mcontext.uc_regs],
  [], [], [UCONTEXT_INCLUDES])
AC_CHECK_MEMBERS([ucontext_t.uc_mcontext.regs],
  [AC_CHECK_MEMBERS([ucontext_t.uc_mcontext.regs.nip],
   [], [], [UCONTEXT_INCLUDES])],
  [], [UCONTEXT_INCLUDES])
AC_CHECK_MEMBERS([ucontext_t.uc_mcontext.gregs],
  [], [], [UCONTEXT_INCLUDES])

m4_define([QUAGGA_INCLUDES],
QUAGGA_INCLUDES
[#if HAVE_SYS_UN_H
# include <sys/un.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#if HAVE_NETINET_IN_VAR_H
# include <netinet/in_var.h>
#endif
#if HAVE_NET_IF_DL_H
# include <net/if_dl.h>
#endif
#if HAVE_NET_NETOPT_H
# include <net/netopt.h>
#endif
#if HAVE_NET_ROUTE_H
# include <net/route.h>
#endif
#if HAVE_INET_ND_H
# include <inet/nd.h>
#endif
#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
/* Required for IDRP */
#if HAVE_NETINET_IP_ICMP_H
# include <netinet/ip_icmp.h>
#endif
])dnl

dnl V6 headers are checked below, after we check for v6

dnl Some systems (Solaris 2.x) require libnsl (Network Services Library)
case "$host" in
  [*-sunos5.[6-7]*] | [*-solaris2.[6-7]*])
      opsys=sol2-6
      AC_DEFINE(SUNOS_56, 1, SunOS 5.6 to 5.7)
      AC_DEFINE(SUNOS_5, 1, SunOS 5)
      AC_CHECK_LIB(xnet, main)
      CURSES=-lcurses
      SOLARIS="solaris"
  ;;
  [*-sunos5.[8-9]] \
  | [*-sunos5.1[0-9]] \
  | [*-sunos5.1[0-9].[0-9]] \
  | [*-solaris2.[8-9]] \
  | [*-solaris2.1[0-9]] \
  | [*-solaris2.1[0-9].[0-9]])
      opsys=sol8
      AC_DEFINE(SUNOS_59, 1, [SunOS 5.8 up])
      AC_DEFINE(SUNOS_5, 1, [SunOS 5])
      AC_CHECK_LIB(socket, main)
      AC_CHECK_LIB(nsl, main)
      AC_CHECK_LIB(umem, main)
      AC_CHECK_FUNCS([printstack],
      	[AC_DEFINE([HAVE_PRINTSTACK],1,[Solaris printstack])
      	 AC_DEFINE([HAVE_STACK_TRACE],1,[Stack symbols decode functionality])
      	])
      CURSES=-lcurses
      SOLARIS="solaris"
  ;;
  *-sunos5* | *-solaris2*)
      AC_DEFINE(SUNOS_5,,SunOS 5, Unknown SunOS)
      AC_CHECK_LIB(socket, main)
      AC_CHECK_LIB(nsl, main)
      CURSES=-lcurses
      SOLARIS="solaris"
  ;;
  *-linux*)
      opsys=gnu-linux
      AC_DEFINE(GNU_LINUX,,GNU Linux)
  ;;
  *-openbsd*)
      opsys=openbsd
      AC_DEFINE(OPEN_BSD,,OpenBSD)
  ;;
esac

AC_SYS_LARGEFILE

dnl -------------------------------
dnl Endian-ness check
dnl -------------------------------
AC_WORDS_BIGENDIAN

dnl -------------------------------
dnl check the size in byte of the C
dnl -------------------------------
dnl AC_CHECK_SIZEOF(char)
dnl AC_CHECK_SIZEOF(int)
dnl AC_CHECK_SIZEOF(short)
dnl AC_CHECK_SIZEOF(long)

dnl ----------------------------
dnl check existance of functions
dnl ----------------------------
AC_FUNC_CHOWN
AC_FUNC_FNMATCH
AC_FUNC_FORK
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_STRFTIME
AC_FUNC_STAT
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STRFTIME
dnl Avoid AC_FUNC_STRNLEN because it pulls in AC_SYSTEM_EXTENSIONS which
dnl can lead to strange side effects.  So we just check for strnlen
dnl directly, see below.
dnl AC_FUNC_STRNLENdnl
AC_FUNC_VPRINTF

dnl ---------------
dnl other functions
dnl ---------------
AC_CHECK_FUNCS([dup2 ftruncate getcwd gethostbyname getpagesize gettimeofday \
	inet_ntoa inet_aton strnlen \
	memchr memmove memset select socket \
	strcasecmp strchr strcspn strdup strerror \
	strncasecmp strndup strrchr strspn strstr \
	strtol strtoul strlcat strlcpy \
	daemon snprintf vsnprintf \
	if_nametoindex if_indextoname getifaddrs \
	uname fcntl getgrouplist])


AC_CHECK_HEADER([asm-generic/unistd.h],
                [AC_CHECK_DECL(__NR_setns,
                               AC_DEFINE(HAVE_NETNS,, Have netns),,
                               QUAGGA_INCLUDES [#include <asm-generic/unistd.h>
                               ])
                 AC_CHECK_FUNCS(setns, AC_DEFINE(HAVE_SETNS,, Have setns))]
               )

dnl ------------------------------------
dnl Determine routing get and set method
dnl ------------------------------------
AC_MSG_CHECKING(zebra between kernel interface method)
if test x"$opsys" = x"gnu-linux"; then
  AC_MSG_RESULT(netlink)
  RT_METHOD=rt_netlink.o
  AC_DEFINE(HAVE_NETLINK,,netlink)
  netlink=yes
else
  AC_MSG_RESULT(Route socket)
  KERNEL_METHOD="kernel_socket.o"
  RT_METHOD="rt_socket.o"
fi
AC_SUBST(RT_METHOD)
AC_SUBST(KERNEL_METHOD)
AM_CONDITIONAL([HAVE_NETLINK], [test "x$netlink" = "xyes"])

dnl ----------
dnl IPv6 check
dnl ----------
AC_MSG_CHECKING(whether does this OS have IPv6 stack)
dnl ---------
dnl KAME IPv6
dnl ---------
  if grep WIDE /usr/include/netinet6/in6.h >/dev/null 2>&1; then
    AC_DEFINE(KAME,1,KAME IPv6)
    AC_MSG_RESULT(KAME)
dnl ------------------------------------
dnl Solaris 9, 10 and potentially higher
dnl ------------------------------------
  elif test x"$opsys" = x"sol8"; then
    AC_DEFINE(SOLARIS_IPV6, 1, Solaris IPv6)
    AC_MSG_RESULT(Solaris IPv6)
dnl ----------
dnl Linux IPv6
dnl ----------
  elif test x"$opsys" = x"gnu-linux"; then
    AC_DEFINE(LINUX_IPV6,1,Linux IPv6 stack)
    AC_MSG_RESULT(Linux IPv6)
  else
    AC_MSG_ERROR([Failed to detect IPv6 stack])
  fi

dnl this is unconditial, for compatibility
AC_DEFINE(HAVE_IPV6,1,IPv6)

dnl ------------------
dnl IPv6 header checks
dnl ------------------
AC_CHECK_HEADERS([netinet6/in6.h netinet/in6_var.h netinet/icmp6.h \
	netinet6/in6_var.h netinet6/nd6.h], [], [],
	QUAGGA_INCLUDES)

m4_define([QUAGGA_INCLUDES],dnl
QUAGGA_INCLUDES
[#if HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#endif
#if HAVE_NETINET_IN6_VAR_H
#include <netinet/in6_var.h>
#endif
#if HAVE_NETINET_ICMP6_H
# include <netinet/icmp6.h>
#endif
#if HAVE_NETINET6_IN6_VAR_H
# include <netinet6/in6_var.h>
#endif
#if HAVE_NETINET6_ND6_H
# include <netinet6/nd6.h>
#endif
])dnl

dnl disable doc check
if test "${enable_doc}" = "no";then
  DOC=""
else
  DOC="doc"
fi

AC_CHECK_LIB(c, inet_ntop, [AC_DEFINE(HAVE_INET_NTOP,,inet_ntop)])
AC_CHECK_LIB(c, inet_pton, [AC_DEFINE(HAVE_INET_PTON,,inet_pton)])
AC_CHECK_LIB(crypt, crypt)
AC_CHECK_LIB(resolv, res_init)

dnl ---------------------------
dnl Daemon declaration
dnl ---------------------------

ZRPCD="zrpcd"
AC_SUBST(ZRPCD)


dnl ---------------------------
dnl sockaddr and netinet checks
dnl ---------------------------
AC_CHECK_TYPES([struct sockaddr, struct sockaddr_in,
	struct sockaddr_in6, struct sockaddr_un, struct sockaddr_dl,
	socklen_t, struct vifctl, struct mfcctl, struct sioc_sg_req,
	vifi_t, struct sioc_vif_req, struct igmpmsg,
	struct ifaliasreq, struct if6_aliasreq, struct in6_aliasreq,
	struct nd_opt_adv_interval, struct rt_addrinfo,
	struct nd_opt_homeagent_info, struct nd_opt_adv_interval],
	[], [], QUAGGA_INCLUDES)

AC_CHECK_MEMBERS([struct sockaddr.sa_len,
	struct sockaddr_in.sin_len, struct sockaddr_un.sun_len,
	struct sockaddr_in6.sin6_scope_id,
	struct sockaddr_dl.sdl_len,
	struct if6_aliasreq.ifra_lifetime,
	struct nd_opt_adv_interval.nd_opt_ai_type],
	[], [], QUAGGA_INCLUDES)

dnl ---------------------------
dnl IRDP/pktinfo/icmphdr checks
dnl ---------------------------
AC_CHECK_TYPES([struct in_pktinfo], 
 [AC_CHECK_TYPES([struct icmphdr],
   [if test "${enable_irdp}" != "no"; then
      AC_DEFINE(HAVE_IRDP,, IRDP)
    fi],
   [if test "${enable_irdp}" = "yes"; then
      AC_MSG_ERROR(['IRDP requires in_pktinfo at the moment!'])
    fi], [QUAGGA_INCLUDES])],
 [if test "${enable_irdp}" = "yes"; then
    AC_MSG_ERROR(['IRDP requires in_pktinfo at the moment!'])
  fi], [QUAGGA_INCLUDES])

dnl -----------------------
dnl checking for IP_PKTINFO
dnl -----------------------
AC_MSG_CHECKING(for IP_PKTINFO)
AC_TRY_COMPILE([#include <netdb.h>], [
  int opt = IP_PKTINFO;
], [
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_IP_PKTINFO, 1, [Have IP_PKTINFO])
], [
  AC_MSG_RESULT(no)
])

dnl --------------------------------------
dnl checking for clock_time monotonic struct and call
dnl --------------------------------------
AC_CHECK_DECL(CLOCK_MONOTONIC,
	[AC_CHECK_LIB(rt, clock_gettime, [LIBS="$LIBS -lrt"])
	 AC_DEFINE(HAVE_CLOCK_MONOTONIC,, Have monotonic clock)
], [AC_MSG_RESULT(no)], [QUAGGA_INCLUDES])

dnl ---------------------------------------------------------------------------
dnl http://www.gnu.org/software/autoconf-archive/ax_sys_weak_alias.html
dnl Check for and set one of the following = 1
dnl   HAVE_SYS_WEAK_ALIAS_ATTRIBUTE
dnl   HAVE_SYS_WEAK_ALIAS_PRAGMA
dnl   HAVE_SYS_WEAK_ALIAS_HPSECONDARY
dnl   HAVE_SYS_WEAK_ALIAS_CRIDUPLICATE
dnl If any scheme is found, set
dnl   HAVE_SYS_WEAK_ALIAS=1
dnl The following variable is set to text value
dnl   WEAK_ALIAS = "attribute" || "pragma" || "hpsecondary" || "criduplicate" || "no"
dnl If weak alias can cross object file boundaries
dnl   WEAK_ALIAS_CROSSFILE = "yes" || "no"
dnl ---------------------------------------------------------------------------
AX_SYS_WEAK_ALIAS

dnl ---------------------------
dnl check for glibc 'backtrace'
dnl --------------------------- 
if test x"${enable_backtrace}" != x"no" ; then
  backtrace_ok=no
  AC_CHECK_HEADER([execinfo.h], [
    AC_SEARCH_LIBS([backtrace], [execinfo], [
      AC_DEFINE(HAVE_GLIBC_BACKTRACE,,[Glibc backtrace])
      AC_DEFINE(HAVE_STACK_TRACE,,[Stack symbol decoding])
      backtrace_ok=yes
    ],, [-lm])
  ])

  if test x"${enable_backtrace}" = x"yes" -a x"${backtrace_ok}" = x"no"; then
    dnl user explicitly requested backtrace but we failed to find support
    AC_MSG_FAILURE([failed to find backtrace support])
  fi
fi

dnl -----------------------------------------
dnl check for malloc mallinfo struct and call
dnl this must try and link using LIBS, in
dnl order to check no alternative allocator
dnl has been specified, which might not provide
dnl mallinfo, e.g. such as Umem on Solaris.
dnl -----------------------------------------
AC_CHECK_HEADER([malloc.h],
 [AC_MSG_CHECKING(whether mallinfo is available)
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <malloc.h>]],
                        [[struct mallinfo ac_x; ac_x = mallinfo ();]])],
      [AC_MSG_RESULT(yes)
       AC_DEFINE(HAVE_MALLINFO,,mallinfo)],
       AC_MSG_RESULT(no)
  )
 ], [], QUAGGA_INCLUDES)

dnl ------
dnl zeromq
dnl ------
if test "$with_zeromq" != "no"; then
   AC_SEARCH_LIBS([zmq_msg_init], [zmq], [
   AC_DEFINE(HAVE_ZEROMQ, 1, [Enable ZeroMQ support])
   AC_DEFINE(ZEROMQ_CFLAGS, $(ZEROMQ_CFLAGS), [cflags for zeromq])
   AC_DEFINE(ZEROMQ_LIBS, $(ZEROMQ_LIBS), [ldflags for zeromq])
   ZEROMQ=true
   AC_SUBST(ZEROMQ_CFLAGS)
   AC_SUBST(ZEROMQ_LIBS)
   ], [
   AC_MSG_ERROR([configuration specifies --with-zeromq but libzmq was not found])
   ])
fi

dnl ------
dnl capnproto
dnl ------
if test "$with_ccapnproto" != "no"; then
  AC_SEARCH_LIBS([capn_init_malloc], [capnp_c], [
    AC_DEFINE(HAVE_CCAPNPROTO, 1, [Enable c-capnproto support])
    AC_DEFINE(CAPN_C_CFLAGS, $(CAPN_C_CFLAGS), [cflags for c-capnproto])
    AC_DEFINE(CAPN_C_LIBS, $(CAPN_C_LIBS), [ldflags for c-capnproto])
    CCAPNPROTO=true
    AC_SUBST(CAPN_C_CFLAGS)
    AC_SUBST(CAPN_C_LIBS)
  ], [
   AC_MSG_ERROR([ccapnproto needed but libcapnp_c was not found])
  ])
fi

dnl ------
dnl quagga
dnl ------
if test "$with_quagga" != "no"; then
  AC_SEARCH_LIBS([vty_init], [zebra], [
    AC_DEFINE(HAVE_QUAGGA, 1, [Enable quagga support])
    AC_DEFINE(QUAGGA_CFLAGS, $(QUAGGA_CFLAGS), [cflags for quagga])
    AC_DEFINE(QUAGGA_LIBS, $(QUAGGA_LIBS), [ldflags for quagga])
    QUAGGA=true
    AC_SUBST(QUAGGA_CFLAGS)
    AC_SUBST(QUAGGA_LIBS)
  ], [
   AC_MSG_ERROR([quagga needed but libzebra library was not found])
  ])
fi

dnl -----------
dnl thrift
dnl -----------
if test "${with_zrpcd}" != "no";then
  PKG_CHECK_MODULES(THRIFT, [thrift_c_glib >= 0.9.3], [
    AC_DEFINE(HAVE_THRIFT, 1, [Enable Thrift support])
    AC_CHECK_PROG([THRIFT_PRG],[thrift],[thrift],[not-in-PATH])
    if test "x$THRIFT_PRG" = "xnot-in-PATH" ; then
	AC_MSG_ERROR([Apache Thrift is required for thrift support.])
    fi
    THRIFT=true
  ], [
    AC_MSG_ERROR([zrpcd requires thrift, but thrift not found or too old (0.9.3 or higher required)])
  ])
fi

# version 1 = L3VPN - default
# version 2 = EVPN + L3VPN 
# version 3 = IPv6 + EVPN + L3VPN
AC_ARG_WITH(thrift-version,
[  --with-thrift-version           Set thrift version for use in zrpcd.])
if test "x$with_thrift_version" != "x" ; then
  THRIFTVERSION="$with_thrift_version" ;
else
  THRIFTVERSION="1" ;
fi

dnl -----------------------------------
dnl Add extra version string to package
dnl name, string and version fields.
dnl -----------------------------------
if test "x${THRIFTVERSION}" = "x1" ; then
  THRIFT_VERSION="1"
  AM_CONDITIONAL([HAVE_THRIFT_V1], [test xtrue = xtrue])
  AC_DEFINE(HAVE_THRIFT_V1, [1], [Version for Thrift])
else
  AM_CONDITIONAL([HAVE_THRIFT_V1], [test x = xtrue])
fi
if test "x${THRIFTVERSION}" = "x2" ; then
  AM_CONDITIONAL([HAVE_THRIFT_V2], [test xtrue = xtrue])
  AC_DEFINE(HAVE_THRIFT_V2, [1], [Version for Thrift])
else
  AM_CONDITIONAL([HAVE_THRIFT_V2], [test x = xtrue])
fi
if test "x${THRIFTVERSION}" = "x3" ; then
  AM_CONDITIONAL([HAVE_THRIFT_V3], [test xtrue = xtrue])
  AC_DEFINE(HAVE_THRIFT_V3, [1], [Version for Thrift])
else
  AM_CONDITIONAL([HAVE_THRIFT_V3], [test x = xtrue])
fi
if test "x${THRIFTVERSION}" = "x4" ; then
  AM_CONDITIONAL([HAVE_THRIFT_V4], [test xtrue = xtrue])
  AC_DEFINE(HAVE_THRIFT_V3, [1], [Version for Thrift])
  AC_DEFINE(HAVE_THRIFT_V4, [1], [Version for Thrift])
else
  AM_CONDITIONAL([HAVE_THRIFT_V4], [test x = xtrue])
fi

dnl -----------
dnl GLIB2
dnl -----------
if test "${with_glib2}" != "no";then
  PKG_CHECK_MODULES(GLIB2, glib-2.0 >= 2.22.5, [
    AC_DEFINE(HAVE_GLIB2, 1, [Enable glib-2.0 support])
    GLIB2=true
  ], [
    AC_MSG_ERROR([zrpcd requires glib-2.0, but glib-2.0 not found or too old (2.22.5 or higher required)])
  ])
fi

dnl -----------
dnl GOBJECT2
dnl -----------
if test "${with_gobject2}" != "no";then
  PKG_CHECK_MODULES(GOBJECT2, gobject-2.0 >= 2.22.5, [
    AC_DEFINE(HAVE_GLIB2, 1, [Enable gobject-2.0 support])
    GOBJECT2=true
  ], [
    AC_MSG_ERROR([zrpcd requires gobject-2.0, but gobject-2.0 not found or too old (2.22.5 or higher required)])
  ])
fi

AM_CONDITIONAL([HAVE_QTHRIFT], test "x$THRIFT" = "xtrue")
AM_CONDITIONAL([HAVE_GLIB2], test "x$GLIB2" = "xtrue")
AM_CONDITIONAL([HAVE_GOBJECT2], test "x$GOBJECT2" = "xtrue")
AM_CONDITIONAL([HAVE_ZEROMQ], test "x$ZEROMQ" = "xtrue")
AM_CONDITIONAL([HAVE_CCAPNPROTO], test "x$CCAPNPROTO" = "xtrue")
AM_CONDITIONAL([HAVE_QUAGGA], test "x$QUAGGA" = "xtrue")

dnl ----------
dnl configure date
dnl ----------
CONFDATE=`date '+%Y%m%d'`
AC_SUBST(CONFDATE)

dnl ------------------------------
dnl set paths for state directory
dnl ------------------------------
AC_MSG_CHECKING(directory to use for state file)
if test "${prefix}" = "NONE"; then
  quaggazrpc_statedir_prefix="";
else
  quaggazrpc_statedir_prefix=${prefix}
fi
if test "${localstatedir}" = '${prefix}/var'; then
  for QUAGGAZRPC_STATE_DIR in ${quaggazrpc_statedir_prefix}/var/run dnl
			${quaggazrpc_statedir_prefix}/var/adm dnl
			${quaggazrpc_statedir_prefix}/etc dnl
			/var/run	dnl
                        /var/adm	dnl
                        /etc		dnl
                        /dev/null;
  do
    test -d $QUAGGAZRPC_STATE_DIR && break
  done
  quaggazrpc_statedir=$QUAGGAZRPC_STATE_DIR
else
  quaggazrpc_statedir=${localstatedir}
fi
if test $quaggazrpc_statedir = "/dev/null"; then
    AC_MSG_ERROR('STATE DIRECTORY NOT FOUND! FIX OR SPECIFY --localstatedir!')
fi
AC_MSG_RESULT(${quaggazrpc_statedir})
AC_SUBST(quaggazrpc_statedir)


AC_DEFINE_UNQUOTED(ZRPC_VTYSH_PATH, "$quagga_statedir/zrpcd.vty",qthrift vty socket)

dnl -------------------------------
dnl Quagga sources should always be 
dnl current wrt interfaces. Dont
dnl allow deprecated interfaces to
dnl be exposed.
dnl -------------------------------
AC_DEFINE(QUAGGA_NO_DEPRECATED_INTERFACES, 1, Hide deprecated interfaces)

dnl ---------------------------
dnl Check htonl works correctly
dnl ---------------------------
AC_MSG_CHECKING(for working htonl)
AC_CACHE_VAL(ac_cv_htonl_works,
 [AC_LINK_IFELSE([AC_LANG_PROGRAM([QUAGGA_INCLUDES],[htonl (0);])],
 		[ac_cv_htonl_works=yes], [ac_cv_htonl_works=no])
 ]
)
AC_MSG_RESULT($ac_cv_htonl_works)

AC_CONFIG_FILES([Makefile zrpcd/Makefile 
	  zrpcd/version.h])

## Hack, but working solution to avoid rebuilding of quagga.info.
## It's already in CVS until texinfo 4.7 is more common.
AC_OUTPUT

echo "
Quagga ZRPC configuration
--------------------
quagga zrpc version      : ${PACKAGE_VERSION}
host operating system   : ${host_os}
source code location    : ${srcdir}
compiler                : ${CC}
compiler flags          : ${CFLAGS}
make                    : ${MAKE-make}
linker flags            : ${LDFLAGS} ${LIBS} ${LIBCAP} ${LIBREADLINE}
state file directory    : ${quagga_statedir}
config file directory   : `eval echo \`echo ${sysconfdir}\``
example directory       : `eval echo \`echo ${exampledir}\``
user to run as		: ${enable_user}
group to run as		: ${enable_group}
group for vty sockets	: ${enable_vty_group}
config file mask        : ${enable_configfile_mask}
log file mask           : ${enable_logfile_mask}

The above user and group must have read/write access to the state file
directory and to the config files in the config file directory."

if test x"$quagga_cv_gnu_make" = x"no"; then echo "
Warning: The ${MAKE-make} programme detected, either in your path or
via the MAKE variable, is not GNU Make. GNU make may be installed as
gmake on some systems. and is required to complete a build of Quagga
" > /dev/stderr 
fi
