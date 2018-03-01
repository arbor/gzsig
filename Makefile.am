ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign no-dependencies

INCLUDES = @OPENSSL_INCLUDES@

bin_PROGRAMS = gzsig

gzsig_SOURCES = gzsig.c key.c sign.c ssh.c ssh2.c util.c verify.c x509.c
gzsig_LDADD = @LIBOBJS@ @OPENSSL_LDFLAGS@ @OPENSSL_LIBS@ -lresolv

man_MANS = gzsig.1

EXTRA_DIST = LICENSE $(man_MANS)

DISTCLEANFILES = *~

# avoid libtool bug with -static
gzsig-static: $(gzsig_OBJECTS) $(gzsig_DEPENDENCIES) $(EXTRA_gzsig_DEPENDENCIES) 
	@rm -f gzsig$(EXEEXT)
	$(AM_V_CCLD)$(LINK) $(gzsig_OBJECTS) $(gzsig_LDADD) $(LIBS) -Xcompiler -static -ldl
	cp gzsig-static /usr/local/bin

