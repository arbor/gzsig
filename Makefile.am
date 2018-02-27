
AUTOMAKE_OPTIONS = foreign no-dependencies

INCLUDES = @OPENSSL_INCLUDES@

bin_PROGRAMS = gzsig

gzsig_SOURCES = gzsig.c key.c sign.c ssh.c ssh2.c util.c verify.c x509.c
gzsig_LDADD = @LIBOBJS@ @KNLIB@ @OPENSSL_LDFLAGS@ @OPENSSL_LIBS@ -lresolv

man_MANS = gzsig.1

EXTRA_DIST = LICENSE $(man_MANS)

DISTCLEANFILES = *~

