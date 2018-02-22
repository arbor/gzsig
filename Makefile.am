
AUTOMAKE_OPTIONS = foreign no-dependencies

INCLUDES = @KNINC@ @OPENSSL_INCLUDES@

bin_PROGRAMS = gzsig

gzsig_SOURCES = gzsig.c gzip.h pkey.h pkey.c ssh.h ssh.c x509.h x509.c
gzsig_LDADD = @LIBOBJS@ @KNLIB@ @OPENSSL_LDFLAGS@ @OPENSSL_LIBS@

man_MANS = gzsig.1

EXTRA_DIST = LICENSE err.h kn.h kn.c $(man_MANS)

DISTCLEANFILES = *~

