/*
 * gzsig.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@arbor.net>
 * Copyright (c) 2001 Arbor Networks, Inc.
 *
 * $Id: gzsig.c,v 1.1.1.1 2001/12/15 00:20:46 dirt Exp $
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gzsig-int.h>

#include "gzip.h"
#include "pkey.h"

#define GZSIG_ID		"GS"
#define GZSIG_VERSION		1

enum gzsig_result {
	GZSIG_OK = 0,
	GZSIG_BADSIG,
	GZSIG_NOSIG,
	GZSIG_EINVAL,
	GZSIG_ERR
};

struct gzsig_data {
	u_char			version;
	u_char			signature[BUFSIZ - 1];
};

struct gzsig_hdr {
	struct gzip_header	gh;
	struct gzip_xfield	gx;
	struct gzsig_data	gd;
	char			fname[MAXPATHLEN];
	char			fcomment[BUFSIZ];
};

#define pletoh16(p)	((uint16_t)		\
	((uint16_t)*((u_char *)p + 1) << 8 |	\
	(uint16_t)*((u_char *)p + 0) << 0))

#define phtole16(p)	pletoh16(p)

static int
_fread_gzsig_hdr(FILE *fp, struct gzsig_hdr *hdr)
{
	u_int i;

	memset(hdr, 0, sizeof(*hdr));
	
	/* Read gzip header. */
	if (fread(&hdr->gh, 1, GZIP_HEADER_LEN, fp) != GZIP_HEADER_LEN) {
		warn("Couldn't read gzip header");
		return (GZSIG_EINVAL);
	}
	if (memcmp(hdr->gh.magic, GZIP_MAGIC, sizeof(hdr->gh.magic)) != 0) {
		warnx("Bad gzip magic - not a gzip file?");
		return (GZSIG_EINVAL);
	}
	if ((hdr->gh.flags & GZIP_FCONT) || (hdr->gh.flags & GZIP_FENCRYPT)) {
		warnx("Multi-part / encrypted gzip files not supported");
		return (GZSIG_EINVAL);
	}
	/* Read signature, if any. */
	if (hdr->gh.flags & GZIP_FEXTRA) {
		if (fread(&hdr->gx, GZIP_XFIELD_LEN, 1, fp) != 1) {
			warn("Couldn't read extra field");
			return (GZSIG_EINVAL);
		}
		i = pletoh16(&hdr->gx.subfield.len);
		
		/* XXX - only handle single signature. */
		if (pletoh16(&hdr->gx.len) != GZIP_SUBFIELD_LEN + i) {
			warnx("Multiple subfields not supported");
			return (GZSIG_EINVAL);
		}
		/* XXX - punt on any extra field but our own */
		if (memcmp(hdr->gx.subfield.id, GZSIG_ID, 
		    sizeof(hdr->gx.subfield.id)) != 0 ||
		    i > sizeof(hdr->gd)) {
			warnx("Non-signature subfields not supported");
			return (GZSIG_EINVAL);
		}
		if (fread(&hdr->gd, i, 1, fp) != 1) {
			warn("Couldn't read signature data");
			return (GZSIG_ERR);
		}
	}	
	/* Read options, if any. */
	if (hdr->gh.flags & GZIP_FNAME) {
		for (i = 0; i < sizeof(hdr->fname); i++)
			if ((hdr->fname[i] = getc(fp)) == '\0')
				break;
	}
	if (hdr->gh.flags & GZIP_FCOMMENT) {
		for (i = 0; i < sizeof(hdr->fcomment); i++)
			if ((hdr->fcomment[i] = getc(fp)) == '\0')
				break;
	}
	if (ferror(fp) || feof(fp)) {
		warn("Error reading gzip header");
		return (GZSIG_ERR);
	}
	return (GZSIG_OK);
}

static FILE *
_fmkstemp(FILE *fin, char *template)
{
	FILE *fout;
	struct stat st;
	int fd;

	if (fstat(fileno(fin), &st) < 0 ||
	    (fd = mkstemp(template)) < 0)
		return (NULL);
	
	if ((fout = fdopen(fd, "w")) != NULL) {
		if (fchmod(fd, st.st_mode) < 0 ||
		    fchown(fd, st.st_uid, st.st_gid) < 0) {
			fclose(fout);
			fout = NULL;
		}
	}
	return (fout);
}

static int
_sign_file(pkey_t *pkey, char *filename)
{
	FILE *fin, *fout;
	SHA_CTX ctx;
	struct gzsig_hdr hdr;
	u_char digest[20], buf[8192];
	char tmpfile[MAXPATHLEN];
	long off;
	u_short len;
	int i, ret;
	
	if (strcmp(filename, "-") == 0) {
		filename = "stdin";
		fin = stdin;
		fout = stdout;
	} else if ((fin = fopen(filename, "r")) == NULL) {
		warn("Couldn't open %s", filename);
		return (GZSIG_ERR);
	} else {
		snprintf(tmpfile, sizeof(tmpfile), "%s.XXXXXX", filename);
		if ((fout = _fmkstemp(fin, tmpfile)) == NULL) {
			warn("Couldn't create tmpfile for %s", filename);
			fclose(fin);
			return (GZSIG_ERR);
		}
	}
	if ((ret = _fread_gzsig_hdr(fin, &hdr)) == GZSIG_OK) {
		if (hdr.gh.flags & GZIP_FEXTRA) {
			warnx("Overwriting existing signature on %s",
			    filename);
		}
		/* Compute signature over data and trailer. */
		off = ftell(fin);
		SHA1_Init(&ctx);
		while ((i = fread(buf, 1, sizeof(buf), fin)) > 0) {
			SHA1_Update(&ctx, buf, i);
		}
		SHA1_Final(digest, &ctx);
		fseek(fin, off, SEEK_SET);
		
		hdr.gd.version = GZSIG_VERSION;
		
		if ((i = pkey_sign(pkey, digest, sizeof(digest),
		    hdr.gd.signature, sizeof(hdr.gd.signature))) > 0) {
			/* Write out gzip header. */
			hdr.gh.flags |= GZIP_FEXTRA;
			fwrite(&hdr.gh, GZIP_HEADER_LEN, 1, fout);
			
			/* Write out signature. */
			memcpy(hdr.gx.subfield.id, GZSIG_ID,
			    sizeof(hdr.gx.subfield.id));
			len = 1 + i;
			hdr.gx.subfield.len = phtole16(&len);
			len += GZIP_SUBFIELD_LEN;
			hdr.gx.len = phtole16(&len);
			fwrite(&hdr.gx, GZIP_XFIELD_LEN, 1, fout);
			fwrite(&hdr.gd, 1 + i, 1, fout);
			
			/* Write out options, if any. */
			if (hdr.gh.flags & GZIP_FNAME)
				fwrite(hdr.fname, strlen(hdr.fname) + 1,
				    1, fout);
			if (hdr.gh.flags & GZIP_FCOMMENT)
				fwrite(hdr.fcomment, strlen(hdr.fcomment) + 1,
				    1, fout);
			
			/* Copy over data and trailer. */
			while ((i = fread(buf, 1, sizeof(buf), fin)) > 0) {
				fwrite(buf, i, 1, fout);
			}
			if (ferror(fin) || ferror(fout)) {
				warn("Error signing %s", filename);
				ret = GZSIG_ERR;
			}
		} else {
			warnx("Signing operation failed on %s", filename);
			ret = GZSIG_ERR;
		}
	} else
		warnx("Error reading gzip header from %s", filename);
	
	if (fin != stdin) {
		fclose(fin);
		fclose(fout);
		
		if (ret == GZSIG_OK) {
			if (rename(tmpfile, filename) < 0) {
				warn("Couldn't rename tmpfile to %s",
				    filename);
				ret = GZSIG_ERR;
			} else
				printf("Signed %s\n", filename);
		} else
			unlink(tmpfile);
	}
	return (ret);
}

static int
_verify_file(pkey_t *pkey, char *filename)
{
	FILE *fp;
	SHA_CTX ctx;
	struct gzsig_hdr hdr;
	u_char digest[20], buf[8192];
	int i, ret;
	
	if (strcmp(filename, "-") == 0) {
		fp = stdin;
		filename = "stdin";
	} else if ((fp = fopen(filename, "r")) == NULL) {
		warn("Couldn't open %s", filename);
		return (GZSIG_ERR);
	}
	if ((ret = _fread_gzsig_hdr(fp, &hdr)) == GZSIG_OK) {
		if (!(hdr.gh.flags & GZIP_FEXTRA)) {
			printf("No signature on %s\n", filename);
			ret = GZSIG_NOSIG;
		} else if (hdr.gd.version != GZSIG_VERSION) {
			warnx("Invalid gzsig version on %s: %d",
			    filename, hdr.gd.version);
			ret = GZSIG_EINVAL;
		} else {
			SHA1_Init(&ctx);
			while ((i = fread(buf, 1, sizeof(buf), fp)) > 0) {
				SHA1_Update(&ctx, buf, i);
			}
			SHA1_Final(digest, &ctx);

			i = pletoh16(&hdr.gx.subfield.len) - 1;
			if (pkey_verify(pkey, digest, sizeof(digest),
			    hdr.gd.signature, i) < 0) {
				printf("Bad signature on %s\n", filename);
				ret = GZSIG_BADSIG;
			} else
				printf("Good signature on %s\n", filename);
		}
	} else
		warnx("Error reading gzip header from %s", filename);
	
	fclose(fp);
	return (ret);
}

static void
usage(void)
{
	fprintf(stderr, "Usage: gzsig sign <privkey> <file> ...\n"
	                "       gzsig verify <pubkey> <file> ...\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	pkey_t *pkey;
	int i, ret = GZSIG_OK;
	
	while ((i = getopt(argc, argv, "h?")) != -1) {
		switch (i) {
		default:
			usage();
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc < 3)
		usage();
	
	OpenSSL_add_all_algorithms();
	
	if ((pkey = pkey_new()) == NULL)
		errx(1, "Couldn't initialize key handle");
	
	if (strcmp(argv[0], "sign") == 0) {
		if (pkey_load_private(pkey, argv[1]) < 0)
			errx(1, "Couldn't load private key from %s", argv[1]);
		for (i = 2; i < argc; i++) {
			ret = _sign_file(pkey, argv[i]);
		}
	} else if (strcmp(argv[0], "verify") == 0) {
		if (pkey_load_public(pkey, argv[1]) < 0)
			errx(1, "Couldn't load public key from %s", argv[1]);
		for (i = 2; i < argc; i++) {
			ret = _verify_file(pkey, argv[i]);
		}
	} else
		usage();
	
	pkey = pkey_free(pkey);
	
	exit(ret);
}
