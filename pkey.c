/*
 * pkey.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@arbor.net>
 * Copyright (c) 2001 Arbor Networks, Inc.
 *
 * $Id: pkey.c,v 1.1.1.1 2001/12/15 00:20:46 dirt Exp $
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <openssl/ssl.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "pkey.h"
#ifdef HAVE_KEYNOTE
#include "kn.h"
#endif
#include "ssh.h"
#include "x509.h"

typedef int (*pkey_loader)(struct pkey *k, struct iovec *iov);

static pkey_loader pubkey_loaders[] = {
#ifdef HAVE_KEYNOTE
	kn_load_public,
#endif
	ssh_load_public,
	x509_load_public,
	NULL
};

static pkey_loader privkey_loaders[] = {
#ifdef HAVE_KEYNOTE
	kn_load_private,
#endif
	ssh_load_private,
	x509_load_private,
	NULL
};

static int
_load_file(const char *filename, struct iovec *iov)
{
	struct stat st;
	int fd, ret = -1;
	
	if ((fd = open(filename, O_RDONLY)) < 0)
		return (ret);
	
	if (fstat(fd, &st) == 0) {
		if (st.st_size > 0 && (iov->iov_base =
		    malloc(st.st_size + 1)) != NULL) {
			iov->iov_len = st.st_size;
			if (read(fd, iov->iov_base, iov->iov_len) ==
			    iov->iov_len) {
				((char *)iov->iov_base)[iov->iov_len] = '\0';
				ret = 0;
			}
		}
	}
	close(fd);
	
	return (ret);
}

struct pkey *
pkey_new(void)
{
	struct pkey *k;

	if ((k = calloc(sizeof(*k), 1)) == NULL)
		return (NULL);

	return (k);
}

int
pkey_load_private(struct pkey *k, const char *filename)
{
	struct iovec iov;
	int i, ret = -1;
	
	if (_load_file(filename, &iov) < 0)
		return (ret);

	for (i = 0; privkey_loaders[i] != NULL; i++) {
		if (privkey_loaders[i](k, &iov) == 0)
			ret = 0;
	}
	free(iov.iov_base);
	
	return (ret);
}

int
pkey_load_public(struct pkey *k, const char *filename)
{
	struct iovec iov;
	int i, ret = -1;

	if (_load_file(filename, &iov) < 0)
		return (ret);

	for (i = 0; pubkey_loaders[i] != NULL; i++) {
		if (pubkey_loaders[i](k, &iov) == 0)
			ret = 0;
	}
	free(iov.iov_base);
	
	return (ret);
}

int
pkey_sign(struct pkey *k, u_char *msg, int mlen, u_char *sig, int slen)
{
	switch (k->type) {
	case PKEY_RSA:
		if (RSA_size((RSA *)k->data) > slen) {
			warnx("RSA modulus too large: %d bits",
			    RSA_size((RSA *)k->data));
			return (-1);
		}
		if (RSA_sign(NID_sha1, msg, mlen, sig, &slen,
		    (RSA *)k->data) <= 0)
			return (-1);
		break;
	case PKEY_DSA:
		if (DSA_size((DSA *)k->data) > slen) {
			warnx("DSA signature size too large: %d bits",
			    DSA_size((DSA *)k->data));
			return (-1);
		}
		if (DSA_sign(NID_sha1, msg, mlen, sig, &slen,
		    (DSA *)k->data) <= 0)
			return (-1);
		break;
	default:
		warnx("Unknown key type: %d", k->type);
		return (-1);
	}
	return (slen);
}

int
pkey_verify(struct pkey *k, u_char *msg, int mlen, u_char *sig, int slen)
{
	switch (k->type) {
		
	case PKEY_RSA:
		if (RSA_verify(NID_sha1, msg, mlen,
		    sig, slen, (RSA *)k->data) <= 0)
			return (-1);
		break;
		
	case PKEY_DSA:
		if (DSA_verify(NID_sha1, msg, mlen,
		    sig, slen, (DSA *)k->data) <= 0) 
			return (-1);
		break;
		
	default:
		warnx("Unknown key type: %d", k->type);
		return (-1);
	}
	return (slen);
}

struct pkey *
pkey_free(struct pkey *k)
{
	if (k->type == PKEY_RSA)
		RSA_free((RSA *)k->data);
	else if (k->type == PKEY_DSA)
		DSA_free((DSA *)k->data);
	else if (k->data != NULL)
		free(k->data);
	free(k);
	return (NULL);
}
