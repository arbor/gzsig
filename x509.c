/*
 * x509.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@arbor.net>
 * Copyright (c) 2001 Arbor Networks, Inc.
 *
 * $Id: x509.c,v 1.1.1.1 2001/12/15 00:20:46 dirt Exp $
 */

#include <sys/types.h>
#include <sys/uio.h>

#include <openssl/ssl.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pkey.h"
#include "x509.h"

#define X509_CERT_MAGIC	"-----BEGIN CERTIFICATE-----"
#define X509_RSA_MAGIC	"-----BEGIN RSA PRIVATE KEY-----"
#define X509_DSA_MAGIC	"-----BEGIN DSA PRIVATE KEY-----"

static int
_x509_passwd_cb(char *buf, int size, int rwflag, void *u)
{
	char *p;
	
	p = getpass("Enter passphrase: ");
	strncpy(buf, p, size - 1);
	buf[size - 1] = '\0';
	memset(p, 0, strlen(p));

	return (strlen(buf));
}

int
x509_load_public(struct pkey *k, struct iovec *iov)
{
	BIO *bio;
	X509 *cert;
	EVP_PKEY *evp;
	
	if (strncmp((char *)iov->iov_base, X509_CERT_MAGIC,
	    strlen(X509_CERT_MAGIC)) != 0)
		return (-1);
	
	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		return (-1);
	
	if (BIO_write(bio, iov->iov_base, iov->iov_len + 1) <= 0) {
		BIO_free(bio);
		return (-1);
	}
	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);
	
	if (cert == NULL)
		return (-1);

	evp = X509_get_pubkey(cert);
	
	if (evp->type == EVP_PKEY_RSA) {
		k->type = PKEY_RSA;
		k->data = (void *)RSAPublicKey_dup(evp->pkey.rsa);
	} else if (evp->type == EVP_PKEY_DSA) {
		k->type = PKEY_DSA;
		k->data = (void *)evp->pkey.dsa;
		evp->pkey.dsa = NULL;			/* XXX */
	} else {
		X509_free(cert);
		return (-1);
	}
	X509_free(cert);
	
	return (0);
}

int
x509_load_private(struct pkey *k, struct iovec *iov)
{
	BIO *bio;
	EVP_PKEY *evp;
	
	if (strncmp((char *)iov->iov_base, X509_RSA_MAGIC,
	        strlen(X509_RSA_MAGIC)) != 0 &&
	    strncmp((char *)iov->iov_base, X509_DSA_MAGIC,
		strlen(X509_DSA_MAGIC)) != 0) {
		return (-1);
	}
	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		return (-1);
	
	if (BIO_write(bio, iov->iov_base, iov->iov_len + 1) <= 0) {
		BIO_free(bio);
		return (-1);
	}
	evp = PEM_read_bio_PrivateKey(bio, NULL, _x509_passwd_cb, NULL);

	BIO_free(bio);
	
	if (evp == NULL)
		return (-1);
	
	if (evp->type == EVP_PKEY_RSA) {
		k->type = PKEY_RSA;
		k->data = (void *)evp->pkey.rsa;
		evp->pkey.rsa = NULL;			/* XXX */
	} else if (evp->type == EVP_PKEY_DSA) {
		k->type = PKEY_DSA;
		k->data = (void *)evp->pkey.dsa;
		evp->pkey.dsa = NULL;			/* XXX */
	} else {
		EVP_PKEY_free(evp);
		return (-1);
	}
	EVP_PKEY_free(evp);
	
	return (0);
}
