/*
 * pkey.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@arbor.net>
 * Copyright (c) 2001 Arbor Networks, Inc.
 *
 * $Id: key.h,v 1.1.1.1 2001/12/15 00:20:46 dirt Exp $
 */

#ifndef PKEY_H
#define PKEY_H

enum pkey_type {
	PKEY_UNSPEC,
	PKEY_RSA,
	PKEY_DSA
};

struct pkey {
	int	 type;
	void	*data;
};

typedef struct pkey	pkey_t;

pkey_t	*pkey_new(void);
int	 pkey_load_public(pkey_t *k, const char *filename);
int	 pkey_load_private(pkey_t *k, const char *filename);
int	 pkey_sign(pkey_t *k, u_char *msg, int mlen, u_char *sig, int slen);
int	 pkey_verify(pkey_t *k, u_char *msg, int mlen, u_char *sig, int slen);
pkey_t	*pkey_free(pkey_t *k);

#endif /* PKEY_H */
