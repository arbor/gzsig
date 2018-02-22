/*
 * kn.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@arbor.net>
 * Copyright (c) 2001 Arbor Networks, Inc.
 *
 * $Id: kn.c,v 1.1.1.1 2001/12/15 00:20:46 dirt Exp $
 */

#include <sys/types.h>
#include <sys/uio.h>

#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <keynote.h>

#include "pkey.h"
#include "kn.h"

static int
_kn_load(int type, struct pkey *k, struct iovec *iov)
{
	struct keynote_deckey dc;
	char *s;

	s = (char *)iov->iov_base;

	if ((s = kn_get_string(s)) == NULL)
		return (-1);
	
	if (kn_decode_key(&dc, s, type) < 0)
		return (-1);

	switch (dc.dec_algorithm) {
	case KEYNOTE_ALGORITHM_RSA:
		k->type = PKEY_RSA;
		k->data = dc.dec_key;
		break;
	case KEYNOTE_ALGORITHM_DSA:
		k->type = PKEY_DSA;
		k->data = dc.dec_key;
		break;
	default:
		kn_free_key(&dc);
		return (-1);
	}
	return (0);
};

int
kn_load_private(struct pkey *k, struct iovec *iov)
{
	return (_kn_load(KEYNOTE_PRIVATE_KEY, k, iov));
}

int
kn_load_public(struct pkey *k, struct iovec *iov)
{
	return (_kn_load(KEYNOTE_PUBLIC_KEY, k, iov));
}
