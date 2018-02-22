/*
 * x509.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@arbor.net>
 * Copyright (c) 2001 Arbor Networks, Inc.
 *
 * $Id: x509.h,v 1.1.1.1 2001/12/15 00:20:46 dirt Exp $
 */

#ifndef X509_H
#define X509_H

int	x509_load_public(struct pkey *k, struct iovec *iov);
int	x509_load_private(struct pkey *k, struct iovec *iov);

#endif /* X509_H */
