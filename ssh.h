/*
 * ssh.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: ssh.h,v 1.1.1.1 2001/12/15 00:20:46 dirt Exp $
 */

#ifndef SSH_H
#define SSH_H

int	ssh_load_public(struct pkey *k, struct iovec *iov);
int	ssh_load_private(struct pkey *k, struct iovec *iov);

#endif /* SSH_H */
