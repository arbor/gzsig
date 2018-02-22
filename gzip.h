/*
 * gzip.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@arbor.net>
 * Copyright (c) 2001 Arbor Networks, Inc.
 *
 * $Id: gzip.h,v 1.1.1.1 2001/12/15 00:20:46 dirt Exp $
 */

#ifndef GZIP_H
#define GZIP_H

/* RFC 1952 is b0rked! This is from gzip-1.2.4's algorithm.doc... */

/* Magic header */
#define GZIP_MAGIC		"\037\213"

/* Compression methods */
#define GZIP_MSTORED		0
#define GZIP_MCOMPRESS		1
#define GZIP_MPACKED		2
#define GZIP_MLZHED		3
#define GZIP_MDEFLATE		8

/* Flags */
#define GZIP_FTEXT		0x01
#define GZIP_FCONT		0x02	/* XXX - never set by gzip-1.2.4 */
#define GZIP_FEXTRA		0x04
#define GZIP_FNAME		0x08
#define GZIP_FCOMMENT		0x10
#define GZIP_FENCRYPT		0x20
#define GZIP_FRESERVED		0xC0

/*
 * NOTE: all length fields below are in little-endian byte order.
 */

#define GZIP_XFIELD_LEN		6
#define GZIP_SUBFIELD_LEN	4
#define GZIP_HEADER_LEN		10
#define GZIP_TRAILER_LEN	8

struct gzip_xfield {
	u_short	len;
	struct gzip_subfield {
		u_char	id[2];
		u_short	len;
#ifdef COMMENT_ONLY
		u_char	data[];
#endif
	} subfield;
};

struct gzip_header {
	u_char		magic[2];
	u_char		method;
	u_char		flags;
	u_char		mtime[4];
	u_char		xflags;
	u_char		os;
#ifdef COMMENT_ONLY
	/* Optional fields */
	u_char		part[2];		/* flags & GZIP_FCONT */
	struct gzip_xfield xfield;		/* flags & GZIP_FEXTRA */
	char		filename[];		/* flags & GZIP_FNAME */
	char		comment[];		/* flags & GZIP_FCOMMENT */
	u_char		encrypt_hdr[12];	/* flags & GZIP_FENCRYPT */
#endif
};

struct gzip_trailer {
	u_char		crc32[4];
	u_char		size[4];
};

#endif /* GZIP_H */
