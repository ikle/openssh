/* $OpenBSD: version.h,v 1.88 2020/09/27 07:22:05 djm Exp $ */

#define SSH_VERSION	"OpenSSH_8.4"

#define SSH_PORTABLE	"p1"
#define SSH_RELEASE_MINIMUM	SSH_VERSION SSH_PORTABLE
#ifdef SSH_EXTRAVERSION
#define SSH_RELEASE	SSH_RELEASE_MINIMUM " " SSH_EXTRAVERSION
#else
#define SSH_RELEASE	SSH_RELEASE_MINIMUM
#endif