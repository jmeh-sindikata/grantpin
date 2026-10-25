//go:build darwin && cgo

#ifndef GRANTD_SEC_DARWIN_H
#define GRANTD_SEC_DARWIN_H

#include <stddef.h>
#include <stdint.h>

// gd_err carries a Security.framework failure. It never contains key material.
typedef struct {
	int32_t code;
	char msg[256];
} gd_err;

// Return codes: 0 ok/found, 1 not found, 2 duplicate, -1 error (see gd_err).

// Secure Enclave key (SecKeyRef is returned as an opaque, +1 retained pointer).
int gd_se_find(const char *tag, void **key, gd_err *e);
int gd_se_create(const char *tag, void **key, gd_err *e);
int gd_se_delete(const char *tag, gd_err *e);
// enc != 0: ECIES-encrypt to the public key of priv. enc == 0: decrypt with priv.
// *out is malloc'd; release with gd_free (which zeroes it).
int gd_se_crypt(int enc, void *priv, const uint8_t *in, size_t inLen,
                uint8_t **out, size_t *outLen, gd_err *e);

// Generic-password item (fallback KEK). dp != 0 uses the data-protection keychain.
// wantData == 0 only checks existence.
int gd_kc_get(const char *service, const char *account, int dp, int wantData,
              uint8_t **out, size_t *outLen, gd_err *e);
int gd_kc_add(const char *service, const char *account, int dp,
              const uint8_t *data, size_t len, gd_err *e);
int gd_kc_delete(const char *service, const char *account, int dp, gd_err *e);

void gd_release(void *cfobj);
// Zeroes then frees a buffer returned in *out.
void gd_free(uint8_t *p, size_t n);

#endif
