//go:build darwin && cgo

#include "sec_darwin.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// ---- error helpers ---------------------------------------------------------

static void set_msg(gd_err *e, CFStringRef s) {
	if (s == NULL) {
		return;
	}
	if (!CFStringGetCString(s, e->msg, sizeof(e->msg), kCFStringEncodingUTF8)) {
		e->msg[0] = '\0';
	}
}

static void err_status(gd_err *e, OSStatus st) {
	e->code = (int32_t)st;
	e->msg[0] = '\0';
	CFStringRef s = SecCopyErrorMessageString(st, NULL);
	if (s != NULL) {
		set_msg(e, s);
		CFRelease(s);
	}
}

// err_cf consumes (releases) err.
static void err_cf(gd_err *e, CFErrorRef err) {
	e->msg[0] = '\0';
	if (err == NULL) {
		e->code = -1;
		strncpy(e->msg, "unknown error", sizeof(e->msg) - 1);
		return;
	}
	e->code = (int32_t)CFErrorGetCode(err);
	CFStringRef d = CFErrorCopyDescription(err);
	if (d != NULL) {
		set_msg(e, d);
		CFRelease(d);
	}
	CFRelease(err);
}

static CFStringRef cfstr(const char *s) {
	return CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
}

static CFDataRef cfdata_copy(const char *s) {
	return CFDataCreate(NULL, (const UInt8 *)s, (CFIndex)strlen(s));
}

static CFMutableDictionaryRef newdict(void) {
	return CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
	                                 &kCFTypeDictionaryValueCallBacks);
}

// copy_out copies d into a fresh malloc'd buffer.
static int copy_out(CFDataRef d, uint8_t **out, size_t *outLen, gd_err *e) {
	CFIndex n = CFDataGetLength(d);
	uint8_t *p = (uint8_t *)malloc(n > 0 ? (size_t)n : 1);
	if (p == NULL) {
		e->code = -1;
		strncpy(e->msg, "out of memory", sizeof(e->msg) - 1);
		return -1;
	}
	if (n > 0) {
		memcpy(p, CFDataGetBytePtr(d), (size_t)n);
	}
	*out = p;
	*outLen = (size_t)n;
	return 0;
}

// ---- Secure Enclave --------------------------------------------------------

// se_query builds the SecItem query that identifies the SE private key.
static CFMutableDictionaryRef se_query(const char *tag) {
	CFMutableDictionaryRef q = newdict();
	CFDataRef tagData = cfdata_copy(tag);
	CFDictionarySetValue(q, kSecClass, kSecClassKey);
	CFDictionarySetValue(q, kSecAttrApplicationTag, tagData);
	CFDictionarySetValue(q, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(q, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(q, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	CFRelease(tagData);
	return q;
}

int gd_se_find(const char *tag, void **key, gd_err *e) {
	CFMutableDictionaryRef q = se_query(tag);
	CFDictionarySetValue(q, kSecReturnRef, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef res = NULL;
	OSStatus st = SecItemCopyMatching(q, &res);
	CFRelease(q);
	if (st == errSecSuccess && res != NULL) {
		*key = (void *)res; // +1 retained
		return 0;
	}
	if (st == errSecItemNotFound) {
		return 1;
	}
	if (res != NULL) {
		CFRelease(res);
	}
	err_status(e, st);
	return -1;
}

int gd_se_create(const char *tag, void **key, gd_err *e) {
	int rc = -1;
	CFErrorRef cferr = NULL;
	CFStringRef label = NULL;
	CFDataRef tagData = NULL;
	SecAccessControlRef ac = NULL;
	CFMutableDictionaryRef priv = NULL, params = NULL;
	CFNumberRef bits = NULL;
	SecKeyRef k = NULL;

	// Protection class: this device only, available while unlocked. Flag:
	// private-key usage ONLY. No UserPresence/Biometry: presence is the
	// Approver's job and the daemon must unwrap at startup without UI.
	ac = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
	                                     kSecAccessControlPrivateKeyUsage, &cferr);
	if (ac == NULL) {
		err_cf(e, cferr);
		goto done;
	}

	int b = 256;
	bits = CFNumberCreate(NULL, kCFNumberIntType, &b);
	tagData = cfdata_copy(tag);
	label = cfstr("grantd vault key-encryption key");

	priv = newdict();
	CFDictionarySetValue(priv, kSecAttrIsPermanent, kCFBooleanTrue);
	CFDictionarySetValue(priv, kSecAttrApplicationTag, tagData);
	CFDictionarySetValue(priv, kSecAttrLabel, label);
	CFDictionarySetValue(priv, kSecAttrAccessControl, ac);

	params = newdict();
	CFDictionarySetValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(params, kSecAttrKeySizeInBits, bits);
	CFDictionarySetValue(params, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(params, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	CFDictionarySetValue(params, kSecPrivateKeyAttrs, priv);

	k = SecKeyCreateRandomKey(params, &cferr);
	if (k == NULL) {
		err_cf(e, cferr);
		goto done;
	}
	*key = (void *)k;
	rc = 0;
done:
	if (params) CFRelease(params);
	if (priv) CFRelease(priv);
	if (label) CFRelease(label);
	if (tagData) CFRelease(tagData);
	if (bits) CFRelease(bits);
	if (ac) CFRelease(ac);
	return rc;
}

int gd_se_delete(const char *tag, gd_err *e) {
	CFMutableDictionaryRef q = se_query(tag);
	OSStatus st = SecItemDelete(q);
	CFRelease(q);
	if (st == errSecSuccess) return 0;
	if (st == errSecItemNotFound) return 1;
	err_status(e, st);
	return -1;
}

int gd_se_crypt(int enc, void *privp, const uint8_t *in, size_t inLen,
                uint8_t **out, size_t *outLen, gd_err *e) {
	int rc = -1;
	CFErrorRef cferr = NULL;
	SecKeyRef priv = (SecKeyRef)privp;
	SecKeyRef pub = NULL;
	CFDataRef input = NULL, result = NULL;
	SecKeyAlgorithm alg = kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM;

	// No-copy view: we do not make an extra copy of the plaintext.
	input = CFDataCreateWithBytesNoCopy(NULL, in, (CFIndex)inLen, kCFAllocatorNull);
	if (input == NULL) {
		e->code = -1;
		strncpy(e->msg, "cannot wrap input", sizeof(e->msg) - 1);
		goto done;
	}
	if (enc) {
		pub = SecKeyCopyPublicKey(priv);
		if (pub == NULL) {
			e->code = -1;
			strncpy(e->msg, "cannot derive public key", sizeof(e->msg) - 1);
			goto done;
		}
		if (!SecKeyIsAlgorithmSupported(pub, kSecKeyOperationTypeEncrypt, alg)) {
			e->code = -1;
			strncpy(e->msg, "ECIES algorithm not supported by key", sizeof(e->msg) - 1);
			goto done;
		}
		result = SecKeyCreateEncryptedData(pub, alg, input, &cferr);
	} else {
		if (!SecKeyIsAlgorithmSupported(priv, kSecKeyOperationTypeDecrypt, alg)) {
			e->code = -1;
			strncpy(e->msg, "ECIES algorithm not supported by key", sizeof(e->msg) - 1);
			goto done;
		}
		result = SecKeyCreateDecryptedData(priv, alg, input, &cferr);
	}
	if (result == NULL) {
		err_cf(e, cferr);
		goto done;
	}
	rc = copy_out(result, out, outLen, e);
done:
	// result may hold plaintext (decrypt); immutable CFData cannot be zeroed
	// portably, so we just release it.
	if (result) CFRelease(result);
	if (input) CFRelease(input);
	if (pub) CFRelease(pub);
	return rc;
}

// ---- generic password (fallback KEK) --------------------------------------

static CFMutableDictionaryRef kc_query(const char *service, const char *account, int dp) {
	CFMutableDictionaryRef q = newdict();
	CFStringRef s = cfstr(service), a = cfstr(account);
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecAttrService, s);
	CFDictionarySetValue(q, kSecAttrAccount, a);
	if (dp) {
		CFDictionarySetValue(q, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	}
	CFRelease(s);
	CFRelease(a);
	return q;
}

int gd_kc_get(const char *service, const char *account, int dp, int wantData,
              uint8_t **out, size_t *outLen, gd_err *e) {
	CFMutableDictionaryRef q = kc_query(service, account, dp);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	if (wantData) {
		CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	} else {
		CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
	}
	CFTypeRef res = NULL;
	OSStatus st = SecItemCopyMatching(q, &res);
	CFRelease(q);
	if (st == errSecItemNotFound) {
		return 1;
	}
	if (st != errSecSuccess || res == NULL) {
		if (res != NULL) CFRelease(res);
		err_status(e, st);
		return -1;
	}
	int rc = 0;
	if (wantData) {
		if (CFGetTypeID(res) != CFDataGetTypeID()) {
			e->code = -1;
			strncpy(e->msg, "unexpected keychain result type", sizeof(e->msg) - 1);
			rc = -1;
		} else {
			rc = copy_out((CFDataRef)res, out, outLen, e);
		}
	}
	CFRelease(res);
	return rc;
}

int gd_kc_add(const char *service, const char *account, int dp,
              const uint8_t *data, size_t len, gd_err *e) {
	CFMutableDictionaryRef q = kc_query(service, account, dp);
	CFDataRef d = CFDataCreateWithBytesNoCopy(NULL, data, (CFIndex)len, kCFAllocatorNull);
	CFDictionarySetValue(q, kSecValueData, d);
	if (dp) {
		// kSecAttrAccessible applies on macOS only with the data-protection
		// keychain (SecItem.h). Never synchronise: kSecAttrSynchronizable unset.
		CFDictionarySetValue(q, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
	}
	OSStatus st = SecItemAdd(q, NULL);
	CFRelease(d);
	CFRelease(q);
	if (st == errSecSuccess) return 0;
	if (st == errSecDuplicateItem) return 2;
	err_status(e, st);
	return -1;
}

int gd_kc_delete(const char *service, const char *account, int dp, gd_err *e) {
	CFMutableDictionaryRef q = kc_query(service, account, dp);
	OSStatus st = SecItemDelete(q);
	CFRelease(q);
	if (st == errSecSuccess) return 0;
	if (st == errSecItemNotFound) return 1;
	err_status(e, st);
	return -1;
}

// ---- memory ----------------------------------------------------------------

void gd_release(void *obj) {
	if (obj != NULL) {
		CFRelease((CFTypeRef)obj);
	}
}

void gd_free(uint8_t *p, size_t n) {
	if (p == NULL) return;
	memset_s(p, n > 0 ? n : 1, 0, n > 0 ? n : 1);
	free(p);
}
