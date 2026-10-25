//go:build darwin && cgo

#import <CoreGraphics/CoreGraphics.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

#include <string.h>

#include "la_darwin.h"

int gd_has_gui_session(void) {
	CFDictionaryRef d = CGSessionCopyCurrentDictionary();
	if (d == NULL) {
		return 0;
	}
	CFRelease(d);
	return 1;
}

void *gd_la_new(void) {
	@autoreleasepool {
		LAContext *ctx = [[LAContext alloc] init];
		return (void *)CFBridgingRetain(ctx);
	}
}

void gd_la_free(void *h) {
	if (h != NULL) {
		CFRelease((CFTypeRef)h);
	}
}

void gd_la_invalidate(void *h) {
	if (h == NULL) {
		return;
	}
	@autoreleasepool {
		LAContext *ctx = (__bridge LAContext *)h;
		[ctx invalidate];
	}
}

static void copy_msg(NSError *err, char *msg, size_t msgLen) {
	if (msgLen == 0) {
		return;
	}
	msg[0] = '\0';
	NSString *d = err.localizedDescription;
	if (d != nil) {
		strncpy(msg, d.UTF8String, msgLen - 1);
		msg[msgLen - 1] = '\0';
	}
}

int gd_la_evaluate(void *h, const char *reasonC, const char *cancelC,
                   int *code, char *msg, size_t msgLen) {
	@autoreleasepool {
		if (h == NULL || reasonC == NULL || reasonC[0] == '\0') {
			return GD_LA_BAD_INPUT;
		}
		NSString *reason = [NSString stringWithUTF8String:reasonC];
		NSString *cancel = cancelC ? [NSString stringWithUTF8String:cancelC] : nil;
		if (reason == nil || reason.length == 0) {
			return GD_LA_BAD_INPUT; // evaluatePolicy throws on nil/empty reason
		}
		LAContext *ctx = (__bridge LAContext *)h;
		if (cancel != nil && cancel.length > 0) {
			ctx.localizedCancelTitle = cancel;
		}

		// Never fall through to "allow": if we cannot authenticate, say so.
		NSError *preErr = nil;
		if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&preErr]) {
			*code = preErr ? (int)preErr.code : -1;
			copy_msg(preErr, msg, msgLen);
			return GD_LA_UNAVAILABLE;
		}

		dispatch_semaphore_t sem = dispatch_semaphore_create(0);
		__block BOOL ok = NO;
		__block NSInteger ecode = 0;
		__block BOOL inDomain = YES;
		__block NSString *emsg = nil;
		[ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
		    localizedReason:reason
		              reply:^(BOOL success, NSError *err) {
			ok = success;
			if (!success) {
				ecode = err ? err.code : -1;
				inDomain = (err != nil) && [err.domain isEqualToString:LAErrorDomain];
				emsg = err.localizedDescription;
			}
			dispatch_semaphore_signal(sem);
		}];
		dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

		if (ok) {
			return GD_LA_OK;
		}
		*code = (int)ecode;
		if (msgLen > 0) {
			msg[0] = '\0';
			if (emsg != nil) {
				strncpy(msg, emsg.UTF8String, msgLen - 1);
				msg[msgLen - 1] = '\0';
			}
		}
		return inDomain ? GD_LA_FAILED : GD_LA_FOREIGN;
	}
}
