//go:build darwin && cgo

#ifndef GRANTD_LA_DARWIN_H
#define GRANTD_LA_DARWIN_H

#include <stddef.h>

// Result codes of gd_la_evaluate.
#define GD_LA_OK 0           // user authenticated
#define GD_LA_FAILED 1       // evaluation failed; *code is the LAError code
#define GD_LA_UNAVAILABLE 2  // canEvaluatePolicy said no; *code is the NSError code
#define GD_LA_BAD_INPUT 3    // reason was not valid UTF-8 / empty
#define GD_LA_FOREIGN 4      // failure outside LAErrorDomain; *code is the NSError code

// 1 if a window-server login session exists (CGSessionCopyCurrentDictionary).
int gd_has_gui_session(void);

// Handle lifecycle: a retained LAContext.
void *gd_la_new(void);
void gd_la_free(void *h);
// Safe to call from another thread while gd_la_evaluate blocks; the pending
// evaluation then fails with LAErrorAppCancel.
void gd_la_invalidate(void *h);

// Blocks until the user decides. Runs inside an autorelease pool.
int gd_la_evaluate(void *h, const char *reason, const char *cancelTitle,
                   int *code, char *msg, size_t msgLen);

#endif
