#import <objc/runtime.h>
#import <substrate.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// ── Chroma Plus Unlocker ──────────────────────────────────────────────────────
// Intercepts three layers of Chroma's auth stack:
//   1. NSUserDefaults  – spoof "spotipw.account.pass" so the cached pass is
//      always present and valid without a network check.
//   2. NSURLSession    – intercept /api/app/me and /api/app/auth/* responses
//      and replace them with a valid Plus payload.
//   3. ObjC property   – hook every class that exposes a `plus` or `plusLocked`
//      property and hard-wire them to YES / NO respectively.
// ─────────────────────────────────────────────────────────────────────────────

// ── Fake Plus pass payload ────────────────────────────────────────────────────
// Reconstructed from Chroma's string table:
//   - "spotipw.account.pass" key stores a NSDictionary (or JSON-decoded dict)
//   - Inner keys: "status", "account", "source", "until"
//   - Status values map to enum:
//       "Plus is on"  -> active (no expiry)
//       "e"           -> not verified
//       "p"           -> paused
//       "Plus until " -> active with expiry date
// We use the raw "Plus is on" enum arm (no expiry).

static NSDictionary *FakePlusPass() {
    return @{
        @"status"  : @"Plus is on",
        @"account" : @"patched@local.dev",
        @"source"  : @"unlocker",
        @"until"   : @"2099-12-31T23:59:59Z",
        @"active"  : @YES,
        @"verified": @YES,
    };
}

// ── Fake /api/app/me JSON response ───────────────────────────────────────────
static NSData *FakeMeResponse() {
    NSDictionary *payload = @{
        @"pass": FakePlusPass(),
        @"email": @"patched@local.dev",
        @"devices": @[@{
            @"id"     : @"aaaaaaaabbbbbbbbccccccccdddddddd",
            @"model"  : @"iPhone",
            @"current": @YES,
        }],
        @"current": @{
            @"id"    : @"aaaaaaaabbbbbbbbccccccccdddddddd",
            @"model" : @"iPhone",
        },
    };
    NSError *err = nil;
    return [NSJSONSerialization dataWithJSONObject:payload
                                          options:0
                                            error:&err];
}

// ── 1. NSUserDefaults hooks ───────────────────────────────────────────────────
static id (*orig_objectForKey)(NSUserDefaults *, SEL, NSString *) = NULL;

static id hooked_objectForKey(NSUserDefaults *self, SEL sel, NSString *key) {
    if ([key isEqualToString:@"spotipw.account.pass"] ||
        [key isEqualToString:@"spotipw.account.email"] ||
        [key isEqualToString:@"spotipw.account.checked"]) {

        if ([key isEqualToString:@"spotipw.account.pass"])    return FakePlusPass();
        if ([key isEqualToString:@"spotipw.account.email"])   return @"patched@local.dev";
        if ([key isEqualToString:@"spotipw.account.checked"]) return @YES;
    }
    return orig_objectForKey(self, sel, key);
}

// objectForKey: is the main read path; also hook -boolForKey: for boolean gates
static BOOL (*orig_boolForKey)(NSUserDefaults *, SEL, NSString *) = NULL;

static BOOL hooked_boolForKey(NSUserDefaults *self, SEL sel, NSString *key) {
    if ([key isEqualToString:@"spotipw.account.checked"]) return YES;
    return orig_boolForKey(self, sel, key);
}

// ── 2. NSURLSession response intercept ───────────────────────────────────────
// Hook -[NSURLSession dataTaskWithRequest:completionHandler:] and swizzle
// the completion block when the URL matches Chroma's auth endpoints.

typedef void (^DataTaskCompletion)(NSData *, NSURLResponse *, NSError *);

static NSURLSessionDataTask *(*orig_dataTask)(NSURLSession *, SEL,
                                               NSURLRequest *,
                                               DataTaskCompletion) = NULL;

static NSURLSessionDataTask *hooked_dataTask(NSURLSession *self,
                                              SEL sel,
                                              NSURLRequest *request,
                                              DataTaskCompletion handler) {
    NSString *urlStr = request.URL.absoluteString;

    // Intercept /api/app/me, /api/app/auth/verify, /api/app/auth/start
    BOOL isAuthEndpoint =
        [urlStr containsString:@"chroma.pw/api/app/me"] ||
        [urlStr containsString:@"chroma.pw/api/app/auth/verify"] ||
        [urlStr containsString:@"chroma.pw/api/app/auth/start"]  ||
        [urlStr containsString:@"chroma.pw/api/certificate"];

    if (isAuthEndpoint && handler) {
        NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc]
            initWithURL:request.URL
             statusCode:200
            HTTPVersion:@"HTTP/1.1"
           headerFields:@{@"Content-Type": @"application/json"}];

        NSData *fakeData = FakeMeResponse();

        // Fire the original task to avoid suspicious nil tasks, but override callback
        DataTaskCompletion patchedHandler = ^(NSData *d, NSURLResponse *r, NSError *e) {
            // Always call back with our fake data regardless of network result
            if (handler) handler(fakeData, fakeResp, nil);
        };
        return orig_dataTask(self, sel, request, patchedHandler);
    }

    return orig_dataTask(self, sel, request, handler);
}

// ── 3. ObjC property hooks via method swizzling ───────────────────────────────
// Hook every class that exposes `plus` (BOOL getter) and `plusLocked` (BOOL getter)
// Return YES for `plus` and NO for `plusLocked` unconditionally.

static IMP orig_plus_getter = NULL;
static BOOL hooked_plus_getter(id self, SEL sel) { return YES; }

static IMP orig_plusLocked_getter = NULL;
static BOOL hooked_plusLocked_getter(id self, SEL sel) { return NO; }

static void HookPlusPropertyOnClass(Class cls) {
    if (!cls) return;

    // Hook `plus` getter
    SEL plusSel = NSSelectorFromString(@"plus");
    Method plusMethod = class_getInstanceMethod(cls, plusSel);
    if (plusMethod) {
        orig_plus_getter = method_setImplementation(plusMethod,
                               (IMP)hooked_plus_getter);
    }

    // Hook `plusLocked` getter
    SEL lockedSel = NSSelectorFromString(@"plusLocked");
    Method lockedMethod = class_getInstanceMethod(cls, lockedSel);
    if (lockedMethod) {
        orig_plusLocked_getter = method_setImplementation(lockedMethod,
                                     (IMP)hooked_plusLocked_getter);
    }

    // Hook `setPlus:` setter — always accept YES, never store NO
    SEL setPlusSel = NSSelectorFromString(@"setPlus:");
    Method setMethod = class_getInstanceMethod(cls, setPlusSel);
    if (setMethod) {
        IMP origSet = method_getImplementation(setMethod);
        method_setImplementation(setMethod, imp_implementationWithBlock(
            ^(id me, BOOL val) {
                // Force YES through the original setter
                ((void(*)(id,SEL,BOOL))origSet)(me, setPlusSel, YES);
            }
        ));
    }
}

// ── Constructor ───────────────────────────────────────────────────────────────
__attribute__((constructor))
static void ChromaPatchInit(void) {
    @autoreleasepool {

        // 1. Hook NSUserDefaults
        MSHookMessageEx(
            [NSUserDefaults class],
            @selector(objectForKey:),
            (IMP)hooked_objectForKey,
            (IMP *)&orig_objectForKey
        );
        MSHookMessageEx(
            [NSUserDefaults class],
            @selector(boolForKey:),
            (IMP)hooked_boolForKey,
            (IMP *)&orig_boolForKey
        );

        // 2. Hook NSURLSession network calls
        MSHookMessageEx(
            [NSURLSession class],
            @selector(dataTaskWithRequest:completionHandler:),
            (IMP)hooked_dataTask,
            (IMP *)&orig_dataTask
        );

        // 3. Hook ObjC Plus property on all SG* classes
        // We enumerate every class at runtime since the classes are registered
        // by spotifyglass.dylib which loads before us or alongside us.
        // Delay slightly to ensure spotifyglass has registered its classes.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            int classCount = objc_getClassList(NULL, 0);
            if (classCount <= 0) return;

            Class *classes = (Class *)malloc(sizeof(Class) * classCount);
            objc_getClassList(classes, classCount);

            for (int i = 0; i < classCount; i++) {
                const char *name = class_getName(classes[i]);
                if (!name) continue;

                // Hook every SGM* and SGR* class (Chroma's prefix = SG)
                if (strncmp(name, "SG", 2) == 0) {
                    HookPlusPropertyOnClass(classes[i]);
                }
            }
            free(classes);

            // Also nuke the UserDefaults "spotipw.account.signed-out" flag
            [[NSUserDefaults standardUserDefaults]
                removeObjectForKey:@"spotipw.account.signed-out"];
            [[NSUserDefaults standardUserDefaults]
                removeObjectForKey:@"spotipw.account.clock-issue"];

            // Inject the fake pass immediately so cached reads return it
            [[NSUserDefaults standardUserDefaults]
                setObject:FakePlusPass()
                   forKey:@"spotipw.account.pass"];
            [[NSUserDefaults standardUserDefaults]
                setObject:@"patched@local.dev"
                   forKey:@"spotipw.account.email"];
            [[NSUserDefaults standardUserDefaults]
                setObject:@YES
                   forKey:@"spotipw.account.checked"];
            [[NSUserDefaults standardUserDefaults] synchronize];
        });
    }
}
