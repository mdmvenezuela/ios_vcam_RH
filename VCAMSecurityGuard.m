//
//  VCAMSecurityGuard.m
//  VCAM iOS - Multi-Layer Security Guard & Anti-Bypass Engine
//

#import "VCAMSecurityGuard.h"
#import "VCAMSharedState.h"
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/stat.h>
#import <unistd.h>

static const char *kVCAMAuthTokenFileName = ".vcam_token";
static const char *kVCamSharedHwidPath    = "/var/mobile/Library/Preferences/.vcam_device_id";

// ── 1. Chuỗi Secret Salt được mã hóa XOR động (Chống hoàn toàn lệnh strings) ──
static const uint8_t kXORSaltData[] = {
    0x00, 0x3E, 0x3D, 0x17, 0x6D, 0x31, 0x20, 0x12, 0x0D, 0x2D, 0x62, 0x08, 0x0C, 0x6F, 0x62, 0x0E,
    0x1C, 0x0B, 0x0E, 0x6D, 0x12, 0x39, 0x6D, 0x10, 0x00, 0x3F, 0x1D, 0x6C, 0x3C, 0x38, 0x1F, 0x34,
    0x62, 0x38, 0x12, 0x2E, 0x3E, 0x1E, 0x3D, 0x68
};
static const size_t kXORSaltLen = sizeof(kXORSaltData);
static const uint8_t kXORKey = 0x5A;

NSString *VCAMGetDecryptedSecretSalt(void) {
    char buf[kXORSaltLen + 1];
    for (size_t i = 0; i < kXORSaltLen; i++) {
        buf[i] = (char)(kXORSaltData[i] ^ kXORKey);
    }
    buf[kXORSaltLen] = '\0';
    return [NSString stringWithUTF8String:buf];
}

#import <dlfcn.h>
#import <sys/sysctl.h>

// ── 2. Lấy định danh phần cứng thực tế đa nguồn (MobileGestalt + IOKit + sysctl) ──

static NSString *VCAMFetchMobileGestalt(CFStringRef prop) {
    void *gestalt = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_GLOBAL | RTLD_LAZY);
    if (!gestalt) return nil;
    
    CFPropertyListRef (*MGCopyAnswer)(CFStringRef) = (CFPropertyListRef (*)(CFStringRef))dlsym(gestalt, "MGCopyAnswer");
    if (!MGCopyAnswer) return nil;
    
    CFPropertyListRef val = MGCopyAnswer(prop);
    if (!val) return nil;
    
    NSString *result = nil;
    if (CFGetTypeID(val) == CFStringGetTypeID()) {
        result = [NSString stringWithString:(__bridge NSString *)val];
    } else if (CFGetTypeID(val) == CFNumberGetTypeID()) {
        long long numVal = 0;
        if (CFNumberGetValue((CFNumberRef)val, kCFNumberLongLongType, &numVal)) {
            result = [NSString stringWithFormat:@"%llX", numVal];
        }
    }
    CFRelease(val);
    return [result stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

typedef mach_port_t vcam_io_service_t;
typedef mach_port_t vcam_io_object_t;

static NSString *VCAMFetchIOKit(CFStringRef prop) {
    vcam_io_service_t (*pIOServiceGetMatchingService)(mach_port_t, CFDictionaryRef) = 
        (vcam_io_service_t (*)(mach_port_t, CFDictionaryRef))dlsym(RTLD_DEFAULT, "IOServiceGetMatchingService");
    CFMutableDictionaryRef (*pIOServiceMatching)(const char *) = 
        (CFMutableDictionaryRef (*)(const char *))dlsym(RTLD_DEFAULT, "IOServiceMatching");
    CFTypeRef (*pIORegistryEntryCreateCFProperty)(vcam_io_service_t, CFStringRef, CFAllocatorRef, uint32_t) = 
        (CFTypeRef (*)(vcam_io_service_t, CFStringRef, CFAllocatorRef, uint32_t))dlsym(RTLD_DEFAULT, "IORegistryEntryCreateCFProperty");
    kern_return_t (*pIOObjectRelease)(vcam_io_object_t) = 
        (kern_return_t (*)(vcam_io_object_t))dlsym(RTLD_DEFAULT, "IOObjectRelease");
        
    if (!pIOServiceGetMatchingService || !pIOServiceMatching || !pIORegistryEntryCreateCFProperty || !pIOObjectRelease) {
        return nil;
    }
    
    CFMutableDictionaryRef matching = pIOServiceMatching("IOPlatformExpertDevice");
    if (!matching) return nil;
    
    vcam_io_service_t service = pIOServiceGetMatchingService(0, matching);
    if (!service) return nil;
    
    CFTypeRef propVal = pIORegistryEntryCreateCFProperty(service, prop, kCFAllocatorDefault, 0);
    pIOObjectRelease(service);
    if (!propVal) return nil;
    
    NSString *result = nil;
    if (CFGetTypeID(propVal) == CFStringGetTypeID()) {
        result = [NSString stringWithString:(__bridge NSString *)propVal];
    } else if (CFGetTypeID(propVal) == CFDataGetTypeID()) {
        NSData *data = (__bridge NSData *)propVal;
        result = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (!result) {
            const unsigned char *bytes = (const unsigned char *)[data bytes];
            NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
            for (NSUInteger i = 0; i < data.length; i++) {
                [hex appendFormat:@"%02x", bytes[i]];
            }
            result = hex;
        }
    } else if (CFGetTypeID(propVal) == CFNumberGetTypeID()) {
        long long numVal = 0;
        if (CFNumberGetValue((CFNumberRef)propVal, kCFNumberLongLongType, &numVal)) {
            result = [NSString stringWithFormat:@"%llX", numVal];
        }
    }
    CFRelease(propVal);
    return [result stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

static NSString *VCAMFetchSysctl(const char *name) {
    size_t size = 0;
    if (sysctlbyname(name, NULL, &size, NULL, 0) != 0 || size == 0) return @"";
    char *buf = malloc(size);
    if (!buf) return @"";
    if (sysctlbyname(name, buf, &size, NULL, 0) == 0) {
        NSString *val = [NSString stringWithUTF8String:buf];
        free(buf);
        return [val stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
    }
    free(buf);
    return @"";
}

NSString *VCAMGetDeviceECID(void) {
    static NSString *sCachedECID = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // 1. Quét từ MobileGestalt: UniqueChipID (CFNumberRef / uint64_t)
        void *gestalt = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_GLOBAL | RTLD_LAZY);
        if (gestalt) {
            CFPropertyListRef (*MGCopyAnswer)(CFStringRef) = (CFPropertyListRef (*)(CFStringRef))dlsym(gestalt, "MGCopyAnswer");
            if (MGCopyAnswer) {
                CFPropertyListRef val = MGCopyAnswer(CFSTR("UniqueChipID"));
                if (val) {
                    if (CFGetTypeID(val) == CFNumberGetTypeID()) {
                        long long chipId = 0;
                        if (CFNumberGetValue((CFNumberRef)val, kCFNumberLongLongType, &chipId) && chipId != 0) {
                            sCachedECID = [NSString stringWithFormat:@"%llX", chipId];
                        }
                    } else if (CFGetTypeID(val) == CFStringGetTypeID()) {
                        NSString *s = [NSString stringWithString:(__bridge NSString *)val];
                        if (s.length > 0) sCachedECID = s;
                    }
                    CFRelease(val);
                }
            }
        }

        // 2. Quét từ IOKit: IOPlatformExpertDevice -> unique-chip-id hoặc die-id
        if (!sCachedECID || sCachedECID.length == 0) {
            vcam_io_service_t (*pIOServiceGetMatchingService)(mach_port_t, CFDictionaryRef) = 
                (vcam_io_service_t (*)(mach_port_t, CFDictionaryRef))dlsym(RTLD_DEFAULT, "IOServiceGetMatchingService");
            CFMutableDictionaryRef (*pIOServiceMatching)(const char *) = 
                (CFMutableDictionaryRef (*)(const char *))dlsym(RTLD_DEFAULT, "IOServiceMatching");
            CFTypeRef (*pIORegistryEntryCreateCFProperty)(vcam_io_service_t, CFStringRef, CFAllocatorRef, uint32_t) = 
                (CFTypeRef (*)(vcam_io_service_t, CFStringRef, CFAllocatorRef, uint32_t))dlsym(RTLD_DEFAULT, "IORegistryEntryCreateCFProperty");
            kern_return_t (*pIOObjectRelease)(vcam_io_object_t) = 
                (kern_return_t (*)(vcam_io_object_t))dlsym(RTLD_DEFAULT, "IOObjectRelease");

            if (pIOServiceGetMatchingService && pIOServiceMatching && pIORegistryEntryCreateCFProperty && pIOObjectRelease) {
                CFMutableDictionaryRef matching = pIOServiceMatching("IOPlatformExpertDevice");
                if (matching) {
                    vcam_io_service_t service = pIOServiceGetMatchingService(0, matching);
                    if (service) {
                        CFTypeRef propVal = pIORegistryEntryCreateCFProperty(service, CFSTR("unique-chip-id"), kCFAllocatorDefault, 0);
                        if (!propVal) {
                            propVal = pIORegistryEntryCreateCFProperty(service, CFSTR("die-id"), kCFAllocatorDefault, 0);
                        }
                        pIOObjectRelease(service);
                        if (propVal) {
                            if (CFGetTypeID(propVal) == CFDataGetTypeID()) {
                                NSData *data = (__bridge NSData *)propVal;
                                if (data.length >= sizeof(uint64_t)) {
                                    uint64_t chipId = *(const uint64_t *)[data bytes];
                                    if (chipId != 0) {
                                        sCachedECID = [NSString stringWithFormat:@"%llX", chipId];
                                    }
                                }
                            } else if (CFGetTypeID(propVal) == CFNumberGetTypeID()) {
                                long long chipId = 0;
                                if (CFNumberGetValue((CFNumberRef)propVal, kCFNumberLongLongType, &chipId) && chipId != 0) {
                                    sCachedECID = [NSString stringWithFormat:@"%llX", chipId];
                                }
                            }
                            CFRelease(propVal);
                        }
                    }
                }
            }
        }

        sCachedECID = [sCachedECID uppercaseString] ?: @"";
    });
    return sCachedECID ?: @"";
}

NSString *VCAMGetSharedDeviceHWID(void) {
    static NSString *sCachedHWID = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // 1. Quét phần cứng từ MobileGestalt
        NSString *mgSerial = VCAMFetchMobileGestalt(CFSTR("SerialNumber"));
        NSString *mgUdid   = VCAMFetchMobileGestalt(CFSTR("UniqueDeviceID"));

        // 2. Quét phần cứng từ IOKit (IOPlatformExpertDevice)
        NSString *ioSerial = VCAMFetchIOKit(CFSTR("IOPlatformSerialNumber"));
        NSString *ioUUID   = VCAMFetchIOKit(CFSTR("IOPlatformUUID"));

        // 3. Quét ECID bất biến trên chip silicon phần cứng (Chống fake thông số máy)
        NSString *ecid     = VCAMGetDeviceECID();

        // 4. Quét thông số vi xử lý & model từ Kernel sysctl
        NSString *hwModel   = VCAMFetchSysctl("hw.model");    // vd: D20AP
        NSString *hwMachine = VCAMFetchSysctl("hw.machine");  // vd: iPhone10,1

        // Chọn mã Serial ưu tiên
        NSString *finalSerial = (mgSerial.length >= 6) ? mgSerial : ((ioSerial.length >= 6) ? ioSerial : @"");
        // Chọn mã UUID/UDID ưu tiên
        NSString *finalUUID   = (ioUUID.length >= 16) ? ioUUID : ((mgUdid.length >= 16) ? mgUdid : @"");
        // Chọn mã ECID ưu tiên
        NSString *finalECID   = (ecid.length >= 4) ? ecid : @"";

        NSString *hwSeed = nil;
        if (finalSerial.length > 0 || finalUUID.length > 0 || finalECID.length > 0) {
            // Ghép nối định danh phần cứng thực tế với Salt bí mật (Bao gồm ECID phần cứng bất biến)
            hwSeed = [NSString stringWithFormat:@"VCAM-HW-%@-%@-%@-%@-%@-%@",
                      finalSerial ?: @"NOSER",
                      finalUUID ?: @"NOUUID",
                      finalECID ?: @"NOECID",
                      hwModel ?: @"NOMODEL",
                      hwMachine ?: @"NOMACH",
                      VCAMGetDecryptedSecretSalt()];
        } else {
            // Fallback nếu sandbox app bên thứ 3 chặn cả Gestalt & IOKit: Đọc file cache đã ghi từ SpringBoard/mediaserverd
            NSString *path = [NSString stringWithUTF8String:kVCamSharedHwidPath];
            if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
                NSString *saved = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
                saved = [saved stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                if (saved.length >= 16) {
                    sCachedHWID = [saved copy];
                    return;
                }
            }
            hwSeed = [NSString stringWithFormat:@"VCAM-STATIC-%@-%@-%@", hwModel, hwMachine, VCAMGetDecryptedSecretSalt()];
        }

        // Băm SHA-256 chuỗi phần cứng để tạo mã HWID 64 ký tự chuẩn hóa
        const char *s = [hwSeed UTF8String];
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(s, (CC_LONG)strlen(s), digest);
        NSMutableString *hwidStr = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
        for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
            [hwidStr appendFormat:@"%02x", digest[i]];
        }
        sCachedHWID = [hwidStr copy];

        // Lưu file cache với quyền 0666 để chia sẻ giữa các tiến trình
        NSString *path = [NSString stringWithUTF8String:kVCamSharedHwidPath];
        [sCachedHWID writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        chmod(kVCamSharedHwidPath, 0666);
    });

    return sCachedHWID ?: @"";
}

// ── 3. Danh sách thư mục tmp khả dụng ──
static NSArray<NSString *> *PossibleTmpDirs(void) {
    static NSArray<NSString *> *dirs = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSMutableArray *list = [NSMutableArray array];
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/rootfs/private/var/tmp"]) {
            [list addObject:@"/rootfs/private/var/tmp"];
        }
        [list addObject:@"/var/tmp"];
        [list addObject:@"/private/var/tmp"];
        dirs = [list copy];
    });
    return dirs;
}

// ── 4. Kiểm tra tính toàn vẹn nhị phân ARM64 trong RAM (Anti-Binary-Patching) ──
BOOL VCAMCheckBinaryIntegrity(void) {
    uint32_t *fnPtr = (uint32_t *)&VCAMVerifyProcessAuthorization;
    if (fnPtr) {
        uint32_t insn = *fnPtr;
        // 0x52800020 = mov w0, #1
        // 0xD65F03C0 = ret
        if (insn == 0x52800020 || insn == 0xD65F03C0) {
            NSLog(@"[VCAMSecurity] CẢNH BÁO: Phát hiện hàm bị can thiệp nhị phân! Tự động từ chối.");
            return NO;
        }
    }
    return YES;
}

// ── 5. Hàm C xác thực bản quyền trực tiếp (chạy ở cả mediaserverd và SpringBoard) ──
BOOL VCAMVerifyProcessAuthorization(void) {
    // 1. Kiểm tra tính toàn vẹn nhị phân trước (Anti-Binary-Patching)
    if (!VCAMCheckBinaryIntegrity()) {
        return NO;
    }

    // Cache RAM 3.0s khi hợp lệ, 0.5s khi chưa hợp lệ để triệt tiêu tải CPU/HMAC trên luồng camera
    static BOOL sCachedValid = NO;
    static NSTimeInterval sLastCheck = 0;
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    NSTimeInterval cacheInterval = sCachedValid ? 3.0 : 0.5;
    if (now - sLastCheck < cacheInterval) {
        return sCachedValid;
    }
    sLastCheck = now;

    NSString *currentHwid = VCAMGetSharedDeviceHWID();
    NSTimeInterval wallNow = [[NSDate date] timeIntervalSince1970];
    NSString *salt = VCAMGetDecryptedSecretSalt();

    // 2. Xác thực trực tiếp từ Shared Memory RAM qua SeqLock (0ms IPC, chống fake file đĩa)
    VCAMSharedFlashState *shared = VCAMGetSharedFlashState(false);
    if (shared && shared->magic == VCAM_SHARED_FLASH_MAGIC) {
        uint64_t seq1, seq2;
        int retries = 0;
        uint32_t active = 0;
        double expiresAt = 0, issuedAt = 0;
        char ramKey[64] = {0};
        char ramHwid[68] = {0};
        char ramSig[68] = {0};

        do {
            seq1 = __atomic_load_n(&shared->authSequence, __ATOMIC_ACQUIRE);
            if (seq1 & 1) { // Đang trong quá trình ghi (odd sequence)
                continue;
            }
            active = shared->authActive;
            expiresAt = shared->authExpiresAt;
            issuedAt = shared->authIssuedAt;
            memcpy(ramKey, (const void *)shared->authKey, sizeof(ramKey));
            memcpy(ramHwid, (const void *)shared->authHwid, sizeof(ramHwid));
            memcpy(ramSig, (const void *)shared->authSignature, sizeof(ramSig));
            seq2 = __atomic_load_n(&shared->authSequence, __ATOMIC_ACQUIRE);
        } while (seq1 != seq2 && ++retries < 5);

        if (active != 0 && ramKey[0] != '\0' && ramHwid[0] != '\0' && ramSig[0] != '\0') {
            NSString *tokenHwid = [NSString stringWithUTF8String:ramHwid];
            if (currentHwid.length >= 16 && tokenHwid.length >= 16) {
                if (![currentHwid isEqualToString:tokenHwid]) {
                    NSLog(@"[VCAMSecurity] LỖI: Token trong RAM không khớp HWID máy!");
                    sCachedValid = NO;
                    return NO;
                }
            }

            if (expiresAt > 0 && wallNow > (expiresAt / 1000.0)) {
                sCachedValid = NO;
                return NO;
            }

            if (issuedAt > wallNow + 300.0) {
                sCachedValid = NO;
                return NO;
            }

            NSString *key = [NSString stringWithUTF8String:ramKey];
            NSString *sig = [NSString stringWithUTF8String:ramSig];
            NSString *payload = [NSString stringWithFormat:@"%@|%@|%.0f|%.0f", key, tokenHwid, expiresAt, issuedAt];
            const char *cKey = [salt cStringUsingEncoding:NSUTF8StringEncoding];
            const char *cData = [payload cStringUsingEncoding:NSUTF8StringEncoding];

            unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
            CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
            NSMutableString *expectedSig = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
            for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
                [expectedSig appendFormat:@"%02x", cHMAC[i]];
            }

            if ([expectedSig isEqualToString:sig]) {
                sCachedValid = YES;
                return YES;
            } else {
                NSLog(@"[VCAMSecurity] LỖI: Chữ ký số token trong RAM không hợp lệ!");
                sCachedValid = NO;
                return NO;
            }
        } else if (active == 0 && shared->authSequence > 0) {
            // Token đã bị thu hồi trong RAM (Revoked)
            sCachedValid = NO;
            return NO;
        }
    }

    // 3. Fallback: Đọc file token ủy quyền trên đĩa
    static NSString *tokenPath = nil;
    static dispatch_once_t tokenOnce;
    dispatch_once(&tokenOnce, ^{
        for (NSString *dir in PossibleTmpDirs()) {
            NSString *p = [dir stringByAppendingPathComponent:[NSString stringWithUTF8String:kVCAMAuthTokenFileName]];
            if (access([p UTF8String], F_OK) == 0) {
                tokenPath = p;
                break;
            }
        }
        if (!tokenPath) {
            tokenPath = [@"/var/tmp" stringByAppendingPathComponent:[NSString stringWithUTF8String:kVCAMAuthTokenFileName]];
        }
    });

    if (!tokenPath || access([tokenPath UTF8String], F_OK) != 0) {
        sCachedValid = NO;
        return NO;
    }

    NSString *content = [NSString stringWithContentsOfFile:tokenPath encoding:NSUTF8StringEncoding error:nil];
    if (!content || content.length == 0) {
        sCachedValid = NO;
        return NO;
    }

    NSArray *lines = [content componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    if (lines.count < 5) {
        sCachedValid = NO;
        return NO;
    }

    NSString *key = lines[0];
    NSString *tokenHwid = lines[1];
    double expiresAt = [lines[2] doubleValue];
    double issuedAt = [lines[3] doubleValue];
    NSString *sig = lines[4];

    // Xác thực HWID trùng khớp máy hiện tại
    if (currentHwid.length >= 16 && tokenHwid.length >= 16) {
        if (![currentHwid isEqualToString:tokenHwid]) {
            NSLog(@"[VCAMSecurity] LỖI: Token bị copy từ máy khác (HWID không khớp)!");
            sCachedValid = NO;
            return NO;
        }
    }

    // Xác thực thời hạn sử dụng
    if (expiresAt > 0 && wallNow > (expiresAt / 1000.0)) {
        sCachedValid = NO;
        return NO;
    }

    // Chống lùi/sai lệch giờ (+300s dung sai)
    if (issuedAt > wallNow + 300.0) {
        sCachedValid = NO;
        return NO;
    }

    // Tính toán và kiểm tra chữ ký số HMAC-SHA256 với Secret Salt đã giải mã
    NSString *payload = [NSString stringWithFormat:@"%@|%@|%.0f|%.0f", key, tokenHwid, expiresAt, issuedAt];
    const char *cKey = [salt cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [payload cStringUsingEncoding:NSUTF8StringEncoding];

    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    NSMutableString *expectedSig = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [expectedSig appendFormat:@"%02x", cHMAC[i]];
    }

    if (![expectedSig isEqualToString:sig]) {
        NSLog(@"[VCAMSecurity] LỖI: Chữ ký số token không hợp lệ (Dấu hiệu giả mạo)!");
        sCachedValid = NO;
        return NO;
    }

    // Đồng bộ lên RAM Shared Memory để các lần đọc tiếp theo đạt 0ms
    if (shared && shared->magic == VCAM_SHARED_FLASH_MAGIC && shared->authActive == 0) {
        uint64_t seq = shared->authSequence;
        __atomic_store_n(&shared->authSequence, seq + 1, __ATOMIC_RELEASE);
        shared->authActive = 1;
        shared->authExpiresAt = expiresAt;
        shared->authIssuedAt = issuedAt;
        strncpy(shared->authKey, [key UTF8String] ?: "", sizeof(shared->authKey) - 1);
        shared->authKey[sizeof(shared->authKey) - 1] = '\0';
        strncpy(shared->authHwid, [tokenHwid UTF8String] ?: "", sizeof(shared->authHwid) - 1);
        shared->authHwid[sizeof(shared->authHwid) - 1] = '\0';
        strncpy(shared->authSignature, [sig UTF8String] ?: "", sizeof(shared->authSignature) - 1);
        shared->authSignature[sizeof(shared->authSignature) - 1] = '\0';
        __atomic_store_n(&shared->authSequence, seq + 2, __ATOMIC_RELEASE);
    }

    sCachedValid = YES;
    return YES;
}

@implementation VCAMSecurityGuard

+ (instancetype)sharedGuard {
    static VCAMSecurityGuard *guard = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        guard = [[VCAMSecurityGuard alloc] init];
    });
    return guard;
}

+ (void)issueAuthorizationTokenWithKey:(NSString *)key expiresAt:(NSTimeInterval)expiresAt hwid:(NSString *)hwid {
    if (!key || key.length == 0 || !hwid || hwid.length == 0) return;
    NSTimeInterval issuedAt = [[NSDate date] timeIntervalSince1970];

    NSString *payload = [NSString stringWithFormat:@"%@|%@|%.0f|%.0f", key, hwid, expiresAt, issuedAt];
    NSString *salt = VCAMGetDecryptedSecretSalt();
    const char *cKey = [salt cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [payload cStringUsingEncoding:NSUTF8StringEncoding];

    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    NSMutableString *sigStr = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [sigStr appendFormat:@"%02x", cHMAC[i]];
    }

    // 1. Cấp phát trực tiếp vào Shared Memory RAM với SeqLock (0ms IPC, chống fake file đĩa)
    VCAMSharedFlashState *shared = VCAMGetSharedFlashState(true);
    if (shared && shared->magic == VCAM_SHARED_FLASH_MAGIC) {
        uint64_t seq = shared->authSequence;
        __atomic_store_n(&shared->authSequence, seq + 1, __ATOMIC_RELEASE);
        shared->authActive = 1;
        shared->authExpiresAt = expiresAt;
        shared->authIssuedAt = issuedAt;
        strncpy(shared->authKey, [key UTF8String] ?: "", sizeof(shared->authKey) - 1);
        shared->authKey[sizeof(shared->authKey) - 1] = '\0';
        strncpy(shared->authHwid, [hwid UTF8String] ?: "", sizeof(shared->authHwid) - 1);
        shared->authHwid[sizeof(shared->authHwid) - 1] = '\0';
        strncpy(shared->authSignature, [sigStr UTF8String] ?: "", sizeof(shared->authSignature) - 1);
        shared->authSignature[sizeof(shared->authSignature) - 1] = '\0';
        __atomic_store_n(&shared->authSequence, seq + 2, __ATOMIC_RELEASE);
    }

    // 2. Ghi fallback file đĩa (/var/tmp/.vcam_token)
    NSString *content = [NSString stringWithFormat:@"%@\n%@\n%.0f\n%.0f\n%@\n", key, hwid, expiresAt, issuedAt, sigStr];
    for (NSString *dir in PossibleTmpDirs()) {
        NSString *p = [dir stringByAppendingPathComponent:[NSString stringWithUTF8String:kVCAMAuthTokenFileName]];
        [content writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
        chmod([p UTF8String], 0666);
    }
    NSLog(@"[VCAMSecurity] Đã cấp phát token chữ ký số bản quyền mới vào RAM Shared Memory & File.");
}

+ (void)revokeAuthorizationToken {
    // 1. Thu hồi tức thì trong RAM Shared Memory (0ms)
    VCAMSharedFlashState *shared = VCAMGetSharedFlashState(true);
    if (shared && shared->magic == VCAM_SHARED_FLASH_MAGIC) {
        uint64_t seq = shared->authSequence;
        __atomic_store_n(&shared->authSequence, seq + 1, __ATOMIC_RELEASE);
        shared->authActive = 0;
        shared->authExpiresAt = 0;
        shared->authIssuedAt = 0;
        memset(shared->authKey, 0, sizeof(shared->authKey));
        memset(shared->authSignature, 0, sizeof(shared->authSignature));
        __atomic_store_n(&shared->authSequence, seq + 2, __ATOMIC_RELEASE);
    }

    // 2. Xóa toàn bộ file token đĩa
    for (NSString *dir in PossibleTmpDirs()) {
        NSString *p = [dir stringByAppendingPathComponent:[NSString stringWithUTF8String:kVCAMAuthTokenFileName]];
        unlink([p UTF8String]);
    }
    NSLog(@"[VCAMSecurity] Đã thu hồi toàn bộ token bản quyền khỏi RAM & Đĩa.");
}

- (BOOL)isTokenValid {
    return VCAMVerifyProcessAuthorization();
}

@end

