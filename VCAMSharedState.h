//
//  VCAMSharedState.h
//  VCAM iOS - Ultra-Low-Latency Inter-Process Shared Memory
//
//  Cơ chế chia sẻ trạng thái tức thì (0ms IPC) giữa SpringBoard và mediaserverd
//  loại bỏ hoàn toàn độ trễ đọc/ghi file plist trên flash storage.
//

#ifndef VCAM_SHARED_STATE_H
#define VCAM_SHARED_STATE_H

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define VCAM_SHARED_FLASH_MAGIC 0x5643414D // 'VCAM'

typedef struct __attribute__((aligned(8))) {
    uint32_t magic;              // 'VCAM' (0x5643414D)

    // Flash Liveness fields (bắt chớp màu KYC)
    uint32_t active;             // 1 = Active (flash active), 0 = Inactive
    float    r;                  // Red tint (0.0 - 1.0)
    float    g;                  // Green tint (0.0 - 1.0)
    float    b;                  // Blue tint (0.0 - 1.0)
    float    intensity;          // Intensity (0.0 - 1.0)
    uint32_t isColorSync;        // 1 = Color Sync mode, 0 = KYC Flash mode
    uint32_t region;             // 0 = Full frame, 1 = Center face
    uint64_t sequence;           // Counter incremented on every change
    double   timestamp;          // Last update timestamp

    // Color Sync fields (đồng bộ sắc độ màu da / kính lúp)
    uint32_t colorSyncActive;    // 1 = Color sync active, 0 = Inactive
    float    colorSyncR;
    float    colorSyncG;
    float    colorSyncB;
    float    colorSyncIntensity;
    uint32_t colorSyncRegion;
    uint64_t colorSyncSequence;
    double   colorSyncTimestamp;

    // Authorization & License Token fields (RAM Shared Memory 0ms verification)
    uint32_t authActive;         // 1 = License valid & active, 0 = Invalid/Revoked
    uint32_t reserved1;
    uint64_t authSequence;       // SeqLock counter for atomic auth token snapshot
    double   authExpiresAt;      // Expiration timestamp (epoch ms or sec)
    double   authIssuedAt;       // Issued timestamp (epoch sec)
    char     authKey[64];        // License key string
    char     authHwid[68];       // Machine HWID (SHA256 hex + padding)
    char     authSignature[68];  // HMAC-SHA256 signature (64 hex + null)

    uint8_t  padding[64];
} VCAMSharedFlashState;

static inline VCAMSharedFlashState *VCAMGetSharedFlashState(bool createIfMissing) {
    static VCAMSharedFlashState *sShared = NULL;
    if (sShared) return sShared;

    const char *paths[] = {
        "/rootfs/private/var/tmp/vcam_shared_flash.bin",
        "/var/tmp/vcam_shared_flash.bin",
        "/private/var/tmp/vcam_shared_flash.bin",
        "/tmp/vcam_shared_flash.bin",
        NULL
    };

    for (int i = 0; paths[i] != NULL; i++) {
        const char *p = paths[i];
        int fd = -1;
        if (createIfMissing) {
            fd = open(p, O_RDWR | O_CREAT, 0666);
            if (fd >= 0) {
                struct stat st;
                if (fstat(fd, &st) == 0 && st.st_size < (off_t)sizeof(VCAMSharedFlashState)) {
                    ftruncate(fd, sizeof(VCAMSharedFlashState));
                }
                fchmod(fd, 0666);
            }
        } else {
            fd = open(p, O_RDWR, 0666);
            if (fd >= 0) {
                struct stat st;
                if (fstat(fd, &st) == 0 && st.st_size < (off_t)sizeof(VCAMSharedFlashState)) {
                    ftruncate(fd, sizeof(VCAMSharedFlashState));
                }
            } else {
                fd = open(p, O_RDONLY, 0666);
            }
        }

        if (fd >= 0) {
            int prot = PROT_READ | PROT_WRITE;
            int flags = MAP_SHARED;
            void *addr = mmap(NULL, sizeof(VCAMSharedFlashState), prot, flags, fd, 0);
            if (addr == MAP_FAILED && !createIfMissing) {
                // Thử map PROT_READ nếu tiến trình chỉ có quyền đọc
                addr = mmap(NULL, sizeof(VCAMSharedFlashState), PROT_READ, flags, fd, 0);
            }
            close(fd);
            if (addr != MAP_FAILED) {
                sShared = (VCAMSharedFlashState *)addr;
                if (createIfMissing && sShared->magic != VCAM_SHARED_FLASH_MAGIC) {
                    memset(sShared, 0, sizeof(VCAMSharedFlashState));
                    sShared->magic = VCAM_SHARED_FLASH_MAGIC;
                    sShared->r = 1.0f;
                    sShared->g = 1.0f;
                    sShared->b = 1.0f;
                    sShared->intensity = 0.50f;
                    sShared->colorSyncR = 0.92f;
                    sShared->colorSyncG = 0.78f;
                    sShared->colorSyncB = 0.71f;
                    sShared->colorSyncIntensity = 0.65f;
                    sShared->authActive = 0;
                    sShared->authSequence = 0;
                }
                break;
            }
        }
    }
    return sShared;
}

#endif // VCAM_SHARED_STATE_H
