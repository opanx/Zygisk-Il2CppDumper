#include "sigsearch.h"

#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <unistd.h>

#include "log.h"

bool hex_to_pattern(const std::string &hex, std::vector<uint8_t> &bytes,
                    std::vector<uint8_t> &mask) {
    bytes.clear();
    mask.clear();
    std::string h;
    for (char c : hex) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        h += (char) std::tolower((unsigned char) c);
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    size_t i = 0;
    while (i < h.size()) {
        if (h[i] == '?' && i + 1 < h.size() && h[i + 1] == '?') {
            bytes.push_back(0);
            mask.push_back(0);
            i += 2;
        } else if (i + 1 < h.size() && nibble(h[i]) >= 0 && nibble(h[i + 1]) >= 0) {
            bytes.push_back((uint8_t) ((nibble(h[i]) << 4) | nibble(h[i + 1])));
            mask.push_back(1);
            i += 2;
        } else {
            return false;
        }
    }
    return !bytes.empty();
}

void *find_pattern(const uint8_t *start, size_t size, const uint8_t *bytes,
                   const uint8_t *mask, size_t len) {
    if (!start || len == 0 || size < len) return nullptr;
    for (size_t i = 0; i <= size - len; ++i) {
        size_t j = 0;
        for (; j < len; ++j) {
            if (mask[j] && start[i + j] != bytes[j]) break;
        }
        if (j == len) return (void *) (start + i);
    }
    return nullptr;
}

bool find_module_range(const char *name_part, uintptr_t &base, size_t &size) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[512];
    uintptr_t first = 0, last = 0;
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long s = 0, e = 0, off = 0;
        char perms[8] = {0};
        char dev[16] = {0};
        char inode[16] = {0};
        char path[256] = {0};
        // perms[0] == 'r' only; maps can contain the name several times
        if (sscanf(line, "%llx-%llx %7s %llx %15s %15s %255s", &s, &e, perms, &off,
                   dev, inode, path) == 7) {
            if (perms[0] != 'r') continue;
            if (strstr(path, name_part)) {
                if (!found) {
                    first = (uintptr_t) s;
                    found = true;
                }
                last = (uintptr_t) e;
            }
        }
    }
    fclose(fp);
    if (!found) return false;
    base = first;
    size = last - first;
    return true;
}

void *search_in_module(const char *module_name_part, const std::string &hex_pattern) {
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
    if (!hex_to_pattern(hex_pattern, bytes, mask)) {
        LOGE("bad pattern for %s: %s", module_name_part, hex_pattern.c_str());
        return nullptr;
    }
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return nullptr;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long s = 0, e = 0, off = 0;
        char perms[8] = {0};
        char dev[16] = {0};
        char inode[16] = {0};
        char path[256] = {0};
        if (sscanf(line, "%llx-%llx %7s %llx %15s %15s %255s", &s, &e, perms, &off,
                   dev, inode, path) != 7)
            continue;
        if (perms[0] != 'r') continue;
        if (!strstr(path, module_name_part)) continue;
        size_t len = (size_t) (e - s);
        if (len < bytes.size()) continue;
        void *hit = find_pattern((const uint8_t *) (uintptr_t) s, len, bytes.data(),
                                 mask.data(), bytes.size());
        if (hit) {
            fclose(fp);
            LOGI("signature hit for %s @ %p", module_name_part, hit);
            return hit;
        }
    }
    fclose(fp);
    LOGW("signature not found for %s", module_name_part);
    return nullptr;
}

void dump_memory_range(const char *outDir, const char *name, uintptr_t start, size_t len) {
    if (!start || !len) return;
    auto outPath = std::string(outDir).append("/files/").append(name);
    FILE *fp = fopen(outPath.c_str(), "wb");
    if (!fp) {
        LOGE("cannot open %s for write", outPath.c_str());
        return;
    }
    size_t written = fwrite((const void *) start, 1, len, fp);
    fclose(fp);
    LOGI("dumped %s: %zu bytes -> %s", name, written, outPath.c_str());
}

void dump_lib_and_metadata(const char *outDir) {
    uintptr_t base = 0;
    size_t size = 0;
    if (!find_module_range("libil2cpp.so", base, size)) {
        LOGW("libil2cpp.so not mapped, skip lib/metadata dump");
        return;
    }
    LOGI("libil2cpp.so @ %" PRIxPTR " size 0x%zx", base, size);
    dump_memory_range(outDir, "libil2cpp_dump.so", base, size);

    // Locate the "global-metadata.dat" string inside the module, then scan
    // backwards for the metadata magic 0xFAB11BAF (bytes AF 1B B1 FA).
    static const char kNeedle[] = "global-metadata.dat";
    void *p = find_pattern((const uint8_t *) base, size, (const uint8_t *) kNeedle,
                           nullptr, sizeof(kNeedle) - 1);
    if (!p) {
        LOGW("global-metadata.dat string not found, skip metadata dump");
        return;
    }
    uintptr_t needle_addr = (uintptr_t) p;
    // Search a bounded window backwards for the magic.
    const uintptr_t kWindow = 0x4000;
    uintptr_t scan_from = needle_addr > kWindow ? needle_addr - kWindow : base;
    uintptr_t meta = 0;
    for (uintptr_t a = needle_addr; a > scan_from; a -= 4) {
        // magic is 4-byte aligned in practice; scan byte by byte to be safe
        const uint8_t *b = (const uint8_t *) a;
        if (b[0] == 0xAF && b[1] == 0x1B && b[2] == 0xB1 && b[3] == 0xFA) {
            meta = a;
            break;
        }
    }
    if (!meta) {
        LOGW("metadata magic not found, skip metadata dump");
        return;
    }
    size_t meta_len = (base + size) - meta;
    LOGI("global-metadata @ %" PRIxPTR " len 0x%zx", meta, meta_len);
    dump_memory_range(outDir, "global-metadata.dat", meta, meta_len);
}
