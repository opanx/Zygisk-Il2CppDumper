#ifndef ZYGISK_IL2CPPDUMPER_SIGSEARCH_H
#define ZYGISK_IL2CPPDUMPER_SIGSEARCH_H

#include <cstdint>
#include <string>
#include <vector>

// Hex pattern "48 8B 05 ?? ?? ?? ?? C3" -> bytes + wildcard mask (1 = must match).
// Returns false on invalid input.
bool hex_to_pattern(const std::string &hex, std::vector<uint8_t> &bytes,
                    std::vector<uint8_t> &mask);

// Scan a memory region for the pattern. Returns first match or nullptr.
void *find_pattern(const uint8_t *start, size_t size, const uint8_t *bytes,
                   const uint8_t *mask, size_t len);

// Find the base address + total size of every readable mapping of a module
// whose path contains name_part (from /proc/self/maps).
bool find_module_range(const char *name_part, uintptr_t &base, size_t &size);

// Locate the module by name and scan all of its readable mappings for the
// hex pattern. Returns first match address or nullptr.
void *search_in_module(const char *module_name_part, const std::string &hex_pattern);

// Write a raw memory range to outDir/name.
void dump_memory_range(const char *outDir, const char *name, uintptr_t start, size_t len);

// Find "global-metadata.dat" inside the libil2cpp module, scan backwards for
// the metadata magic (0xFAB11BAF) and dump the decrypted metadata from memory.
void dump_lib_and_metadata(const char *outDir);

#endif //ZYGISK_IL2CPPDUMPER_SIGSEARCH_H
