#ifndef ZYGISK_IL2CPPDUMPER_PATTERNS_H
#define ZYGISK_IL2CPPDUMPER_PATTERNS_H

#include <string>

// Load built-in defaults and (if OnlineConfigUrl is set) fetch the latest
// signature table from the server. Called once at startup.
void patterns_init();

// Hex pattern for an il2cpp api function name. Empty string = unknown
// (keep the xdl_sym() result).
std::string patterns_get(const char *name);

#endif //ZYGISK_IL2CPPDUMPER_PATTERNS_H
