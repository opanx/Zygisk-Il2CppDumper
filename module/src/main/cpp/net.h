#ifndef ZYGISK_IL2CPPDUMPER_NET_H
#define ZYGISK_IL2CPPDUMPER_NET_H

#include <string>

// Minimal HTTP(S) GET. https is supported via dlopen("libssl.so") from the
// system (BoringSSL), no bundled TLS code. Returns the response body on
// success (HTTP 200), empty string on any failure. Safe to call from the
// game process; never throws.
std::string http_get(const char *url, int timeout_sec = 8);

#endif //ZYGISK_IL2CPPDUMPER_NET_H
