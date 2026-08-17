#include "patterns.h"

#include <map>
#include <string>
#include <utility>

#include "game.h"
#include "log.h"
#include "net.h"

// ---------------------------------------------------------------------------
// Built-in default patterns.
//
// These are a starting point for standard (unmodified) Unity il2cpp builds.
// Games with heavy protection such as Mobile Legends (com.mobile.legends,
// version 2.1.95.12053) strip the exports and/or alter the code, so the
// patterns must be extracted per version and served through OnlineConfigUrl
// (see game.h) — the online config OVERRIDES these entries and is loaded
// without recompiling the module.
// ---------------------------------------------------------------------------
static const std::pair<const char *, const char *> kDefaultPatterns[] = {
    // {"il2cpp_domain_get_assemblies", "AA BB CC ..."},
};

static std::map<std::string, std::string> g_patterns;

// Minimal JSON parser for:
//   {"version":"...","patterns":{"name":"AA BB ?? CC", ...}}
// Best effort; anything it can't understand is skipped.
static void parse_patterns_json(const std::string &body) {
    size_t p = body.find("\"patterns\"");
    if (p == std::string::npos) {
        LOGW("online config: no \"patterns\" key");
        return;
    }
    size_t start = body.find('{', p);
    if (start == std::string::npos) return;
    size_t loaded = 0;
    size_t i = start + 1;
    while (i < body.size()) {
        size_t kq = body.find('"', i);
        if (kq == std::string::npos) break;
        size_t ke = body.find('"', kq + 1);
        if (ke == std::string::npos) break;
        std::string key = body.substr(kq + 1, ke - kq - 1);
        size_t colon = body.find(':', ke);
        if (colon == std::string::npos) break;
        size_t vq = body.find('"', colon);
        if (vq == std::string::npos) break;
        size_t ve = body.find('"', vq + 1);
        if (ve == std::string::npos) break;
        std::string val = body.substr(vq + 1, ve - vq - 1);
        if (key == "version") {
            LOGI("online config: %s", val.c_str());
        } else if (!key.empty() && !val.empty()) {
            g_patterns[key] = val;
            ++loaded;
        }
        i = ve + 1;
    }
    LOGI("online config: %zu patterns loaded", loaded);
}

void patterns_init() {
    for (const auto &kv : kDefaultPatterns) {
        g_patterns[kv.first] = kv.second;
    }
    const char *url = OnlineConfigUrl;
    if (url && url[0]) {
        LOGI("fetching online config: %s", url);
        std::string body = http_get(url);
        if (!body.empty()) {
            parse_patterns_json(body);
        } else {
            LOGW("online config fetch failed, using built-in defaults");
        }
    } else {
        LOGI("no OnlineConfigUrl set, using built-in defaults only");
    }
}

std::string patterns_get(const char *name) {
    if (!name) return {};
    auto it = g_patterns.find(name);
    if (it != g_patterns.end()) return it->second;
    return {};
}
