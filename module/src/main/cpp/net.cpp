#include "net.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"

// ---------------------------------------------------------------------------
// Minimal TLS via dlopen("libssl.so") (system BoringSSL on Android).
// ---------------------------------------------------------------------------
struct ssl_st;
struct ssl_ctx_st;

static void *g_ssl_handle = nullptr;
static ssl_ctx_st *(*g_SSL_CTX_new)(const void *method) = nullptr;
static void (*g_SSL_CTX_free)(ssl_ctx_st *) = nullptr;
static ssl_st *(*g_SSL_new)(ssl_ctx_st *) = nullptr;
static void (*g_SSL_free)(ssl_st *) = nullptr;
static int (*g_SSL_set_fd)(ssl_st *, int) = nullptr;
static int (*g_SSL_connect)(ssl_st *) = nullptr;
static int (*g_SSL_write)(ssl_st *, const void *, int) = nullptr;
static int (*g_SSL_read)(ssl_st *, void *, int) = nullptr;
static const void *(*g_TLS_client_method)(void) = nullptr;

static bool tls_init() {
    if (g_ssl_handle) return true;
    g_ssl_handle = dlopen("libssl.so", RTLD_NOW | RTLD_GLOBAL);
    if (!g_ssl_handle) {
        LOGW("dlopen libssl.so failed: %s", dlerror());
        return false;
    }
    // libssl depends on libcrypto
    dlopen("libcrypto.so", RTLD_NOW | RTLD_GLOBAL);
    g_SSL_CTX_new = (ssl_ctx_st *(*)(const void *)) dlsym(g_ssl_handle, "SSL_CTX_new");
    g_SSL_CTX_free = (void (*)(ssl_ctx_st *)) dlsym(g_ssl_handle, "SSL_CTX_free");
    g_SSL_new = (ssl_st *(*)(ssl_ctx_st *)) dlsym(g_ssl_handle, "SSL_new");
    g_SSL_free = (void (*)(ssl_st *)) dlsym(g_ssl_handle, "SSL_free");
    g_SSL_set_fd = (int (*)(ssl_st *, int)) dlsym(g_ssl_handle, "SSL_set_fd");
    g_SSL_connect = (int (*)(ssl_st *)) dlsym(g_ssl_handle, "SSL_connect");
    g_SSL_write = (int (*)(ssl_st *, const void *, int)) dlsym(g_ssl_handle, "SSL_write");
    g_SSL_read = (int (*)(ssl_st *, void *, int)) dlsym(g_ssl_handle, "SSL_read");
    g_TLS_client_method = (const void *(*)()) dlsym(g_ssl_handle, "TLS_client_method");
    if (!g_SSL_CTX_new || !g_SSL_CTX_free || !g_SSL_new || !g_SSL_free || !g_SSL_set_fd ||
        !g_SSL_connect || !g_SSL_write || !g_SSL_read || !g_TLS_client_method) {
        LOGE("libssl.so missing required symbols");
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// URL parsing (http/https only).
// ---------------------------------------------------------------------------
struct Url {
    bool https = false;
    std::string host;
    int port = 80;
    std::string path = "/";
};

static bool parse_url(const char *url, Url &u) {
    std::string s(url);
    size_t p = s.find("://");
    if (p == std::string::npos) return false;
    std::string scheme = s.substr(0, p);
    if (scheme == "https") {
        u.https = true;
        u.port = 443;
    } else if (scheme == "http") {
        u.https = false;
        u.port = 80;
    } else {
        return false;
    }
    std::string rest = s.substr(p + 3);
    size_t slash = rest.find('/');
    std::string hostport = slash == std::string::npos ? rest : rest.substr(0, slash);
    u.path = slash == std::string::npos ? "/" : rest.substr(slash);
    if (hostport.empty()) return false;
    // reject userinfo and query/hash inside host:port
    if (hostport.find('@') != std::string::npos) return false;
    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos && hostport.find(']') == std::string::npos) {
        u.host = hostport.substr(0, colon);
        u.port = atoi(hostport.substr(colon + 1).c_str());
        if (u.port <= 0) u.port = u.https ? 443 : 80;
    } else {
        u.host = hostport;
    }
    if (u.host.empty()) return false;
    return true;
}

std::string http_get(const char *url, int timeout_sec) {
    Url u;
    if (!parse_url(url, u)) {
        LOGE("bad url: %s", url);
        return {};
    }

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", u.port);
    struct addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = nullptr;
    if (getaddrinfo(u.host.c_str(), portstr, &hints, &res) != 0 || !res) {
        LOGE("resolve failed: %s", u.host.c_str());
        return {};
    }
    int fd = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd == -1) {
        LOGE("connect failed: %s", u.host.c_str());
        return {};
    }

    struct timeval tv = {};
    tv.tv_sec = timeout_sec;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    std::string req = "GET " + u.path + " HTTP/1.1\r\n"
                      "Host: " + u.host + "\r\n"
                      "User-Agent: zygisk-il2cppdumper/1.0\r\n"
                      "Connection: close\r\n\r\n";

    ssl_st *ssl = nullptr;
    bool is_tls = false;
    if (u.https) {
        if (!tls_init()) {
            close(fd);
            return {};
        }
        ssl_ctx_st *ctx = g_SSL_CTX_new(g_TLS_client_method());
        ssl = ctx ? g_SSL_new(ctx) : nullptr;
        if (ctx) g_SSL_CTX_free(ctx);
        if (!ssl || g_SSL_set_fd(ssl, fd) != 1 || g_SSL_connect(ssl) != 1) {
            LOGE("TLS handshake failed for %s", u.host.c_str());
            if (ssl) g_SSL_free(ssl);
            close(fd);
            return {};
        }
        is_tls = true;
        g_SSL_write(ssl, req.data(), (int) req.size());
    } else {
        send(fd, req.data(), req.size(), 0);
    }

    std::string resp;
    char buf[4096];
    for (;;) {
        int n = is_tls ? g_SSL_read(ssl, buf, (int) sizeof(buf))
                       : (int) recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, (size_t) n);
        if (resp.size() > 512 * 1024) break;  // safety cap
    }
    if (is_tls) g_SSL_free(ssl);
    close(fd);

    if (resp.rfind("HTTP/1.1 200", 0) != 0 && resp.rfind("HTTP/1.0 200", 0) != 0) {
        LOGW("http status != 200 for %s: %.60s", url, resp.c_str());
        return {};
    }
    size_t hdr_end = resp.find("\r\n\r\n");
    if (hdr_end == std::string::npos) return {};
    return resp.substr(hdr_end + 4);
}
