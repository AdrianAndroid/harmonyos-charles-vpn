// Node-API bridge for the Charles TUN proxy.
//
// ArkTS surface (import charles_vpn from 'libcharles_vpn.so'):
//   startVpnProxy(targetIp: string, targetPort: number): void
//       Public. Validates the IPv4 literal/port and prepares a proxy session in
//       this extension process. No worker thread and no fd is touched here;
//       ArkTS calls VpnConnection.protectProcessNet() (API 22+) before creating
//       the TUN, so outbound sockets need no private protection syscall.
//   attachTunFd(fd: number): void
//       Internal bridge. Duplicates the TUN fd and starts the worker thread on
//       the copy; the ArkTS side retains ownership of its own fd.
//   stopVpnProxy(): void
//       Public, idempotent. Wakes poll, joins the worker and closes every owned
//       descriptor (duplicated TUN fd, wake pipe, all Charles sockets).
//   isVpnRunning(): boolean
//       Public. Reflects whether a worker is currently attached.
//   setVpnEventCallback(cb: ((message: string) => void) | null): void
//       Internal. Installs a ThreadSafeFunction. Forwarding errors raised on
//       the worker are marshalled to JS as strings; the worker never calls into
//       JS directly. Synchronous start/attach failures throw a JS Error instead.
//
// TSFN discipline: all napi_release_threadsafe_function calls happen on the JS
// thread (callback replacement / module unload), never from the worker. The
// worker only performs non-blocking napi_call_threadsafe_function and drops the
// event when the queue is full or closing, so no use-after-release is possible.

#include <node_api.h>

#include <cstdint>
#include <cstring>
#include <cmath>
#include <mutex>
#include <new>
#include <string>

#include "http_request.h"
#include "tun_proxy.h"

namespace {

charles::TunProxy& proxy() {
    static charles::TunProxy instance;
    return instance;
}

std::mutex& bridge_mutex() {
    static std::mutex m;
    return m;
}

napi_threadsafe_function g_tsfn = nullptr;
napi_env g_env = nullptr;

void throw_js_error(napi_env env, const std::string& message) {
    napi_throw_error(env, nullptr, message.c_str());
}

bool require_argc(napi_env env, size_t argc, size_t expected) {
    if (argc < expected) {
        throw_js_error(env, "insufficient arguments");
        return false;
    }
    return true;
}

// napi_threadsafe_function entry point: runs on the JS thread.
void call_js_event(napi_env env, napi_value js_callback, void* /*context*/, void* data) {
    auto* message = static_cast<std::string*>(data);
    if (env == nullptr || js_callback == nullptr) {
        delete message;  // environment tearing down
        return;
    }
    napi_handle_scope scope;
    if (napi_open_handle_scope(env, &scope) != napi_ok) {
        delete message;
        return;
    }
    napi_value argv;
    if (napi_create_string_utf8(env, message->c_str(), message->size(), &argv) == napi_ok) {
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        napi_call_function(env, undefined, js_callback, 1, &argv, nullptr);
    }
    napi_close_handle_scope(env, scope);
    delete message;
}

void dispatch_event_to_js(const std::string& message) {
    napi_threadsafe_function tsfn;
    {
        std::lock_guard<std::mutex> lock(bridge_mutex());
        tsfn = g_tsfn;
    }
    if (tsfn == nullptr) return;  // no listener installed: drop
    auto* heap = new (std::nothrow) std::string(message);
    if (heap == nullptr) return;
    // Non-blocking: a full queue returns napi_queue_full and we drop the event
    // instead of stalling the forwarding worker.
    napi_status st = napi_call_threadsafe_function(tsfn, heap, napi_tsfn_nonblocking);
    if (st != napi_ok) delete heap;
}

napi_value StartVpnProxy(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (!require_argc(env, argc, 2)) return nullptr;

    napi_valuetype t0;
    napi_typeof(env, argv[0], &t0);
    napi_valuetype t1;
    napi_typeof(env, argv[1], &t1);
    if (t0 != napi_string || t1 != napi_number) {
        throw_js_error(env, "usage: startVpnProxy(targetIp: string, targetPort: number)");
        return nullptr;
    }

    size_t copied = 0;
    char ip_buf[64];
    if (napi_get_value_string_utf8(env, argv[0], ip_buf, sizeof(ip_buf), &copied) != napi_ok) {
        throw_js_error(env, "targetIp is not a valid string");
        return nullptr;
    }
    std::string ip(ip_buf, copied);

    double requested_port = 0;
    if (napi_get_value_double(env, argv[1], &requested_port) != napi_ok ||
        !std::isfinite(requested_port) || std::floor(requested_port) != requested_port ||
        requested_port < 1 || requested_port > 65535) {
        throw_js_error(env, "targetPort must be an integer in 1..65535");
        return nullptr;
    }
    uint32_t port = static_cast<uint32_t>(requested_port);

    uint32_t parsed = 0;
    if (!charles::parse_ipv4(ip, parsed)) {
        throw_js_error(env, "targetIp must be a valid IPv4 dotted-quad address");
        return nullptr;
    }

    std::string error;
    if (!proxy().configure(ip, static_cast<uint16_t>(port), error)) {
        throw_js_error(env, error);
        return nullptr;
    }
    // Re-arm the event sink in case a fresh proxy instance is configured.
    proxy().set_event_callback(dispatch_event_to_js);
    return nullptr;
}

napi_value AttachTunFd(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (!require_argc(env, argc, 1)) return nullptr;

    napi_valuetype t;
    napi_typeof(env, argv[0], &t);
    if (t != napi_number) {
        throw_js_error(env, "usage: attachTunFd(fd: number)");
        return nullptr;
    }
    int32_t fd = -1;
    if (napi_get_value_int32(env, argv[0], &fd) != napi_ok || fd < 0) {
        throw_js_error(env, "attachTunFd requires a non-negative file descriptor");
        return nullptr;
    }

    std::string error;
    if (!proxy().attach(fd, error)) {
        throw_js_error(env, error);
        return nullptr;
    }
    return nullptr;
}

napi_value StopVpnProxy(napi_env env, napi_callback_info /*info*/) {
    (void)env;
    proxy().stop();  // idempotent; safe with no prior attach
    return nullptr;
}

napi_value IsVpnRunning(napi_env env, napi_callback_info /*info*/) {
    napi_value result;
    napi_get_boolean(env, proxy().is_running(), &result);
    return result;
}

napi_value SetVpnEventCallback(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (!require_argc(env, argc, 1)) return nullptr;

    napi_valuetype t;
    napi_typeof(env, argv[0], &t);
    if (t != napi_function && t != napi_null && t != napi_undefined) {
        throw_js_error(env, "usage: setVpnEventCallback(cb: function | null)");
        return nullptr;
    }

    napi_threadsafe_function old;
    {
        std::lock_guard<std::mutex> lock(bridge_mutex());
        old = g_tsfn;
    }
    if (old != nullptr && proxy().is_running()) {
        throw_js_error(env, "stopVpnProxy must be called before replacing the event callback");
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(bridge_mutex());
        g_tsfn = nullptr;
    }
    if (old != nullptr) {
        // Join even an already-failed worker; is_running()==false alone does not
        // prove that the thread has returned from its final event callback.
        proxy().stop();
        napi_release_threadsafe_function(old, napi_tsfn_release);
    }

    if (t == napi_function) {
        napi_value name;
        napi_create_string_utf8(env, "charlesVpnEvents", NAPI_AUTO_LENGTH, &name);
        napi_threadsafe_function tsfn;
        // Bounded queue: under an event storm the non-blocking call below gets
        // napi_queue_full and the worker drops the event instead of growing
        // memory without limit.
        constexpr size_t MAX_QUEUE = 64;
        napi_status st = napi_create_threadsafe_function(env, argv[0], nullptr, name, MAX_QUEUE, 1,
                                                         nullptr, nullptr, nullptr, call_js_event,
                                                         &tsfn);
        if (st != napi_ok) {
            throw_js_error(env, "failed to create threadsafe event callback");
            return nullptr;
        }
        {
            std::lock_guard<std::mutex> lock(bridge_mutex());
            g_tsfn = tsfn;
        }
        proxy().set_event_callback(dispatch_event_to_js);
    } else {
        proxy().set_event_callback(nullptr);
    }
    return nullptr;
}

void environment_cleanup(void* data) {
    // Env teardown may happen without ArkTS onDestroy. Join first, then release
    // the TSFN on the JS thread so a worker can never retain a freed function.
    proxy().stop();
    proxy().set_event_callback(nullptr);
    napi_threadsafe_function tsfn = nullptr;
    {
        std::lock_guard<std::mutex> lock(bridge_mutex());
        if (g_env == data) {
            tsfn = g_tsfn;
            g_tsfn = nullptr;
            g_env = nullptr;
        }
    }
    if (tsfn != nullptr) napi_release_threadsafe_function(tsfn, napi_tsfn_release);
}

napi_value Register(napi_env env, napi_value exports) {
    g_env = env;
    napi_add_env_cleanup_hook(env, environment_cleanup, env);
    const napi_property_descriptor desc[] = {
        {"startVpnProxy", nullptr, StartVpnProxy, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"attachTunFd", nullptr, AttachTunFd, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"stopVpnProxy", nullptr, StopVpnProxy, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"isVpnRunning", nullptr, IsVpnRunning, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"setVpnEventCallback", nullptr, SetVpnEventCallback, nullptr, nullptr, nullptr, napi_default,
         nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}

}  // namespace

static napi_module g_vpn_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Register,
    .nm_modname = "charles_vpn",
    .nm_priv = nullptr,
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterCharlesVpnModule(void) {
    napi_module_register(&g_vpn_module);
}
