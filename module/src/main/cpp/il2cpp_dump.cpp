//
// Created by Perfare on 2020/7/4.
//

#include "il2cpp_dump.h"
#include <dlfcn.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "xdl.h"
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"
#include "patterns.h"
#include "sigsearch.h"

#define DO_API(r, n, p) r (*n) p

#include "il2cpp-api-functions.h"

#undef DO_API

static uint64_t il2cpp_base = 0;

// ---------------------------------------------------------------------------
// File-based logging (no adb needed): every step is also written to
// <game_data_dir>/files/il2cppdumper.log so the user can check progress.
// ---------------------------------------------------------------------------
const char *g_log_dir = nullptr;  // set by hack.cpp before il2cpp_api_init
static FILE *g_log = nullptr;

static void logfile_open() {
    if (!g_log_dir) return;
    std::string dir = std::string(g_log_dir) + "/files";
    mkdir(dir.c_str(), 0755);
    g_log = fopen((dir + "/il2cppdumper.log").c_str(), "a");
}

static void logfile(const char *fmt, ...) {
    if (!g_log) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fprintf(g_log, "\n");
    fflush(g_log);
}

// Decode the MLBB-style 16-byte trampoline to find its m_*_ptr slot:
//     adrp x8, #page ; ldr x8, [x8, #off] ; ldr xN, [x8] ; br xN
// The cell at (page+off) is a R_AARCH64_GLOB_DAT relocation pointing to the
// slot variable, i.e. *cell == &m_<name>_ptr. Returns the slot address or
// nullptr if fn is not such a trampoline.
static void **trampoline_slot_of(void *fn) {
    if (!fn) return nullptr;
    uint32_t *code = (uint32_t *) fn;
    // adrp xD, #imm
    if ((code[0] & 0x9F000000) != 0x90000000) return nullptr;
    // ldr xD, [xD, #imm12<<3]  (unsigned immediate, 64-bit)
    if ((code[1] & 0xFFC00000) != 0xF9400000) return nullptr;
    int rd = code[0] & 0x1F;
    int rn = (code[1] >> 5) & 0x1F;
    int rt = code[1] & 0x1F;
    if (rd != rn || rd != rt) return nullptr;
    int64_t immhi = (code[0] >> 5) & 0x7FFFF;
    int64_t immlo = (code[0] >> 29) & 0x3;
    int64_t imm = (immhi << 2) | immlo;
    if (imm & 0x100000) imm -= 0x200000;  // sign extend 21-bit
    uint64_t page = ((uint64_t) fn & ~0xFFFULL) + ((uint64_t) imm << 12);
    uint64_t off = ((code[1] >> 10) & 0xFFF) << 3;
    void **cell = (void **) (page + off);
    return (void **) *cell;  // GLOB_DAT: cell holds the address of the slot
}

// ---------------------------------------------------------------------------
// Signature search fallback for games that strip the exported symbols from
// libil2cpp.so (e.g. Mobile Legends / com.mobile.legends). For every api that
// xdl_sym() could not resolve, try to locate it with a byte pattern from the
// online config (or built-in defaults).
// ---------------------------------------------------------------------------
struct ApiSlot {
    const char *name;
    void **slot;
};

#define API_SLOT(n) { #n, reinterpret_cast<void **>(&n) }

static const ApiSlot kApiSlots[] = {
    API_SLOT(il2cpp_domain_get),
    API_SLOT(il2cpp_domain_get_assemblies),
    API_SLOT(il2cpp_assembly_get_image),
    API_SLOT(il2cpp_image_get_name),
    API_SLOT(il2cpp_image_get_class_count),
    API_SLOT(il2cpp_image_get_class),
    API_SLOT(il2cpp_class_get_type),
    API_SLOT(il2cpp_class_from_type),
    API_SLOT(il2cpp_class_get_name),
    API_SLOT(il2cpp_class_get_namespace),
    API_SLOT(il2cpp_class_get_flags),
    API_SLOT(il2cpp_class_is_valuetype),
    API_SLOT(il2cpp_class_is_enum),
    API_SLOT(il2cpp_class_get_parent),
    API_SLOT(il2cpp_class_get_interfaces),
    API_SLOT(il2cpp_class_get_fields),
    API_SLOT(il2cpp_class_get_properties),
    API_SLOT(il2cpp_class_get_methods),
    API_SLOT(il2cpp_class_from_name),
    API_SLOT(il2cpp_field_get_flags),
    API_SLOT(il2cpp_field_get_name),
    API_SLOT(il2cpp_field_get_type),
    API_SLOT(il2cpp_field_get_offset),
    API_SLOT(il2cpp_field_static_get_value),
    API_SLOT(il2cpp_property_get_get_method),
    API_SLOT(il2cpp_property_get_set_method),
    API_SLOT(il2cpp_property_get_name),
    API_SLOT(il2cpp_method_get_flags),
    API_SLOT(il2cpp_method_get_return_type),
    API_SLOT(il2cpp_method_get_param_count),
    API_SLOT(il2cpp_method_get_param),
    API_SLOT(il2cpp_method_get_param_name),
    API_SLOT(il2cpp_method_get_name),
    API_SLOT(il2cpp_type_is_byref),
    API_SLOT(il2cpp_is_vm_thread),
    API_SLOT(il2cpp_thread_attach),
    API_SLOT(il2cpp_string_new),
};

static void api_fallback_search() {
    for (const auto &s : kApiSlots) {
        if (*s.slot) continue;
        std::string pat = patterns_get(s.name);
        if (pat.empty()) continue;
        void *addr = search_in_module("libil2cpp.so", pat);
        if (addr) {
            LOGI("found %s via signature @ %p", s.name, addr);
            *s.slot = addr;
        }
    }
}

static uint64_t resolve_base_from_apis() {
    for (const auto &s : kApiSlots) {
        if (*s.slot) {
            Dl_info dlInfo;
            if (dladdr(*s.slot, &dlInfo)) {
                return reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
            }
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// MLBB-style stub loader (Mobile Legends): libil2cpp.so on disk is a small
// stub that exports every il2cpp api as a 16-byte trampoline:
//     adrp x8, ...; ldr x8, [x8, #off]; ldr x0, [x8]; br x0
// i.e. it jumps through a global slot "m_<name>_ptr". The real (decrypted)
// lib registers into those slots later via il2cpp_api_register_symbols().
// Calling a trampoline before registration jumps to NULL -> crash / no dump.
// Fix: resolve the slot addresses (they are exported OBJECT symbols), wait
// until the real lib fills them, then overwrite our api pointers with the
// real function addresses.
// ---------------------------------------------------------------------------
static void init_via_stub_slots(void *handle) {
    // canary slot: try the exported OBJECT symbol first, then decode the
    // trampoline of il2cpp_domain_get as a fallback.
    void **domain_slot = (void **) xdl_sym(handle, "m_il2cpp_domain_get_ptr", nullptr);
    void *domain_fn = (void *) xdl_sym(handle, "il2cpp_domain_get", nullptr);
    if (!domain_slot && domain_fn) domain_slot = trampoline_slot_of(domain_fn);
    if (!domain_slot) {
        LOGI("no stub slots (normal lib), skipping slot wait");
        logfile("[init] no stub slots (normal lib), skipping slot wait");
        return;
    }
    LOGI("stub-style lib detected, waiting for real lib registration...");
    logfile("[init] stub-style lib detected, waiting for real lib registration...");
    const int kTimeoutSec = 120;
    int waited = 0;
    for (; waited < kTimeoutSec; ++waited) {
        if (*(volatile void **) domain_slot) break;
        sleep(1);
    }
    if (!*(volatile void **) domain_slot) {
        LOGE("real lib never registered within %ds", kTimeoutSec);
        logfile("[init] ERROR: real lib never registered within %ds", kTimeoutSec);
        return;
    }
    LOGI("real lib registered after ~%ds, resolving real api addresses", waited);
    logfile("[init] real lib registered after ~%ds", waited);
    int resolved = 0;
    int decoded = 0;
    for (const auto &s : kApiSlots) {
        void *real = nullptr;
        std::string slot_name = "m_";
        slot_name += s.name;
        slot_name += "_ptr";
        void **slot = (void **) xdl_sym(handle, slot_name.c_str(), nullptr);
        if (slot && *slot) {
            real = *slot;
        } else {
            void *fn = (void *) xdl_sym(handle, s.name, nullptr);
            void **ts = trampoline_slot_of(fn);
            if (ts && *ts) {
                real = *ts;
                ++decoded;
            }
        }
        if (real) {
            *s.slot = real;
            ++resolved;
        }
    }
    LOGI("resolved %d real functions via slots (%d via trampoline decode)",
         resolved, decoded);
    logfile("[init] resolved %d real functions via slots (%d via trampoline decode)",
            resolved, decoded);
}

void init_il2cpp_api(void *handle) {
#define DO_API(r, n, p) {                      \
    n = (r (*) p)xdl_sym(handle, #n, nullptr); \
    if(!n) {                                   \
        LOGW("api not found %s", #n);          \
    }                                          \
}

#include "il2cpp-api-functions.h"

#undef DO_API
}

std::string get_method_modifier(uint32_t flags) {
    std::stringstream outPut;
    auto access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
    switch (access) {
        case METHOD_ATTRIBUTE_PRIVATE:
            outPut << "private ";
            break;
        case METHOD_ATTRIBUTE_PUBLIC:
            outPut << "public ";
            break;
        case METHOD_ATTRIBUTE_FAMILY:
            outPut << "protected ";
            break;
        case METHOD_ATTRIBUTE_ASSEM:
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
            outPut << "internal ";
            break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & METHOD_ATTRIBUTE_STATIC) {
        outPut << "static ";
    }
    if (flags & METHOD_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            outPut << "override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_FINAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            outPut << "sealed override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_VIRTUAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT) {
            outPut << "virtual ";
        } else {
            outPut << "override ";
        }
    }
    if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) {
        outPut << "extern ";
    }
    return outPut.str();
}

bool _il2cpp_type_is_byref(const Il2CppType *type) {
    auto byref = type->byref;
    if (il2cpp_type_is_byref) {
        byref = il2cpp_type_is_byref(type);
    }
    return byref;
}

std::string dump_method(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Methods\n";
    void *iter = nullptr;
    while (auto method = il2cpp_class_get_methods(klass, &iter)) {
        //TODO attribute
        if (method->methodPointer) {
            outPut << "\t// RVA: 0x";
            outPut << std::hex << (uint64_t) method->methodPointer - il2cpp_base;
            outPut << " VA: 0x";
            outPut << std::hex << (uint64_t) method->methodPointer;
        } else {
            outPut << "\t// RVA: 0x VA: 0x0";
        }
        /*if (method->slot != 65535) {
            outPut << " Slot: " << std::dec << method->slot;
        }*/
        outPut << "\n\t";
        uint32_t iflags = 0;
        auto flags = il2cpp_method_get_flags(method, &iflags);
        outPut << get_method_modifier(flags);
        //TODO genericContainerIndex
        auto return_type = il2cpp_method_get_return_type(method);
        if (_il2cpp_type_is_byref(return_type)) {
            outPut << "ref ";
        }
        auto return_class = il2cpp_class_from_type(return_type);
        outPut << il2cpp_class_get_name(return_class) << " " << il2cpp_method_get_name(method)
               << "(";
        auto param_count = il2cpp_method_get_param_count(method);
        for (int i = 0; i < param_count; ++i) {
            auto param = il2cpp_method_get_param(method, i);
            auto attrs = param->attrs;
            if (_il2cpp_type_is_byref(param)) {
                if (attrs & PARAM_ATTRIBUTE_OUT && !(attrs & PARAM_ATTRIBUTE_IN)) {
                    outPut << "out ";
                } else if (attrs & PARAM_ATTRIBUTE_IN && !(attrs & PARAM_ATTRIBUTE_OUT)) {
                    outPut << "in ";
                } else {
                    outPut << "ref ";
                }
            } else {
                if (attrs & PARAM_ATTRIBUTE_IN) {
                    outPut << "[In] ";
                }
                if (attrs & PARAM_ATTRIBUTE_OUT) {
                    outPut << "[Out] ";
                }
            }
            auto parameter_class = il2cpp_class_from_type(param);
            outPut << il2cpp_class_get_name(parameter_class) << " "
                   << il2cpp_method_get_param_name(method, i);
            outPut << ", ";
        }
        if (param_count > 0) {
            outPut.seekp(-2, outPut.cur);
        }
        outPut << ") { }\n";
        //TODO GenericInstMethod
    }
    return outPut.str();
}

std::string dump_property(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Properties\n";
    void *iter = nullptr;
    while (auto prop_const = il2cpp_class_get_properties(klass, &iter)) {
        //TODO attribute
        auto prop = const_cast<PropertyInfo *>(prop_const);
        auto get = il2cpp_property_get_get_method(prop);
        auto set = il2cpp_property_get_set_method(prop);
        auto prop_name = il2cpp_property_get_name(prop);
        outPut << "\t";
        Il2CppClass *prop_class = nullptr;
        uint32_t iflags = 0;
        if (get) {
            outPut << get_method_modifier(il2cpp_method_get_flags(get, &iflags));
            prop_class = il2cpp_class_from_type(il2cpp_method_get_return_type(get));
        } else if (set) {
            outPut << get_method_modifier(il2cpp_method_get_flags(set, &iflags));
            auto param = il2cpp_method_get_param(set, 0);
            prop_class = il2cpp_class_from_type(param);
        }
        if (prop_class) {
            outPut << il2cpp_class_get_name(prop_class) << " " << prop_name << " { ";
            if (get) {
                outPut << "get; ";
            }
            if (set) {
                outPut << "set; ";
            }
            outPut << "}\n";
        } else {
            if (prop_name) {
                outPut << " // unknown property " << prop_name;
            }
        }
    }
    return outPut.str();
}

std::string dump_field(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Fields\n";
    auto is_enum = il2cpp_class_is_enum(klass);
    void *iter = nullptr;
    while (auto field = il2cpp_class_get_fields(klass, &iter)) {
        //TODO attribute
        outPut << "\t";
        auto attrs = il2cpp_field_get_flags(field);
        auto access = attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access) {
            case FIELD_ATTRIBUTE_PRIVATE:
                outPut << "private ";
                break;
            case FIELD_ATTRIBUTE_PUBLIC:
                outPut << "public ";
                break;
            case FIELD_ATTRIBUTE_FAMILY:
                outPut << "protected ";
                break;
            case FIELD_ATTRIBUTE_ASSEMBLY:
            case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                outPut << "internal ";
                break;
            case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                outPut << "protected internal ";
                break;
        }
        if (attrs & FIELD_ATTRIBUTE_LITERAL) {
            outPut << "const ";
        } else {
            if (attrs & FIELD_ATTRIBUTE_STATIC) {
                outPut << "static ";
            }
            if (attrs & FIELD_ATTRIBUTE_INIT_ONLY) {
                outPut << "readonly ";
            }
        }
        auto field_type = il2cpp_field_get_type(field);
        auto field_class = il2cpp_class_from_type(field_type);
        outPut << il2cpp_class_get_name(field_class) << " " << il2cpp_field_get_name(field);
        //TODO 获取构造函数初始化后的字段值
        if (attrs & FIELD_ATTRIBUTE_LITERAL && is_enum) {
            uint64_t val = 0;
            il2cpp_field_static_get_value(field, &val);
            outPut << " = " << std::dec << val;
        }
        outPut << "; // 0x" << std::hex << il2cpp_field_get_offset(field) << "\n";
    }
    return outPut.str();
}

std::string dump_type(const Il2CppType *type) {
    std::stringstream outPut;
    auto *klass = il2cpp_class_from_type(type);
    outPut << "\n// Namespace: " << il2cpp_class_get_namespace(klass) << "\n";
    auto flags = il2cpp_class_get_flags(klass);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) {
        outPut << "[Serializable]\n";
    }
    //TODO attribute
    auto is_valuetype = il2cpp_class_is_valuetype(klass);
    auto is_enum = il2cpp_class_is_enum(klass);
    auto visibility = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility) {
        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC:
            outPut << "public ";
            break;
        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
            outPut << "internal ";
            break;
        case TYPE_ATTRIBUTE_NESTED_PRIVATE:
            outPut << "private ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAMILY:
            outPut << "protected ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & TYPE_ATTRIBUTE_ABSTRACT && flags & TYPE_ATTRIBUTE_SEALED) {
        outPut << "static ";
    } else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && flags & TYPE_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
    } else if (!is_valuetype && !is_enum && flags & TYPE_ATTRIBUTE_SEALED) {
        outPut << "sealed ";
    }
    if (flags & TYPE_ATTRIBUTE_INTERFACE) {
        outPut << "interface ";
    } else if (is_enum) {
        outPut << "enum ";
    } else if (is_valuetype) {
        outPut << "struct ";
    } else {
        outPut << "class ";
    }
    outPut << il2cpp_class_get_name(klass); //TODO genericContainerIndex
    std::vector<std::string> extends;
    auto parent = il2cpp_class_get_parent(klass);
    if (!is_valuetype && !is_enum && parent) {
        auto parent_type = il2cpp_class_get_type(parent);
        if (parent_type->type != IL2CPP_TYPE_OBJECT) {
            extends.emplace_back(il2cpp_class_get_name(parent));
        }
    }
    void *iter = nullptr;
    while (auto itf = il2cpp_class_get_interfaces(klass, &iter)) {
        extends.emplace_back(il2cpp_class_get_name(itf));
    }
    if (!extends.empty()) {
        outPut << " : " << extends[0];
        for (int i = 1; i < extends.size(); ++i) {
            outPut << ", " << extends[i];
        }
    }
    outPut << "\n{";
    outPut << dump_field(klass);
    outPut << dump_property(klass);
    outPut << dump_method(klass);
    //TODO EventInfo
    outPut << "}\n";
    return outPut.str();
}

void il2cpp_api_init(void *handle) {
    LOGI("il2cpp_handle: %p", handle);
    logfile_open();
    logfile("=== il2cpp_api_init handle=%p ===", handle);
    patterns_init();
    init_il2cpp_api(handle);
    init_via_stub_slots(handle);
    api_fallback_search();
    il2cpp_base = resolve_base_from_apis();
    LOGI("il2cpp_base: %" PRIx64"", il2cpp_base);
    logfile("[init] il2cpp_base: %" PRIx64, il2cpp_base);
    if (!il2cpp_base) {
        LOGE("Failed to initialize il2cpp api.");
        logfile("[init] ERROR: failed to initialize il2cpp api");
        return;
    }
    while (!il2cpp_is_vm_thread(nullptr)) {
        LOGI("Waiting for il2cpp_init...");
        sleep(1);
    }
    logfile("[init] il2cpp vm thread ready");
    auto domain = il2cpp_domain_get();
    il2cpp_thread_attach(domain);
}

void il2cpp_dump(const char *outDir) {
    LOGI("dumping...");
    logfile("[dump] dumping to %s", outDir);
    size_t size;
    auto domain = il2cpp_domain_get();
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
    std::stringstream imageOutput;
    for (int i = 0; i < size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        imageOutput << "// Image " << i << ": " << il2cpp_image_get_name(image) << "\n";
    }
    std::vector<std::string> outPuts;
    if (il2cpp_image_get_class) {
        LOGI("Version greater than 2018.3");
        //使用il2cpp_image_get_class
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            imageStr << "\n// Dll : " << il2cpp_image_get_name(image);
            auto classCount = il2cpp_image_get_class_count(image);
            for (int j = 0; j < classCount; ++j) {
                auto klass = il2cpp_image_get_class(image, j);
                auto type = il2cpp_class_get_type(const_cast<Il2CppClass *>(klass));
                //LOGD("type name : %s", il2cpp_type_get_name(type));
                auto outPut = imageStr.str() + dump_type(type);
                outPuts.push_back(outPut);
            }
        }
    } else {
        LOGI("Version less than 2018.3");
        //使用反射
        auto corlib = il2cpp_get_corlib();
        auto assemblyClass = il2cpp_class_from_name(corlib, "System.Reflection", "Assembly");
        auto assemblyLoad = il2cpp_class_get_method_from_name(assemblyClass, "Load", 1);
        auto assemblyGetTypes = il2cpp_class_get_method_from_name(assemblyClass, "GetTypes", 0);
        if (assemblyLoad && assemblyLoad->methodPointer) {
            LOGI("Assembly::Load: %p", assemblyLoad->methodPointer);
        } else {
            LOGI("miss Assembly::Load");
            return;
        }
        if (assemblyGetTypes && assemblyGetTypes->methodPointer) {
            LOGI("Assembly::GetTypes: %p", assemblyGetTypes->methodPointer);
        } else {
            LOGI("miss Assembly::GetTypes");
            return;
        }
        typedef void *(*Assembly_Load_ftn)(void *, Il2CppString *, void *);
        typedef Il2CppArray *(*Assembly_GetTypes_ftn)(void *, void *);
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            auto image_name = il2cpp_image_get_name(image);
            imageStr << "\n// Dll : " << image_name;
            //LOGD("image name : %s", image->name);
            auto imageName = std::string(image_name);
            auto pos = imageName.rfind('.');
            auto imageNameNoExt = imageName.substr(0, pos);
            auto assemblyFileName = il2cpp_string_new(imageNameNoExt.data());
            auto reflectionAssembly = ((Assembly_Load_ftn) assemblyLoad->methodPointer)(nullptr,
                                                                                        assemblyFileName,
                                                                                        nullptr);
            auto reflectionTypes = ((Assembly_GetTypes_ftn) assemblyGetTypes->methodPointer)(
                    reflectionAssembly, nullptr);
            auto items = reflectionTypes->vector;
            for (int j = 0; j < reflectionTypes->max_length; ++j) {
                auto klass = il2cpp_class_from_system_type((Il2CppReflectionType *) items[j]);
                auto type = il2cpp_class_get_type(klass);
                //LOGD("type name : %s", il2cpp_type_get_name(type));
                auto outPut = imageStr.str() + dump_type(type);
                outPuts.push_back(outPut);
            }
        }
    }
    LOGI("write dump file");
    auto outPath = std::string(outDir).append("/files/dump.cs");
    std::ofstream outStream(outPath);
    outStream << imageOutput.str();
    auto count = outPuts.size();
    for (int i = 0; i < count; ++i) {
        outStream << outPuts[i];
    }
    outStream.close();
    LOGI("dump done!");
    logfile("[dump] dump.cs written (%zu types)", outPuts.size());

    // Bonus: also save the decrypted libil2cpp.so and global-metadata.dat
    // straight from memory, so they can be analysed offline with
    // Il2CppDumper / IDA even when the on-disk copies are packed.
    dump_lib_and_metadata(outDir, (uintptr_t) il2cpp_base);
}