# Zygisk-Il2CppDumper
Il2CppDumper with Zygisk, dump il2cpp data at runtime, can bypass protection, encryption and obfuscation.

中文说明请戳[这里](README.zh-CN.md)

## How to use
1. Install [Magisk](https://github.com/topjohnwu/Magisk) v24 or later and enable Zygisk
2. Build module
   - GitHub Actions
      1. Fork this repo
      2. Go to the **Actions** tab in your forked repo
      3. In the left sidebar, click the **Build** workflow.
      4. Above the list of workflow runs, select **Run workflow**
      5. Input the game package name and click **Run workflow**
      6. Wait for the action to complete and download the artifact
   - Android Studio
      1. Download the source code
      2. Edit `game.h`, modify `GamePackageName` to the game package name
      3. Use Android Studio to run the gradle task `:module:assembleRelease` to compile, the zip package will be generated in the `out` folder
3. Install module in Magisk
4. Start the game, `dump.cs` will be generated in the `/data/data/GamePackageName/files/` directory

## Mobile Legends (com.mobile.legends) support

This fork targets **Mobile Legends: Bang Bang** (`com.mobile.legends`) by default and adds three things on top of the upstream module:

### 1. Signature search fallback (stripped exports)

Some games strip the exported symbols from `libil2cpp.so`, so the normal `xdl_sym()` lookup fails and `dump.cs` is never generated. This fork falls back to a **byte-pattern (signature) scan** of the module in memory to locate the il2cpp API functions.

### 1b. MLBB stub-loader wait (Mobile Legends specific)

MLBB ships a **small stub** `libil2cpp.so` (~384 KB) that exports every il2cpp API as a 16-byte trampoline jumping through a global slot `m_<name>_ptr`. The real (decrypted) lib is unpacked from `assets/Resources4-*.dat` at runtime and registers into those slots via `il2cpp_api_register_symbols()`. Calling a trampoline before registration jumps to NULL → crash / no dump.

The module detects the exported `m_*_ptr` slots, **waits until the real lib registers them** (up to 120 s), then replaces the API pointers with the real addresses — the trampolines are never called early.

### 2. Online signature config (no recompile per game version)

The patterns are served from a URL instead of being hardcoded, so they can be updated whenever MLBB ships a new version (the game updates very often). Format served by the URL:

```json
{
  "version": "MLBB 2.1.95.12053",
  "patterns": {
    "il2cpp_domain_get_assemblies": "48 8B 05 ?? ?? ?? ?? C3",
    "il2cpp_class_get_methods": "..."
  }
}
```

- Hex bytes separated by spaces, `??` = wildcard.
- Supports `http://` and `https://` (https uses the system `libssl.so`, no bundled TLS).
- If the URL is empty or unreachable, the module keeps the plain `xdl_sym()` behaviour — normal Unity games are unaffected.
- Set the URL in `module/src/main/cpp/game.h` (`OnlineConfigUrl`) or via the **Build workflow input** `config_url` — no source changes needed per game update.

### 3. Memory dump of libil2cpp.so + global-metadata.dat

After dumping `dump.cs`, the module also saves the decrypted `libil2cpp_dump.so` and `global-metadata.dat` straight from memory into the same `files/` directory, so the binary can be analysed offline (Il2CppDumper / IDA) even when the on-disk copies are packed or encrypted.

### Building for MLBB

1. Fork this repo
2. **Actions** tab → **Build** workflow → **Run workflow**
3. `package_name` defaults to `com.mobile.legends`; optionally paste your signature config URL into `config_url`
4. Download the artifact and install the zip in Magisk
5. Start the game — `dump.cs`, `libil2cpp_dump.so` and `global-metadata.dat` land in `/data/data/com.mobile.legends/files/`