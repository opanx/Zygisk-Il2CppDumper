//
// Created by Perfare on 2020/7/4.
//

#ifndef ZYGISK_IL2CPPDUMPER_GAME_H
#define ZYGISK_IL2CPPDUMPER_GAME_H

// Package name of the game to dump. The GitHub Actions workflow replaces
// the "com.game.packagename" placeholder automatically (default input:
// com.mobile.legends).
#define GamePackageName "com.game.packagename"

// Online signature config URL (optional, keep "" to disable).
//
// Games like Mobile Legends (com.mobile.legends) strip the exported symbols
// from libil2cpp.so, so xdl_sym() fails and dump.cs is never generated.
// This module falls back to a byte-pattern (signature) search in memory.
// The patterns are served from this URL so they can be updated per game
// version WITHOUT recompiling the module.
//
// Format (plain JSON, http:// or https://):
//   {
//     "version": "MLBB 1.9.x",
//     "patterns": {
//       "il2cpp_domain_get_assemblies": "48 8B 05 ?? ?? ?? ?? C3",
//       "il2cpp_class_get_methods": "..."
//     }
//   }
// Hex bytes separated by spaces, "??" = wildcard. Any function that has no
// pattern (or when the URL is empty / unreachable) simply keeps the
// xdl_sym() result (works fine for normal Unity games).
#define OnlineConfigUrl ""

#endif //ZYGISK_IL2CPPDUMPER_GAME_H
