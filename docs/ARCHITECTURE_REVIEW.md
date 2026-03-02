# LiveINI Starfield: Architecture and Newcomer Guide

## What this project is
LiveINI Starfield is a native Windows desktop reverse-engineering utility for the game `Starfield.exe`. It uses Win32 + DirectX 11 + Dear ImGui to present multiple research tools in one UI:
- process attachment and memory snapshotting,
- RTTI/vtable discovery,
- game setting discovery and live editing,
- AOB signature scanning,
- method-to-vtable lookup,
- coarse heap scanning.

At a high level, the app opens the game process, copies the game executable image into local memory, derives metadata from PE sections, then uses heuristic scans over that snapshot to populate UI tabs.

## Runtime flow (end-to-end)
1. **UI startup**: `WinMain` creates a Win32 window, initializes D3D11, and starts the ImGui frame loop.
2. **User clicks "Scan Starfield"**: the app resolves a process ID (`Starfield.exe` or matching window title), opens the process, snapshots the image module into `GameProcessInfo.buffer`.
3. **Analysis pipeline** (ordered and stateful):
   - `perform_exe_section_analysis()` locates `.text/.rdata/.data/.rsrc` ranges.
   - `perform_exe_version_analysis()` extracts ProductVersion from `.rsrc`.
   - `turbo_vtable_algorithm()` walks `.rdata` and `.data` to infer RTTI/vtable candidates.
   - `scan_vtable()` (unless Ctrl held) finds live `GameSetting` instances by matching known setting class vtables.
4. **Tabs consume shared process state**:
   - **Setting** tab filters/edits settings and writes back with `WriteProcessMemory`.
   - **RTTI** tab browses discovered classes and vtable metadata.
   - **AOB** tab scans `.text` for byte signatures.
   - **Method** tab maps a function RVA back to owning vtables.
   - **Heap** tab enumerates large committed regions and scans for pointer matches.

## Core data model newcomers should understand first
- `GameProcessInfo` is the global state bag with process handle, image snapshot, PE section metadata, discovered RTTI map, and process identity.
- `GameSetting` is the target in-memory record (`vTable`, `Active`, `Default`, `Name`).
- `Setting` is the UI/edit wrapper around `GameSetting`, including search fields and type/origin flags.

Understanding those three makes almost every tab implementation straightforward.

## File-by-file map
- `LiveINI/main.cpp`: app bootstrap, tab wiring, and scan trigger orchestration.
- `LiveINI/process.cpp`: process discovery, module base lookup, RPM/WPM wrappers.
- `LiveINI/memory_scan.cpp`: PE parsing, RTTI/vtable inference, settings discovery/edit/filter, version extraction.
- `LiveINI/setting.{h,cpp}`: setting type/origin flags and guarded update write-back.
- `LiveINI/rtti_window.cpp`: RTTI browser/search UI.
- `LiveINI/aob_window.cpp` + `LiveINI/aobscan.cpp`: user-entered signature compilation and scanning.
- `LiveINI/method_window.cpp`: function-offset-to-vtable reverse lookup.
- `LiveINI/heap_window.cpp`: big-region heap discovery + pointer scans.

## Important implementation details
- The scanner intentionally works on a **local snapshot** of the main module for speed and deterministic analysis.
- Writes (`Setting::Update`) are guarded by identity checks (vtable/name/default) before mutating `Active`.
- Search in RTTI/setting tabs supports regex via bundled `minilibs/regexp`.
- AOB supports wildcard nibbles (`?`) by encoding masks in a custom `uint16_t` signature format.

## Issues found
1. **Flag collision bug**: `OriginRegSetting` and `FlagChanged` both use `1 << 13`.
   - Effect: changed-state tracking overlaps with origin classification.
   - Symptom: include/exclude filters and “Reset changed settings” behavior can become ambiguous.
2. **Potential out-of-bounds read in AOB scanner**:
   - `aob_scan` increments `i` inside the inner `while` without checking `i < count` before `haystack[i]` access.
   - Crafted or edge signatures near buffer tail can read past end.
3. **Resource leak path in process scanning**:
   - `ScanProcess` can allocate/open (`proc_handle`, `buffer`) and then return early on `RPM` failure without releasing new resources.
4. **No handle cleanup on app exit for attached process**:
   - Main shutdown path does not explicitly close `GameProcessInfo.process` or free `GameProcessInfo.buffer`.
5. **Heap enumeration filter likely inverted/overly strict**:
   - `if (address > GameProcessInfo.base_address) continue;` skips regions above module base, excluding many heaps on 64-bit layouts.
6. **Aggressive process rights**:
   - Uses `PROCESS_ALL_ACCESS`; can fail on stricter environments where narrower rights would succeed.
7. **Robustness gaps from `assert` in user paths**:
   - Several parsing/scanning paths rely on asserts (`perform_exe_version_analysis`, AOB parser), which may hard-stop in debug builds on malformed input.

## Recommendations (prioritized)
1. **Fix flags first**
   - Move `FlagChanged` to a unique bit (`1 << 14` or above) and re-test filters.
2. **Harden bounds in scan loops**
   - Guard all index arithmetic in `aob_scan` and turbo-vtable candidate walks (`i+1` access) with explicit bounds checks.
3. **Introduce RAII for process resources**
   - Wrap process handle and aligned buffer with scoped owners to eliminate leak-prone early returns.
4. **Reduce requested process permissions**
   - Use minimal rights (`PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION`) and escalate only when needed.
5. **Add explicit detach/cleanup semantics**
   - On rescan and on app shutdown, consistently release process handle, free buffer, clear maps/results.
6. **Add a tiny validation suite for pure functions**
   - Unit-test `aob_compile/aob_scan`, flag helpers, and type decoding in isolation (no game process needed).
7. **Document operator workflow**
   - Expand README with scan-order assumptions, key modifiers (Shift/Ctrl), and expected failure modes.

## Newcomer onboarding checklist
1. Read `main.cpp` to understand tab lifecycle and scan trigger.
2. Read `process.cpp` to understand process/module primitives.
3. Step through `memory_scan.cpp` in this exact order:
   - section analysis,
   - version analysis,
   - RTTI/vtable inference,
   - setting discovery.
4. Validate one end-to-end setting edit in debugger (`Setting::Update`).
5. Then explore specialized tabs (RTTI/AOB/Method/Heap).
