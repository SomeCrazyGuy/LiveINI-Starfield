# LiveINI Starfield

[![MSBuild](https://github.com/SomeCrazyGuy/LiveINI-Starfield/actions/workflows/msbuild.yml/badge.svg)](https://github.com/SomeCrazyGuy/LiveINI-Starfield/actions/workflows/msbuild.yml)

LiveINI Starfield is a Win32/DirectX11 + Dear ImGui research utility for discovering and editing live game settings in `Starfield.exe`.

## Repository orientation
- Main application entry and tab orchestration: `LiveINI/main.cpp`
- Process attach/memory primitives: `LiveINI/process.cpp`
- Scanning and settings logic: `LiveINI/memory_scan.cpp`
- RTTI/AOB/Method/Heap tools: corresponding `*_window.cpp` files

## Newcomer guide and architecture review
A detailed walkthrough of internals, issue audit, and recommendations is available at:

- `docs/ARCHITECTURE_REVIEW.md`
