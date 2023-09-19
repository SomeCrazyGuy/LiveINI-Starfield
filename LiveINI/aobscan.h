#pragma once

constexpr unsigned AOB_NO_MATCH = 0xFFFFFFFF;

//treat as opaque
typedef uint16_t* AOB_SIG;

//compiles an array of bytes string to an optimized format, returns null on error
extern AOB_SIG aob_compile(const char* signature);

//free a compiled signature
extern void aob_free(AOB_SIG sig);

/// scan a buffer of memory for a hex signature match, ?? is supported
/// returns the offset of the match or AOB_NO_MATCH
extern unsigned aob_scan(const void* buffer, unsigned buffer_size, unsigned starting_offset, AOB_SIG sig);
