#pragma once

constexpr unsigned AOB_NO_MATCH = 0xFFFFFFFF;

/// scan a buffer of memory for a hex signature match, ?? is supported
/// returns the offset of the match or AOB_NO_MATCH
extern unsigned aob_scan(const void* buffer, unsigned buffer_size, unsigned starting_offset, const char* signature);
