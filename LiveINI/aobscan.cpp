#include "main.h"
#include "aobscan.h"


static constexpr uint16_t sig_end = 0xFFFF;

extern AOB_SIG aob_compile(const char* signature) {
        const auto siglen = strlen(signature);

        //compile signature
        uint16_t* sig = (uint16_t*)malloc((siglen + 1) * 2);
        assert(sig != NULL);

        static const auto unhex = [](char upper, char lower) -> uint16_t {
                uint16_t ret = 0xFF00;

                upper = (char)::toupper(upper);
                lower = (char)::toupper(lower);

                if (upper == '?') {
                        ret &= 0x0FFF;
                }
                else if ((upper >= '0') && (upper <= '9')) {
                        ret |= (upper - '0') << 4;
                }
                else if ((upper >= 'A') && (upper <= 'F')) {
                        ret |= (10 + (upper - 'A')) << 4;
                }
                else {
                        assert(false);
                }

                if (lower == '?') {
                        ret &= 0xF0FF;
                }
                else if ((lower >= '0') && (lower <= '9')) {
                        ret |= (lower - '0');
                }
                else if ((lower >= 'A') && (lower <= 'F')) {
                        ret |= (10 + (lower - 'A'));
                }
                else {
                        assert(false);
                }

                return ret;
        };

        auto matchcount = 0;
        for (auto i = 0; i < siglen; ) {
                char upper = signature[i++];
                char lower = signature[i++];
                char test = signature[i++];

                assert(matchcount < siglen);
                sig[matchcount++] = unhex(upper, lower);

                if ((test != ' ') && (test != '\0')) {
                        Log("signature-bad format: %s", &signature[i - 3]);
                        free(sig);
                        return NULL;
                }
        }

        sig[matchcount] = sig_end;

        return sig;
}


extern void aob_free(AOB_SIG sig) {
        free(sig);
}


extern unsigned aob_scan(const void* buffer, unsigned buffer_size, unsigned starting_offset, AOB_SIG sig) {
        assert(starting_offset < buffer_size);

        const unsigned char* haystack = (const unsigned char*)buffer + starting_offset;
        const unsigned count = buffer_size - starting_offset;
        

        for (unsigned i = 0; i < count; ++i) {
                auto match = 0;

                while ((haystack[i] & (sig[match] >> 8)) == (sig[match] & 0xFF)) {
                        ++i;
                        ++match;
                        if (sig[match] == sig_end) {
                                return starting_offset + (i - match);
                        }
                }
        }

        return AOB_NO_MATCH;
}