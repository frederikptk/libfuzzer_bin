#include <stdint.h>
#include <fuzz_lib.h>

int (*test)(int a, int b, int c);

extern void reset_fuzzer();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	reset_fuzzer();
	
	test = (int(*)(int, int, int)) (loaded_text_base + 0x100);

	test(1, 2, 3);
	return 0;
}
