#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdint.h>

#include <stdexcept>

#include <fuzz_lib.h>

#define PTRACE_CHECK(x) if (x < 0) { printf("ptrace failed!\n"); return -1; }

int (*test)(int a, int b, int c);

extern void reset_fuzzer();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	int status;
	struct user_regs_struct regs;
	int found = 0;
	unsigned int index;
	uint8_t byte;
	uint64_t data;

	// Create all breakpoints necessary
	reset_fuzzer();
	
	child_pid = fork();
	
	if (child_pid == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) _exit(1);
		
		asm("int3"); // first wait stops here
		
		test = (int(*)(int, int, int)) (loaded_text_base + 0x100);
		
		test(3, 4, 3);
		
		_exit(1);
	} else {
		waitpid(child_pid, &status, 0);
		
		// Execute until the first breakpoint
		PTRACE_CHECK(ptrace(PTRACE_CONT, child_pid, 0, 0))
		waitpid(child_pid, &status, 0);
		
		while (1) {
			// Check the exit status
			if (WIFEXITED(status)) break;
			
    			if (WIFSTOPPED(status)) {
				// Now handle all breakpoints in the child
				PTRACE_CHECK(ptrace(PTRACE_GETREGS, child_pid, 0, &regs))
				regs.rip--;
				uint64_t instr = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip, 0);
				
				PTRACE_CHECK(ptrace(PTRACE_SETREGS, child_pid, 0, &regs))
				
				try {
					index = bb_map_index.at(regs.rip);
					byte = bb_map_patched_byte.at(regs.rip);
					
					data = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip, 0);
					ptrace(PTRACE_POKETEXT, child_pid, regs.rip, (data & 0xFFFFFFFFFFFFFF00) | byte);
					// fuzzer counter
					((uint8_t*)&__start__sancov_cntrs)[index]++;
				} catch (const std::out_of_range& e){
					// Fail in case of an int3 which was not set by our debugger
					//return -1;
				}
				
				PTRACE_CHECK(ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0))
				waitpid(child_pid, &status, 0);
				
				PTRACE_CHECK(ptrace(PTRACE_GETREGS, child_pid, 0, &regs))

				try {
					index = bb_map_index.at(regs.rip);
					byte = bb_map_patched_byte.at(regs.rip);
					
					data = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip, 0);
					ptrace(PTRACE_POKETEXT, child_pid, regs.rip, (data & 0xFFFFFFFFFFFFFF00) | 0xCC);
				} catch (const std::out_of_range& e){
					// Fail in case of an int3 which was not set by our debugger
					//return -1;
				}
				
				if (WIFEXITED(status)) break;
				
				// Resume from the current breakpoint
				PTRACE_CHECK(ptrace(PTRACE_CONT, child_pid, 0, 0))
				waitpid(child_pid, &status, 0);
			}
		}
	}

	return 0;
}
