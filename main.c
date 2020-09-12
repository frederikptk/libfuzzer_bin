#include <sys/ptrace.h>

#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdint.h>

#include <fuzz_lib.h>

#define PTRACE_CHECK(x) if (x < 0) { printf("ptrace failed!\n"); return -1; }

int (*test)(int a, int b, int c);

extern void reset_fuzzer();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	int status;
	struct user_regs_struct regs;
	int found = 0;

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
		//PTRACE_CHECK(ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACEEXIT))
		
		// Execute until the first breakpoint
		PTRACE_CHECK(ptrace(PTRACE_CONT, child_pid, 0, 0))
		waitpid(child_pid, &status, 0);
		
		while (1) {
			//printf("status: 0x%lx\n", status);
			//printf("WIFEXITED(status): 0x%lx\n", WIFEXITED(status));
			//printf("WTERMSIG(status): 0x%lx\n", WTERMSIG(status));
			//printf("WEXITSTATUS(status): 0x%lx\n", WEXITSTATUS(status));
			
			
			// Check the exit status
			if (WIFEXITED(status)) break;
			
    			if (WIFSTOPPED(status)) {
				// Now handle all breakpoints in the child
				PTRACE_CHECK(ptrace(PTRACE_GETREGS, child_pid, 0, &regs))
				regs.rip--;
				//printf("BP @ 0x%lx\n", regs.rip);
				uint64_t instr = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip, 0);
				//printf("instr: 0x%lx\n", instr);
				
				PTRACE_CHECK(ptrace(PTRACE_SETREGS, child_pid, 0, &regs))
				
				for (unsigned int i = 0; i < BB_COUNT; i++) {
					if (bb_addr[i] == regs.rip) {
						uint64_t data = ptrace(PTRACE_PEEKTEXT, child_pid, bb_addr[i], 0);
						ptrace(PTRACE_POKETEXT, child_pid, bb_addr[i], (data & 0xFFFFFFFFFFFFFF00) | bb_patched_byte[i]);
						
						// fuzzer counter
						((uint8_t*)&__start__sancov_bools)[i]++;
						found = 1;
						break;
					}
				}
				
				if (found == 0) {
				}
				
				PTRACE_CHECK(ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0))
				waitpid(child_pid, &status, 0);
				
				PTRACE_CHECK(ptrace(PTRACE_GETREGS, child_pid, 0, &regs))
				//printf("ss @ 0x%lx\n", regs.rip);
				instr = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rsp, 0);
				//printf("[rsp]: 0x%lx\n", instr);
				//instr = ptrace(PTRACE_PEEKTEXT, child_pid, instr, 0);
				//printf("[rsp]: 0x%lx\n", instr);
				
				found = 0;
				for (unsigned int i = 0; i < BB_COUNT; i++) {
					if (bb_addr[i] == regs.rip) {						
						uint64_t data = ptrace(PTRACE_PEEKTEXT, child_pid, bb_addr[i], 0);
						ptrace(PTRACE_POKETEXT, child_pid, bb_addr[i], (data & 0xFFFFFFFFFFFFFF00) | 0xCC);
						found = 1;
						break;
					}
				}
				
				if (found == 0) {
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
