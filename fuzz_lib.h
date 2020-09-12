#pragma once

#define _GNU_SOURCE
#define __USE_GNU	// used in link.h instead of _GNU_SOURCE

#include <link.h>
#include <dlfcn.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include<signal.h>
#include <sys/mman.h>

#include <bb.h>

// Will be filled with the offsets during compile-time and will later
// hold the addresses of the functions (base + offset)
extern unsigned long bb_addr[BB_COUNT];

extern unsigned char bb_patched_byte[BB_COUNT];

extern void* __start__sancov_pcs;
extern void* __stop__sancov_pcs;
extern void* __start__sancov_bools;
extern void* __stop__sancov_bools;

void* elf_handle = NULL;
uint64_t loaded_text_base = 0;
uint64_t loaded_text_segment_base = 0; // base of the segment containing the .text section
uint64_t file_text_base = 0;
uint64_t loaded_elf_base = 0;
uint64_t text_segment_base_file = -1;

pid_t child_pid;

int check_elf_magic(Elf64_Ehdr* hdr){
	return ((hdr->e_ident[EI_MAG0] == ELFMAG0) && (hdr->e_ident[EI_MAG1] == ELFMAG1) &&
			(hdr->e_ident[EI_MAG2] == ELFMAG2) && (hdr->e_ident[EI_MAG3] == ELFMAG3));
}

Elf64_Shdr* get_elf_section_header(Elf64_Ehdr* hdr){
	return (Elf64_Shdr*)((long)hdr + hdr->e_shoff);
}

Elf64_Shdr* get_elf_section(Elf64_Ehdr* hdr, int index){
	return &(get_elf_section_header(hdr)[index]);
}

Elf64_Phdr* get_elf_program_header(Elf64_Ehdr* hdr, int index){
	return &(((Elf64_Phdr*)((long)hdr + hdr->e_phoff))[index]);
}

char* get_elf_string(Elf64_Ehdr* hdr, int section_idx, int string_idx){
	char* string_table_base = (char*)((long)hdr + get_elf_section(hdr, section_idx)->sh_offset);
	return string_table_base + string_idx;
}

int dl_iterate_phdr_callback(struct dl_phdr_info* info, size_t size, void* data) {
	int found_segment = 0;

	if (strcmp(BINARY_PATH, info->dlpi_name) == 0) {
		for (unsigned int i = 0; i < info->dlpi_phnum; i++) {
			// Search for the text_phdr segment in the loaded ELF file
			if ((uint64_t)(info->dlpi_phdr[i].p_vaddr) == text_segment_base_file) {
				found_segment = 1;
				printf("found\n");
				loaded_elf_base = info->dlpi_addr;
				loaded_text_base = (uint64_t)(info->dlpi_phdr[i].p_vaddr + loaded_elf_base + (file_text_base - info->dlpi_phdr[i].p_offset));
				loaded_text_segment_base = (uint64_t)(info->dlpi_phdr[i].p_vaddr + loaded_elf_base);
				return 0;
			}
		}
		if (found_segment != 1) {
			printf("Could not find .text segment in ELF in memory!\n");
			exit(EXIT_FAILURE);
		}
	}

	return 0;
}

void signal_handler_sigtrap(int signo, siginfo_t *si, void* arg) {
	ucontext_t* context = (ucontext_t*)arg;
	uint64_t rip;

	if (signo == SIGTRAP) {	// sanity check
		context->uc_mcontext.gregs[REG_RIP] -= 1;
		rip = context->uc_mcontext.gregs[REG_RIP];
		//printf("RIP: 0x%lx\n", rip);
		
		for (unsigned int i = 0; i < BB_COUNT; i++) {
			if (bb_addr[i] == rip) {
				// patch the old byte
				*((uint8_t*)(bb_addr[i])) = bb_patched_byte[i];
				
				// fuzzer counter
				((uint8_t*)&__start__sancov_bools)[i] = 1;
				
				return;
			}
		}
		
		// if we are here, we could not find a BB for the trap
		for (unsigned int i = 0; i < BB_COUNT; i++) {
			printf(" BB: 0x%lx\n", bb_addr[i]);
		}
	}
}

void signal_handler_sigint(int signo, siginfo_t *si, void* arg) {
	kill(child_pid, SIGKILL);
}

void init_fuzzer() {
	printf("Initializing fuzzer\n");
	
	for (unsigned int i = 0; i < BB_COUNT; i++) {
		printf(" BB: 0x%lx\n", bb_addr[i]);
		
		((uint8_t*)&__start__sancov_bools)[i] = 0; // reset the bool array
		
		uint8_t* patched_byte = (uint8_t*)(bb_addr[i]);
		bb_patched_byte[i] = *patched_byte; // just read in this byte one time during initialization
		*patched_byte = 0xcc; // int3
	}
}

void reset_fuzzer() {
	//printf("[RESETTING FUZZER]\n");
	
	for (unsigned int i = 0; i < BB_COUNT; i++) {
		//printf(" BB: 0x%lx\n", bb_addr[i]);
		
		//((uint8_t*)&__start__sancov_bools)[i] = 0; // reset the bool array
			
		uint8_t* patched_byte = (uint8_t*)(bb_addr[i]);
		*patched_byte = 0xcc; // int3
	}
}

__attribute__((constructor)) void init_elf() {
	FILE* fp;
	struct stat st;
	Elf64_Ehdr* ehdr;
	Elf64_Shdr* text_shdr = NULL;
	Elf64_Phdr* text_phdr = NULL;
	struct link_map lm;
	int fd;
	uint64_t text_section_offset;
	struct sigaction action;
	
	printf("FUZZER: LOADING ELF FILE\n");
	
	// Load the ELF file and get the base address
	if ((elf_handle = dlopen(BINARY_PATH, RTLD_LAZY)) == NULL) {
		printf("Error while opening file: %s\n", BINARY_PATH);
		printf("dlopen() failed: %s\n", dlerror());
		exit(EXIT_FAILURE);
	}
	if (dlinfo(elf_handle, RTLD_DI_LINKMAP, &lm) == -1) {
		printf("dlinfo() failed: %s\n", dlerror());
		exit(EXIT_FAILURE);
	}
	
	// Read in the ELF file and load it into memory
	fp = fopen(BINARY_PATH, "r");
	if (fp == NULL){
		printf("\nError. ELF file not found: %s\n", BINARY_PATH);
		exit(EXIT_FAILURE);
	} else {
		printf("Ok.\n");
	}
	
	//printf("Reading ELF file... ");	
	fstat(fileno(fp), &st);
	ehdr = (Elf64_Ehdr*) malloc(st.st_size);
	fseek(fp, 0L, SEEK_SET);
	fread(ehdr, sizeof(char), st.st_size, fp);
	//printf("Copied ELF into memory. Size: 0x%lx\n", st.st_size);
	
	
	if (!check_elf_magic(ehdr)){
		printf(" ELF Magic number is invalid.\n");
		exit(EXIT_FAILURE);
	} else{
		printf("Ok.\n");
	}
	
	// Read in the offset of .text section
	for (int j = 0; j < ehdr->e_shnum; j++){
		Elf64_Shdr* shdr = get_elf_section(ehdr, j);
		char* section_name = get_elf_string(ehdr,  ehdr->e_shstrndx, shdr->sh_name);
		if (strcmp(".text", section_name) == 0) {
			text_shdr = shdr;
			file_text_base = text_shdr->sh_offset;
			break;
		}
	}
	
	if (text_shdr == NULL) {
		printf("Could not find .text section!\n");
		exit(EXIT_FAILURE);
	}
	
	// Find the segment in which the .text section will be loaded in
	for (int i = 0; i < ehdr->e_phnum; i++){
		Elf64_Phdr* phdr = get_elf_program_header(ehdr, i);
		if (phdr->p_type == PT_LOAD && phdr->p_flags == (PF_R | PF_X)){
			if (text_shdr->sh_offset >= phdr->p_offset && 
				text_shdr->sh_offset + text_shdr->sh_size <= phdr->p_offset + phdr->p_filesz) {
				text_phdr = phdr;
				text_segment_base_file = phdr->p_vaddr;
				break;
			}
		}
	}
	if (text_phdr == NULL || text_segment_base_file == -1) {
		printf("Could not find .text segment in ELF file!\n");
		exit(EXIT_FAILURE);
	}
	
	// Get the base of the ELF file
	dl_iterate_phdr(dl_iterate_phdr_callback, NULL);
	
	// Init the bb_addr
	if (loaded_text_base != 0) {
		printf("Loaded base of .text: 0x%lx\n", loaded_text_base);
		for (unsigned int i = 0; i < BB_COUNT; i++) {
			bb_addr[i] += loaded_text_base;
			((uint64_t*)&__start__sancov_pcs)[i] = bb_addr[i];
		}
	} else {
		printf(".text at address 0 in memory!\n");
		exit(EXIT_FAILURE);
	}
	
	
	// Copy the first bytes of the functions into the trampolines
	if (mprotect((void*)loaded_text_segment_base, text_phdr->p_memsz, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
		printf("mprotect failed: Could not make binary code R/W\n");
		exit(EXIT_FAILURE);
		return;
	}
	
	init_fuzzer();
	
	/*if (mprotect((void*)loaded_text_segment_base, text_phdr->p_memsz, PROT_READ | PROT_EXEC) == -1) {
		printf("mprotect failed: Could not make binary code R/E\n");
		exit(EXIT_FAILURE);
		return;
	}*/
	
	// register the signal handler
	/*action.sa_sigaction = &signal_handler_sigtrap;
	action.sa_flags = SA_SIGINFO;
	if (sigaction(SIGTRAP, &action, NULL) == -1) {
        	printf("Can't register signal handler for: SIGTRAP\n");
        }*/
        
        action.sa_sigaction = &signal_handler_sigint;
	action.sa_flags = SA_SIGINFO;
	if (sigaction(SIGINT, &action, NULL) == -1) {
        	exit(EXIT_FAILURE);
        }
	
	fclose(fp);
	free(ehdr);
	
	printf("FUZZER: DONE\n");
}

extern "C" void __sanitizer_cov_8bit_counters_init(void*, void*); // __sanitizer_cov_bool_flag_init
extern "C" void __sanitizer_cov_pcs_init(void*, void*);

__attribute__((constructor)) void sancov_init_bool_flags() {
	__sanitizer_cov_8bit_counters_init(&__start__sancov_bools, &__stop__sancov_bools);
	__sanitizer_cov_pcs_init(&__start__sancov_pcs, &__stop__sancov_pcs);
}

__attribute__((destructor)) void finit_elf() {
	if (elf_handle) {
		dlclose(elf_handle);
	} else {
		printf("dlclose() failed: %s\n", dlerror());
	}
}
