#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

int check_elf_magic(Elf64_Ehdr* hdr){
	return ((hdr->e_ident[EI_MAG0] == ELFMAG0) && (hdr->e_ident[EI_MAG1] == ELFMAG1) &&
			(hdr->e_ident[EI_MAG2] == ELFMAG2) && (hdr->e_ident[EI_MAG3] == ELFMAG3));
}

int main(int argc, char* argv[]) {
	FILE* fp;
	Elf64_Ehdr e_hdr;
	Elf64_Dyn dyn;
	Elf64_Shdr s_hdr;

	if (argc != 2) {
		return EXIT_FAILURE;
	}

	fp = fopen(argv[1], "r+b");
	if (fp == NULL) {
		printf("Cannot open file\n");
		return EXIT_FAILURE;
	}

	if (fread(&e_hdr, sizeof(Elf64_Ehdr), 1, fp) != 1) {
		printf("Could not read ELF header\n");
		return EXIT_FAILURE;
	}
	
	// Patch the executable type
	e_hdr.e_type = ET_DYN;
	if (fseek(fp, 0, SEEK_SET) == -1) {
		printf("Seek failed\n");
	}
			
	if (fwrite(&e_hdr, sizeof(Elf64_Ehdr), 1, fp) != 1) {
		printf("Writing ELF header failed\n");
		return EXIT_FAILURE;
	}
    
	if (!check_elf_magic(&e_hdr)) {
		printf("ELF magic not found!\n");
		return EXIT_FAILURE;
	}
	
	// Search for the dynamic section
	if (fseek(fp, e_hdr.e_shoff, SEEK_SET) == -1) {
		printf("Seek failed\n");
	}
	for (unsigned int i = 0; i < e_hdr.e_shnum; ++i) {
		if (fread(&s_hdr, e_hdr.e_shentsize, 1, fp) != 1) {
			printf("Could not read section header\n");
			return EXIT_FAILURE;
		}
		
		printf("Section header type: 0x%lx\n", s_hdr.sh_type);
		
		if (s_hdr.sh_type == SHT_DYNAMIC) {
			printf("Found Dynamic section\n");
			if (fseek(fp, s_hdr.sh_offset, SEEK_SET) == -1) {
				printf("Invalid ELF file offset\n");
			}
			
			for (unsigned int j = 0; j < (unsigned int)(s_hdr.sh_size / sizeof(Elf64_Dyn)); j++) {
				if (fread(&dyn, sizeof(Elf64_Dyn), 1, fp) != 1) {
					printf("Could not read dynamic section\n");
					return EXIT_FAILURE;
				}
				
				if (dyn.d_tag == 0x6ffffffb) {
					printf("Found a section to patch!\n");
					// Clear the PIE flag in order to bypass dlopen message:
					// "cannot dynamically load position-independent executable"
					dyn.d_un.d_val &= ~DF_1_PIE;
					
					if (fseek(fp, -sizeof(Elf64_Dyn), SEEK_CUR) != 0) {
						printf("fseek failed\n");
						return EXIT_FAILURE;
					}
					
					if (fwrite(&dyn, sizeof(Elf64_Dyn), 1, fp) != 1) {
						printf("Writing to ELF file failed\n");
						return EXIT_FAILURE;
					}
					
					fclose(fp);
					return EXIT_SUCCESS;
				}
			}
			
			// If we are here, we could not find the FLAGS_1 dynamic section entry. Try to overwrite
			// another entry which is not important.
			printf("Did not find FLAGS_1 ... Replacing another dynamic section entry\n");
			// TODO
			
		}
	}

	printf("Could not find any entry to patch\n");

	fclose(fp);
	return EXIT_SUCCESS;
}
