#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <fcntl.h>

long get_pid_text_seg_size(int pid) {
	char maps[255], line[512];
	int fd;
	char *addr[2];
	char *delim = "- ";
	long len = 0;
	snprintf(maps, 255, "/proc/%d/maps", pid);
	if((fd = open(maps, O_RDONLY)) < 0) {
		perror("open maps");
		exit(-1);
	}

	if(read(fd, line, 512) < 0) {
		perror("read maps");
		exit(-1);
	}

	addr[0] = strtok(line, delim);
	addr[1] = strtok(NULL, delim);

	len = strtol(addr[1], NULL, 16) - strtol(addr[0], NULL, 16);
	printf("text seg size is %lx\n", len);

	return len;
}

Elf64_Addr get_pid_text_seg_start(int pid) {
	char maps[255], line[512];
	int fd;
	char *addr;
	char *delim = "-";
	snprintf(maps, 255, "/proc/%d/maps", pid);
	if((fd = open(maps, O_RDONLY)) < 0) {
		perror("open maps");
		exit(-1);
	}
	
	if(read(fd, line, 512) < 0) {
		perror("read maps");
		exit(-1);
	}

	addr = strtok(line, delim);
	printf("text seg starts from 0x%s\n", addr);

	return strtol(addr, NULL, 16);
}

int pid_read(int pid, void *dst, const void *src, size_t len)
{
	int sz = len / sizeof(void *);
	unsigned char *s = (unsigned char *)src;
	unsigned char *d = (unsigned char *)dst;
	unsigned long word;
	while (sz != 0) {
		word = ptrace(PTRACE_PEEKTEXT, pid, (long *)s, NULL);
		if(word == -1) {
			return -1;
		}
		*(long *)d = word;
		s += sizeof(long);
		d += sizeof(long);
		sz -= sizeof(void*);
	}
	return 0;
}

int main(int argc, char **argv)
{
	int c;
	int pid, len;
	Elf64_Addr start;
	int fd, i;
	uint8_t *mem;
	struct stat st;
	char *StringTable, *interp;

	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;

	if(argc != 3) {
		printf("Usage: %s -f <file> or %s -p <pid>\n", argv[0], argv[0]);
		exit(0);
	}

	c = getopt(argc, argv, "p:f");
	switch(c) {
		case 'p':
			pid = atoi(argv[2]);
			if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
				perror("PTRACE_ATTACH");
				exit(-1);
			}
			len = get_pid_text_seg_size(pid);
			start = get_pid_text_seg_start(pid);
			mem = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if(mem == MAP_FAILED) {
				perror("mmap");
				exit(-1);
			}
			if(pid_read(pid, mem, start, len) != 0) {
				perror("PTRACE_PEEKTEXT");
				exit(-1);
			}
			ptrace(PTRACE_CONT, pid, NULL, NULL);
			break;
		case 'f':
			if((fd = open(argv[2], O_RDONLY)) < 0) {
				perror("open");
				exit(-1);
			}
			
			if(fstat(fd, &st) < 0) {
				perror("fstat");
				exit(-1);
			}
			len = st.st_size;
			mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
			if(mem == MAP_FAILED) {
				perror("mmap");
				exit(-1);
			}
			break;	
		default:
			printf("Usage: %s -f <file> or %s -p <pid>\n", argv[0], argv[0]);
			exit(0);
	}

	ehdr = (Elf64_Ehdr *)mem;

	phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff];
	shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];

	if(mem[0] != 0x7f && strncmp(&mem[1], "ELF", 3)) {
		fprintf(stderr, "%s is not an ELF file\n", argv[2]);
		exit(-1);
	}

	if(ehdr->e_type != ET_EXEC) {
		fprintf(stderr, "%s is not an executable\n", argv[2]);
		exit(-1);
	}

	printf("Program Entry Point: 0x%lx\n", ehdr->e_entry);

	if(pid == 0) {
		StringTable = &mem[shdr[ehdr->e_shstrndx].sh_offset];

		printf("\nSection header address:%lx\n", (long unsigned int)(ehdr->e_shoff));
		printf("Program header list: total %d section headers\n\n", ehdr->e_shnum);
		printf("Section header list:\n\n");
		for(i = 1; i < ehdr->e_shnum; i++)
			printf("%s: 0x%lx\n", &StringTable[shdr[i].sh_name], shdr[i].sh_addr);
	}

	printf("\n\n\nProgram header address:%lx\n", (long unsigned int)(ehdr->e_phoff));
	printf("Program header list: total %d program headers\n\n", ehdr->e_phnum);
	for(i = 0; i < ehdr->e_phnum; i++) {
		switch(phdr[i].p_type) {
			case PT_LOAD:
				if(phdr[i].p_offset == 0)
					printf("Text Segment: 0x%lx\n", phdr[i].p_vaddr);
				else
					printf("Data Segment: 0x%lx\n", phdr[i].p_vaddr);
				break;
			case PT_INTERP:
				interp = strdup((char*)&mem[phdr[i].p_offset]);
				printf("Interpreter: %s\n", interp);
				break;
			case PT_NOTE:
				printf("Note segment: 0x%lx\n", phdr[i].p_vaddr);
				break;
			case PT_DYNAMIC:
				printf("Dynamic segment: 0x%lx\n", phdr[i].p_vaddr);
				break;
			case PT_PHDR:
				printf("Phdr segment: 0x%lx\n", phdr[i].p_vaddr);
				break;
			default:
				printf("I don't know what segment it is, address: 0x%lx\n", phdr[i].p_vaddr);
		}
	}

	if(munmap(mem, len) != 0) {
		perror("munmap");
		exit(-1);
	}

	exit(0);
}
