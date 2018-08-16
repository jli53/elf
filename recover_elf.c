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

#define TEXT_SEG 1
#define DATA_SEG 2

long get_pid_seg_size(int seg, int pid) {
	char maps[255];
	char *line = NULL;
	FILE *fd = NULL;
	char *addr[2];
	char *delim = "- ";
	long len, read_len = 0;
	snprintf(maps, 255, "/proc/%d/maps", pid);
	if((fd = fopen(maps, "r")) == NULL) {
		perror("open maps");
		exit(-1);
	}

	if(getline(&line, &read_len, fd) < 0) {
		perror("read maps");
		exit(-1);
	}

	if(seg == DATA_SEG) {
		if(getline(&line, &read_len, fd) < 0) {
			perror("read maps");
			exit(-1);
		}
		if(getline(&line, &read_len, fd) < 0) {
			perror("read maps");
			exit(-1);
		}
	}
		
	addr[0] = strtok(line, delim);
	addr[1] = strtok(NULL, delim);

	len = strtol(addr[1], NULL, 16) - strtol(addr[0], NULL, 16);
	printf("%s seg size is %lx\n", seg == DATA_SEG ? "data" : "text", len);

	fclose(fd);
	return len;
}

Elf64_Addr get_pid_seg_start(int seg, int pid) {
	char maps[255];
	char *line = NULL;
	FILE *fd = NULL;
	char *addr;
	char *delim = "-";
	int read_len = 0;
	snprintf(maps, 255, "/proc/%d/maps", pid);
	if((fd = fopen(maps, "r")) == NULL) {
		perror("open maps");
		exit(-1);
	}
	
	if(getline(&line, &read_len, fd) < 0) {
		perror("read maps");
		exit(-1);
	}

	if(seg == DATA_SEG) {
		if(getline(&line, &read_len, fd) < 0) {
			perror("read maps");
			exit(-1);
		}
		if(getline(&line, &read_len, fd) < 0) {
			perror("read maps");
			exit(-1);
		}
	}

	addr = strtok(line, delim);
	printf("%s seg starts from 0x%s\n", seg == DATA_SEG ? "data" : "text", addr);

	fclose(fd);
	return strtol(addr, NULL, 16);
}

int pid_read(int pid, void *dst, const void *src, size_t len)
{
	int sz = len / sizeof(void *);
	unsigned char *s = (unsigned char *)src;
	unsigned char *d = (unsigned char *)dst;
	unsigned long word;
	while (sz != 0) {
		printf("xxx sz is %d\n", sz);
		word = ptrace(PTRACE_PEEKTEXT, pid, (long *)s, NULL);
		if(word == -1) {
			return -1;
		}
		*(long *)d = word;
		s += sizeof(long);
		d += sizeof(long);
		sz -= 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int c;
	int pid, len = 0;
	Elf64_Addr start;
	char *filename = NULL;
	FILE *fd_new_file = NULL;
	uint8_t *mem_text, *mem_data;

	if(argc != 3){
		printf("Usage: %s -p <pid>\n", argv[0]);
		exit(0);
	}

	c = getopt(argc, argv, "p");
	switch(c) {
		case 'p':
			pid = atoi(argv[2]);
			filename = strdup(argv[2]);
			fd_new_file = fopen(filename, "w+");
			if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
				perror("PTRACE_ATTACH");
				exit(-1);
			}
			break;
		default:
			printf("Usage: %s -p <pid>\n", argv[0]);
			exit(0);
	}

	//dump text seg memory
	len = get_pid_seg_size(TEXT_SEG, pid);
	start = get_pid_seg_start(TEXT_SEG, pid);
	mem_text = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(mem_text == MAP_FAILED) {
		perror("mmap text");
		exit(-1);
	}
	if(pid_read(pid, mem_text, start, len) != 0) {
		perror("PTRACE_PEEKTEXT");
		exit(-1);
	}

	Elf64_Ehdr *ehdr = (Elf64_Ehdr*)mem_text;
	Elf64_Phdr *phdr = (Elf64_Phdr*)&mem_text[ehdr->e_phoff];

	Elf64_Addr dataVaddr = 0;
	long dataSize = 0;
    long dataOffset = 0;
	Elf64_Addr textVaddr = 0;
	long textSize = 0;
	for(c = 0; c < ehdr->e_phnum; c++) {
		if(phdr[c].p_type == PT_LOAD) {
			if(phdr[c].p_offset) {
				dataVaddr = phdr[c].p_vaddr;
				dataSize = phdr[c].p_memsz;
                dataOffset = phdr[c].p_offset;
				printf("data seg start from %lx, size is %lx\n", dataVaddr, dataSize);
			} else {
				textVaddr = phdr[c].p_vaddr;
				textSize = phdr[c].p_memsz;
				printf("text seg start from %lx, size is %lx\n", textVaddr, textSize);
			}
			if(dataSize && textSize)
				break;
		}
	}

	fwrite(mem_text, 1, textSize, fd_new_file);
	if(munmap(mem_text, len) != 0) {
		perror("munmap");
		exit(-1);
	}
	
    char *zero = (char*)calloc(dataOffset - textSize, 1);
    fwrite(zero, 1, dataOffset - textSize, fd_new_file);
    free(zero);


	//dump data seg memory
	mem_data = mmap(NULL, dataSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(mem_data == MAP_FAILED) {
		perror("mmap data");
		exit(-1);
	}
	if(pid_read(pid, mem_data, dataVaddr, dataSize) != 0) {
		perror("PTRACE_PEEKTEXT");
		exit(-1);
	}
    printf("xxx got value is %lx\n", (long*)(mem_data+488));
    *(long*)(mem_data+488) = 0;
	fwrite(mem_data, 1, dataSize, fd_new_file);
	if(munmap(mem_data, dataSize) != 0) {
		perror("munmap");
		exit(-1);
	}

	ptrace(PTRACE_CONT, pid, NULL, NULL);
	fclose(fd_new_file);
}
