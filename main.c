
#include <stdio.h>
#include <stdint.h>
#include "string.h"
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#define FUSE_USE_VERSION            29
#include <fuse.h>


#define MAXIMUM_OF_FILENAME         8
#define MAXIMUM_OF_FILEEXT          3
#define SIZE_OF_BLOCK               512
#define NUMBER_OF_BLOCKS            256
#define MAXIMUM_OF_IMAGE_FILE       (NUMBER_OF_BLOCKS * SIZE_OF_BLOCK)

#define BACKUP_SUPER_BLOCK          0
#define MAIN_SUPER_BLOCK            255

#define SIZE_OF_FILE_ENTRY          32
#define NUMBER_OF_FILE_ENTRIES      (SIZE_OF_BLOCK / SIZE_OF_FILE_ENTRY)

char*           memeFile = NULL;
uint8_t*        handle_of_map;

static uint8_t  block_buffer[SIZE_OF_BLOCK];

uint8_t*        file_allocation_table = NULL;
uint16_t        size_of_file_allocation_table = SIZE_OF_BLOCK;

//static int hello_stat(fuse_ino_t ino, struct stat* stbuf)
//{
////    stbuf->st_ino = ino;
////    switch (ino) {
////        case 1:
////            stbuf->st_mode = S_IFDIR | 0755;
////            stbuf->st_nlink = 2;
////            break;
////
////        case 2:
////            stbuf->st_mode = S_IFREG | 0444;
////            stbuf->st_nlink = 1;
////            stbuf->st_size = strlen(hello_str);
////            break;
////
////        default:
////            return -1;
////    }
//    return 0;
//}
//

//static void hello_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char* name)
//{
////    struct fuse_entry_param e;
////
////    if (parent != 1 || strcmp(name, hello_name) != 0)
////        fuse_reply_err(req, ENOENT);
////    else {
////        memset(&e, 0, sizeof(e));
////        e.ino = 2;
////        e.attr_timeout = 1.0;
////        e.entry_timeout = 1.0;
////        hello_stat(e.ino, &e.attr);
////
////        fuse_reply_entry(req, &e);
////    }
//}
//
//static void hello_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
//                             off_t off, struct fuse_file_info* fi)
//{
////    (void) fi;
////
////    if (ino != 1)
////        fuse_reply_err(req, ENOTDIR);
////    else {
////        struct dirbuf b;
////
////        memset(&b, 0, sizeof(b));
////        dirbuf_add(req, &b, ".", 1);
////        dirbuf_add(req, &b, "..", 1);
////        dirbuf_add(req, &b, hello_name, 2);
////        reply_buf_limited(req, b.p, b.size, off, size);
////        free(b.p);
////    }
//}
//
//static void hello_ll_open(fuse_req_t req, fuse_ino_t ino,
//                          struct fuse_file_info* fi)
//{
////    if (ino != 2)
////        fuse_reply_err(req, EISDIR);
////    else if ((fi->flags & 3) != O_RDONLY)
////        fuse_reply_err(req, EACCES);
////    else
////        fuse_reply_open(req, fi);
//}
//
//static void hello_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size,
//                          off_t off, struct fuse_file_info* fi)
//{
////    (void) fi;
////
////    assert(ino == 2);
////    reply_buf_limited(req, hello_str, strlen(hello_str), off, size);
//}

struct node {
    struct stat     bufStat;
    void*           data;
    unsigned int    fd_count;
};

typedef struct memefs_timestamp {
	unsigned char   century;
	unsigned char   year_in_century;
	unsigned char   month;
	unsigned char   day;
	unsigned char   hour;
	unsigned char   minute;
	unsigned char   second;
	unsigned char   reserved;
} __attribute__((packed)) memefs_timestamp_t;

typedef struct memefs_superblock {
    char            signature[16];
    uint8_t         cleanly_unmounted;
    uint8_t         reseerved[3];
    uint32_t        fs_version;
    memefs_timestamp_t  fs_ctime;
    uint16_t        main_fat;
    uint16_t        main_fat_size;
    uint16_t        backup_fat;
    uint16_t        backup_fat_size;
    uint16_t        directory_start;
    uint16_t        directory_size;
    uint16_t        num_user_blocks;
    uint16_t        first_user_block;
    char            volume_label[16];
    uint8_t         unused[448];
} __attribute__((packed)) memefs_superblock_t;

typedef struct memefs_file_entry {
    uint16_t        file_type;
    uint16_t        location_first_block;
	char            filename_label[11];
    uint8_t         unused;
    memefs_timestamp_t  write_ctime;
    uint32_t        file_size;
    uint16_t        user_id;
    uint16_t        owner_group_id;
}__attribute__((packed)) memefs_file_entry_t;

typedef struct memefs_dirctory
{
    memefs_file_entry_t     file_entries[NUMBER_OF_FILE_ENTRIES];
}__attribute__((packed)) memefs_dirctory_t;

static void getSB(uint8_t* ptr, memefs_superblock_t* sb)
{
    memefs_superblock_t* sbptr = (memefs_superblock_t*)ptr;
	
    // Get Backup block
    memcpy(sb->signature, ptr, 16);
    sb->cleanly_unmounted =  ptr[16];
    memcpy(sb->reseerved, ptr + 17, 3);
    uint32_t version  = 0;
    memcpy(&version, ptr + 20 , 4);
    sb->fs_version  = ntohl(version);
    memcpy((void*)(&sb->fs_ctime), ptr + 24 , 8);
    uint16_t main_fat  = 0;
    memcpy(&main_fat, ptr + 32, 2);
    sb->main_fat =  ntohs(main_fat);
    uint16_t main_fat_size  = 0;
    memcpy(&main_fat_size, ptr + 34, 2);
    sb->main_fat_size = ntohs(main_fat_size);
    uint16_t backup_fat  = 0;
    memcpy(&backup_fat, ptr + 36, 2);
    sb->backup_fat  = ntohs(backup_fat);
    uint16_t backup_fat_size  = 0;
    memcpy(&backup_fat_size, ptr + 38, 2);
    sb->backup_fat_size  = ntohs(backup_fat_size);
    uint16_t directory_start  = 0;
    memcpy(&directory_start, ptr + 40, 2);
    sb->directory_start  = ntohs(directory_start);
    uint16_t directory_size  = 0;
    memcpy(&directory_size, ptr + 42, 2);
    sb->directory_size  = ntohs(directory_size);
    uint16_t num_user_blocks  = 0;
    memcpy(&num_user_blocks, ptr + 44, 2);
    sb->num_user_blocks  = ntohs(num_user_blocks);
    uint16_t first_user_block  = 0;
    memcpy(&first_user_block, ptr + 46, 2);
    sb->first_user_block =  ntohs(first_user_block);
    memcpy(sb->volume_label, ptr + 48 , 16);
    memcpy(sb->unused, ptr + 64, 448);
}

static void getDirectory(uint8_t* ptr, memefs_file_entry_t* sb) {
    // Get Backup block
    uint16_t fileType = 0;
    memcpy(&fileType, ptr, 2);
    sb->file_type = ntohs(fileType);
    uint16_t location_first_block = 0;
    memcpy(&location_first_block, ptr +2 , 2);
    sb->location_first_block = ntohs(location_first_block);
    memcpy(sb->filename_label, ptr +4, 11);
    sb->unused = ptr[15];
    memcpy((void*)(&sb->write_ctime), ptr + 16 , 8);
    uint32_t file_size = 0;
    memcpy(&file_size, ptr + 24 , 4);
    sb->file_size = ntohl(file_size);
    uint16_t user_id = 0;
    memcpy(&user_id, ptr +28 , 2);
    sb->user_id = ntohs(user_id);
    uint16_t owner_group_id = 0;
    memcpy(&owner_group_id, ptr + 30 , 2);
    sb->owner_group_id = ntohs(owner_group_id);
}

struct stat* open_map_file()
{
	const int fd  = open(memeFile, O_RDWR);

	if (fd < 0) {
        printf("\n\"%s \" could not open\n ", memeFile);
        exit(1);
    }

    struct stat statbuf;
    const int err  = fstat(fd, &statbuf);
	
    if (err < 0) {
        printf("\n\"%s \" could not open\n ", memeFile);
        exit(2);
    }

    handle_of_map = mmap(NULL,statbuf.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	
    if (handle_of_map == MAP_FAILED) {
        printf("Mapping Failed\n");
        exit(1);
    }

    close(fd);

    return &statbuf;
}

int close_map_file(struct stat statbuf)
{
	const int err = munmap(handle_of_map, statbuf.st_size);
	
    if (err != 0) {
        printf("UnMapping Failed\n");
        return 1;
    }

    return 0;
} 

void read_block(uint8_t index_of_block)
{
	memcpy(block_buffer, handle_of_map + (index_of_block * SIZE_OF_BLOCK), SIZE_OF_BLOCK);
}

void write_block(uint8_t index_of_block)
{
    memcpy(handle_of_map + (index_of_block * SIZE_OF_BLOCK), block_buffer, SIZE_OF_BLOCK);
}

void read_backup_super_block()
{
    read_block(BACKUP_SUPER_BLOCK);
}

void read_main_super_block()
{
    read_block(MAIN_SUPER_BLOCK);
}

void sync_super_block()
{
	read_block(MAIN_SUPER_BLOCK);
    write_block(BACKUP_SUPER_BLOCK);
}

void restore_main_super_block()
{
	read_block(BACKUP_SUPER_BLOCK);
	write_block(MAIN_SUPER_BLOCK);
}

void free_fat()
{
	if (file_allocation_table != NULL) {
		free(file_allocation_table);

		file_allocation_table = NULL;
	}
}

void malloc_fat(uint16_t size_of_fat)
{
    free_fat();

    file_allocation_table = malloc(size_of_fat);
    size_of_file_allocation_table = size_of_fat;
}

void read_backup_fat()
{
    read_main_super_block();

    memefs_superblock_t* sb = (memefs_superblock_t*)block_buffer;

    const uint16_t index_of_fat = ntohs(sb->backup_fat);
    const uint16_t size_of_fat = ntohs(sb->backup_fat_size);
	
    malloc_fat(SIZE_OF_BLOCK * size_of_fat);

	for (int i = 0; i < size_of_fat; i++) {
        read_block(index_of_fat + i);
        memcpy(file_allocation_table + i * SIZE_OF_BLOCK, block_buffer, SIZE_OF_BLOCK);
	}
}

void write_backup_fat()
{
	read_main_super_block();

	memefs_superblock_t* sb = (memefs_superblock_t*)block_buffer;

	const uint16_t index_of_fat = ntohs(sb->backup_fat);
	const uint16_t size_of_fat = ntohs(sb->backup_fat_size);

	for (int i = 0; i < size_of_fat; i++) {
		memcpy(block_buffer, file_allocation_table + i * SIZE_OF_BLOCK, SIZE_OF_BLOCK);
		write_block(index_of_fat + i);
	}
}

void read_main_fat()
{
	read_main_super_block();

	memefs_superblock_t* sb = (memefs_superblock_t*)block_buffer;

	const uint16_t index_of_fat = ntohs(sb->main_fat);
	const uint16_t size_of_fat = ntohs(sb->main_fat_size);

	malloc(SIZE_OF_BLOCK * size_of_fat);

	for (int i = 0; i < size_of_fat; i++) {
		read_block(index_of_fat + i);
		memcpy(file_allocation_table + i * SIZE_OF_BLOCK, block_buffer, SIZE_OF_BLOCK);
	}
}

void write_main_fat()
{
	read_block(MAIN_SUPER_BLOCK);

	memefs_superblock_t* sb = (memefs_superblock_t*)block_buffer;

	const uint16_t index_of_fat = ntohs(sb->main_fat);
	const uint16_t size_of_fat = ntohs(sb->main_fat_size);

	for (int i = 0; i < size_of_fat; i++) {
		memcpy(block_buffer, file_allocation_table + i * SIZE_OF_BLOCK, SIZE_OF_BLOCK);
		write_block(index_of_fat + i);
	}
}

void sync_fat()
{
    read_main_fat();
    write_backup_fat();

    free_fat();
}

void restore_main_fat()
{
	read_backup_fat();
	write_main_fat();

    free_fat();
}

uint16_t get_fat_element(uint16_t index)
{
    if (file_allocation_table != NULL && index < size_of_file_allocation_table / sizeof(uint16_t)) {
        return (uint16_t)ntohs(file_allocation_table[index]);
    }
	
    return 0;
}

void write_fat_element(uint16_t index, uint16_t value)
{
    if (file_allocation_table != NULL && index < size_of_file_allocation_table / sizeof(uint16_t)) {
        uint16_t* fat = (uint16_t*)file_allocation_table;
        file_allocation_table[index] = htons(value);
    }
}

int is_valid_filename(const char* filename)
{
	for (size_t i = 0; i < strlen(filename); i++) {
		const char letter = filename[i];

		if (('A' <= letter && letter <= 'Z') || ('a' <= letter && letter <= 'z') || ('0' <= letter && letter <= '9')) {
            continue;
		}

		if (letter == '^' || letter == '-' || letter == '_' || letter == '|' || letter == '.') {
            continue;
		}

        return 0;
	}

    return 1;
}

int write_filename_in_entry(const char* filename, char* filename_label)
{
    int dot_position = -1;
	
    for (int i = (int)strlen(filename) - 1; i >= 0; i++) {
		if (filename[i] == '.') {
            dot_position = i;
		}
    }

    int filename_length = 0;
    int fileext_length = 0;
	
    if (dot_position != -1) {
        filename_length = (dot_position > MAXIMUM_OF_FILENAME) ? MAXIMUM_OF_FILENAME : dot_position;
        fileext_length = (strlen(filename) - dot_position > MAXIMUM_OF_FILEEXT) ? MAXIMUM_OF_FILEEXT : (int)strlen(filename) - dot_position - 1;
    }
    else {
		filename_length = (strlen(filename) > MAXIMUM_OF_FILENAME) ? MAXIMUM_OF_FILENAME : (int)strlen(filename);
    }

    memset(filename_label, 0, MAXIMUM_OF_FILENAME + MAXIMUM_OF_FILEEXT);
	
	for (int i = 0; i < filename_length; i++) {
        filename_label[i] = filename[i];
	}

	for (int i = 0; i < fileext_length; i++) {
		filename_label[MAXIMUM_OF_FILENAME + i] = filename[dot_position + i + 1];
	}

    return 1;
}

uint8_t get_bcd_code(unsigned char value)
{
    return 16 * (value / 10) + (value % 10);
}

int write_bcd_timestamp(memefs_timestamp_t* timestamp)
{
    time_t t = time(NULL);
    struct tm* tm = gmtime(&t);

    const int year = tm->tm_year + 1990;
    timestamp->century = get_bcd_code(year / 100);
	timestamp->year_in_century = get_bcd_code(year % 100);
    timestamp->month = get_bcd_code(tm->tm_mon + 1);
	timestamp->day = get_bcd_code(tm->tm_mday);
	timestamp->hour = get_bcd_code(tm->tm_hour);
	timestamp->minute = get_bcd_code(tm->tm_min);
	timestamp->second = get_bcd_code(tm->tm_sec);

	timestamp->reserved = 0;
	return 1;
}

uint16_t get_free_user_data_blocks()
{
    read_main_super_block();
	
	memefs_superblock_t* sb = (memefs_superblock_t*)block_buffer;

	const uint16_t index_of_userdata = ntohs(sb->first_user_block);
	const uint16_t size_of_userdata = ntohs(sb->num_user_blocks);

    uint16_t free_data_blocks = 0;
	
	if (file_allocation_table != NULL) {
		for (uint16_t i = index_of_userdata; i < index_of_userdata + size_of_userdata; i++) {
			if (file_allocation_table[i] == 0) {
                free_data_blocks++;
			}
		}
	}

    return free_data_blocks;
}

uint16_t get_used_file_entries()
{
	read_main_super_block();

	memefs_superblock_t* sb = (memefs_superblock_t*)block_buffer;

	const uint16_t index_of_directory = ntohs(sb->directory_start);
	const uint16_t size_of_directory = ntohs(sb->directory_size);

	uint16_t used_file_entries = 0;

	for (uint16_t i = index_of_directory; i > index_of_directory - size_of_directory; i--) {
        read_block(i);

        memefs_dirctory_t* dir = (memefs_dirctory_t*)block_buffer;

        uint16_t index;
		
		for (index = 0; index < NUMBER_OF_FILE_ENTRIES; index++) {
			if (dir->file_entries[index].file_type != 0) {
                used_file_entries++;
                continue;
			}

            break;
		}

		if (index < NUMBER_OF_FILE_ENTRIES) {
			break;
		}
	}
	
	return used_file_entries;
}

uint16_t get_free_file_entries()
{
	read_main_super_block();

	memefs_superblock_t* sb = (memefs_superblock_t*)block_buffer;

	const uint16_t index_of_directory = ntohs(sb->directory_start);
	const uint16_t size_of_directory = ntohs(sb->directory_size);

	const uint16_t free_file_entries = NUMBER_OF_FILE_ENTRIES * size_of_directory - get_used_file_entries();
    return free_file_entries;
}

int memefs_getattr(const char* path, struct stat* st)
{
	struct stat* buf = open_map_file();
    read_main_super_block();
	memefs_superblock_t* sb = (memefs_superblock_t*)block_buffer;
	memset(st, 0, sizeof(struct stat));

	printf("requesting for path %s", path);

	st->st_mode = buf->st_mode;
	st->st_nlink = buf->st_nlink;
	st->st_size = buf->st_size;
	st->st_blocks = sb->num_user_blocks;

	st->st_uid = buf->st_uid;
	st->st_gid = buf->st_gid;
	st->st_mtime = buf->st_mtime;
	st->st_atime = buf->st_atime;
	st->st_ctime = buf->st_ctime;

	return 0;
}

int memefs_readdir(const int8_t* path, void* buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi)
{
	filler(buffer, ".", NULL, 0);           // current directory reference
	filler(buffer, "..", NULL, 0);          // parent directory reference
    filler(buffer, "abc.txt", NULL, 0);     // any filename at path in your image
	return 0;
}

static struct fuse_operations memefs_operations = {
	.getattr	= memefs_getattr,
	.readdir	= memefs_readdir
//  .open		= memefs_ll_open,
//  .read		= memefs_ll_read,
};

int main(int argc, char** argv)
{
    int i;
 
	// get the device or image filename from arguments
	for (i = 1; i < argc && argv[i][0] == '-'; i++);
	
	if (i < argc) {
		memeFile = realpath(argv[i], NULL);
		memcpy(&argv[i], &argv[i + 1], (argc - i) * sizeof(argv[0]));
		argc--;
	}

	// leave the rest to FUSE
	return fuse_main(argc, argv, &memefs_operations, NULL);
}
