
#include <stdio.h>
#include <stdint.h>
#include "string.h"
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#define FUSE_USE_VERSION 29
#include <fuse.h>


static uint8_t block_buf[512];

//static int hello_stat(fuse_ino_t ino, struct stat *stbuf)
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
static void myfs_getattr(const char *path, struct stat *st){
//    struct stat stbuf;
//
//    (void) fi;
//
//    memset(&stbuf, 0, sizeof(stbuf));
//    if (hello_stat(ino, &stbuf) == -1)
//        fuse_reply_err(req, ENOENT);
//    else
//        fuse_reply_attr(req, &stbuf, 1.0);
}

//static void hello_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
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
//                             off_t off, struct fuse_file_info *fi)
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
//                          struct fuse_file_info *fi)
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
//                          off_t off, struct fuse_file_info *fi)
//{
////    (void) fi;
////
////    assert(ino == 2);
////    reply_buf_limited(req, hello_str, strlen(hello_str), off, size);
//}



typedef struct memefs_superblock {
    char signature[16];
    uint8_t cleanly_unmounted;
    uint8_t reseerved1[3];
    uint32_t fs_version;
    uint8_t fs_ctime[8];
    uint16_t main_fat;
    uint16_t main_fat_size;
    uint16_t backup_fat;
    uint16_t backup_fat_size;
    uint16_t directory_start;
    uint16_t directory_size;
    uint16_t num_user_blocks;
    uint16_t first_user_block;
    char volume_label[16];
    uint8_t unused[448];
} __attribute__((packed)) memefs_superblock_t;

typedef struct memefs_fat{
    uint16_t mbr;

} __attribute__((packed)) memefs_fat_t;

typedef struct memfs_directory {

    uint16_t file_type;
    uint16_t location_first_block; 
    char filename_label[11];
    uint8_t unused; 
    uint8_t write_ctime[8];
    uint32_t file_size;
    uint16_t user_id;
    uint16_t owner_group_id;
}__attribute__((packed)) memefs_directorry_t;




static struct fuse_operations hello_filesystem_operations = {
    //    .getattr	= hello_ll_getattr,
    //    .readdir	= hello_ll_readdir,
    //    .open		= hello_ll_open,
    //    .read		= hello_ll_read,
};



static  void getSB(uint8_t  *ptr, memefs_superblock_t *sb) {
    //Get Backup block
    memcpy(sb->signature, ptr, 16);
    sb->cleanly_unmounted =  ptr[16];
    memcpy(sb->reseerved1, ptr + 17, 3);
    uint32_t version  = 0;
    memcpy(&version, ptr + 20 , 4);
     sb->fs_version  = ntohl(version);
    memcpy(sb->fs_ctime, ptr + 24 , 8);
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

static  void getDirectory(uint8_t  *ptr, memefs_directorry_t *sb) {
    //Get Backup block
    uint16_t fileType = 0;
    memcpy(&fileType, ptr, 2);
    sb->file_type = ntohs(fileType);
    uint16_t location_first_block = 0;
    memcpy(&location_first_block, ptr +2 , 2);
    sb->location_first_block = ntohs(location_first_block);
    memcpy(sb->filename_label, ptr +4, 11);
    sb->unused = ptr[15];
    memcpy(sb->write_ctime, ptr + 16 , 8);
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
static  void getFat(uint8_t  *ptr, memefs_fat_t *sb) {
    //Get Backup block
    uint16_t mbr = 0;
    memcpy(&mbr, ptr, 2);
    sb->mbr =  ntohs(mbr);

    for (int i = 0;  i< 4; i++){

    }

    //value signifying that this data cluster is the last cluster of a file
    //value signifying that this data cluster is currently unised
    //value signifying where the NExt data cluster of the current file is located

    uint16_t rest  = 0;
//    memcpy(&rest, ptr + 2, 510);

}


char *memeFile  = NULL; 




void getStats() {

    int fd  = open(memeFile, O_RDWR);
    if (fd <  0){
        printf("\n\"%s \" could not open\n ", filePath);
        exit(1);
    }

    struct stat statbuf;
    int err  = fstat(fd, &statbuf);
    if(err < 0){
        printf("\n\"%s \" could not open\n ", filePath);
        exit(2);
    }




    uint8_t  *ptr = mmap(NULL,statbuf.st_size,
                     PROT_READ|PROT_WRITE,
                     MAP_SHARED,
                     fd,0);
    if(ptr == MAP_FAILED){
        printf("Mapping Failed\n");
        return 1;
    }

    close(fd);

    //Get the First Block of data which is the super block
    memefs_superblock_t *sb = (memefs_superblock_t *)block_buf;
    uint8_t *ptrFirst = malloc(sizeof(uint8_t )* 512);
    memcpy(ptrFirst, ptr, 512);
    getSB(ptrFirst, sb);


    //Get the Last Block which is the main Super block
    memefs_superblock_t *sa = (memefs_superblock_t *)block_buf;
    uint8_t *ptrMain = malloc(sizeof(uint8_t )* 512);
    memcpy(ptrMain, ptr + (statbuf.st_size - 512), 512);
    getSB(ptrFirst, sb);

    //Get the Directory
    memefs_directorry_t *dir = (memefs_directorry_t *)block_buf;
    uint8_t *ptrDir = malloc(sizeof(uint8_t )* 512);
    memcpy(ptrDir, ptr + (sa->directory_start * 512), 512);
    getDirectory(ptrDir, dir);

    //Get the MainFat
    memefs_fat_t *fat = (memefs_fat_t *)block_buf;
    uint8_t *ptrFat = malloc(sizeof(uint8_t )* 512);
    memcpy(ptrFat, ptr + (sa->main_fat * 512), 512);
    getFat(ptrFat, fat);

    ssize_t n = write(1,ptr,statbuf.st_size);
    if(n != statbuf.st_size){
        printf("Write failed");
    }

    err = munmap(ptr, statbuf.st_size);
    if (err != 0){
        printf("UnMapping Failed\n");
        return 1;
    }

} 


int main(int argc, char **argv) {
   
   int i;
 
  // get the device or image filename from arguments
  for (i = 1; i < argc && argv[i][0] == '-'; i++);
  if (i < argc) {
    memeFile = realpath(argv[i], NULL);
    memcpy(&argv[i], &argv[i+1], (argc-i) * sizeof(argv[0]));
    argc--;
  }
  // leave the rest to FUSE
  return fuse_main(argc, argv, &hello_filesystem_operations, NULL);
}

