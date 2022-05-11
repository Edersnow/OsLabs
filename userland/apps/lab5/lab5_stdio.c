/*
 * Copyright (c) 2022 Institute of Parallel And Distributed Systems (IPADS)
 * ChCore-Lab is licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 */

#include "lab5_stdio.h"


extern struct ipc_struct *tmpfs_ipc_struct;

/* You could add new functions or include headers here.*/
/* LAB 5 TODO BEGIN */
int call_seek(FILE *f) {
	ipc_msg_t *msg;
	struct fs_request *request;
	int ret;

	msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 1);
	request = (struct fs_request *) ipc_get_msg_data(msg);
	request->req = FS_REQ_LSEEK;
	request->lseek.fd = f->fd;
	request->lseek.offset = f->offset;
	request->lseek.whence = SEEK_SET;
	ret = ipc_call(tmpfs_ipc_struct, msg);
	ipc_destroy_msg(tmpfs_ipc_struct, msg);

	return ret;
}

int call_open(int fd, u32 mode, const char *filename) {
	ipc_msg_t *msg;
	struct fs_request *request;
	int ret;

	msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 1);
	request = (struct fs_request *) ipc_get_msg_data(msg);
	request->req = FS_REQ_OPEN;
	request->open.new_fd = fd;
	request->open.mode = mode;

	if (*filename == '\0') {
		strcpy(request->open.pathname, "/");
	}
	else if (*filename != '/') {
		request->open.pathname[0] = '/';
		strcpy(request->open.pathname + 1, filename);
	} 
	else {
		strcpy(request->open.pathname, filename);
	}

	ret = ipc_call(tmpfs_ipc_struct, msg);
	ipc_destroy_msg(tmpfs_ipc_struct, msg);

	return ret;
}

int call_create(u32 mode, const char *filename) {
	ipc_msg_t *msg;
	struct fs_request *request;
	int ret;

	msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 1);
	request = (struct fs_request *) ipc_get_msg_data(msg);
	request->req = FS_REQ_CREAT;
	request->creat.mode = mode;

	if (*filename == '\0') {
		strcpy(request->creat.pathname, "/");
	}
	else if (*filename != '/') {
		request->creat.pathname[0] = '/';
		strcpy(request->creat.pathname + 1, filename);
	} 
	else {
		strcpy(request->creat.pathname, filename);
	}

	ret = ipc_call(tmpfs_ipc_struct, msg);
	ipc_destroy_msg(tmpfs_ipc_struct, msg);

	return ret;
}

int call_write(FILE *f, const void *src, size_t nmemb) {
	ipc_msg_t *msg;
	struct fs_request *request;
	int ret;

	msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request) + nmemb + 1, 1);
	request = (struct fs_request *) ipc_get_msg_data(msg);
	request->req = FS_REQ_WRITE;
	request->write.fd = f->fd;
	request->write.count = nmemb;
	memcpy((char *)request + sizeof(struct fs_request), src, nmemb);
	ret = ipc_call(tmpfs_ipc_struct, msg);
	if (ret >= 0) {
		f->offset += ret;
	}
	ipc_destroy_msg(tmpfs_ipc_struct, msg);

	return ret;
}

int call_read(FILE *f, void *destv, size_t nmemb) {
	ipc_msg_t *msg;
	struct fs_request *request;
	int ret;

	msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 1);
	request = (struct fs_request *) ipc_get_msg_data(msg);
	request->req = FS_REQ_READ;
	request->read.fd = f->fd;
	request->read.count = nmemb;
	ret = ipc_call(tmpfs_ipc_struct, msg);
	if (ret > 0) {
		memcpy(destv, ipc_get_msg_data(msg), ret);
		f->offset += ret;
	}
	ipc_destroy_msg(tmpfs_ipc_struct, msg);

	return ret;
}

int call_close(FILE *f) {
	ipc_msg_t *msg;
	struct fs_request *request;
	int ret;

	msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 1);
	request = (struct fs_request *) ipc_get_msg_data(msg);
	request->req = FS_REQ_CLOSE;
	request->close.fd = f->fd;
	ret = ipc_call(tmpfs_ipc_struct, msg);
	ipc_destroy_msg(tmpfs_ipc_struct, msg);
	if (ret >= 0) {
		--f->refcnt;
		if (f->refcnt == 0) {
			free(f);
		}
	}

	return ret;
}

int double_buf(char *buf, int size) {
	char *new_buf = malloc(2 * size);
	memcpy(new_buf, buf, size);
	free(buf);
	buf = new_buf;
	return size * 2;
}
/* LAB 5 TODO END */


FILE *fopen(const char * filename, const char * mode) {

	/* LAB 5 TODO BEGIN */
	static fd = 0;
	int ret;
	ipc_msg_t *msg;
	struct fs_request *request;

	++fd;

	ret = call_open(fd, (u32) mode, filename);

	if (ret < 0) {
		if (*mode == 'r') {
			return NULL;
		}
		else {
			ret = call_create((u32) mode, filename);
			if (ret < 0) {
				return NULL;
			}
			ret = call_open(fd, (u32) mode, filename);
		}
	}

	FILE* file = malloc(sizeof(struct FILE));
	file->fd = fd;
	strcpy(file->filename, filename);
	file->mode = (u32) mode;
	file->offset = 0;
	/* LAB 5 TODO END */
    return file;
}

size_t fwrite(const void * src, size_t size, size_t nmemb, FILE * f) {

	/* LAB 5 TODO BEGIN */
	int ret;
	call_seek(f);
	ret = call_write(f, src, nmemb);
	/* LAB 5 TODO END */
    return ret;

}

size_t fread(void * destv, size_t size, size_t nmemb, FILE * f) {

	/* LAB 5 TODO BEGIN */
	int ret;
	call_seek(f);
	ret = call_read(f, destv, nmemb);
	/* LAB 5 TODO END */
    return ret;

}

int fclose(FILE *f) {

	/* LAB 5 TODO BEGIN */
	call_close(f);
	/* LAB 5 TODO END */
    return 0;

}

/* Need to support %s and %d. */
int fscanf(FILE * f, const char * fmt, ...) {

	/* LAB 5 TODO BEGIN */
	int size = 8192;
	int ret;
	char buf[size];
	fread(buf, sizeof(char), size, f);
	int off = 0;

	va_list va;
	char *s_dst;
	int *d_dst;

	int i = 0;
	
	va_start(va, fmt);
	while (fmt[i] != '\0') {
		if (fmt[i] == '%') {
			++i;
			switch (fmt[i]) {
				case 'd':
					d_dst = va_arg(va, int *);

					while (buf[off] == ' ' || buf[off] == '\n' || buf[off] == '\0') {
						++off;
						if (off == size) {
							fread(buf, sizeof(char), size, f);
							off = 0;
						}
					}
					
					if (buf[off] < '0' || buf[off] > '9') {
						return 0;
					}

					int number = 0;
					while ('0' <= buf[off] && buf[off] <= '9') {
						number = (buf[off] - '0') + number * 10;
						++off;
						if (off == size) {
							fread(buf, sizeof(char), size, f);
							off = 0;
						}
					}
					*d_dst = number;
					break;

				case 's':
					s_dst = va_arg(va, char *);
					while (buf[off] == ' ' || buf[off] == '\n' || buf[off] == '\0') {
						++off;
						if (off == size) {
							fread(buf, sizeof(char), size, f);
							off = 0;
						}
					}
					
					int start_off = off;
					while (buf[off] != ' ' && buf[off] != '\n' && buf[off] != '\0') {
						++off;
						if (off == size) {
							memcpy(s_dst, buf + start_off, off - start_off);
							s_dst += off - start_off;

							fread(buf, sizeof(char), size, f);
							start_off = off = 0;
						}
					}
					if (off != start_off) {
						memcpy(s_dst, buf + start_off, off - start_off);
					}
					break;
			}
		}
		++i;
	}
	va_end(va);
	/* LAB 5 TODO END */
    return 0;
}

/* Need to support %s and %d. */
int fprintf(FILE * f, const char * fmt, ...) {

	/* LAB 5 TODO BEGIN */
	int size = 8192;
	char *buf = malloc(size);

	va_list va;

	int i = 0;
	int off = 0;

	int num, j, s_len;
	char *s_src;

	va_start(va, fmt);
	while (fmt[i] != '\0') {
		if (fmt[i] == '%') {
			++i;
			switch (fmt[i])
			{
				case 'd':
					num = va_arg(va, int);
					j = 0;
					char tmp[64] = {'\0'};
					while (num > 0) {
						tmp[j++] = (num % 10) + '0';
						num /= 10;
					}
					
					while (off + j >= size) {
						size = double_buf(buf, size);
					}
					for (int z = j - 1; z >= 0; --z) {
						buf[off++] = tmp[z];	
					}
					break;

				case 's':
					s_src = va_arg(va, char *);
					s_len = strlen(s_src);
					while (off + s_len >= size) {
						size = double_buf(buf, size);
					}

					memcpy(buf + off, s_src, s_len);
					off += s_len;
					break;
			}
		} 
		else {
			if (off >= size) {
				size = double_buf(buf, size);
			}
			buf[off++] = fmt[i];
		}
		++i;
	}
	va_end(va);
	buf[off] = '\0';
	fwrite(buf, sizeof(char), off, f);
	free(buf);
	
	/* LAB 5 TODO END */
    return 0;
}

