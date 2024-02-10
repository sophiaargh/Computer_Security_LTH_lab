/*
 * Shows user info from local pwfile.
 *  
 * Usage: userinfo username
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pwdblib.h"   /* include header declarations for pwdblib.c */

/* Define some constants. */
#define USERNAME_SIZE (32)
#define NOUSER (-1)
#define PASSWD_SIZE (32)
#define SALT_SIZE (2)


int print_info(const char *username)
{
  struct pwdb_passwd *p = pwdb_getpwnam(username);
  if (p != NULL) {
    printf("Name: %s\n", p->pw_name);
    printf("Passwd: %s\n", p->pw_passwd);
    printf("Uid: %u\n", p->pw_uid);
    printf("Gid: %u\n", p->pw_gid);
    printf("Real name: %s\n", p->pw_gecos);
    printf("Home dir: %s\n",p->pw_dir);
    printf("Shell: %s\n", p->pw_shell);
	return 0;
  } else {
    return NOUSER;
  }
}

int find_user(const char *username, const char *password){
  struct pwdb_passwd *p = pwdb_getpwnam(username);
  char salt[SALT_SIZE + 1];
  //char *h_passwd = malloc(PASSWD_SIZE+SALT_SIZE);
  if (p != NULL) {

    //extract the salt from the database (first 2 bytes of the passwd)
    strncpy(salt, p->pw_passwd, SALT_SIZE);

    //compare the hashed password with the password in the database
    //if the passwords are different, return NOUSER
    if(strcmp(p->pw_passwd, crypt(password, salt)) != 0){
        return NOUSER;
    }
    return 0;
  } else {
    return NOUSER;
  }
}

void read_username(char *username)
{
  printf("login: ");
  fgets(username, USERNAME_SIZE, stdin);

  /* remove the newline included by getline() */
  username[strlen(username) - 1] = '\0';
}

void read_password(char *password)
{
  printf("password: ");
  
  //password = getpass();
  fgets(password, PASSWD_SIZE, stdin);
  /* remove the newline included by getline() */
  password[strlen(password) - 1] = '\0';
  printf("hello");
}

int main(int argc, char **argv){
  while(1){

    char username[USERNAME_SIZE];
    char password[PASSWD_SIZE];

    /* 
    * Write "login: " and read user input. Copies the username to the
    * username variable.
    */
    read_username(username);
    /* 
    * Write "password: " and read user input. Copies the password to the
    * password variable.
    */
    read_password(password);

    /* Show user info from our local pwfile. */
    if (find_user(username, password) == NOUSER) {
        /* if there are no user with that username*/
        printf("\nUnknown user or incorrect password\n"); 
    }else{
        printf("\nUser authenticated successfully");
        return 0;
    }
  }
}
  

  
