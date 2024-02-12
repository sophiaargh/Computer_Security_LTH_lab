/*
 * Shows user info from local pwfile.
 *  
 * Usage: userinfo username
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include "pwdblib.h"   /* include header declarations for pwdblib.c */

/* Define some constants. */
#define USERNAME_SIZE (32)
#define NOUSER (-1)
#define PASSWD_SIZE (32)
#define SALT_SIZE (2)
#define MAX_TRIES (5)
#define OLD_AGE (10)
#define LOCKED (-2)
#define FAILED (1)

void read_username(char *username){
    printf("login: ");
    fgets(username, USERNAME_SIZE, stdin);
    /* remove the newline included by getline() */
    username[strlen(username) - 1] = '\0';
}

int authentication(char * username, char * password){
    struct pwdb_passwd *p = pwdb_getpwnam(username);
    char salt[SALT_SIZE];
    int return_val = 0;
    if (p != NULL) {
        if (p->pw_failed >= MAX_TRIES){
            return LOCKED;
        }
        if (p->pw_age > OLD_AGE){
            printf("Please change your password");
        }
        //extract the salt from the database (first 2 bytes of the passwd)
        strncpy(salt, p->pw_passwd, SALT_SIZE);

        //compare the hashed password with the password in the database
        //if the passwords are different, increase the pw_failed 
        if(strcmp(p->pw_passwd, crypt(password, salt)) != 0){
            (p->pw_failed)++;
            return_val = FAILED;
        } else {
            (p->pw_age)++;
            p->pw_failed = 0;
        }
        pwdb_update_user(p);
        return return_val;
    } else {
        return NOUSER;
    }
}
int main(int argc, char **argv){
    int f_login = 0; 
    char username[USERNAME_SIZE];
    char *password;
    while(1){
        /* 
        * Write "login: " and read user input. Copies the username to the
        * username variable.
        */
        read_username(username);
        /* 
        * Write "password: " and read user input. Copies the password to the
        * password variable without echo.
        */
        password = getpass("password: ");
        int auth = authentication(username, password);
        if (auth > 0 || auth == NOUSER){
            printf("\nUnknown user or incorrect password \n");  
        } else if (auth == LOCKED){
            printf("\nNumber of maximum tries exceeded,");
            printf("\nyou are locked\n");
        } else {
            printf("\nUser authenticated successfully \n");
            return 0;
        }
    }
}

  


