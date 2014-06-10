#include <stdio.h>
#include <string.h>
#include "c_des.h"
#include "utils.h"


int main (int argc, char** argv) {
    
    FILE *infile = fopen(argv[1],"rb");
    if (!infile) {
	printf("USAGE: %s input_file\n",argv[0]);
	return 1;
    }
    fclose(infile);
    
    FILE *pass = fopen("pass","wb");
    struct hyp_struct hyp;
    
    char pwd[40], check[40];
    puts("Insert a password (8 characters), leave blank for random:");
    gets(pwd);
    fflush(stdin);
    puts("Insert a checkstring (8 characters), leave blank for random:");
    gets(check);
    fflush(stdin);
    printf("\n\n%s\n%s\n",pwd,check);
    if (strlen(pwd) < 8) {
	rand_string(pwd, 8);
    }
    if (strlen(check) < 8) {
	rand_string(check, 8);
    }
    
    strncpy(hyp.check, check, 8);
    hyp.check[8] = '\0';
    strncpy(hyp.pass_hint, pwd,4);
    hyp.pass_hint[4] = '\0';
    DesEncrypt(hyp.check, pwd, hyp.enc_check);
    
    fwrite(&hyp, sizeof(struct hyp_struct), 1, pass);
    encrypt_file(argv[1], pwd, "enc_win");
    
    fclose(pass);
    
    return 0;
}
    
    