//To filter the User Input file in order to extract vulnerable functions
#include <stdio.h>
#include <stdlib.h>
int linecount=0;
void RemoveSpaces(char* source)
    {
        char* i = source;
        char* j = source;
        while(*j != 0)
        {
            *i = *j++;
            if(*i != ' ')
            i++;
        }
        *i = 0;
    }
void filter()
{
    FILE *fptr,*fptr2;
    char ch;
    char str[10000];
    char *file;
    char ignore[1024];
    int i=0;
    int n=0;
    fptr=fopen("Test_file_1.txt","r");
    fptr2 = fopen("final_func.txt","w+");
    if (fptr == NULL)
    {
        printf("Cannot open file \n");
        exit(0);
    }
    while ((ch = fgetc(fptr)) != EOF )
    {
        n++;
        if(ch=='#'||ch=='/'||ch=='{'||ch=='}')
        {
          fgets(ignore, sizeof(ignore), fptr);
          n=0;
          i++;
        }
        else if(ch=='(')
        {
            fseek(fptr,-n,SEEK_CUR);
            fgets(str,sizeof(str),fptr);
            fprintf(fptr2,"%d",i);
            RemoveSpaces(str);
            fputs(str,fptr2);
            n=0;
            i++;

        }
        else if(ch=='\n')
        {
            i++;
            n=0;
        }
    }
fclose(fptr);
fclose(fptr2);
}
