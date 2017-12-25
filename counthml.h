//To count the number of Functions with severity High, Low, Medium
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int h=0;
int l=0;
int m=0;
int totalcount=0;

void counthml()
{
    FILE *fp;
    FILE *fp2;
    char line[100];
    char line2[100];
    int i=0,j=0;

    fp= fopen("graphical_output.txt","r");
    fp2=fopen("final_func.txt","r");
    while(!feof(fp))
    {
        fgets(line,sizeof(line),fp);
        for(i=0;i<strlen(line);i++)
        {
            if(line[i]=='h'|| line[i]=='l' || line[i]=='m')
            {
                   if(line[i]=='l' && line[i+1]=='o' && line[i+2]=='w')
                   {
                       l++;
                   }
                   else if(line[i]=='h' && line[i+1]=='i' && line[i+2]=='g' && line[i+3]=='h'){
                    h++;
                   }
                   else if(line[i]=='m' && line[i+1]=='e' && line[i+2]=='d' && line[i+3]=='i'&& line[i+4]=='u'&& line[i+5]=='m')
                   {
                    m++;
                   }

               }
            }
        }

        while(fgets(line2,sizeof(line2),fp2) !='\0')
        {
            /*if(fgetc(fp2)=='\n')
            {
                 totalcount++;
            }*/
             totalcount++;
        }
        printf("totalcount: %d",totalcount);
        printf("\n\n***************************************\n Severity Level | Number of Functions \n  Low \t\t\t %d \n  Medium\t\t %d \n  High\t\t\t %d \n\n",l,m,h);
        fclose(fp);
}




