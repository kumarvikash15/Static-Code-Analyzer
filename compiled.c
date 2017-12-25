#include "MinorFilter.h"
#include "counthml.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define d 256

struct hash *hashTable = NULL;
int eleCount = 0;
int totalcount=0;
int totalvulcount=0;

struct node {
    int hash;
    char name[100];
    char severity[10];
    struct node *next;
};

struct hash {
    struct node *head;
    int count;
};

struct node * createNode(int hash, char *name,char *severity)           //Creating Node with Hash value, Name, Severity
{
    struct node *newnode;
    newnode = (struct node *) malloc(sizeof(struct node));
    newnode->hash = hash;
    strncpy(newnode->name, name,sizeof(newnode->name));
    strncpy(newnode->severity, severity,sizeof(newnode->severity));
    newnode->next = NULL;
    return newnode;
}

void insertToHash(int hash, char *name,char *severity)                      //Inserting Hash Value, Vulnerable Function Name, Severity in Hash Table.
{

    int hashIndex = hash % eleCount;
    struct node *newnode = createNode(hash, name,severity);

    if (!hashTable[hashIndex].head)
    {
        hashTable[hashIndex].head = newnode;
        hashTable[hashIndex].count = 1;
        return;
    }
    newnode->next = (hashTable[hashIndex].head);
    hashTable[hashIndex].head = newnode;
    hashTable[hashIndex].count++;

    return;
}

int searchInHash(int hash,int len)                                     //Searching for hash value in the Hash Table
{
    int hashIndex = hash % eleCount;
    int flag1 = 0;
    struct node *myNode=0;
    myNode = hashTable[hashIndex].head;
    int result;
    if (!myNode)
    {
        //printf("Search element unavailable in hash table\n");
    }
    while (myNode != NULL)
    {
        if (myNode->hash == hash && len==strlen(myNode->name))
        {
            flag1 = 1;
            result = myNode->hash;
            break;
        }
        myNode = myNode->next;
    }
    if (flag1==0)
    {
       //printf("Search element unavailable in hash not in table\n");
    }
    return result;
}

char* return_name(int hash,int len)                                        //returning the name of searched hash value
{
    int hashIndex = hash % eleCount;
    int flag2 = 0;
    struct node *myNode=0;
    myNode = hashTable[hashIndex].head;
    char* result;
    if (!myNode)
    {
       // printf("display element unavailable in hash table\n");
    }
    while (myNode != NULL) {
        if (myNode->hash == hash && len==strlen(myNode->name))
        {
            flag2 = 1;
            result = myNode->name;
            break;
        }
        myNode = myNode->next;
    }

    if (flag2==0)
     {
       // printf("display element unavailable in hash not table\n");
     }
    return result;
}


void output(int hash,int len)                                           //Printing found vulnerable function in graphical_output file
{
    FILE *fpout;
    int hash_num;
    char *hash_name;
    char *hash_severity;
    int hashIndex = hash % eleCount;
    int flag3 = 0;
    struct node *finalNode=0;
    finalNode = hashTable[hashIndex].head;

    fpout= fopen("graphical_output.txt","a");
    if (!finalNode)
    {
       // printf("display element unavailable in hash table\n");
    }
    while (finalNode != NULL) {
        if (finalNode->hash == hash && len==strlen(finalNode->name))
        {
            flag3=1;
            hash_num=finalNode->hash;
            hash_name=finalNode->name;
            hash_severity=finalNode->severity;
            fprintf(fpout,"%d ",hash_num);
            fprintf(fpout,"%s ",hash_name);
            fprintf(fpout,"%s ",hash_severity);
            fprintf(fpout,"\n");
            break;
        }
        finalNode = finalNode->next;
    }

    if (flag3==0)
     {
        // printf("display element unavailable in hash not table\n");
     }
fclose(fpout);
}


void rabin_search(char txt[], int q, FILE *fptr2)                   //using Rabin Karp algorithm for string matching
{
int M[10]={4,5,6,7,8};
int N=strlen(txt);
int v=0;
int z,w=0;
int p = 0;
int t = 0;
int h = 1;
int i,j;
char* name;

while(w!=5)
{
z=M[w];
t=0;
h=1;
for (i = 0; i < z-1; i++)
{
    h = (h*d)%q;
}
for (i = 0; i < z; i++)
{
    t = (d*t + txt[i])%q;
}
p=searchInHash(t,z);
for (i = 0; i < N - z; i++)
{
        if ( p == t )
        {
            name= return_name(p,z);
            for (j = 0; j < z; j++)
            {
                if (txt[i+j] != name[j])
                    break;
            }
            if (j == z)
            {
                //fscanf(fptr2,"%d",&linecount);
                //printf("%d\n",linecount);
                printf("'%s()' function found in line number %d at index %d \n\n",name,linecount,i);
                output(p,z);
                totalvulcount++;
            }
        }
        if ( i < N-z )
        {
            t = (d*(t - txt[i]*h) + txt[i+z])%q;
            if (t < 0)
            {
                t = (t + q);
            }
            p=searchInHash(t,z);
        }
}
w++;
}

}
/*void show()                   //Hash Table Value
{
    struct node *myNode;
    int i;
    for (i = 0; i < eleCount; i++) {
        if (hashTable[i].count == 0)
            continue;
        myNode = hashTable[i].head;
        if (!myNode)
            continue;
        printf("\nData at index %d in Hash Table:\n", i);
        printf("HashValue    Name    Severity     \n");
        printf("---------------------\n");
        while (myNode != NULL) {
            printf("%-12d", myNode->hash);
            printf("%-15s", myNode->name);
            printf("%-15s", myNode->severity);
            myNode = myNode->next;
        }
    }
    return;
}*/

int main()
{
    FILE *fptr;
    FILE *fptr2;
    FILE *fpout;
    int i;
    char txt[1000];
    int q = 101; // A prime number
    char ch;
    int key;
    char name[100];
    char severity[20];
    char *token;
    char line[1000];
    int n,hash;

    printf("\n***************************************\n       Static Code Analysis   \n***************************************\n\n");
    eleCount = 20;
    filter();

    fptr=fopen("vulfunc.txt","r");          //Opening file with vulnerable functions.
    fptr2=fopen("final_func.txt","r");        //Opening Users code file to be scanned.

    if(fptr == NULL || fptr2 == NULL)
    {
        fprintf(stderr,"error fopen(): Failed to open file vulfunc.txt.\n");
        fprintf(stderr,"error fopen(): Failed to open file final_func.txt.\n");
        exit(EXIT_FAILURE);
    }
    hashTable = (struct hash *) calloc(n, sizeof(struct hash));

    while((fgets(line, sizeof(line), fptr)) != '\0')                        //Creating Hash Table
            {
                token = strtok(line, ":");
                key = atoi(token);
                token = strtok(NULL, ":");
                if(token==NULL)
                {
                    break;
                }
                strncpy(name,token,sizeof(name));
                token = strtok(NULL, ":");
                strncpy(severity,token,sizeof(severity));
                insertToHash(key,name,severity);
            }
    fpout= fopen("graphical_output.txt","w");
    if(fpout==NULL)
    {
        perror("Error in opening the file");
        return -1;
    }
    fprintf(fpout,"\nHash Value | Name | Severity \n============================\n\n");
    fclose(fpout);

    while(!feof(fptr2))                                             //Taking Input file to be scanned, from user and using String matching Algorithm
    {
        fscanf(fptr2,"%d",&linecount);
        fgets(txt,sizeof(txt),fptr2);
        rabin_search(txt,q,fptr2);
        totalcount++;
    }
    printf("\n***************************************\n \tAnalysis of Code \n***************************************\n \n");
    printf  ("Total Functions  Vulnerable Functions\n\n\t %d \t\t %d  ",totalcount-1, totalvulcount);

    fpout= fopen("graphical_output.txt","a");
    if(fpout==NULL)
    {
        perror("Error in opening the file");
        return -1;
    }
    fprintf(fpout,"\n*****************************\n");
    fclose(fpout);

    counthml();

    fclose(fptr);
    fclose(fptr2);
    free(hashTable);

    return 0;
}
