#include"helpers.h"

void chk_err(int check)
{
    if(check == -1)
    {
        perror("An error has occurred");
        exit(-1);
    }
}

void chk_memerr(void * check)
{
    if(check == NULL)
    {
        perror("An error has occurred");
        exit(-1);
    }
}
