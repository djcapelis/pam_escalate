/**********************************************************************
| libescalate
| Version 0
| 
| A PAM to use separate escalation credentials
| Web: http://escalate.capelis.dj
| 
| Author: D.J. Capelis
| Copyright the Regents of the University of California, 2008.
| Released under the GNU General Public License
| 
**********************************************************************/

#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>
#include<pwd.h>
#include<errno.h>

#define BUF 1024

int main()
{
    struct passwd * user;
    char * es_name;
    
    user = getpwuid(getuid());
    printf("User: %s Homedir: %s ID: %d\n", user->pw_name, user->pw_dir, user->pw_uid);

    es_name=calloc(1, L_cuserid+5);
    strncpy(es_name, user->pw_name, L_cuserid);
    strncat(es_name, "_root", L_cuserid+5);

    printf("Checking for valid escalation user %s...\n", es_name);
    user = getpwnam(es_name);
    if(!user)
    {
        printf("You are not authorized to escalate\n");
        exit(EPERM);
    }
    if(strncmp(user->pw_dir, "/root", 6))
    {
        printf("An escalation user exists for your username, but is not valid\n");
        exit(EPERM);
    }
    else
    {
        printf("You are authorized to escalate\n");
    }

    printf("Escalation user: %s Homedir: %s ID: %d\n", user->pw_name, user->pw_dir, user->pw_uid);
}
