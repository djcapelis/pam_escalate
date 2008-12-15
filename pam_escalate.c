/**********************************************************************
| pam_escalate
| Version 1
| 
| A PAM to use separate escalation credentials
| Web: http://projects.capelis.dj/pam_escalate
| 
| Author: D.J. Capelis
| 
**********************************************************************/

#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>
#include<pwd.h>

#include<security/pam_appl.h>
#include<security/pam_misc.h>

#include"helpers.h"
void chk_pamerr(int chk, pam_handle_t * pamh); 

#define BUF 1024

int main()
{
    /* Part I - Initial checks */
    struct passwd * user;
    struct passwd pwent;
    char * pwentchars;
    char * es_name;
    char * root_home;
    int ret;
    int pwentcharsmax = sysconf(_SC_GETPW_R_SIZE_MAX);

    es_name = calloc(1, L_cuserid+5);
    chk_memerr(es_name);
    pwentchars = calloc(1, pwentcharsmax);
    chk_memerr(pwentchars);
    root_home = calloc(1, pwentcharsmax);
    chk_memerr(pwentchars);
    errno = 0;

    if(getuid() == 0)
    {
        printf("You are already what you seek to become.  Just use your hands.\n");
        free(es_name);
        free(pwentchars);
        free(root_home);
        return 0;
    }

    ret = getpwuid_r(0, &pwent, pwentchars, pwentcharsmax, &user);
    strncpy(root_home, user->pw_dir, pwentcharsmax);

    ret = getpwuid_r(getuid(), &pwent, pwentchars, pwentcharsmax, &user);
    printf("User: %s Homedir: %s ID: %d\n", user->pw_name, user->pw_dir, user->pw_uid);

    es_name=calloc(1, L_cuserid+5);
    strncpy(es_name, user->pw_name, L_cuserid);
    strncat(es_name, "_root", L_cuserid+5);

    printf("Checking for valid escalation user %s...\n", es_name);
    ret = getpwnam_r(es_name, &pwent, pwentchars, pwentcharsmax, &user);
    if(ret == 0 && user == NULL)
    {
        printf("You are not authorized to escalate\n");
        free(es_name);
        free(pwentchars);
        free(root_home);
        return EPERM;
    }
    /* If user's still null after the return from above, an actual error happened */
    chk_memerr(user);
    if(strncmp(user->pw_dir, root_home, pwentcharsmax))
    {
        printf("An escalation user exists for your username, but is not valid\n");
        free(es_name);
        free(pwentchars);
        free(root_home);
        return EPERM;
    }
    else
    {
        printf("You are authorized to escalate\n");
    }

    printf("Escalation user: %s Homedir: %s ID: %d\n", user->pw_name, user->pw_dir, user->pw_uid);


    /* Part II - Talk with PAM*/
    /* Okay, so now check that they've got the right escalation password */
    pam_handle_t * pamh;
    struct pam_conv conv;
    conv.conv=misc_conv;

    ret = pam_start("pam_escalate", es_name, &conv, &pamh);
    chk_pamerr(ret, pamh);
    ret = pam_authenticate(pamh, 0);
    chk_pamerr(ret, pamh);
    printf("password correct\n");
    ret = pam_acct_mgmt(pamh, 0);
    chk_pamerr(ret, pamh);
    printf("account valid\n");
    pam_end(pamh, ret);

    free(es_name);
    free(pwentchars);
    free(root_home);

    return 0;
}

void chk_pamerr(int chk, pam_handle_t * pamh)
{
    if(chk != PAM_SUCCESS)
    {
        printf("%s\n", pam_strerror(pamh, chk));
        pam_end(pamh, chk);
        exit(-1);
    }
}
