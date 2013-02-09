/**********************************************************************
| pam_escalate
| Version 0.9-rc1
| 
| A PAM to use separate escalation credentials
| 
| This is an old unmaintained project
| 
| Author: D J Capelis
| Contact: mail@capelis.dj
| 
**********************************************************************/

#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>
#include<pwd.h>
#include<errno.h>

#include<pam_appl.h>

#define PAM_SM_AUTH
#include<pam_modules.h>

void chk_pamerr(int chk, pam_handle_t * pamh, void * free0, void * free1, void * free2);
void chk_err(void * check, void * free0, void * free1, void * free2);

#define BUF 1024

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * apph, int flags, int argc, const char ** argv)
{
    /* Part I - Initial checks */
    struct passwd * user;
    struct passwd pwent;
    char * pwentchars;
    char * es_name;
    char * root_home;
    char * uname;
    int uid;
    int ret;
    int pwentcharsmax = sysconf(_SC_GETPW_R_SIZE_MAX);
    struct pam_conv * conv;
    int i;
    int proxy = 0;
    int own_substack = 0;

    for(i=0; i<argc;++i)
    {
        if(!strncmp(argv[i], "proxy", 6))
            proxy = 1;
        if(!strncmp(argv[i], "own_substack", 13))
            own_substack = 1;
    }

    es_name = calloc(1, pwentcharsmax+5);
    chk_err(es_name, NULL, NULL, NULL);
    if(es_name == NULL)
        return PAM_AUTH_ERR;
    pwentchars = calloc(1, pwentcharsmax);
    chk_err(pwentchars, es_name, NULL, NULL);
    if(pwentchars == NULL)
        return PAM_AUTH_ERR;
    root_home = calloc(1, pwentcharsmax);
    chk_err(root_home, es_name, pwentchars, NULL);
    if(root_home == NULL)
        return PAM_AUTH_ERR;
    errno = 0;

    ret = pam_get_item(apph, PAM_USER, (void*) &uname);
    chk_pamerr(ret, NULL, es_name, pwentchars, root_home);
    if(ret != PAM_SUCCESS)
        return PAM_AUTH_ERR;

    ret = getpwnam_r(uname, &pwent, pwentchars, pwentcharsmax, &user);

    if(getuid() == 0 && user->pw_uid == 0)
    {
        //You are already what you seek to become.  Just use your hands.
        free(es_name);
        free(pwentchars);
        free(root_home);
        return PAM_SUCCESS;
    }
    if(getuid() == 0)
    {
        uid = user->pw_uid;
    }
    else
    {
        uid = getuid();
    }

    ret = getpwuid_r(0, &pwent, pwentchars, pwentcharsmax, &user);
    strncpy(root_home, user->pw_dir, pwentcharsmax);

    ret = getpwuid_r(uid, &pwent, pwentchars, pwentcharsmax, &user);
    //printf("User: %s Homedir: %s ID: %d\n", user->pw_name, user->pw_dir, user->pw_uid);

    strncpy(es_name, user->pw_name, pwentcharsmax);
    strncat(es_name, "_root", pwentcharsmax+5);

    //printf("Checking for valid escalation user %s...\n", es_name);
    ret = getpwnam_r(es_name, &pwent, pwentchars, pwentcharsmax, &user);
    if(ret == 0 && user == NULL)
    {
        //printf("You are not authorized to escalate\n");
        free(es_name);
        free(pwentchars);
        free(root_home);
        return PAM_AUTH_ERR;
    }
    /* If user's still null after the return from above, an actual error happened */
    chk_err(user, es_name, pwentchars, root_home);
    if(user == NULL)
        return PAM_AUTH_ERR;
    if(strncmp(user->pw_dir, root_home, pwentcharsmax))
    {
        //printf("An escalation user exists for your username, but is not valid\n");
        free(es_name);
        free(pwentchars);
        free(root_home);
        return PAM_AUTH_ERR;
    }

    //printf("Escalation user: %s Homedir: %s ID: %d\n", user->pw_name, user->pw_dir, user->pw_uid);

    /* Okay, so now check that they've got the right escalation password */
    if(proxy)
    {
        pam_handle_t * pamh;
        //Reuse the same memory we already allocated and manage for root_home, except under a clearer name
        char * service = root_home;

        strncpy(service, "pam_escalate", pwentcharsmax);
        if(own_substack)
        {
            char * srvname;

            ret = pam_get_item(apph, PAM_SERVICE, (void *) &srvname);
            chk_pamerr(ret, NULL, es_name, pwentchars, root_home);
            if(ret != PAM_SUCCESS)
                return ret;
            strncat(service, "_", 1);
            strncat(service, srvname, pwentcharsmax - 1 - 12 - 1); //room for null, "_" and "pam_escalate"
        }
        ret = pam_get_item(apph, PAM_CONV, (void *) &conv);
        chk_pamerr(ret, NULL, es_name, pwentchars, root_home);
        if(ret != PAM_SUCCESS)
            return ret;
        ret = pam_start(service, es_name, conv, &pamh);
        chk_pamerr(ret, pamh, es_name, pwentchars, root_home);
        if(ret != PAM_SUCCESS)
            return ret;
        ret = pam_authenticate(pamh, flags);
        chk_pamerr(ret, pamh, es_name, pwentchars, root_home);
        if(ret != PAM_SUCCESS)
            return ret;
        ret = pam_acct_mgmt(pamh, flags);
        chk_pamerr(ret, pamh, es_name, pwentchars, root_home);
        if(ret != PAM_SUCCESS)
            return ret;
        pam_end(pamh, ret);

        free(es_name);
        free(pwentchars);
        free(root_home);

        return PAM_SUCCESS;
    }
    ret = pam_set_item(apph, PAM_USER, es_name);
    chk_pamerr(ret, NULL, es_name, pwentchars, root_home);
    if(ret != PAM_SUCCESS)
        return ret;

    free(es_name);
    free(pwentchars);
    free(root_home);

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(__attribute__ ((unused)) pam_handle_t * apph, __attribute__ ((unused)) int flags, __attribute__ ((unused)) int argc, __attribute__ ((unused)) const char ** argv)
{
    return PAM_SUCCESS;
}

void chk_pamerr(int chk, pam_handle_t * pamh, void * free0, void * free1, void * free2)
{
    if(chk != PAM_SUCCESS)
    {
        //printf("%s\n", pam_strerror(pamh, chk));
        free(free0);
        free(free1);
        free(free2);
        if(pamh)
            pam_end(pamh, chk);
    }
}

void chk_err(void * check, void * free0, void * free1, void * free2)
{
    if(check == NULL)
    {
        //perror("An error has occurred");
        if(free0)
            free(free0);
        if(free1)
            free(free1);
        if(free2)
            free(free2);
    }
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_escalate_modstruct = {
    "pam_escalate",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};

#endif
