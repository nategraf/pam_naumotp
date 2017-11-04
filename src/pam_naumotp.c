/************************************************************************************
 * file:        pam_hamc.c
 * author:      nate graf based on the work of ben servoz
 * description: PAM module to provide HMAC challenge response based symetric key auth
************************************************************************************/
#define PAM_SM_AUTH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <openssl/hmac.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

// Number of bytes in the challenge
#define CHAL_LEN 8
#define SECRET_PATH_FORMAT "/home/%s/.naumotp_secret"

void bytes_to_hex( unsigned char *data, unsigned int len, char *buf ) {
    int i ;

    for (i = 0; i < len; i++) {
        sprintf(buf + i*2, "%02x", data[i]) ;
    }

    buf[len] = '\0' ;
}

char* read_secret(const char *username) {
    size_t path_len = strlen(username) + strlen(SECRET_PATH_FORMAT) ;
    char *path = (char*) malloc(sizeof(char)*path_len) ;
    snprintf(path, path_len, SECRET_PATH_FORMAT, username) ;

    FILE *fp = fopen(path, "r") ;
    free(path) ;

    if (fp != NULL){
        fseek(fp, 0L, SEEK_END) ;
        size_t sz = ftell(fp) ;
        rewind(fp) ;

        char *secret = malloc(sizeof(char)*sz + 1) ;
        size_t rdsz = fread(secret, sizeof(char), sz, fp) ;
        secret[rdsz] = '\0' ;

        fclose(fp) ;
        return secret ;
    }
    else {
        return NULL ;
    }
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
        return PAM_SUCCESS ;
}

/* this function is ripped from pam_unix/support.c, it lets us do IO via PAM */
int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response ) {
        int retval ;
        struct pam_conv *conv ;

        retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ;
        if( retval==PAM_SUCCESS ) {
                retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr ) ;
        }

        return retval ;
}


/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
        int retval ;
        int i ;
        int debug = 0;

        /* Process args. Looking for "debug" */
        for (i = 0; i < argc; i++) {
            const char *arg = argv[i];
            if( strncmp("debug", arg, 5) == 0 ) {
                debug = 1 ;
                setlogmask( LOG_UPTO (LOG_DEBUG) ) ;
                openlog( "pam_naumotp", LOG_PERROR, LOG_AUTH ) ;
            }
        }

        /* these guys will be used by converse() */
        char *input ;
        struct pam_message msg[1], *pmsg[1] ;
        struct pam_response *resp ;

        if (debug) syslog( LOG_DEBUG, "starting hmac challenge response authentication" ) ;

        /* getting the username that was used in the previous authentication */
        const char *username ;
            if((retval = pam_get_user(pamh, &username, "login: ")) != PAM_SUCCESS) {
                if (debug) {syslog( LOG_DEBUG, "FAIL: failed to retrieve username" ) ; closelog() ;}
                return retval ;
        }

        if (debug) syslog( LOG_DEBUG, "processing code for user '%s'", username ) ;

        /* generating a random one-time challenge */
        char chal_str[CHAL_LEN*2+1] ;
          unsigned char chal[CHAL_LEN] ;

        FILE *urandom = fopen( "/dev/urandom", "r" ) ;
        fread( &chal, CHAL_LEN, 1, urandom ) ;
        fclose( urandom ) ;

        bytes_to_hex(chal, CHAL_LEN, chal_str) ;

        if (debug) syslog( LOG_DEBUG, "generated challenge '%s'", chal_str ) ;

        /* get the secret from file */
        char *secret = read_secret(username) ;
        if (secret == NULL) {
            if (debug) {syslog( LOG_DEBUG, "FAIL: failed to read secret file") ; closelog() ;}
            return PAM_AUTH_ERR ;
        }
        if (debug) syslog( LOG_DEBUG, "read from file secret '%s'", secret) ;

        /* calculate the answer */
        unsigned char ans[EVP_MAX_MD_SIZE] ;
        unsigned char ans_str[EVP_MAX_MD_SIZE*2 +1] ;
        unsigned int ans_len ;
        HMAC( EVP_sha256(), secret, strlen(secret), chal, CHAL_LEN, ans, &ans_len ) ;
        free(secret) ;
        bytes_to_hex(ans, ans_len, ans_str) ;

        if (debug) syslog( LOG_DEBUG, "calculated answer '%s'", ans_str ) ;

        /* setting up conversation call prompting for one-time chal */
        char prompt[23 + CHAL_LEN*2 + 1] ;
        pmsg[0] = &msg[0] ;
        msg[0].msg_style = PAM_PROMPT_ECHO_ON ;
        msg[0].msg = prompt ;
        snprintf(prompt, 23 + CHAL_LEN*2 + 1, "challenge [%s]\nresponse: ", chal_str) ;

        resp = NULL ;
        if((retval = converse(pamh, 1, pmsg, &resp)) != PAM_SUCCESS) {
                // if this function fails, make sure that ChallengeResponseAuthentication in sshd_config is set to yes
                if (debug) {syslog( LOG_DEBUG, "FAIL: could not converse with the user" ) ; closelog() ;}
                return retval ;
        }


        /* retrieving user input */
        if( resp ) {
                if( (flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL ) {
                            free( resp );
                        if (debug) {syslog( LOG_DEBUG, "FAIL: user response is NULL" ) ; closelog() ;}
                            return PAM_AUTH_ERR;
                }
                input = resp[ 0 ].resp;
                resp[ 0 ].resp = NULL;
            } else {
                if (debug) {syslog( LOG_DEBUG, "FAIL: conversation error" ) ; closelog() ;}
                return PAM_CONV_ERR;
        }

        if (debug) syslog( LOG_DEBUG, "user responded with '%s'", input ) ;

        /* comparing user input with known challenge */
        if(strcmp(input, ans_str) == 0) {
                /* good to go! */
                free( input ) ;
                if (debug) {syslog( LOG_DEBUG, "SUCESS: correct response" ) ; closelog() ;}
                return PAM_SUCCESS ;
        } else {
                /* wrong resp */
                free( input ) ;
                if (debug) {syslog( LOG_DEBUG, "FAIL: incorrect response" ) ; closelog() ;}
                return PAM_AUTH_ERR ;
        }

        /* we shouldn't read this point, but if we do, we might as well return something bad */
        return PAM_AUTH_ERR ;
}
