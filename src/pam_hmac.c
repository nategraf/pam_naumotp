/************************************************************************************
 * file:        pam_hamc.c
 * author:      nate graf based on the work of ben servoz
 * description: PAM module to provide HMAC challenge response based symetric key auth
************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

// Number of hex chars in the challenge
#define CHAL_LEN 16

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
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval ;
	int i ;
    
	/* these guys will be used by converse() */
	char *input ;
	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp;
	

	/* getting the username that was used in the previous authentication */
	const char *username ;
    	if((retval = pam_get_user(pamh, &username, "login: ")) != PAM_SUCCESS) {
		return retval ;
	}

	/* generating a random one-time chal */
	char chal[CHAL_LEN+1] ;
  	unsigned long random_number ;
	FILE *urandom = fopen( "/dev/urandom", "r" ) ;
	fread( &random_number, sizeof(random_number), 1, urandom ) ;
	fclose( urandom ) ;

	snprintf( chal, CHAL_LEN+1,"%016lx", random_number ) ;
	chal[CHAL_LEN] = '\0' ; // because it needs to be null terminated

	/* setting up conversation call prompting for one-time chal */
        char prompt[23 + CHAL_LEN + 1] ;
	pmsg[0] = &msg[0] ;
	msg[0].msg_style = PAM_PROMPT_ECHO_ON ;
        msg[0].msg = prompt ;
	snprintf(prompt, 23 + CHAL_LEN + 1, "challenge [%s]\nresponse: ", chal) ;

	resp = NULL ;
	if((retval = converse(pamh, 1, pmsg, &resp)) != PAM_SUCCESS) {
		// if this function fails, make sure that ChallengeResponseAuthentication in sshd_config is set to yes
		return retval ;
	}

	/* retrieving user input */
	if( resp ) {
		if( (flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL ) {
	    		free( resp );
	    		return PAM_AUTH_ERR;
		}
		input = resp[ 0 ].resp;
		resp[ 0 ].resp = NULL; 		  				  
    	} else {
		return PAM_CONV_ERR;
	}
	
	/* comparing user input with known chal */
	if(strcmp(input, chal) == 0) {
		/* good to go! */
		free( input ) ;
		return PAM_SUCCESS ;
	} else {
		/* wrong resp */
		free( input ) ;
		return PAM_AUTH_ERR ;
	}

	/* we shouldn't read this point, but if we do, we might as well return something bad */
	return PAM_AUTH_ERR ;
}
