#ifndef _REQUESTS_
#define _REQUESTS_

char *compute_get_request(char *host, char *url, char *url_params, char *cookie,
	char *auth_header);
char *compute_post_request(char *host, char *url, char *form_data, char *cookie,
	char *type, char *auth_header);

#endif