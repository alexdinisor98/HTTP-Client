#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <sys/types.h>
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "jsmn.h"
#define JSMN_HEADER

//sursa "jsoneq": github
static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

//parsare cookies in header-ul de request
char* get_cookies(char* response){

	int offset_cookie = 12;
	char* copy_response = calloc(strlen(response) , sizeof(char));
    strcpy(copy_response, response);

    char* line = strstr(copy_response, "Set-Cookie: ") + offset_cookie;
    char* copy_line = calloc(strlen(line), sizeof(char));
    strcpy(copy_line, line);
    char* cookie1 = strtok(line,"\r\n");
    strcat(cookie1, "\0");

    char* rest_line = strstr(copy_line, "Set-Cookie: ") + offset_cookie;
    char* cookie2 = strtok(rest_line, "\r\n");
    strcat(cookie2, "\0");

    char* final_cookie = calloc(strlen(cookie1) + strlen(cookie2) + 2, sizeof(char));
    strcat(final_cookie, cookie1);
    strcat(final_cookie, "; ");
    strcat(final_cookie, cookie2);

    return final_cookie;
}

char* get_ip(char* name){
	struct addrinfo hints, *result, *p;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = 0;
	hints.ai_flags = AI_CANONNAME;

	if (getaddrinfo(name, "http", &hints, &result) < 0){
		error("getaddrinfo");
	}
	struct sockaddr_in* addr;

	char *service = calloc(16, sizeof(char));

	p = result;
	if(p != NULL) {
		addr = (struct sockaddr_in*) p->ai_addr;
		service = inet_ntoa(addr->sin_addr);
	}

	freeaddrinfo(result);
	return service;
}

//parsare json pt logare cu username si password
void parse_for_log(char* string_json, int r, jsmn_parser p, jsmntok_t *t, 
	char* method, char* url, char* type, char* user, char* pass){
	int i;
  	for (i = 1; i < r; i++) {
    	if (jsoneq(string_json, &t[i], "enunt") == 0) {
      		i++;
    	} else if (jsoneq(string_json, &t[i], "url") == 0) {
    		snprintf(url, t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
      		i++;
    	} else if (jsoneq(string_json, &t[i], "method") == 0) {
    		snprintf(method, t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
      		i++;
    	} else if (jsoneq(string_json, &t[i], "type") == 0) {
    		snprintf(type, t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
      		i++;
    	}else if (jsoneq(string_json, &t[i], "username") == 0) {
    		snprintf(user, t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
      		i++; 
      	}else if (jsoneq(string_json, &t[i], "password") == 0) {
    		snprintf(pass, t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
      		i++;
      	} 
  	}
}

//parsare json pentru jwt cu token pt authorization header
void parse_for_jwt(char* string_json, int r, jsmn_parser p, jsmntok_t *t, 
	char* method, char* url, char* token, char* id){
	int i;
  	for (i = 1; i < r; i++) {
    	if (jsoneq(string_json, &t[i], "enunt") == 0) {
      		i++;
    	} else if (jsoneq(string_json, &t[i], "url") == 0) {
    		snprintf(url, t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
      		i++;
    	} else if (jsoneq(string_json, &t[i], "method") == 0) {
    		snprintf(method, t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
      		i++;
    	} else if (jsoneq(string_json, &t[i], "token") == 0) {
    		snprintf(token, t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
      		i++;
      	}else if (jsoneq(string_json, &t[i], "id") == 0) {
    		snprintf(id, t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
      		i++; 
      	}
  	}
}

//parsare json pentru starea vremii
void parse_for_weather(char* string_json, int r, jsmn_parser p, jsmntok_t *t, 
	char** methods, char** urls, char* type, char* q, char* appid){
	int i;
	int cnt_methods = 0;
  	int cnt_urls = 0;
  	for (i = 1; i < r; i++) {
    	if (jsoneq(string_json, &t[i], "enunt") == 0) {
      		i++;
    	} else if (jsoneq(string_json, &t[i], "url") == 0) {
    		snprintf(urls[cnt_urls], 
    			t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
    		cnt_urls++;
      		i++;

    	} else if (jsoneq(string_json, &t[i], "method") == 0) {
    		snprintf(methods[cnt_methods], 
    			t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
    		cnt_methods++;
      		i++;

    	} else if (jsoneq(string_json, &t[i], "type") == 0) {
    		snprintf(type, t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
      		i++;
      	}else if (jsoneq(string_json, &t[i], "q") == 0) {
    		snprintf(q, t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
      		i++; 
      	}else if (jsoneq(string_json, &t[i], "APPID") == 0) {
    		snprintf(appid, t[i + 1].end - t[i + 1].start + 1, "%s", string_json + t[i + 1].start);
      		i++; 
      	}
  	}
}

int main(int argc, char *argv[]) {
    char *message;
    char *response;
    int sockfd;
    char* ip_server = "185.118.200.35";

    //TASK 1
    sockfd = open_connection(ip_server, 8081, AF_INET, SOCK_STREAM, 0);
    message = compute_get_request(ip_server, "/task1/start", NULL, NULL, NULL);
    printf("______________________ TASK 1 ___________________________\n");
    printf("%s\n", message);
    
    send_to_server(sockfd, message);
    
    response = receive_from_server(sockfd);
    printf("%s\n", response);
    close_connection(sockfd);

    // TASK 2
    char* final_cookie;
    char *string;
    char *string_json;
  	int r;
  	jsmn_parser p;
  	jsmntok_t t[128];
  	char method[100];
  	char url[100];
  	char type[100];
  	char user[100];
  	char pass[100];

  	final_cookie = get_cookies(response);

  	//string json din response cautat dupa new line-uri
    string = strstr(response, "\r\n\r\n");
   	string_json = string + 4;

   	jsmn_init(&p);
  	r = jsmn_parse(&p, string_json, strlen(string_json), t,
                 sizeof(t) / sizeof(t[0]));
  	//verificare erori
  	if (r < 0) {
    	printf("Failed to parse JSON: %d\n", r);
    	return 1;
  	}
  	if (r < 1 || t[0].type != JSMN_OBJECT) {
    	printf("Object expected\n");
    	return 1;
  	}

  	parse_for_log(string_json, r, p, t, method, url, type, user, pass);

  	//concatenare credentiale de login in string-ul "log"
  	int len = strlen("username=") + strlen(user) + strlen("&password=") + strlen(pass);
	char *log = calloc(len , sizeof(char));
	strcat(log, "username=");
	strcat(log,user);
	strcat(log, "&password=");
	strcat(log, pass);

    sockfd = open_connection(ip_server, 8081, AF_INET, SOCK_STREAM, 0);
    if(strcmp(method, "POST") == 0)
    	message = compute_post_request(ip_server, url, log, final_cookie, type, NULL);
    printf("______________________ TASK 2 ___________________________\n");
    printf("%s\n", message);
    send_to_server(sockfd, message);
    
    response = receive_from_server(sockfd);
    printf("%s\n", response);
    
    close_connection(sockfd);

	//TASK 3
	final_cookie = get_cookies(response);
	char token[1000];
	char id[100];

	string = strstr(response, "\r\n\r\n");
	string_json = string + 4;

	jsmn_init(&p);
  	r = jsmn_parse(&p, string_json, strlen(string_json), t,
				sizeof(t) / sizeof(t[0]));
	if (r < 0) {
    	printf("Failed to parse JSON: %d\n", r);
    	return 1;
  	}
  	if (r < 1 || t[0].type != JSMN_OBJECT) {
    	printf("Object expected\n");
    	return 1;
  	}

	parse_for_jwt(string_json, r, p, t, method, url, token, id);

	//concatenare raspunsuri si id din json
  	len = 100;
  	char* answer = calloc(len, sizeof(char));
  	strcat(answer,"raspuns1=omul&raspuns2=numele&id=");
  	strcat(answer,id);

  	sockfd = open_connection(ip_server, 8081, AF_INET, SOCK_STREAM, 0);
  	if(strcmp(method, "GET") == 0)
    	message = compute_get_request(ip_server, url, answer, final_cookie, token);
    printf("______________________ TASK 3 ___________________________\n");
    printf("%s\n", message);
    send_to_server(sockfd, message);
    
    response = receive_from_server(sockfd);
    printf("%s\n", response);
    
    close_connection(sockfd);

    // TASK 4
    final_cookie = get_cookies(response);

    string = strstr(response, "\r\n\r\n");
   	string_json = string + 4;

   	jsmn_init(&p);
  	r = jsmn_parse(&p, string_json, strlen(string_json), t,
                 sizeof(t) / sizeof(t[0]));
  	if (r < 0) {
    	printf("Failed to parse JSON: %d\n", r);
    	return 1;
  	}
  	if (r < 1 || t[0].type != JSMN_OBJECT) {
    	printf("Object expected\n");
    	return 1;
  	}

	parse_for_jwt(string_json, r, p, t, method, url, token, id);

  	sockfd = open_connection(ip_server, 8081, AF_INET, SOCK_STREAM, 0);
  	if(strcmp(method, "GET") == 0)
    	message = compute_get_request(ip_server, url, NULL, final_cookie, token);
    printf("______________________ TASK 4 ___________________________\n");
    printf("%s\n", message);
    send_to_server(sockfd, message);
    
    response = receive_from_server(sockfd);
    printf("%s\n", response);
    
    close_connection(sockfd);

    //TASK 5.0
    char method1[100];
  	char method2[100];
  	char url1[100];
  	char url2[100];
  	char **urls = calloc(2, sizeof(char *));
  	for (int i = 0; i < 2; i++)
    	urls[i] = calloc(100, sizeof(char));
  	
  	char **methods = calloc(2, sizeof(char *));
  	for (int i = 0; i < 2; i++)
    	methods[i] = calloc(100, sizeof(char));
  	
  	char q[100];
  	char appid[100];

    final_cookie = get_cookies(response);

    string = strstr(response, "\r\n\r\n");
   	string_json = string + 4;

   	jsmn_init(&p);
  	r = jsmn_parse(&p, string_json, strlen(string_json), t,
                 sizeof(t) / sizeof(t[0]));
  	if (r < 0) {
    	printf("Failed to parse JSON: %d\n", r);
    	return 1;
  	}
  	if (r < 1 || t[0].type != JSMN_OBJECT) {
    	printf("Object expected\n");
    	return 1;
  	}

	parse_for_weather(string_json, r, p, t, methods, urls, type, q, appid);

  	strcpy(url1, urls[0]);
  	strcpy(url2, urls[1]);

  	strcpy(method1, methods[0]);
  	strcpy(method2, methods[1]);

  	//concatenare starea vremii si request pe url-ul de vreme
	char *weather = calloc(strlen("q=") + strlen(q) + strlen("&APPID=") + strlen(appid), sizeof(char));
	strcat(weather, "q=");
	strcat(weather, q);
	strcat(weather, "&APPID=");
	strcat(weather, appid);

	char* request_url = strstr(url2, "/");

	char name_domain[23];
	memcpy(name_domain, &url2[0], 22);
	name_domain[23] = '\0';
	char* ip_weather = get_ip(name_domain);
	
  	sockfd = open_connection(ip_weather, 80, AF_INET, SOCK_STREAM, 0);
  	if(strcmp(method2, "GET") == 0)
    	message = compute_get_request(ip_weather, request_url, weather, final_cookie, token);
    printf("______________________ TASK 5.0 ___________________________\n");
    printf("%s\n", message);
    send_to_server(sockfd, message);
    
    response = receive_from_server(sockfd);
    printf("%s\n", response);
    
    close_connection(sockfd);

    // TASK 5.1
    //trimitere raspuns in fromat json catre server
	char* weather_forecast = strstr(response,"\r\n\r\n");

    sockfd = open_connection(ip_server, 8081, AF_INET, SOCK_STREAM, 0);
    if(strcmp(method1, "POST") == 0)
    	message = compute_post_request(ip_server, url1, weather_forecast
    		, final_cookie, type, token);
    printf("______________________ TASK 5.1 ___________________________\n");
    printf("%s\n", message);
    send_to_server(sockfd, message);
    
    response = receive_from_server(sockfd);
    printf("%s\n", response);
    
    close_connection(sockfd);

    free(message);
    return 0;
}