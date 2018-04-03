#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h> 
 
#define FAIL    -1
 
int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;
 
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
 
SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  
    SSL_load_error_strings();   
    method = TLSv1_2_client_method();  
    ctx = SSL_CTX_new(method);   
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); 
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       
        X509_free(cert);     
    }
    else
        printf("Info: No client certificates configured.\n");
}
 
void *ReciveData(void* sslPoint)
{
	SSL *ssl ;
	ssl =(SSL *)sslPoint;
    	int bytes;
	char buf[2048];
	while(1)
    	{
		bytes = SSL_read(ssl, buf, sizeof(buf)); 
		if(bytes>0){       	
			buf[bytes] = 0;
			printf("%s\n", buf);
		}
		
		
	}
    	return 0;
}

int main(int count, char *strings[])
{   

SSL_CTX *ctx;
    int server;
    SSL *ssl;
    
 char acClientRequest[1024];
    char *hostname, *portnum;
 
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }

    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];
 	const char *exit = "/EXIT"; 
    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
	
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {  
	pthread_t sniffer_thread;
       
         
        if( pthread_create( &sniffer_thread , NULL ,  ReciveData , (void*) ssl) < 0)
        {
            perror("could not create thread");
            return 1;
        }
 
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
	while(1){
		if( fgets(acClientRequest, sizeof(acClientRequest), stdin)){
			if (1 == sscanf(acClientRequest, "%[^\n]%*c")) {
        			SSL_write(ssl,acClientRequest, strlen(acClientRequest));   /* encrypt & send message */
				if(strcmp(acClientRequest,exit) == 0)
					break;
			}
		}
	}
        
               /* release connection state */
    }
	SSL_free(ssl); 
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}


/*#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
 
void *ReciveData(void *);

int main(int argc , char *argv[])
{
    int sock;
    struct sockaddr_in server;
    char message[1024];
     
    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
     
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );
 
    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }
     
    puts("Connected\n");
     
    //keep communicating with server
    while(1)
    {
        scanf("%s" , message);
         
	pthread_t sniffer_thread;
       
         
        if( pthread_create( &sniffer_thread , NULL ,  ReciveData , (void*) &sock) < 0)
        {
            perror("could not create thread");
            return 1;
        }

        //Send some data
        if( send(sock , message , strlen(message) , 0) < 0)
        {
            puts("Send failed");
            return 1;
        }
        
        
    }
    
    close(sock);
    return 0;
}

void *ReciveData(void *socket_desc)
{
	
	char server_reply[2048];
	while(1)
    	{
		if( recv(*(int*)socket_desc, server_reply , 2048 , 0) < 0)
		{
		    puts("recv failed");
		    break;
		}
		puts("Server reply :");
		puts(server_reply);
	}
 	close(*(int*)socket_desc);
    	return 0;
}*/
