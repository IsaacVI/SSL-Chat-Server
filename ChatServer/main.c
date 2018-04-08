#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <pthread.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#define FAIL    -1

unsigned char *rootPass;

struct Client
{
	float answerTime;
	SSL *ssl;
	char *ip;
	char *name;
	char *talker;
};


int clientLenght =0;
struct Client *clients;



char* GetWord(char *str, int word)
{
	char *result;
	int currentWord=1;
	int destWord=0;
	if(word==1)
		destWord=1;
	int wordLength=0;
	int destynyWordStart=0;
	int i=0;
	while(1)
	{
		if(*(str+i)=='\0')
			break;
		
		
		if(destWord){
			if(*(str+i)==' ' || *(str+i)=='\0')
				break;
			else
				wordLength++;
		}
		else
		{
			if(*(str+i)==' ' && *(str+i+1)!=' ' && *(str+i+1)!='\0')
			{
				currentWord++;
				if(currentWord==word){
					destynyWordStart=i+1;
					destWord=1;		
					}
			}
		}
		i++;
			
	}
	
	if(destWord){
		result =malloc(sizeof(char)*(wordLength+1));
	
		memcpy( result, &str[destynyWordStart], wordLength );
		result[wordLength]='\0';
		return result;
	}
	else
		return NULL;
}

void AddClient(SSL *ssl, char ip[])
{

	
	if(clientLenght>0)
	{
		clientLenght++;
		clients = realloc(clients,sizeof(struct Client)*(clientLenght));
		(*(clients+clientLenght-1)).ssl =ssl;
		(*(clients+clientLenght-1)).talker=NULL;
		(*(clients+clientLenght-1)).ip=malloc(25);
		strcpy((*(clients+clientLenght-1)).ip, ip);
		(*(clients+clientLenght-1)).name=malloc(25);
		strcpy((*(clients+clientLenght-1)).name,"UNKNOWN");
	}
	else
	{
		
		
		clientLenght++;
		clients = malloc(sizeof(struct Client));
		(*clients).ssl =ssl;
		(*clients).talker =NULL;
		(*clients).ip=malloc(25);
		strcpy((*clients).ip, ip);
		(*clients).name=malloc(25);
		strcpy((*clients).name,"UNKNOWN");
	}
}

void  RemoveClient(int id)
{
	clientLenght--;
	if(clientLenght>0){
		struct Client *temp = malloc(sizeof(struct Client)*clientLenght);
		int i;	
		for(i=0;i<clientLenght+1;i++)
		{
			if(i==id) continue;
			if(i<id)
			{
				(*(temp+i)).ssl =(*(clients+i)).ssl;
				(*(temp+i)).talker=(*(clients+i)).talker;
				(*(temp+i)).ip=malloc(25);
				strcpy((*(temp+i)).ip, (*(clients+i)).ip);
				(*(temp+i)).name=malloc(25);
				strcpy((*(temp+i)).name,(*(clients+i)).name);
			}
			if(i>id)
			{
				(*(temp+i-1)).ssl =(*(clients+i)).ssl;
				(*(temp+i-1)).talker=(*(clients+i)).talker;
				(*(temp+i-1)).ip=malloc(25);
				strcpy((*(temp+i-1)).ip, (*(clients+i)).ip);
				(*(temp+i-1)).name=malloc(25);
				strcpy((*(temp+i-1)).name,(*(clients+i)).name);
			}
		}
		free(clients);
		clients =temp;
	}
	
	else
		clients=NULL;
	
}

int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;
 
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
 
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
 
}

SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  
    SSL_load_error_strings(); 
    method = TLSv1_2_server_method(); 
    ctx = SSL_CTX_new(method);   
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}


char *HashPass(unsigned char* pass)
{
	 SHA256_CTX context;
	 unsigned char *res =malloc(SHA256_DIGEST_LENGTH);
	 SHA256_Init(&context);
	 SHA256_Update(&context, pass, strlen(pass));
	 SHA256_Final(res, &context);
	 while(strlen(res)<SHA256_DIGEST_LENGTH)
		 strcat(res,"x");
	 return res;
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    unsigned char *line;
 
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
        printf("No certificates.\n");
}


int CheckPassword(char* login,char *pass)
{
	int i=0;
	unsigned char *hash;
	hash =HashPass(pass);
	if(strcmp(login,"root")==0)
	{
		for(i=0;i<SHA256_DIGEST_LENGTH;i++){
			if(rootPass[i]!=hash[i]){
				free(hash);
				return 0;}
			}
		free(hash);
		return 1;
	}
	char file[30]="users/";
	strcat(file,login);
	
	if( access(file, F_OK ) != -1 ) {
		FILE *fp;
		unsigned char buff[255];
		fp = fopen(file, "r");
		fscanf(fp, "%s", buff);
		fgets(buff,SHA256_DIGEST_LENGTH,fp);
		fread(buff, SHA256_DIGEST_LENGTH, 1, fp);
		
		
			for(i=0;i<SHA256_DIGEST_LENGTH;i++){
				if(buff[i]!=hash[i]){
					free(hash);
					return 0;
					
				}
			}
			free(hash);
			return 1;
				
	} else {
		free(hash);
		return 0;
	}
	return 0;
		
}


struct Client *GetClientBySSL(SSL* ssl)
{
	if(clientLenght>0)
	{
		int i;
		for(i=0;i<clientLenght;i++)
		{
			if(ssl == (*(clients+i)).ssl)
				return clients+i;
		}
	}
	return NULL;
}

struct Client *GetClientByName(char *name)
{
	if(clientLenght>0)
	{
		int i;
		for(i=0;i<clientLenght;i++)
		{
			if(strcmp(name, (*(clients+i)).name)==0)
				return clients+i;
		}
	}
	return NULL;
}

void SendTo(char* message, char* name)
{
	if(clientLenght>0)
	{
		int i;
		for(i=0;i<clientLenght;i++)
		{
			if(strcmp(name, (*(clients+i)).name)==0)
				SSL_write((*(clients+i)).ssl, message, strlen(message));
		}
	}
}

void CreatUser(char* login,char *pass)
{
	
	unsigned char *hash; 
	hash = HashPass(pass);
	char file[40] ="users/";
	strcat(file,login);
	FILE *fp;
	fp = fopen(file, "w");
	
	fputs( login,fp);
	fputs( "\n",fp);
	fputs(	hash,fp);
	fclose(fp);
	free(hash);
	
}

void HandleMessage(SSL* ssl, char *message)
{
	/////////////////////////////////////////////////////////////////////////////
	struct Client *source =  GetClientBySSL(ssl);
		
	if(source!=NULL)
	{
		source->answerTime=0;
		if(*message=='/')
			{
				
				
				char *command = GetWord(message,1);
				int used;
				
				if(strcmp(command, "/question")==0)
				{	
					char temp[25] ="/answer";
					SSL_write(ssl, temp, strlen(temp));
					return;
				}
				if(strcmp(command, "/login")==0)
				{	
					char *name =GetWord(message,2);
					char *pass =GetWord(message,3);
					if(name!=NULL && pass!=NULL){
						if(CheckPassword(name,pass)){
							strcpy((*source).name,name);
							char temp[25] ="Logged";
							SSL_write(ssl, temp, strlen(temp));
						}
						else
						{
							char temp[25] ="Wrong Pass";
							SSL_write(ssl, temp, strlen(temp));
						}
					}
					else
					{
						char temp[35] ="ERROR: /login [name] [password]";
						SSL_write(ssl, temp, strlen(temp));
					}
					used=1;
					free(name);

					free(pass);
					return;
				}
				if(strcmp((*source).name , "UNKNOWN"))
				{
					printf("%s msg: \"%s\"\n",(*source).name , message);
					if(strcmp(command, "/talk")==0)
					{	
						char *name =GetWord(message,2);
						if(name!=NULL){
								if((*source).talker==NULL)		
									(*source).talker=malloc(sizeof(char)*20);
								strcpy((*source).talker,name);
								char temp[100] ="Talking to ";
								strcat(temp,name);
								SSL_write(ssl, temp, strlen(temp));
								
						}
						else
						{
							char temp[30] ="ERROR: /talk [nameToTalk]";
							SSL_write(ssl, temp, strlen(temp));
						}
						used=1;
						free(name);
						return;
					
					}
					if(strcmp(command, "/creatuser")==0)
					{
						if(strcmp((*source).name , "root")==0){
							char *name =GetWord(message,2);
							char *pass =GetWord(message,3);
							if(pass!=NULL && name!=NULL)
							{
								CreatUser(name,pass);
								char temp[30] ="User created";
								SSL_write(ssl, temp, strlen(temp));
							}
							else
							{
								char temp[100] ="ERROR:/creatuser [login] [password]";
								SSL_write(ssl, temp, strlen(temp));
							}
							free(name);
							free(pass);
						}
						else
						{
							char temp[30] ="PERMISSION DENIED";
							SSL_write(ssl, temp, strlen(temp));
						}
					}
					if(used==0)
					{
						char temp[30] ="UNKNOW COMMAND";
						SSL_write(ssl, temp, strlen(temp));
					}
					
				}
				else
				{
					char temp[30] ="LOGIN FIRST";
					SSL_write(ssl, temp, strlen(temp));
				}
				free(command);
			}
			else
			{
				if(strcmp((*source).name , "UNKNOWN"))
				{
					if((*source).talker !=NULL)
					{
						char *temp = malloc(2048);
						strcpy(temp,(*source).name);
						strcat(temp,":");
						strcat(temp, message);
						SendTo(temp,(*source).talker);
					}
					else
					{
						char temp[] ="UNKNOW TALKER";
						SSL_write(ssl, temp, strlen(temp));
					}
				}
				else
				{
					char temp[30] ="LOGIN FIRST";
					SSL_write(ssl, temp, strlen(temp));
				}
			}
		
		
	}

	//////////////////////////////////////////////////////////////////////////////
}
 
void *Servlet(void* sslPoin) 
{   char buf[1024] = {0};
   SSL *ssl;
	ssl =(SSL *)  sslPoin;
    int sd, bytes;

    if ( SSL_accept(ssl) == FAIL )      
        ERR_print_errors_fp(stderr);
    else
    {
       
	while (1){
 		
		bytes = SSL_read(ssl, buf, sizeof(buf)); 
	 	buf[bytes] = '\0';
	 	if ( bytes > 0 )
		{
	 		
		 	HandleMessage(ssl, &buf);
			
		}
		if(bytes==0){
			struct Client *this = GetClientBySSL(ssl);
			printf("%s disconneted\n",this->ip);
			RemoveClient(this-clients);
			printf("%d\n",clientLenght);
			return;
		}
		if(bytes<0){
			struct Client *this = GetClientBySSL(ssl);
			printf("%s recive failed\n",this->ip);
			RemoveClient(this-clients);
			return;
 		}
	}
            
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}
 

int main(int count, char *Argc[])
{   
    SSL_CTX *ctx;
    int server;
    char *portnum;
 
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    
    DIR* dir = opendir("users");
    if (dir)
    {
    	closedir(dir);
    	FILE *fp;
		unsigned char buff[255];
		if( access( "users/root", F_OK ) != -1 ) {
			
			fp = fopen("users/root", "r");
			fscanf(fp, "%s", buff);
			
			fgets(buff,SHA256_DIGEST_LENGTH,fp);
			fread(buff, SHA256_DIGEST_LENGTH, 1, fp);
			rootPass = malloc(SHA256_DIGEST_LENGTH);
			strcat(rootPass,buff);
		} else {
			fp = fopen("users/root", "w+");
			rootPass = malloc(SHA256_DIGEST_LENGTH);
			rootPass = HashPass("secretpass");
			fputs( "root\n",fp);
			fputs(	rootPass,fp);
		}
		fclose(fp);
        
    }
    else if (ENOENT == errno)
    {
    	mkdir("users", 0777);
    	FILE *fp;
    	fp = fopen("users/root", "w+"); 
		rootPass = malloc(SHA256_DIGEST_LENGTH);
		rootPass = HashPass("secretpass");
		fputs( "root\n",fp);
		fputs(	rootPass,fp);
    }
    else
    {
    	printf("Cant create or load root account!!");
		exit(0);
    }
    
    
 // Initialize the SSL library
    SSL_library_init();
 
    portnum = Argc[1];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */
    while (1)
    {   
	struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
	ssl =malloc(1);
	
 	int *client ;
	client = malloc(sizeof(int));
        *client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
	int port =ntohs(addr.sin_port);
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr),port) ;
          /* set connection socket to SSL state */
	char ip[] ="";
	strcat(ip, inet_ntoa(addr.sin_addr)); 
	strcat(ip, ":");
	char temp[10]; 
	sprintf(temp, "%d", port);
	strcat(ip, temp); 	
	ssl = SSL_new(ctx);              /* get new SSL state with context */
       	SSL_set_fd(ssl, *client);
		 
	
	
	AddClient(ssl, ip);
	pthread_t sniffer_thread;
	
	printf("%d\n",clientLenght);
        if( pthread_create( &sniffer_thread , NULL ,  Servlet , (void*) ssl) < 0)
        {
            perror("could not create thread");
            return 1;
        }
		        /* service connection */
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}
/*

#include<stdio.h>
#include<string.h>    
#include<stdlib.h>    
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<unistd.h>    
#include<pthread.h> 
 
//the thread function
void *connection_handler(void *);
 
int main(int argc , char *argv[])
{
    int socket_desc , client_sock , c , *new_sock;
    struct sockaddr_in server , client;
     
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
     
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );
     
    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");
     
    //Listen
    listen(socket_desc , 3);
     
    //Accept and incoming connection
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);
    while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
    {
        puts("Connection accepted");
         
        pthread_t sniffer_thread;
        new_sock = malloc(1);
        *new_sock = client_sock;
         
        if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) new_sock) < 0)
        {
            perror("could not create thread");
            return 1;
        }
         
        //Now join the thread , so that we dont terminate before the thread
        //pthread_join( sniffer_thread , NULL);
        puts("Handler assigned");
    }
     
    if (client_sock < 0)
    {
        perror("accept failed");
        return 1;
    }
     
    return 0;
}
 

void *connection_handler(void *socket_desc)
{
    //Get the socket descriptor
    int sock = *(int*)socket_desc;
    int read_size;
    char *message , client_message[2048];


    while( (read_size = recv(sock , client_message , 2048 , 0)) > 0 )
    {
        write(sock , client_message , strlen(client_message));
	memset(client_message, 0, sizeof client_message);
    }
     
    if(read_size == 0)
    {
        puts("Client disconnected");
        fflush(stdout);
    }
    else if(read_size == -1)
    {
        perror("recv failed");
    }
       
    free(socket_desc);
     
    return 0;
}*/
