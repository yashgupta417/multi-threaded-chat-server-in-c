#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <signal.h>

#define SERVER_PORT 8888
#define BUFFER_SIZE 4096
#define MAX_CONNECTIONS 10

#define LOGIN "log"
#define REGISTER "reg"
#define CHAT "cha"
#define SIZEOF_ACTION sizeof(LOGIN)

#define OK "ok"
#define FAILED "fa"
#define SIZEOF_RESPONSE sizeof(OK)

#define MSG_BUFFER_SIZE 4096

void* client_handler(void*);
void login_handler(int);
void register_handler(int);
void chat_handler(int);

int client_sockets[10];
int sock_count = 0;

void run_server() {
    int server_socket, client_socket, addr_size = sizeof(struct sockaddr_in);
    struct sockaddr_in server_addr, client_addr;

    //create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        printf("Socket creation failed.");
        exit(0);
    }

    //initialize the address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    //bind
    if (bind(server_socket, (struct sockaddr*)&server_addr , sizeof(server_addr)) < 0) {
        printf("Bind failed.");
        exit(0);
    }

    //listen
    if (listen(server_socket, MAX_CONNECTIONS < 0)) {
        printf("Listen failed.");
        exit(0);
    }
    printf("Chat Server running at port: %d\n", SERVER_PORT); fflush(stdout);

    while(1){
        //accept connection
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, (socklen_t*)&addr_size);
        printf("New client connected!\n"); fflush(stdout);
        
        //add socket to list
        client_sockets[sock_count++] = client_socket;

        //allocate new thread for the connection
        pthread_t thread;
        if (pthread_create(&thread, NULL, client_handler, (void*)&client_socket) < 0) {
            printf("Thread creation failed.");
            exit(0);
        } 
    }

    close(server_socket);
}

void* client_handler(void* client_socket) {
    int socket = *(int*) client_socket;

    char request[20];
    int r_size;

    while((r_size = read(socket, request, SIZEOF_ACTION)) > 0){
        //printf("r_size: %d\n",r_size);
        request[r_size] = '\0';
        if (strcmp(request, LOGIN) == 0){
            login_handler(socket);   
        } else if (strcmp(request, REGISTER) == 0) {
            register_handler(socket);
        } else if (strcmp(request, CHAT) == 0) {
            chat_handler(socket);
        }
    }
    return 0; 
}

void chat_handler(int socket) {
    char message[MSG_BUFFER_SIZE];
    int r_size;
    while((r_size = read(socket, message, MSG_BUFFER_SIZE)) > 0) {
        printf("New message recieved!\n"); fflush(stdout);
        for(int i=0;i<sock_count;i++){
            if(client_sockets[i] == socket) continue;
            //printf("sending message to socket %d\n",client_sockets[i]); fflush(stdout);
            write(client_sockets[i], message, MSG_BUFFER_SIZE);   
        }
    }
    //printf("done handling chats\n"); fflush(stdout);
}

struct User{
    char name[20];
    char pass[20];
};

struct User* get_user_data(char* username) {
    FILE *fptr;
    char filename[256];
    sprintf(filename,"./users/%s.txt",username);
    //printf("%s\n",filename); fflush(stdout);

    if (access(filename, F_OK) != 0) {
        return NULL;
    }

    if ((fptr = fopen(filename,"r")) == NULL){
        printf("Error while opening file. %s\n", filename); fflush(stdout);
        return NULL;
    }

    char user_data[256];
    fgets(user_data, sizeof(user_data), fptr);
    fclose(fptr);
    //printf("%s\n", user_data); fflush(stdout);
    struct User* user = malloc(sizeof(struct User));
    strcpy(user->name, strtok(user_data,","));
    strcpy(user->pass, strtok(NULL,","));
    //printf("data: %s %s\n", user->name, user->pass); fflush(stdout);
    return user;
}

void login_handler(int socket){
    char username[20], password[20];
    int r_size;
    r_size = read(socket, username, sizeof(username));
    username[r_size] = '\0';
    r_size = read(socket, password, sizeof(password));
    password[r_size] = '\0';

    struct User* user = get_user_data(username);
    if (user == NULL || user->pass == NULL) {
        // printf("user is null"); fflush(stdout);
        write(socket, FAILED, sizeof(FAILED));
        return;
    }

    //printf("data: %s %s\n", user->pass, user->name); fflush(stdout);
    if (strcmp(password, user->pass) == 0) {
        write(socket, OK, sizeof(OK));
    } else {
        write(socket, FAILED, sizeof(FAILED));
    }
    free(user);
}


void register_handler(int socket) {
    char name[20], username[20], password[20];
    int r_size;
    
    r_size = read(socket, name, sizeof(name)); name[r_size] = '\0'; //printf("%d\n",r_size);
    r_size = read(socket, username, sizeof(username)); username[r_size] = '\0'; //printf("%d\n",r_size);
    r_size = read(socket, password, sizeof(password)); password[r_size] = '\0'; //printf("%d\n",r_size);
    
    //printf("%s %s %s\n",name, username, password); fflush(stdout);
    FILE *fptr;
    char filename[100];
    sprintf(filename,"./users/%s.txt",username);

    if (access(filename, F_OK) == 0) {
        write(socket, FAILED, sizeof(FAILED));
        return;
    }

    if ((fptr = fopen(filename,"w")) == NULL){
        printf("Error while opening file. %s", filename); fflush(stdout);
        write(socket, FAILED, sizeof(FAILED));
        return;
    }

    fprintf(fptr,"%s,%s", name, password);
    fclose(fptr); 
    write(socket, OK, sizeof(OK));
}

int main(){
    signal(SIGPIPE, SIG_IGN);
    run_server();
}