#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h> 
#include <pthread.h>
#include <sys/stat.h>
#include <stdbool.h>

#define SERVER_PORT 8888
#define MSG_BUFFER_SIZE 4096

#define LOGIN "log"
#define REGISTER "reg"
#define CHAT "cha"
#define SIZEOF_ACTION sizeof(LOGIN)

#define OK "ok"
#define FAILED "fa"
#define SIZEOF_RESPONSE sizeof(OK)

#define AES_KEY "e5d0b7a946f90680"
#define AES_IV "0000000000000000"

#define TO_ALL "all"
#define MSG_TO_SEPARATOR '>'

char client_username[20];

int connect_to_server() {
    //create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Socket creation failed.");
        exit(0);
    }

    //configuring server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (connect(sock, (struct sockaddr*)& server_addr, sizeof(server_addr)) < 0) {
        printf("Error while connecting to server.");
        exit(-1);
    }

    return sock;
}

void disconnect_from_server(int sock) {
    close(sock);
}

void create_dir(char* dir) {
    struct stat st = {0};
    if (stat(dir, &st) == -1) {
        mkdir(dir, 0700);
    }
}

void sign_message(char* message_filename) {
    char command[1000];
    sprintf(command, "/bin/bash -c 'openssl dgst -sha256 -sign ./%s/privatekey.pem -out ./%s/data.txt.signature %s 2>/dev/null'",client_username, client_username, message_filename);
    system(command);
}

void verify_singature(char* sender, char* message_filename) {
    char command[1000];
    sprintf(command, "/bin/bash -c 'openssl dgst -sha256 -verify ./%s/publickey.pem -signature ./%s/data.txt.signature %s >/dev/null 2>/dev/null'", sender, sender, message_filename);
    int status = system(command);

    if(status == 1) {
        printf("[Warning] Signature verification failed\n");
    }   
}

char* encrypt(char* plaintext, char* to) {
    char encryptCommand[600], pt_filename[200], cy_filename[200], temp_filename[200];

    create_dir(client_username);
    sprintf(pt_filename,"./%s/plaintext.txt",client_username);
    sprintf(cy_filename,"./%s/cypher.txt",client_username);
    sprintf(temp_filename,"./%s/temp.txt",client_username);
    
    //writing plaintext to file
    char echoCommand[300];
    sprintf(echoCommand, "echo '%s' > %s", plaintext, pt_filename);
    system(echoCommand);

    //encrypting
    if (strcmp(to, TO_ALL) == 0) {
        //DES encryption for group messages
        //printf("des\n");
        sprintf(encryptCommand, "/bin/bash -c 'openssl enc -des-cbc -in %s -out %s -nosalt -iv %s -K %s -a 2>/dev/null'", pt_filename, cy_filename, AES_IV, AES_KEY);
        system(encryptCommand);
    } else {
        //RSA encryption for direct messages
        //printf("rsa\n");
        sprintf(encryptCommand, "/bin/bash -c 'openssl rsautl -encrypt -in %s -out %s -pubin -inkey ./%s/publickey.pem 2>/dev/null'", pt_filename, cy_filename, to);
        system(encryptCommand);

        // sprintf(encryptCommand, "xxd -ps %s > %s",temp_filename, cy_filename);
        // system(encryptCommand);
    }
    //printf("%s\n", encryptCommand);

    //read cypher from file
    FILE* cy_file = fopen(cy_filename,"r");
    char* cypher = malloc(MSG_BUFFER_SIZE);
    fgets(cypher, MSG_BUFFER_SIZE, cy_file);
    cypher[strcspn(cypher, "\n")] = 0;
    fclose(cy_file);

    //perform digital signature
    sign_message(cy_filename);

    //remove(pt_filename);
    //remove(cy_filename);

    return cypher;
}

char* decrypt(char* cypher, bool is_direct, char* from) {
    char decryptCommand[600], dt_filename[200], cy_filename[200];
    
    create_dir(client_username);
    sprintf(dt_filename,"./%s/decrypttext.txt",client_username);
    sprintf(cy_filename,"./%s/cypher.txt",client_username);

    //writing cypher to file
    char echoCommand[300];
    sprintf(echoCommand, "echo '%s' > %s", cypher, cy_filename);
    system(echoCommand);

    //decrypting
    if (!is_direct) {
        //using DES for group messages
        //printf("dec\n");
        sprintf(decryptCommand, "/bin/bash -c 'openssl enc -d -des-cbc -in %s -out %s -nosalt -iv %s -K %s -a 2>/dev/null'", cy_filename, dt_filename, AES_IV, AES_KEY);
        system(decryptCommand);
    } else {
        //using RSA for direct messages
        //printf("rsa\n");

        sprintf(cy_filename,"./%s/cypher.txt", from); //todo: fix this
        sprintf(decryptCommand, "/bin/bash -c 'openssl rsautl -decrypt -in %s -out %s -inkey ./%s/privatekey.pem 2>/dev/null'", cy_filename, dt_filename, client_username);
        system(decryptCommand);
    }
    //printf("%s\n %s\n", cypher, decryptCommand);


    //read cypher from file
    FILE* dt_file = fopen(dt_filename,"r");
    char* dec_text = malloc(MSG_BUFFER_SIZE);
    fgets(dec_text, MSG_BUFFER_SIZE, dt_file);
    dec_text[strcspn(dec_text, "\n")] = 0;
    fclose(dt_file);

    //remove(dt_filename);
    //remove(cy_filename);

    //verify signature
    char temp_text[MSG_BUFFER_SIZE];
    strcpy(temp_text, dec_text);
    char* sender = strtok(temp_text,":");
    verify_singature(sender, cy_filename);

    return dec_text;
}

void* listen_messages(void* sock_){
    int sock = *(int*)sock_;
    char message[MSG_BUFFER_SIZE];
    int r_size;
    while((r_size = read(sock, message, MSG_BUFFER_SIZE)) > 0) {
        if(r_size != MSG_BUFFER_SIZE) continue;
        
        //check message receipients
        char temp_msg[MSG_BUFFER_SIZE];
        strcpy(temp_msg, message);
        char* text = strtok(temp_msg,",");
        char* to = strtok(NULL,",");
        char* from = strtok(NULL,",");
        bool is_direct = (strcmp(to, TO_ALL) == 0 ? false : true);
        //printf("%s %s %s\n", text, to, from);

        char* dec_message = decrypt(text, is_direct, from);

        char* dec_text = strtok(dec_message,">");
        if(strcmp(to, TO_ALL) != 0){
            strcat(dec_text," [PRIVATE]");
        }
        printf("%s\n", dec_text); fflush(stdout);

        free(dec_message);
    }
}

void chat_room(int sock) {
    system("clear");
    printf("You are inside Top Chat room as @%s\n\n", client_username); fflush(stdout);
    write(sock, CHAT, sizeof(CHAT));

    //allocate new thread for listening messages
    pthread_t thread;
    if (pthread_create(&thread, NULL, listen_messages, (void*)&sock) < 0) {
        printf("Thread creation failed.");
        exit(0);
    } 

    char text[70], message[100];
    while(1){
        fgets(text, sizeof(text), stdin); text[strcspn(text, "\n")] = 0;

        // erasing last line and displaying formatted input
        system("tput cuu 1 && tput el");
        printf("%s (You): %s\n", client_username, text);

        if (strcmp(text, "exit") == 0) {
            disconnect_from_server(sock);
            break;
        }

        sprintf(message,"%s: %s", client_username, text);

        //check type of message
        char temp_msg[MSG_BUFFER_SIZE];
        strcpy(temp_msg, text);
        char* to = strrchr(temp_msg, MSG_TO_SEPARATOR);
        to = to ? to + 1 : TO_ALL;

        //encrypting and sending message
        char* enc_message = encrypt(message, to);
        strcat(enc_message, ",");
        strcat(enc_message, to);
        strcat(enc_message,",");
        strcat(enc_message,client_username);

        //printf("%s\n",enc_message);
        write(sock, enc_message, MSG_BUFFER_SIZE);
        
        free(enc_message);
    }
}

void generateRSAKeys(char* username) {
    char command[200];
    create_dir(username);

    //generating private key
    sprintf(command, "openssl genrsa -out ./%s/privatekey.pem 2048", username);
    system(command);

    //generating public key
    sprintf(command, "openssl rsa -in ./%s/privatekey.pem -outform PEM -pubout -out ./%s/publickey.pem", username, username);
    system(command);
}

int menu(int sock) {
    printf("\n\nWelcome to TopChat!\n");
    printf("1. Login\n");
    printf("2. Register\n");
    printf("3. Exit\n");
	int choice;
	scanf("%d",&choice);getchar();

    if(choice == 1){
        char username[20], password[20];
		printf("Enter Username: ");
		fgets(username, sizeof(username), stdin); username[strcspn(username, "\n")] = 0;
        printf("Enter Password: ");
        fgets(password, sizeof(password), stdin); password[strcspn(password, "\n")] = 0;

        write(sock, LOGIN, sizeof(LOGIN));
        write(sock, username, sizeof(username));
        write(sock, password, sizeof(password));

        char response[10];
        int r_size = read(sock, response, SIZEOF_RESPONSE);
        response[r_size] = '\0';

        if(strcmp(response, OK) == 0){
            printf("Login sucessfull.\n");
            strcpy(client_username, username);
            return 1;
        }else {
            printf("Invalid username/password\n");
            return 0;
        }
        fflush(stdout);
    }else if(choice == 2){
        char name[20], username[20], password[20];
		printf("Enter Name: ");
		fgets(name, sizeof(name), stdin); name[strcspn(name, "\n")] = 0;
		printf("Enter Username: ");
		fgets(username, sizeof(username), stdin); username[strcspn(username, "\n")] = 0;
        printf("Enter Password: ");
        fgets(password, sizeof(password), stdin); password[strcspn(password, "\n")] = 0;

        write(sock, REGISTER, sizeof(REGISTER));
        write(sock, name, sizeof(name));
        write(sock, username, sizeof(username));
        write(sock, password, sizeof(password));
        
        char response[10];
        int r_size = read(sock, response, SIZEOF_RESPONSE);
        response[r_size] = '\0';

        if(strcmp(response, OK) == 0){
            printf("Registration sucessfull.\n");
            strcpy(client_username, username);
            generateRSAKeys(username);
            return 1;
        }else {
            printf("Username might already exists, please try changing it.\n");
            return 0;
        }
        fflush(stdout);
    }else{
        disconnect_from_server(sock);
        exit(0);
    }
}

int main() {
    int sock = connect_to_server();
    while(!menu(sock)){}
    chat_room(sock);

    printf("Bye! see you later.\n");
}