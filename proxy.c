#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sched.h>
#include <fcntl.h>
#include <semaphore.h>
#include <errno.h>
#include "netdb.h"
#include "arpa/inet.h"
#include "time.h"

#define WORKER_SOCK_PATH "/tmp/worker_socket" 

int numberOfProcess;

sem_t* fileLock; 
sem_t* IpListLock;

int *lastRead; //a shared int for gertting the last readed line of logs file
char (*IpList)[16]; // share memory that maps which sokcet to ip address
char* targetAddress; //shared memory for storing the target address path



void bindToCore(int coreId){

    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);
    CPU_SET(coreId,&cpuSet);
    pid_t PID = getpid();
    
    if(sched_setaffinity(PID,sizeof(cpu_set_t),&cpuSet)){
        printf("failed to bind cpu core\n");
        return;
    }

}

int isLogFilePath(char * clientReq){
    
    char GetValue[256]={0};

    const char* pathStart = strstr(clientReq,"GET ");
    
    if(pathStart){
    
        pathStart+=4;
        
        const char* pathEnd = strstr(pathStart," ");
        
        if(pathEnd){

            size_t pathSize = pathEnd-pathStart;
            strncpy(GetValue,pathStart,pathSize);
            GetValue[pathSize]='\0';
        }
    }

    if(!strcmp(GetValue,"/.svc/collect_logs")){
        return 1;
    }
    return 0;
}


int isHostlocalhost(char* clientReq){

    char hostValue[256]={0};

    const char* hostStart = strstr(clientReq,"Host: ");
    
    if(hostStart){
    
        hostStart+=6;
        
        const char* hostEnd = strstr(hostStart,"\r\n");
        
        if(hostEnd){

            size_t hostSize = hostEnd-hostStart;
            strncpy(hostValue,hostStart,hostSize);
            hostValue[hostSize]='\0';
        }
    }

    if(!strcmp(hostValue,"localhost")){
        return 1;
    }
    return 0;
}

void logRequests(int socket,int pid){

    char ip[INET_ADDRSTRLEN];
    sem_wait(IpListLock);
    inet_ntop(AF_INET,&IpList[socket],ip,INET_ADDRSTRLEN);
    sem_post(IpListLock);
    
    sem_wait(fileLock);
    int logfile = open("log.txt",O_WRONLY | O_CREAT | O_APPEND,0644);

    if(logfile < 0){
        printf("failed to open log.txt\n");
        return;
    }

    time_t now = time(NULL);
    char logBuffer[256];
    snprintf(logBuffer,sizeof(logBuffer),"%ld  %s %d\n",now,ip,pid);
    
    if(write(logfile,logBuffer,strlen(logBuffer)) < 0){

        printf("failed to write on log file!!!\n");
        close(logfile);
        return;
    }
    sem_post(fileLock);
    close(logfile);
    return;
}

void readLog(int clientSocket){

    sem_wait(fileLock);
    FILE *logFile = fopen("log.txt","r");
    if(logFile == NULL){
        printf("could not open log file for reading\n");
        return;
    }


    char totalLog[4096];
    char line[256];
    int index = 0;

    while (fgets(line,sizeof(line),logFile)!=NULL){
    
        if(index >= *lastRead){
            printf("%s",line);
            strcat(totalLog,line);
        }
        index++;
    }

    *lastRead = index;
    char response[5100];
    snprintf(response,5100,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n"
            "%s\n",sizeof(totalLog),totalLog
    );

    if(send(clientSocket,response,strlen(response),0) == -1){
        printf("failed to send log to cloud\n");
    }
    fclose(logFile);

    sem_post(fileLock);
    return;
}

//checks if the request is for the target affress or not
int isRequestValid(char* clientReq, char* targetAddress){
    char hostValue[256]={0};

    const char* hostStart = strstr(clientReq,"Host: ");
    
    if(hostStart){
    
        hostStart+=6;
        
        const char* hostEnd = strstr(hostStart,"\r\n");
        
        if(hostEnd){
            size_t hostSize = hostEnd-hostStart;
            strncpy(hostValue,hostStart,hostSize);
            hostValue[hostSize]='\0';
        }
    }

    if(!strcmp(hostValue,targetAddress)){
        return 1;
    }
    return 0;
}

// this function reads the request from a client socket and after sending it to target address reply back the response to the client
void handleRequest(int clientSocket) {

    char request_buffer[4096], response_buffer[4096];
    
    int bytes_read = read(clientSocket, request_buffer, 4096-1);
    
    request_buffer[bytes_read] = '\0';

    logRequests(clientSocket,getpid());

    if(bytes_read == -1){
        close(clientSocket);
        return;
    }

    int localhost = isHostlocalhost(request_buffer);
    int logPath = isLogFilePath(request_buffer);

    if(localhost && logPath){
        readLog(clientSocket);
        return;
    }

    if(!isRequestValid(request_buffer,targetAddress)){
        printf("request is not valid\n");

    const char* response = 
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 100\r\n"
            "Connection: close\r\n\r\n"
            "InValid Host!\n";

    send(clientSocket,response,strlen(response),0);
    close(clientSocket);
    }
    
    int backend_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (backend_socket < 0) {
        perror("Failed to create backend socket");
        close(clientSocket);
        return;
    }

    struct sockaddr_in backend_addr;
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_port = htons(80);

    struct hostent *he = gethostbyname(targetAddress);

    memcpy(&backend_addr.sin_addr,he->h_addr_list[0],he->h_length);
    
    if (connect(backend_socket, (struct sockaddr*)&backend_addr, sizeof(backend_addr)) < 0) {
        printf("Failed to connect to backend server");
        close(clientSocket);
        close(backend_socket);
        return;
    }

    if (bytes_read > 0) {
        send(backend_socket, request_buffer, bytes_read, 0);

        while ((bytes_read = recv(backend_socket, response_buffer, sizeof(response_buffer), 0)) > 0) {
            send(clientSocket, response_buffer, bytes_read, 0);
        }
    }
}

void sendFileDescriptor(int unix_sock, int socket) {
    
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(socket))];
    memset(buf, '\0', sizeof(buf));

    struct iovec io = { .iov_base = (void*)" ", .iov_len = 1 };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(socket));

    *((int*) CMSG_DATA(cmsg)) = socket;

    if (sendmsg(unix_sock, &msg, 0) < 0) {
        perror("Failed to send file descriptor");
        exit(EXIT_FAILURE);
    }
}

int recvFileDescriptor(int unix_sock) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))];
    char dummy;
    struct iovec io = { .iov_base = &dummy, .iov_len = sizeof(dummy) };
    int fd;

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    if (recvmsg(unix_sock, &msg, 0) < 0) {
        printf("Failed to receive file descriptor");
        exit(EXIT_FAILURE);
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS) {
        fprintf(stderr, "no file descriptor received\n");
        exit(EXIT_FAILURE);
    }

    fd = *((int*) CMSG_DATA(cmsg));
    return fd;
}

void listenerProcess(int unixSock) {
    int listenSocket;
    struct sockaddr_in listen_addr;

    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0) {
        printf("Failed to create listening socket");
        exit(EXIT_FAILURE);
    }

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(80);

    if (bind(listenSocket, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        printf("Failed to bind listening socket");
        close(listenSocket);
        exit(EXIT_FAILURE);
    }

    if (listen(listenSocket, 128) < 0) {
        printf("Failed to listen on socket");
        close(listenSocket);
        exit(EXIT_FAILURE);
    }

    printf("Listening on 0.0.0.0:%d\n", 80);

    char IpAddress[INET_ADDRSTRLEN];
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int clientSocket = accept(listenSocket, (struct sockaddr*)&client_addr, &client_len);
       
        if (clientSocket < 0) {
            printf("failed to accept client connection");
            continue;
        }

        inet_ntop(AF_INET,&client_addr.sin_addr,IpAddress,INET_ADDRSTRLEN);

        sem_wait(IpListLock);
        strncpy(IpList[clientSocket],IpAddress,INET_ADDRSTRLEN);
        sem_post(IpListLock);

        sendFileDescriptor(unixSock, clientSocket);// if the accept be succesfull it adds the socket to file descriptor
        close(clientSocket);              
    }
}

void workerProcess(int unixSock) {

    printf("Worker process started (PID=%d)\n", getpid());

    while (1) {
        int clientSocket = recvFileDescriptor(unixSock); // get a made socket from the file descriptor
        if (clientSocket > 0) {
            handleRequest(clientSocket);
            close(clientSocket); 
        }
    }
}

int main(int argc, char* argv[]) {

    int numberOfCores = sysconf(_SC_NPROCESSORS_ONLN);

    numberOfProcess = numberOfCores/2; //just make process half of availble cores

    // it is assumed that the parameters are passed as --inbound 0.0.0.:80 --outbound "targetAddress" and the outbound is the last one
    if(argc !=5){
        printf("incorrect parameters are passed to programm\n");
        return 0;
    }

    char* outbound = argv[4];

    int sharedOutbound = shm_open("sharedOutbound",O_CREAT|O_RDWR,0666);
    
    if(sharedOutbound == -1){
        printf("failed to create sharedOutbound\n");
        return 0;
    }

    if(ftruncate(sharedOutbound,strlen(outbound)) == -1){
        printf("failed to set size for sharedOutbound\n");
        return 0;
    }

    targetAddress = mmap(NULL,strlen(outbound),PROT_READ|PROT_WRITE, MAP_SHARED,sharedOutbound,0);

    if(targetAddress == MAP_FAILED){
        printf("failed to create shared memory\n");
        return 0;
    }

    strncpy((char*)targetAddress,outbound,strlen(outbound));
    
    int IpListShared = shm_open("IpListShared",O_CREAT|O_RDWR,0666);
    
    if(IpListShared == -1){
        printf("failed to create IpListShared\n");
        return 0;
    }

    if(ftruncate(IpListShared,100*16*sizeof(char)) == -1){
        printf("failed to set size for IpListShared\n");
        return 0;
    }

    IpList = mmap(NULL,100 * 16 * sizeof(char),PROT_READ|PROT_WRITE, MAP_SHARED,IpListShared,0);

    if(IpList == MAP_FAILED){
        printf("failed to create shared memory\n");
        return 0;
    }


    lastRead = mmap(NULL,sizeof(int),PROT_READ|PROT_WRITE, MAP_SHARED,IpListShared,0);

    if(lastRead == MAP_FAILED){
        printf("failed to create shared memory for lastRead\n");
        return 0;
    }

    *lastRead =0; // atfirst not log has been readed !!

    fileLock = sem_open("/fileLock",O_CREAT,0666,1);
    IpListLock = sem_open("/IpListLock",O_CREAT,0666,1);

    if(fileLock == SEM_FAILED){
        printf("failed to initialize the fileLock semaphore");
    }
    if(IpListLock == SEM_FAILED){
        printf("failed to initialize the fileLock semaphore");
    }

    int unix_sock[2]; // child and parrent processes can communicate with each other
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, unix_sock) < 0) {
        printf("Failed to create Unix domain socket");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < numberOfProcess; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            close(unix_sock[0]);
            bindToCore(i);
            workerProcess(unix_sock[1]);
            exit(0);
        }
    }

    close(unix_sock[1]); 
    listenerProcess(unix_sock[0]);

    
    sem_unlink("/fileLock");
    sem_unlink("/IpListLock");

    sem_close(fileLock);
    sem_close(IpListLock);

    munmap(targetAddress,strlen(outbound));
    munmap(IpList,100*16*sizeof(char));

    close(sharedOutbound);
    close(IpListShared);
    return 0;
}