//
// Simple chat server for TSAM-409
//
// Command line: ./chat_server 4000
//
// Author: Jacky Mallett (jacky@ru.is)
//
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <algorithm>
#include <map>
#include <vector>

#include <iostream>
#include <sstream>
#include <thread>
#include <map>

#include <unistd.h>

// fix SOCK_NONBLOCK for OSX
#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#define BACKLOG 5 // Allowed length of queue of waiting connections
#define PORT 4002
#define GROUP "V_Group_96"

// Simple class for handling connections from clients.
//
// Client(int socket) - socket to send/receive traffic from client.
class Client
{
public:
    int sock;         // socket of client connection
    std::string name; // Limit length of name of client's user

    Client(int socket) : sock(socket) {}

    ~Client() {} // Virtual destructor defined for base class
};
class Server
{
public:
    int sock;                 // socket of server connection
    std::string name;         // Limit length of name of server's user
    std::string ip;           // the ip of the server
    std::string port;         // the port of the server
    std::string msgVector[5]; // vector for messages for this server
    int msgs;
    int newestMsg;

    Server() : msgs(0), newestMsg(0) {}
    Server(int socket, std::string ipaddr, std::string port) : sock(socket), ip(ipaddr), port(port), msgs(0), newestMsg(0) {}
    ~Server() {} // Virtual destructor defined for base class
    void addMsg(std::string msg){
        if (msgs >= 5){
            newestMsg = (newestMsg + 1) % 6;
            msgVector[newestMsg] = msg;
        }
        else{
            msgs++;
            newestMsg = (newestMsg + 1) % 6;
            msgVector[newestMsg] = msg;
        }
    }
    std::string getMsg(){
        if (msgs > 0){
            std::string msg = msgVector[newestMsg]; //TODO kannski adda msg = NULL
            (newestMsg == 1 && msgs > 1) ? newestMsg = 5 : newestMsg--;
            msgs--;
            return msg;
        }
        return NULL;
    }
};

// Note: map is not necessarily the most efficient method to use here,
// especially for a server with large numbers of simulataneous connections,
// where performance is also expected to be an issue.
//
// Quite often a simple array can be used as a lookup table,
// (indexed on socket no.) sacrificing memory for speed.

std::map<int, Client *> clients; // Lookup table for per Client information
std::map<int, Server *> servers; // Lookup table for per Server information
Server thisServer = Server();    // global variable to referenc this server

// Gets the computers (that is running the program) ip address on the internet by making
// a tcp connection to googles dns server and then retrieving the ip address it used.
in_addr getLocalIpAddr(const char *hostName)
{
    struct sockaddr_in serverAddr; // Server information
    int sock;                      // Socket for tcp connection

    // Initialize socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Failed to open socket");
        exit(0);
    }

    memset(&serverAddr, 0, sizeof(serverAddr));       // Initialize server information struct
    serverAddr.sin_family = AF_INET;                  // Set address family
    serverAddr.sin_addr.s_addr = inet_addr(hostName); // Set hostname
    serverAddr.sin_port = htons(PORT);                // Set the port

    // Connect to the server
    int err = connect(sock, (const struct sockaddr *)&serverAddr, sizeof(serverAddr));
    if (err < 0)
    {
        perror("Failed to connect: ");
        exit(0);
    }

    struct sockaddr_in ipaddress;                                     // Variable for the ip adress
    socklen_t namelen = sizeof(ipaddress);                            // Size of the ip address
    err = getsockname(sock, (struct sockaddr *)&ipaddress, &namelen); // Get the ip address used to connect from
    if (err < 0)
    {
        perror("Failed to get socket name: ");
        exit(0);
    }
    close(sock);

    return ipaddress.sin_addr;
}

// Open socket for specified port.
//
// Returns -1 if unable to create the socket for any reason.

int open_socket(int portno)
{
    struct sockaddr_in sk_addr; // address settings for bind()
    int sock;                   // socket opened for this port
    int set = 1;                // for setsockopt

    // Create socket for connection. Set to be non-blocking, so recv will
    // return immediately if there isn't anything waiting to be read.
#ifdef __APPLE__
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Failed to open socket");
        return (-1);
    }
#else
    if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
    {
        perror("Failed to open socket");
        return (-1);
    }
#endif

    // Turn on SO_REUSEADDR to allow socket to be quickly reused after
    // program exit.

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
    {
        perror("Failed to set SO_REUSEADDR:");
    }
    set = 1;
#ifdef __APPLE__
    if (setsockopt(sock, SOL_SOCKET, SOCK_NONBLOCK, &set, sizeof(set)) < 0)
    {
        perror("Failed to set SOCK_NOBBLOCK");
    }
#endif
    memset(&sk_addr, 0, sizeof(sk_addr));

    sk_addr.sin_family = AF_INET;
    sk_addr.sin_addr = getLocalIpAddr("8.8.8.8");
    sk_addr.sin_port = htons(portno);

    // Bind to socket to listen for connections from clients

    if (::bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr)) < 0)
    {
        perror("Failed to bind to socket:");
        return (-1);
    }
    else
    {
        return (sock);
    }
}

// Close a client's connection, remove it from the client list, and
// tidy up select sockets afterwards.

void closeClient(int clientSocket, fd_set *openSockets, int *maxfds)
{
    // Remove client from the clients list
    clients.erase(clientSocket);

    // If this client's socket is maxfds then the next lowest
    // one has to be determined. Socket fd's can be reused by the Kernel,
    // so there aren't any nice ways to do this.

    if (*maxfds == clientSocket)
    {
        for (auto const &p : clients)
        {
            *maxfds = std::max(*maxfds, p.second->sock);
        }
    }

    // And remove from the list of open sockets.

    FD_CLR(clientSocket, openSockets);
}

void closeServer(int serverSocket, fd_set *openSockets, int *maxfds)
{
    // Remove client from the clients list
    servers.erase(serverSocket);

    // If this client's socket is maxfds then the next lowest
    // one has to be determined. Socket fd's can be reused by the Kernel,
    // so there aren't any nice ways to do this.

    if (*maxfds == serverSocket)
    {
        for (auto const &p : servers)
        {
            *maxfds = std::max(*maxfds, p.second->sock);
        }
    }

    // And remove from the list of open sockets.

    FD_CLR(serverSocket, openSockets);
}

int connectToServer(std::string portno, std::string ipAddress)
{
    struct addrinfo hints, *svr; // Network host entry for server
    int serverSocket;            // Socket used for server
    int set = 1;                 // Toggle for setsockopt

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET; // IPv4 only addresses
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(ipAddress.c_str(), portno.c_str(), &hints, &svr) != 0)
    {
        perror("getaddrinfo failed: ");
        return -1;
    }

    serverSocket = socket(svr->ai_family, svr->ai_socktype, svr->ai_protocol);

    // Turn on SO_REUSEADDR to allow socket to be quickly reused after
    // program exit.

    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
    {
        printf("Failed to set SO_REUSEADDR for port %s\n", portno.c_str());
        perror("setsockopt failed: ");
    }

    if (connect(serverSocket, svr->ai_addr, svr->ai_addrlen) < 0)
    {
        printf("Failed to open socket to server: %s\n", ipAddress.c_str());
        perror("Connect failed: ");
        return -1;
    }

    std::string sending = "";
    sending += '\x01';
    sending += "LISTSERVERS,";
    sending += "V_Group_96";
    sending += '\x04';
    send(serverSocket, sending.c_str(), sending.length(), 0);

    return serverSocket;
}

// Process command from client on the server

void clientCommand(int clientSocket, fd_set *openSockets, int *maxfds,
                   char *buffer)
{
    std::vector<std::string> tokens;
    std::string token;

    // Split command from client into tokens for parsing
    std::stringstream stream(buffer);

    while (stream >> token)
        tokens.push_back(token);

    if ((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 2))
    {
        clients[clientSocket]->name = tokens[1];
    }
    else if (tokens[0].compare("LEAVE") == 0)
    {
        if (tokens.size() == 2)
        {
            std::string msg;
            int serverSock;
            for (auto const &server : servers)
            {
                if (server.second->name == tokens[1]) //&& server.second->port == tokens[1])
                {
                    // closeServer(server, openSockets, maxfds);
                    /*msg = "LEAVE," + server.second->ip + "," + server.second->port;
                    msg = '\x01' + msg;
                    msg = msg + '\x04';*/

                    serverSock = server.second->sock;
                }
            }
            msg = "LEAVE," + thisServer.ip + "," + thisServer.port;
            msg = '\x01' + msg;
            msg = msg + '\x04';        
            send(serverSock, msg.c_str(), msg.length(), 0);
            std::cout << "Sent LEAVE to server " << tokens[1] << std::endl;
            closeServer(serverSock, openSockets, maxfds);
        }
        // Close the socket, and leave the socket handling
        // code to deal with tidying up clients etc. when
        // select() detects the OS has torn down the connection.
        else
        {
            std::string msg = "Good bye";
            send(clientSocket, msg.c_str(), msg.length(), 0);
            closeClient(clientSocket, openSockets, maxfds);
        }
    }
    else if (tokens[0].compare("WHO") == 0)
    {
        std::cout << "Who is logged on" << std::endl;
        std::string msg;

        for (auto const &names : clients)
        {
            msg += names.second->name + ",";
        }
        // Reducing the msg length by 1 loses the excess "," - which
        // granted is totally cheating.
        send(clientSocket, msg.c_str(), msg.length() - 1, 0);
    }
    // This is slightly fragile, since it's relying on the order
    // of evaluation of the if statement.
    else if ((tokens[0].compare("MSG") == 0) && (tokens[1].compare("ALL") == 0))
    {
        std::string msg;
        for (auto i = tokens.begin() + 2; i != tokens.end(); i++)
        {
            msg += *i + " ";
        }

        for (auto const &pair : clients)
        {
            send(pair.second->sock, msg.c_str(), msg.length(), 0);
        }
    }
    else if ((tokens[0].compare("MSG") == 0) && (tokens.size() >= 2))
    {
        for (auto const &pair : clients)
        {
            if (pair.second->name.compare(tokens[1]) == 0)
            {
                std::string msg;
                for (auto i = tokens.begin() + 2; i != tokens.end(); i++)
                {
                    msg += *i + " ";
                }
                send(pair.second->sock, msg.c_str(), msg.length(), 0);
            }
        }
    }
    else if ((tokens[0].compare("SENDMSG") == 0) && (tokens.size() >= 2))
    {
        for (auto const &pair : servers) // to make sure we have the server we want to msg in our map
        {
            if (pair.second->name.compare(tokens[1]) == 0)
            {
                std::string msg, group(GROUP);
                msg += '\x01';
                msg += "SEND_MSG," + group + "," + tokens[1] + ",";
                for (auto i = tokens.begin() + 2; i != tokens.end(); i++)
                {
                    msg += *i + " ";
                }
                msg += '\x04';
                pair.second->addMsg(msg);
                break;
            }
        }
    }
    else if ((tokens[0].compare("GETMSG") == 0) && (tokens.size() == 2))
    {
        if( tokens[1] == thisServer.name ){
            std::string msg = thisServer.getMsg();
            send(clientSocket, msg.c_str(), msg.length(), 0);
        }
        else{
            for (auto const &pair : servers) // to make sure we have the server we want to msg in our map
            {
                if (pair.second->name.compare(tokens[1]) == 0)
                {
                    std::string msg = pair.second->getMsg();
                    send(clientSocket, msg.c_str(), msg.length(), 0);
                    break;
                }
            }
        }
    }
    else if ((tokens[0].compare("SERVER") == 0) && (tokens.size() == 3))
    {
        if (servers.size() < 5)
        {
            int serverSocket = connectToServer(tokens[2], tokens[1]);
            if(serverSocket == -1){
                std::string msg = "Failed to connect to server...";
                send(clientSocket, msg.c_str(), msg.length(), 0);
            }
            else{
                FD_SET(serverSocket, openSockets);
                servers[serverSocket] = new Server(serverSocket, tokens[1], tokens[2]);
                *maxfds = std::max(*maxfds, serverSocket);
                std::cout << "Connected to server on socket: " << serverSocket << std::endl;
            }
            
        }
        else
        {
            std::string msg = "To many servers connected";
            send(clientSocket, msg.c_str(), msg.length(), 0);
        }
    }
    else if ((tokens[0].compare("LISTSERVERS") == 0) && (tokens.size() == 1))
    {
        std::string msg = "SERVERS ";

        for (auto const &server : servers)
        {
            msg +=  server.second->name + "," + server.second->ip + "," + server.second->port + ";";
        }

        // Reducing the msg length by 1 loses the excess "," - which
        // granted is totally cheating.
        send(clientSocket, msg.c_str(), msg.length() - 1, 0);
    }
    else if ((tokens[0].compare("LISTSERVERS") == 0) && (tokens.size() == 2))
    {
        std::string msg;
        std::string group(GROUP);
        int serverSocket;

        for (auto const &server : servers)
        {
            if (tokens[1] == server.second->name)
            {
                serverSocket = server.second->sock;
            }
            //msg +="SERVERS " + server.second->name + "," + server.second->ip + "," + server.second->port + ";";
        }
        msg = "LISTSERVERS," + group;
        msg = '\x01' + msg;
        msg = msg + '\x04';
        // Reducing the msg length by 1 loses the excess "," - which
        // granted is totally cheating.
        send(serverSocket, msg.c_str(), msg.length(), 0);
    }
    else
    {
        std::string msg = "Unknown command from client:";
        std::cout << msg << buffer << std::endl;
        send(clientSocket, msg.c_str(), msg.length(), 0);
    }
}

void serverCommand(int serverSocket, fd_set *openSockets, int *maxfds,
                   char *buffer)
{
    std::vector<std::string> tokens;
    std::string token;

    // Split command from client into tokens for parsing
    std::stringstream stream(buffer);
    while (stream.good())
    {
        //std::string substr;
        getline(stream, token, ',');
        tokens.push_back(token);
    }

    if ((tokens[0].compare("LEAVE") == 0) && (tokens.size() == 3))
    {
        // Close the socket, and leave the socket handling
        // code to deal with tidying up clients etc. when
        // select() detects the OS has torn down the connection.
        std::string command(buffer);
        std::cout << "LEAVE msg: " << command << std::endl;
        for (auto const &server : servers)
        {
            if ((server.second->ip == tokens[1]) && (server.second->port == tokens[2]))
            {
                closeServer(server.first, openSockets, maxfds);
                std::cout << "Closed connection to server" << std::endl;
            }
        }
    }
    else if ((tokens[0].compare("SERVERS") == 0) && (tokens.size() >= 4))
    {
        // Close the socket, and leave the socket handling
        // code to deal with tidying up clients etc. when
        // select() detects the OS has torn down the connection.
        std::cout << "Received SERVERS from: " << tokens[1] << std::endl;
        servers[serverSocket]->name = tokens[1];
        servers[serverSocket]->ip = tokens[2];
        servers[serverSocket]->port = tokens[3];
        std::cout << buffer << std::endl;
        //   while(servers){}
    }
    

    else if ((tokens[0].compare("LISTSERVERS") == 0) && (tokens.size() == 2))
    {
        std::string msg, sender;

        sender += "SERVERS," + thisServer.name + "," + thisServer.ip + "," + thisServer.port + ";";
        for (auto const &server : servers)
        {
            msg += server.second->name + "," + server.second->ip + "," + server.second->port + ";";
        }
        msg = '\x01' + sender + msg + '\x04';
        // Reducing the msg length by 1 loses the excess "," - which
        // granted is totally cheating.
        std::cout << "Sending LISTSERVERS: " << msg << std::endl;
        send(serverSocket, msg.c_str(), msg.length(), 0);
    }
    else if ((tokens[0].compare("SEND_MSG") == 0) && (tokens.size() >= 3))
    {
        if(tokens[2] == thisServer.name ){
            std::string msg = "From :" + tokens[1] + " To :" + tokens[2];
            for (auto i = tokens.begin() + 3; i != tokens.end(); i++)
            {
                msg += *i;
            }
            thisServer.addMsg(msg);
        }
        else {
            for (auto const &pair : servers) // to make sure we have the server we want to msg in our map
            {
                if (pair.second->name.compare(tokens[2]) == 0)
                {
                    pair.second->addMsg(std::string(buffer));
                    break;
                }
            }
        }
    }
    else if ((tokens[0].compare("GET_MSG") == 0) && (tokens.size() == 2))
    {
        for (auto const &pair : servers) 
        {
            if (pair.second->name.compare(tokens[1]) == 0)
            {
                std::string msg;
                while(pair.second->msgs > 0){
                    msg = pair.second->getMsg();
                    send(serverSocket, msg.c_str(), msg.length(), 0);
                }
            }
        }
    }
    else
    {
        std::string msg;
        msg = "Unknown command from server:";
        std::string command = std::string(buffer);
        msg += " " + command;
        std::cout << msg << std::endl;
        send(serverSocket, msg.c_str(), msg.length(), 0);
    }
}

int main(int argc, char *argv[])
{
    bool finished;
    int listenSock;       // Socket for connections to server
    int listenLocalSock;  // Socket for connections to server
    int clientSock;       // Socket of connecting client
    int serverSock;       // Socket of connecting servers
    fd_set openSockets;   // Current open sockets
    fd_set readSockets;   // Socket list for select()
    fd_set exceptSockets; // Exception socket list
    int maxfds;           // Passed to select() as max fd in set
    struct sockaddr_in client, server;
    socklen_t clientLen;
    char buffer[1025]; // buffer for reading from clients

    if (argc != 2)
    {
        printf("Usage: chat_server <ip port>\n");
        exit(0);
    }
    // int PORT = atoi(argv[2]);
    thisServer.name = GROUP;
    thisServer.port = argv[1];
    thisServer.ip = inet_ntoa(getLocalIpAddr("8.8.8.8"));

    // Setup socket for server to listen to

    listenSock = open_socket(atoi(argv[1]));
    listenLocalSock = open_socket(PORT);
    printf("Listening on port: %d\n", atoi(argv[1]));
    printf("Listening on Local port: %d\n", PORT);

    if (listen(listenSock, BACKLOG) < 0)
    {
        printf("Listen failed on port %s\n", argv[1]);
        exit(0);
    }
    else if (listen(listenLocalSock, BACKLOG) < 0)
    {
        printf("Listen Local failed on port %d\n", PORT);
        exit(0);
    }
    else
    // Add listen socket to sockets set we are monitoring
    {
        FD_ZERO(&openSockets);
        FD_SET(listenSock, &openSockets);
        FD_SET(listenLocalSock, &openSockets);
        maxfds = std::max(listenSock, listenLocalSock);
    }

    finished = false;

    while (!finished)
    {
        // Get modifiable copy of readSockets
        readSockets = exceptSockets = openSockets;
        memset(buffer, 0, sizeof(buffer));

        // Look at sockets and see which ones have something to be read()
        int n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, NULL);

        if (n < 0)
        {
            perror("select failed - closing down\n");
            finished = true;
        }
        else
        {
            // First, accept  any new connections to the server on the listening socket
            if (FD_ISSET(listenLocalSock, &readSockets))
            {
                clientSock = accept(listenLocalSock, (struct sockaddr *)&client,
                                    &clientLen);
                printf("accept client connection:ip :%s  port :%u\n", inet_ntoa(client.sin_addr), htons(client.sin_port));
                // Add new client to the list of open sockets
                FD_SET(clientSock, &openSockets);

                // And update the maximum file descriptor
                maxfds = std::max(maxfds, clientSock);

                // create a new client to store information.
                clients[clientSock] = new Client(clientSock);

                // Decrement the number of sockets waiting to be dealt with
                n--;

                printf("Client connected on server: %d\n", clientSock);
            }
            if (FD_ISSET(listenSock, &readSockets) && servers.size() < 5)
            {
                serverSock = accept(listenSock, (struct sockaddr *)&server,
                                    &clientLen);
                printf("accept server connection ip :%s  port :%u\n", inet_ntoa(server.sin_addr), htons(server.sin_port));
                // Add new client to the list of open sockets
                FD_SET(serverSock, &openSockets);

                // And update the maximum file descriptor
                maxfds = std::max(maxfds, serverSock);

                // create a new client to store information.
                servers[serverSock] = new Server(serverSock, inet_ntoa(server.sin_addr), std::to_string(htons(server.sin_port)));
                // Decrement the number of sockets waiting to be dealt with
                        std::string msg;
                        std::string group(GROUP);
                        msg = '\x01';
                        msg += "LISTSERVERS," + group;
                        msg += '\x04';
                //serverCommand(serverSock, &openSockets, &maxfds, (char *) msg.c_str());
                send(serverSock, msg.c_str(), msg.length(), 0);
                n--;

                printf("server connected on server: %d\n", serverSock);
            }
            // Now check for commands from clients
            while (n-- > 0)
            {
                for (auto const &pair : clients)
                {
                    Client *client = pair.second;

                    if (FD_ISSET(client->sock, &readSockets))
                    {
                        // recv() == 0 means client has closed connection
                        memset(buffer, 0, sizeof(buffer));
                        if (recv(client->sock, buffer, sizeof(buffer), MSG_DONTWAIT) == 0)
                        {
                            printf("Client closed connection: %d", client->sock);
                            close(client->sock);

                            closeClient(client->sock, &openSockets, &maxfds);
                        }
                        // We don't check for -1 (nothing received) because select()
                        // only triggers if there is something on the socket for us.
                        else
                        {
                            std::cout << buffer << std::endl;
                            clientCommand(client->sock, &openSockets, &maxfds,
                                          buffer);
                        }
                    }
                }
                for (auto const &pair : servers)
                {
                    Server *server = pair.second;

                    if (FD_ISSET(server->sock, &readSockets))
                    {
                        // recv() == 0 means client has closed connection
                        memset(buffer, 0, sizeof(buffer));
                        int bytesRecv;
                        if ((bytesRecv = recv(server->sock, buffer, sizeof(buffer), MSG_DONTWAIT)) == 0)
                        {
                            printf("Server closed connection: %d", server->sock);
                            close(server->sock);

                            closeServer(server->sock, &openSockets, &maxfds);
                        }
                        // We don't check for -1 (nothing received) because select()
                        // only triggers if there is something on the socket for us.
                        else
                        {
                            std::cout << "Bytes received: " << bytesRecv << std::endl;
                            std::cout << buffer << std::endl;
                            if ((buffer[0] == '\x01') && (buffer[bytesRecv - 1] == '\x04'))
                            {
                                std::cout << "Right format" << std::endl;
                                std::vector<std::string> tokens;
                                std::string token;

                                // Split command from client into tokens for parsing
                                std::stringstream stream(buffer);
                                while (stream.good())
                                {
                                    //std::string substr;
                                    getline(stream, token, '\x04');
                                    tokens.push_back(token);
                                }
                                for(u_int i = 0; i != tokens.size(); i++){
                                    char bufferToParse[5000];
                                    bzero(bufferToParse, sizeof(bufferToParse));
                                    memcpy(bufferToParse, tokens[i].c_str() + 1 , sizeof(tokens[i])-2);
                                    serverCommand(server->sock, &openSockets, &maxfds,
                                              bufferToParse);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
