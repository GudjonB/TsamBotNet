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
#include <fstream>

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
#define PORT 4101
#define GROUP "P3_GROUP_96"
#define CLIENTAUTH "CLIENT96_1337"

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
    std::string msgArray[5]; // vector for messages for this server
    int msgs;
    int newestMsg;

    Server() : msgs(0), newestMsg(0) {}
    Server(int socket, std::string ipaddr, std::string port) : sock(socket), ip(ipaddr), port(port), msgs(0), newestMsg(0) {}
    ~Server() {} // Virtual destructor defined for base class
    void addMsg(std::string msg)
    {
        if (msgs >= 5)
        {
            newestMsg = (newestMsg + 1) % 6;
            msgArray[newestMsg] = msg;
        }
        else
        {
            msgs++;
            newestMsg = (newestMsg + 1) % 6;
            msgArray[newestMsg] = msg;
        }
    }
    std::string getMsg()
    {
        if (msgs > 0)
        {
            std::string msg = msgArray[newestMsg]; //TODO kannski adda msg = NULL
            (newestMsg == 1 && msgs > 1) ? newestMsg = 5 : newestMsg--;
            msgs--;
            return msg;
        }
        return "NO MESSAGES";
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
int listenSock;                  // Socket for connections to server
int listenLocalSock;             // Socket for connections to server


void logger(std::string msg)
{
    std::time_t result = std::time(nullptr);
    std::string timeString = std::asctime(std::localtime(&result));
    std::ofstream logfile;
    logfile.open("log.txt", std::ofstream::out | std::ofstream::app);
    std::cout << "before writing " << timeString << std::endl;
    logfile <<  timeString.substr(0, timeString.length() - 1) + " " + msg + "\n";
    logfile.close();
}

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
        if (!clients.empty())
        {
            for (auto const &p : clients)
            {
                *maxfds = std::max(*maxfds, p.second->sock);
            }
        }
        else if (!servers.empty())
        {
            for (auto const &p : servers)
            {
                *maxfds = std::max(*maxfds, p.second->sock);
            }
        }
        else{
            *maxfds = std::max(listenSock, listenLocalSock);
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
        if(!servers.empty()){
            for (auto const &p : servers)
            {
                *maxfds = std::max(*maxfds, p.second->sock);
            }
        }
        else if(!clients.empty()){
            for (auto const &p : clients)
            {
                *maxfds = std::max(*maxfds, p.second->sock);
            }
        }
        else{
            *maxfds = std::max(listenSock, listenLocalSock);
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
        return -1;
    }

    if (connect(serverSocket, svr->ai_addr, svr->ai_addrlen) < 0)
    {
        printf("Failed to connect to server: %s\n", ipAddress.c_str());
        perror("Connect failed: ");
        return -1;
    }

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
    if(tokens.empty()){
        std::string msg = "Unknown command from client:";
        std::cout << msg << buffer << std::endl;
        send(clientSocket, msg.c_str(), msg.length(), 0);
        return;
    }
    else if ((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 2))
    {
        clients[clientSocket]->name = tokens[1];
    }
    else if (tokens[0].compare("LEAVE") == 0)
    {
        int serverSock;
        if (tokens.size() == 2)
        {
            std::string msg;
            for (auto const &server : servers)
            {
                if (server.second->name == tokens[1])
                {
                    serverSock = server.second->sock;
                    msg = "LEAVE," + thisServer.ip + "," + thisServer.port;
                    msg = '\x01' + msg;
                    msg = msg + '\x04';        
                    send(serverSock, msg.c_str(), msg.length(), 0);
                    std::cout << "Sent LEAVE to server " << tokens[1] << std::endl;
                    closeServer(serverSock, openSockets, maxfds);
                }
            }
        }
        else if(tokens.size() == 3){
            for (auto const &server : servers)
            {
                if ((server.second->ip == tokens[1]) && (server.second->port == tokens[2]))
                {
                    serverSock = server.second->sock;
                    closeServer(serverSock, openSockets, maxfds);
                }
            }
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
    else if ((tokens[0].compare("SENDMSG") == 0) && (tokens.size() > 2))
    {
        if(tokens[1].compare("FORWARD") == 0){
            for (auto const &pair : servers) // to make sure we have the server we want to msg in our map
            {
                if (pair.second->name.compare(tokens[2]) == 0)
                {
                    std::string msg, group(GROUP);
                    msg += '\x01';
                    msg += "SEND_MSG," + group + "," + tokens[3] + ",";
                    for (auto i = tokens.begin() + 4 ;i != tokens.end(); i++)
                    {
                        msg += *i + " ";
                    }
                    msg[msg.length()-1] = '\x04';
                    send(pair.first, msg.c_str(), msg.length(), 0);
                    break;
                }
            }
        }
        else if(tokens[1].compare("SECRET") == 0){
            for (auto const &pair : servers) // to make sure we have the server we want to msg in our map
            {
                if (pair.second->name.compare(tokens[2]) == 0)
                {
                    std::string msg, group(GROUP);
                    msg += '\x01';
                    msg += "SEND_MSG," + group + ",";
                    for (auto i = tokens.begin() + 3 ;i != tokens.end(); i++)
                    {
                        msg += *i + " ";
                    }
                    msg[msg.length()-1] = '\x04';
                    std::cout<< "secret msg sent : " + msg << std::endl; 
                    send(pair.first, msg.c_str(), msg.length(), 0);
                    break;
                }
            }
        }
        else if(tokens[1].compare("ALL") == 0){
            for (auto const &pair : servers) // to make sure we have the server we want to msg in our map
            {
                std::string msg, group(GROUP);
                msg += '\x01';
                msg += "SEND_MSG," + group + "," + pair.second->name + ",";
                for (auto i = tokens.begin() + 2; i != tokens.end(); i++)
                {
                    msg += *i + " ";
                }
                msg[msg.length()-1] = '\x04';
                send(pair.first, msg.c_str(), msg.length(), 0);
                logger(msg);
            }
        }
        else {
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
                    msg[msg.length()-1] = '\x04';
                    send(pair.first, msg.c_str(), msg.length(), 0);
                    logger(msg);
                    break;
                }
            }
        }
    }
    else if ((tokens[0].compare("SENDMSG") == 0) && (tokens.size() <= 2))
    {
        std::string msg = "Message is empty, nothing sent";
        send(clientSocket, msg.c_str(), msg.length(), 0);

    }
    else if ((tokens[0].compare("GETMSG") == 0) && (tokens.size() == 2))
    {   

        std::string msg = "GET_MSG,";
        std::string group = tokens[1];
        msg = '\x01'+ msg + group + '\x04';
        for (auto const &pair : servers) // to make sure we have the server we want to msg in our map
        {
            send(pair.first, msg.c_str(), msg.length(), 0);
        }
        
    }
    else if ((tokens[0].compare("GETMSG") == 0) && (tokens[1].compare("FROM") == 1) &&  (tokens.size() == 3))
    {
        std::string msg = "GET_MSG,";
        std::string group(GROUP);
        msg = '\x01'+ msg + group + '\x04';
        send(clientSocket, msg.c_str(), msg.length(), 0);
        for (auto const &pair : servers) // to make sure we have the server we want to msg in our map
        {
            if (pair.second->name.compare(tokens[2]) == 0)
            {
                send(pair.first, msg.c_str(), msg.length(), 0);
                break;
            }
        }
    }
    else if ((tokens[0].compare("SERVER") == 0) && (tokens.size() == 3))
    {
        int found = 0;
            for (auto const &pair : servers)
            {
                if ((pair.second->ip.compare(tokens[1]) == 0) && (pair.second->port.compare(tokens[2]) == 0))
                {
                    found = 1;
                    break;
                }
            }
        if (servers.size() < 5 && !found)
        {
            int serverSocket = connectToServer(tokens[2], tokens[1]);
            if (serverSocket == -1)
            {
                std::string msg = "Failed to connect to server...";
                send(clientSocket, msg.c_str(), msg.length(), 0);
            }
            else
            {
                FD_SET(serverSocket, openSockets);
                servers[serverSocket] = new Server(serverSocket, tokens[1], tokens[2]);
                *maxfds = std::max(*maxfds, serverSocket);
                std::cout << "Connected to server on socket: " << serverSocket << std::endl;
                std::string sending = "";
                sending += '\x01';
                sending += "LISTSERVERS,";
                sending += GROUP;
                sending += '\x04';
                send(serverSocket, sending.c_str(), sending.length(), 0);
            }
        }
        else
        {
            if(found){
                std::string msg = "Server already connected";
                send(clientSocket, msg.c_str(), msg.length(), 0);
            }
            else{
                std::string msg = "To many servers connected";
                send(clientSocket, msg.c_str(), msg.length(), 0);
            }
        }
    }
    else if ((tokens[0].compare("LISTSERVERS") == 0) && (tokens.size() == 1))
    {
        std::string msg = "\nOur SERVERS:\n";

        for (auto const &server : servers)
        {
            msg += "  Name: " + server.second->name + "  IP: " + server.second->ip + "  Port: " + server.second->port + "\n";
        }
        // Reducing the msg length by 1 loses the excess "," - which
        // granted is totally cheating.
        send(clientSocket, msg.c_str(), msg.length(), 0);
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
        }
        msg = "LISTSERVERS," + group;
        msg = '\x01' + msg;
        msg = msg + '\x04';
        send(serverSocket, msg.c_str(), msg.length(), 0);
    }
    else if ((tokens[0].compare("STATUSREQ") == 0) && (tokens.size() == 2))
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
        }
        msg = "STATUSREQ," + group;
        msg = '\x01' + msg;
        msg = msg + '\x04';
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
    size_t pos;
    // Split command from client into tokens for parsing
    std::stringstream stream(buffer);
    while (stream.good())
    {
        //std::string substr;

        getline(stream, token, ',');
        if ((pos = token.find_first_of(";")) != std::string::npos)
        {
            tokens.push_back(token.substr(0, pos));
            tokens.push_back(token.substr(pos+1, token.length()-1));
        }
        else
        {
            tokens.push_back(token);
        }
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
            //std::cout << tokens[1] << "," << tokens[2] << " : " << server.second->ip <<  "," << server.second->port << std::endl;
            if ((tokens[1].compare(server.second->ip) == 0) && (tokens[2]).compare(server.second->port) == 0)
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
        std::string group(GROUP);
        std::string greeting = "AUTOMATED MESSAGE: you have connected to group 96. Please respond to this message :)";
        std::string autoMsg = '\x01' + "SEND_MSG," + group + "," + tokens[1] + "," + greeting + '\x04';
        std::cout << "Received SERVERS from: " << tokens[1] << std::endl;
        servers[serverSocket]->name = tokens[1];
        servers[serverSocket]->ip = tokens[2];
        servers[serverSocket]->port = tokens[3];
        send(serverSocket, autoMsg.c_str(), autoMsg.length(), 0);
        for(u_int i = 4; ((i+3) < tokens.size()) && (servers.size() < 5); i += 3){
            int found = 0;
            for (auto const &pair : servers)
            {
                if (pair.second->name.compare(tokens[i]) == 0)
                {
                    found = 1;
                    break;
                }
            }
            if(!found && (tokens[i].compare(thisServer.name) != 0) && (tokens[i].length() != 0)){
                std::cout <<"name "+tokens[i] +" port" + tokens[i+2] + " ip" +tokens[i+1] << std::endl;
                int newServerSock = connectToServer(tokens[i+2],tokens[i+1]);
                if (newServerSock == -1){
                    std::cout << "Failed to connect to server... " << tokens[i+1] << std::endl;
                }
                else{
                    FD_SET(newServerSock, openSockets);
                    servers[newServerSock] = new Server(newServerSock, tokens[i+1], tokens[i+2]);
                    servers[newServerSock]->name = tokens[i];
                    *maxfds = std::max(*maxfds, newServerSock);
                    std::cout << "Connected to server on socket: " << newServerSock << std::endl;
                    autoMsg = '\x01' + "SEND_MSG," + group + "," + tokens[i] + "," + greeting + '\x04';
                    send(newServerSock, autoMsg.c_str(), autoMsg.length(), 0);
                }
            }
        }

        std::string msg = "";
        msg += "Server respone from: " + tokens[1] + "\n";

        for(int i = 1; (i + 3) < (int) tokens.size(); i = i + 3) 
        {
            msg += "Name: " + tokens[i] + "  IP: " + tokens[i + 1] + "  Port: " + tokens[i + 2] + "\n";
        }
        for (auto const &pair : clients) // to make sure we have the server we want to msg in our map
        {
            send(pair.first, msg.c_str(), msg.length(), 0);
        }
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
        if (tokens[2] == thisServer.name)
        {
            std::string msg;
            if(servers[serverSocket]->name != tokens[1])
            {
                msg = "Message through: " + servers[serverSocket]->name + "\n From :" + tokens[1] + " To : " + tokens[2] + " >> ";
            }
            else
            {
                msg = "\nFrom :" + tokens[1] + " To : " + tokens[2] + " >> ";
            }
            
            for (auto i = tokens.begin() + 3; i != tokens.end(); i++)
            {
                msg += *i;
            }
            for (auto const &pair : clients) // to make sure we have the server we want to msg in our map
            {
                send(pair.first, msg.c_str(), msg.length(), 0);
            }
            std::string logtext(buffer);
            logger(logtext);
            

        }
        else
        {
            for (auto const &pair : servers) // to make sure we have the server we want to msg in our map
            {
                if (pair.second->name.compare(tokens[2]) == 0)
                {
                    std::string msg(buffer);
                    msg = '\x01' + msg;
                    msg += '\x04';
                    send(pair.first, msg.c_str(), msg.length(), 0);
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
                while (pair.second->msgs > 0)
                {
                    msg = pair.second->getMsg();
                    send(serverSocket, msg.c_str(), msg.length(), 0);
                }
            }
        }
    }
    else if ((tokens[0].compare("KEEPALIVE") == 0) && (tokens.size() == 2))
    {
        if(tokens[1] != "0"){
            std::string msg, group(GROUP);
            msg += '\x01';
            msg += "GET_MSG," + group;
            msg += '\x04';
            send(serverSocket, msg.c_str(), msg.length(), 0);
        }
        std::string msg;
        msg = tokens[0] + " " + tokens[1] + " from : " + servers[serverSocket]->name; 
        for (auto const &pair : clients)
        {
            send(pair.first, msg.c_str(), msg.length(), 0);
        }
    }
    else if ((tokens[0].compare("STATUSREQ") == 0) && (tokens.size() == 2))
    {
        std::string list, msg, group(GROUP);
        msg = '\x01';
        msg += "STATUSRESP,";
        msg += group + "," + tokens[1];

        for (auto const &pair : servers)
        {
            
            if((pair.second->name.compare(tokens[1]) != 0) && (pair.second->msgs != 0))
            {
                msg += "," + pair.second->name + "," + std::to_string(pair.second->msgs);
            }
        }
        // msg += list;
        msg += '\x04';
        send(serverSocket, msg.c_str(), msg.length(), 0);
    }
    else if ((tokens[0].compare("STATUSRESP") == 0)) //&& (tokens.size() >= 3))
    {
        
        std::string msg = "";
        msg += "\nStatus respone from: " + tokens[1] + " To: " + tokens[2] + "\n";

        for(int i = 3; i < (int) tokens.size(); i = i + 2) 
        {
            msg += "Server: " + tokens[i] + " has " + tokens[i + 1] + " messages\n";
        }
        std::cout << msg << std::endl;
        for (auto const &pair : clients)
        {
            send(pair.first, msg.c_str(), msg.length(), 0);
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
    
    int clientSock;       // Socket of connecting client
    int serverSock;       // Socket of connecting servers
    fd_set openSockets;   // Current open sockets
    fd_set readSockets;   // Socket list for select()
    fd_set exceptSockets; // Exception socket list
    int maxfds;           // Passed to select() as max fd in set
    struct sockaddr_in client, server;
    socklen_t clientLen;
    char buffer[5000]; // buffer for reading from clients

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
    timeval* time = new timeval();
    time->tv_sec = 60;

    while (!finished)
    {

        // Get modifiable copy of readSockets
        readSockets = exceptSockets = openSockets;
        memset(buffer, 0, sizeof(buffer));

        // Look at sockets and see which ones have something to be read()
        int n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, time);

        if (n < 0)
        {
            perror("select failed - closing down\n");
            finished = true;
        }
        else if(n == 0){
            for (auto const &server : servers)
                    {
                        std::cout << "Sending keepalive to server: " << server.second->name << std::endl;
                        std::string msg = "KEEPALIVE,";
                        msg += std::to_string(server.second->msgs);
                        msg = '\x01' + msg;
                        msg = msg + '\x04';
                        send(server.first, msg.c_str(), msg.length(), 0);
                    }
                    time->tv_sec = 60;
        }
        else
        {
            // First, accept  any new connections to the server on the listening socket
            if (FD_ISSET(listenLocalSock, &readSockets))
            {
                clientSock = accept(listenLocalSock, (struct sockaddr *)&client,
                                    &clientLen);
                printf("Client trying connection:ip :%s  port :%u\n", inet_ntoa(client.sin_addr), htons(client.sin_port));
                int bytesRecv;
                usleep(500);
                if((bytesRecv = recv(clientSock, buffer, sizeof(buffer), MSG_DONTWAIT)) == 0)
                {
                    std::cout << "Unauthorized client trying to connect" << std::endl;

                }
                else
                {
                    std::string authToken(buffer);
                    if(authToken.compare(CLIENTAUTH) != 0) 
                    {
                        std::cout << "Unauthorized client trying to connect" << std::endl;
                    }
                    else
                    {
                        // Add new client to the list of open sockets
                        FD_SET(clientSock, &openSockets);

                        // And update the maximum file descriptor
                        maxfds = std::max(maxfds, clientSock);

                        // create a new client to store information.
                        clients[clientSock] = new Client(clientSock);

                        // Decrement the number of sockets waiting to be dealt with
                        n--;

                        printf("Client connected on server: %d\n", clientSock);
                        std::string msg("Welcome to Group 96's server !\n");
                        send(clientSock, msg.c_str(),msg.length(),0);
                        
                    }
                    
                }
                

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
                            printf("Server closed connection: %s", servers[server->sock]->name.c_str());
                            close(server->sock);

                            closeServer(server->sock, &openSockets, &maxfds);
                        }
                        // We don't check for -1 (nothing received) because select()
                        // only triggers if there is something on the socket for us.
                        else
                        {
                            // PRINT
                            std::cout << "Bytes received: " << bytesRecv << std::endl;
                            std::cout << buffer << std::endl;
                            if ((buffer[0] == '\x01') && (buffer[bytesRecv - 1] == '\x04'))
                            {
                                // PRINT
                                std::cout << "Right format" << std::endl;
                                std::vector<std::string> tokens;
                                std::string token;

                                // Split command from client into tokens for parsing
                                std::stringstream stream(buffer);
                                while (stream.good())
                                {
                                    getline(stream, token, '\x04');
                                    if (strlen(token.c_str()) > 0)
                                    {
                                        tokens.push_back(token);
                                    }
                                }
                                for (u_int i = 0; i < tokens.size(); i++)
                                {
                                    char bufferToParse[5000];
                                    bzero(bufferToParse, sizeof(bufferToParse));
                                    memcpy(bufferToParse, tokens[i].c_str() + 1, tokens[i].length());
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

