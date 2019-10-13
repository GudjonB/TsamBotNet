//
// Simple chat server for TSAM-409
//
// Command line: ./vgroup96 4096
//
// Authors: Guðjón Björnsson (gudjon17@ru.is)
//          Sölvi Baldursson (solvib@ru.is)
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
#define PORT 4011
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

// Simple class for handling connections from servers.
// has functions for adding and retreving the newest message
// Server(int socket, std::string ipaddr, std::string port) - socket to send/receive traffic from server.
class Server
{
public:
    int sock;                 // socket of server connection
    std::string name;         // Limit length of name of server's user
    std::string ip;           // the ip of the server
    std::string port;         // the port of the server
    std::string msgArray[5];  // arrayfor messages for this server
    int msgs;                 // number of valid messages in the array
    int newestMsg;            // the position of the newest message in the array

    Server() : msgs(0), newestMsg(0) {}
    Server(int socket, std::string ipaddr, std::string port) : sock(socket), ip(ipaddr), port(port), msgs(0), newestMsg(0) {}
    ~Server() {} // Virtual destructor defined for base class
    // Adds messages to the array making it work like a circular buffer
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
    // removes the newest message from the array and decrements the number of messages
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


// Map for clients keyed on the socketfd
std::map<int, Client *> clients; // Lookup table for per Client information
// Map for the servers keyed on the socketfd
std::map<int, Server *> servers; // Lookup table for per Server information
// This server initialized for later referencing the ip and port
Server thisServer = Server();    // global variable to referenc this server
int listenSock;                  // Socket for connections to server
int listenLocalSock;             // Socket for connections to server


// logger function for loging the messages sent and received 
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
        else if (!servers.empty()) // check to see if there are servers and if so if thay have the highest fd
        {
            for (auto const &p : servers)
            {
                *maxfds = std::max(*maxfds, p.second->sock);
            }
        }
        else{ // if the last client disconnected and there are no servers then the maxfd is either listenSock or listenLocalSock
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
        else if(!clients.empty()){ // check to see if there are clients and if so if thay have the highest fd
            for (auto const &p : clients)
            {
                *maxfds = std::max(*maxfds, p.second->sock);
            }
        }
        else{ // if the last client disconnected and there are no servers then the maxfd is either listenSock or listenLocalSock
            *maxfds = std::max(listenSock, listenLocalSock);
        }
    }

    // And remove from the list of open sockets.

    FD_CLR(serverSocket, openSockets);
}

// Connects to a server and creates the socket for it
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
  	// CONNECT sets the name of the clients
    else if ((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 2))
    {
        clients[clientSocket]->name = tokens[1];
    }
  	// LEAVE can be used for disconnecting the current client or to tell the server to disconnect 
  	// from a given server, the server can be given as a name or ip and port
    else if (tokens[0].compare("LEAVE") == 0)
    {
        int serverSock;
        if (tokens.size() == 2) // if there were only two tokens then we have a server name
        {
            std::string msg;
            for (auto const &server : servers)
            {
                if (server.second->name == tokens[1])
                {
                    serverSock = server.second->sock; // we can tell the other server to disconnect from us
                    msg = "LEAVE," + thisServer.ip + "," + thisServer.port;
                    msg = '\x01' + msg;
                    msg = msg + '\x04';        
                    send(serverSock, msg.c_str(), msg.length(), 0);
                    std::cout << "Sent LEAVE to server " << tokens[1] << std::endl;
                    closeServer(serverSock, openSockets, maxfds);
                }
            }
        }
        else if(tokens.size() == 3){ // if there are 3 tokens then the server was given by ip and port
            for (auto const &server : servers)
            {
                std::string msg;
                if ((server.second->ip == tokens[1]) && (server.second->port == tokens[2]))
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
        // Close the socket, and leave the socket handling
        // code to deal with tidying up clients etc. when
        // select() detects the OS has torn down the connection.
        else // if the only token sent was LEAVE then we disconnect that client
        {
            std::string msg = "Good bye"; // the client recognizes this message and exits
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
  	// sendmsg sends a message to a server, SENDMSG can be used in the four following ways
  	// SENDMSG <To name> <message> : sends a message to the server corresponding to that name
  	// SENDMSG FORWARD <Through name> <To name> <message> : for sending a message through another server to one of his serves
  	// the message is sent to the "Throug name" server but has the sender and recipient as normal
  	// SENDMSG ALL <message> : sends the message to all servers we are connected to
  	// SENDMSG SECRET <mesage> : this was implimented to send a mesage to the oracle since it only wants to get the sender and not
  	// it self as the recipient 
    else if ((tokens[0].compare("SENDMSG") == 0) && (tokens.size() > 2))
    {
        if(tokens[1].compare("FORWARD") == 0){
            for (auto const &pair : servers) // to make sure we have the server we want to message through in our map
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
                    logger(msg);
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
  	// if there was no message we let the client know
    else if ((tokens[0].compare("SENDMSG") == 0) && (tokens.size() <= 2))
    {
        std::string msg = "Message is empty, nothing sent";
        send(clientSocket, msg.c_str(), msg.length(), 0);

    }
  	// sends a GET_MSG to all servers we are connected to for the group given as token 2
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
  	// Takes in the ip and port for a server to connect to, if the connection is successful we send that server 
  	// a LISTSERVERS message to retreive it's name
    else if ((tokens[0].compare("SERVER") == 0) && (tokens.size() == 3))
    {
        int found = 0; // first check to see if we have already a connection to that server
            for (auto const &pair : servers)
            {
                if ((pair.second->ip.compare(tokens[1]) == 0) && (pair.second->port.compare(tokens[2]) == 0))
                {
                    found = 1;
                    break;
                }
            }
        if (servers.size() < 5 && !found) // aslong as we have room and havent connected already we connect
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
  	// listservers can be sent on its own to display the servers that are connected or with a groupname to get its 1 hop servers
  	// LISTSERVERS : our one hop servers
  	// LISTSERVERS <Group name> : their one hop servers
    else if ((tokens[0].compare("LISTSERVERS") == 0) && (tokens.size() == 1))
    {
        std::string msg = "\nOur SERVERS:\n"; // a nicer way to read the response

        for (auto const &server : servers)
        {
            msg += "  Name: " + server.second->name + "  IP: " + server.second->ip + "  Port: " + server.second->port + "\n";
        }
        send(clientSocket, msg.c_str(), msg.length(), 0);
    }
    // Send a listservers request from this server to another connected server
    else if ((tokens[0].compare("LISTSERVERS") == 0) && (tokens.size() == 2))
    {
        std::string msg;
        std::string group(GROUP);
        int serverSocket;
		// Find the server in our map
        for (auto const &server : servers)
        {
            if (tokens[1] == server.second->name)
            {
                serverSocket = server.second->sock;
            }
        }
        // Build the message
        msg = "LISTSERVERS," + group;
        msg = '\x01' + msg;
        msg = msg + '\x04';
        send(serverSocket, msg.c_str(), msg.length(), 0);
    }
    // Send a status request from our server
    else if ((tokens[0].compare("STATUSREQ") == 0) && (tokens.size() == 2))
    {
        std::string msg;
        std::string group(GROUP);
        int serverSocket;
		// Find the server we want to send to
        for (auto const &server : servers)
        {
            if (tokens[1] == server.second->name)
            {
                serverSocket = server.second->sock;
            }
        }
        // Build the message to send
        msg = "STATUSREQ," + group;
        msg = '\x01' + msg;
        msg = msg + '\x04';
        send(serverSocket, msg.c_str(), msg.length(), 0);
    }
  	// Send client back that the command is unknown
    else
    {
        std::string msg = "Unknown command from client:";
        std::cout << msg << buffer << std::endl;
        send(clientSocket, msg.c_str(), msg.length(), 0);
    }
}
// Process command from a server on our server
void serverCommand(int serverSocket, fd_set *openSockets, int *maxfds,
                   char *buffer)
{
    std::vector<std::string> tokens;									// Vector to store tokens from the parsed buffer
    std::string token;
    size_t pos;
    // Split command from client into tokens for parsing
    std::stringstream stream(buffer);
    while (stream.good())
    {
        getline(stream, token, ',');									// Split on commas
        if ((pos = token.find_first_of(";")) != std::string::npos)		// If the token for the port icludes semi-colon at the end we take it out
        {
            tokens.push_back(token.substr(0, pos));
            tokens.push_back(token.substr(pos+1, token.length()-1));
        }
        else
        {
            tokens.push_back(token);
        }
    }
	// If we get a leave from a server we close the onnection down
    if ((tokens[0].compare("LEAVE") == 0) && (tokens.size() == 3))
    {
        std::string command(buffer);
        std::cout << "LEAVE msg: " << command << std::endl;
        for (auto const &server : servers)
        {
            if ((tokens[1].compare(server.second->ip) == 0) && (tokens[2]).compare(server.second->port) == 0)
            {
                closeServer(server.first, openSockets, maxfds);
                std::cout << "Closed connection to server" << std::endl;
            }
        }
    }
    // Handling for receiving server list from servers connecting to us
    else if ((tokens[0].compare("SERVERS") == 0) && (tokens.size() >= 4))
    {
        // Building a automated message to send to servers that connect to us
        std::string group(GROUP);
        std::string greeting = "AUTOMATED MESSAGE: you have connected to group 96. Please respond to this message :)";
        std::string autoMsg = "";
        autoMsg = "SEND_MSG," + group + "," + tokens[1] + "," + greeting;
        autoMsg = '\x01' + autoMsg + '\x04';
        logger(autoMsg);
         
        std::cout << "Received SERVERS from: " << tokens[1] << std::endl;
        // Updating the information about the server connecting to us from the information he sent
        servers[serverSocket]->name = tokens[1];
        servers[serverSocket]->ip = tokens[2];
        servers[serverSocket]->port = tokens[3];
        send(serverSocket, autoMsg.c_str(), autoMsg.length(), 0);
        // In the following loop this server tries to connect to all the other servers that were in the server response up to maxmimum of 5
        for(u_int i = 4; ((i+3) < tokens.size()) && (servers.size() < 5); i += 3){
            int found = 0;
            // Check if the server is alread connected
            for (auto const &pair : servers)
            {
                if (pair.second->name.compare(tokens[i]) == 0)
                {
                    found = 1;
                    break;
                }
            }
            // If the server has no name, and is not connected to us and is not this server we do not try to connect
            if(!found && (tokens[i].compare(thisServer.name) != 0) && (tokens[i].length() != 0)){
                std::cout <<"name "+tokens[i] +" port" + tokens[i+2] + " ip" +tokens[i+1] << std::endl;
                // Try to connect
                int newServerSock = connectToServer(tokens[i+2],tokens[i+1]);     
                if (newServerSock == -1){
                    std::cout << "Failed to connect to server... " << tokens[i+1] << std::endl;
                }
                // Update our open sockets, the add the server to our map and send an automated message
                else{
                    FD_SET(newServerSock, openSockets);
                    servers[newServerSock] = new Server(newServerSock, tokens[i+1], tokens[i+2]);
                    servers[newServerSock]->name = tokens[i];
                    *maxfds = std::max(*maxfds, newServerSock);
                    std::cout << "Connected to server on socket: " << newServerSock << std::endl;
                    autoMsg = "";
                    autoMsg = "SEND_MSG," + group + "," + tokens[i] + "," + greeting;
                    autoMsg = '\x01' + autoMsg + '\x04';
                    send(newServerSock, autoMsg.c_str(), autoMsg.length(), 0);
                    logger(autoMsg);
                }
            }
        }
		// Send the server sesponse from the originally connected server to our clients in a nice format
        std::string msg = "";
        msg += "Server respone from: " + tokens[1] + "\n";

        for(int i = 1; (i + 3) < (int) tokens.size(); i = i + 3) 
        {
            msg += "Name: " + tokens[i] + "  IP: " + tokens[i + 1] + "  Port: " + tokens[i + 2] + "\n";
        }
        for (auto const &pair : clients)
        {
            send(pair.first, msg.c_str(), msg.length(), 0);
        }
    }
	// Respond with a list of our servers with this server listed first to the server requesting it
    else if ((tokens[0].compare("LISTSERVERS") == 0) && (tokens.size() == 2))
    {
        std::string msg, sender;
		// Generate the response
        sender += "SERVERS," + thisServer.name + "," + thisServer.ip + "," + thisServer.port + ";";
        for (auto const &server : servers)
        {
            msg += server.second->name + "," + server.second->ip + "," + server.second->port + ";";
        }
        msg = '\x01' + sender + msg + '\x04';
        std::cout << "Sending LISTSERVERS: " << msg << std::endl;
        send(serverSocket, msg.c_str(), msg.length(), 0);
    }
    // Receive messages sent from connected servers
    else if ((tokens[0].compare("SEND_MSG") == 0) && (tokens.size() >= 3))
    {
        // If the message is for this server we send it to al lour clients
        if (tokens[2] == thisServer.name)
        {
            // Create readable text for the clients
            std::string msg;
            // If the message is routed through another server we include in the text which server it is routed from
            if(servers[serverSocket]->name != tokens[1])
            {
                msg = "Message through: " + servers[serverSocket]->name + "\n From :" + tokens[1] + " To : " + tokens[2] + " >> ";
            }
            else
            {
                msg = "\nFrom :" + tokens[1] + " To : " + tokens[2] + " >> ";
            }
        	// Add the message part to the text
            for (auto i = tokens.begin() + 3; i != tokens.end(); i++)
            {
                msg += *i;
            }
            for (auto const &pair : clients)
            {
                send(pair.first, msg.c_str(), msg.length(), 0);
            }
            std::string logtext(buffer);
            logger(logtext);				// Log the message
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
    // Send all messges we have for the server sending get message.
    else if ((tokens[0].compare("GET_MSG") == 0) && (tokens.size() == 2))
    {
        // Find the server in our map
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
    // Send keepalive messages received from server to all our clients
    else if ((tokens[0].compare("KEEPALIVE") == 0) && (tokens.size() == 2))
    {
        // If the keepalive message indicates that there are messages for us on the other end we send get message to that server
        if(tokens[1] != "0"){
            std::string msg, group(GROUP);
            msg += '\x01';
            msg += "GET_MSG," + group;
            msg += '\x04';
            send(serverSocket, msg.c_str(), msg.length(), 0);
        }
        // Create a readable text for the clients
        std::string msg;
        msg = tokens[0] + " " + tokens[1] + " from : " + servers[serverSocket]->name; 
        for (auto const &pair : clients)
        {
            send(pair.first, msg.c_str(), msg.length(), 0);
        }
    }
    // Send status response to server that sent us a statusreq
    else if ((tokens[0].compare("STATUSREQ") == 0) && (tokens.size() == 2))
    {
        std::string list, msg, group(GROUP);
        msg = '\x01';
        msg += "STATUSRESP,";
        msg += group + "," + tokens[1];
		// Create the statusresponse to send
        for (auto const &pair : servers)
        {      
            if((pair.second->name.compare(tokens[1]) != 0) && (pair.second->msgs != 0))
            {
                msg += "," + pair.second->name + "," + std::to_string(pair.second->msgs);
            }
        }
        msg += '\x04';
        send(serverSocket, msg.c_str(), msg.length(), 0);
    }
    // Send status response received from server to all connected clients
    else if ((tokens[0].compare("STATUSRESP") == 0))
    {       
        std::string msg = "";
        msg += "\nStatus respone from: " + tokens[1] + " To: " + tokens[2] + "\n";
		// Create a readable text from the response for our clients
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
    // Sending the server back that his command is invalid
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
    // Set up global variable that stores information about our sever
    thisServer.name = GROUP;
    thisServer.port = argv[1];
    thisServer.ip = inet_ntoa(getLocalIpAddr("8.8.8.8"));

    // Setup sockets for server to listen to
    listenSock = open_socket(atoi(argv[1]));			// Socket for clients
    listenLocalSock = open_socket(PORT);				// Socket for severs
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
	// Variables to set timeout for select()
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
        // Select has timed out and keepalive message is sent to all our connected servers
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
          			// Reset timer for timeout
                    time->tv_sec = 60;
        }
        else
        {
            // First, accept any new client connections to the server on the listening socket
            if (FD_ISSET(listenLocalSock, &readSockets))
            {
                clientSock = accept(listenLocalSock, (struct sockaddr *)&client,
                                    &clientLen);
                printf("Client trying connection:ip :%s  port :%u\n", inet_ntoa(client.sin_addr), htons(client.sin_port));
                
                int bytesRecv;
                usleep(500);
                // Check if the connecting client sends us the correct authentication string
                // If nothing is received or the wrong string is received client is not added to our list of open sockets
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
            // Accept new server connection
            if (FD_ISSET(listenSock, &readSockets) && servers.size() < 5)
            {
                serverSock = accept(listenSock, (struct sockaddr *)&server,
                                    &clientLen);
                printf("accept server connection ip :%s  port :%u\n", inet_ntoa(server.sin_addr), htons(server.sin_port));
                // Add new server to the list of open sockets
                FD_SET(serverSock, &openSockets);

                // And update the maximum file descriptor
                maxfds = std::max(maxfds, serverSock);

                // Add the new server to our map of connected servers
                servers[serverSock] = new Server(serverSock, inet_ntoa(server.sin_addr), std::to_string(htons(server.sin_port)));
                // Respond with listservers command to the new server
                std::string msg;
                std::string group(GROUP);
                msg = '\x01';
                msg += "LISTSERVERS," + group;
                msg += '\x04';
                send(serverSock, msg.c_str(), msg.length(), 0);
                n--;

                printf("server connected on server: %d\n", serverSock);
            }
            // Now check for commands from clients and servers
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
                // Loop through our connected servers to match the socket that has something for us
                for (auto const &pair : servers)
                {
                    Server *server = pair.second;
					// Check if the server socket has something for us
                    if (FD_ISSET(server->sock, &readSockets))
                    {     
                        memset(buffer, 0, sizeof(buffer));
                        int bytesRecv;
                        // Close server if nothing is received
                        if ((bytesRecv = recv(server->sock, buffer, sizeof(buffer), MSG_DONTWAIT)) == 0)
                        {
                            printf("Server closed connection: %s", servers[server->sock]->name.c_str());
                            close(server->sock);

                            closeServer(server->sock, &openSockets, &maxfds);
                        }
                        else
                        {
                            // Check if the message received from a server is in the right format, with right start and end characters
                            if ((buffer[0] == '\x01') && (buffer[bytesRecv - 1] == '\x04'))
                            {
								// Vector to store tokens parsed from the buffer received
                                std::vector<std::string> tokens;
                                std::string token;

                                // Split command from client into tokens for parsing
                                std::stringstream stream(buffer);
                                while (stream.good())
                                {
                                    // If we receive two legitimate commands in one buffer we split them apart
                                    getline(stream, token, '\x04');
                                    if (strlen(token.c_str()) > 0)
                                    {
                                        tokens.push_back(token);
                                    }
                                }
                                // For every command parsed from the buffer we send it to server command
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

