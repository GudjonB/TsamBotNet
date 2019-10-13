# Project 3: The Botnet Rises

The program consists of a server and client. The server can be executed on the botnet on skel.ru.is to communicate with other servers running there through a common API. The server can only accept connection with the accompanied client, and commands that can be executed on the server have to be initiated through client.

## Technical information

The program was built and run on linux but should work on mac as well.

## Description

The server has all the commands listed in the project description implemented, and they have to be initiated through the client. When the client is connected to the server, it can execute the commands as follows:

CONNECT <name>  

> Give your client a name 

WHO 
> Send all connected clients

LEAVE
> Disconnect your client from the server

LEAVE <ServerName>
> Disconnect from server with **ServerName**

LEAVE <Ip> <Port>
> Disconnect from server with this **Ip** and **Port**

MSG ALL <Message>
> Send **Message** to all connected clients

MSG <ClientName> <Message>
> Send **Message** to client with **ClientName**

SENDMSG FORWARD <ThroughServer> <ToServer> <Message>
> Send **Message** to server **ThroughServer** to route to server **ToServer**

SENDMSG SECRET <ServerName> <Message>
> Send **Message** to **ServerName** with only the name of the server sending

SENDMSG ALL <Message>
> Send **Message** to all connected servers

SENDMSG <ServerName> <Message>
> Send **Message** to **ServerName**

GETMSG <ServerName>
> Sends a get message request to all connected servers for **ServerName**

GETMSG FROM <ServerName>
> Sends a get message request to **ServerName** for this server

SERVER <Ip> <Port>
> Tries to connect to a server with **Ip** address and **Port** number

LISTSERVERS
> Client requests a list of connected servers to his server

LISTSERVERS <ServerName>
> Sends a request for list of connected servers connected to **ServerName**

STATUSREQ <ServerName>
> Sends a status request to **ServerName**

# Compile and Run
#### Input format for server: `./tsamvgroup96 <port>`
#### Input format for client: `./client <ip> <port>`

1. Unpack the assignment in a directory of your choice
2. Open a terminal in the directory
3. Write `make` in the terminal to compile the project
4. Write `make run` 
