// Signatus - Vulnerable C++ server
// Created while preparing for OSED
// William Moody, 12.06.2021

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctime>

#pragma comment (lib, "ws2_32.lib")

#define DEFAULT_BUFLEN 2048
#define DEFAULT_PORT "9999"
#define OTD_SECRET 0x74829726
#define LOG_PATH "C:\\Users\\Public\\signatus.log"

using namespace std;

/**
 * Calls the correct code depending on the opcode passed
 */
void handleOpcode(SOCKET ClientSocket, DWORD opcode)
{
	try
	{
		if (opcode == 0x1)
		{
			// Add to log file
			char recvbuf[DEFAULT_BUFLEN];
			// Receive the buffer
			int recvlen;
			if ((recvlen = recv(ClientSocket, recvbuf, DEFAULT_BUFLEN - 1, 0)) == SOCKET_ERROR)
			{
				printf("    > handleOpcode(1) failed while receiving buffer.\n");
				return;
			}

			// Open the log file
			FILE* fp;
			if ((fp = fopen(LOG_PATH, "a")) == NULL)
			{
				printf("    > handleOpcode(1) failed during fopen.\n");
				return;
			}

			// Write buffer to the log file
			recvbuf[recvlen] = 0;

			fprintf(fp, "%s", recvbuf);
			fflush(fp);
			printf("    > wrote buffer to %s.\n", LOG_PATH);

			// Close the log file
			fclose(fp);
		}
		else if (opcode == 0x2)
		{
			// Get last line from log file
			FILE* fp;
			if ((fp = fopen(LOG_PATH, "r")) == NULL)
			{
				printf("    > handleOpcode(2) failed during fopen.\n");
				return;
			}

			// Scan until last line
			char line[DEFAULT_BUFLEN] = { 0 };
			while (fscanf(fp, "%[^\n]\n", line) != EOF);

			// Send last line to client
			if (send(ClientSocket, line, strlen(line), 0) == SOCKET_ERROR)
			{
				printf("    > handleOpcode(2) failed during send.\n");
				return;
			}

			fclose(fp);
		}
		else if (opcode == 0x3)
		{
			// Clear log file
			FILE* fp;
			if ((fp = fopen(LOG_PATH, "w")) == NULL)
			{
				printf("    > handleOpcode(3) failed during fopen.\n");
				return;
			}

			fprintf(fp, "");
			fflush(fp);
			fclose(fp);
			printf("    > cleared %s.\n", LOG_PATH);
		}
	}
	catch (...)
	{
		printf("    > handleOpcode(%d) failed due to an exception\n", opcode);
		return;
	}
}

/**
 * Generates a one time dword to prove to the server that
 * the packet is coming from someone that it should come from.
 *
 * Changes every 10 seconds.
 */
DWORD getOTD()
{
	time_t seconds = time(0);
	WORD s = (seconds / 10) & 0xff;
	DWORD sec_d = s | (((s * s) >> 4) << 8)
		| (((s * s * s) >> 8) << 16) | (((s * s * s * s) >> 12) << 24);
	return sec_d ^ OTD_SECRET;
}

/**
 * Receives a DWORD from a given socket
 */
int recvDword(SOCKET ClientSocket, DWORD* pDword)
{
	// Buffer to receive OTD and OPCODE
	char recvbuf[4];
	memset(recvbuf, 0, 4);

	// Receive packet from client (should contain dword)
	int recvlen;
	if ((recvlen = recv(ClientSocket, recvbuf, sizeof(DWORD), 0)) == SOCKET_ERROR)
	{
		closesocket(ClientSocket);
		return 1;
	}

	// Check if we got 4 bytes
	if (recvlen != sizeof(DWORD))
	{
		closesocket(ClientSocket);
		return 1;
	}

	// Convert the received buffer to a dword
	*pDword = ((recvbuf[3] << 24) & 0xff000000) | ((recvbuf[2] << 16) & 0xff0000)
		| ((recvbuf[1] << 8) & 0xff00) | (recvbuf[0] & 0xff);

	return 0;
}

/**
 * Thread which handles a client connection
 */
DWORD WINAPI handleConnection(LPVOID ClientSocket)
{
	DWORD recv_otd;
	if (recvDword((SOCKET)ClientSocket, &recv_otd) != 0)
	{
		printf("    > recvDword (otd) failed.\n");
		closesocket((SOCKET)ClientSocket);
		return 1;
	}

	// Check if the otd is correct
	if (recv_otd != getOTD())
	{
		printf("    > received incorrect OTD (Badly formed packet).\n");
		closesocket((SOCKET)ClientSocket);
		return 1;
	}
	printf("    > correct OTD received.\n");

	// Receive the next 4 bytes (opcode)
	DWORD opcode;
	if (recvDword((SOCKET)ClientSocket, &opcode) != 0)
	{
		printf("   > recvDword (opcode) failed.\n");
		closesocket((SOCKET)ClientSocket);
		return 1;
	}

	// Call the correct code depending on opcode
	printf("    > received opcode %d.\n", opcode);
	handleOpcode((SOCKET)ClientSocket, opcode);

	// Shutdown the connection when we're done
	if (shutdown((SOCKET)ClientSocket, SD_SEND) == SOCKET_ERROR)
	{
		printf("    > shutdown failed with code %d\n", WSAGetLastError());
		closesocket((SOCKET)ClientSocket);
		return 1;
	}

	closesocket((SOCKET)ClientSocket);
	return 0;
}

/**
 * Entrypoint of the program. Sets up WSA and main accept loop.
 * Calls threads for each connection.
 */
int main(int argc, char* argv[])
{
	WSADATA wsaData;
	int iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo* result = NULL;
	struct addrinfo hints;

	// Initialize Winsock
	if ((iResult = WSAStartup(0x22, &wsaData)) != 0)
	{
		printf("[-] WSAStartup failed with code %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	if ((iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result)) != 0)
	{
		printf("[-] getaddrinfo failed with code %d\n", iResult);
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for connecting to server
	if ((ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) == INVALID_SOCKET)
	{
		printf("[-] socket failed with code %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	if ((iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen)) == SOCKET_ERROR)
	{
		printf("[-] bind failed with code %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	if ((iResult = listen(ListenSocket, SOMAXCONN)) == SOCKET_ERROR)
	{
		printf("[-] listen failed with code %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	printf("[+] Listening on port %s...\n", DEFAULT_PORT);

	// Accept a client socket
	while ((ClientSocket = accept(ListenSocket, NULL, NULL)) != INVALID_SOCKET)
	{
		printf("[+] Client connected...\n");

		// Create a thread to handle the client connection
		HANDLE hThread;
		if ((hThread = CreateThread(NULL, 0, handleConnection, (LPVOID)ClientSocket, 0, NULL)) == NULL)
		{
			printf("[-] CreateThread failed with code %d\n", GetLastError());
			CloseHandle(hThread);
			closesocket(ClientSocket);
			WSACleanup();
			return 1;
		}

		// Cleanup after thread
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}

	// Failed to accept a connection
	printf("[-] accept failed with code %d\n", WSAGetLastError());
	closesocket(ListenSocket);
	WSACleanup();
	return 1;
}