/* 
 * File name : clrscr.c
 * API description : Has the same effect as system("cls");.
 * Author : wxx9248
 */

#include <windows.h>

__declspec(dllexport) void clrscr(void);

void clrscr(void)
{
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD coordScreen = {0, 0};	// When cleared, set back to (0, 0)
	DWORD cCharsWritten;
	CONSOLE_SCREEN_BUFFER_INFO csbi;	// Save the buffer info
	DWORD dwConSize;	// How many chars can be contained ? This is set in line 28.

	GetConsoleScreenBufferInfo(hStdOut, &csbi);
	dwConSize = csbi.dwSize.X * csbi.dwSize.Y;	// Line 28
	FillConsoleOutputCharacter(hStdOut, (TCHAR)' ', dwConSize, coordScreen, &cCharsWritten);	// Fill in the blanks
	GetConsoleScreenBufferInfo(hStdOut, &csbi);
	FillConsoleOutputAttribute(hStdOut, csbi.wAttributes, dwConSize, coordScreen, &cCharsWritten);
	SetConsoleCursorPosition(hStdOut, coordScreen);	// Back to (0, 0)
}
