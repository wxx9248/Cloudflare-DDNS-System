#include <stdlib.h>
#include <string.h>
#include <Windows.h>

#define ABS(x)		((x) < 0 ? -(x) : (x))

int main(int argc, char *argv[])
{
	int msSleep = 0;
	
	if (argc != 2 && !argv[1])
		return -1;
	
	msSleep = atoi(argv[1]);
	msSleep = ABS(msSleep);
	Sleep(msSleep);
	
	return 0;
}
