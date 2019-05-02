#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <Windows.h>

bool isStrNum(char *str)
{
	bool flag = true;
	for (int i = 0; str[i]; ++i)
	{
		if (!isdigit(str[i]))
			return false;
	}
	return flag;
}

int main(int argc, char *argv[])
{
	int i = 0;
	char *p = NULL;
	
	if (argc != 2 && !argv[1])
		return 1;
	
	p = strtok(argv[1], ".");
	while (p && isStrNum(p))
	{
		++i;
		p = strtok(NULL, ".");
	}
	
	if (i == 4)
		return 0;
	else
		return 1;
}
