PROJNAME	= Cloudflare DDNS System Auxiliaries
AUTHOR		= wxx9248

CC			= gcc
MAKE 		= make

SOURCE1 	= Sleep
SOURCE2		= isIPv4OK

FLAGS		= -std=c11 -s -O3

all :
	$(CC) $(FLAGS) -o $(SOURCE1).exe $(SOURCE1).c
	$(CC) $(FLAGS) -o $(SOURCE2).exe $(SOURCE2).c
	
clean :
	@rm -rf *.exe

love :
	@echo "Dude...I can't *MAKE* this."
	@echo "YOU SHOULD DEPEND ON YOUR OWN."
	@echo "Best wishes."
