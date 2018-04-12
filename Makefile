most: format

#test:
#	c++-7 test.c -Wall -Wextra -Werror -pedantic -o Sharlotte256Test
#	./Sharlotte256Test
#	rm Sharlotte256Test

#clean:
#	rm Sharlotte256

format:
	clang-format -i -verbose -style="{BasedOnStyle: Google, UseTab: Always, IndentPPDirectives: AfterHash}" sha256.cpp Sharlotte256.c test.c Sharlotte256.h
