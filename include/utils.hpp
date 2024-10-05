#ifndef UTILS_H_e8e5c3edd642059b2482967828fa8d2bc0dd2f6dd9ac2b18d70ff7d346f54065
#define UTILS_H_e8e5c3edd642059b2482967828fa8d2bc0dd2f6dd9ac2b18d70ff7d346f54065

#include <limits.h>
#include <stdlib.h>

/* ANSI color escape sequences */
#ifdef COLOR
#define GREEN(str)	"\033[1;32m" str "\033[0m"
#define RED(str)	"\033[1;91m" str "\033[0m"
#define YELLOW(str)	"\033[1;93m" str "\033[0m"
#define MAGENTA(str)	"\033[1;95m" str "\033[0m"
#else
#define GREEN(str)	str
#define RED(str)	str
#define YELLOW(str)	str
#define MAGENTA(str)	str
#endif

#define str(arg)  xstr(arg)
#define xstr(arg) #arg

#ifdef DEBUG
#define DPRINTF(...)                                                                       \
	do {                                                                               \
		fprintf(stderr, "[" MAGENTA("DBG") " " __FILE__ ":" str(__LINE__) "] "); \
		fprintf(stderr, __VA_ARGS__);                                              \
	} while (0)
#else
#define DPRINTF(...) do { } while (0)
#endif

/*! @returns INT_MIN when str is not fully convertable to a number */
static inline int stoi(const char *str) {
	char *endptr;
	long ret = strtol(str, &endptr, 10);
	if (!(endptr != NULL && *endptr == '\0'))
		return INT_MIN;
	return ret;
}

#endif
