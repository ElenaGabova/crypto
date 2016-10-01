#ifndef MACROS_H_
#define MACROS_H_

#ifndef FALSE
#define FALSE	0
#endif
#ifndef TRUE
#define TRUE	(!FALSE)
#endif

#define ARRAY_SIZE(x)	(sizeof(x)/sizeof((x)[0]))

#ifndef NDEBUG
#define DEBUG_ONLY(x)	x
#else
#define DEBUG_ONLY(x)	
#endif

#ifndef NDEBUG
#endif 
#endif

