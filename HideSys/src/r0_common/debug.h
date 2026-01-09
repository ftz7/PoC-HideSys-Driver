#ifdef DBGMSG_FULL

void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...);
void DbgClose(void);
void DbgInit(void);

#else 

#define DbgMsg
#define DbgClose
#define DbgInit

#endif 

#ifdef DBGPIPE
void DbgOpenPipe(void);
void DbgClosePipe(void);
#endif

#ifdef DBGLOGFILE
void DbgOpenLogFile(void);
#endif

void DbgHexdump(PUCHAR Data, ULONG Length);
