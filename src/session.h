#ifndef SESSION_INCLUDED
#define SESSION_INCLUDED

#include <chttp.h> // Only for HTTP_String

typedef struct SessionStorage SessionStorage;

SessionStorage *session_storage_init(int max_sessions);
void            session_storage_free(SessionStorage *storage);

int create_session(SessionStorage *storage, int user, HTTP_String *psess, HTTP_String *pcsrf);
int delete_session(SessionStorage *storage, HTTP_String sess);
int find_session(SessionStorage *storage, HTTP_String sess, HTTP_String *pcsrf, int *puser);

#endif // SESSION_INCLUDED
