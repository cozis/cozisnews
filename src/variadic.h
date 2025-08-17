#ifndef VARIADIC_INCLUDED
#define VARIADIC_INCLUDED

#include <stdbool.h>
#include "chttp.h"

typedef enum {
    VARG_TYPE_C,
    VARG_TYPE_S,
    VARG_TYPE_I,
    VARG_TYPE_L,
    VARG_TYPE_LL,
    VARG_TYPE_SC,
    VARG_TYPE_SS,
    VARG_TYPE_SI,
    VARG_TYPE_SL,
    VARG_TYPE_SLL,
    VARG_TYPE_UC,
    VARG_TYPE_US,
    VARG_TYPE_UI,
    VARG_TYPE_UL,
    VARG_TYPE_ULL,
    VARG_TYPE_F,
    VARG_TYPE_D,
    VARG_TYPE_B,
    VARG_TYPE_STR,
} VArgType;

typedef struct {
    VArgType type;
    union {
        char c;
        short s;
        int i;
        long l;
        long long ll;
        signed char sc;
        signed short ss;
        signed int si;
        signed long sl;
        signed long long sll;
        unsigned char uc;
        unsigned short us;
        unsigned int ui;
        unsigned long ul;
        unsigned long long ull;
        float f;
        double d;
        bool b;
        HTTP_String str;
    };
} VArg;

VArg varg_from_c   (char c);
VArg varg_from_s   (short s);
VArg varg_from_i   (int i);
VArg varg_from_l   (long l);
VArg varg_from_ll  (long long ll);
VArg varg_from_sc  (char sc);
VArg varg_from_ss  (short ss);
VArg varg_from_si  (int si);
VArg varg_from_sl  (long sl);
VArg varg_from_sll (long long sll);
VArg varg_from_uc  (char uc);
VArg varg_from_us  (short us);
VArg varg_from_ui  (int ui);
VArg varg_from_ul  (long ul);
VArg varg_from_ull (long long ull);
VArg varg_from_f   (float f);
VArg varg_from_d   (double d);
VArg varg_from_b   (bool b);
VArg varg_from_str (HTTP_String str);

#define VARG(X) (_Generic((X),   \
    char              : varg_from_c,   \
    short             : varg_from_s,   \
    int               : varg_from_i,   \
    long              : varg_from_l,   \
    long long         : varg_from_ll,  \
    signed char       : varg_from_sc,  \
    /*signed short      : varg_from_ss,*/ \
    /*signed int        : varg_from_si,*/ \
    /*signed long       : varg_from_sl,*/ \
    /*signed long long  : varg_from_sll,*/ \
    unsigned char     : varg_from_uc,  \
    unsigned short    : varg_from_us,  \
    unsigned int      : varg_from_ui,  \
    unsigned long     : varg_from_ul,  \
    unsigned long long: varg_from_ull, \
    float             : varg_from_f,   \
    double            : varg_from_d,   \
    bool              : varg_from_b,   \
    HTTP_String       : varg_from_str  \
))(X)

typedef struct {
    int   len;
    VArg *ptr;
} VArgs;

#define VARGS_1(a)             (VArgs) {1, (VArg[]) { VARG(a) } }
#define VARGS_2(a, b)          (VArgs) {2, (VArg[]) { VARG(a), VARG(b) } }
#define VARGS_3(a, b, c)       (VArgs) {3, (VArg[]) { VARG(a), VARG(b), VARG(c) } }
#define VARGS_4(a, b, c, d)    (VArgs) {4, (VArg[]) { VARG(a), VARG(b), VARG(c), VARG(d) } }
#define VARGS_5(a, b, c, d, e) (VArgs) {5, (VArg[]) { VARG(a), VARG(b), VARG(c), VARG(d), VARG(e) } }

#define DISPATCH__(_1, _2, _3, _4, _5, NAME, ...) NAME
#define VARGS(...) DISPATCH__(__VA_ARGS__, VARGS_5, VARGS_4, VARGS_3, VARGS_2, VARGS_1)(__VA_ARGS__)

#endif // VARIADIC_INCLUDED