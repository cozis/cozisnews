#include "variadic.h"

VArg varg_from_c   (char c)          { return (VArg) { VARG_TYPE_C,   .c=c     }; }
VArg varg_from_s   (short s)         { return (VArg) { VARG_TYPE_S,   .s=s     }; }
VArg varg_from_i   (int i)           { return (VArg) { VARG_TYPE_I,   .i=i     }; }
VArg varg_from_l   (long l)          { return (VArg) { VARG_TYPE_L,   .l=l     }; }
VArg varg_from_ll  (long long ll)    { return (VArg) { VARG_TYPE_LL,  .ll=ll   }; }
VArg varg_from_sc  (char sc)         { return (VArg) { VARG_TYPE_SC,  .sc=sc   }; }
VArg varg_from_ss  (short ss)        { return (VArg) { VARG_TYPE_SS,  .ss=ss   }; }
VArg varg_from_si  (int si)          { return (VArg) { VARG_TYPE_SI,  .si=si   }; }
VArg varg_from_sl  (long sl)         { return (VArg) { VARG_TYPE_SL,  .sl=sl   }; }
VArg varg_from_sll (long long sll)   { return (VArg) { VARG_TYPE_SLL, .sll=sll }; }
VArg varg_from_uc  (char uc)         { return (VArg) { VARG_TYPE_UC,  .uc=uc   }; }
VArg varg_from_us  (short us)        { return (VArg) { VARG_TYPE_US,  .us=us   }; }
VArg varg_from_ui  (int ui)          { return (VArg) { VARG_TYPE_UI,  .ui=ui   }; }
VArg varg_from_ul  (long ul)         { return (VArg) { VARG_TYPE_UL,  .ul=ul   }; }
VArg varg_from_ull (long long ull)   { return (VArg) { VARG_TYPE_ULL, .ull=ull }; }
VArg varg_from_f   (float f)         { return (VArg) { VARG_TYPE_F,   .f=f     }; }
VArg varg_from_d   (double d)        { return (VArg) { VARG_TYPE_D,   .d=d     }; }
VArg varg_from_b   (bool b)          { return (VArg) { VARG_TYPE_B,   .b=b     }; }
VArg varg_from_str (HTTP_String str) { return (VArg) { VARG_TYPE_STR, .str=str }; }
