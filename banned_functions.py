#!/usr/bin/python

#this script uses r2pipe for communicating with radare2. 'pip install r2pipe' should suffice

import r2pipe, sys


bannedList = (["strcpy", "strcpyA", "strcpyW", "wcscpy", "_tcscpy", "_mbscpy", "StrCpy",
       "StrCpyA", "StrCpyW", "lstrcpy", "lstrcpyA", "lstrcpyW", "_tccpy", "_mbccpy",
       "_ftcscpy", "strcat", "strcatA", "strcatW", "wcscat", "_tcscat", "_mbscat",
       "StrCat", "StrCatA", "StrCatW", "lstrcat", "lstrcatA", "lstrcatW", "StrCatBuff",
       "StrCatBuffA", "StrCatBuffW", "StrCatChainW", "_tccat", "_mbccat", "_ftcscat",
       "sprintfW", "sprintfA", "wsprintf", "wsprintfW", "wsprintfA", "sprintf", "swprintf",
       "_stprintf", "wvsprintf", "wvsprintfA", "wvsprintfW", "vsprintf", "_vstprintf",
       "vswprintf", "strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy", "StrCpyN",
       "StrCpyNA", "StrCpyNW", "StrNCpy", "strcpynA", "StrNCpyA", "StrNCpyW", "lstrcpyn",
       "lstrcpynA", "lstrcpynW", "strncat", "wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat",
       "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW", "lstrncat",
       "lstrcatnA", "lstrcatnW", "lstrcatn", "gets", "_getts", "_gettws", "IsBadWritePtr",
       "IsBadHugeWritePtr", "IsBadReadPtr", "IsBadHugeReadPtr", "IsBadCodePtr", "IsBadStringPtr"])


#Wrap this in a function for exiting without quitting radare
def main(args):

    r = r2pipe.open()

    if (len(args) > 1):
        r = r2pipe.open(args[1])

    r.cmd("aaa")

    debugging = r.cmdj("dij")['stopreason']

    #sadly, output is not consistent between iij and afi, so afl must be used
    #imports = r.cmdj("iij")
    funcs = r.cmdj("aflj")

    if len(funcs) < 1:
        print("No functions detected. Have you run 'aa' yet?")
        return

    print(funcs)

    bad_funcs = []

    print("\nCollecting banned functions...")

    #First, collect all imports which are banned functions
    for func in funcs:
        for banned in bannedList:
            if banned in func['name']:
                bad_funcs.append(func)

    if len(bad_funcs) == 0:
        print("\nNo banned functions found")
        return

    print("\n%d banned function(s) found:" % len(bad_funcs))

    for func in bad_funcs:
        print("* %s" % func['name'])

    if debugging > -1:
        print("\nCurrently debugging, adding breakpoints...")
    else:
        print("\nNot currently debugging, no breakpoints will be added.")

    for func in bad_funcs:
        print("\n===%s:" % func['name'])
        for xref in func['codexrefs']:
            print("Called at 0x%x" % xref['addr'])
            if debugging > -1:
                #TODO: Some error handling and reporting
                r.cmd('db 0x%x' %xref['addr'])
                print("Breakpoint added!")


#hack for determining if we're in radare or not
if 'argv' in sys.__dict__:
    main(sys.argv)
else:
    main([])
