#!/usr/bin/python3

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
        machine = r.cmdj('ij')['bin']['os']
        
        #Sometimes you can get away with using less analysis on non-windows platforms, but only sometimes
        if machine == "windows":
            r.cmd("aaa")
        else:
            r.cmd("aaa")

    debugging = ( ('pid' in r.cmdj("dij")) and (r.cmdj("dij")['pid']) > -1)
    machine = r.cmdj("ij")['bin']['os']


    #sadly, output is not consistent between iij and afi, so afl must be used
    #imports = r.cmdj("iij")
    funcs = r.cmdj("aflj")

    if funcs is None or len(funcs) < 1:
        print("No functions detected. Have you run 'aaa'?")
        return

    bad_funcs = []

    print("\nCollecting banned functions...")

    #First, collect all imports which are banned functions
    #linux and windows have different 'gotchas' in the naming convention, so they are split up
    if machine == 'linux' or machine == 'osx':
        for func in funcs:
            for banned in bannedList:
                if banned in func['name'].split(".")[-1].split("_") and "_chk" not in func['name'].split(".")[-1]:
                    bad_funcs.append(func)
    elif machine == 'windows':
        for func in funcs:
            for banned in bannedList:
                if banned in func['name'].split(".")[-1].split("_"):
                    bad_funcs.append(func)
    else:
        print("OS %s not currently supported" % machine)
        return



    if len(bad_funcs) == 0:
        print("\nNo banned functions found")
        return

    print("\n%d banned function(s) found:" % len(bad_funcs))

    for func in bad_funcs:
        print("* %s" % func['name'])

    if debugging:
        print("\nCurrently debugging, adding breakpoints...")
    else:
        print("\nNot currently debugging, no breakpoints will be added.")

    for func in bad_funcs:
        print("\n===%s:" % func['name'])
        try:
            for xref in func['codexrefs']:
                if xref['type'] == "C":
                    print("Called at 0x%x" % xref['addr'])
                    if debugging:
                        #TODO: Some error handling and reporting
                        r.cmd('db 0x%x' %xref['addr'])
                        print("Breakpoint added!")
        except KeyError:
             print("\nERROR: function %s found with no codexrefs. May need to run 'aaa'." % func['name'])
             

#hack for determining if we're in radare or not
if 'argv' in sys.__dict__:
    main(sys.argv)
else:
    main([])


