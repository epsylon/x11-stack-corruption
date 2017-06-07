=================================================================== 

 X11/libX11.so.6 (XQueryKeymap) Stack corruption/Access violation [PoC+ Fuzzer]

    - 0day: 03/06/2017
    - Vulnerable (tested) library: libx11-6 / Version: 2:1.6.4-3
    - Debian package: libx11-6_1.6.4-3_amd64.deb (8ad41adbd147ffe4bf64c50efcac497b) 
    - Tested at: Intel/x86_64 - Debian 4.9.25-1 (stretch)

----------

The XQueryKeymap() function returns a bit vector for the logical state of the keyboard, where each bit set to 1 indicates that the corresponding key is currently pressed down. The vector is represented as 32 bytes. Byte N (from 0) contains the bits for keys 8N to 8N + 7 with the least-significant bit in the byte representing key 8N. 

    XQueryKeymap(display, keys_return)
       Display *display;
       char keys_return[32];

--------

#### Vulnerable code (example):

    #!/usr/bin/python
    import ctypes as ct
    from ctypes.util import find_library
    x11 = ct.cdll.LoadLibrary(find_library("X11"))
    display = x11.XOpenDisplay(None)
    print "CT.C:", ct.c_char * 16
    keyboard = (ct.c_char * 16)()
    print "Display:", display
    x11.XQueryKeymap(display, keyboard)
