from idaapi import *
import idautils


ea = idc.get_inf_attr(INF_MIN_EA)

for seg in idautils.Segments():
 start = idc.get_segm_start(ea)
 end = idc.get_segm_end(ea)


def fixDridex(start, end):
    for address in xrange(start, end + 1):
     new_address = next_addr(address)
     print "Processing Address " +  hex(new_address)
     if get_byte(new_address) == 0xCC :
      patch_byte(new_address, 0xFF)
      print "Patching INT 3 at " + hex(new_address)
     else: 
         if get_byte(new_address) == 0xC3:
          patch_byte(new_address, 0xD0)
          print "Patching RET at " +  hex(new_address)
         else:
           print "No Anti-Analysis Detected " 



fixDridex(start, end)
