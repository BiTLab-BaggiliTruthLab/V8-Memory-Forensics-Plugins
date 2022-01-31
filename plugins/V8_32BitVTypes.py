import volatility.obj as obj
import volatility.plugins.common as common
import volatility.plugins.malware.malfind as malfind
import volatility.utils as utils
import volatility.win32 as win32

import volatility.plugins.addrspaces as addrspaces
import sys
import re

from volatility.renderers import TreeGrid

import json
import re
import base64
import ntpath
import csv
import binascii
import struct

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

word_size = 8
WORD_SIZE = 4
DWORD_SIZE = WORD_SIZE * 2
ISOLATE_PTR_OFFSETS = [0x0, 0x38, 0x0, 0x10]
ROOT_SET_OFFSET = 0x10 * DWORD_SIZE
META_MAP_OFFSET = 0xA * DWORD_SIZE
PAGE_SIZE = 0x1000

YARA_opcodes = {
    'opcodes':
        'rule opcodes { \
        strings: $p = { ff 03 (40 | 20) 00 } \
        condition: $p \
    }'
}


# Helper functions ================================================================================ 
def read_word(raw_word):
    return struct.unpack("<I", raw_word)[0]


def read_double_word(raw_double_word):
    return struct.unpack("<Q", raw_double_word)[0]


class BinaryScanVtype(common.AbstractWindowsCommand):

    def init(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.init(self, config, *args, **kwargs)
        config.add_option('OUTDIR', short_option='Z', default=None,
                          help='outfile')

    def calculate(self):
        rules_opcodes = yara.compile(sources=YARA_opcodes)
        rulesets = [rules_opcodes]
        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)
        maps = []
        not_maps = []
        metamaps = []

        for task in tasks:
            #if str(task.ImageFileName) != 'node.exe':
            if str(task.ImageFileName) != 'Discord.exe':
                continue
            else:
                print("Scanning {0} pid: {1}".format(task.ImageFileName, task.UniqueProcessId))
                
                proc_addr_space = task.get_process_address_space()
                print(proc_addr_space)
                original_stdout = sys.stdout
                  
                with open('temp.txt', 'w') as f:
                    sys.stdout = f 
                    print(proc_addr_space)
                    sys.stdout = original_stdout
                    
                basestring = ''
                with open('temp.txt', 'r') as f:
                    basestring = f.readline()
                
                result = re.search('0x(.*)>', basestring)
                base = result.group(1)
                
                scanner = malfind.DiscontigYaraScanner(proc_addr_space, rulesets)
                addresss = 0x000
                hits = 0
                
                print(base)
                intbase = int(base, 16)

                addresslist = []
                
                for hit_obj, offset in scanner.scan():
                    address = offset
                    #print("Opcode address: " + str(hex(address)))

                    #raw_data = proc_addr_space.zread(address, DWORD_SIZE)  # This is for 64-bit
                    raw_data = proc_addr_space.zread(address, WORD_SIZE)    # This is for 32-bit    # This is the match
                    #print("Address data: " + hex(read_word(raw_data)))

                    #address = address - 18      # What is this 18???? There are 16 bytes between BIT_FIELD3 and the start of the Map on 64-bit arch
                    address = address - 12       # *** THIS WORKS ON 32-bit ***
                    #meta_map_ptr = proc_addr_space.zread(address, DWORD_SIZE)  # This is for 64-bit
                    meta_map_ptr = proc_addr_space.zread(address, WORD_SIZE)    # This is for 32-bit
                    #print("Value Ptr: " + str(hex(read_word(meta_map_ptr))))
                    #print ""

                    #addresslist.append(hex(read_double_word(meta_map_ptr)))    # This is for 64-bit
                    addresslist.append(hex(read_word(meta_map_ptr)))            # This is for 32-bit

                    hits += 1

                print "\n*** Got {} hits!***\n".format(hits)
                    
                dup = [x for i, x in enumerate(addresslist) if i != addresslist.index(x)]
                #print(dup)

                # TODO: Remove
                #for d in dup:
                    #print dup
                print "Done processing matches"
                # 0x   f2ec0169
                # 0x356f2ec0169
                #sys.exit(1)
                
                str_meta_map = dup[0]
                str_meta_map = str_meta_map[:13]
                #print(str_meta_map)
                
                address = int(str_meta_map, 16)
                address = address - 1
                print("Meta Map Address: " + str(hex(address)))
                #raw_data = proc_addr_space.zread(address, DWORD_SIZE)  # This is for 64-bit
                raw_data = proc_addr_space.zread(address, WORD_SIZE)    # This is for 32-bit
                print("New Meta Map Value : " + hex(read_word(raw_data)))   # This is for 64-bit
                #print("New Meta Map Value : " + hex(read_word(raw_data)))           # This is for 32-bit

                # Vtype stuff below ===============================================================
                if read_word(raw_data) == 0x0:
                    print "MetaMap not found in this process.  Continuing."
                    continue

                # Read meta map into vtype
                try:
                    print("\n\nParsing meta map into vtype object:")
                    map_obj = V8Map(address, proc_addr_space, arch=32) 
                    map_vtype_obj = map_obj.get_vtype_obj()
                    if "NoneType" in str(type(map_vtype_obj)):
                        print("Fatal: Vtype not parsed")
                        sys.exit(1)
                    print("Successfully parsed meta map into vtype object")
                    print("")

                    # Print metamap vtype fields ======================================================
                    print("---- Printing map vtype info below ----\n")

                    print("\nStandard map print:")
                    print(map_obj)                  # Key info displayed

                    print("\nFull map print:")
                    print(map_obj.str_full())       # All bitfields displayed
                    print("")
                except Exception as ex:
                    print "ERROR PARSING INTO MAP OBJECT"


    def render_text(self, two, three):
        print('written without errors')


class V8Map(object):

    MAP_SIZE_64 = 10 * DWORD_SIZE
    MAP_SIZE_32 = 10 * WORD_SIZE

    # Sizes for other vtypes
    BIT_FIELD1_SIZE = 1
    BIT_FIELD2_SIZE = 1
    BIT_FIELD3_SIZE = 1 * WORD_SIZE

    # Offets for vtypes
    OFFSETS = dict()

    # 64-bit offsets
    OFFSETS["METAMAP_64"]          = 0 * DWORD_SIZE
    OFFSETS["INT1_64"]             = 1 * DWORD_SIZE
    OFFSETS["INT2_64"]             = OFFSETS["INT1_64"] + WORD_SIZE
    OFFSETS["INT3_64"]             = OFFSETS["INT2_64"] + WORD_SIZE
    OFFSETS["NULL_INT_64"]         = OFFSETS["INT3_64"] + WORD_SIZE
    OFFSETS["PROTOTYPE_64"]        = 3 * DWORD_SIZE
    OFFSETS["CTOR_64"]             = 4 * DWORD_SIZE
    OFFSETS["DESCRIPTORS_64"]      = 5 * DWORD_SIZE
    OFFSETS["LDESCRIPTORS_64"]     = 6 * DWORD_SIZE
    OFFSETS["DEPENDENT_64"]        = 7 * DWORD_SIZE
    OFFSETS["VALIDITY_64"]         = 8 * DWORD_SIZE
    OFFSETS["TRANSITIONS_64"]      = 9 * DWORD_SIZE
    OFFSETS["FIRST_DESC_ENTRY_64"] = 3 * DWORD_SIZE
    DESCRIPTOR_ENTRY_SIZE_64       = 3 * DWORD_SIZE
    OFFSETS["STRING_CHAR_64"]      = 2 * DWORD_SIZE 
    OFFSETS["STRING_SIZE_64"]      = 1 * DWORD_SIZE + WORD_SIZE
    STRING_SIZE_SIZE_64            = 1 * WORD_SIZE
    OFFSETS["SHARED_INFO_64"]      = 3 * DWORD_SIZE

    # 32-bit offsets
    OFFSETS["METAMAP_32"]           = 0 * WORD_SIZE
    OFFSETS["INT1_32"]              = 1 * WORD_SIZE 
    OFFSETS["INT2_32"]              = OFFSETS["INT1_32"] + WORD_SIZE
    OFFSETS["INT3_32"]              = OFFSETS["INT2_32"] + WORD_SIZE
    # OFFSETS["NULL_INT_32"] = None     # There is no null int with 32-bit versions of V8
    OFFSETS["PROTOTYPE_32"]        = 4 * WORD_SIZE
    OFFSETS["CTOR_32"]             = 5 * WORD_SIZE
    OFFSETS["DESCRIPTORS_32"]      = 6 * WORD_SIZE
    #OFFSETS["LDESCRIPTORS_32"]     = 6 * DWORD_SIZE    # TODO: This doesn't line up with map.h
    OFFSETS["DEPENDENT_32"]        = 7 * WORD_SIZE
    OFFSETS["VALIDITY_32"]         = 8 * WORD_SIZE
    OFFSETS["TRANSITIONS_32"]      = 9 * WORD_SIZE
    # TODO: Validate these don't need changes other than DWORD -> WORD when switching to 32-bit V8 
    OFFSETS["FIRST_DESC_ENTRY_32"] = 3 * WORD_SIZE
    DESCRIPTOR_ENTRY_SIZE_32       = 3 * WORD_SIZE
    OFFSETS["STRING_CHAR_32"]      = 2 * WORD_SIZE 
    OFFSETS["STRING_SIZE_32"]      = 1 * WORD_SIZE + WORD_SIZE
    STRING_SIZE_SIZE_32            = 1 * WORD_SIZE
    OFFSETS["SHARED_INFO_64"]      = 3 * WORD_SIZE

    V8MAP_VTYPES = {
        "_V8MAP_64_VTYPE": [MAP_SIZE_64, {
            # TODO: Create a tagged-pointer type to replace 'pointer'
            # Always points to MetaMap root
            "METAMAP":      [OFFSETS["METAMAP_64"],        ['pointer', ['_V8MAP_64_VTYPE']]],

            # Parse entire INT1 as well as the bitfields within
            # TODO: Make the bitfields vtypes themselves
            "INT1":             [OFFSETS["INT1_64"],       ['int']],
                "INSTANCE_SIZE":    [OFFSETS["INT1_64"],       ['BitField', {'end_bit': 7, 'start_bit': 0}]],
                "CTX_OR_PROPS":     [OFFSETS["INT1_64"],       ['BitField', {'end_bit': 15, 'start_bit': 8}]],
                "USED_OR_UNUSED":   [OFFSETS["INT1_64"],       ['BitField', {'end_bit': 23, 'start_bit': 16}]],
                "VISITOR_ID":       [OFFSETS["INT1_64"],       ['BitField', {'end_bit': 31, 'start_bit': 24}]],

            # Parse entire INT2 as well as the bitfields within
            # TODO: Make the bitfields vtypes themselves
            "INT2":             [OFFSETS["INT2_64"],       ['int']],
                "INSTANCE_TYPE":    [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 15, 'start_bit': 0}]],
                "BIT_FIELD":        [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 23, 'start_bit': 16}]],
                    "HAS_NON_INSTANCE_PROTOTYPE":       [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 16, 'start_bit': 16}]],
                    "IS_CALLABLE":                      [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 17, 'start_bit': 17}]],
                    "HAS_NAMED_INTERCEPTOR":            [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 18, 'start_bit': 18}]],
                    "HAS_INDEXED_INTERCEPTOR":          [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 19, 'start_bit': 19}]],
                    "IS_UNDETECTABLE":                  [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 20, 'start_bit': 20}]],
                    "IS_ACCESS_CHECK_NEEDED":           [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 21, 'start_bit': 21}]],
                    "IS_CONSTRUCTOR":                   [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 22, 'start_bit': 22}]],
                    "HAS_PROTOTYPE_SLOT":                [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 23, 'start_bit': 23}]],
                "BIT_FIELD2_RAW":   [OFFSETS["INT2_64"],           ['BitField', {'end_bit': 31, 'start_bit': 24}]],
                "BIT_FIELD2":       [OFFSETS["INT2_64"] + 3,       ['BIT_FIELD2_VTYPE']],
                    #"NEW_TARGET_IS_BASE":               [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 24, 'start_bit': 24}]],
                    #"IS_IMMUTABLE_PROTO":               [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 25, 'start_bit': 25}]],
                    #"ELEMENTS_KIND":                    [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 31, 'start_bit': 26}]],

            # Parse entire INT3 as well as the bitfields within
            # TODO: Make the bitfields vtypes themselves
            "INT3":         [OFFSETS["INT3_64"],           ['int']],
                "ENUM_LENGTH":              [OFFSETS["INT3_64"],       ['BitField', {'end_bit': 9, 'start_bit': 0}]],
                "NUM_OWN_DESCRIPTORS":      [OFFSETS["INT3_64"],       ['BitField', {'end_bit': 19, 'start_bit': 10}]],
                "IS_PROTOTYPE_MAP":         [OFFSETS["INT3_64"],       ['BitField', {'end_bit': 20, 'start_bit': 20}]],
                "IS_DICTIONARY_MAP":        [OFFSETS["INT3_64"],       ['BitField', {'end_bit': 21, 'start_bit': 21}]],
                "OWNS_DESCRIPTORS":         [OFFSETS["INT3_64"],       ['BitField', {'end_bit': 22, 'start_bit': 22}]],
                "IS_IN_RETAINED_MAP":       [OFFSETS["INT3_64"],       ['BitField', {'end_bit': 23, 'start_bit': 23}]],
                "IS_DEPRECATED":            [OFFSETS["INT3_64"],       ['BitField', {'end_bit': 24, 'start_bit': 24}]],
                "IS_UNSTABLE":              [OFFSETS["INT3_64"],       ['BitField', {'end_bit': 25, 'start_bit': 25}]],
                "IS_MIGRATION_TARGET":       [OFFSETS["INT3_64"],      ['BitField', {'end_bit': 26, 'start_bit': 26}]],
                # TODO: The v8.h documentation says:
                #   // |               |   - is_migration_target (bit 26)                |
                #   // |               |   - is_extensible (bit 28)                      |
                #   // |               |   - may_have_interesting_symbols (bit 28)       |
                # I am assuming that is_extensible should be bit 27
                "IS_EXTENSIBLE":            [OFFSETS["INT3_64"],       ['BitField', {'end_bit': 27, 'start_bit': 27}]],
                "MAY_HAVE_INTERESTING_SYMBOLS":      [OFFSETS["INT3_64"],       ['BitField', {'end_bit': 28, 'start_bit': 28}]],
                "CONSTRUCTION_COUNTER":     [OFFSETS["INT3_64"],       ['BitField', {'end_bit': 31, 'start_bit': 29}]],
            
            # TODO: Represent prototype as vtype
            "PROTOTYPE":    [OFFSETS["PROTOTYPE_64"],      ['pointer', ['void']]],

            # TODO: Represent constructor as vtype
            "CONSTRUCTOR":  [OFFSETS["CTOR_64"],           ['pointer', ['void']]],

            # TODO: Not a good candidate for vtype representation, figure out what to do with 'void'
            "DESCRIPTORS":  [OFFSETS["DESCRIPTORS_64"],    ['pointer', ['void']]],
            "LDESCRIPTORS": [OFFSETS["LDESCRIPTORS_64"],   ['pointer', ['void']]],

            "DEPENDENT":    [OFFSETS["DEPENDENT_64"],       ['pointer', ['void']]],
            "VALIDITY":     [OFFSETS["VALIDITY_64"],        ['pointer', ['void']]],
            "DEPENDENT":    [OFFSETS["TRANSITIONS_64"],     ['pointer', ['void']]],
        }],
        "_V8MAP_32_VTYPE": [MAP_SIZE_32, {
            # Always points to MetaMap root

            #"METAMAP":      [OFFSETS["METAMAP_32"],        ['pointer', ['_V8MAP_32_VTYPE']]],
            "METAMAP":      [OFFSETS["METAMAP_32"],        ['pointer32', ['_V8MAP_32_VTYPE']]],

            # Parse entire INT1 as well as the bitfields within
            # TODO: Make the bitfields vtypes themselves
            "INT1":             [OFFSETS["INT1_32"],       ['int']],
                "INSTANCE_SIZE":    [OFFSETS["INT1_32"],       ['BitField', {'end_bit': 7, 'start_bit': 0}]],
                "CTX_OR_PROPS":     [OFFSETS["INT1_32"],       ['BitField', {'end_bit': 15, 'start_bit': 8}]],
                "USED_OR_UNUSED":   [OFFSETS["INT1_32"],       ['BitField', {'end_bit': 23, 'start_bit': 16}]],
                "VISITOR_ID":       [OFFSETS["INT1_32"],       ['BitField', {'end_bit': 31, 'start_bit': 24}]],

            # Parse entire INT2 as well as the bitfields within
            # TODO: Make the bitfields vtypes themselves
            "INT2":             [OFFSETS["INT2_32"],       ['int']],
                "INSTANCE_TYPE":    [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 15, 'start_bit': 0}]],
                "BIT_FIELD":        [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 23, 'start_bit': 16}]],
                    "HAS_NON_INSTANCE_PROTOTYPE":       [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 16, 'start_bit': 16}]],
                    "IS_CALLABLE":                      [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 17, 'start_bit': 17}]],
                    "HAS_NAMED_INTERCEPTOR":            [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 18, 'start_bit': 18}]],
                    "HAS_INDEXED_INTERCEPTOR":          [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 19, 'start_bit': 19}]],
                    "IS_UNDETECTABLE":                  [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 20, 'start_bit': 20}]],
                    "IS_ACCESS_CHECK_NEEDED":           [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 21, 'start_bit': 21}]],
                    "IS_CONSTRUCTOR":                   [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 22, 'start_bit': 22}]],
                    "HAS_PROTOTYPE_SLOT":                [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 23, 'start_bit': 23}]],
                "BIT_FIELD2_RAW":   [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 31, 'start_bit': 24}]],
                "BIT_FIELD2":       [OFFSETS["INT2_32"] + 3,       ['BIT_FIELD2_VTYPE']],
                    #"NEW_TARGET_IS_BASE":               [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 24, 'start_bit': 24}]],
                    #"IS_IMMUTABLE_PROTO":               [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 25, 'start_bit': 25}]],
                    #"ELEMENTS_KIND":                    [OFFSETS["INT2_32"],       ['BitField', {'end_bit': 31, 'start_bit': 26}]],

            # Parse entire INT3 as well as the bitfields within
            # TODO: Make the bitfields vtypes themselves
            "INT3":         [OFFSETS["INT3_32"],           ['int']],
                "ENUM_LENGTH":              [OFFSETS["INT3_32"],       ['BitField', {'end_bit': 9, 'start_bit': 0}]],
                "NUM_OWN_DESCRIPTORS":      [OFFSETS["INT3_32"],       ['BitField', {'end_bit': 19, 'start_bit': 10}]],
                "IS_PROTOTYPE_MAP":         [OFFSETS["INT3_32"],       ['BitField', {'end_bit': 20, 'start_bit': 20}]],
                "IS_DICTIONARY_MAP":        [OFFSETS["INT3_32"],       ['BitField', {'end_bit': 21, 'start_bit': 21}]],
                "OWNS_DESCRIPTORS":         [OFFSETS["INT3_32"],       ['BitField', {'end_bit': 22, 'start_bit': 22}]],
                "IS_IN_RETAINED_MAP":       [OFFSETS["INT3_32"],       ['BitField', {'end_bit': 23, 'start_bit': 23}]],
                "IS_DEPRECATED":            [OFFSETS["INT3_32"],       ['BitField', {'end_bit': 24, 'start_bit': 24}]],
                "IS_UNSTABLE":              [OFFSETS["INT3_32"],       ['BitField', {'end_bit': 25, 'start_bit': 25}]],
                "IS_MIGRATION_TARGET":       [OFFSETS["INT3_32"],      ['BitField', {'end_bit': 26, 'start_bit': 26}]],
                # TODO: The v8.h documentation says:
                #   // |               |   - is_migration_target (bit 26)                |
                #   // |               |   - is_extensible (bit 28)                      |
                #   // |               |   - may_have_interesting_symbols (bit 28)       |
                # I am assuming that is_extensible should be bit 27
                "IS_EXTENSIBLE":            [OFFSETS["INT3_32"],       ['BitField', {'end_bit': 27, 'start_bit': 27}]],
                "MAY_HAVE_INTERESTING_SYMBOLS":      [OFFSETS["INT3_32"],       ['BitField', {'end_bit': 28, 'start_bit': 28}]],
                "CONSTRUCTION_COUNTER":     [OFFSETS["INT3_32"],       ['BitField', {'end_bit': 31, 'start_bit': 29}]],
            
            "PROTOTYPE":    [OFFSETS["PROTOTYPE_32"],      ['pointer32', ['void']]],
            "CONSTRUCTOR":  [OFFSETS["CTOR_32"],           ['pointer32', ['void']]],
            "DESCRIPTORS":  [OFFSETS["DESCRIPTORS_32"],    ['pointer32', ['void']]],
            # TODO: This is commented out in offsets
            #"LDESCRIPTORS": [OFFSETS["LDESCRIPTORS_32"],   ['pointer', ['void']]],
            "DEPENDENT":    [OFFSETS["DEPENDENT_32"],       ['pointer32', ['void']]],
            "VALIDITY":     [OFFSETS["VALIDITY_32"],        ['pointer32', ['void']]],
            "DEPENDENT":    [OFFSETS["TRANSITIONS_32"],     ['pointer32', ['void']]],
        }],
        "BIT_FIELD2_VTYPE": [BIT_FIELD2_SIZE, {
                    # "NEW_TARGET_IS_BASE":               [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 24, 'start_bit': 24}]],
                    # "IS_IMMUTABLE_PROTO":               [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 25, 'start_bit': 25}]],
                    # "ELEMENTS_KIND":                    [OFFSETS["INT2_64"],       ['BitField', {'end_bit': 31, 'start_bit': 26}]],
                    "NEW_TARGET_IS_BASE":               [0,       ['BitField', {'end_bit': 0, 'start_bit': 0}]],
                    "IS_IMMUTABLE_PROTO":               [0,       ['BitField', {'end_bit': 1, 'start_bit': 1}]],
                    "ELEMENTS_KIND":                    [0,       ['BitField', {'end_bit': 7, 'start_bit': 2}]],
        }],
    }

    @staticmethod
    def parse_into_vtype(address, address_space):
        # To read from memory into map:PROTOTYPi
        # map_obj = obj.Object('_MAP_VTYPE', offset=<OFFSET_TO_MAP>, vm=process_space)
        #return obj.Object('_V8MAP_64_VTYPE', offset=address, vm=address_space)
        return obj.Object('_V8MAP_32_VTYPE', offset=address, vm=address_space)

    def __init__(self, address, addr_space, arch=64):
        self.address = address
        self.addr_space = addr_space
        self.raw_data = addr_space.zread(address, V8Map.MAP_SIZE_64 if arch == 64 else V8Map.MAP_SIZE_32)

        self._vtype_obj = V8Map.parse_into_vtype(self.address, self.addr_space)

    def get_vtype_obj(self):
        return self._vtype_obj

    def __str__(self):
        return \
        "<V8Map\n" + \
        "    MetaMap:               {}\n".format(hex(self._vtype_obj.METAMAP)) + \
        "    INT1:                  {}\n".format(hex(self._vtype_obj.INT1)) + \
        "       INSTANCE_SIZE:      {}\n".format(self._vtype_obj.INSTANCE_SIZE) + \
        "       CTX_OR_PROPS:       {}\n".format(self._vtype_obj.CTX_OR_PROPS) + \
        "       USED_OR_UNSUED:     {}\n".format(self._vtype_obj.USED_OR_UNUSED) + \
        "       VISITOR_ID:         {}\n".format(self._vtype_obj.VISITOR_ID) + \
        "    INT2:                  {}\n".format(hex(self._vtype_obj.INT2)) + \
        "       INSTANCE_TYPE:      {}\n".format(self._vtype_obj.INSTANCE_TYPE) + \
        "       BIT_FIELD:          {}\n".format(self._vtype_obj.BIT_FIELD) + \
        "       BIT_FIELD2:         {}\n".format(self._vtype_obj.BIT_FIELD2_RAW) + \
        "    INT3:                  {}\n".format(hex(self._vtype_obj.INT3)) + \
        "    PROTOTYPE:             {}\n".format(hex(self._vtype_obj.PROTOTYPE)) + \
        "    CTOR:                  {}\n".format(hex(self._vtype_obj.CONSTRUCTOR)) + \
        ">"

    def __repr__(self):
        return str(self)

    def str_full(self):
        return \
        "<V8Map\n" + \
        "    MetaMap:                               {}\n".format(hex(self._vtype_obj.METAMAP)) + \
        "    INT1:                                  {}\n".format(hex(self._vtype_obj.INT1)) + \
        "       INSTANCE_SIZE:                      {}\n".format(self._vtype_obj.INSTANCE_SIZE) + \
        "       CTX_OR_PROPS:                       {}\n".format(self._vtype_obj.CTX_OR_PROPS) + \
        "       USED_OR_UNSUED:                     {}\n".format(self._vtype_obj.USED_OR_UNUSED) + \
        "       VISITOR_ID:                         {}\n".format(self._vtype_obj.VISITOR_ID) + \
        "    INT2:                                  {}\n".format(hex(self._vtype_obj.INT2)) + \
        "       INSTANCE_TYPE:                      {}\n".format(self._vtype_obj.INSTANCE_TYPE) + \
        "       BIT_FIELD:                          {}\n".format(self._vtype_obj.BIT_FIELD) + \
        "           HAS_NON_INSTANCE_PROTOTYPE:     {}\n".format(self._vtype_obj.HAS_NON_INSTANCE_PROTOTYPE) + \
        "           IS_CALLABLE:                    {}\n".format(self._vtype_obj.IS_CALLABLE) + \
        "           HAS_NAMED_INTERCEPTOR:          {}\n".format(self._vtype_obj.HAS_NAMED_INTERCEPTOR) + \
        "           HAS_INDEXED_INTERCEPTOR:        {}\n".format(self._vtype_obj.HAS_INDEXED_INTERCEPTOR) + \
        "           IS_UNDETECTABLE:                {}\n".format(self._vtype_obj.IS_UNDETECTABLE) + \
        "           IS_ACCESS_CHECK_NEEDED:         {}\n".format(self._vtype_obj.IS_ACCESS_CHECK_NEEDED) + \
        "           IS_CONSTRUCTOR:                 {}\n".format(self._vtype_obj.IS_CONSTRUCTOR) + \
        "           HAS_PROTOTYPE_SLOT:             {}\n".format(self._vtype_obj.HAS_PROTOTYPE_SLOT) + \
        "       BIT_FIELD2:                         {}\n".format(self._vtype_obj.BIT_FIELD2_RAW) + \
        "           NEW_TARGET_IS_BASE:             {}\n".format(self._vtype_obj.BIT_FIELD2.NEW_TARGET_IS_BASE) + \
        "           IS_IMMUTABLE_PROTO:             {}\n".format(self._vtype_obj.BIT_FIELD2.IS_IMMUTABLE_PROTO) + \
        "           ELEMENTS_KIND:                  {}\n".format(self._vtype_obj.BIT_FIELD2.ELEMENTS_KIND) + \
        "    INT3:                                  {}\n".format(hex(self._vtype_obj.INT3)) + \
        "       ENUM_LENGTH:                        {}\n".format(hex(self._vtype_obj.ENUM_LENGTH)) + \
        "       NUM_OWN_DESCRIPTORS:                {}\n".format(hex(self._vtype_obj.NUM_OWN_DESCRIPTORS)) + \
        "       IS_PROTOTYPE_MAP:                   {}\n".format(hex(self._vtype_obj.IS_PROTOTYPE_MAP)) + \
        "       IS_DICTIONARY_MAP:                  {}\n".format(hex(self._vtype_obj.IS_DICTIONARY_MAP)) + \
        "       OWNS_DESCRIPTORS:                   {}\n".format(hex(self._vtype_obj.OWNS_DESCRIPTORS)) + \
        "       IS_IN_RETAINED_MAP:                 {}\n".format(hex(self._vtype_obj.IS_IN_RETAINED_MAP)) + \
        "       IS_DEPRECATED:                      {}\n".format(hex(self._vtype_obj.IS_DEPRECATED)) + \
        "       IS_UNSTABLE:                        {}\n".format(hex(self._vtype_obj.IS_UNSTABLE)) + \
        "       IS_MIGRATION_TARGET:                {}\n".format(hex(self._vtype_obj.IS_MIGRATION_TARGET)) + \
        "       IS_EXTENSIBLE:                      {}\n".format(hex(self._vtype_obj.IS_EXTENSIBLE)) + \
        "       MAY_HAVE_INTERESTING_SYMBOLS:       {}\n".format(hex(self._vtype_obj.MAY_HAVE_INTERESTING_SYMBOLS)) + \
        "       CONSTRUCTION_COUNTER:               {}\n".format(hex(self._vtype_obj.CONSTRUCTION_COUNTER)) + \
        "    PROTOTYPE:                             {}\n".format(hex(self._vtype_obj.PROTOTYPE)) + \
        "    CTOR:                                  {}\n".format(hex(self._vtype_obj.CONSTRUCTOR)) + \
        ">"


# Update the current profile to contain the new vtypes
class V8MapDump(obj.ProfileModification):
    
    def modification(self, profile):
        profile.vtypes.update(V8Map.V8MAP_VTYPES)
