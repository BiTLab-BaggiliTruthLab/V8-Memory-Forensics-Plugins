import volatility.plugins.common as common
import volatility.plugins.malware.malfind as malfind
import volatility.utils as utils
import volatility.win32 as win32
import volatility.plugins.addrspaces as addrspaces
import volatility.renderers.basic as RenderType

import json
import re
import base64
import ntpath
import csv
import binascii
import struct
import collections
import pprint
import sys

from volatility.renderers import TreeGrid
from volatility.renderers.text import TextRenderer
from volatility.renderers.html import JSONRenderer


pp = pprint.PrettyPrinter(indent=4)

try:
    import yara

    HAS_YARA = True
except ImportError:
    HAS_YARA = False

WORD_SIZE = 4
DWORD_SIZE = WORD_SIZE * 2
ISOLATE_PTR_OFFSETS = [0x0, 0x38, 0x0, 0x10]
ROOT_SET_OFFSET = 0x10 * DWORD_SIZE
META_MAP_OFFSET = 0xA * DWORD_SIZE
PAGE_SIZE = 0x1000

YARA_opcodes = {
    'opcodes':
        'rule opcodes { \
        strings: $p = { ff 03 (20 | 40) 00 00 00 00 00 } \
        condition: $p \
    }'
}


# 0x03e3ff3c1160
# 
class v8_extractprops(common.AbstractWindowsCommand):
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

        for task in tasks:
            if str(task.ImageFileName) != 'node.exe':
                continue
            else:
                print("Scanning {0} pid: {1}".format(task.ImageFileName, task.UniqueProcessId))

                proc_addr_space = task.get_process_address_space()
                scanner = malfind.DiscontigYaraScanner(proc_addr_space, rulesets)

                addresss = 0x000

                meta_map = find_metamap(scanner, proc_addr_space)
                maps = get_maps(meta_map, proc_addr_space)
                valid_maps = get_valid_maps(maps, proc_addr_space)

                objs = get_objs_by_inst_type(0x75, valid_maps, proc_addr_space)
                # objs = get_arrays(valid_maps, proc_addr_space)
                count = 0
                for obj in objs:
                    # print str(hex(obj))
                    print(str(hex(obj.address)))
                    print(str(hex(obj.map.instance_type)))
                    print(obj.data)
                    count += 1
                print("Total number: " + str(count))

                # pp.pprint(collections.Counter(types))

    def render_text(the, three, args):
        print('written without errors')


class v8_findalltypes(common.AbstractWindowsCommand):
    """List all object types for findjsinstances"""

    def calculate(self):
        rules_opcodes = yara.compile(sources=YARA_opcodes)
        rulesets = [rules_opcodes]

        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)
        maps = []
        not_maps = []

        for task in tasks:
            if str(task.ImageFileName) != 'node.exe':
                continue
            else:
                print("Scanning {0} pid: {1}".format(task.ImageFileName, task.UniqueProcessId))

                proc_addr_space = task.get_process_address_space()
                scanner = malfind.DiscontigYaraScanner(proc_addr_space, rulesets)

                addresss = 0x000

                meta_map = find_metamap(scanner, proc_addr_space)
                maps = get_maps(meta_map, proc_addr_space)
                valid_maps = get_valid_maps(maps, proc_addr_space)
                return valid_maps

    def generator(self, data):
        new_data = []
        name_found = False
        for map in data:
            for map_data in new_data:
                if map_data[0] == map.type_name and map_data[1] == map.instance_type:
                    map_data[2] += 1
                    name_found = True
            if not name_found:
                new_data.append([map.type_name, map.instance_type, 1])
            else:
                name_found = False

        for map in new_data:
            yield (0, [
                str(map[0]),
                int(map[1]),
                int(map[2])
            ])

    def unified_output(self, data):
        return TreeGrid([
            ("Name", str),
            ("Instance Type", int),
            ("Map Count", int)],
            self.generator(data))


class v8_instancetypeaddr(common.AbstractWindowsCommand):
    """List all objects of a specific typename for jsprint"""

    def calculate(self):
        rules_opcodes = yara.compile(sources=YARA_opcodes)
        rulesets = [rules_opcodes]

        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)
        not_maps = []

        for task in tasks:
            if str(task.ImageFileName) != 'node.exe':
                continue
            else:
                print("Scanning {0} pid: {1}".format(task.ImageFileName, task.UniqueProcessId))

                proc_addr_space = task.get_process_address_space()
                scanner = malfind.DiscontigYaraScanner(proc_addr_space, rulesets)

                addresss = 0x000

                meta_map = find_metamap(scanner, proc_addr_space)
                maps = get_maps(meta_map, proc_addr_space)
                valid_maps = get_valid_maps(maps, proc_addr_space)

                type_name = input("Please enter the Instance Number: ")
                print("Instance Number entered: " + str(type_name))
                objs = get_objs_by_inst_type(type_name, valid_maps, proc_addr_space)
                print("Number   Object Address")
                count = 1
                for obj in objs:
                    print(str(count) + "        " + str(hex(obj.address)))
                    #print(str(hex(obj.map.instance_type)))
                    #print(obj.data)
                    count = count + 1
                exit()
                
class v8_extractobjects(common.AbstractWindowsCommand):
    """Print the details of a specific object"""

    def calculate(self):
        rules_opcodes = yara.compile(sources=YARA_opcodes)
        rulesets = [rules_opcodes]

        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)
        maps = []
        not_maps = []

        for task in tasks:
            if str(task.ImageFileName) != 'node.exe':
                continue
            else:
                print("Scanning {0} pid: {1}".format(task.ImageFileName, task.UniqueProcessId))

                proc_addr_space = task.get_process_address_space()
                scanner = malfind.DiscontigYaraScanner(proc_addr_space, rulesets)

                obj_address = input("Please enter the object address: ")
                # obj_address = 0x344bd600510 # 0x421 Object
                # obj_address = 0x69637234d0 # 0x75 Array
                # obj_address = 0x6963708ce8  # 0x8 String
                print("Address entered: " + str(hex(obj_address)))

                return get_object_by_addr(obj_address, proc_addr_space)

    def generator1(self, data):
        if is_string(data.map.instance_type):
            yield (0, [
                str("String"),
                RenderType.Address64(data.map.address),
                RenderType.Address64(data.address)
            ])
        elif is_array(data.map.instance_type):
            yield (0, [
                str("Array"),
                RenderType.Address64(data.map.address),
                RenderType.Address64(data.address)
            ])
        elif is_object(data.map.instance_type):
            yield (0, [
                str("Object"),
                RenderType.Address64(data.map.address),
                RenderType.Address64(data.address)
            ])
        else:
            yield (0, [
                str("Error! This should never be reached!")
            ])

    def generator2(self, data):
        if is_string(data.map.instance_type):
            yield (0, [
                str(data.data)
            ])
        elif is_array(data.map.instance_type):
            for obj in data.data:
                if len(obj) is 3:
                    yield (0, [
                        str(obj[0]),
                        str(obj[1]),
                        RenderType.Address64(obj[2])
                    ])
                elif len(obj) is 4:  # TODO: Figure out how to recursively yield
                    yield (0, [
                        str(obj[0]),
                        str(obj[1]),
                        RenderType.Address64(obj[2])
                    ])
        elif is_object(data.map.instance_type):
            for count, obj in enumerate(data.data.items()):
                yield (0, [
                    int(count),
                    str(obj[0]),
                    RenderType.Address64(obj[1])
                ])
        else:
            yield (0, [
                str("Error! This should never be reached!")
            ])

    def unified_output1(self, data):
        if is_string(data.map.instance_type):
            return TreeGrid([
                ("Type", str),
                ("Map Address", RenderType.Address64),
                ("String Address", RenderType.Address64)],
                self.generator1(data)
            )
        elif is_array(data.map.instance_type):
            return TreeGrid([
                ("Type", str),
                ("Map Address", RenderType.Address64),
                ("Array Address", RenderType.Address64)],
                self.generator1(data)
            )
        elif is_object(data.map.instance_type):
            return TreeGrid([
                ("Type", str),
                ("Map Address", RenderType.Address64),
                ("Object Address", RenderType.Address64)],
                self.generator1(data)
            )
        else:
            return TreeGrid([
                ("Error", str)],
                self.generator1(data)
            )

    def unified_output2(self, data):
        if is_string(data.map.instance_type):
            return TreeGrid([
                ("String", str)],
                self.generator2(data)
            )
        elif is_array(data.map.instance_type):
            return TreeGrid([
                ("Property Number", str),
                ("Property Type", str),
                ("Property", RenderType.Address64)],
                self.generator2(data)
            )
        elif is_object(data.map.instance_type):
            return TreeGrid([
                ("Number", int),
                ("Object Name", str),
                ("Object Address", RenderType.Address64)],
                self.generator2(data)
            )
        else:
            return TreeGrid([
                ("Error", str)],
                self.generator2(data)
            )

    def render_text(self, outfd, data):
        renderer = TextRenderer(self.text_cell_renderers, sort_column=self.text_sort_column)
        renderer.render(outfd, self.unified_output1(data))
        renderer.render(outfd, self.unified_output2(data))

    def render_json(self, outfd, data):
        renderer = JSONRenderer()
        renderer.render(outfd, self.unified_output1(data))
        renderer.render(outfd, self.unified_output2(data))

def find_metamap(scanner, proc_addr_space):
    addresslist = []
    for hit_obj, offset in scanner.scan():
        address = offset                                                                            # Search bytecode signatures              
        raw_data = proc_addr_space.zread(address, DWORD_SIZE)                  
        address = address - 18
        meta_map_ptr = proc_addr_space.zread(address, DWORD_SIZE)                                   # Read pointer stored in same structure
        addresslist.append(hex(read_double_word(meta_map_ptr)))
    dup = [x for i, x in enumerate(addresslist) if i != addresslist.index(x)]                       # Find duplicates and select the most common element         
    str_meta_map = dup[0]
    str_meta_map = str_meta_map.rstrip('0')                                                                # Concatenate the first 13 indexes
    address = int(str_meta_map, 16)
    address = address - 1
    print("Meta Map Address: " + str(hex(address)))
    raw_data = proc_addr_space.zread(address, DWORD_SIZE)
    print("New Meta Map Value : " + hex(read_double_word(raw_data)))
    return address + 1

def get_arrays(valid_maps, addr_space):
    objs = []
    for mp in valid_maps:
        if is_basic_array(mp.instance_type):
            objs += get_objects(mp, addr_space, 0, 100)
    return objs


def get_objs_by_name(name, valid_maps, addr_space):
    objs = []
    for mp in valid_maps:
        if mp.type_name == name:
            objs += get_objects(mp, addr_space, 0, 100)
    return objs

def get_objs_by_name(inst_type, valid_maps, addr_space):
    objs = []
    count = 0
    max = input("Enter MAX Number:")
    for mp in valid_maps:
        if mp.instance_type == inst_type:
            objs += get_objects(mp, addr_space, count, max)
            count = len(objs)
            if count >= max:
                return objs
    return objs

def get_obj_addrs_by_name(name, valid_maps, addr_space):
    objs = []
    for mp in valid_maps:
        if mp.type_name == name:
            print("Map found: " + str(hex(mp.address)))
            objs += get_obj_addresses(mp, addr_space)
    return objs


def get_objs_by_inst_type(inst_type, valid_maps, addr_space):
    objs = []
    count = 0
    max = input("Enter Max number of objects: ")
    for mp in valid_maps:
        if mp.instance_type == inst_type:
            objs += get_objects(mp, addr_space, count, max)
            count = len(objs)
            if count >= max:
                return objs
    return objs


def get_meta_map(isolate_ptr, addr_space):
    addr = isolate_ptr + ROOT_SET_OFFSET + META_MAP_OFFSET
    maybe_meta_map_ptr = read_dword_as_int(addr, addr_space) - 1
    maybe_meta_map = parse_map(maybe_meta_map_ptr, addr_space)
    if not maybe_meta_map.is_meta_map():
        # if this is not the correct map, try the metamap this map references
        maybe_meta_map = parse_map(maybe_meta_map.meta_map - 1, addr_space)
        if not maybe_meta_map.is_meta_map():
            print("Cannot find metamap")
            exit()

    return maybe_meta_map


def read_dword_as_int(address, addr_space):
    raw_data = addr_space.zread(address, DWORD_SIZE)
    return read_double_word(raw_data)


def read_word_as_int(address, addr_space):
    raw_data = addr_space.zread(address, WORD_SIZE)
    return read_word(raw_data)


def get_isolate(first_ptr, addr_space):
    print("Begin walking pointers")
    current_ptr = first_ptr

    for offset in ISOLATE_PTR_OFFSETS:
        print("Current pointer: " + str(hex(current_ptr)))
        raw_data = addr_space.zread(current_ptr + offset, DWORD_SIZE)
        current_ptr = read_double_word(raw_data)

    return current_ptr


def read_word(raw_word):
    return struct.unpack("<I", raw_word)[0]


def read_double_word(raw_double_word):
    return struct.unpack("<Q", raw_double_word)[0]


def parse_map(addr, addr_space):
    raw_data = addr_space.zread(addr, V8Map.MAP_SIZE)
    return V8Map(raw_data, addr, addr_space)


def parse_proto_map(addr, addr_space):
    raw_data = addr_space.zread(addr, V8Map.MAP_SIZE)
    return V8ProtoMap(raw_data, addr, addr_space)


def get_valid_maps(maps, addr_space):
    valid = []
    for mp in maps:
        if mp.valid:
            valid.append(mp)

    return valid


def get_maps(meta_map_ptr, addr_space):
    scanner = get_custom_yara_scanner(meta_map_ptr, addr_space)
    maps = []

    for hit_obj, address in scanner.scan():

        maybe_map = parse_map(address, addr_space)

        if maybe_map.valid:
            maps.append(maybe_map)

    return maps


def swap64(word):
    return struct.pack("<Q", word)


def validate_meta_map(ptr, addr_space):
    pass


def get_custom_yara_scanner(addr, addr_space):
    # Takes a 64 bit integer and returns a scanner object
    hex_string = swap64(addr).encode("hex")

    rule_raw = 'rule custom {{ \
        strings: $p = {{{0}}} \
        condition: $p \
        }}'.format(hex_string)
    rule = {'rule': rule_raw}

    rule_compiled = yara.compile(sources=rule)
    ruleset = [rule_compiled]
    return malfind.DiscontigYaraScanner(addr_space, ruleset)


def get_obj_addresses(mp, addr_space):
    scanner = get_custom_yara_scanner(mp.address + 1, addr_space)
    objs = []

    for hit_obj, address in scanner.scan():
        print("Object found: " + str(hex(address)))
        objs.append(address)
    print(str(len(objs)) + " Objects found")

    return objs


def is_string(instance_type):
    return 0x0 <= instance_type <= 0x3F


def is_basic_array(instance_type):
    true = 0x75 <= instance_type <= 0x77 or 0x80 <= instance_type <= 0x82 or instance_type == 0x84
    true = true or instance_type == 0xab
    return true


def is_array(instance_type):  # There are many different array types scattered practically randomly throughout the list
    true = instance_type == 0x57 or 0x75 <= instance_type <= 0x87 or 0x98 <= instance_type <= 0x99
    true = true or 0x9E <= instance_type <= 0x9F or instance_type == 0xA4 or instance_type == 0xAE
    true = true or instance_type == 0xB5 or instance_type == 0xB8 or instance_type == 0x41B
    true = true or 0x437 <= instance_type <= 0x438 or instance_type == 0x43D or 0x424 <= instance_type <= 0x42F
    return is_basic_array(instance_type) or true


def is_object(instance_type):
    return instance_type == 0x421


def get_objects(mp, addr_space, count, max):
    scanner = get_custom_yara_scanner(mp.address + 1, addr_space)
    objs = []
    if is_string(mp.instance_type):
        for hit_obj, address in scanner.scan():
            objs.append(V8String(address, mp, addr_space))
            count += 1
            if count >= max:
                return objs
    elif is_array(mp.instance_type):
        for hit_obj, address in scanner.scan():
            objs.append(V8Array(address, mp, addr_space))
            # objs.append(address)
            count += 1
            if count >= max:
                return objs
    else:
        for hit_obj, address in scanner.scan():
            objs.append(V8Object(address, mp, addr_space))

    return objs


def validate_string(string):
    re1 = re.compile(r'[^a-zA-Z0-9.]')
    return re1.search(string)


"""def get_objects(mp, addr_space):
    scanner = get_custom_yara_scanner(mp.address + 1, addr_space)
    objs = []
    if is_string(mp.instance_type):
        for hit_obj, address in scanner.scan():
            objs.append(V8String(address, mp, addr_space))
    elif is_array(mp.instance_type):
        for hit_obj, address in scanner.scan():
            objs.append(V8Array(address, mp, addr_space))
            # objs.append(address)
    else:
        for hit_obj, address in scanner.scan():
            objs.append(V8Object(address, mp, addr_space))
    return objs"""


def get_object_by_addr(address, addr_space):
    if addr_space.is_valid_address(address):
        raw_map_ptr = addr_space.zread(address, DWORD_SIZE)
        map_ptr = read_double_word(raw_map_ptr) - 1
        raw_maybe_metamap_ptr = addr_space.zread(map_ptr, DWORD_SIZE)
        maybe_metamap_ptr = read_double_word(raw_maybe_metamap_ptr) - 1

        if map_ptr == maybe_metamap_ptr:
            return parse_map(address, addr_space)

        map = parse_map(map_ptr, addr_space)
        if map.valid:
            if is_string(map.instance_type):
                return V8String(address, map, addr_space)
            elif is_array(map.instance_type):
                return V8Array(address, map, addr_space)
                # return address
            elif is_object(map.instance_type):
                return V8Object(address, map, addr_space)
            else:
                print("Object type not supported!")
                exit()
        else:
            print("Invalid map!")
            exit()
    else:
        print("Error! Not a valid address!")
        exit()


def print_object_properties(obj):
    for num, prop in enumerate(obj.data, start=1):
        print("\t\tProperty " + str(num) + ": " + str(hex(prop)))


class V8Array(object):
    MAP_PTR_OFFSET = 0
    LENGTH_OFFSET = 1 * DWORD_SIZE + WORD_SIZE
    PROPERTIES_START_OFFSET = 2 * DWORD_SIZE
    MIN_ARRAY_SIZE = 2 * DWORD_SIZE

    def __init__(self, address, mp, addr_space):
        self.address = address
        self.map = mp
        self._parse_start(addr_space)

    def _parse_start(self, addr_space):
        if is_basic_array(self.map.instance_type):
            self._parse_basic(addr_space)
        elif self.map.instance_type == 0x424:
            self._parse_424(addr_space)
        else:  # Inserted temporarily to make it easier to make sure what I'm currently working on works
            self.data = []

    def _parse_basic(self, addr_space):
        parse = self._parse_one_pointer
        props_start = self.address + V8Array.PROPERTIES_START_OFFSET
        bonus_offset = 0

        maybe_map = self._read_ptr(self.address + DWORD_SIZE, addr_space) - 1
        maybe_metamap = self._read_ptr(maybe_map, addr_space)
        if maybe_metamap == self.map.meta_map:
            self.length = -1
            self.data = ["No array"]
        else:
            # print("Array Address: " + str(hex(self.address)))
            self.length = read_word_as_int(self.address + V8Array.LENGTH_OFFSET, addr_space)
            if self.length <= 0x1000:
                raw_data = addr_space.zread(props_start, self.length * DWORD_SIZE)
                self.data = []

                if self.map.instance_type == 81:
                    bonus_offset = 1 * DWORD_SIZE

                for index in range(self.length):
                    item = parse(raw_data[index * DWORD_SIZE + bonus_offset: (index + 1) * DWORD_SIZE + bonus_offset])
                    self.data.append(['Property ' + str(index)] + self._parse_property(item, addr_space))
            else:
                self.data = ["Array too long or could not be parsed properly"]

    def _parse_424(self, addr_space):
        parse = self._parse_one_pointer

        array1_offset = self.address + DWORD_SIZE
        self.data1_addr = parse(addr_space.zread(array1_offset, DWORD_SIZE)) - 1

        array1_map_ptr = parse(addr_space.zread(self.data1_addr, DWORD_SIZE)) - 1
        array1_map = parse_map(array1_map_ptr, addr_space)

        array1 = V8Array(self.data1_addr, array1_map, addr_space)

        array2_offset = array1_offset + DWORD_SIZE
        self.data2_addr = parse(addr_space.zread(array2_offset, DWORD_SIZE)) - 1

        array2_map_ptr = parse(addr_space.zread(self.data2_addr, DWORD_SIZE)) - 1
        array2_map = parse_map(array2_map_ptr, addr_space)

        array2 = V8Array(self.data2_addr, array2_map, addr_space)

        self.data = []

        self.data += array1.data
        self.data += array2.data

        self.length = len(self.data)

    def _parse_property(self, item, addr_space):
        parse = self._parse_one_pointer
        # print("Item: " + str(hex(item)))

        if item & 0xFFFFFFFF == 0:  # Smi's are always half empty
            return ['smi ', item >> 32]
        else:
            item_map_ptr = parse(addr_space.zread(item - 1, DWORD_SIZE)) - 1
            # print("Item map pointer: " + str(hex(item_map_ptr)))

            if addr_space.is_valid_address(item_map_ptr) and item_map_ptr != 0:
                if self.map.is_map(item_map_ptr, addr_space):
                    item_map = parse_map(item_map_ptr, addr_space)

                    if is_string(item_map.instance_type):
                        return ['string', item, V8String(item - 1, item_map, addr_space).data]
                    elif is_array(item_map.instance_type):
                        return ['array', item, V8Array(item - 1, item_map, addr_space).data]
                    elif is_object(item_map.instance_type):
                        return ['object', item, V8Object(item - 1, item_map, addr_space).data]
                    else:
                        return ['unknown object', str(hex(item))]
                else:
                    return ['unknown address', str(hex(item))]
            else:
                return ['unknown', str(hex(item))]

    def _parse_one_pointer(self, raw_double_word):
        return read_double_word(raw_double_word)

    def _read_ptr(self, offset, addr_space):
        raw_data = addr_space.zread(offset, DWORD_SIZE)
        return read_double_word(raw_data)


class V8String(object):
    MAP_PTR_OFFSET = 0
    STRING_LENGTH_OFFSET = 1 * DWORD_SIZE + WORD_SIZE
    PROPERTIES_START_OFFSET = 2 * DWORD_SIZE
    MIN_STRING_SIZE = 1 * DWORD_SIZE

    def __init__(self, address, mp, addr_space):
        self.address = address
        self.map = mp

        self._parse_start(addr_space)

    def _parse_start(self, addr_space):
        parse = self._parse_one_pointer

        self.length = read_word_as_int(self.address + V8String.STRING_LENGTH_OFFSET, addr_space)

        if self.map.instance_type == 0x8:
            self._parse_8(addr_space)
        elif self.map.instance_type == 0x20:
            self._parse_20(addr_space)
        elif self.map.instance_type == 0x28:
            self._parse_28(addr_space)
        elif self.map.instance_type == 0x29:
            self._parse_29(addr_space)
        elif self.map.instance_type == 0x2b:
            self._parse_2b(addr_space)
        elif self.map.instance_type == 0x2d:
            self._parse_2d(addr_space)
        else:
            self.data = ""

    def _parse_8(self, addr_space):
        self.data = addr_space.zread(self.address + V8String.PROPERTIES_START_OFFSET, self.length)

    def _parse_20(self, addr_space):
        """These strings are ridiculously long and contiguous, so they have a decent chance of going through
        multiple pages. Unfortunately, reading through multiple pages breaks zread, so we have to only zread up to the
        end of the page then do a second zread in the next page, and repeat that until we get to the end of the string"""
        string = ""
        curr_len = 0
        while curr_len < self.length * 2:
            chunk_len = min(self.length * 2 - curr_len, PAGE_SIZE - (self.address % PAGE_SIZE))
            string += addr_space.zread(self.address + V8String.PROPERTIES_START_OFFSET + curr_len, chunk_len)
            curr_len += chunk_len

        try:
            self.data = string.decode('utf_8', 'strict')
        except:
            self.data = ""

    def _parse_28(self, addr_space):
        self.data = addr_space.zread(self.address + V8String.PROPERTIES_START_OFFSET, self.length)

    def _parse_29(self, addr_space):  # NOT DONE. Does not work in some weird cases
        parse = self._parse_one_pointer
        str1_offset = self.address + V8String.PROPERTIES_START_OFFSET

        self.str1_addr = parse(addr_space.zread(str1_offset, DWORD_SIZE)) - 1
        self.str1_length = read_word_as_int(self.str1_addr + V8String.STRING_LENGTH_OFFSET, addr_space)
        str1_map_ptr = parse(addr_space.zread(self.str1_addr, DWORD_SIZE)) - 1

        str1_map = parse_map(str1_map_ptr, addr_space)
        string1 = V8String(self.str1_addr, str1_map, addr_space)

        self.str2_addr = parse(addr_space.zread(str1_offset + DWORD_SIZE, DWORD_SIZE)) - 1
        self.str2_length = read_word_as_int(self.str2_addr + V8String.STRING_LENGTH_OFFSET, addr_space)
        str2_map_ptr = parse(addr_space.zread(self.str2_addr, DWORD_SIZE)) - 1

        str2_map = parse_map(str2_map_ptr, addr_space)
        string2 = V8String(self.str2_addr, str2_map, addr_space)

        string = string1.data + string2.data

        if len(string) == self.length:
            self.data = string
        else:
            self.data = string[0: self.length]

    def _parse_2b(self, addr_space):  # NOT DONE. Only works in the simplest case
        parse = self._parse_one_pointer
        str_offset = self.address + V8String.PROPERTIES_START_OFFSET

        self.str_addr = parse(addr_space.zread(str_offset, DWORD_SIZE)) - 1
        string = addr_space.zread(self.str_addr + V8String.PROPERTIES_START_OFFSET, self.length)

        try:
            self.data = string.decode('ascii', 'strict')
        except:
            self.data = ""

    def _parse_2d(self, addr_space):  # NOT DONE. Only works in the simplest case
        parse = self._parse_one_pointer
        str_offset = self.address + V8String.PROPERTIES_START_OFFSET

        self.str_addr = parse(addr_space.zread(str_offset, DWORD_SIZE)) - 1
        string = addr_space.zread(self.str_addr + V8String.PROPERTIES_START_OFFSET, self.length)

        try:
            self.data = string.decode('ascii', 'strict')
        except:
            self.data = ""

    def _parse_one_pointer(self, raw_double_word):
        return read_double_word(raw_double_word)

    def _read_ptr(self, offset, addr_space):
        raw_data = addr_space.zread(offset, DWORD_SIZE)
        return read_double_word(raw_data)


class V8Object(object):
    MAP_PTR_OFFSET = 0
    OVERFLOW_ARRAY_OFFSET = 1 * DWORD_SIZE
    ELEMENT_ARRAY_OFFSET = 2 * DWORD_SIZE
    PROPERTIES_OFFSET = 3 * DWORD_SIZE
    MIN_OBJ_SIZE = 3 * DWORD_SIZE
    OVERFLOW_SIZE_OFFSET = DWORD_SIZE
    OVERFLOW_PROPS_OFFSET = 2 * DWORD_SIZE

    def __init__(self, address, mp, addr_space):
        self.address = address
        self.map = mp
        self._in_obj_index = 0  # index of next in obj prop to be parsed
        self._in_obj_num = mp.num_own_desc  # number of props in obj, will go down as desc and overflow
        self._overflow_index = 0  # index of next property in overflow ar to be parsed
        self._overflow_num = 0  # number of properties in overflow array
        self.slow = False
        self.data = {}

        self._parse_start(addr_space)
        if self.slow:
            return
        # print "Num inobj: " + str(hex(self._in_obj_num))
        # print "Num overflow: " + str(hex(self._overflow_num))
        self._parse_properties(addr_space)
        # print "addr: " + str(hex(self.address))
        # print "map: " + str(hex(self.map.address))
        # print self.data

    def _get_next_property(self, addr_space):
        if self._overflow_index < self._overflow_num:
            offset = self.overflow_ptr + V8Object.OVERFLOW_PROPS_OFFSET + (self._overflow_index * DWORD_SIZE)
            # print str(hex(offset))
            self._overflow_index += 1
            return self._read_ptr(offset, addr_space)
        elif self._in_obj_index < self._in_obj_num:
            offset = self.address + V8Object.PROPERTIES_OFFSET + (self._in_obj_index * DWORD_SIZE)
            self._in_obj_index += 1
            return self._read_ptr(offset, addr_space)

    def _parse_properties(self, addr_space):
        parse = self._parse_one_pointer

        for descriptor in self.map.descriptors:
            if descriptor.unknown:
                self.data[descriptor.name] = descriptor.desc_value
            else:
                next_property = self._get_next_property(addr_space)
                self.data[descriptor.name] = next_property

    def _parse_start(self, addr_space):
        parse = self._parse_one_pointer
        data = addr_space.zread(self.address, V8Object.MIN_OBJ_SIZE)

        # self.map_ptr = parse(data[V8Object.MAP_PTR_OFFSET: V8Object.MAP_PTR_OFFSET + DWORD_SIZE])
        self.overflow_ptr = parse(data[V8Object.OVERFLOW_ARRAY_OFFSET: V8Object.OVERFLOW_ARRAY_OFFSET + DWORD_SIZE]) - 1
        self.element_ptr = parse(data[V8Object.ELEMENT_ARRAY_OFFSET: V8Object.ELEMENT_ARRAY_OFFSET + DWORD_SIZE]) - 1

        if self.overflow_ptr != self.element_ptr:
            raw_dword = addr_space.zread(self.overflow_ptr + V8Object.OVERFLOW_SIZE_OFFSET, DWORD_SIZE)
            overflow = read_double_word(raw_dword)
            if not overflow & 0x1:
                # If this is not an SMI there are slow properties in a dict
                self._overflow_num = overflow >> 32
                self._in_obj_num -= self._overflow_num
            else:
                self.slow = True

        self._in_obj_num -= self.map.edge_case_descriptors

    def _parse_one_pointer(self, raw_double_word):
        return read_double_word(raw_double_word)

    def _read_ptr(self, offset, addr_space):
        raw_data = addr_space.zread(offset, DWORD_SIZE)
        return read_double_word(raw_data)


class V8Descriptor(object):
    def __init__(self, name, desc_value, unknown=None):
        self.name = name
        self.desc_value = desc_value
        self.unknown = unknown


class V8Map(object):
    INT1_OFFSET = 1 * DWORD_SIZE
    INT2_OFFSET = INT1_OFFSET + WORD_SIZE
    INT3_OFFSET = INT2_OFFSET + WORD_SIZE
    NULL_INT_OFFSET = INT3_OFFSET + WORD_SIZE

    METAMAP_OFFSET = 0 * DWORD_SIZE
    PROTOTYPE_OFFSET = 3 * DWORD_SIZE
    CTOR_OFFSET = 4 * DWORD_SIZE
    DESCRIPTORS_OFFSET = 5 * DWORD_SIZE
    LDESCRIPTORS_OFFSET = 6 * DWORD_SIZE
    DEPENDENT_OFFSET = 7 * DWORD_SIZE
    VALIDITY_OFFSET = 8 * DWORD_SIZE
    TRANSITIONS_OFFSET = 9 * DWORD_SIZE

    MAP_SIZE = 10 * DWORD_SIZE

    DESCRIPTOR_ENTRY_SIZE = 3 * DWORD_SIZE
    FIRST_DESC_ENTRY_OFFSET = 3 * DWORD_SIZE
    STRING_CHAR_OFFSET = 2 * DWORD_SIZE
    STRING_SIZE_OFFSET = 1 * DWORD_SIZE + WORD_SIZE
    STRING_SIZE_SIZE = 1 * WORD_SIZE
    SHARED_INFO_OFFSET = 3 * DWORD_SIZE

    BIT_MASK = 0x1
    THREE_BIT_MASK = 0x7
    FIVE_BIT_MASK = 0x1F
    BYTE_MASK = 0xFF
    TEN_BIT_MASK = 0x3FF
    SHORT_MASK = 0xFFFF

    # Int Field 1
    INSTANCE_SIZE_SHIFT = 0
    IN_OBJ_PROP_SHIFT = 8
    USED_OR_UNUSED_SHIFT = 16
    VISITOR_ID_SHIFT = 24

    # Int Field 2
    INSTANCE_TYPE_SHIFT = 0
    # Bitfield 1
    NON_INST_PROT_SHIFT = 16
    IS_CALLABLE_SHIFT = 17
    NAMED_INTER_SHIFT = 18
    INDEX_INTER_SHIFT = 19
    IS_UNDETECT_SHIFT = 20
    ACCESS_CHECK_SHIFT = 21
    IS_CTOR_SHIFT = 22
    HAS_PROTO_SLOT_SHIFT = 23
    # Bitfield 2
    NEW_TARGET_SHIFT = 24
    IS_IMMUT_PROT_SHIFT = 25
    ELEMENTS_KIND_SHIFT = 27

    # Int Field 3
    # Bitfield 3
    ENUM_LENGTH_SHIFT = 0
    NUM_OWN_DESC_SHIFT = 10
    IS_PROTO_SHIFT = 20
    IS_DICT_SHIFT = 21
    OWNS_DESC_SHIFT = 22
    IS_RETAINED_SHIFT = 23
    IS_DEPRECATED_SHIFT = 24
    IS_UNSTABLE_SHIFT = 25
    IS_MIGRATE_TRGT_SHIFT = 26
    IS_EXTENSIBLE_SHIFT = 27
    INTERESTING_SYM_SHIFT = 28
    CONSTRUCTED_CTR_SHIFT = 29

    def __init__(self, raw_data, address, addr_space):
        """raw_data is a string of ascii read directly from memory with zread"""
        # print("Parsing map at: " + str(hex(address)))
        self.raw_data = raw_data
        self.address = address
        self.edge_case_descriptors = 0  # number of descriptors that dont have a ptr to obj
        self.type_name = ""

        try:
            self._parse_pointers()
            self._parse_intfields()
            if not self.validate(addr_space):
                self.valid = False
                return
            self._parse_descriptors(addr_space)
            self.valid = True
            self._get_type_name(addr_space)
        except:
            self.valid = False
        # self._print_bitfields()

    def _print_bitfields(self):  # For debug use
        print(str(hex(self.instance_type)))
        print("Bitfield 1:")
        print(self.non_inst_prot)
        print(self.is_callable)
        print(self.named_inter)
        print(self.index_inter)
        print(self.is_undetect)
        print(self.access_check)
        print(self.is_ctor)
        print(self.has_proto_slot)

        print("Bitfield 2:")
        print(self.new_target)
        print(self.is_immut_prot)
        print(self.elements_kind)

        print("Bitfield 3:")
        print(self.enum_length)
        print(self.num_own_desc)
        print(self.is_proto)
        print(self.is_dict)
        print(self.owns_desc)
        print(self.is_retained)
        print(self.is_deprecated)
        print(self.is_unstable)
        print(self.is_migrate_target)
        print(self.is_extensible)
        print(self.interesting_sym)
        print(self.constructed_ctr)

    def _get_type_name(self, addr_space):
        if not self.is_proto:
            # print "address: " + str(hex(self.address))
            # print "prot: " + str(hex(self.prototype - 1))
            proto_map_ptr = read_dword_as_int(self.prototype - 1, addr_space)
            # print("Proto map ptr: " + str(hex(proto_map_ptr)))
            prototype_map = parse_proto_map(proto_map_ptr - 1, addr_space)
            if not prototype_map.valid:
                # print("Not valid")
                return

            proto = V8Object(self.prototype - 1, prototype_map, addr_space)
            # print(proto.data)
            if not proto.data.has_key("constructor"):
                # print("No CTOR")
                # print ("Map Address: " + str(hex(self.address)))
                # self._print_bitfields()
                self._walk_back_pointers(addr_space)
            else:
                self.ctor = proto.data["constructor"]

        offset_of_shared_info = (self.ctor - 1) + V8Map.SHARED_INFO_OFFSET
        # print hex(offset_of_shared_info)
        shared_info_addr = self._read_ptr(offset_of_shared_info, addr_space)
        # print "\tSFI addr: " + str(hex(shared_info_addr))
        # TODO MAKE IT SO WE CAN ALWAYS GET STRING
        offset_of_string = (shared_info_addr - 1) + (DWORD_SIZE * 2)
        str_ptr = self._read_ptr(offset_of_string, addr_space) - 1
        # print "\tstr_ptr: " + str(hex(str_ptr))
        maybe_name = self._read_string(str_ptr, addr_space)
        if len(maybe_name.strip(' \t\n\r')) <= 2 and not validate_string(maybe_name):
            self.type_name = "Invalid Typename"
        else:
            self.type_name = maybe_name
        # print "\ttype name: " + str(maybe_name)

    def _walk_back_pointers(self, addr_space):
        # print("Walking back pointers")
        while True:
            new_map = parse_map(self.ctor - 1, addr_space)
            self.ctor = new_map.ctor
            if not new_map.valid:
                # print("Constructor found: " + str(hex(self.ctor)))
                break

    def _parse_descriptors(self, addr_space):
        num = self.num_own_desc
        arr_start = self.descriptor_array - 1
        raw_data = addr_space.zread(arr_start, (num + 1) * V8Map.DESCRIPTOR_ENTRY_SIZE)

        self.descriptors = []
        for index in range(num):
            unknown = None
            entry_offset = (index * V8Map.DESCRIPTOR_ENTRY_SIZE) + V8Map.FIRST_DESC_ENTRY_OFFSET
            data = raw_data[entry_offset: entry_offset + V8Map.DESCRIPTOR_ENTRY_SIZE]
            str_ptr = data[:DWORD_SIZE]
            str_address = self._parse_one_pointer(str_ptr) - 1
            raw_string = self._read_string(str_address, addr_space)

            desc_value = read_double_word(data[DWORD_SIZE * 2:])

            # TODO: CLEAN THIS UP WHEN WE KNOW MORE ABOUT THIS VALUE
            if desc_value != 0x100000000 and desc_value != 0x200000000:
                # these are the two currently known possible desc_values
                nibble = desc_value & 0xF
                if nibble == 0x1 or nibble == 0x9:
                    # If the desc_value is a tagged ptr, the property will not be found in the obj
                    unknown = True
                    self.edge_case_descriptors += 1
                elif nibble == 0x3 or nibble == 0xb:
                    # if it is a double tagged ptr (last 2 bits on), the property will be found in the obj
                    # and this desc_value will be a double tagged ptr to some map
                    pass
                elif desc_value == 0:
                    # probably some error has occurred, for now just dont try to read the property
                    unknown = True
                    self.edge_case_descriptors += 1
                else:
                    # unknown desc_value, something is very wrong
                    # print("unknown desc_value of: " + str(hex(desc_value)))
                    # print("encountered in map: " + str(hex(self.address)))
                    # print("in descriptor array: " + str(hex(self.descriptor_array)))
                    raise Exception("Unknown desc_value")

            descriptor = V8Descriptor(raw_string, desc_value, unknown=unknown)
            self.descriptors.append(descriptor)

    def _read_string(self, addr, addr_space):
        size = read_word_as_int(addr + V8Map.STRING_SIZE_OFFSET, addr_space)
        # print "\tsize: " + str(hex(size))
        if size > 0x10000:
            return
        raw_string = addr_space.zread(addr + V8Map.STRING_CHAR_OFFSET, size)
        return raw_string
        # TODO MAKE THIS NOT SUCK
        # size check is a hack in case we arent actually dealing with a map

    def _parse_pointers(self):
        parse = self._parse_one_pointer
        data = self.raw_data

        self.meta_map = parse(data[V8Map.METAMAP_OFFSET: V8Map.METAMAP_OFFSET + DWORD_SIZE])
        self.prototype = parse(data[V8Map.PROTOTYPE_OFFSET: V8Map.PROTOTYPE_OFFSET + DWORD_SIZE])
        self.ctor = parse(data[V8Map.CTOR_OFFSET: V8Map.CTOR_OFFSET + DWORD_SIZE])
        self.descriptor_array = parse(data[V8Map.DESCRIPTORS_OFFSET: V8Map.DESCRIPTORS_OFFSET + DWORD_SIZE])
        self.ldescriptors = parse(data[V8Map.LDESCRIPTORS_OFFSET: V8Map.LDESCRIPTORS_OFFSET + DWORD_SIZE])
        self.dependent = parse(data[V8Map.DEPENDENT_OFFSET: V8Map.DEPENDENT_OFFSET + DWORD_SIZE])
        self.validity = parse(data[V8Map.VALIDITY_OFFSET: V8Map.VALIDITY_OFFSET + DWORD_SIZE])
        self.transtions = parse(data[V8Map.TRANSITIONS_OFFSET: V8Map.TRANSITIONS_OFFSET + DWORD_SIZE])

    def _read_ptr(self, offset, addr_space):
        raw_data = addr_space.zread(offset, DWORD_SIZE)
        return read_double_word(raw_data)

    def _parse_one_pointer(self, raw_double_word):
        return read_double_word(raw_double_word)

    def _parse_intfields(self):
        data = self.raw_data

        raw_word = data[V8Map.INT1_OFFSET: V8Map.INT1_OFFSET + WORD_SIZE]
        self._parse_intfield1(read_word(raw_word))

        raw_word = data[V8Map.INT2_OFFSET: V8Map.INT2_OFFSET + WORD_SIZE]
        self._parse_intfield2(read_word(raw_word))

        raw_word = data[V8Map.INT3_OFFSET: V8Map.INT3_OFFSET + WORD_SIZE]
        self._parse_intfield3(read_word(raw_word))

    def _parse_intfield1(self, word):
        self.instance_size = (word >> V8Map.INSTANCE_SIZE_SHIFT) & V8Map.BYTE_MASK
        self.in_obj_prop = (word >> V8Map.IN_OBJ_PROP_SHIFT) & V8Map.BYTE_MASK
        self.used_or_unused = (word >> V8Map.USED_OR_UNUSED_SHIFT) & V8Map.BYTE_MASK
        self.visitor_id = (word >> V8Map.VISITOR_ID_SHIFT) & V8Map.BYTE_MASK

    def _parse_intfield2(self, word):
        self.instance_type = (word >> V8Map.INSTANCE_TYPE_SHIFT) & V8Map.SHORT_MASK
        self.non_inst_prot = (word >> V8Map.NON_INST_PROT_SHIFT) & V8Map.BIT_MASK
        self.is_callable = (word >> V8Map.IS_CALLABLE_SHIFT) & V8Map.BIT_MASK
        self.named_inter = (word >> V8Map.NAMED_INTER_SHIFT) & V8Map.BIT_MASK
        self.index_inter = (word >> V8Map.INDEX_INTER_SHIFT) & V8Map.BIT_MASK
        self.is_undetect = (word >> V8Map.IS_UNDETECT_SHIFT) & V8Map.BIT_MASK
        self.access_check = (word >> V8Map.ACCESS_CHECK_SHIFT) & V8Map.BIT_MASK
        self.is_ctor = (word >> V8Map.IS_CTOR_SHIFT) & V8Map.BIT_MASK
        self.has_proto_slot = (word >> V8Map.HAS_PROTO_SLOT_SHIFT) & V8Map.BIT_MASK

        self.new_target = (word >> V8Map.NEW_TARGET_SHIFT) & V8Map.BIT_MASK
        self.is_immut_prot = (word >> V8Map.IS_IMMUT_PROT_SHIFT) & V8Map.BIT_MASK
        self.elements_kind = (word >> V8Map.ELEMENTS_KIND_SHIFT) & V8Map.FIVE_BIT_MASK

    def _parse_intfield3(self, word):
        self.enum_length = (word >> V8Map.ENUM_LENGTH_SHIFT) & V8Map.TEN_BIT_MASK
        self.num_own_desc = (word >> V8Map.NUM_OWN_DESC_SHIFT) & V8Map.TEN_BIT_MASK
        self.is_proto = (word >> V8Map.IS_PROTO_SHIFT) & V8Map.BIT_MASK
        self.is_dict = (word >> V8Map.IS_DICT_SHIFT) & V8Map.BIT_MASK
        self.owns_desc = (word >> V8Map.OWNS_DESC_SHIFT) & V8Map.BIT_MASK
        self.is_retained = (word >> V8Map.IS_RETAINED_SHIFT) & V8Map.BIT_MASK
        self.is_deprecated = (word >> V8Map.IS_DEPRECATED_SHIFT) & V8Map.BIT_MASK
        self.is_unstable = (word >> V8Map.IS_UNSTABLE_SHIFT) & V8Map.BIT_MASK
        self.is_migrate_target = (word >> V8Map.IS_MIGRATE_TRGT_SHIFT) & V8Map.BIT_MASK
        self.is_extensible = (word >> V8Map.IS_EXTENSIBLE_SHIFT) & V8Map.BIT_MASK
        self.interesting_sym = (word >> V8Map.INTERESTING_SYM_SHIFT) & V8Map.BIT_MASK
        self.constructed_ctr = (word >> V8Map.CONSTRUCTED_CTR_SHIFT) & V8Map.THREE_BIT_MASK

    def validate(self, addr_space):
        ptrs = [
            self.meta_map,
            self.prototype,
            self.ctor,
            self.descriptor_array,
            self.ldescriptors,
            self.dependent,
            self.transtions
        ]

        for ptr in ptrs:
            if not addr_space.is_valid_address(ptr - 1) and ptr != 0:
                return False

        """edge_case = self.validity
        if addr_space.is_valid_address(edge_case - 1) is False and edge_case != 0:
            return False
        """
        if self.is_map(self.descriptor_array - 1, addr_space):
            return False

        return True

    def is_meta_map(self):
        # print "Testing map at: " + str(hex(self.address))
        # print "metamap: " + hex(self.meta_map)
        return self.address == self.meta_map - 1

    def is_map(self, addr, addr_space):
        maybe_map = self._read_ptr(addr, addr_space)
        if maybe_map == self.meta_map:
            return True


class V8ProtoMap(V8Map):
    def _get_type_name(self, addr_space):
        offset_of_shared_info = (self.ctor - 1) + V8Map.SHARED_INFO_OFFSET
        # print hex(offset_of_shared_info)
        shared_info_addr = self._read_ptr(offset_of_shared_info, addr_space)
        # print "\tSFI addr: " + str(hex(shared_info_addr))
        # TODO MAKE IT SO WE CAN ALWAYS GET STRING
        offset_of_string = (shared_info_addr - 1) + (DWORD_SIZE * 2)
        str_ptr = self._read_ptr(offset_of_string, addr_space) - 1
        # print "\tstr_ptr: " + str(hex(str_ptr))
        maybe_name = self._read_string(str_ptr, addr_space)
        self.type_name = maybe_name
        # print "\ttype name: " + str(maybe_name)