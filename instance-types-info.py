import ctypes as cc
from enum import Enum



class StringRepresentationTag(Enum):
    kSeqStringTag = 0x0
    kConsStringTag = 0x1
    kExternalStringTag = 0x2
    kSlicedStringTag = 0x3
    kThinStringTag = 0x5




class InstanceTypes:

    # Enum for the various forms of tags used.
    STR_REP_TAG = StringRepresentationTag

    # We use the full 16 bits of the instance_type field to encode heap object
    # instance types. All the high-order bits (bits 6-15) are cleared if 
    # the object is a string, and contain set bits if it is not a string.
    kIsNotStringMask = cc.c_uint32(~((1 << 6) - 1))
    kStringTag       = cc.c_uint32(0x0)
    
    
    # For strings, bits 0-2 indicate the representation of the string. In
    # particular, bit 0 indicates whether the string is direct or indirect.
    kStringRepresentationMask = cc.c_uint32((1 << 3) - 1)
    kIsIndirectStringMask     = cc.c_uint32(1 << 0)
    kIsIndirectStringTag      = cc.c_uint32(1 << 0)
    
    # For strings, bit 3 indicates whether the string consists of two-byte
    # characters or one-byte characters.
    kStringEncodingMask = cc.c_uint32(1 << 3)
    kTwoByteStringTag   = cc.c_uint32(0)
    kOneByteStringTag   = cc.c_uint32(1 << 3)

    # For strings, bit 4 indicates whether the data pointer of an external 
    # string is cached. Note that the string representation is expected to be
    # kExternalStringTag
    kUncachedExternalStringMask = cc.c_uint32(1 << 4)
    kUncachedExternalStringTag  = cc.c_uint32(1 << 4)

    # For strings, bit 5 indicates that the string is internalized (if not set)
    # or isn't (if set)
    kIsNotInternalizedMask = cc.c_uint32(1 << 5)
    kNotInternalizedTag    = cc.c_uint32(1 << 5)
    kInternalizedTag       = cc.c_uint32(0);

    # A ConsString with an empty string as the right side is a candidate
    # for being shortcut by the garbage collector. We don't allocate any
    # non-flat internalized strings, so we do not shortcut them thereby
    # avoiding turning internalized strings into strings. The bit-masks
    # below contain the internalized bit as additional safety.
    # See heap.cc, mark-compact.cc and objects-visiting.cc.
    kShortcutTypeMask = cc.c_uint32(kIsNotStringMask.value | kIsNotInternalizedMask.value | kStringRepresentationMask.value)
    kShortcutTypeTag  = cc.c_uint32(STR_REP_TAG.kConsStringTag.value | kNotInternalizedTag.value)

    # String Types TODO: REVERSE ENGINEER THESE TYPES
    INTERNALIZED_STRING_TYPE                            = kTwoByteStringTag.value | STR_REP_TAG.kSeqStringTag.value | kInternalizedTag.value
    ONE_BYTE_INTERNALIZED_STRING_TYPE                   = kOneByteStringTag.value | STR_REP_TAG.kSeqStringTag.value | kInternalizedTag.value
    EXTERNAL_INTERNALIZED_STRING_TYPE                   = kTwoByteStringTag.value | STR_REP_TAG.kExternalStringTag.value | kInternalizedTag.value
    EXTERNAL_ONE_BYTE_INTERNALIZED_STRING_TYPE          = kOneByteStringTag.value | STR_REP_TAG.kExternalStringTag.value | kInternalizedTag.value

    UNCACHED_EXTERNAL_INTERNALIZED_STRING_TYPE          = EXTERNAL_INTERNALIZED_STRING_TYPE | kUncachedExternalStringTag.value | kInternalizedTag.value
    UNCACHED_EXTERNAL_ONE_BYTE_INTERNALIZED_STRING_TYPE = EXTERNAL_ONE_BYTE_INTERNALIZED_STRING_TYPE | kUncachedExternalStringTag.value | kInternalizedTag.value
    STRING_TYPE                                         = INTERNALIZED_STRING_TYPE | kNotInternalizedTag.value
    ONE_BYTE_STRING_TYPE                                = ONE_BYTE_INTERNALIZED_STRING_TYPE | kNotInternalizedTag.value
    CONS_STRING_TYPE                                    = kTwoByteStringTag.value | STR_REP_TAG.kConsStringTag.value | kNotInternalizedTag.value
    CONS_ONE_BYTE_STRING_TYPE                           = kOneByteStringTag.value | STR_REP_TAG.kConsStringTag.value | kNotInternalizedTag.value
    SLICED_STRING_TYPE                                  = kTwoByteStringTag.value | STR_REP_TAG.kSlicedStringTag.value | kNotInternalizedTag.value
    SLICED_ONE_BYTE_STRING_TYPE                         = kOneByteStringTag.value | STR_REP_TAG.kSlicedStringTag.value | kNotInternalizedTag.value
    EXTERNAL_STRING_TYPE                                = EXTERNAL_INTERNALIZED_STRING_TYPE | kNotInternalizedTag.value
    EXTERNAL_ONE_BYTE_STRING_TYPE                       = EXTERNAL_ONE_BYTE_INTERNALIZED_STRING_TYPE | kNotInternalizedTag.value
    UNCACHED_EXTERNAL_STRING_TYPE                       = UNCACHED_EXTERNAL_INTERNALIZED_STRING_TYPE | kNotInternalizedTag.value
    UNCACHED_EXTERNAL_ONE_BYTE_STRING_TYPE              = UNCACHED_EXTERNAL_ONE_BYTE_INTERNALIZED_STRING_TYPE | kNotInternalizedTag.value
    THIN_STRING_TYPE                                    = kTwoByteStringTag.value | STR_REP_TAG.kThinStringTag.value | kNotInternalizedTag.value
    THIN_ONE_BYTE_STRING_TYPE                           = kOneByteStringTag.value | STR_REP_TAG.kThinStringTag.value | kNotInternalizedTag.value
    
    # this value may change just for ref
    SYMBOL_T                                         = 64

    # Pseudo-types
    FIRST_UNIQUE_NAME_TYPE = INTERNALIZED_STRING_TYPE
    LAST_UNIQUE_NAME_TYPE = SYMBOL_T
    FIRST_NON_STRING_TYPE = SYMBOL_T
    LAST_JS_OBJECT_TYPE = 2132 # THIS NEEDS TO BE FIXED L8R
    LAST_JS_CUSTOM_ELEMENTS_OBJ_TYPE = 1041

    # convenient names for things where the generated name is akward
    FIRST_HEAP_OBJECT_TYPE  = 0 # from gen instance-type file make sure to check l8r
    LAST_HEAP_OBJECT_TYPE   = 2132 # from gen instance-type as well fix l8r
    BIG_INT_BASE_TYPE       = 65

    FIRST_TYPE              = FIRST_HEAP_OBJECT_TYPE
    LAST_TYPE               = LAST_HEAP_OBJECT_TYPE 
    BIGINT_TYPE             = BIG_INT_BASE_TYPE

    @classmethod
    def isShortcutCandidate(cls, int_type: int) -> bool:
        return ((int_type & kShortcutTypeMask.value) == kShortcutTypeTag.value)

    @classmethod 
    def getInstanceTypeInfo(cls):
        print("*" * 15,"INSTANCE TYPES FOR STRING", "*" * 15)
        for key, value in cls.__dict__.items():
            if "STRING" in key:
                print(f"{key:<64}: 0x{value:>02X} {value:>016b} {value:>5d}")


if __name__ == "__main__":
    InstanceTypes.getInstanceTypeInfo()
