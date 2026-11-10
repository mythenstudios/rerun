//! Pins the written-out layout against the `windows-sys` structures and constants (ADR 0013,
//! "Layout constants"). The structures come in through dev-dependency features only; the
//! shipped feature set of `windows-sys` does not change. Nothing is called.

use std::mem::{offset_of, size_of};

use windows_sys::Win32::Storage::FileSystem::{
    VS_FFI_SIGNATURE, VS_FIXEDFILEINFO, VS_VERSION_INFO,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
    IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_FILE_DLL,
    IMAGE_FILE_HEADER, IMAGE_FILE_LARGE_ADDRESS_AWARE, IMAGE_LOAD_CONFIG_DIRECTORY32,
    IMAGE_LOAD_CONFIG_DIRECTORY64, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64,
    IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_OPTIONAL_HEADER32,
    IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER, IMAGE_SUBSYSTEM_NATIVE,
    IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_SUBSYSTEM_WINDOWS_GUI,
};
use windows_sys::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE,
    IMAGE_NUMBEROF_DIRECTORY_ENTRIES, IMAGE_OS2_SIGNATURE, IMAGE_OS2_SIGNATURE_LE,
    IMAGE_RESOURCE_DATA_ENTRY, IMAGE_RESOURCE_DATA_IS_DIRECTORY, IMAGE_RESOURCE_DIRECTORY,
    IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_RESOURCE_NAME_IS_STRING, IMAGE_SIZEOF_FILE_HEADER,
    IMAGE_SIZEOF_SECTION_HEADER, IMAGE_SIZEOF_SHORT_NAME, LANG_ENGLISH, LANG_NEUTRAL,
    SUBLANG_ENGLISH_US, SUBLANG_NEUTRAL,
};
use windows_sys::Win32::System::WindowsProgramming::IMAGE_DELAYLOAD_DESCRIPTOR;
use windows_sys::Win32::UI::WindowsAndMessaging::RT_VERSION;

use super as l;

fn us(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

#[test]
fn signatures_machines_and_flags_match_the_sdk() {
    assert_eq!(&IMAGE_DOS_SIGNATURE.to_le_bytes(), l::DOS_SIGNATURE);
    assert_eq!(&IMAGE_NT_SIGNATURE.to_le_bytes(), l::NT_SIGNATURE);
    assert_eq!(&IMAGE_OS2_SIGNATURE.to_le_bytes(), l::NE_SIGNATURE);
    assert_eq!(&IMAGE_OS2_SIGNATURE_LE.to_le_bytes(), l::LE_SIGNATURE);
    // `LX` has no constant in the SDK headers (OS/2 2.x); it is the `LE` signature with `X`.
    assert_eq!(l::LX_SIGNATURE, b"LX");

    assert_eq!(IMAGE_FILE_MACHINE_I386, l::MACHINE_I386);
    assert_eq!(IMAGE_FILE_MACHINE_AMD64, l::MACHINE_AMD64);
    assert_eq!(IMAGE_FILE_MACHINE_ARM64, l::MACHINE_ARM64);
    assert_eq!(IMAGE_FILE_LARGE_ADDRESS_AWARE, l::FILE_LARGE_ADDRESS_AWARE);
    assert_eq!(IMAGE_FILE_DLL, l::FILE_DLL);
    assert_eq!(IMAGE_NT_OPTIONAL_HDR32_MAGIC, l::OPTIONAL_MAGIC_PE32);
    assert_eq!(IMAGE_NT_OPTIONAL_HDR64_MAGIC, l::OPTIONAL_MAGIC_PE32_PLUS);
    assert_eq!(IMAGE_SUBSYSTEM_NATIVE, l::SUBSYSTEM_NATIVE);
    assert_eq!(IMAGE_SUBSYSTEM_WINDOWS_GUI, l::SUBSYSTEM_WINDOWS_GUI);
    assert_eq!(IMAGE_SUBSYSTEM_WINDOWS_CUI, l::SUBSYSTEM_WINDOWS_CUI);
}

#[test]
fn dos_and_file_headers_match_the_sdk() {
    assert_eq!(size_of::<IMAGE_DOS_HEADER>(), l::DOS_HEADER_SIZE);
    assert_eq!(offset_of!(IMAGE_DOS_HEADER, e_lfanew), l::DOS_E_LFANEW);

    assert_eq!(size_of::<IMAGE_FILE_HEADER>(), l::FILE_HEADER_SIZE);
    assert_eq!(us(IMAGE_SIZEOF_FILE_HEADER), l::FILE_HEADER_SIZE);
    assert_eq!(offset_of!(IMAGE_FILE_HEADER, Machine), l::FILE_MACHINE);
    assert_eq!(
        offset_of!(IMAGE_FILE_HEADER, NumberOfSections),
        l::FILE_NUMBER_OF_SECTIONS
    );
    assert_eq!(
        offset_of!(IMAGE_FILE_HEADER, SizeOfOptionalHeader),
        l::FILE_SIZE_OF_OPTIONAL_HEADER
    );
    assert_eq!(
        offset_of!(IMAGE_FILE_HEADER, Characteristics),
        l::FILE_CHARACTERISTICS
    );
    // The COFF header follows the 4-byte signature, the optional header the COFF header.
    for (file, opt) in [
        (
            offset_of!(IMAGE_NT_HEADERS32, FileHeader),
            offset_of!(IMAGE_NT_HEADERS32, OptionalHeader),
        ),
        (
            offset_of!(IMAGE_NT_HEADERS64, FileHeader),
            offset_of!(IMAGE_NT_HEADERS64, OptionalHeader),
        ),
    ] {
        assert_eq!(file, l::NT_SIGNATURE.len());
        assert_eq!(opt, file + l::FILE_HEADER_SIZE);
    }
}

#[test]
fn optional_headers_and_data_directories_match_the_sdk() {
    type O32 = IMAGE_OPTIONAL_HEADER32;
    type O64 = IMAGE_OPTIONAL_HEADER64;
    assert_eq!(offset_of!(O32, Magic), l::OPT_MAGIC);
    assert_eq!(offset_of!(O64, Magic), l::OPT_MAGIC);
    assert_eq!(offset_of!(O32, ImageBase), l::OPT32_IMAGE_BASE);
    assert_eq!(offset_of!(O64, ImageBase), l::OPT64_IMAGE_BASE);
    assert_eq!(offset_of!(O32, SizeOfHeaders), l::OPT_SIZE_OF_HEADERS);
    assert_eq!(offset_of!(O64, SizeOfHeaders), l::OPT_SIZE_OF_HEADERS);
    assert_eq!(offset_of!(O32, CheckSum), l::OPT_CHECKSUM);
    assert_eq!(offset_of!(O64, CheckSum), l::OPT_CHECKSUM);
    assert_eq!(offset_of!(O32, Subsystem), l::OPT_SUBSYSTEM);
    assert_eq!(offset_of!(O64, Subsystem), l::OPT_SUBSYSTEM);
    assert_eq!(
        offset_of!(O32, DllCharacteristics),
        l::OPT_DLL_CHARACTERISTICS
    );
    assert_eq!(
        offset_of!(O64, DllCharacteristics),
        l::OPT_DLL_CHARACTERISTICS
    );
    assert_eq!(
        offset_of!(O32, NumberOfRvaAndSizes),
        l::OPT32_NUMBER_OF_RVA_AND_SIZES
    );
    assert_eq!(
        offset_of!(O64, NumberOfRvaAndSizes),
        l::OPT64_NUMBER_OF_RVA_AND_SIZES
    );
    assert_eq!(offset_of!(O32, DataDirectory), l::OPT32_DATA_DIRECTORY);
    assert_eq!(offset_of!(O64, DataDirectory), l::OPT64_DATA_DIRECTORY);
    // The structures end with the 16 directories.
    let dirs = l::NUMBER_OF_DIRECTORY_ENTRIES * l::DATA_DIRECTORY_SIZE;
    assert_eq!(size_of::<O32>(), l::OPT32_DATA_DIRECTORY + dirs);
    assert_eq!(size_of::<O64>(), l::OPT64_DATA_DIRECTORY + dirs);

    assert_eq!(size_of::<IMAGE_DATA_DIRECTORY>(), l::DATA_DIRECTORY_SIZE);
    assert_eq!(
        us(IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
        l::NUMBER_OF_DIRECTORY_ENTRIES
    );
    assert_eq!(usize::from(IMAGE_DIRECTORY_ENTRY_IMPORT), l::DIR_IMPORT);
    assert_eq!(usize::from(IMAGE_DIRECTORY_ENTRY_RESOURCE), l::DIR_RESOURCE);
    assert_eq!(usize::from(IMAGE_DIRECTORY_ENTRY_SECURITY), l::DIR_SECURITY);
    assert_eq!(
        usize::from(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG),
        l::DIR_LOAD_CONFIG
    );
    assert_eq!(
        usize::from(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT),
        l::DIR_DELAY_IMPORT
    );
    assert_eq!(
        usize::from(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR),
        l::DIR_COM_DESCRIPTOR
    );
}

#[test]
fn sections_imports_and_load_config_match_the_sdk() {
    type S = IMAGE_SECTION_HEADER;
    assert_eq!(size_of::<S>(), l::SECTION_HEADER_SIZE);
    assert_eq!(us(IMAGE_SIZEOF_SECTION_HEADER), l::SECTION_HEADER_SIZE);
    assert_eq!(offset_of!(S, Name), l::SECTION_NAME);
    assert_eq!(us(IMAGE_SIZEOF_SHORT_NAME), l::SECTION_NAME_SIZE);
    // `Misc` is the union of `PhysicalAddress` and `VirtualSize`.
    assert_eq!(offset_of!(S, Misc), l::SECTION_VIRTUAL_SIZE);
    assert_eq!(offset_of!(S, VirtualAddress), l::SECTION_VIRTUAL_ADDRESS);
    assert_eq!(offset_of!(S, SizeOfRawData), l::SECTION_SIZE_OF_RAW_DATA);
    assert_eq!(
        offset_of!(S, PointerToRawData),
        l::SECTION_POINTER_TO_RAW_DATA
    );

    assert_eq!(
        size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
        l::IMPORT_DESCRIPTOR_SIZE
    );
    assert_eq!(offset_of!(IMAGE_IMPORT_DESCRIPTOR, Name), l::IMPORT_NAME);
    type D = IMAGE_DELAYLOAD_DESCRIPTOR;
    assert_eq!(size_of::<D>(), l::DELAYLOAD_DESCRIPTOR_SIZE);
    // `Attributes` is the union of `AllAttributes` and the bit field `RvaBased` (bit 0; the
    // SDK has no constant for it).
    assert_eq!(offset_of!(D, Attributes), l::DELAYLOAD_ATTRIBUTES);
    assert_eq!(offset_of!(D, DllNameRVA), l::DELAYLOAD_DLL_NAME_RVA);
    assert_eq!(l::DELAYLOAD_RVA_BASED, 1);

    assert_eq!(
        offset_of!(IMAGE_LOAD_CONFIG_DIRECTORY32, Size),
        l::LOAD_CONFIG_SIZE
    );
    assert_eq!(
        offset_of!(IMAGE_LOAD_CONFIG_DIRECTORY64, Size),
        l::LOAD_CONFIG_SIZE
    );
    assert_eq!(
        offset_of!(IMAGE_LOAD_CONFIG_DIRECTORY32, DependentLoadFlags),
        l::LOAD_CONFIG32_DEPENDENT_LOAD_FLAGS
    );
    assert_eq!(
        offset_of!(IMAGE_LOAD_CONFIG_DIRECTORY64, DependentLoadFlags),
        l::LOAD_CONFIG64_DEPENDENT_LOAD_FLAGS
    );
}

#[test]
fn resources_and_the_version_resource_match_the_sdk() {
    type Dir = IMAGE_RESOURCE_DIRECTORY;
    assert_eq!(size_of::<Dir>(), l::RESOURCE_DIRECTORY_SIZE);
    assert_eq!(
        offset_of!(Dir, NumberOfNamedEntries),
        l::RESOURCE_NUMBER_OF_NAMED_ENTRIES
    );
    assert_eq!(
        offset_of!(Dir, NumberOfIdEntries),
        l::RESOURCE_NUMBER_OF_ID_ENTRIES
    );
    type E = IMAGE_RESOURCE_DIRECTORY_ENTRY;
    assert_eq!(size_of::<E>(), l::RESOURCE_ENTRY_SIZE);
    // `Anonymous1` is the union of `Name` and `Id`, `Anonymous2` that of `OffsetToData` and
    // the directory bit field.
    assert_eq!(offset_of!(E, Anonymous1), l::RESOURCE_ENTRY_NAME);
    assert_eq!(offset_of!(E, Anonymous2), l::RESOURCE_ENTRY_OFFSET_TO_DATA);
    assert_eq!(IMAGE_RESOURCE_NAME_IS_STRING, l::RESOURCE_NAME_IS_STRING);
    assert_eq!(
        IMAGE_RESOURCE_DATA_IS_DIRECTORY,
        l::RESOURCE_DATA_IS_DIRECTORY
    );
    type Data = IMAGE_RESOURCE_DATA_ENTRY;
    assert_eq!(size_of::<Data>(), l::RESOURCE_DATA_ENTRY_SIZE);
    assert_eq!(
        offset_of!(Data, OffsetToData),
        l::RESOURCE_DATA_OFFSET_TO_DATA
    );
    assert_eq!(offset_of!(Data, Size), l::RESOURCE_DATA_SIZE);

    // `RT_VERSION` is `MAKEINTRESOURCE(16)`, a pointer-sized integer.
    assert_eq!(RT_VERSION.addr(), usize::from(l::RT_VERSION));
    assert_eq!(VS_VERSION_INFO, u32::from(l::VS_VERSION_INFO));
    // MAKELANGID(primary, sub) = sub << 10 | primary.
    assert_eq!(
        SUBLANG_NEUTRAL << 10 | LANG_NEUTRAL,
        u32::from(l::LANG_NEUTRAL)
    );
    assert_eq!(
        SUBLANG_ENGLISH_US << 10 | LANG_ENGLISH,
        u32::from(l::LANG_EN_US)
    );

    type F = VS_FIXEDFILEINFO;
    assert_eq!(size_of::<F>(), l::FIXED_FILE_INFO_SIZE);
    assert_eq!(VS_FFI_SIGNATURE.cast_unsigned(), l::FIXED_SIGNATURE_VALUE);
    assert_eq!(offset_of!(F, dwSignature), l::FIXED_SIGNATURE);
    assert_eq!(offset_of!(F, dwFileVersionMS), l::FIXED_FILE_VERSION_MS);
    assert_eq!(offset_of!(F, dwFileVersionLS), l::FIXED_FILE_VERSION_LS);
    assert_eq!(
        offset_of!(F, dwProductVersionMS),
        l::FIXED_PRODUCT_VERSION_MS
    );
    assert_eq!(
        offset_of!(F, dwProductVersionLS),
        l::FIXED_PRODUCT_VERSION_LS
    );
    assert_eq!(offset_of!(F, dwFileFlagsMask), l::FIXED_FILE_FLAGS_MASK);
    assert_eq!(offset_of!(F, dwFileFlags), l::FIXED_FILE_FLAGS);
    assert_eq!(offset_of!(F, dwFileOS), l::FIXED_FILE_OS);
    assert_eq!(offset_of!(F, dwFileType), l::FIXED_FILE_TYPE);
    assert_eq!(offset_of!(F, dwFileSubtype), l::FIXED_FILE_SUBTYPE);
}
