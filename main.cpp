#include <Windows.h>
#include <iostream>
#include <cstring>
#include <vector>

std::vector<int> pattern_to_byte( const char* pattern )
{
    auto bytes = std::vector<int>{};
    const auto start = const_cast<char*>( pattern );
    const auto end = const_cast<char*>( pattern ) + strlen( pattern );

    for ( auto current = start; current < end; ++current )
    {
        if ( *current == '?' )
        {
            ++current;

            if ( *current == '?' )
                ++current;

            bytes.push_back( -1 );
        } else
        {
            bytes.push_back( strtoul( current, &current, 16 ) );
        }
    }
    return bytes;
}

std::uintptr_t find_pattern( const std::uint8_t* start_data, const std::size_t image_size, const char* pattern )
{
    const auto pattern_bytes = pattern_to_byte( pattern );
    const auto signature_size = pattern_bytes.size();
    const auto signature_bytes = pattern_bytes.data();

    for ( auto i = 0; i < image_size; i++ )
    {
        if ( start_data[ i ] == pattern_bytes[ 0 ] )
        {
            for ( std::size_t j = 1; j < signature_size; j++ )
            {
                if ( signature_bytes[ j ] != -1 && signature_bytes[ j ] != start_data[ i + j ] )
                    break;

                if ( j + 1 == signature_size )
                    return i;
            }
        }
    }

    return 0;
}

int main()
{
    const auto file_handle = CreateFileA( "ffxiv_dx11.exe", GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
    if ( file_handle == INVALID_HANDLE_VALUE )
    {
        std::printf( "[x] failed to create file\n" );
        return 1;
    }

    const auto file_mapping = CreateFileMappingA( file_handle, nullptr, PAGE_READONLY, 0, 0, nullptr );
    if ( !file_mapping )
    {
        std::printf( "[x] failed to create file mapping\n" );
        return 1;
    }

    const auto file_base = MapViewOfFile( file_mapping, FILE_MAP_READ, 0, 0, 0 );
    if ( !file_base )
    {
        std::printf( "[x] failed to map the file for ffxiv_dx11.exe\n" );
        CloseHandle( file_mapping );
        CloseHandle( file_handle );
        return 1;
    }

    if ( const auto dos_header = static_cast<PIMAGE_DOS_HEADER>( file_base ); dos_header->e_magic == IMAGE_DOS_SIGNATURE )
    {
        if ( const auto pe_header = reinterpret_cast<PIMAGE_NT_HEADERS>( reinterpret_cast<std::uint8_t*>( dos_header ) + dos_header->e_lfanew ); pe_header->Signature == IMAGE_NT_SIGNATURE )
        {
            const auto image_base = pe_header->OptionalHeader.ImageBase;
            const auto image_size = pe_header->OptionalHeader.SizeOfImage;
            const auto header_size = pe_header->OptionalHeader.SizeOfHeaders;
            const auto code_base = pe_header->OptionalHeader.BaseOfCode;
            std::cout << "Image base: 0x" << std::uppercase << std::hex << image_base << std::dec << std::endl;
            std::cout << "Image size: " << image_size << std::endl;
            const auto offset = find_pattern( static_cast<uint8_t*>( file_base ), image_size, "pattern goes brrrr" ) + code_base - header_size;
            std::cout << "offset: 0x" << std::uppercase << std::hex << offset << std::dec << std::endl;
            std::cout << "address: 0x" << std::uppercase << std::hex << image_base + offset << std::dec << std::endl;
        }
    } else
    {
        return 1;
    }

    system( "pause" );

    return 0;
}
