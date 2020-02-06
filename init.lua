--------------------------------------------------------
-- Minetest :: Simple Cipher Mod v1.1 (cipher)
--
-- See README.txt for licensing and other information.
-- Copyright (c) 2016-2020, Leslie E. Krause
--
-- ./games/just_test_tribute/mods/cipher/init.lua
--------------------------------------------------------

dofile( "/home/minetest/games/minetest_game/mods/bitwise/init.lua" )

cipher = { }

cipher.alphabet = "7pdy3jbhvms5zxrftnc9gqw"
cipher.password = "password123"

-------------------------------

local LSHIFT = LSHIFT
local RSHIFT = RSHIFT
local XOR = XOR
local AND = AND

local floor = math.floor
local ceil = math.ceil
local sub = string.sub
local to_char = string.char
local to_byte = string.byte

-------------------------------------------

local algorithms = {
	-- https://gchq.github.io/CyberChef/#recipe=Adler-32_Checksum()&input=VGVzdA
	-- "Minetest" -> 0x0e35034a
	adler32 = function ( str )
		local a = 1
		local b = 0

		for i = 1, #str do
               		a = ( a + to_byte( str, i ) ) % 65521
                	b = ( a + b ) % 65521
		end

		return b * 65536 + a	-- put first sum into lower 16 bits and second sum into upper 16 bits
	end,
	-- https://gchq.github.io/CyberChef/#recipe=Fletcher-16_Checksum()&input=VGVzdA
	-- "Minetest" -> 0x3b4c
	fletcher16 = function ( str )
		local a = 0
		local b = 0

		for i = 1, #str do
               		a = ( a + to_byte( str, i ) ) % 255
                	b = ( a + b ) % 255
		end

		return b * 256 + a	-- put first sum into lower 8 bits and second sum into upper 8 bits
	end,
	-- https://gchq.github.io/CyberChef/#recipe=Fletcher-32_Checksum()&input=VGVzdA
	-- "Minetest" -> 0x0e2d0349
	fletcher32 = function ( str )
		local a = 0
		local b = 0

		for i = 1, #str do
               		a = ( a + to_byte( str, i ) ) % 65535
                	b = ( a + b ) % 65535
		end

		return b * 65536 + a	-- put first sum into lower 16 bits and second sum into upper 16 bits
	end,
	-- https://gchq.github.io/CyberChef/#recipe=Fletcher-64_Checksum()&input=VGVzdA
	-- "Minetest" -> 0x00000e2d00000349
	fletcher64 = function ( str )
		local a = 0
		local b = 0

		for i = 1, #str do
               		a = ( a + to_byte( str, i ) ) % 4294967295
                	b = ( a + b ) % 4294967295
		end

		return b * 4294967296 + a	-- put first sum into lower 32 bits and second sum into upper 32 bits
	end,
}

-------------------------------

cipher.get_checksum = function ( str, method )
	return algorithms[ method or "adler32" ]( str )
end

cipher.tokenize = function ( hash )
	local base = #alphabet
	local str = ""

	hash = hash + cipher.get_checksum( password, "fletcher64" )

	while hash > 0 do
		local idx = hash % base + 1
		str = str .. sub( alphabet, idx, idx )
		hash = floor( hash / base )
	end

	return str
end

-------------------------------

local _

local function is_match( text, glob )
        -- use array for captures
        _ = { string.match( text, glob ) }
        return #_ > 0 and _ or nil
end

local function to_byte_fill( str, idx )
	return to_byte( str, idx ) or 0x00
end

local function to_char_trim( num )
	return num == 0 and "" or to_char( num )
end

local function string_to_blocks( str, off, can_fill )
	local blocks = { }
	local to_byte = can_fill and to_byte_fill or to_byte

	-- dissassemble string into pairs of DWORDs and pad with zeroes, if necessary
	for idx = 1 + off, ceil( #str / 8 ) do
		local b1 = to_byte( str, 8 * idx - 7 )
		local b2 = to_byte( str, 8 * idx - 6 )
		local b3 = to_byte( str, 8 * idx - 5 )
		local b4 = to_byte( str, 8 * idx - 4 )
		local b5 = to_byte( str, 8 * idx - 3 )
		local b6 = to_byte( str, 8 * idx - 2 )
		local b7 = to_byte( str, 8 * idx - 1 )
		local b8 = to_byte( str, 8 * idx )

		-- block must be 64-bits (big endian) for XTEA algorithm to work
		table.insert( blocks, {
			upper = b1 * 16777216 + b2 * 65536 + b3 * 256 + b4,	-- upper 32-bits as <b1><b2><b3><b4>
			lower = b5 * 16777216 + b6 * 65536 + b7 * 256 + b8,	-- lower 32-bits as <b5><b6><b7><b8>
		} )
	end

	return blocks
end

local function serialize( upper, lower, can_trim )
	local to_char = can_trim and to_char_trim or to_char

	return table.concat( {
		to_char( AND( RSHIFT( upper, 24 ), 0xFF ) ),	-- 0x??000000 (byte 1)
		to_char( AND( RSHIFT( upper, 16 ), 0xFF ) ),	-- 0x00??0000 (byte 2)
		to_char( AND( RSHIFT( upper, 8 ), 0xFF ) ),	-- 0x0000??00 (byte 3)
		to_char( AND( upper, 0xFF ) ),			-- 0x000000?? (byte 4)
		to_char( AND( RSHIFT( lower, 24 ), 0xFF ) ),	-- 0x??000000 (byte 5)
		to_char( AND( RSHIFT( lower, 16 ), 0xFF ) ),	-- 0x00??0000 (byte 6)
		to_char( AND( RSHIFT( lower, 8 ), 0xFF ) ),	-- 0x0000??00 (byte 7)
		to_char( AND( lower, 0xFF ) ),			-- 0x000000?? (byte 8)
	}, "" )
end

cipher.generate_key = function ( username, password )
	local upper = cipher.get_checksum( password or cipher.password, "fletcher64" )	-- get password checksum for private key
	local lower = cipher.get_checksum( username, "fletcher64" )			-- get username checksum for public key

	-- generate a 128-bit key from the two 64-bit hashes

	local key = {
		AND( RSHIFT( upper, 32 ), 0xFFFFFFFF ),
		AND( upper, 0xFFFFFFFF ),
		AND( RSHIFT( lower, 32 ), 0xFFFFFFFF ),
		AND( lower, 0xFFFFFFFF ),
	}

--	print( "key = ", key[ 1 ], key[ 2 ], key[ 3 ], key[ 4 ] )

	return key
end

cipher.decrypt_from_base64 = function ( str, username )
	local key = cipher.generate_key( username )
	local head = string.sub( str, 1, 8 )
	local data = minetest.decode_base64( string.sub( str, 9 ) )

	return cipher.decrypt( head .. data, key )
end

cipher.encrypt_to_base64 = function ( str, username )
	local key = cipher.generate_key( username )
	local out = cipher.encrypt( 32, str, key )

	return string.sub( out, 1, 8 ) .. minetest.encode_base64( string.sub( out, 9 ) )
end

cipher.decrypt = function ( str, key )
	local ver, num

	-- format of 8-byte header-block for encrypted strings: SC<VER>/<NUM>/
	-- <VER> is the major revision of SimpleCipher in decimal (currently 01)
	-- <NUM> is the number of rounds minus one in octal (64 maximum rounds)

	if is_match( str, "^SC([0-9][0-9])/([0-7][0-7])/" ) then
		ver = tonumber( _[ 1 ] )
		num = tonumber( _[ 2 ], 8 ) + 1

		assert( ver == 1, "Unsupported version in stream header." )
		assert( #str % 8 == 0, "Invalid stream length." )		-- encrypted string must be a multiple of 8-bytes!
	else
		error( "Unable to parse stream header." )
	end

	local blocks = string_to_blocks( str, 1, false )	-- be sure to skip over header-block
	local chunks = { }

	-- perform block-chain decryption by iterating the 64-bit blocks
	-- based on XTEA algorithm: https://en.wikipedia.org/wiki/XTEA

	for _, val in ipairs( blocks ) do
		local v1 = val.upper	-- upper DWORD of block
		local v2 = val.lower	-- lower DWORD of block
		local delta = 0x9E3779B9
		local sum = delta * num

		for idx = 1, num do
			-- print( "block (in) = ", v1, v2 )

			v2 = v2 - XOR( XOR( LSHIFT( v1, 4 ), RSHIFT( v1, 5 ) ) + v1, sum + key[ 1 + AND( RSHIFT( sum, 11 ), 3 ) ] )
			v2 = AND( v2 < 0 and NOT32( math.abs( v2 ) ) + 1 or v2, 0xFFFFFFFF )  -- avoid negatives and limit to 32-bits
			sum = sum - delta
			v1 = v1 - XOR( XOR( LSHIFT( v2, 4 ), RSHIFT( v2, 5 ) ) + v2, sum + key[ 1 + AND( sum, 3 ) ] )
			v1 = AND( v1 < 0 and NOT32( math.abs( v1 ) ) + 1 or v1, 0xFFFFFFFF )  -- avoid negatives and limit to 32-bits

			-- print( "block (out) = ", v1, v2 )
		end

		table.insert( chunks, serialize( v1, v2, true ) )	-- serialize block as a string of 8 bytes
	end

	-- string concat is slow, so assemble string chunks via temporary table
	return table.concat( chunks, "" ), ver, num
end

cipher.encrypt = function ( num, str, key )
	local blocks = string_to_blocks( str, 0, true )
	local chunks = {
		string.format( "SC%02d/%02o/", 1, num - 1 )		-- begin with 8-byte header-block
	}

	-- perform block-chain encryption by iterating the 64-bit blocks
	-- based on XTEA algorithm: https://en.wikipedia.org/wiki/XTEA

	for _, val in ipairs( blocks ) do
		local v1 = val.upper	-- upper DWORD of block
		local v2 = val.lower	-- lower DWORD of block
		local delta = 0x9E3779B9
		local sum = 0

		for idx = 1, num do
			-- print( "block (in) = ", v1, v2 )

			v1 = v1 + XOR( XOR( LSHIFT( v2, 4 ), RSHIFT( v2, 5 ) ) + v2, sum + key[ 1 + AND( sum, 3 ) ] )
			v1 = AND( v1, 0xFFFFFFFF )	-- limit to 32 bits
			sum = AND( sum + delta, 0xFFFFFFFF )
			v2 = v2 + XOR( XOR( LSHIFT( v1, 4 ), RSHIFT( v1, 5 ) ) + v1, sum + key[ 1 + AND( RSHIFT( sum, 11 ), 3 ) ] )
			v2 = AND( v2, 0xFFFFFFFF )	-- limit to 32 bits

			-- print( "block (out) = ", v1, v2 )
		end

		table.insert( chunks, serialize( v1, v2, false ) )	-- serialize block as a string of 8 bytes
	end

	return table.concat( chunks, "" )
end

-------------------------------

if cipher.get_checksum( "Minetest" ) ~= 0x0e35034a then
	error( "[cipher] Failed to generate correct checksum from Adler32!" )
elseif cipher.get_checksum( "Minetest", "fletcher16" ) ~= 0x3b4c then
	error( "[cipher] Failed to generate correct checksum from Fletcher16!" )
elseif cipher.get_checksum( "Minetest", "fletcher32" ) ~= 0x0e2d0349 then
	error( "[cipher] Failed to generate correct checksum from Fletcher32!" )
elseif cipher.get_checksum( "Minetest", "fletcher64" ) ~= 0x00000e2d00000349 then
	error( "[cipher] Failed to generate correct checksum from Fletcher64!" )
end
