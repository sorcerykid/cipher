--------------------------------------------------------
-- Minetest :: Simple Cipher Mod v1.0 (cipher)
--
-- See README.txt for licensing and other information.
-- Copyright (c) 2016-2019, Leslie E. Krause
--
-- ./games/just_test_tribute/mods/cipher/init.lua
--------------------------------------------------------

-- alphabet soup to be used by the tokenizer
local alphabet = "pdy3jbh7vms5zxrftnc9gqw"

cipher = { }

cipher.tokenize = function ( hash )
	local base = #alphabet
	local str = ""

	hash = hash + 4294836226

	while hash > 0 do
		local idx = hash % base + 1
		str = str .. string.sub( alphabet, idx, idx )
		hash = math.floor( hash / base )
	end

	return str
end

cipher.get_checksum = function ( input )
	local a = 378551
	local b = 63689
	local hash = 0
	local i = 0

	for i = 1, #input do
		hash = ( hash * a + string.byte( input, i ) ) % 2147483648
		a = ( a * b ) % 65536
	end

	return 4294967295 - hash
end

if cipher.tokenize( cipher.get_checksum( "sorcerykid" ) ) ~= "gfwd9pmd" then
	-- basic sanity check upon startup
	error( "[cipher] Failed to generate correct token from hash!" )
end
