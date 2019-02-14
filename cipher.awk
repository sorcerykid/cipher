#!/bin/awk -f

function ord_init( _low, _high, _i, _t )
{
	_low = 0;
	_high = 127;
	for( _i = _low; _i <= _high; _i++ ) {
		_t = sprintf( "%c", _i );
		ord_data[ _t ] = _i;
	}
}

function ord( _s, _i )
{
	return ord_data[ substr( _s, _i, 1 ) ]
}

function chr( _c )
{
	return sprintf( "%c", _c );
}

function getToken( idx, _alphabet, _str, _base )
{
	_alphabet = "7pdy3jbhvms5zxrftnc9gqw";
	_base = length( _alphabet );

	idx += 4294836226;
	while( idx > 0 ) {
		_str = _str substr( _alphabet, idx % _base + 1, 1 );
		idx = int( idx / _base );
        }

        return _str;
}

function getChecksum( input, _a, _b, _hash, _idx )
{
	_a = 378551;
	_b = 63689;
	_hash = 0;
	_i = 0;

	for( _i = 0; _i < length( input ); _i++ ) {
		_hash = ( _hash * _a + ord( input, _i + 1 ) ) % 2147483648;
		_a = ( _a * _b ) % 65536;
	}
	return 4294967295 - _hash;
}

BEGIN {
	ord_init( );

	x = "sorcerykid";
	print getChecksum( x ) "->" getToken( getChecksum( x ) )
}

