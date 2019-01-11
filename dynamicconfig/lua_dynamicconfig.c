/**********************************************************\
|                                                          |
| xxtea.c                                                  |
|                                                          |
| XXTEA encryption algorithm library for Lua.              |
|                                                          |
| Encryption Algorithm Authors:                            |
|      David J. Wheeler                                    |
|      Roger M. Needham                                    |
|                                                          |
| Code Authors: Chen fei <cf850118@163.com>                |
|               Ma Bingyao <mabingyao@gmail.com>           |
| LastModified: Feb 7, 2016                                |
|                                                          |
\**********************************************************/

#include <string.h>
#include <errno.h>
#include<stdio.h>
#include<stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include "xxtea.h"
#include "b64.h"

static int _xxtea_encrypt(lua_State *L) {
	unsigned char *result;
	const char *data, *key;
	size_t data_len, key_len, out_len;

	data = luaL_checklstring(L, 1, &data_len);
	key  = luaL_checklstring(L, 2, &key_len);
	result = xxtea_encrypt(data, data_len, key, &out_len);

	if(result == NULL){
		lua_pushnil(L);
	}else{
		lua_pushlstring(L, (const char *)result, out_len);
		free(result);
	}

	return 1;
}

static int _xxtea_decrypt(lua_State *L) {
	unsigned char *result;
	const char *data, *key;
	size_t data_len, key_len, out_len;

	data = luaL_checklstring(L, 1, &data_len);
	key  = luaL_checklstring(L, 2, &key_len);
	result = xxtea_decrypt(data, data_len, key, &out_len);

	if(result == NULL){
		lua_pushnil(L);
	}else{
		lua_pushlstring(L, (const char *)result, out_len);
		free(result);
	}

	return 1;
}

static int _xor_encrypt(lua_State *L) {
	char *result;
	const char *data, *key;
	size_t data_len, key_len;

	data = luaL_checklstring(L, 1, &data_len);
	key  = luaL_checklstring(L, 2, &key_len);
	result = xor_encrypt(data, data_len, key, key_len);

	if(result == NULL){
		lua_pushnil(L);
	}else{
		lua_pushlstring(L, (const char *)result, data_len);
		free(result);
	}

	return 1;
}

static int _xor_decrypt(lua_State *L) {
	char *result;
	const char *data, *key;
	size_t data_len, key_len;

	data = luaL_checklstring(L, 1, &data_len);
	key  = luaL_checklstring(L, 2, &key_len);
	result = xor_decrypt(data, data_len, key, key_len);

	if(result == NULL){
		lua_pushnil(L);
	}else{
		lua_pushlstring(L, (const char *)result, data_len);
		free(result);
	}

	return 1;
}

static int _b64_setup(lua_State *L) {
	const char *key;
	size_t key_len;

	key = luaL_checklstring(L, 1, &key_len);
	b64_setup((unsigned char *)key);
	return 0;
}

static int _b64_encrypt(lua_State *L) {
	char *result;
	const char *data;
	size_t data_len;

	data = luaL_checklstring(L, 1, &data_len);
	result = (char *)b64_encode((const unsigned char *)data, data_len);

	if(result == NULL){
		lua_pushnil(L);
	}else{
		lua_pushlstring(L, (const char *)result, strlen(result));
		free(result);
	}

	return 1;
}

static int _b64_decrypt(lua_State *L) {
	char *result;
	const char *data;
	size_t data_len;

	data = luaL_checklstring(L, 1, &data_len);
	result = (char *)b64_decode((const unsigned char *)data, data_len);

	if(result == NULL){
		lua_pushnil(L);
	}else{
		lua_pushlstring(L, (const char *)result, strlen(result));
		free(result);
	}

	return 1;
}

static int _dofile(lua_State *L) {
  // const char *filename = luaL_optstring(L, 1, NULL);
  // int n = lua_gettop(L);
  // if (luaL_loadfile(L, filename) != 0) lua_error(L);
  // lua_call(L, 0, LUA_MULTRET);
  // return lua_gettop(L) - n;

	const char *filename = luaL_optstring(L, 1, NULL);
	const int encrypt = luaL_optint(L, 2, 0);

	int n = lua_gettop(L);

	FILE *f;
	if (filename == NULL) luaL_error(L, "dofile filename is null");

	f = fopen(filename, "rb");
	if (f == NULL)
	{
		luaL_error(L, "cannot open:%s", filename);
	}else
	{
		fseek(f, 0, SEEK_END);
		long fsize = ftell(f);
		rewind(f);

		char *buffer = (char*)malloc(sizeof(char)*fsize + 1);
		if (!buffer)
		{
			luaL_error(L, "fail to malloc len of char:%d", fsize);
		}
		else
		{
			// set the memory to zero before you copy in.
			// the fsize + 1 byte will be 0 which is NULL '\0'
			// note, we clear memory and add the NULL at the same time
			memset(buffer, 0, sizeof(char)*fsize + 1);

			fread(buffer, sizeof(char), fsize, f);

			/* Make sure the buffer is NUL-terminated, just in case */
			// size_t fsz;
			// fsz = (size_t)fsize;
			// buffer[fsz] = '\0';
			buffer[fsize] = '\0';

			if(encrypt == 1)
			{
				char *result = (char *)b64_decode((const unsigned char *)buffer, strlen((char *)buffer));
				free(buffer);
				buffer = result;
			}

			if (luaL_loadbuffer(L, buffer, strlen(buffer), filename) == 0)
			{
				 if(lua_pcall(L, 0, LUA_MULTRET, 0) != 0)
				 {
				 	luaL_error(L, "lua_pcall error");
				 }
			}

			free(buffer);
		}

		fclose(f);
	}
	

	return lua_gettop(L) - n;
}

static const luaL_Reg dynamicconfig[] = {
	{"xxtea_encrypt",	_xxtea_encrypt},
	{"xxtea_decrypt",	_xxtea_decrypt},
	{"xor_encrypt",		_xor_encrypt},
	{"xor_decrypt",		_xor_decrypt},
	{"b64_setup",		_b64_setup},
	{"b64_encrypt",		_b64_encrypt},
	{"b64_decrypt",		_b64_decrypt},
	{"dofile",			_dofile},
	{0, 0}
};

LUALIB_API int luaopen_dynamicconfig(lua_State * L) {
#if LUA_VERSION_NUM >= 502 // LUA 5.2 or above
    lua_newtable(L);
    luaL_setfuncs(L, dynamicconfig, 0);
#else
	luaL_register(L, "dynamicconfig", dynamicconfig);
#endif
	return 1;
}
