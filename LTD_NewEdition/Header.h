#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <Urlmon.h>
#include <Storm.h>
#include <atlenc.h>
#include <array>
#include <sstream>
#include <wininet.h>
#include <fstream>
#include <regex>
#include <vector>
#include <map>

#include "XorStr.hpp"

#pragma comment(lib, "Storm.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "wininet.lib")

using namespace std;