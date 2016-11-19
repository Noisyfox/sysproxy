#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include <Wininet.h>
#include <tchar.h>
#include <ras.h>
#include <raserror.h>

#pragma comment(lib, "rasapi32.lib")
#pragma comment(lib, "Wininet.lib")

enum RET_ERRORS
{
    RET_NO_ERROR = 0,
    INVALID_FORMAT = 1,
    NO_PERMISSION = 2,
    SYSCALL_FAILED = 3,
    NO_MEMORY = 4,
    INVAILD_OPTION_COUNT = 5,
};


void usage(LPCTSTR binName)
{
    _tprintf(_T("Usage: %s global <proxy server> [<bypass>]\n"), binName);
    _tprintf(_T("       %s pac <pac url>\n"), binName);
    _tprintf(_T("       %s off\n"), binName);

    exit(INVALID_FORMAT);
}

void reportWindowsError(LPCTSTR action)
{
    LPTSTR pErrMsg = NULL;
    DWORD errCode = GetLastError();
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                                FORMAT_MESSAGE_FROM_SYSTEM |
                                                FORMAT_MESSAGE_ARGUMENT_ARRAY,
                                                NULL,
                                                errCode,
                                                LANG_NEUTRAL,
                                                (LPTSTR)&pErrMsg,
                                                0,
                                                NULL);
    _ftprintf(stderr, _T("Error %s: %lu %s\n"), action, errCode, pErrMsg);
}


void reportError(LPCTSTR action)
{
    _ftprintf(stderr, _T("Error %s\n"), action);
}


void initialize(INTERNET_PER_CONN_OPTION_LIST* options, int option_count)
{
    if (option_count < 1)
    {
        exit(INVAILD_OPTION_COUNT);
    }

    DWORD dwBufferSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    options->dwSize = dwBufferSize;

    options->dwOptionCount = option_count;
    options->dwOptionError = 0;

    options->pOptions = (INTERNET_PER_CONN_OPTION*)calloc(option_count, sizeof(INTERNET_PER_CONN_OPTION));

    if (!options->pOptions)
    {
        exit(NO_MEMORY);
    }

    options->pOptions[0].dwOption = INTERNET_PER_CONN_FLAGS;
}


int apply_connect(INTERNET_PER_CONN_OPTION_LIST* options, LPTSTR conn)
{
    options->pszConnection = conn;

    BOOL result = InternetSetOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, options, sizeof(INTERNET_PER_CONN_OPTION_LIST));
    if (!result)
    {
        reportWindowsError(_T("setting options"));
        return SYSCALL_FAILED;
    }

    result = InternetSetOption(NULL, INTERNET_OPTION_PROXY_SETTINGS_CHANGED, NULL, 0);
    if (!result)
    {
        reportWindowsError(_T("propagating changes"));
        return SYSCALL_FAILED;
    }

    result = InternetSetOption(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
    if (!result)
    {
        reportWindowsError(_T("refreshing"));
        return SYSCALL_FAILED;
    }

    return RET_NO_ERROR;
}


int apply(INTERNET_PER_CONN_OPTION_LIST* options)
{
    DWORD dwCb = 0;
    DWORD dwRet;
    DWORD dwEntries = 0;
    LPRASENTRYNAME lpRasEntryName = NULL;

    dwRet = RasEnumEntries(NULL, NULL, lpRasEntryName, &dwCb, &dwEntries);

    if (dwRet == ERROR_BUFFER_TOO_SMALL)
    {
        lpRasEntryName = (LPRASENTRYNAME)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCb);

        if (lpRasEntryName == NULL)
        {
            reportError(_T("HeapAlloc"));
            return NO_MEMORY;
        }

        for (DWORD i = 0; i < dwEntries; i++)
        {
            lpRasEntryName[i].dwSize = sizeof(RASENTRYNAME);
        }

        dwRet = RasEnumEntries(NULL, NULL, lpRasEntryName, &dwCb, &dwEntries);

        int ret;

        if (ERROR_SUCCESS != dwRet)
        {
            reportError(_T("RasEnumEntries"));

            ret = SYSCALL_FAILED;
        }
        else
        {
            // First set default connection.
            ret = apply_connect(options, NULL);

            for (DWORD i = 0; i < dwEntries && ret == RET_NO_ERROR; i++)
            {
                ret = apply_connect(options, lpRasEntryName[i].szEntryName);
            }
        }

        HeapFree(GetProcessHeap(), 0, lpRasEntryName);

        return ret;
    }

    if (dwEntries >= 1)
    {
        reportError(_T("acquire buffer size"));
        return SYSCALL_FAILED;
    }

    // No ras entry, set default only.
    return apply_connect(options, NULL);
}


int _tmain(int argc, LPTSTR argv[])
{
#ifdef _UNICODE
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
#endif

    if (argc < 2)
    {
        usage(argv[0]);
    }

    INTERNET_PER_CONN_OPTION_LIST options;
    if (_tcscmp(argv[1], _T("off")) == 0)
    {
        initialize(&options, 1);

        options.pOptions[0].Value.dwValue = PROXY_TYPE_AUTO_DETECT | PROXY_TYPE_DIRECT;
    }
    else if (_tcscmp(argv[1], _T("global")) == 0 && argc >= 3)
    {
        initialize(&options, 3);

        options.pOptions[0].Value.dwValue = PROXY_TYPE_PROXY | PROXY_TYPE_DIRECT;

        options.pOptions[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        options.pOptions[1].Value.pszValue = argv[2];

        options.pOptions[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;

        if (argc > 4)
        {
            _tprintf(_T("Error: bypass list shouldn't contain spaces, please check parameters.\n"));
            usage(argv[0]);
        }
        else if (argc == 4)
        {
            options.pOptions[2].Value.pszValue = argv[3];
        }
        else
        {
            options.pOptions[2].Value.pszValue = _T("<local>");
        }
    }
    else if (_tcscmp(argv[1], _T("pac")) == 0 && argc >= 3)
    {
        initialize(&options, 2);

        options.pOptions[0].Value.dwValue = PROXY_TYPE_AUTO_PROXY_URL;

        options.pOptions[1].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
        options.pOptions[1].Value.pszValue = argv[2];
    }
    else
    {
        usage(argv[0]);
    }


    apply(&options);

    return RET_NO_ERROR;
}
