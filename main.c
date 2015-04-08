#include <windows.h>
#include <Aclapi.h>
#include <sddl.h>
#include <conio.h>
#include <stdio.h>
#include <stdlib.h>

HRESULT CreateTestRegistryKey(wchar_t const* securityDescriptor);
void Failed(HRESULT hr);

int main(void)
{
    LONG lStatus;
    HRESULT hr;
    puts("Locked Registry Key Testing Tool");
    hr = CreateTestRegistryKey(L"O:BAG:BAD:PAI(A;CI;GA;;;SY)(A;CI;GR;;;WD)");
    if (hr == S_OK)
    {
        puts("Locked registry key HKEY_CURRENT_USER\\Software\\BillyONeal\\LockedTestKey created.");
    }
    else if (hr == S_FALSE)
    {
        puts("Locked registry key HKEY_CURRENT_USER\\Software\\BillyONeal\\LockedTestKey already present. Deleting...");
        hr = CreateTestRegistryKey(L"O:BAG:BAD:PAI(A;CI;GA;;;SY)(A;CI;GA;;;WD)");
        if (FAILED(hr))
        {
            Failed(hr);
            goto end;
        }

        lStatus = RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\BillyONeal\\LockedTestKey");
        if (lStatus != ERROR_SUCCESS)
        {
            Failed(HRESULT_FROM_WIN32(lStatus));
        }

        puts("Deleted.");
    }
    else
    {
        Failed(hr);
    }

end:

    puts("Press any key to exit.");
    _getch();
    return EXIT_SUCCESS;
}

HRESULT CreateTestRegistryKey(wchar_t const* securityDescriptor)
{
    HRESULT hr = S_OK;
    LSTATUS regStatus;
    HKEY hOuterKey = INVALID_HANDLE_VALUE;
    HKEY hKey = INVALID_HANDLE_VALUE;
    DWORD disposition;
    DWORD lastError;
    SECURITY_DESCRIPTOR* sd = NULL;
    PACL acl;
    SECURITY_ATTRIBUTES sa;
    BOOL unusedDaclPresent;
    BOOL unusedDaclDefaulted;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        securityDescriptor,
        SDDL_REVISION_1,
        &sd,
        NULL))
    {
        lastError = GetLastError();
        printf("Failed to make security descriptor \"%ls\": 0x%08X\n", securityDescriptor, lastError);
        hr = HRESULT_FROM_WIN32(lastError);
        goto cleanup;
    }

    if (!GetSecurityDescriptorDacl(sd, &unusedDaclPresent, &acl, &unusedDaclDefaulted))
    {
        lastError = GetLastError();
        printf("Failed to get ACL from SD: 0x%08X", lastError);
        hr = HRESULT_FROM_WIN32(lastError);
        goto cleanup;
    }

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = sd;

    regStatus = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\BillyONeal",
        0,
        NULL,
        0,
        KEY_READ | KEY_WOW64_64KEY,
        0,
        &hOuterKey,
        NULL
        );

    if (regStatus != ERROR_SUCCESS)
    {
        printf("Failed to create outer registry key: 0x%08X\n", regStatus);
        hr = HRESULT_FROM_WIN32(regStatus);
        goto cleanup;
    }

    regStatus = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\BillyONeal\\LockedTestKey",
        0,
        NULL,
        0,
        KEY_READ | WRITE_DAC | KEY_WOW64_64KEY,
        &sa,
        &hKey,
        &disposition
        );

    if (regStatus != ERROR_SUCCESS)
    {
        printf("Failed to create registry key: 0x%08X\n", regStatus);
        hr = HRESULT_FROM_WIN32(regStatus);
        goto cleanup;
    }

    if (disposition == REG_CREATED_NEW_KEY)
    {
        hr = S_OK;
    }
    else if (disposition == REG_OPENED_EXISTING_KEY)
    {
        hr = S_FALSE;

        regStatus = SetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, 0, 0, acl, 0);
        if (regStatus != ERROR_SUCCESS)
        {
            printf("Failed to set DACL: 0x%08X\n", regStatus);
            hr = HRESULT_FROM_WIN32(regStatus);
            goto cleanup;
        }
    }

cleanup:
    if (hKey != INVALID_HANDLE_VALUE)
    {
        RegCloseKey(hKey);
    }

    if (hOuterKey != INVALID_HANDLE_VALUE)
    {
        RegCloseKey(hOuterKey);
    }

    if (sd != NULL)
    {
        LocalFree(sd);
    }

    return hr;
}

void Failed(HRESULT hr)
{
    printf("Failed operation on registry key HKEY_CURRENT_USER\\Software\\BillyONeal\\LockedTestKey. HRESULT=0x%08X\n", hr);
}
