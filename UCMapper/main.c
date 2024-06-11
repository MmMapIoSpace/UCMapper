#include "main.h"

int __cdecl wmain(_In_ int argc, _In_ wchar_t** argv)
{
    NTSTATUS Status;
    PVOID ImageBase;
    SIZE_T ImageSize;
    LPWSTR DriverPath;
    DEVICE_DRIVER_OBJECT Driver;

    if (argc != 2) {
        Status = STATUS_INVALID_PARAMETER;
        DEBUG_PRINT_NTSTATUS(Status);
        DEBUG_PRINT("[!] invalid arguments.\r\n\t%ws <Driver Path>\r\n", argv[0]);
        return Status;
    }

    //
    // Map File as Image.
    //
    DriverPath = argv[1];
    Status     = RtlFileMapImage(DriverPath, &ImageBase, &ImageSize);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    //
    // Load driver and map image.
    //
    Status = LoadDriver(&Driver);
    if NT_SUCCESS (Status) {
        Status = MmLoadSystemImage(&Driver, ImageBase);
        DEBUG_PRINT("[+] Mapping result: 0x%08X.", Status);
        UnloadDriver(&Driver);
    }

    RtlFileUnmap(ImageBase);
    return Status;
}

LRESULT CALLBACK MainProcedure(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
    case WM_INITDIALOG: {
        Button_SetElevationRequiredState(GetDlgItem(hWnd, IDC_MAP), TRUE);
        // Place the window in the center of screen.
        RECT WindowRect;
        if (GetWindowRect(hWnd, &WindowRect)) {
            POINT Position;
            Position.x  = GetSystemMetrics(SM_CXSCREEN) / 2;
            Position.y  = GetSystemMetrics(SM_CYSCREEN) / 2;
            Position.x -= (WindowRect.right - WindowRect.left) / 2;
            Position.y -= (WindowRect.bottom - WindowRect.top) / 2;
            SetWindowPos(hWnd, HWND_TOP, Position.x, Position.y, 0, 0, SWP_NOSIZE);
        }

        return TRUE;
    }
    case WM_COMMAND: {
        WORD wmId    = LOWORD(wParam);
        WORD wmEvent = HIWORD(wParam);

        // Parse the menu selections:
        if (wmEvent == BN_CLICKED) {
            switch (wmId) {
            case IDC_BROWSE: {
                OPENFILENAME ofn;
                TCHAR szFile[260] = {0};

                // Inisialisasi struktur OPENFILENAME
                ZeroMemory(&ofn, sizeof(ofn));
                ofn.lStructSize  = sizeof(ofn);
                ofn.lpstrFile    = szFile;
                ofn.lpstrFile[0] = '\0';
                ofn.nMaxFile     = sizeof(szFile);
                ofn.lpstrFilter  = TEXT("Driver Files (*.sys)\0*.sys\0All Files (*.*)\0*.*\0");
                ofn.nFilterIndex = 1;
                ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

                // Membuka dialog pemilihan file
                if (GetOpenFileName(&ofn) == TRUE) {
                    // File dipilih, lakukan sesuatu dengan file tersebut
                    SetWindowText(GetDlgItem(hWnd, IDC_EDIT), szFile);
                }
                return TRUE;
            } break;

            case IDC_MAP: {
                NTSTATUS Status;
                WCHAR DriverPath[MAX_PATH] = {L'\0'};
                PVOID ImageBase;
                SIZE_T ImageSize;
                DEVICE_DRIVER_OBJECT Driver;

                GetWindowTextW(GetDlgItem(hWnd, IDC_EDIT), DriverPath, MAX_PATH);

                Status = RtlFileMapImage(DriverPath, &ImageBase, &ImageSize);
                if NT_ERROR (Status) {
                    MsgBoxFormat("Error: 0x%08X", Status);
                    return NT_SUCCESS(Status);
                }

                //
                // Load driver and map image.
                //
                Status = LoadDriver(&Driver);
                if NT_SUCCESS (Status) {
                    Status = MmLoadSystemImage(&Driver, ImageBase);
                    MsgBoxFormat("Mapping result: 0x%08X.", Status);
                    UnloadDriver(&Driver);
                }

                RtlFileUnmap(ImageBase);
                return NT_SUCCESS(Status);
            } break;

            default:
                break;
            }
        }
        break;
    } break;

    case WM_CLOSE:
    case WM_DESTROY:
        EndDialog(hWnd, 0);
        break;
    default:

        break;
    }

    return FALSE;
}

LRESULT CALLBACK InitProcedure(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
    case WM_CREATE:
        break;

    case WM_DESTROY: {
        DestroyWindow(hwndDlg);
        PostQuitMessage(0);
        break;
    }

    break;
    default:

        return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
    }

    return FALSE;
}

ATOM APIENTRY RegisterWindow(_In_ HINSTANCE hInstance)
{
    WNDCLASSEX wcex;
    ZeroMemory(&wcex, sizeof(WNDCLASSEX));
    wcex.cbSize        = sizeof(WNDCLASSEX);
    wcex.style         = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc   = InitProcedure;
    wcex.cbClsExtra    = 0;
    wcex.cbWndExtra    = 0;
    wcex.hInstance     = hInstance;
    wcex.hIcon         = LoadIcon(hInstance, MAKEINTRESOURCE(IDC_ICON));
    wcex.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszClassName = L"UCMapper";
    wcex.hIconSm       = LoadIcon(hInstance, MAKEINTRESOURCE(IDC_ICON));
    // wcex.lpszMenuName = MAKEINTRESOURCEW(IDI_MENU);
    return RegisterClassEx(&wcex);
}

BOOL APIENTRY CreateInstance(_In_ HINSTANCE hInstance, _Out_ HANDLE* Mutex, _Out_ HWND* hWnd)
{
    *hWnd  = NULL;
    *Mutex = NULL; // Initialize Mutex to NULL

    *Mutex = CreateMutex(NULL, TRUE, L"UCMapper");
    if (GetLastError() == ERROR_ALREADY_EXISTS || *Mutex == INVALID_HANDLE_VALUE
        || *Mutex == NULL) {
        MessageBox(NULL, L"Program is already running.", L"Error", MB_ICONERROR);
        if (*Mutex)
            CloseHandle(*Mutex);

        return FALSE;
    }

    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        MessageBox(NULL, L"Error initializing Common Control.", L"Error", MB_ICONERROR);
        CoUninitialize();
        if (*Mutex) {
            CloseHandle(*Mutex);
            *Mutex = NULL; // Set Mutex to NULL after closing the handle
        }

        return FALSE;
    }

    RegisterWindow(hInstance);
    *hWnd = CreateWindow(
        L"UCMapper",
        L"UCMapper",
        WS_SYSMENU,
        CW_USEDEFAULT,
        0,
        0,
        0,
        NULL,
        NULL,
        hInstance,
        NULL);

    if (!*hWnd) {
        MessageBox(NULL, L"Failed to creating window.", L"Error", MB_ICONERROR);
        CoUninitialize();
        if (*Mutex) {
            CloseHandle(*Mutex);
            *Mutex = NULL; // Set Mutex to NULL after closing the handle
        }
        UnregisterClass(L"UCMapper", hInstance);

        return FALSE;
    }

    return TRUE;
}

BOOL APIENTRY wWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR pCmdLine,
    _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(pCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    int result = 0;
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (NULL != argv) {
        if (argc == 2) {
            result = wmain(argc, argv);
        }
        LocalFree(argv);
    }

    if (nCmdShow != SW_HIDE) {
        HWND MainWindow;
        HANDLE Mutex;
        if (CreateInstance(hInstance, &Mutex, &MainWindow)) {
            result = (int)
                DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), MainWindow, MainProcedure);
        }

        if (Mutex) {
            CloseHandle(Mutex);
            Mutex = NULL;
        }

        UnregisterClass(L"UCMapper", hInstance);
        if (MainWindow) {
            DestroyWindow(MainWindow);
            MainWindow = NULL;
        }
    }

    return result;
}
