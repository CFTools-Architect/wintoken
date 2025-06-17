package wintoken

import (
	"fmt"
	"github.com/winlabs/gowin32"
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
	"unsafe"
)

const (
	WTS_CURRENT_SERVER_HANDLE windows.Handle = 0
)

// OpenProcessToken opens a process token using PID, pass 0 as PID for self token
func OpenProcessToken(pid int, tokenType tokenType) (*Token, error) {
	var (
		t               windows.Token
		duplicatedToken windows.Token
		procHandle      windows.Handle
		err             error
	)

	if pid == 0 {
		procHandle = windows.CurrentProcess()
	} else {
		procHandle, err = windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	}
	if err != nil {
		return nil, err
	}

	if err = windows.OpenProcessToken(procHandle, windows.TOKEN_ALL_ACCESS, &t); err != nil {
		return nil, err
	}

	defer windows.CloseHandle(windows.Handle(t))

	switch tokenType {
	case TokenPrimary:
		if err := windows.DuplicateTokenEx(t, windows.MAXIMUM_ALLOWED, nil, windows.SecurityDelegation, windows.TokenPrimary, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err)
		}
	case TokenImpersonation:
		if err := windows.DuplicateTokenEx(t, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err)
		}

	case TokenLinked:
		if err := windows.DuplicateTokenEx(t, windows.MAXIMUM_ALLOWED, nil, windows.SecurityDelegation, windows.TokenPrimary, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err)
		}
		dt, err := duplicatedToken.GetLinkedToken()
		windows.CloseHandle(windows.Handle(duplicatedToken))
		if err != nil {
			return nil, fmt.Errorf("error while getting LinkedToken: %w", err)
		}
		duplicatedToken = dt
	}

	return &Token{token: duplicatedToken, typ: tokenType}, nil
}

func checkState(state uint32) bool {
	switch state {
	case windows.WTSActive, windows.WTSConnected, windows.WTSDisconnected, windows.WTSIdle:
		return true
	default:
		return false
	}
}

// GetInteractiveToken gets the interactive token associated with an existing interactive session.
// It uses Windows API WTSEnumerateSessions, WTSQueryUserToken and DuplicateTokenEx to return a valid wintoken.
// Session is considered valid, if it's state is one of WTSActive, WTSConnected, WTSDisconnected or WTSIdle.
func GetInteractiveToken(tokenType tokenType) (*Token, error, uint32) {

	var selectedSession uint32

	switch tokenType {
	case TokenPrimary, TokenImpersonation, TokenLinked:
	default:
		return nil, ErrOnlyPrimaryImpersonationTokenAllowed, selectedSession
	}

	var (
		sessionPointer   uintptr
		sessionCount     uint32
		interactiveToken windows.Token
		duplicatedToken  windows.Token
		sessionID        uint32
	)

	err := windows.WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, (**windows.WTS_SESSION_INFO)(unsafe.Pointer(&sessionPointer)), &sessionCount)
	if err != nil {
		return nil, fmt.Errorf("error while enumerating sessions: %v", err), selectedSession
	}
	defer windows.WTSFreeMemory(sessionPointer)

	sessions := make([]*windows.WTS_SESSION_INFO, sessionCount)
	size := unsafe.Sizeof(windows.WTS_SESSION_INFO{})

	for i := range sessions {
		sessions[i] = (*windows.WTS_SESSION_INFO)(unsafe.Pointer(sessionPointer + (size * uintptr(i))))
	}

	for i := range sessions {
		if checkState(sessions[i].State) && sessions[i].SessionID != 0 && sessions[i].SessionID != 1 {
			console, _ := syscall.UTF16PtrFromString("console")
			services, _ := syscall.UTF16PtrFromString("services")
			if sessions[i].WindowStationName == console || sessions[i].WindowStationName == services {
				continue
			}
			sessionID = sessions[i].SessionID
			selectedSession = sessionID
			break
		}
	}
	if sessionID == 0 {
		return nil, ErrNoActiveSession, selectedSession
	}

	if err := windows.WTSQueryUserToken(sessionID, &interactiveToken); err != nil {
		return nil, fmt.Errorf("error while WTSQueryUserToken: %w", err), selectedSession
	}

	defer windows.CloseHandle(windows.Handle(interactiveToken))

	switch tokenType {
	case TokenPrimary:
		if err := windows.DuplicateTokenEx(interactiveToken, windows.MAXIMUM_ALLOWED, nil, windows.SecurityDelegation, windows.TokenPrimary, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err), selectedSession
		}
	case TokenImpersonation:
		if err := windows.DuplicateTokenEx(interactiveToken, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err), selectedSession
		}
	case TokenLinked:
		if err := windows.DuplicateTokenEx(interactiveToken, windows.MAXIMUM_ALLOWED, nil, windows.SecurityDelegation, windows.TokenPrimary, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err), selectedSession
		}
		dt, err := duplicatedToken.GetLinkedToken()
		windows.CloseHandle(windows.Handle(duplicatedToken))
		if err != nil {
			return nil, fmt.Errorf("error while getting LinkedToken: %w", err), selectedSession
		}
		duplicatedToken = dt
	}

	if windows.Handle(duplicatedToken) == windows.InvalidHandle {
		return nil, ErrInvalidDuplicatedToken, selectedSession
	}

	return &Token{typ: tokenType, token: duplicatedToken}, nil, selectedSession
}

// GetInteractiveTokenByUser gets the interactive token associated with an existing interactive session created for a defined user.
// It uses Windows API WTSEnumerateSessions, WTSServer query and DuplicateTokenEx to return a valid wintoken.
// Session is considered valid, if it's state is one of WTSActive, WTSConnected, WTSDisconnected or WTSIdle.
func GetInteractiveTokenByUser(tokenType tokenType, account string) (*Token, error) {
	switch tokenType {
	case TokenPrimary, TokenImpersonation, TokenLinked:
	default:
		return nil, ErrOnlyPrimaryImpersonationTokenAllowed
	}

	var (
		sessionPointer   uintptr
		sessionCount     uint32
		interactiveToken windows.Token
		duplicatedToken  windows.Token
	)

	// Enumerate all sessions
	err := windows.WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, (**windows.WTS_SESSION_INFO)(unsafe.Pointer(&sessionPointer)), &sessionCount)
	if err != nil {
		return nil, fmt.Errorf("error while enumerating sessions: %v", err)
	}
	defer windows.WTSFreeMemory(sessionPointer)

	size := unsafe.Sizeof(windows.WTS_SESSION_INFO{})
	var sessionID uint32
	found := false

	// Loop over sessions and find an active session matching the specified user
	for i := uint32(0); i < sessionCount; i++ {
		sessionInfo := (*windows.WTS_SESSION_INFO)(unsafe.Pointer(sessionPointer + uintptr(i)*size))

		if !checkState(sessionInfo.State) {
			continue // Find another session, state of this session in unacceptable.
		}

		username, err := querySessionUsername(sessionInfo.SessionID)
		if err != nil {
			continue // ignore sessions we can't query
		}

		if strings.EqualFold(username, account) {
			sessionID = sessionInfo.SessionID
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("no active session found for user: %s", account)
	}

	// Get user token for the session
	if err := windows.WTSQueryUserToken(sessionID, &interactiveToken); err != nil {
		return nil, fmt.Errorf("error while WTSQueryUserToken: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(interactiveToken))

	// Duplicate the token as requested
	switch tokenType {
	case TokenPrimary:
		if err := windows.DuplicateTokenEx(interactiveToken, windows.MAXIMUM_ALLOWED, nil, windows.SecurityDelegation, windows.TokenPrimary, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err)
		}
	case TokenImpersonation:
		if err := windows.DuplicateTokenEx(interactiveToken, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err)
		}
	case TokenLinked:
		if err := windows.DuplicateTokenEx(interactiveToken, windows.MAXIMUM_ALLOWED, nil, windows.SecurityDelegation, windows.TokenPrimary, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err)
		}
		dt, err := duplicatedToken.GetLinkedToken()
		windows.CloseHandle(windows.Handle(duplicatedToken))
		if err != nil {
			return nil, fmt.Errorf("error while getting LinkedToken: %w", err)
		}
		duplicatedToken = dt
	}

	if windows.Handle(duplicatedToken) == windows.InvalidHandle {
		return nil, ErrInvalidDuplicatedToken
	}

	return &Token{typ: tokenType, token: duplicatedToken}, nil
}

func querySessionUsername(sessionID uint32) (string, error) {

	server := gowin32.OpenWTSServer("127.0.0.1")
	defer server.Close()
	username, err := server.QuerySessionUserName(uint(sessionID))
	if err != nil {
		return "", fmt.Errorf("querySessionUserName failed! Err: %s", err)
	}

	return username, nil
}
