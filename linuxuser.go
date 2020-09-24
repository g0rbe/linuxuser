/*

Package linuxuser parses `/etc/passwd` and if the permissions allows, the `/etc/shadow`.

*/

package linuxuser

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

// Shadow stores the fields of a user in `/etc/shadow`.
type Shadow struct {
	Password    string // Password hash
	Lastchanged int    // Number of days since Jan 1, 1970 that the password changed
	Minimum     int    // Number of days before password can be changed
	Maximum     int    // Number of days before a password change is required
	Warn        int    // The number of days before password is to expire that user is warned
	Inactive    int    // The number of days after password expires that account is disabled
	Expire      int    // Number of days since Jan 1, 1970 that account is disabled
}

// Passwd stores the fields of a user in `/etc/passwd`.
type Passwd struct {
	Username string // Username
	Password Shadow // Shadow struct, containing teh infomations about the password
	UID      int    // User's ID
	GID      int    // user's group ID
	Gecos    string // User's extra information
	Home     string // User's home directory
	Shell    string // user's default shell
}

// parseShadowLine parses a line of /etc/shadow and returns a struct from it.
// It seraches for username and parse the corresponding line.
// Returns an empty struct if EUID != 0.
func parseShadowLine(username string) (Shadow, error) {

	// Returns without error if not run as root
	if os.Geteuid() != 0 {
		return Shadow{}, nil
	}

	shadowFull, err := ioutil.ReadFile("/etc/shadow")

	if err != nil {
		return Shadow{}, fmt.Errorf("failed to read /etc/shadow: %s", err)
	}

	var fields []string

	for _, line := range strings.Split(string(shadowFull), "\n") {

		fields = strings.Split(line, ":")

		if fields[0] == username {
			break
		}
	}

	result := Shadow{}

	result.Password = fields[1]

	if fields[2] != "" {
		if result.Lastchanged, err = strconv.Atoi(fields[2]); err != nil {
			return result, fmt.Errorf("failed to convert Lastchanged: %s", err)
		}
	}

	if fields[3] != "" {
		if result.Minimum, err = strconv.Atoi(fields[3]); err != nil {
			return result, fmt.Errorf("failed to convert Minimum: %s", err)
		}
	}

	if fields[4] != "" {
		if result.Maximum, err = strconv.Atoi(fields[4]); err != nil {
			return result, fmt.Errorf("failed to convert Maximum: %s", err)
		}
	}

	if fields[5] != "" {
		if result.Warn, err = strconv.Atoi(fields[5]); err != nil {
			return result, fmt.Errorf("failed to convert Warn: %s", err)
		}
	}

	if fields[6] != "" {
		if result.Inactive, err = strconv.Atoi(fields[6]); err != nil {
			return result, fmt.Errorf("failed to convert Inactive: %s", err)
		}
	}

	if fields[7] != "" {
		if result.Expire, err = strconv.Atoi(fields[7]); err != nil {
			return result, fmt.Errorf("failed to convert Expire: %s", err)
		}
	}

	return result, nil
}

// parsePasswdLine parses a line of /etc/passwd and returns a struct from it.
func parsePasswdLine(line string) (Passwd, error) {

	fields := strings.Split(line, ":")

	var err error
	result := Passwd{}

	result.Username = fields[0]

	if fields[2] != "" {
		if result.UID, err = strconv.Atoi(fields[2]); err != nil {
			return result, fmt.Errorf("failed to convert Uid: %s", err)
		}
	}

	if fields[3] != "" {
		if result.GID, err = strconv.Atoi(fields[3]); err != nil {
			return result, fmt.Errorf("failed to convert Gid: %s", err)
		}
	}

	result.Gecos = fields[4]
	result.Home = fields[5]
	result.Shell = fields[6]

	return result, nil
}

// GetAll parses /etc/passwd and /etc/shadow, returns an array of every user's information.
// The `Shadow` struct will be an empty struct if the program dont
// have permission to read /etc/shadow.
func GetAll() ([]Passwd, error) {

	passwdFull, err := ioutil.ReadFile("/etc/passwd")

	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/passwd: %s", err)
	}

	result := make([]Passwd, 0, 10)

	for _, line := range strings.Split(string(passwdFull), "\n") {

		if line == "" {
			continue
		}

		passwd, err := parsePasswdLine(line)

		if err != nil {
			return nil, fmt.Errorf("failed to parse passwd line: %s", err)
		}

		passwd.Password, err = parseShadowLine(passwd.Username)

		if err != nil {
			return nil, fmt.Errorf("failed to parse shadow line: %s", err)
		}

		result = append(result, passwd)
	}

	return result, nil
}

// Current get the current user's information
func Current() (Passwd, error) {

	passwds, err := GetAll()

	if err != nil {
		return Passwd{}, fmt.Errorf("failed to get every user: %s", err)
	}

	for i := range passwds {
		if os.Geteuid() == passwds[i].UID {
			return passwds[i], nil
		}
	}

	return Passwd{}, fmt.Errorf("failed to find the current user")
}

// Lookup search for `username` in /etc/passwd.
// If the user cannot be found, an empty struct is returned.
func Lookup(username string) (Passwd, error) {

	passwds, err := GetAll()

	if err != nil {
		return Passwd{}, fmt.Errorf("failed to get every user: %s", err)
	}

	for i := range passwds {
		if passwds[i].Username == username {
			return passwds[i], nil
		}
	}

	return Passwd{}, nil
}

// LookupID search for `uid` in /etc/passwd.
// If the UID cannot be found, an empty struct is returned.
func LookupID(uid int) (Passwd, error) {

	passwds, err := GetAll()

	if err != nil {
		return Passwd{}, fmt.Errorf("failed to get every user: %s", err)
	}

	for i := range passwds {
		if passwds[i].UID == uid {
			return passwds[i], nil
		}
	}

	return Passwd{}, nil
}
