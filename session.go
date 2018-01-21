/* Copyright © 2018 Tim Peoples <coders@toolman.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

// Package passwd provides tools and utilities for entering, checking and
// changing passwords on the command line (without echoing back to the
// terminal)
package passwd // import "toolman.org/security/tools/passwd"

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"

	"toolman.org/time/timetool"
)

var mx sync.Mutex

// A PromptSet is a set of strings used for prompting the user to enter
// a password. Each field is used in a different situation.
type PromptSet struct {
	// Get is used in the simple case of prompting for a password.
	Get string

	// Old is used during a password change session to prompt for the user's
	// current password.
	Old string

	// New1 is used during a password change session as the first prompt asking
	// for the user's new password.
	New1 string

	// New2 is used during a password change session as the second prompt asking
	// for the user's new password.
	New2 string
}

// Prompts provides a reasonable set of default prompt values.
var Prompts = &PromptSet{
	Get:  "Password: ",
	Old:  "Old Password: ",
	New1: "New Password: ",
	New2: "New Password (again): ",
}

// GetPass prompts the user to enter a password (using the `Get` prompt), reads
// the password string from stdin without echoing back to the terminal, and
// returns the plain text password as a byte array -- or, returns nil and en
// error if a problem occurred.
func (p *PromptSet) GetPass() ([]byte, error) {
	return withSession(func(s *session) ([]byte, error) {
		return s.getPass(p.Get)
	})
}

// GetHash is a wrapper around GetPass that returns a bcrypt hash of the
// entered password.
func (p *PromptSet) GetHash() ([]byte, error) {
	return withSession(func(s *session) ([]byte, error) {
		return s.getHash(p.Get)
	})
}

// NewPass prompts the user to enter a new password two separate times -- first
// using the `New1` prompt then with the `New2` prompt, Each time it reads the
// password string from stdin without echoing back to the terminal. If the two
// password strings agree, the plain text password is returned as a byte array.
// If they do not, the user is informed as such and the cycle is restarted --
// unless the user presses `Enter` for both prompts (which aborts the process).
// Up to 4 attempts are made to acquire a new password.  If the user aborts the
// process, exhausts all attempts or some other error occurs, a nil array and
// an error is returned instead.
// error if a problem occurred.
func (p *PromptSet) NewPass() ([]byte, error) {
	return withSession(func(s *session) ([]byte, error) {
		return s.newPass(p.New1, p.New2)
	})
}

// NewHash is a wrapper around NewPass that returns a bcrypt hash of the
// entered password.
func (p *PromptSet) NewHash() ([]byte, error) {
	return withSession(func(s *session) ([]byte, error) {
		return s.newHash(p.New1, p.New2)
	})
}

// Check prompts the user for a password similar to GetPass then compares the
// entered password to the provided bcrypt hash value.  If they agree, nill is
// returned -- otherwise an approprate error is returned.
func (p *PromptSet) Check(hash []byte) error {
	_, err := withSession(func(s *session) ([]byte, error) {
		return s.checkPassword(p.Get, hash)
	})
	return err
}

// Change is a convenience wrapper around Check and NewHash for changing an
// exising passsword.  If the user's current password is provided as oldHash,
// the user is prompted for their current password (using the `Old` prompt). If
// and only if the entered password matches the priveded hash is the user then
// prompted to enter a new password similar to NewPass.  If successful, the
// bcrypt has of the newly entered password is returned -- or, if not, an
// appropriate error is emitted.
func (p *PromptSet) Change(oldHash []byte) ([]byte, error) {
	return withSession(func(s *session) ([]byte, error) {
		return s.changePassword(oldHash, p)
	})
}

// Compare is used to compare the provided plain-text password and bcrypt hash
// value. It is equivlent to bcrypt.CompareHashAndPassword(hash, pass)
func Compare(pass, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, pass)
}

type session struct {
	stdin *os.File
}

type sessionFunc func(*session) ([]byte, error)

func withSession(do sessionFunc) ([]byte, error) {
	mx.Lock()
	defer mx.Unlock()

	s, err := newSession()
	if err != nil {
		return nil, err
	}
	defer s.close()

	return do(s)
}

func newSession() (*session, error) {
	in, err := os.OpenFile("/dev/stdin", os.O_RDWR, 0777)
	if err != nil {
		return nil, err
	}

	return &session{in}, nil
}

func (s *session) close() error {
	return s.stdin.Close()
}

func (s *session) getPass(p string) ([]byte, error) {
	var (
		pass []byte
		err  error
	)

	fmt.Print(p)

	timetool.RetryWithBackoffDuration(50*time.Millisecond, 3, func(i int) bool {
		if pass, err = terminal.ReadPassword(int(s.stdin.Fd())); err == syscall.EAGAIN {
			return false
		}
		return true
	})

	fmt.Print("\n")

	return pass, err
}

func (s *session) newPass(p1, p2 string) ([]byte, error) {
	var (
		pass []byte
		err  error
		try  int
	)

	for {
		try++
		pv := make([]string, 2)
		for i, p := range []string{p1, p2} {
			var ba []byte
			if ba, err = s.getPass(p); err != nil {
				return nil, err
			}
			pv[i] = string(ba)
		}

		if pv[0] == pv[1] {
			pass = []byte(pv[0])
			break
		}

		if try == 4 {
			return nil, errors.New("all attempts exhausted")
		}

		msg := "Passwords do not match; try again"

		if try > 1 {
			msg += " (Press <Enter> twice to abort)"
		}

		fmt.Printf("\a\n%s\n\n\a", msg)
	}

	if len(pass) == 0 {
		return nil, errors.New("new password retrieval aborted")
	}

	return pass, nil
}

func (s *session) getHash(p string) ([]byte, error) {
	pass, err := s.getPass(p)
	if err != nil {
		return nil, err
	}

	return bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
}

func (s *session) newHash(p1, p2 string) ([]byte, error) {
	pass, err := s.newPass(p1, p2)
	if err != nil {
		return nil, err
	}

	return bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
}

func (s *session) checkPassword(prompt string, hash []byte) ([]byte, error) {
	pass, err := s.getPass(prompt)
	if err != nil {
		return nil, err
	}
	return nil, Compare(pass, hash)
}

func (s *session) changePassword(old []byte, ps *PromptSet) ([]byte, error) {
	if len(old) != 0 {
		if _, err := s.checkPassword(ps.Old, old); err != nil {
			return nil, err
		}
	}

	return s.newHash(ps.New1, ps.New2)
}
