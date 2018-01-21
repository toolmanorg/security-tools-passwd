

# passwd
`import "toolman.org/security/tools/passwd"`

* [Overview](#pkg-overview)
* [Index](#pkg-index)

## <a name="pkg-overview">Overview</a>
Package passwd provides tools and utilities for entering, checking and
changing passwords on the command line (without echoing back to the
terminal)


## <a name="pkg-overview">Install</a>

    go get toolman.org/security/tools/passwd

## <a name="pkg-index">Index</a>
* [Variables](#pkg-variables)
* [func Compare(pass, hash []byte) error](#Compare)
* [type PromptSet](#PromptSet)
  * [func (p *PromptSet) Change(oldHash []byte) ([]byte, error)](#PromptSet.Change)
  * [func (p *PromptSet) Check(hash []byte) error](#PromptSet.Check)
  * [func (p *PromptSet) GetHash() ([]byte, error)](#PromptSet.GetHash)
  * [func (p *PromptSet) GetPass() ([]byte, error)](#PromptSet.GetPass)
  * [func (p *PromptSet) NewHash() ([]byte, error)](#PromptSet.NewHash)
  * [func (p *PromptSet) NewPass() ([]byte, error)](#PromptSet.NewPass)


#### <a name="pkg-files">Package files</a>
[session.go](/src/toolman.org/security/tools/passwd/session.go) 



## <a name="pkg-variables">Variables</a>
``` go
var Prompts = &PromptSet{
    Get:  "Password: ",
    Old:  "Old Password: ",
    New1: "New Password: ",
    New2: "New Password (again): ",
}
```
Prompts provides a reasonable set of default prompt values.



## <a name="Compare">func</a> [Compare](/src/target/session.go?s=4753:4790#L122)
``` go
func Compare(pass, hash []byte) error
```
Compare is used to compare the provided plain-text password and bcrypt hash
value. It is equivlent to bcrypt.CompareHashAndPassword(hash, pass)




## <a name="PromptSet">type</a> [PromptSet](/src/target/session.go?s=1198:1657#L30)
``` go
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
```
A PromptSet is a set of strings used for prompting the user to enter
a password. Each field is used in a different situation.










### <a name="PromptSet.Change">func</a> (\*PromptSet) [Change](/src/target/session.go?s=4442:4500#L114)
``` go
func (p *PromptSet) Change(oldHash []byte) ([]byte, error)
```
Change is a convenience wrapper around Check and NewHash for changing an
exising passsword.  If the user's current password is provided as oldHash,
the user is prompted for their current password (using the `Old` prompt). If
and only if the entered password matches the priveded hash is the user then
prompted to enter a new password similar to NewPass.  If successful, the
bcrypt has of the newly entered password is returned -- or, if not, an
appropriate error is emitted.




### <a name="PromptSet.Check">func</a> (\*PromptSet) [Check](/src/target/session.go?s=3784:3828#L100)
``` go
func (p *PromptSet) Check(hash []byte) error
```
Check prompts the user for a password similar to GetPass then compares the
entered password to the provided bcrypt hash value.  If they agree, nill is
returned -- otherwise an approprate error is returned.




### <a name="PromptSet.GetHash">func</a> (\*PromptSet) [GetHash](/src/target/session.go?s=2350:2395#L67)
``` go
func (p *PromptSet) GetHash() ([]byte, error)
```
GetHash is a wrapper around GetPass that returns a bcrypt hash of the
entered password.




### <a name="PromptSet.GetPass">func</a> (\*PromptSet) [GetPass](/src/target/session.go?s=2120:2165#L59)
``` go
func (p *PromptSet) GetPass() ([]byte, error)
```
GetPass prompts the user to enter a password (using the `Get` prompt), reads
the password string from stdin without echoing back to the terminal, and
returns the plain text password as a byte array -- or, returns nil and en
error if a problem occurred.




### <a name="PromptSet.NewHash">func</a> (\*PromptSet) [NewHash](/src/target/session.go?s=3424:3469#L91)
``` go
func (p *PromptSet) NewHash() ([]byte, error)
```
NewHash is a wrapper around NewPass that returns a bcrypt hash of the
entered password.




### <a name="PromptSet.NewPass">func</a> (\*PromptSet) [NewPass](/src/target/session.go?s=3185:3230#L83)
``` go
func (p *PromptSet) NewPass() ([]byte, error)
```
NewPass prompts the user to enter a new password two separate times -- first
using the `New1` prompt then with the `New2` prompt, Each time it reads the
password string from stdin without echoing back to the terminal. If the two
password strings agree, the plain text password is returned as a byte array.
If they do not, the user is informed as such and the cycle is restarted --
unless the user presses `Enter` for both prompts (which aborts the process).
Up to 4 attempts are made to acquire a new password.  If the user aborts the
process, exhausts all attempts or some other error occurs, a nil array and
an error is returned instead.
error if a problem occurred.








- - -
Generated by [godoc2md](http://godoc.org/github.com/davecheney/godoc2md)
