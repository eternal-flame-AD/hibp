package hibp

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func sha1str(s string) string {
	p := sha1.New()
	p.Write([]byte(s))
	return fmt.Sprintf("%X", p.Sum(nil))
}

// Password finds how many times a password has been pwned. The password is hashed with SHA1 and only the first 5 hash characters(20 bits) is sent to the server
func Password(password string) (int, error) {
	hash := sha1str(password)
	hashHead, hashTail := hash[:5], hash[5:]
	req := buildRequest("range", hashHead, nil, true)
	res, err := makeRequest(req)
	if err != nil {
		return 0, err
	}
	resStr := string(res)
	items := strings.Split(resStr, "\r\n")
	for _, v := range items {
		if strings.HasPrefix(v, hashTail) {
			numStr := strings.Split(v, ":")[1]
			num, _ := strconv.Atoi(numStr)
			return num, nil
		}
	}
	return 0, nil
}

// PasteAccount searches for occurrences of a certain email in pastebins
func PasteAccount(email string) ([]Paste, error) {
	req := buildRequest("pasteaccount", email, nil, false)
	res, err := makeRequest(req)
	if err != nil {
		if err == errNotFound {
			return nil, nil
		}
		return nil, err
	}
	p := make([]Paste, 0)
	if err := json.Unmarshal(res, &p); err != nil {
		return nil, err
	}
	return p, nil
}

// DataClasses returns all data classes present in the system
func DataClasses() ([]string, error) {
	req := buildRequest("dataclasses", "", nil, false)
	res, err := makeRequest(req)
	if err != nil {
		if err == errNotFound {
			return nil, nil
		}
		return nil, err
	}
	p := make([]string, 0)
	if err := json.Unmarshal(res, &p); err != nil {
		return nil, err
	}
	return p, nil
}

// BreachByName fetches the information regarding a breach
func BreachByName(name string) (*Breach, error) {
	req := buildRequest("breach", name, nil, false)
	res, err := makeRequest(req)
	if err != nil {
		if err == errNotFound {
			return nil, nil
		}
		return nil, err
	}
	p := new(Breach)
	if err := json.Unmarshal(res, &p); err != nil {
		return nil, err
	}
	return p, nil
}

// Breaches fetches all breaches in the system
func Breaches() ([]Breach, error) {
	return BreachesByDomain("")
}

// BreachesByDomain fetches breaches regarding a particular domain in the system
func BreachesByDomain(domain string) ([]Breach, error) {
	var param map[string]string
	if domain != "" {
		param = map[string]string{
			"domain": domain,
		}
	}
	req := buildRequest("breaches", "", param, false)
	res, err := makeRequest(req)
	if err != nil {
		if err == errNotFound {
			return nil, nil
		}
		return nil, err
	}
	p := make([]Breach, 0)
	if err := json.Unmarshal(res, &p); err != nil {
		return nil, err
	}
	return p, nil
}

// SearchOptions defines detailed options in a BreachByAccount search
type SearchOptions struct {
	// NameOnly truncates all other fields but the Name field.
	NameOnly bool
	// IncludeUnverified includes unverified breaches in the response
	IncludeUnverified bool
	// Domain filters the response by domain
	Domain string
}

func (c *SearchOptions) marshal() map[string]string {
	if c == nil {
		return nil
	}
	res := make(map[string]string)
	if c.NameOnly {
		res["truncateResponse"] = "true"
	}
	if c.IncludeUnverified {
		res["includeUnverified"] = "true"
	}
	if c.Domain != "" {
		res["domain"] = c.Domain
	}
	return res
}

// BreachByAccount searches a particular account for breaches
func BreachByAccount(account string, opt *SearchOptions) ([]Breach, error) {
	req := buildRequest("breachedaccount", account, opt.marshal(), false)
	res, err := makeRequest(req)
	if err != nil {
		if err == errNotFound {
			return nil, nil
		}
		return nil, err
	}
	p := make([]Breach, 0)
	if err := json.Unmarshal(res, &p); err != nil {
		return nil, err
	}
	return p, nil
}
