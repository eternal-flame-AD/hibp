package hibp

// Breach is info regarding a breach
// https://haveibeenpwned.com/API/v2#BreachModel
type Breach struct {
	Name         string
	Title        string
	Domain       string
	BreachData   string
	AddedDate    string
	ModifiedDate string
	PwnCount     int
	Description  string
	LogoPath     string
	DataClasses  []string
	IsVerified   bool
	IsFabricated bool
	IsSensitive  bool
	IsRetired    bool
	IsSpamList   bool
}

// Paste is info regarding a paste
// https://haveibeenpwned.com/API/v2#PasteModel
type Paste struct {
	Source     string
	ID         string `json:"Id"`
	Title      string
	Date       string
	EmailCount int
}
