package hibp

import (
	"fmt"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func ExamplePassword() {
	n, err := Password("12345678")
	if err != nil {
		panic(err)
	}
	fmt.Printf("This password has been pwned %d times.\n", n)
	// Output: This password has been pwned 2840404 times.
}

func ExampleBreachByAccount() {
	BreachByAccount("test@example.com", nil)
}
func ExampleBreachByAccount_truncateBody() {
	BreachByAccount("test@example.com", &SearchOptions{
		NameOnly: true,
	})
}

func shouldBeAllOfDomain(actual interface{}, expected ...interface{}) string {
	breach, ok := actual.([]Breach)
	if !ok {
		return "value is not a slice of breach"
	}
	for _, b := range breach {
		pass := false
		for _, d := range expected {
			if strings.HasSuffix(b.Domain, d.(string)) {
				pass = true
				break
			}
		}
		if !pass {
			return fmt.Sprintf("domain %s is not expected", b.Domain)
		}
	}
	return ""
}

func shouldNotBeAllVerified(actual interface{}, expected ...interface{}) string {
	breach, ok := actual.([]Breach)
	if !ok {
		return "value is not a slice of breach"
	}
	for _, b := range breach {
		if !b.IsVerified {
			return ""
		}
	}
	return "breach is all verified"
}

func shouldBeAllVerified(actual interface{}, expected ...interface{}) string {
	breach, ok := actual.([]Breach)
	if !ok {
		return "value is not a slice of breach"
	}
	for _, b := range breach {
		if !b.IsVerified {
			return "breach is not all verified"
		}
	}
	return ""
}

func TestSha1(t *testing.T) {
	Convey("hash function", t, func() {
		Convey("sha1", func() {
			So(sha1str("12345678"), ShouldEqual, "7C222FB2927D828AF22F592134E8932480637C0D")
		})
	})
}

func TestAPI(t *testing.T) {
	Convey("api test", t, func() {
		ticker := time.NewTicker(1800 * time.Millisecond)
		defer ticker.Stop()
		tick := func() {
			<-ticker.C
		}
		Convey("pwd range", func() {
			n, err := Password("12345678")
			So(err, ShouldBeNil)
			So(n, ShouldBeGreaterThan, 10)
			tick()
			n, err = Password("3]p[]f[]dfnjvnx")
			So(err, ShouldBeNil)
			So(n, ShouldEqual, 0)
			tick()
		})
		Convey("paste account", func() {
			n, err := PasteAccount("test@example.com")
			So(err, ShouldBeNil)
			So(len(n), ShouldBeGreaterThan, 0)
			tick()
			n, err = PasteAccount("wofncuvnel@wnc8ekxi.com")
			So(err, ShouldBeNil)
			So(len(n), ShouldEqual, 0)
			tick()
		})
		Convey("data classes", func() {
			c, err := DataClasses()
			So(err, ShouldBeNil)
			So(len(c), ShouldBeGreaterThan, 10)
			tick()
		})
		Convey("breaches", func() {
			Convey("breach by name", func() {
				b, err := BreachByName("Adobe")
				So(err, ShouldBeNil)
				So(b, ShouldNotBeNil)
				tick()
				b, err = BreachByName("this breach just does not exist")
				So(err, ShouldBeNil)
				So(b, ShouldBeNil)
				tick()
			})
			Convey("breaches", func() {
				b, err := Breaches()
				So(err, ShouldBeNil)
				So(len(b), ShouldBeGreaterThan, 10)
				tick()
			})
			Convey("breach by domain", func() {
				b, err := BreachesByDomain("adobe.com")
				So(err, ShouldBeNil)
				So(len(b), ShouldBeGreaterThan, 0)
				tick()
			})
			Convey("breach by account", func() {
				Convey("no opts", func() {
					b, err := BreachByAccount("test@example.com", nil)
					So(err, ShouldBeNil)
					So(len(b), ShouldBeGreaterThan, 0)
					So(b, shouldBeAllVerified)
					tick()
				})
				Convey("include unverified", func() {
					b, err := BreachByAccount("test@example.com", &SearchOptions{
						IncludeUnverified: true,
					})
					So(err, ShouldBeNil)
					So(len(b), ShouldBeGreaterThan, 0)
					So(b, shouldNotBeAllVerified)
					tick()
				})
				Convey("filter domain", func() {
					b, err := BreachByAccount("test@example.com", &SearchOptions{
						Domain: "adobe.com",
					})
					So(err, ShouldBeNil)
					So(len(b), ShouldBeGreaterThan, 0)
					So(b, shouldBeAllVerified)
					tick()
				})
				Convey("truncate body", func() {
					b, err := BreachByAccount("test@example.com", &SearchOptions{
						NameOnly: true,
					})
					So(err, ShouldBeNil)
					So(len(b), ShouldBeGreaterThan, 0)
					So(b, shouldNotBeAllVerified)
					tick()
				})
				Convey("not breached", func() {
					b, err := BreachByAccount("justanotbreachedemail@rejrjinci.com", nil)
					So(err, ShouldBeNil)
					So(len(b), ShouldEqual, 0)
					tick()
				})
			})
		})
	})
}
