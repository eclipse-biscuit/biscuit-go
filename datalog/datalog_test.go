package datalog

import (
	"crypto/sha256"
	"testing"
	"time"
)

func hashVar(s string) Variable {
	h := sha256.Sum256([]byte(s))
	id := uint32(h[0]) +
		uint32(h[1])<<8 +
		uint32(h[2])<<16 +
		uint32(h[3])<<24
	return Variable(id)
}

func TestFamily(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}
	a := syms.Insert("A")
	b := syms.Insert("B")
	c := syms.Insert("C")
	d := syms.Insert("D")
	e := syms.Insert("e")
	parent := syms.Insert("parent")
	grandparent := syms.Insert("grandparent")

	w.AddFact(Fact{Predicate{parent, []ID{a, b}}})
	w.AddFact(Fact{Predicate{parent, []ID{b, c}}})
	w.AddFact(Fact{Predicate{parent, []ID{c, d}}})

	r1 := Rule{
		Head: Predicate{grandparent, []ID{hashVar("grandparent"), hashVar("grandchild")}},
		Body: []Predicate{
			{parent, []ID{hashVar("grandparent"), hashVar("parent")}},
			{parent, []ID{hashVar("parent"), hashVar("grandchild")}},
		},
	}

	t.Logf("querying r1: %s", dbg.Rule(r1))
	queryRuleResult := w.QueryRule(r1)
	t.Logf("r1 query: %s", dbg.FactSet(queryRuleResult))
	t.Logf("current facts: %s", dbg.FactSet(w.facts))

	r2 := Rule{
		Head: Predicate{grandparent, []ID{hashVar("grandparent"), hashVar("grandchild")}},
		Body: []Predicate{
			{parent, []ID{hashVar("grandparent"), hashVar("parent")}},
			{parent, []ID{hashVar("parent"), hashVar("grandchild")}},
		},
	}

	t.Logf("adding r2: %s", dbg.Rule(r2))
	w.AddRule(r2)
	if err := w.Run(); err != nil {
		t.Error(err)
	}

	w.AddFact(Fact{Predicate{parent, []ID{c, e}}})
	if err := w.Run(); err != nil {
		t.Error(err)
	}

	res := w.Query(Predicate{grandparent, []ID{hashVar("grandparent"), hashVar("grandchild")}})
	t.Logf("grandparents after inserting parent(C, E): %s", dbg.FactSet(res))
	expected := &FactSet{
		Fact{Predicate{grandparent, []ID{a, c}}},
		Fact{Predicate{grandparent, []ID{b, d}}},
		Fact{Predicate{grandparent, []ID{b, e}}},
	}
	if !res.Equal(expected) {
		t.Errorf("unexpected result:\nhave %s\n want %s", dbg.FactSet(res), dbg.FactSet(expected))
	}
}

func TestNumbers(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}

	abc := syms.Insert("abc")
	def := syms.Insert("def")
	ghi := syms.Insert("ghi")
	jkl := syms.Insert("jkl")
	mno := syms.Insert("mno")
	aaa := syms.Insert("AAA")
	bbb := syms.Insert("BBB")
	ccc := syms.Insert("CCC")
	t1 := syms.Insert("t1")
	t2 := syms.Insert("t2")
	join := syms.Insert("join")

	w.AddFact(Fact{Predicate{t1, []ID{Integer(0), abc}}})
	w.AddFact(Fact{Predicate{t1, []ID{Integer(1), def}}})
	w.AddFact(Fact{Predicate{t1, []ID{Integer(2), ghi}}})
	w.AddFact(Fact{Predicate{t1, []ID{Integer(3), jkl}}})
	w.AddFact(Fact{Predicate{t1, []ID{Integer(4), mno}}})

	w.AddFact(Fact{Predicate{t2, []ID{Integer(0), aaa, Integer(0)}}})
	w.AddFact(Fact{Predicate{t2, []ID{Integer(1), bbb, Integer(0)}}})
	w.AddFact(Fact{Predicate{t2, []ID{Integer(2), ccc, Integer(1)}}})

	res := w.QueryRule(Rule{
		Head: Predicate{join, []ID{hashVar("left"), hashVar("right")}},
		Body: []Predicate{
			{t1, []ID{hashVar("id"), hashVar("left")}},
			{t2, []ID{hashVar("t2_id"), hashVar("right"), hashVar("id")}},
		},
	})
	expected := &FactSet{
		{Predicate{join, []ID{abc, aaa}}},
		{Predicate{join, []ID{abc, bbb}}},
		{Predicate{join, []ID{def, ccc}}},
	}
	if !expected.Equal(res) {
		t.Errorf("query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}

	res = w.QueryRule(Rule{
		Head: Predicate{join, []ID{hashVar("left"), hashVar("right")}},
		Body: []Predicate{
			{t1, []ID{Variable(1234), hashVar("left")}},
			{t2, []ID{hashVar("t2_id"), hashVar("right"), Variable(1234)}},
		},
		Constraints: []Constraint{{1234, IntegerComparisonMatcher{IntegerComparisonLT, 1}}},
	})
	expected = &FactSet{
		{Predicate{join, []ID{abc, aaa}}},
		{Predicate{join, []ID{abc, bbb}}},
	}
	if !expected.Equal(res) {
		t.Errorf("constraint query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}
}

func TestString(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}

	app0 := syms.Insert("app_0")
	app1 := syms.Insert("app_1")
	app2 := syms.Insert("app_2")
	route := syms.Insert("route")
	suff := syms.Insert("route suffix")

	w.AddFact(Fact{Predicate{route, []ID{Integer(0), app0, String("example.com")}}})
	w.AddFact(Fact{Predicate{route, []ID{Integer(1), app1, String("test.com")}}})
	w.AddFact(Fact{Predicate{route, []ID{Integer(2), app2, String("test.fr")}}})
	w.AddFact(Fact{Predicate{route, []ID{Integer(3), app0, String("www.example.com")}}})
	w.AddFact(Fact{Predicate{route, []ID{Integer(4), app1, String("mx.example.com")}}})

	testSuffix := func(suffix String) *FactSet {
		return w.QueryRule(Rule{
			Head:        Predicate{suff, []ID{hashVar("app_id"), Variable(1234)}},
			Body:        []Predicate{{route, []ID{Variable(0), hashVar("app_id"), Variable(1234)}}},
			Constraints: []Constraint{{1234, StringComparisonMatcher{StringComparisonSuffix, suffix}}},
		})
	}

	res := testSuffix(".fr")
	expected := &FactSet{{Predicate{suff, []ID{app2, String("test.fr")}}}}
	if !expected.Equal(res) {
		t.Errorf(".fr suffix query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}

	res = testSuffix("example.com")
	expected = &FactSet{
		{Predicate{suff, []ID{app0, String("example.com")}}},
		{Predicate{suff, []ID{app0, String("www.example.com")}}},
		{Predicate{suff, []ID{app1, String("mx.example.com")}}},
	}
	if !expected.Equal(res) {
		t.Errorf("example.com suffix query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}
}

func TestDate(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}

	t1 := time.Unix(1, 0)
	t2 := t1.Add(10 * time.Second)
	t3 := t2.Add(30 * time.Second)

	abc := syms.Insert("abc")
	def := syms.Insert("def")
	x := syms.Insert("x")
	before := syms.Insert("before")
	after := syms.Insert("after")

	w.AddFact(Fact{Predicate{x, []ID{Date(t1.Unix()), abc}}})
	w.AddFact(Fact{Predicate{x, []ID{Date(t3.Unix()), def}}})

	res := w.QueryRule(Rule{
		Head: Predicate{before, []ID{Variable(1234), hashVar("val")}},
		Body: []Predicate{{x, []ID{Variable(1234), hashVar("val")}}},
		Constraints: []Constraint{
			{1234, DateComparisonMatcher{DateComparisonBefore, Date(t2.Unix())}},
			{1234, DateComparisonMatcher{DateComparisonAfter, 0}},
		},
	})
	expected := &FactSet{{Predicate{before, []ID{Date(t1.Unix()), abc}}}}
	if !expected.Equal(res) {
		t.Errorf("before query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}

	res = w.QueryRule(Rule{
		Head: Predicate{after, []ID{Variable(1234), hashVar("val")}},
		Body: []Predicate{{x, []ID{Variable(1234), hashVar("val")}}},
		Constraints: []Constraint{
			{1234, DateComparisonMatcher{DateComparisonAfter, Date(t2.Unix())}},
			{1234, DateComparisonMatcher{DateComparisonAfter, 0}},
		},
	})
	expected = &FactSet{{Predicate{after, []ID{Date(t3.Unix()), def}}}}
	if !expected.Equal(res) {
		t.Errorf("before query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}
}

func TestResource(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}

	authority := syms.Insert("authority")
	ambient := syms.Insert("ambient")
	resource := syms.Insert("resource")
	operation := syms.Insert("operation")
	right := syms.Insert("right")
	file1 := syms.Insert("file1")
	file2 := syms.Insert("file2")
	read := syms.Insert("read")
	write := syms.Insert("write")

	w.AddFact(Fact{Predicate{resource, []ID{ambient, file2}}})
	w.AddFact(Fact{Predicate{operation, []ID{ambient, write}}})
	w.AddFact(Fact{Predicate{right, []ID{authority, file1, read}}})
	w.AddFact(Fact{Predicate{right, []ID{authority, file2, read}}})
	w.AddFact(Fact{Predicate{right, []ID{authority, file1, write}}})

	caveat1 := syms.Insert("caveat1")
	res := w.QueryRule(Rule{
		Head: Predicate{caveat1, []ID{file1}},
		Body: []Predicate{{resource, []ID{ambient, file1}}},
	})
	if len(*res) > 0 {
		t.Errorf("unexpected facts: %s", dbg.FactSet(res))
	}

	caveat2 := syms.Insert("caveat2")
	var0 := Variable(0)
	r2 := Rule{
		Head: Predicate{caveat2, []ID{var0}},
		Body: []Predicate{
			{resource, []ID{ambient, var0}},
			{operation, []ID{ambient, read}},
			{right, []ID{authority, var0, read}},
		},
	}
	t.Logf("r2 = %s", dbg.Rule(r2))
	res = w.QueryRule(r2)
	if len(*res) > 0 {
		t.Errorf("unexpected facts: %s", dbg.FactSet(res))
	}
}
