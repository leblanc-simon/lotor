package license

import (
	"errors"
	"slices"
	"strings"
	"unicode"
)

// Expression SPDX (annexe D de la spécification SPDX 2.3) :
//
//	compound = simple | compound "WITH" exception | compound "AND" compound
//	         | compound "OR" compound | "(" compound ")"
//	simple   = identifiant ["+"] | "LicenseRef-…" | "DocumentRef-…:LicenseRef-…"
//
// AND lie plus fort que OR ; WITH plus fort que AND. Les opérateurs se lisent sans tenir
// compte de la casse (la spécification les veut en majuscules, des SBOM réels les écrivent
// en minuscules). Une valeur qui n'est pas une expression lisible (un nom libre :
// « Apache License 2.0 », « BSD-like ») est une licence inconnue.

// Node est un nœud d'expression : une licence (ID non vide) ou une conjonction (Op « AND »)
// ou disjonction (« OR ») de ses enfants.
type Node struct {
	Op       string
	Children []*Node
	// ID est l'identifiant de licence tel qu'écrit ; Plus, la forme « ou ultérieure » ;
	// Exception, l'exception « WITH » ; Ref, une référence LicenseRef- (licence propre au
	// document, jamais connue de la liste SPDX).
	ID        string
	Plus      bool
	Exception string
	Ref       bool
}

// ErrSyntax : la valeur n'est pas une expression SPDX lisible.
var ErrSyntax = errors.New("license: expression SPDX illisible")

// maxTokens borne une expression (une valeur venue d'un SBOM).
const maxTokens = 128

// Parse lit une expression SPDX.
func Parse(s string) (*Node, error) {
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, ErrSyntax
	}
	return n, nil
}

func tokenize(s string) ([]string, error) {
	var toks []string
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '(' || r == ')':
			flush()
			toks = append(toks, string(r))
		case unicode.IsSpace(r):
			flush()
		case r < 0x80 && (r == '-' || r == '.' || r == '+' || r == ':' || unicode.IsLetter(r) || unicode.IsDigit(r)):
			cur.WriteRune(r)
		default:
			return nil, ErrSyntax
		}
		if len(toks) > maxTokens {
			return nil, ErrSyntax
		}
	}
	flush()
	if len(toks) == 0 || len(toks) > maxTokens {
		return nil, ErrSyntax
	}
	return toks, nil
}

type parser struct {
	toks []string
	pos  int
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *parser) keyword(k string) bool {
	if strings.EqualFold(p.peek(), k) {
		p.pos++
		return true
	}
	return false
}

func (p *parser) or() (*Node, error) {
	first, err := p.and()
	if err != nil {
		return nil, err
	}
	n := &Node{Op: "OR", Children: []*Node{first}}
	for p.keyword("OR") {
		next, err := p.and()
		if err != nil {
			return nil, err
		}
		n.Children = append(n.Children, next)
	}
	if len(n.Children) == 1 {
		return first, nil
	}
	return n, nil
}

func (p *parser) and() (*Node, error) {
	first, err := p.with()
	if err != nil {
		return nil, err
	}
	n := &Node{Op: "AND", Children: []*Node{first}}
	for p.keyword("AND") {
		next, err := p.with()
		if err != nil {
			return nil, err
		}
		n.Children = append(n.Children, next)
	}
	if len(n.Children) == 1 {
		return first, nil
	}
	return n, nil
}

func (p *parser) with() (*Node, error) {
	n, err := p.atom()
	if err != nil {
		return nil, err
	}
	if p.keyword("WITH") {
		exc := p.peek()
		if n.ID == "" || exc == "" || exc == "(" || exc == ")" || isOperator(exc) || !validID(exc) {
			return nil, ErrSyntax
		}
		p.pos++
		n.Exception = exc
	}
	return n, nil
}

func (p *parser) atom() (*Node, error) {
	t := p.peek()
	switch {
	case t == "(":
		p.pos++
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, ErrSyntax
		}
		p.pos++
		return n, nil
	case t == "" || t == ")" || isOperator(t):
		return nil, ErrSyntax
	}
	p.pos++
	n := &Node{ID: t}
	if strings.HasSuffix(t, "+") {
		n.ID, n.Plus = strings.TrimSuffix(t, "+"), true
	}
	ref := strings.HasPrefix(strings.ToLower(n.ID), "licenseref-") || strings.HasPrefix(strings.ToLower(n.ID), "documentref-")
	if !validID(n.ID) || (ref && n.Plus) {
		return nil, ErrSyntax
	}
	n.Ref = ref
	return n, nil
}

func isOperator(t string) bool {
	return strings.EqualFold(t, "AND") || strings.EqualFold(t, "OR") || strings.EqualFold(t, "WITH")
}

// validID : lettres, chiffres, « - », « . », et « : » seulement entre DocumentRef et
// LicenseRef.
func validID(id string) bool {
	if id == "" || strings.Contains(id, "+") {
		return false
	}
	if strings.Contains(id, ":") {
		doc, ref, ok := strings.Cut(id, ":")
		return ok && strings.HasPrefix(strings.ToLower(doc), "documentref-") && strings.HasPrefix(strings.ToLower(ref), "licenseref-") &&
			!strings.Contains(ref, ":")
	}
	return true
}

// IDs renvoie les identifiants de licence d'une expression (exceptions exclues), dans
// l'ordre d'écriture, sans doublon.
func (n *Node) IDs() []string {
	var out []string
	var walk func(*Node)
	walk = func(n *Node) {
		if n.ID != "" {
			if !slices.Contains(out, n.ID) {
				out = append(out, n.ID)
			}
			return
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(n)
	return out
}

// String écrit l'expression sous sa forme canonique (opérateurs en majuscules,
// parenthèses seulement où il en faut).
func (n *Node) String() string {
	if n.ID != "" {
		s := n.ID
		if n.Plus {
			s += "+"
		}
		if n.Exception != "" {
			s += " WITH " + n.Exception
		}
		return s
	}
	parts := make([]string, len(n.Children))
	for i, c := range n.Children {
		parts[i] = c.String()
		if c.ID == "" && n.Op == "AND" && c.Op == "OR" {
			parts[i] = "(" + parts[i] + ")"
		}
	}
	return strings.Join(parts, " "+n.Op+" ")
}
