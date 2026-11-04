package license

import (
	"slices"
	"strings"
)

// Status est le verdict d'une politique sur une licence ou un composant.
type Status string

// Verdicts, du meilleur au pire.
const (
	StatusAllowed Status = "allowed"
	StatusReview  Status = "review"
	StatusDenied  Status = "denied"
)

// Statuses renvoie les verdicts, du meilleur au pire.
func Statuses() []Status { return []Status{StatusAllowed, StatusReview, StatusDenied} }

func rank(s Status) int { return slices.Index(Statuses(), s) }

// Reason dit d'où vient le verdict d'une licence.
type Reason string

// Raisons d'un verdict.
const (
	ReasonListed  Reason = "listed"  // licence citée par la politique
	ReasonDefault Reason = "default" // licence SPDX connue, non citée : règle par défaut
	ReasonUnknown Reason = "unknown" // identifiant inconnu de la liste SPDX, LicenseRef- ou nom libre
	ReasonMissing Reason = "missing" // composant sans licence, avec RequireLicense
)

// Policy est la politique de licences d'une organisation. Par défaut (décision de
// l'utilisateur, T20), toute licence SPDX connue est autorisée. Une licence inconnue (nom
// libre, identifiant absent de la liste SPDX, LicenseRef-) n'est jamais autorisée : elle
// est à revoir, sauf si la politique la cite. Les identifiants se comparent sans tenir
// compte de la casse.
type Policy struct {
	// Default s'applique aux licences SPDX connues que la politique ne cite pas.
	Default Status
	Allowed []string
	Review  []string
	Denied  []string
	// RequireLicense : un composant sans licence est à revoir (sinon, il ne donne pas de
	// constat).
	RequireLicense bool
}

// DefaultPolicy est la politique d'une organisation qui n'en a pas posé.
func DefaultPolicy() Policy { return Policy{Default: StatusAllowed} }

// Known dit si un identifiant figure dans la liste des licences SPDX.
type Known func(id string) bool

// LicenseVerdict est le verdict sur une licence d'une expression.
type LicenseVerdict struct {
	ID     string
	Status Status
	Reason Reason
}

// Verdict est le verdict sur les licences d'un composant : le statut, et les licences qui
// le déterminent (celles de l'alternative retenue, pour une disjonction).
type Verdict struct {
	Status   Status
	Licenses []LicenseVerdict
	// Missing : composant sans licence.
	Missing bool
}

// IDs renvoie les identifiants des licences du verdict.
func (v Verdict) IDs() []string {
	out := make([]string, 0, len(v.Licenses))
	for _, l := range v.Licenses {
		out = append(out, l.ID)
	}
	return out
}

func (p Policy) lookup(id string) (Status, bool) {
	for _, l := range []struct {
		ids []string
		s   Status
	}{{p.Denied, StatusDenied}, {p.Review, StatusReview}, {p.Allowed, StatusAllowed}} {
		if slices.ContainsFunc(l.ids, func(x string) bool { return strings.EqualFold(x, id) }) {
			return l.s, true
		}
	}
	return "", false
}

// leaf évalue une licence : citée (sous sa forme écrite, puis sans « + »), connue (règle
// par défaut), sinon inconnue, donc à revoir.
func (p Policy) leaf(n *Node, known Known) LicenseVerdict {
	id := n.ID
	if n.Plus {
		id += "+"
	}
	if s, ok := p.lookup(id); ok {
		return LicenseVerdict{ID: id, Status: s, Reason: ReasonListed}
	}
	if n.Plus {
		if s, ok := p.lookup(n.ID); ok {
			return LicenseVerdict{ID: id, Status: s, Reason: ReasonListed}
		}
	}
	if !n.Ref && known != nil && known(n.ID) {
		return LicenseVerdict{ID: id, Status: p.Default, Reason: ReasonDefault}
	}
	return LicenseVerdict{ID: id, Status: StatusReview, Reason: ReasonUnknown}
}

// eval évalue un nœud : une conjonction vaut sa pire licence, une disjonction sa
// meilleure alternative (« MIT OR GPL-3.0-only » est conforme si l'une des deux l'est).
func (p Policy) eval(n *Node, known Known) Verdict {
	if n.ID != "" {
		l := p.leaf(n, known)
		return Verdict{Status: l.Status, Licenses: []LicenseVerdict{l}}
	}
	var out Verdict
	for i, c := range n.Children {
		v := p.eval(c, known)
		switch {
		case i == 0:
			out = v
		case n.Op == "AND":
			if rank(v.Status) > rank(out.Status) {
				out.Status = v.Status
			}
			out.Licenses = append(out.Licenses, v.Licenses...)
		case rank(v.Status) < rank(out.Status):
			out = v
		}
	}
	return out
}

// Evaluate évalue les licences déclarées d'un composant (chacune une expression SPDX ou un
// nom libre) : toutes s'appliquent ensemble, comme une conjonction.
func (p Policy) Evaluate(licenses []string, known Known) Verdict {
	if len(licenses) == 0 {
		if p.RequireLicense {
			return Verdict{Status: StatusReview, Missing: true}
		}
		return Verdict{Status: StatusAllowed, Missing: true}
	}
	var out Verdict
	for i, l := range licenses {
		var v Verdict
		if n, err := Parse(l); err == nil {
			v = p.eval(n, known)
		} else {
			v = Verdict{Status: StatusReview, Licenses: []LicenseVerdict{{ID: strings.TrimSpace(l), Status: StatusReview, Reason: ReasonUnknown}}}
		}
		if i == 0 || rank(v.Status) > rank(out.Status) {
			out.Status = v.Status
		}
		out.Licenses = append(out.Licenses, v.Licenses...)
	}
	return out
}

// Normalize met une politique saisie en forme : identifiants sans espace ni doublon, triés,
// chacun dans une seule liste (la plus stricte l'emporte).
func (p Policy) Normalize() Policy {
	seen := map[string]bool{}
	clean := func(ids []string) []string {
		var out []string
		for _, id := range ids {
			id = strings.TrimSpace(id)
			k := strings.ToLower(id)
			if id == "" || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, id)
		}
		slices.SortFunc(out, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
		return out
	}
	p.Denied = clean(p.Denied)
	p.Review = clean(p.Review)
	p.Allowed = clean(p.Allowed)
	if rank(p.Default) < 0 {
		p.Default = StatusAllowed
	}
	return p
}
