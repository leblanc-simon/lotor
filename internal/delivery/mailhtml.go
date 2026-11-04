package delivery

// Version HTML des courriels (ADR 0056). Le gabarit templates/notification.html.tmpl a été
// validé dans Thunderbird 153, mode sombre compris ; Gmail, Outlook et Apple Mail n'ont
// pas été testés. Contraintes à conserver à chaque modification :
//
//  1. Le mode sombre de Thunderbird réécrit les styles en ligne : il retire un fond dont la
//     luminance dépasse 200, ou dont le contraste avec le texte est inférieur à 3,5
//     (L = 0,2125 R + 0,7154 G + 0,0721 B, canaux 0 à 255 ; contraste = (Lmax + 0,05) /
//     (Lmin + 0,05)). TestMailColorsSurviveThunderbirdDarkMode le vérifie pour chaque
//     couleur d'étiquette et le bouton.
//  2. Les couleurs tiennent en styles en ligne : une règle @media all avec !important ne
//     les protège pas dans le vrai Thunderbird. Le bloc <style> ne sert qu'au mobile et au
//     thème sombre des autres messageries.
//  3. En-tête sans fond blanc : une seule queue en PNG transparent, affichée en
//     17 × 40 px, et « lotor » en vrai texte à côté, dans la police et la couleur du
//     contenu. Aucune police embarquée.
//  4. Le logo est joint au message et appelé par cid: : multipart/alternative { text/plain,
//     multipart/related { text/html, image/png } }, Content-ID et Content-Disposition
//     inline. Ni image externe, ni SVG, ni data:.
//  5. Couleurs fond / texte des étiquettes (sevStyle) : Critique #6E1230 / #FFFFFF, Élevée
//     #A92B21 / #FFFFFF, Moyenne #E5C56B / #3D2C00, Faible #B5C9E2 / #12345C, KEV
//     #F5C518 / #161B26, bouton #0A5452 / #FFFFFF. Hors Critique, elles diffèrent
//     volontairement de web/static/css/tokens.css : les couleurs de l'interface ne tiennent
//     pas les seuils de Thunderbird (fond de « Moyenne » trop clair, bouton trop peu
//     contrasté) ou sont trop pâles une fois le fond retiré.
//  6. CSS à plat dans le gabarit : exception à la règle du CSS imbriqué, que les messageries
//     ne comprennent pas.
//  7. Aucun texte en dur hormis le nom « lotor » : tous les champs arrivent traduits
//     (notify.HTML) ; TestMailTemplateHasNoHardcodedText le vérifie.

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"html/template"
	"io"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"

	"leblanc.io/lotor/internal/notify"
)

//go:embed templates/notification.html.tmpl
var mailTemplateSource string

//go:embed templates/lotor-logo-email.png
var mailLogo []byte

// mailLogoCID est l'identifiant de contenu du logo dans le message (cid:).
const mailLogoCID = "lotor-logo@lotor"

// mailColor est le couple fond / texte d'une étiquette de courriel (contrainte 5).
type mailColor struct{ bg, fg string }

// Couleurs des étiquettes et du bouton ; voir la contrainte 5 en tête de fichier.
var (
	mailSeverityColors = map[string]mailColor{
		"critical": {"#6E1230", "#FFFFFF"},
		"high":     {"#A92B21", "#FFFFFF"},
		"medium":   {"#E5C56B", "#3D2C00"},
		"low":      {"#B5C9E2", "#12345C"},
	}
	mailKEVColor    = mailColor{"#F5C518", "#161B26"}
	mailButtonColor = mailColor{"#0A5452", "#FFFFFF"}
)

// sevStyle renvoie les couleurs en ligne de l'étiquette d'une sévérité. Une sévérité sans
// couleur (négligeable, inconnue) prend une bordure neutre, sans fond.
func sevStyle(severity string) template.CSS {
	c, ok := mailSeverityColors[severity]
	if !ok {
		return template.CSS("border:1px solid #838C9A;color:#434B5A;line-height:18px;")
	}
	return template.CSS("background-color:" + c.bg + ";color:" + c.fg + ";")
}

var mailTemplate = template.Must(template.New("notification").Funcs(template.FuncMap{"sevStyle": sevStyle}).
	Parse(mailTemplateSource))

// mailView est la vue du gabarit : le contenu traduit, le sujet et le logo.
type mailView struct {
	notify.HTML
	Subject string
	LogoCID string
}

// renderMailHTML met en forme la version HTML d'un courriel.
func renderMailHTML(subject string, h *notify.HTML) ([]byte, error) {
	var b bytes.Buffer
	if err := mailTemplate.Execute(&b, mailView{HTML: *h, Subject: subject, LogoCID: mailLogoCID}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// writeBody écrit le corps d'un courriel après ses en-têtes communs : texte seul, ou
// multipart/alternative { text/plain, multipart/related { text/html, image/png } } quand
// une version HTML est fournie (contrainte 4).
func writeBody(b *bytes.Buffer, hdr func(k, v string), m notify.Mail) error {
	if m.HTML == nil {
		hdr("Content-Type", "text/plain; charset=utf-8")
		hdr("Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n")
		return writeQP(b, m.Text)
	}
	html, err := renderMailHTML(m.Subject, m.HTML)
	if err != nil {
		return err
	}
	alt := multipart.NewWriter(b)
	hdr("Content-Type", `multipart/alternative; boundary="`+alt.Boundary()+`"`)
	b.WriteString("\r\n")
	text, err := alt.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"},
		"Content-Transfer-Encoding": {"quoted-printable"}})
	if err != nil {
		return err
	}
	if err := writeQPTo(text, m.Text); err != nil {
		return err
	}
	var rel bytes.Buffer
	related := multipart.NewWriter(&rel)
	part, err := alt.CreatePart(textproto.MIMEHeader{"Content-Type": {`multipart/related; type="text/html"; boundary="` + related.Boundary() + `"`}})
	if err != nil {
		return err
	}
	htmlPart, err := related.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/html; charset=utf-8"},
		"Content-Transfer-Encoding": {"quoted-printable"}})
	if err != nil {
		return err
	}
	if err := writeQPTo(htmlPart, string(html)); err != nil {
		return err
	}
	logo, err := related.CreatePart(textproto.MIMEHeader{"Content-Type": {"image/png"}, "Content-Transfer-Encoding": {"base64"},
		"Content-ID": {"<" + mailLogoCID + ">"}, "Content-Disposition": {`inline; filename="lotor.png"`}})
	if err != nil {
		return err
	}
	if _, err := logo.Write(base64Lines(mailLogo)); err != nil {
		return err
	}
	if err := related.Close(); err != nil {
		return err
	}
	if _, err := part.Write(rel.Bytes()); err != nil {
		return err
	}
	return alt.Close()
}

func writeQP(b *bytes.Buffer, s string) error { return writeQPTo(b, s) }

func writeQPTo(w io.Writer, s string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := qp.Write([]byte(crlf(s))); err != nil {
		return err
	}
	return qp.Close()
}

// crlf normalise les fins de ligne en CRLF.
func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

// base64Lines encode data en base64 par lignes de 76 caractères (RFC 2045).
func base64Lines(data []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(data)
	var b bytes.Buffer
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes()
}
