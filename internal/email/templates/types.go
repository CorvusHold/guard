package templates

// TemplateType identifies the kind of email template.
type TemplateType string

const (
	TemplateMagicLink         TemplateType = "magic_link"
	TemplatePasswordReset     TemplateType = "password_reset"
	TemplateInvitation        TemplateType = "invitation"
	TemplateWelcome           TemplateType = "welcome"
	TemplateEmailVerification TemplateType = "email_verification"
)

// TemplateData holds the variables available to email templates.
type TemplateData struct {
	AppName    string
	RecipientEmail string
	Link       string
	TenantName string
	InviterName string
	ExpiresIn  string
	Extra      map[string]string
}
