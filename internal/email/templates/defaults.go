package templates

// Default subject and body templates for each template type.
var DefaultSubjects = map[TemplateType]string{
	TemplateMagicLink:         "Your sign-in link for {{.AppName}}",
	TemplatePasswordReset:     "Reset your password for {{.AppName}}",
	TemplateInvitation:        "You've been invited to {{.TenantName}}",
	TemplateWelcome:           "Welcome to {{.AppName}}",
	TemplateEmailVerification: "Verify your email for {{.AppName}}",
}

var DefaultBodies = map[TemplateType]string{
	TemplateMagicLink: `Hi {{.RecipientEmail}},

Click the link below to sign in to {{.AppName}}:

{{.Link}}

This link expires in {{.ExpiresIn}}.

If you didn't request this, you can safely ignore this email.`,

	TemplatePasswordReset: `Hi {{.RecipientEmail}},

We received a request to reset your password for {{.AppName}}.

Click the link below to set a new password:

{{.Link}}

This link expires in {{.ExpiresIn}}.

If you didn't request a password reset, you can safely ignore this email.`,

	TemplateInvitation: `Hi {{.RecipientEmail}},

{{.InviterName}} has invited you to join {{.TenantName}} on {{.AppName}}.

Click the link below to accept the invitation:

{{.Link}}

This link expires in {{.ExpiresIn}}.`,

	TemplateWelcome: `Welcome to {{.AppName}}, {{.RecipientEmail}}!

Your account has been created successfully. You can now sign in at:

{{.Link}}`,

	TemplateEmailVerification: `Hi {{.RecipientEmail}},

Please verify your email address for {{.AppName}} by clicking the link below:

{{.Link}}

This link expires in {{.ExpiresIn}}.`,
}
