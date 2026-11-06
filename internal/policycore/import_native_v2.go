package policycore

// LegacyAdmissionProfile records an explicitly verified legacy admission
// setting. Its zero value cannot select conversion semantics.
type LegacyAdmissionProfile struct {
	initialized bool
	scoped      bool
}

func NewLegacyAdmissionProfile(verifiedIntraOrgGrantTracing bool) LegacyAdmissionProfile {
	return LegacyAdmissionProfile{initialized: true, scoped: verifiedIntraOrgGrantTracing}
}

// LegacyNativeV2Report names the remaining operational qualification work; a
// successful conversion is source translation, not runtime readiness.
type LegacyNativeV2Report struct {
	Limitations []string
}

// ImportLegacyNativeV2 preserves explicit legacy grants and restricts generated
// shared defaults to nested frames. It never reads current environment or SQL.
// Unsupported source returns no policy, as with ImportLegacy.
func ImportLegacyNativeV2(snapshot LegacySnapshot, cat Catalog, profile LegacyAdmissionProfile) (*Policy, LegacyNativeV2Report, error) {
	report := LegacyNativeV2Report{Limitations: []string{
		"Deployment, history and privacy behavior require operational runtime qualification; this translation does not establish full migration parity.",
	}}
	if !profile.initialized {
		return nil, report, &LegacyImportError{Issues: []LegacyImportIssue{{Reason: "explicit verified legacy admission profile is required"}}}
	}
	if !profile.scoped {
		report.Limitations = append(report.Limitations, "Unscoped indirect upgrades require an explicit target-qualified rule and that group's upgrade claim; the nested org fallback grants no upgrade authority.")
	}
	p, err := ImportLegacy(snapshot, cat)
	if err != nil {
		return nil, report, err
	}
	p = p.clone()
	p.APIVersion = NativeV2APIVersion
	admins := make(map[string]bool, len(snapshot.Groups))
	for _, group := range snapshot.Groups {
		admins[group.ID] = group.OrgAdmin
	}
	for i := range p.Bindings {
		binding := &p.Bindings[i]
		for j := range binding.Allow {
			if binding.Allow[j].TargetClass == "shared" {
				minimum := 1
				binding.Allow[j].MinDepth = &minimum
			}
		}
		if !profile.scoped && !admins[binding.Group] {
			minimum := 1
			binding.Allow = append(binding.Allow, FrameRule{
				TargetClass: "org", Selector: "*", MinDepth: &minimum,
				CallTypes: []CallType{CallTypeCall, CallTypeStaticCall, CallTypeDelegateCall, CallTypeCallCode},
			})
		}
	}
	if _, err := ValidateNativeV2(p, cat); err != nil {
		return nil, report, &LegacyImportError{Issues: []LegacyImportIssue{{Reason: "native-v2 conversion failed validation: " + err.Error()}}}
	}
	return p, report, nil
}
