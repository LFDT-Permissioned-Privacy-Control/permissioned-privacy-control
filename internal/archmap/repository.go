package archmap

// Repository-specific settings for the perimeter rules. The rules themselves
// are generic; these name the shipped binaries and the build.

// ModulePrefix is the import path prefix of this repository's Go module.
const ModulePrefix = "privacy-proxy/"

// Paths of the module map and the generated report, relative to the root.
const (
	ManifestPath = "docs/architecture/modules.toml"
	ReportPath   = "docs/architecture/perimeter-report.md"
)

// ShippedMains are the server and the operator binaries built from this
// repository (the server image builds cmd/server).
var ShippedMains = []string{"./cmd/server", "./cmd/privacy-cli", "./cmd/migrate"}

// ProductionBuildFlags are the flags release images are built with
// (Dockerfile.backend), so the rules check the code that ships.
var ProductionBuildFlags = []string{"-tags=production"}

// RepositoryCheckOptions are the rule settings for this repository.
var RepositoryCheckOptions = CheckOptions{
	InitCallAllowlist: []string{
		// fmt.Errorf is not here: it runs its operands' String and Error
		// methods.
		"errors.New",
		"regexp.MustCompile",
		"github.com/redis/go-redis/v9.NewScript",
	},
}

// CheckRepository type-checks the shipped packages under root with the
// production build flags and applies the perimeter rules.
func CheckRepository(m *Manifest, root string) ([]Violation, *Analysis, error) {
	pkgs, err := ShippedPackages(root, ModulePrefix, ProductionBuildFlags, ShippedMains...)
	if err != nil {
		return nil, nil, err
	}
	a, err := Analyze(root, AnalyzeOptions{Patterns: pkgs, BuildFlags: ProductionBuildFlags})
	if err != nil {
		return nil, nil, err
	}
	return Check(m, a, RepositoryCheckOptions), a, nil
}
