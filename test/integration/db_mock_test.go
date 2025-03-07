package integration

import (
	v5 "github.com/anchore/grype/grype/db/v5"
)

// integrity check
var _ v5.VulnerabilityStoreReader = &mockStore{}

type mockStore struct {
	normalizedPackageNames map[string]map[string]string
	backend                map[string]map[string][]v5.Vulnerability
}

func (s *mockStore) GetVulnerability(namespace, id string) ([]v5.Vulnerability, error) {
	// TODO implement me
	panic("implement me")
}

func (s *mockStore) GetVulnerabilityNamespaces() ([]string, error) {
	var results []string
	for k := range s.backend {
		results = append(results, k)
	}

	return results, nil
}

func (s *mockStore) GetVulnerabilityMatchExclusion(id string) ([]v5.VulnerabilityMatchExclusion, error) {
	return nil, nil
}

func newMockDbStore() *mockStore {
	return &mockStore{
		normalizedPackageNames: map[string]map[string]string{
			"github:language:python": {
				"pygments":   "pygments",
				"my-package": "my-package",
			},
			"github:language:dotnet": {
				"AWSSDK.Core": "awssdk.core",
			},
		},
		backend: map[string]map[string][]v5.Vulnerability{
			"nvd:cpe": {
				"jdk": []v5.Vulnerability{
					{
						ID:                "CVE-jdk",
						PackageName:       "jdk",
						VersionConstraint: "< 1.8.0_401",
						VersionFormat:     "jvm",
						CPEs:              []string{"cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*"},
					},
				},
				"libvncserver": []v5.Vulnerability{
					{
						ID:                "CVE-alpine-libvncserver",
						VersionConstraint: "< 0.9.10",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
					},
				},
				"my-package": []v5.Vulnerability{
					{
						ID:                "CVE-bogus-my-package-1",
						VersionConstraint: "< 2.0",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:bogus:my-package:*:*:*:*:*:*:something:*"},
					},
					{
						ID:                "CVE-bogus-my-package-2-never-match",
						VersionConstraint: "< 2.0",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:something-wrong:my-package:*:*:*:*:*:*:something:*"},
					},
				},
			},
			"alpine:distro:alpine:3.12": {
				"libvncserver": []v5.Vulnerability{
					{
						ID:                "CVE-alpine-libvncserver",
						VersionConstraint: "< 0.9.10",
						VersionFormat:     "unknown",
					},
				},
				"ko": []v5.Vulnerability{
					{
						ID:                "CVE-azure-autorest-vuln-false-positive",
						VersionConstraint: "< 0",
						VersionFormat:     "apk",
					},
				},
				"npm-apk-package-with-false-positive": []v5.Vulnerability{
					{
						ID:                "CVE-npm-false-positive-in-apk-subpackage",
						VersionConstraint: "< 0",
						VersionFormat:     "apk",
					},
				},
			},
			"gentoo:distro:gentoo:2.8": {
				"app-containers/skopeo": []v5.Vulnerability{
					{
						ID:                "CVE-gentoo-skopeo",
						VersionConstraint: "< 1.6.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:go": {
				"github.com/anchore/coverage": []v5.Vulnerability{
					{
						ID:                "CVE-coverage-main-module-vuln",
						VersionConstraint: "< 1.4.0",
						VersionFormat:     "unknown",
					},
				},
				"github.com/google/uuid": []v5.Vulnerability{
					{
						ID:                "CVE-uuid-vuln",
						VersionConstraint: "< 1.4.0",
						VersionFormat:     "unknown",
					},
				},
				"github.com/azure/go-autorest/autorest": []v5.Vulnerability{
					{
						ID:                "CVE-azure-autorest-vuln-false-positive",
						VersionConstraint: "< 0.11.30",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:idris": {
				"my-package": []v5.Vulnerability{
					{
						ID:                "CVE-bogus-my-package-2-idris",
						VersionConstraint: "< 2.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:javascript": {
				"npm": []v5.Vulnerability{
					{
						ID:                "CVE-javascript-validator",
						VersionConstraint: "> 5, < 7.2.1",
						VersionFormat:     "unknown",
					},
				},
				"npm-apk-subpackage-with-false-positive": []v5.Vulnerability{
					{
						ID:                "CVE-npm-false-positive-in-apk-subpackage",
						VersionConstraint: "< 2.0.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:python": {
				"pygments": []v5.Vulnerability{
					{
						ID:                "CVE-python-pygments",
						VersionConstraint: "< 2.6.2",
						VersionFormat:     "python",
					},
				},
				"my-package": []v5.Vulnerability{},
			},
			"github:language:ruby": {
				"bundler": []v5.Vulnerability{
					{
						ID:                "CVE-ruby-bundler",
						VersionConstraint: "> 2.0.0, <= 2.1.4",
						VersionFormat:     "gemfile",
					},
				},
			},
			"github:language:java": {
				"org.anchore:example-java-app-maven": []v5.Vulnerability{
					{
						ID:                "CVE-java-example-java-app",
						VersionConstraint: ">= 0.0.1, < 1.2.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:dotnet": {
				"awssdk.core": []v5.Vulnerability{
					{
						ID:                "CVE-dotnet-sample",
						VersionConstraint: ">= 3.7.0.0, < 3.7.12.0",
						VersionFormat:     "dotnet",
					},
				},
			},
			"github:language:haskell": {
				"shellcheck": []v5.Vulnerability{
					{
						ID:                "CVE-haskell-sample",
						VersionConstraint: "< 0.9.0",
						VersionFormat:     "haskell",
					},
				},
			},
			"github:language:rust": {
				"hello-auditable": []v5.Vulnerability{
					{
						ID:                "CVE-rust-sample-1",
						VersionConstraint: "< 0.2.0",
						VersionFormat:     "unknown",
					},
				},
				"auditable": []v5.Vulnerability{
					{
						ID:                "CVE-rust-sample-2",
						VersionConstraint: "< 0.2.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"debian:distro:debian:8": {
				"apt-dev": []v5.Vulnerability{
					{
						ID:                "CVE-dpkg-apt",
						VersionConstraint: "<= 1.8.2",
						VersionFormat:     "dpkg",
					},
				},
			},
			"redhat:distro:redhat:8": {
				"dive": []v5.Vulnerability{
					{
						ID:                "CVE-rpmdb-dive",
						VersionConstraint: "<= 1.0.42",
						VersionFormat:     "rpm",
					},
				},
			},
			"msrc:distro:windows:10816": {
				"10816": []v5.Vulnerability{
					{
						ID:                "CVE-2016-3333",
						VersionConstraint: "3200970 || 878787 || base",
						VersionFormat:     "kb",
					},
				},
			},
			"sles:distro:sles:12.5": {
				"dive": []v5.Vulnerability{
					{
						ID:                "CVE-rpmdb-dive",
						VersionConstraint: "<= 1.0.42",
						VersionFormat:     "rpm",
					},
				},
			},
		},
	}
}

func (s *mockStore) SearchForVulnerabilities(namespace, name string) ([]v5.Vulnerability, error) {
	namespaceMap := s.backend[namespace]
	if namespaceMap == nil {
		return nil, nil
	}
	entries, ok := namespaceMap[name]
	if !ok {
		return entries, nil
	}
	for i := range entries {
		entries[i].Namespace = namespace
	}
	return entries, nil
}

func (s *mockStore) GetAllVulnerabilities() (*[]v5.Vulnerability, error) {
	return nil, nil
}

func (s *mockStore) GetVulnerabilityMetadata(id string, namespace string) (*v5.VulnerabilityMetadata, error) {
	return nil, nil
}

func (s *mockStore) GetAllVulnerabilityMetadata() (*[]v5.VulnerabilityMetadata, error) {
	return nil, nil
}
