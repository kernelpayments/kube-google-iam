package mappings

import (
	"fmt"
	"testing"

	"k8s.io/api/core/v1"
)

const (
	serviceAccountKey = "serviceAccountKey"
	namespaceKey      = "namespaceKey"
)

func TestExtractServiceAccount(t *testing.T) {
	var serviceAccountExtractionTests = []struct {
		test                  string
		annotations           map[string]string
		defaultServiceAccount string
		expected              string
		expectError           bool
	}{
		{
			test:        "No default, no annotation",
			annotations: map[string]string{},
			expectError: true,
		},
		{
			test:        "No default, has annotation",
			annotations: map[string]string{serviceAccountKey: "super-service-account@fancy-project.iam.gserviceaccount.com"},
			expected:    "super-service-account@fancy-project.iam.gserviceaccount.com",
		},
		{
			test:                  "Default present, no annotations",
			annotations:           map[string]string{},
			defaultServiceAccount: "super-service-account@fancy-project.iam.gserviceaccount.com",
			expected:              "super-service-account@fancy-project.iam.gserviceaccount.com",
		},
		{
			test:                  "Default present, has annotations",
			annotations:           map[string]string{serviceAccountKey: "something@fancy-project.iam.gserviceaccount.com"},
			defaultServiceAccount: "boring@fancy-project.iam.gserviceaccount.com",
			expected:              "something@fancy-project.iam.gserviceaccount.com",
		},
		{
			test:                  "Default present, has different annotations",
			annotations:           map[string]string{"nonMatchingAnnotation": "something"},
			defaultServiceAccount: "boring@fancy-project.iam.gserviceaccount.com",
			expected:              "boring@fancy-project.iam.gserviceaccount.com",
		},
	}
	for _, tt := range serviceAccountExtractionTests {
		t.Run(tt.test, func(t *testing.T) {
			rp := ServiceAccountMapper{}
			rp.iamServiceAccountKey = "serviceAccountKey"
			rp.defaultServiceAccount = tt.defaultServiceAccount

			pod := &v1.Pod{}
			pod.Annotations = tt.annotations

			resp, err := rp.extractServiceAccount(pod)
			if tt.expectError && err == nil {
				t.Error("Expected error however didn't recieve one")
				return
			}
			if !tt.expectError && err != nil {
				t.Errorf("Didn't expect error but recieved %s", err)
				return
			}
			if resp != tt.expected {
				t.Errorf("Response [%s] did not equal expected [%s]", resp, tt.expected)
				return
			}
		})
	}
}

func TestCheckServiceAccountForNamespace(t *testing.T) {
	var serviceAccountCheckTests = []struct {
		test                  string
		namespaceRestriction  bool
		defaultServiceAccount string
		namespace             string
		namespaceAnnotations  map[string]string
		serviceAccount        string
		expectedResult        bool
	}{
		{
			test:                 "No restrictions",
			namespaceRestriction: false,
			serviceAccount:       "boring@fancy-project.iam.gserviceaccount.com",
			namespace:            "default",
			expectedResult:       true,
		},
		{
			test:                  "Restrictions enabled, default",
			namespaceRestriction:  true,
			defaultServiceAccount: "boring@fancy-project.iam.gserviceaccount.com",
			serviceAccount:        "boring@fancy-project.iam.gserviceaccount.com",
			expectedResult:        true,
		},
		{
			test:                  "Restrictions enabled, allowed",
			namespaceRestriction:  true,
			defaultServiceAccount: "boring@fancy-project.iam.gserviceaccount.com",
			serviceAccount:        "cool@fancy-project.iam.gserviceaccount.com",
			namespace:             "default",
			namespaceAnnotations:  map[string]string{namespaceKey: "[\"cool@fancy-project.iam.gserviceaccount.com\"]"},
			expectedResult:        true,
		},
		{
			test:                  "Restrictions enabled, partial glob in annotation",
			namespaceRestriction:  true,
			defaultServiceAccount: "boring@fancy-project.iam.gserviceaccount.com",
			serviceAccount:        "cool-account@fancy-project.iam.gserviceaccount.com",
			namespace:             "default",
			namespaceAnnotations:  map[string]string{namespaceKey: "[\"cool-*@fancy-project.iam.gserviceaccount.com\"]"},
			expectedResult:        true,
		},
		{
			test:                  "Restrictions enabled, not in annotation",
			namespaceRestriction:  true,
			defaultServiceAccount: "boring@fancy-project.iam.gserviceaccount.com",
			serviceAccount:        "cool-account@fancy-project.iam.gserviceaccount.com",
			namespace:             "default",
			namespaceAnnotations:  map[string]string{namespaceKey: "[\"unrelated@fancy-project.iam.gserviceaccount.com\"]"},
			expectedResult:        false,
		},
		{
			test:                 "Restrictions enabled, no annotations",
			namespaceRestriction: true,
			serviceAccount:       "cool-account@fancy-project.iam.gserviceaccount.com",
			namespace:            "default",
			namespaceAnnotations: map[string]string{namespaceKey: ""},
			expectedResult:       false,
		},
	}

	for _, tt := range serviceAccountCheckTests {
		t.Run(tt.test, func(t *testing.T) {
			rp := NewServiceAccountMapper(
				serviceAccountKey,
				tt.defaultServiceAccount,
				tt.namespaceRestriction,
				namespaceKey,
				&storeMock{
					namespace:   tt.namespace,
					annotations: tt.namespaceAnnotations,
				},
			)

			resp := rp.checkServiceAccountForNamespace(tt.serviceAccount, tt.namespace)
			if resp != tt.expectedResult {
				t.Errorf("Expected [%t] for test but recieved [%t]", tt.expectedResult, resp)
			}
		})
	}
}

type storeMock struct {
	namespace   string
	annotations map[string]string
}

func (k *storeMock) ListPodIPs() []string {
	return nil
}
func (k *storeMock) PodByIP(string) (*v1.Pod, error) {
	return nil, nil
}
func (k *storeMock) ListNamespaces() []string {
	return nil
}
func (k *storeMock) NamespaceByName(ns string) (*v1.Namespace, error) {
	if ns == k.namespace {
		nns := &v1.Namespace{}
		nns.Name = k.namespace
		nns.Annotations = k.annotations
		return nns, nil
	}
	return nil, fmt.Errorf("Namepsace isn't present")
}
