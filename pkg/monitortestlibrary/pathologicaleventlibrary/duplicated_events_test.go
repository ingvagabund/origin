package pathologicaleventlibrary

import (
	_ "embed"
	"testing"
	"time"

	v1 "github.com/openshift/api/config/v1"
	"github.com/openshift/origin/pkg/monitor/monitorapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllowedRepeatedEvents(t *testing.T) {
	//message: `ns/ pod/pfpod node/ - reason/Unhealthy `,
	tests := []struct {
		name    string
		locator monitorapi.Locator
		msg     monitorapi.Message
		// expectedMatchName is the name of the PathologicalEventMatcher we expect to be returned as allowing this duplicated event.
		expectedMatchName string
	}{
		{
			name: "unhealthy e2e port forwarding pod readiness probe",
			locator: monitorapi.Locator{
				Keys: map[monitorapi.LocatorKey]string{
					monitorapi.LocatorNamespaceKey: "e2e-port-forwarding-588",
					monitorapi.LocatorPodKey:       "pfpod",
					monitorapi.LocatorNodeKey:      "ci-op-g1d5csj7-b08f5-fgrqd-worker-b-xj89f",
				},
			},
			msg: monitorapi.NewMessage().HumanMessage("Readiness probe failed: some error goes here").
				Reason("Unhealthy").Build(),
			expectedMatchName: "UnhealthyE2EPortForwarding",
		},
		{
			name: "scc-test-3",
			locator: monitorapi.Locator{
				Keys: map[monitorapi.LocatorKey]string{
					monitorapi.LocatorNamespaceKey: "e2e-test-scc-578l5",
					monitorapi.LocatorPodKey:       "test3",
				},
			},
			msg: monitorapi.NewMessage().HumanMessage("0/6 nodes are available: 3 node(s) didn't match Pod's node affinity/selector, 3 node(s) had taint {node-role.kubernetes.io/master: }, that the pod didn't tolerate.").
				Reason("FailedScheduling").Build(),
			expectedMatchName: "E2ESCCFailedScheduling",
		},
		{
			name: "non-root",
			locator: monitorapi.Locator{
				Keys: map[monitorapi.LocatorKey]string{
					monitorapi.LocatorNamespaceKey: "e2e-security-context-test-6596",
					monitorapi.LocatorPodKey:       "explicit-root-uid",
				},
			},
			msg: monitorapi.NewMessage().HumanMessage("Error: container's runAsUser breaks non-root policy (pod: \"explicit-root-uid_e2e-security-context-test-6596(22bf29d0-e546-4a15-8dd7-8acd9165c924)\", container: explicit-root-uid)").
				Reason("Failed").Build(),
			expectedMatchName: "E2ESecurityContextBreaksNonRootPolicy",
		},
		{
			name: "local-volume-failed-scheduling",
			locator: monitorapi.Locator{
				Keys: map[monitorapi.LocatorKey]string{
					monitorapi.LocatorNamespaceKey: "e2e-persistent-local-volumes-test-7012",
					monitorapi.LocatorPodKey:       "pod-940713ce-7645-4d8c-bba0-5705350a5655",
				},
			},
			msg: monitorapi.NewMessage().HumanMessage("0/6 nodes are available: 1 node(s) had volume node affinity conflict, 2 node(s) didn't match Pod's node affinity/selector, 3 node(s) had taint {node-role.kubernetes.io/master: }, that the pod didn't tolerate. (2 times)").
				Reason("FailedScheduling").Build(),
			expectedMatchName: "E2EPersistentVolumesFailedScheduling",
		},
		{
			name: "missing image",
			locator: monitorapi.Locator{
				Keys: map[monitorapi.LocatorKey]string{
					monitorapi.LocatorNamespaceKey: "e2e-deployment-478",
					monitorapi.LocatorPodKey:       "webserver-deployment-795d758f88-fdr4d ",
				},
			},
			msg: monitorapi.NewMessage().HumanMessage("Back-off pulling image \"webserver:404\"").
				Reason("BackOff").Build(),
			expectedMatchName: "BackOffPullingWebserverImage404",
		},
		{
			name: "port-forward",
			locator: monitorapi.Locator{
				Keys: map[monitorapi.LocatorKey]string{
					monitorapi.LocatorNamespaceKey: "e2e-port-forwarding-588",
					monitorapi.LocatorPodKey:       "pfpod",
				},
			},
			msg: monitorapi.NewMessage().HumanMessage("Readiness probe failed").
				Reason("Unhealthy").Build(),
			expectedMatchName: "KubeletUnhealthyReadinessProbeFailed",
		},
		{
			name: "container-probe",
			locator: monitorapi.Locator{
				Keys: map[monitorapi.LocatorKey]string{
					monitorapi.LocatorNamespaceKey: "e2e-container-probe-3794",
					monitorapi.LocatorPodKey:       "test-webserver-3faa80d6-05f2-42a7-9846-099e8a4cf28c",
				},
			},
			msg: monitorapi.NewMessage().HumanMessage("Readiness probe failed: Get \"http://10.131.0.54:81/\": dial tcp 10.131.0.54:81: connect: connection refused").
				Reason("Unhealthy").Build(),
			expectedMatchName: "E2EContainerProbeFailedOrWarning",
		},
		{
			name: "failing-init-container",
			locator: monitorapi.Locator{
				Keys: map[monitorapi.LocatorKey]string{
					monitorapi.LocatorNamespaceKey: "e2e-init-container-368",
					monitorapi.LocatorPodKey:       "pod-init-cb40ee55-e9c5-4c4b-b541-47cc018d9856",
					monitorapi.LocatorNodeKey:      "ci-op-ncxkp5gj-875d2-5jcfn-worker-c-pwf97",
				},
			},
			msg: monitorapi.NewMessage().HumanMessage("Back-off restarting failed container").
				Reason("BackOff").Build(),
			expectedMatchName: "E2EInitContainerRestartBackoff",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allowed, matchedAllowedDupe := MatchesAny(AllowedPathologicalEvents, test.locator, test.msg, "")
			if test.expectedMatchName != "" {
				assert.True(t, allowed, "duplicated event should have been allowed")
				require.NotNil(t, matchedAllowedDupe, "an allowed dupe even should have been returned")
				assert.Equal(t, test.expectedMatchName, matchedAllowedDupe.Name, "duplicated event was not allowed by the correct PathologicalEventMatcher")
			} else {
				require.False(t, allowed, "duplicated event should not have been allowed")
				assert.Nil(t, matchedAllowedDupe, "duplicated event should not have been allowed by matcher")
			}
		})
	}

}

func TestPathologicalEventsWithNamespaces(t *testing.T) {
	evaluator := duplicateEventsEvaluator{
		allowedDupeEvents: AllowedPathologicalEvents,
	}
	from := time.Unix(872827200, 0).In(time.UTC)
	to := time.Unix(872827200, 0).In(time.UTC)

	tests := []struct {
		name            string
		namespace       string
		platform        v1.PlatformType
		topology        v1.TopologyMode
		intervals       []monitorapi.Interval
		expectedMessage string
	}{
		{
			name: "matches 22 with namespace openshift",
			intervals: []monitorapi.Interval{
				monitorapi.NewInterval(monitorapi.SourceKubeEvent, monitorapi.Info).
					Locator(monitorapi.Locator{Keys: map[monitorapi.LocatorKey]string{
						monitorapi.LocatorNamespaceKey: "openshift",
					}}).Message(
					monitorapi.NewMessage().Reason("SomeEvent1").HumanMessage("foo").
						WithAnnotation(monitorapi.AnnotationCount, "22")).
					Build(time.Unix(872827200, 0).In(time.UTC), time.Unix(872827200, 0).In(time.UTC)),
			},
			namespace:       "openshift",
			platform:        v1.AWSPlatformType,
			topology:        v1.SingleReplicaTopologyMode,
			expectedMessage: "1 events happened too frequently\n\nevent happened 22 times, something is wrong: namespace/openshift - reason/SomeEvent1 foo From: 04:00:00Z To: 04:00:00Z result=reject ",
		},
		{
			name: "matches 22 with namespace e2e",
			intervals: []monitorapi.Interval{
				monitorapi.NewInterval(monitorapi.SourceKubeEvent, monitorapi.Info).
					Locator(monitorapi.Locator{Keys: map[monitorapi.LocatorKey]string{
						monitorapi.LocatorNamespaceKey: "random",
					}}).Message(
					monitorapi.NewMessage().Reason("SomeEvent1").HumanMessage("foo").
						WithAnnotation(monitorapi.AnnotationCount, "22")).
					Build(time.Unix(872827200, 0).In(time.UTC), time.Unix(872827200, 0).In(time.UTC)),
			},
			namespace:       "",
			platform:        v1.AWSPlatformType,
			topology:        v1.SingleReplicaTopologyMode,
			expectedMessage: "1 events happened too frequently\n\nevent happened 22 times, something is wrong: namespace/random - reason/SomeEvent1 foo From: 04:00:00Z To: 04:00:00Z result=reject ",
		},
		{
			name: "matches 22 with no namespace",
			intervals: []monitorapi.Interval{
				monitorapi.NewInterval(monitorapi.SourceKubeEvent, monitorapi.Info).
					Locator(monitorapi.Locator{Keys: map[monitorapi.LocatorKey]string{}}).Message(
					monitorapi.NewMessage().Reason("SomeEvent1").HumanMessage("foo").
						WithAnnotation(monitorapi.AnnotationCount, "22")).
					Build(time.Unix(872827200, 0).In(time.UTC), time.Unix(872827200, 0).In(time.UTC)),
			},
			namespace:       "",
			platform:        v1.AWSPlatformType,
			topology:        v1.SingleReplicaTopologyMode,
			expectedMessage: "1 events happened too frequently\n\nevent happened 22 times, something is wrong:  - reason/SomeEvent1 foo From: 04:00:00Z To: 04:00:00Z result=reject ",
		},
		{
			name: "matches 12 with namespace openshift",
			intervals: []monitorapi.Interval{
				monitorapi.NewInterval(monitorapi.SourceKubeEvent, monitorapi.Info).
					Locator(monitorapi.Locator{Keys: map[monitorapi.LocatorKey]string{
						monitorapi.LocatorNamespaceKey: "openshift",
					}}).Message(
					monitorapi.NewMessage().Reason("SomeEvent1").HumanMessage("foo").
						WithAnnotation(monitorapi.AnnotationCount, "12")).
					Build(time.Unix(872827200, 0).In(time.UTC), time.Unix(872827200, 0).In(time.UTC)),
			},
			namespace:       "openshift",
			platform:        v1.AWSPlatformType,
			topology:        v1.SingleReplicaTopologyMode,
			expectedMessage: "",
		},
		{
			// This is ignored because it was during a master NodeUpdate interval
			name: "ignore FailedScheduling in openshift-controller-manager if masters are updating",
			intervals: []monitorapi.Interval{
				{
					Condition: monitorapi.Condition{
						Level: monitorapi.Info,
						StructuredLocator: monitorapi.Locator{
							Type: monitorapi.LocatorTypeNode,
							Keys: map[monitorapi.LocatorKey]string{}, // what node doesn't matter, all we can do is see if masters are updating
						},
						StructuredMessage: monitorapi.Message{
							Reason:       monitorapi.NodeUpdateReason,
							HumanMessage: "config/rendered-master-5ab4844b3b5a58958785e2c27d99f50f phase/Update roles/control-plane,master reached desired config roles/control-plane,master",
							Annotations: map[monitorapi.AnnotationKey]string{
								monitorapi.AnnotationConstructed: "node-lifecycle-constructor",
								monitorapi.AnnotationPhase:       "Update",
								monitorapi.AnnotationRoles:       "control-plane,master",
							},
						},
					},
					Source: monitorapi.SourceNodeState,
					From:   from.Add(-1 * time.Minute),
					To:     to.Add(1 * time.Minute),
				},

				monitorapi.NewInterval(monitorapi.SourceKubeEvent, monitorapi.Info).
					Locator(monitorapi.Locator{Keys: map[monitorapi.LocatorKey]string{
						monitorapi.LocatorNamespaceKey: "openshift-controller-manager",
					}}).Message(
					monitorapi.NewMessage().Reason("FailedScheduling").
						HumanMessage("0/6 nodes are available: 2 node(s) were unschedulable, 4 node(s) didn't match pod anti-affinity rules. preemption: 0/6 nodes are available: 2 Preemption is not helpful for scheduling, 4 No preemption victims found for incoming pod..").
						WithAnnotation(monitorapi.AnnotationCount, "22")).
					Build(time.Unix(872827200, 0).In(time.UTC), time.Unix(872827200, 0).In(time.UTC)),
			},
			namespace:       "openshift-controller-manager",
			platform:        v1.AWSPlatformType,
			topology:        v1.HighlyAvailableTopologyMode,
			expectedMessage: "",
		},
		{
			// This is not ignored because there were no masters in NodeUpdate
			name: "match FailedScheduling in openshift-controller-manager when masters are not updating",
			intervals: []monitorapi.Interval{
				monitorapi.NewInterval(monitorapi.SourceKubeEvent, monitorapi.Info).
					Locator(monitorapi.Locator{Keys: map[monitorapi.LocatorKey]string{
						monitorapi.LocatorNamespaceKey: "openshift-controller-manager",
					}}).Message(
					monitorapi.NewMessage().Reason("FailedScheduling").
						HumanMessage("0/6 nodes are available: 2 node(s) were unschedulable, 4 node(s) didn't match pod anti-affinity rules. preemption: 0/6 nodes are available: 2 Preemption is not helpful for scheduling, 4 No preemption victims found for incoming pod..").
						WithAnnotation(monitorapi.AnnotationCount, "22")).
					Build(time.Unix(872827200, 0).In(time.UTC), time.Unix(872827200, 0).In(time.UTC)),
			},
			namespace:       "openshift-controller-manager",
			platform:        v1.AWSPlatformType,
			topology:        v1.HighlyAvailableTopologyMode,
			expectedMessage: "1 events happened too frequently\n\nevent happened 22 times, something is wrong: namespace/openshift-controller-manager - reason/FailedScheduling 0/6 nodes are available: 2 node(s) were unschedulable, 4 node(s) didn't match pod anti-affinity rules. preemption: 0/6 nodes are available: 2 Preemption is not helpful for scheduling, 4 No preemption victims found for incoming pod.. From: 04:00:00Z To: 04:00:00Z result=reject ",
		},
		{
			// This still matches despite the masters updating because it's not in an openshift namespace
			name: "match FailedScheduling outside openshift namespaces if masters are updating",
			intervals: []monitorapi.Interval{
				{
					Condition: monitorapi.Condition{
						Level: monitorapi.Info,
						StructuredLocator: monitorapi.Locator{
							Type: monitorapi.LocatorTypeNode,
							Keys: map[monitorapi.LocatorKey]string{}, // what node doesn't matter, all we can do is see if masters are updating
						},
						StructuredMessage: monitorapi.Message{
							Reason:       monitorapi.NodeUpdateReason,
							HumanMessage: "config/rendered-master-5ab4844b3b5a58958785e2c27d99f50f phase/Update roles/control-plane,master reached desired config roles/control-plane,master",
							Annotations: map[monitorapi.AnnotationKey]string{
								monitorapi.AnnotationConstructed: "node-lifecycle-constructor",
								monitorapi.AnnotationPhase:       "Update",
								monitorapi.AnnotationRoles:       "control-plane,master",
							},
						},
					},
					Source: monitorapi.SourceNodeState,
					From:   from.Add(-1 * time.Minute),
					To:     to.Add(1 * time.Minute),
				},
				monitorapi.NewInterval(monitorapi.SourceKubeEvent, monitorapi.Info).
					Locator(monitorapi.Locator{Keys: map[monitorapi.LocatorKey]string{
						monitorapi.LocatorNamespaceKey: "mynamespace",
					}}).Message(
					monitorapi.NewMessage().Reason("FailedScheduling").
						HumanMessage("0/6 nodes are available: 2 node(s) were unschedulable, 4 node(s) didn't match pod anti-affinity rules. preemption: 0/6 nodes are available: 2 Preemption is not helpful for scheduling, 4 No preemption victims found for incoming pod..").
						WithAnnotation(monitorapi.AnnotationCount, "22")).
					Build(time.Unix(872827200, 0).In(time.UTC), time.Unix(872827200, 0).In(time.UTC)),
			},
			namespace:       "mynamespace",
			platform:        v1.AWSPlatformType,
			topology:        v1.HighlyAvailableTopologyMode,
			expectedMessage: "1 events happened too frequently\n\nevent happened 22 times, something is wrong:  - ns/mynamespace reason/FailedScheduling 0/6 nodes are available: 2 node(s) were unschedulable, 4 node(s) didn't match pod anti-affinity rules. preemption: 0/6 nodes are available: 2 Preemption is not helpful for scheduling, 4 No preemption victims found for incoming pod.. From: 04:00:00Z To: 04:00:00Z result=reject ",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			events := monitorapi.Intervals(test.intervals)

			evaluator.platform = test.platform
			evaluator.topology = test.topology

			testName := "events should not repeat"
			junits := evaluator.testDuplicatedEvents(testName, false, events, nil, false)
			namespaces := getNamespacesForJUnits()
			assert.Equal(t, len(namespaces), len(junits), "didn't get junits for all known namespaces")

			jUnitName := getJUnitName(testName, test.namespace)
			for _, junit := range junits {
				if (junit.Name == jUnitName) && (test.expectedMessage != "") {
					require.NotNil(t, junit.FailureOutput, "expected junit to have failure output")
					assert.Equal(t, test.expectedMessage, junit.FailureOutput.Output)
				} else {
					if !assert.Nil(t, junit.FailureOutput, "expected success but got failure output") {
						t.Logf(junit.FailureOutput.Output)
					}
				}
			}

		})
	}
}

/* TODO: bring these back in another form
func TestKnownBugEvents(t *testing.T) {
	evaluator := duplicateEventsEvaluator{
		allowedRepeatedEventPatterns: AllowedRepeatedEventPatterns,
		knownRepeatedEventsBugs: []KnownProblem{
			{
				Regexp: regexp.MustCompile(`ns/.* reason/SomeEvent1.*`),
				BZ:     "https://bugzilla.redhat.com/show_bug.cgi?id=1234567",
			},
			{
				Regexp:   regexp.MustCompile("ns/.*reason/SomeEvent2.*"),
				BZ:       "https://bugzilla.redhat.com/show_bug.cgi?id=1234567",
				Topology: TopologyPointer(v1.SingleReplicaTopologyMode),
			},
			{
				Regexp:   regexp.MustCompile("ns/.*reason/SomeEvent3.*"),
				BZ:       "https://bugzilla.redhat.com/show_bug.cgi?id=1234567",
				Platform: PlatformPointer(v1.AWSPlatformType),
			},
			{
				Regexp:   regexp.MustCompile("ns/.*reason/SomeEvent4.*"),
				BZ:       "https://bugzilla.redhat.com/show_bug.cgi?id=1234567",
				Topology: TopologyPointer(v1.HighlyAvailableTopologyMode),
			},
			{
				Regexp:   regexp.MustCompile("ns/.*reason/SomeEvent5.*"),
				BZ:       "https://bugzilla.redhat.com/show_bug.cgi?id=1234567",
				Platform: PlatformPointer(v1.GCPPlatformType),
			},
			{
				Regexp:   regexp.MustCompile("ns/.*reason/SomeEvent6.*"),
				BZ:       "https://bugzilla.redhat.com/show_bug.cgi?id=1234567",
				Platform: PlatformPointer(""),
			},
		},
	}

	tests := []struct {
		name     string
		message  string
		match    bool
		platform v1.PlatformType
		topology v1.TopologyMode
	}{
		{
			name:     "matches without platform or topology",
			message:  `ns/e2e - reason/SomeEvent1 foo (21 times)`,
			match:    true,
			platform: v1.AWSPlatformType,
			topology: v1.SingleReplicaTopologyMode,
		},
		{
			name:     "matches with topology",
			message:  `ns/e2e - reason/SomeEvent2 foo (21 times)`,
			match:    true,
			platform: v1.AWSPlatformType,
			topology: v1.SingleReplicaTopologyMode,
		},
		{
			name:     "matches with topology and platform",
			message:  `ns/e2e - reason/SomeEvent3 foo (21 times)`,
			match:    true,
			platform: v1.AWSPlatformType,
			topology: v1.SingleReplicaTopologyMode,
		},
		{
			name:     "does not match against different topology",
			message:  `ns/e2e - reason/SomeEvent4 foo (21 times)`,
			platform: v1.AWSPlatformType,
			topology: v1.SingleReplicaTopologyMode,
			match:    false,
		},
		{
			name:     "does not match against different platform",
			message:  `ns/e2e - reason/SomeEvent5 foo (21 times)`,
			platform: v1.AWSPlatformType,
			topology: v1.SingleReplicaTopologyMode,
			match:    false,
		},
		{
			name:     "empty platform matches empty platform",
			message:  `ns/e2e - reason/SomeEvent6 foo (21 times)`,
			platform: "",
			match:    true,
		},
		{
			name:     "empty platform doesn't match another platform",
			message:  `ns/e2e - reason/SomeEvent6 foo (21 times)`,
			platform: v1.AWSPlatformType,
			match:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			events := monitorapi.Intervals{}
			events = append(events,
				monitorapi.Interval{
					Condition: monitorapi.Condition{Message: test.message},
					From:      time.Unix(1, 0).In(time.UTC),
					To:        time.Unix(1, 0).In(time.UTC)},
			)
			evaluator.platform = test.platform
			evaluator.topology = test.topology

			junits := evaluator.testDuplicatedEvents("events should not repeat", false, events, nil, true)
			assert.GreaterOrEqual(t, len(junits), 1, "didn't get junit for duplicated event")

			if test.match {
				require.NotNil(t, junits[0].FailureOutput)
				assert.Contains(t, junits[0].FailureOutput.Output, "1 events with known BZs")
			} else {
				assert.Nil(t, junits[0].FailureOutput)
			}

		})
	}
}

func TestKnownBugEventsGroup(t *testing.T) {
	evaluator := duplicateEventsEvaluator{
		allowedRepeatedEventPatterns: AllowedRepeatedEventPatterns,
		knownRepeatedEventsBugs: []KnownProblem{
			{
				Regexp: regexp.MustCompile(`ns/.* reason/SomeEvent1.*`),
				BZ:     "https://bugzilla.redhat.com/show_bug.cgi?id=1234567",
			},
		},
	}

	tests := []struct {
		name            string
		messages        []string
		platform        v1.PlatformType
		topology        v1.TopologyMode
		expectedMessage string
	}{
		{
			name:            "matches 22 before",
			messages:        []string{`ns/e2e - reason/SomeEvent1 foo (22 times)`, `ns/e2e - reason/SomeEvent1 foo (21 times)`},
			platform:        v1.AWSPlatformType,
			topology:        v1.SingleReplicaTopologyMode,
			expectedMessage: "1 events with known BZs\n\nevent happened 22 times, something is wrong:  - ns/e2e - reason/SomeEvent1 foo From: 04:00:00Z To: 04:00:00Z - https://bugzilla.redhat.com/show_bug.cgi?id=1234567 result=allow ",
		},
		{
			name:            "matches 25 after",
			messages:        []string{`ns/e2e - reason/SomeEvent1 foo (21 times)`, `ns/e2e - reason/SomeEvent1 foo (25 times)`},
			platform:        v1.AWSPlatformType,
			topology:        v1.SingleReplicaTopologyMode,
			expectedMessage: "1 events with known BZs\n\nevent happened 25 times, something is wrong:  - ns/e2e - reason/SomeEvent1 foo From: 04:00:00Z To: 04:00:00Z - https://bugzilla.redhat.com/show_bug.cgi?id=1234567 result=allow ",
		},
		{
			name:            "matches 22 below with below threshold following",
			messages:        []string{`ns/e2e - reason/SomeEvent1 foo (22 times)`, `ns/e2e - reason/SomeEvent1 foo (5 times)`},
			platform:        v1.AWSPlatformType,
			topology:        v1.SingleReplicaTopologyMode,
			expectedMessage: "1 events with known BZs\n\nevent happened 22 times, something is wrong:  - ns/e2e - reason/SomeEvent1 foo From: 04:00:00Z To: 04:00:00Z - https://bugzilla.redhat.com/show_bug.cgi?id=1234567 result=allow ",
		},
		{
			name:            "matches 22 with multiple line message",
			messages:        []string{"ns/e2e - reason/SomeEvent1 foo \nbody:\n (22 times)"},
			platform:        v1.AWSPlatformType,
			topology:        v1.SingleReplicaTopologyMode,
			expectedMessage: "1 events with known BZs\n\nevent happened 22 times, something is wrong:  - ns/e2e - reason/SomeEvent1 foo  result=allow \nbody:\n From: 04:00:00Z To: 04:00:00Z - https://bugzilla.redhat.com/show_bug.cgi?id=1234567",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			events := monitorapi.Intervals{}
			for _, message := range test.messages {

				events = append(events,
					monitorapi.Interval{
						Condition: monitorapi.Condition{Message: message},
						From:      time.Unix(872827200, 0).In(time.UTC),
						To:        time.Unix(872827200, 0).In(time.UTC)},
				)
			}

			evaluator.platform = test.platform
			evaluator.topology = test.topology

			junits := evaluator.testDuplicatedEvents("events should not repeat", false, events, nil, true)
			assert.GreaterOrEqual(t, len(junits), 1, "didn't get junit for duplicated event")

			assert.Equal(t, test.expectedMessage, junits[0].FailureOutput.Output)

		})
	}
}

*/

func TestMakeProbeTestEventsGroup(t *testing.T) {

	tests := []struct {
		name            string
		intervals       monitorapi.Intervals
		match           bool
		matcher         *PathologicalEventMatcher
		operator        string
		expectedMessage string
	}{
		{
			name: "matches 22 before",
			intervals: monitorapi.Intervals{
				BuildTestDupeKubeEvent("openshift-oauth-apiserver", "", "ProbeError",
					"foo Liveness probe error: Get \"https://10.128.0.21:8443/healthz\": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers) occurred", 22),
				BuildTestDupeKubeEvent("openshift-oauth-apiserver", "", "ProbeError",
					"foo Liveness probe error: Get \"https://10.128.0.21:8443/healthz\": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers) occurred", 21),
			},
			match:           true,
			operator:        "openshift-oauth-apiserver",
			matcher:         ProbeErrorLiveness,
			expectedMessage: "I namespace/openshift-oauth-apiserver count/22 reason/ProbeError foo Liveness probe error: Get \"https://10.128.0.21:8443/healthz\": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers) occurred\n",
		},
		{
			name: "no matches 22 before",
			intervals: monitorapi.Intervals{
				BuildTestDupeKubeEvent("e2e", "", "ProbeError",
					"foo Liveness probe error: Get \"https://10.128.0.21:8443/healthz\": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers) occurred",
					22),
				BuildTestDupeKubeEvent("e2e", "", "ProbeError",
					"foo Liveness probe error: Get \"https://10.128.0.21:8443/healthz\": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers) occurred",
					21),
			},
			match:           false,
			operator:        "e2e",
			matcher:         ProbeErrorConnectionRefused,
			expectedMessage: "",
		},
		{
			name: "matches 25 after",
			intervals: monitorapi.Intervals{
				BuildTestDupeKubeEvent("openshift-oauth-apiserver", "apiserver-647fc6c7bf-s8b4h", "ProbeError",
					"Readiness probe error: Get \"https://10.128.0.38:8443/readyz\": dial tcp 10.128.0.38:8443: connect: connection refused occurred",
					22),
				BuildTestDupeKubeEvent("openshift-oauth-apiserver", "apiserver-647fc6c7bf-s8b4h", "ProbeError",
					"Readiness probe error: Get \"https://10.128.0.38:8443/readyz\": dial tcp 10.128.0.38:8443: connect: connection refused occurred",
					25),
			},
			operator:        "openshift-oauth-apiserver",
			match:           true,
			matcher:         ProbeErrorConnectionRefused,
			expectedMessage: "I namespace/openshift-oauth-apiserver pod/openshift-oauth-apiserver count/25 reason/ProbeError Readiness probe error: Get \"https://10.128.0.38:8443/readyz\": dial tcp 10.128.0.38:8443: connect: connection refused occurred\n",
		},
		{
			name: "no matches 25 after",
			intervals: monitorapi.Intervals{
				BuildTestDupeKubeEvent("openshift-oauth-apiserver", "apiserver-647fc6c7bf-s8b4h", "ProbeError",
					"Readiness probe error: Get \"https://10.128.0.38:8443/readyz\": dial tcp 10.128.0.38:8443: connect: connection refused occurred",
					22),
				BuildTestDupeKubeEvent("openshift-oauth-apiserver", "apiserver-647fc6c7bf-s8b4h", "ProbeError",
					"Readiness probe error: Get \"https://10.128.0.38:8443/readyz\": dial tcp 10.128.0.38:8443: connect: connection refused occurred",
					25),
			},
			operator:        "openshift-oauth-apiserver",
			match:           false,
			matcher:         ProbeErrorLiveness,
			expectedMessage: "",
		},
		{
			name: "matches 22 below with below threshold following",
			intervals: monitorapi.Intervals{
				BuildTestDupeKubeEvent("openshift-oauth-apiserver", "", "ProbeError",
					"Readiness probe error: Get \"https://10.130.0.15:8443/healthz\": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers) occurred ",
					22),
				BuildTestDupeKubeEvent("openshift-oauth-apiserver", "", "ProbeError",
					"Readiness probe error: Get \"https://10.130.0.15:8443/healthz\": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers) occurred ",
					5),
			},
			operator:        "openshift-oauth-apiserver",
			match:           true,
			matcher:         ProbeErrorTimeoutAwaitingHeaders,
			expectedMessage: "I namespace/openshift-oauth-apiserver count/22 reason/ProbeError Readiness probe error: Get \"https://10.130.0.15:8443/healthz\": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers) occurred\n",
		},
		{
			name: "no matches 22 below with below threshold following",
			intervals: monitorapi.Intervals{
				BuildTestDupeKubeEvent("", "", "ProbeError",
					"Readiness probe error: Get \"https://10.130.0.15:8443/healthz\": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers) occurred",
					22),
				BuildTestDupeKubeEvent("", "", "ProbeError",
					"Readiness probe error: Get \"https://10.130.0.15:8443/healthz\": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers) occurred",
					5),
			},
			operator:        "openshift-oauth-apiserver",
			match:           false,
			matcher:         ProbeErrorConnectionRefused,
			expectedMessage: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			events := test.intervals

			junits := MakeProbeTest("Test Test", events, test.operator, test.matcher, DuplicateEventThreshold)

			assert.GreaterOrEqual(t, len(junits), 1, "Didn't get junit for duplicated event")

			if test.match {
				require.NotNil(t, junits[0].FailureOutput)
				assert.Contains(t, junits[0].FailureOutput.Output, test.expectedMessage)
			} else {
				assert.Nil(t, junits[0].FailureOutput, "expected case to not match, but it did: %s", test.name)
			}

		})
	}
}

func TestPathologicalEventsTopologyAwareHintsDisabled(t *testing.T) {
	evaluator := duplicateEventsEvaluator{
		allowedDupeEvents: AllowedPathologicalEvents,
	}
	from := time.Unix(872827200, 0).In(time.UTC)
	to := time.Unix(872827200, 0).In(time.UTC)

	tests := []struct {
		name            string
		namespace       string
		intervals       []monitorapi.Interval
		expectedMessage string
	}{
		{
			// This is ignored because the node is tainted by test
			name: "ignore TopologyAwareHintsDisabled before dns container ready",
			intervals: []monitorapi.Interval{
				{
					Condition: monitorapi.Condition{
						Level: monitorapi.Info,
						StructuredLocator: monitorapi.Locator{
							Type: monitorapi.LocatorTypeE2ETest,
							Keys: map[monitorapi.LocatorKey]string{
								monitorapi.LocatorE2ETestKey: "[sig-node] NoExecuteTaintManager Single Pod [Serial] doesn't evict pod with tolerations from tainted nodes [Skipped:SingleReplicaTopology] [Suite:openshift/conformance/serial] [Suite:k8s]",
							},
						},
						StructuredMessage: monitorapi.Message{},
					},
					Source: monitorapi.SourceE2ETest,
					From:   from.Add(-10 * time.Minute),
					To:     to.Add(10 * time.Minute),
				},
				{
					Condition: monitorapi.Condition{
						Level: monitorapi.Info,
						StructuredLocator: monitorapi.Locator{
							Type: monitorapi.LocatorTypePod,
							Keys: map[monitorapi.LocatorKey]string{
								monitorapi.LocatorNamespaceKey: "openshift-dns",
								monitorapi.LocatorPodKey:       "dns-default-jq2qn",
							},
						},
						StructuredMessage: monitorapi.Message{
							Reason: monitorapi.PodReasonGracefulDeleteStarted,
							Annotations: map[monitorapi.AnnotationKey]string{
								monitorapi.AnnotationConstructed: "pod-lifecycle-constructor",
								monitorapi.AnnotationReason:      "GracefulDelete",
							},
						},
					},
					Source: monitorapi.SourcePodState,
					From:   from.Add(-5 * time.Minute),
					To:     to.Add(1 * time.Minute),
				},
				{
					Condition: monitorapi.Condition{
						Level: monitorapi.Info,
						StructuredLocator: monitorapi.Locator{
							Type: "",
							Keys: map[monitorapi.LocatorKey]string{
								monitorapi.LocatorNamespaceKey:   "openshift-dns",
								monitorapi.LocatorKey("service"): "dns-default",
								monitorapi.LocatorHmsgKey:        "ade328ddf3",
							},
						},
						StructuredMessage: monitorapi.Message{
							Reason:       "TopologyAwareHintsDisabled",
							HumanMessage: "Unable to allocate minimum required endpoints to each zone without exceeding overload threshold (5 endpoints, 3 zones), addressType: IPv4",
							Annotations: map[monitorapi.AnnotationKey]string{
								monitorapi.AnnotationReason:       "TopologyAwareHintsDisabled",
								monitorapi.AnnotationPathological: "true",
								monitorapi.AnnotationCount:        "23",
							},
						},
					},
					From: from.Add(11 * time.Minute),
					To:   to.Add(12 * time.Minute),
				},
				{
					Condition: monitorapi.Condition{
						Level: monitorapi.Info,
						StructuredLocator: monitorapi.Locator{
							Type: monitorapi.LocatorTypeContainer,
							Keys: map[monitorapi.LocatorKey]string{
								monitorapi.LocatorNamespaceKey: "openshift-dns",
								monitorapi.LocatorContainerKey: "dns",
								monitorapi.LocatorPodKey:       "dns-default-jq2qn",
							},
						},
						StructuredMessage: monitorapi.Message{
							Reason: monitorapi.ContainerReasonReady,
							Annotations: map[monitorapi.AnnotationKey]string{
								monitorapi.AnnotationConstructed: "pod-lifecycle-constructor",
								monitorapi.AnnotationReason:      "Ready",
							},
						},
					},
					Source: monitorapi.SourcePodState,
					From:   from.Add(15 * time.Minute),
					To:     to.Add(16 * time.Minute),
				},
			},
			namespace:       "openshift-dns",
			expectedMessage: "",
		},
		{
			// This is not ignored because there is no dns ready following
			name: "fire TopologyAwareHintsDisabled when there is no dns container ready",
			intervals: []monitorapi.Interval{
				{
					Condition: monitorapi.Condition{
						Level: monitorapi.Info,
						StructuredLocator: monitorapi.Locator{
							Type: monitorapi.LocatorTypeE2ETest,
							Keys: map[monitorapi.LocatorKey]string{
								monitorapi.LocatorE2ETestKey: "[sig-node] NoExecuteTaintManager Single Pod [Serial] doesn't evict pod with tolerations from tainted nodes [Skipped:SingleReplicaTopology] [Suite:openshift/conformance/serial] [Suite:k8s]",
							},
						},
						StructuredMessage: monitorapi.Message{},
					},
					Source: monitorapi.SourceE2ETest,
					From:   from.Add(-10 * time.Minute),
					To:     to.Add(10 * time.Minute),
				},
				{
					Condition: monitorapi.Condition{
						Level: monitorapi.Info,
						StructuredLocator: monitorapi.Locator{
							Type: monitorapi.LocatorTypePod,
							Keys: map[monitorapi.LocatorKey]string{
								monitorapi.LocatorNamespaceKey: "openshift-dns",
								monitorapi.LocatorPodKey:       "dns-default-jq2qn",
							},
						},
						StructuredMessage: monitorapi.Message{
							Reason: monitorapi.PodReasonGracefulDeleteStarted,
							Annotations: map[monitorapi.AnnotationKey]string{
								monitorapi.AnnotationConstructed: "pod-lifecycle-constructor",
								monitorapi.AnnotationReason:      "GracefulDelete",
							},
						},
					},
					Source: monitorapi.SourcePodState,
					From:   from.Add(-5 * time.Minute),
					To:     to.Add(1 * time.Minute),
				},
				{
					Condition: monitorapi.Condition{
						Level: monitorapi.Info,
						StructuredLocator: monitorapi.Locator{
							Type: "",
							Keys: map[monitorapi.LocatorKey]string{
								monitorapi.LocatorNamespaceKey:   "openshift-dns",
								monitorapi.LocatorKey("service"): "dns-default",
								monitorapi.LocatorHmsgKey:        "ade328ddf3",
							},
						},
						StructuredMessage: monitorapi.Message{
							Reason:       "TopologyAwareHintsDisabled",
							HumanMessage: "Unable to allocate minimum required endpoints to each zone without exceeding overload threshold (5 endpoints, 3 zones), addressType: IPv4",
							Annotations: map[monitorapi.AnnotationKey]string{
								monitorapi.AnnotationReason:       "TopologyAwareHintsDisabled",
								monitorapi.AnnotationPathological: "true",
								monitorapi.AnnotationCount:        "23",
							},
						},
					},
					From: from.Add(11 * time.Minute),
					To:   to.Add(12 * time.Minute),
				},
			},
			namespace:       "openshift-dns",
			expectedMessage: "1 events happened too frequently\n\nevent happened 23 times, something is wrong:  - reason/TopologyAwareHintsDisabled Unable to allocate minimum required endpoints to each zone without exceeding overload threshold (5 endpoints, 3 zones), addressType: IPv4 From: 04:11:00Z To: 04:12:00Z result=reject ",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			events := monitorapi.Intervals(test.intervals)

			testName := "events should not repeat"
			junits := evaluator.testDuplicatedEvents(testName, false, events, nil, false)
			jUnitName := getJUnitName(testName, test.namespace)
			for _, junit := range junits {
				t.Logf("checking junit: %s", junit.Name)
				if (junit.Name == jUnitName) && (test.expectedMessage != "") {
					require.NotNil(t, junit.FailureOutput)
					assert.Equal(t, test.expectedMessage, junit.FailureOutput.Output)
				} else {
					if !assert.Nil(t, junit.FailureOutput, "expected success but got failure output for junit: %s", junit.Name) {
						t.Logf(junit.FailureOutput.Output)
					}
				}
			}

		})
	}
}
