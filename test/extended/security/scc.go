package security

import (
	"context"
	"fmt"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	authenticationv1 "k8s.io/api/authentication/v1"
	kubeauthorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kapierror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	rbacv1helpers "k8s.io/kubernetes/pkg/apis/rbac/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	admissionapi "k8s.io/pod-security-admission/api"

	securityv1 "github.com/openshift/api/security/v1"
	securityv1client "github.com/openshift/client-go/security/clientset/versioned/typed/security/v1"

	"github.com/openshift/origin/test/extended/authorization"
	exutil "github.com/openshift/origin/test/extended/util"
	"github.com/openshift/origin/test/extended/util/image"
)

var _ = g.Describe("[sig-auth][Feature:SecurityContextConstraints] ", func() {
	defer g.GinkgoRecover()
	oc := exutil.NewCLIWithPodSecurityLevel("scc", admissionapi.LevelPrivileged)
	ctx := context.Background()

	g.It("TestPodUpdateSCCEnforcement [apigroup:user.openshift.io][apigroup:authorization.openshift.io]", func() {
		t := g.GinkgoT()

		projectName := oc.Namespace()
		haroldUser := oc.CreateUser("harold-").Name
		haroldClientConfig := oc.GetClientConfigForUser(haroldUser)
		haroldKubeClient := kubernetes.NewForConfigOrDie(haroldClientConfig)
		authorization.AddUserAdminToProject(oc, projectName, haroldUser)

		RunTestPodUpdateSCCEnforcement(ctx, haroldKubeClient, oc.AdminKubeClient(), projectName, t)
	})

	g.It("TestPodUpdateSCCEnforcement with service account", func() {
		t := g.GinkgoT()

		projectName := oc.Namespace()
		sa := createServiceAccount(ctx, oc, projectName)
		createPodAdminRoleOrDie(ctx, oc, sa)
		restrictedClient, _ := createClientFromServiceAccount(oc, sa)

		RunTestPodUpdateSCCEnforcement(ctx, restrictedClient, oc.AdminKubeClient(), projectName, t)
	})
})

func RunTestPodUpdateSCCEnforcement(ctx context.Context, restrictedClient, clusterAdminKubeClientset kubernetes.Interface, namespace string, t g.GinkgoTInterface) {
	// so cluster-admin can create privileged pods, but harold cannot.  This means that harold should not be able
	// to update the privileged pods either, even if he lies about its privileged nature
	privilegedPod := getPrivilegedPod("unsafe")

	if _, err := restrictedClient.CoreV1().Pods(namespace).Create(ctx, privilegedPod, metav1.CreateOptions{}); !isForbiddenBySCC(err) {
		t.Fatalf("missing forbidden: %v", err)
	}

	actualPod, err := clusterAdminKubeClientset.CoreV1().Pods(namespace).Create(ctx, privilegedPod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	actualPod.Spec.Containers[0].Image = "something-nefarious"
	if _, err := restrictedClient.CoreV1().Pods(namespace).Update(ctx, actualPod, metav1.UpdateOptions{}); !isForbiddenBySCC(err) {
		t.Fatalf("missing forbidden: %v", err)
	}

	// try to connect to /exec subresource as harold
	haroldCorev1Rest := restrictedClient.CoreV1().RESTClient()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := &metav1.Status{}
	err = haroldCorev1Rest.Post().
		Resource("pods").
		Namespace(namespace).
		Name(actualPod.Name).
		SubResource("exec").
		Param("container", "first").
		Do(ctx).
		Into(result)
	if !isForbiddenBySCCExecRestrictions(err) {
		t.Fatalf("missing forbidden by SCCExecRestrictions: %v", err)
	}

	// try to lie about the privileged nature
	actualPod.Spec.HostPID = false
	if _, err := restrictedClient.CoreV1().Pods(namespace).Update(context.Background(), actualPod, metav1.UpdateOptions{}); err == nil {
		t.Fatalf("missing error: %v", err)
	}
}

var _ = g.Describe("[sig-auth][Feature:SecurityContextConstraints] ", func() {
	ctx := context.Background()

	defer g.GinkgoRecover()
	// pods running as root are being started here
	oc := exutil.NewCLIWithPodSecurityLevel("scc", admissionapi.LevelPrivileged)

	g.It("TestAllowedSCCViaRBAC [apigroup:project.openshift.io][apigroup:user.openshift.io][apigroup:authorization.openshift.io][apigroup:security.openshift.io]", func() {
		t := g.GinkgoT()

		clusterAdminKubeClientset := oc.AdminKubeClient()

		project1 := oc.Namespace()
		project2 := oc.CreateProject()
		user1 := oc.CreateUser("user1-").Name
		user2 := oc.CreateUser("user2-").Name

		clusterRole := "all-scc-" + oc.Namespace()
		rule := rbacv1helpers.NewRule("use").Groups("security.openshift.io").Resources("securitycontextconstraints").RuleOrDie()

		// set a up cluster role that allows access to all SCCs
		if _, err := clusterAdminKubeClientset.RbacV1().ClusterRoles().Create(
			ctx,
			&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: clusterRole},
				Rules:      []rbacv1.PolicyRule{rule},
			},
			metav1.CreateOptions{},
		); err != nil {
			t.Fatal(err)
		}
		oc.AddExplicitResourceToDelete(rbacv1.SchemeGroupVersion.WithResource("clusterroles"), "", clusterRole)

		// set up 2 projects for 2 users

		authorization.AddUserAdminToProject(oc, project1, user1)
		user1Config := oc.GetClientConfigForUser(user1)
		user1Client := kubernetes.NewForConfigOrDie(user1Config)
		user1SecurityClient := securityv1client.NewForConfigOrDie(user1Config)

		authorization.AddUserAdminToProject(oc, project2, user2)
		user2Config := oc.GetClientConfigForUser(user2)
		user2Client := kubernetes.NewForConfigOrDie(user2Config)
		user2SecurityClient := securityv1client.NewForConfigOrDie(user2Config)

		createOpts := metav1.CreateOptions{}

		// user1 cannot make a privileged pod
		if _, err := user1Client.CoreV1().Pods(project1).Create(ctx, getPrivilegedPod("test1"), createOpts); !isForbiddenBySCC(err) {
			t.Fatalf("missing forbidden for user1: %v", err)
		}

		// user2 cannot make a privileged pod
		if _, err := user2Client.CoreV1().Pods(project2).Create(ctx, getPrivilegedPod("test2"), createOpts); !isForbiddenBySCC(err) {
			t.Fatalf("missing forbidden for user2: %v", err)
		}

		// this should allow user1 to make a privileged pod in project1
		rb := rbacv1helpers.NewRoleBindingForClusterRole(clusterRole, project1).Users(user1).BindingOrDie()
		if _, err := clusterAdminKubeClientset.RbacV1().RoleBindings(project1).Create(ctx, &rb, createOpts); err != nil {
			t.Fatal(err)
		}

		// this should allow user1 to make pods in project2
		rbEditUser1Project2 := rbacv1helpers.NewRoleBindingForClusterRole("edit", project2).Users(user1).BindingOrDie()
		if _, err := clusterAdminKubeClientset.RbacV1().RoleBindings(project2).Create(ctx, &rbEditUser1Project2, createOpts); err != nil {
			t.Fatal(err)
		}

		// this should allow user2 to make pods in project1
		rbEditUser2Project1 := rbacv1helpers.NewRoleBindingForClusterRole("edit", project1).Users(user2).BindingOrDie()
		if _, err := clusterAdminKubeClientset.RbacV1().RoleBindings(project1).Create(ctx, &rbEditUser2Project1, createOpts); err != nil {
			t.Fatal(err)
		}

		// this should allow user2 to make a privileged pod in all projects
		crb := rbacv1helpers.NewClusterBinding(clusterRole).Users(user2).BindingOrDie()
		if _, err := clusterAdminKubeClientset.RbacV1().ClusterRoleBindings().Create(ctx, &crb, createOpts); err != nil {
			t.Fatal(err)
		}
		oc.AddExplicitResourceToDelete(rbacv1.SchemeGroupVersion.WithResource("clusterrolebindings"), "", crb.Name)

		// wait for RBAC to catch up to user1 role binding for SCC
		if err := oc.WaitForAccessAllowed(&kubeauthorizationv1.SelfSubjectAccessReview{
			Spec: kubeauthorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &kubeauthorizationv1.ResourceAttributes{
					Namespace: project1,
					Verb:      rule.Verbs[0],
					Group:     rule.APIGroups[0],
					Resource:  rule.Resources[0],
				},
			},
		}, user1); err != nil {
			t.Fatal(err)
		}

		// wait for RBAC to catch up to user1 role binding for edit
		if err := oc.WaitForAccessAllowed(&kubeauthorizationv1.SelfSubjectAccessReview{
			Spec: kubeauthorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &kubeauthorizationv1.ResourceAttributes{
					Namespace: project2,
					Verb:      "create",
					Group:     "",
					Resource:  "pods",
				},
			},
		}, user1); err != nil {
			t.Fatal(err)
		}

		// wait for RBAC to catch up to user2 role binding
		if err := oc.WaitForAccessAllowed(&kubeauthorizationv1.SelfSubjectAccessReview{
			Spec: kubeauthorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &kubeauthorizationv1.ResourceAttributes{
					Namespace: project1,
					Verb:      "create",
					Group:     "",
					Resource:  "pods",
				},
			},
		}, user2); err != nil {
			t.Fatal(err)
		}

		// wait for RBAC to catch up to user2 cluster role binding
		if err := oc.WaitForAccessAllowed(&kubeauthorizationv1.SelfSubjectAccessReview{
			Spec: kubeauthorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &kubeauthorizationv1.ResourceAttributes{
					Namespace: project2,
					Verb:      rule.Verbs[0],
					Group:     rule.APIGroups[0],
					Resource:  rule.Resources[0],
				},
			},
		}, user2); err != nil {
			t.Fatal(err)
		}

		// user1 can make a privileged pod in project1
		if _, err := user1Client.CoreV1().Pods(project1).Create(ctx, getPrivilegedPod("test3"), createOpts); err != nil {
			t.Fatalf("user1 failed to create pod in project1 via local binding: %v", err)
		}

		// user1 cannot make a privileged pod in project2
		if _, err := user1Client.CoreV1().Pods(project2).Create(ctx, getPrivilegedPod("test4"), createOpts); !isForbiddenBySCC(err) {
			t.Fatalf("missing forbidden for user1 in project2: %v", err)
		}

		// user2 can make a privileged pod in project1
		if _, err := user2Client.CoreV1().Pods(project1).Create(ctx, getPrivilegedPod("test5"), createOpts); err != nil {
			t.Fatalf("user2 failed to create pod in project1 via cluster binding: %v", err)
		}

		// user2 can make a privileged pod in project2
		if _, err := user2Client.CoreV1().Pods(project2).Create(ctx, getPrivilegedPod("test6"), createOpts); err != nil {
			t.Fatalf("user2 failed to create pod in project2 via cluster binding: %v", err)
		}

		// make sure PSP self subject review works since that is based by the same SCC logic but has different wiring

		// user1 can make a privileged pod in project1
		user1PSPReview, err := user1SecurityClient.PodSecurityPolicySelfSubjectReviews(project1).Create(ctx, runAsRootPSPSSR(), createOpts)
		if err != nil {
			t.Fatal(err)
		}
		if allowedBy := user1PSPReview.Status.AllowedBy; allowedBy == nil || allowedBy.Name != "anyuid" {
			t.Fatalf("user1 failed PSP SSR in project1: %v", allowedBy)
		}

		// user2 can make a privileged pod in project2
		user2PSPReview, err := user2SecurityClient.PodSecurityPolicySelfSubjectReviews(project2).Create(ctx, runAsRootPSPSSR(), createOpts)
		if err != nil {
			t.Fatal(err)
		}
		if allowedBy := user2PSPReview.Status.AllowedBy; allowedBy == nil || allowedBy.Name != "anyuid" {
			t.Fatalf("user2 failed PSP SSR in project2: %v", allowedBy)
		}
	})

	g.It("TestAllowedSCCViaRBAC with service account [apigroup:security.openshift.io]", func() {
		t := g.GinkgoT()

		clusterAdminKubeClientset := oc.AdminKubeClient()

		newNamespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("%s-namespace-2", oc.Namespace()),
			},
		}
		_, err := oc.AdminKubeClient().CoreV1().Namespaces().Create(context.Background(), newNamespace, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		defer func() {
			oc.AdminKubeClient().CoreV1().Namespaces().Delete(context.Background(), newNamespace.Name, metav1.DeleteOptions{})
		}()

		project1 := oc.Namespace()
		project2 := newNamespace.Name

		sa1 := createServiceAccount(ctx, oc, project1)
		createPodAdminRoleOrDie(ctx, oc, sa1)
		createPodsecuritypolicyselfsubjectreviewsRoleBindingOrDie(ctx, oc, sa1)

		sa2 := createServiceAccount(ctx, oc, project2)
		createPodAdminRoleOrDie(ctx, oc, sa2)
		createPodsecuritypolicyselfsubjectreviewsRoleBindingOrDie(ctx, oc, sa2)

		clusterRole := "all-scc-" + oc.Namespace()
		rule := rbacv1helpers.NewRule("use").Groups("security.openshift.io").Resources("securitycontextconstraints").RuleOrDie()

		// set a up cluster role that allows access to all SCCs
		if _, err := clusterAdminKubeClientset.RbacV1().ClusterRoles().Create(
			ctx,
			&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: clusterRole},
				Rules:      []rbacv1.PolicyRule{rule},
			},
			metav1.CreateOptions{},
		); err != nil {
			t.Fatal(err)
		}
		oc.AddExplicitResourceToDelete(rbacv1.SchemeGroupVersion.WithResource("clusterroles"), "", clusterRole)

		// set up 2 projects for 2 users
		sa1Client, sa1SecurityClient := createClientFromServiceAccount(oc, sa1)
		sa2Client, sa2SecurityClient := createClientFromServiceAccount(oc, sa2)

		createOpts := metav1.CreateOptions{}

		// serviceaccount1 cannot make a privileged pod
		if _, err := sa1Client.CoreV1().Pods(project1).Create(ctx, getPrivilegedPod("test1"), createOpts); !isForbiddenBySCC(err) {
			t.Fatalf("missing forbidden for serviceaccount1: %v", err)
		}

		// serviceaccount2 cannot make a privileged pod
		if _, err := sa2Client.CoreV1().Pods(project2).Create(ctx, getPrivilegedPod("test2"), createOpts); !isForbiddenBySCC(err) {
			t.Fatalf("missing forbidden for serviceaccount2: %v", err)
		}

		// this should allow serviceaccount1 to make a privileged pod in project1
		rb := rbacv1helpers.NewRoleBindingForClusterRole(clusterRole, project1).SAs(project1, sa1.Name).BindingOrDie()
		if _, err := clusterAdminKubeClientset.RbacV1().RoleBindings(project1).Create(ctx, &rb, createOpts); err != nil {
			t.Fatal(err)
		}

		// this should allow serviceaccount1 to make pods in project2
		rbEditUser1Project2 := rbacv1helpers.NewRoleBindingForClusterRole("edit", project2).SAs(project1, sa1.Name).BindingOrDie()
		if _, err := clusterAdminKubeClientset.RbacV1().RoleBindings(project2).Create(ctx, &rbEditUser1Project2, createOpts); err != nil {
			t.Fatal(err)
		}

		// this should allow serviceaccount2 to make pods in project1
		rbEditUser2Project1 := rbacv1helpers.NewRoleBindingForClusterRole("edit", project1).SAs(project2, sa2.Name).BindingOrDie()
		if _, err := clusterAdminKubeClientset.RbacV1().RoleBindings(project1).Create(ctx, &rbEditUser2Project1, createOpts); err != nil {
			t.Fatal(err)
		}

		// this should allow serviceaccount2 to make a privileged pod in all projects
		crb := rbacv1helpers.NewClusterBinding(clusterRole).SAs(project2, sa2.Name).BindingOrDie()
		if _, err := clusterAdminKubeClientset.RbacV1().ClusterRoleBindings().Create(ctx, &crb, createOpts); err != nil {
			t.Fatal(err)
		}
		oc.AddExplicitResourceToDelete(rbacv1.SchemeGroupVersion.WithResource("clusterrolebindings"), "", crb.Name)

		// wait for RBAC to catch up to serviceaccount1 role binding for SCC
		if err := exutil.WaitForAccess(sa1Client, true, &kubeauthorizationv1.SelfSubjectAccessReview{
			Spec: kubeauthorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &kubeauthorizationv1.ResourceAttributes{
					Namespace: project1,
					Verb:      rule.Verbs[0],
					Group:     rule.APIGroups[0],
					Resource:  rule.Resources[0],
				},
			},
		}); err != nil {
			t.Fatal(err)
		}

		// wait for RBAC to catch up to serviceaccount1 role binding for edit
		if err := exutil.WaitForAccess(sa1Client, true, &kubeauthorizationv1.SelfSubjectAccessReview{
			Spec: kubeauthorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &kubeauthorizationv1.ResourceAttributes{
					Namespace: project2,
					Verb:      "create",
					Group:     "",
					Resource:  "pods",
				},
			},
		}); err != nil {
			t.Fatal(err)
		}

		// wait for RBAC to catch up to serviceaccount2 role binding
		if err := exutil.WaitForAccess(sa2Client, true, &kubeauthorizationv1.SelfSubjectAccessReview{
			Spec: kubeauthorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &kubeauthorizationv1.ResourceAttributes{
					Namespace: project1,
					Verb:      "create",
					Group:     "",
					Resource:  "pods",
				},
			},
		}); err != nil {
			t.Fatal(err)
		}

		// wait for RBAC to catch up to serviceaccount2 cluster role binding
		if err := exutil.WaitForAccess(sa2Client, true, &kubeauthorizationv1.SelfSubjectAccessReview{
			Spec: kubeauthorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &kubeauthorizationv1.ResourceAttributes{
					Namespace: project2,
					Verb:      rule.Verbs[0],
					Group:     rule.APIGroups[0],
					Resource:  rule.Resources[0],
				},
			},
		}); err != nil {
			t.Fatal(err)
		}

		// serviceaccount1 can make a privileged pod in project1
		if _, err := sa1Client.CoreV1().Pods(project1).Create(ctx, getPrivilegedPod("test3"), createOpts); err != nil {
			t.Fatalf("serviceaccount1 failed to create pod in project1 via local binding: %v", err)
		}

		// serviceaccount1 cannot make a privileged pod in project2
		if _, err := sa1Client.CoreV1().Pods(project2).Create(ctx, getPrivilegedPod("test4"), createOpts); !isForbiddenBySCC(err) {
			t.Fatalf("missing forbidden for serviceaccount1 in project2: %v", err)
		}

		// serviceaccount2 can make a privileged pod in project1
		if _, err := sa2Client.CoreV1().Pods(project1).Create(ctx, getPrivilegedPod("test5"), createOpts); err != nil {
			t.Fatalf("serviceaccount2 failed to create pod in project1 via cluster binding: %v", err)
		}

		// serviceaccount2 can make a privileged pod in project2
		if _, err := sa2Client.CoreV1().Pods(project2).Create(ctx, getPrivilegedPod("test6"), createOpts); err != nil {
			t.Fatalf("serviceaccount2 failed to create pod in project2 via cluster binding: %v", err)
		}

		// make sure PSP self subject review works since that is based by the same SCC logic but has different wiring

		framework.Logf("All good so far")
		// serviceaccount1 can make a privileged pod in project1
		serviceaccount1PSPReview, err := sa1SecurityClient.PodSecurityPolicySelfSubjectReviews(project1).Create(ctx, runAsRootPSPSSR(), createOpts)
		if err != nil {
			t.Fatal(err)
		}
		if allowedBy := serviceaccount1PSPReview.Status.AllowedBy; allowedBy == nil || allowedBy.Name != "anyuid" {
			t.Fatalf("serviceaccount1 failed PSP SSR in project1: %v", allowedBy)
		}

		// serviceaccount2 can make a privileged pod in project2
		serviceaccount2PSPReview, err := sa2SecurityClient.PodSecurityPolicySelfSubjectReviews(project2).Create(ctx, runAsRootPSPSSR(), createOpts)
		if err != nil {
			t.Fatal(err)
		}
		if allowedBy := serviceaccount2PSPReview.Status.AllowedBy; allowedBy == nil || allowedBy.Name != "anyuid" {
			t.Fatalf("serviceaccount2 failed PSP SSR in project2: %v", allowedBy)
		}
	})
})

var _ = g.Describe("[sig-auth][Feature:SecurityContextConstraints] ", func() {
	defer g.GinkgoRecover()
	oc := exutil.NewCLIWithPodSecurityLevel("ssc", admissionapi.LevelBaseline)

	g.It("TestPodDefaultCapabilities", func() {
		g.By("Running a restricted pod and getting it's inherited capabilities")
		pod, err := exutil.NewPodExecutor(oc, "restrictedcapsh", image.ShellImage())
		o.Expect(err).NotTo(o.HaveOccurred())

		// TODO: remove desiredCapabilities once restricted-v2 is the default
		// system:authenticated SCC in the cluster - in favour of alternativeDesiredCapabilities
		desiredCapabilities := "000000000000051b"
		alternativeDesiredCapabilities := "0000000000000000"

		capabilities, err := pod.Exec("cat /proc/1/status | grep CapBnd | cut -f 2")
		o.Expect(err).NotTo(o.HaveOccurred())

		capString, err := pod.Exec("capsh --decode=" + capabilities)
		o.Expect(err).NotTo(o.HaveOccurred())

		desiredCapString, err := pod.Exec("capsh --decode=" + desiredCapabilities)
		o.Expect(err).NotTo(o.HaveOccurred())

		alternativeDesiredCapString, err := pod.Exec("capsh --decode=" + alternativeDesiredCapabilities)
		o.Expect(err).NotTo(o.HaveOccurred())

		framework.Logf("comparing capabilities: %s with desired: %s or more restricitve desired: %s", capabilities, desiredCapabilities, alternativeDesiredCapabilities)
		framework.Logf("which translates to: %s compared with desired: %s or more restrictive desired %s", capString, desiredCapString, alternativeDesiredCapString)
		o.Expect(capabilities).To(o.Or(o.Equal(desiredCapabilities), o.Equal(alternativeDesiredCapabilities)))
	})
})

func isForbiddenBySCC(err error) bool {
	return kapierror.IsForbidden(err) && strings.Contains(err.Error(), "unable to validate against any security context constraint")
}

func isForbiddenBySCCExecRestrictions(err error) bool {
	return kapierror.IsForbidden(err) && strings.Contains(err.Error(), "pod's security context exceeds your permissions")
}

func getPrivilegedPod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PodSpec{
			NodeSelector: map[string]string{
				"e2e.openshift.io/unschedulable": "should-not-run",
			},
			Containers: []corev1.Container{
				{Name: "first", Image: "something-innocuous"},
			},
			HostPID: true,
		},
	}
}

func runAsRootPSPSSR() *securityv1.PodSecurityPolicySelfSubjectReview {
	return &securityv1.PodSecurityPolicySelfSubjectReview{
		Spec: securityv1.PodSecurityPolicySelfSubjectReviewSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "fake",
							Image: "fake",
							SecurityContext: &corev1.SecurityContext{
								RunAsUser: new(int64), // root
							},
						},
					},
				},
			},
		},
	}
}

func createPodAdminRoleOrDie(ctx context.Context, oc *exutil.CLI, sa *corev1.ServiceAccount) {
	framework.Logf("Creating role")
	rule := rbacv1helpers.NewRule("create", "update").Groups("").Resources("pods", "pods/exec").RuleOrDie()
	_, err := oc.AdminKubeClient().RbacV1().Roles(sa.Namespace).Create(
		ctx,
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "podadmin"},
			Rules:      []rbacv1.PolicyRule{rule},
		},
		metav1.CreateOptions{},
	)
	o.Expect(err).NotTo(o.HaveOccurred())

	framework.Logf("Creating rolebinding")
	_, err = oc.AdminKubeClient().RbacV1().RoleBindings(sa.Namespace).Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    sa.Namespace,
			GenerateName: "podadmin-",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "ServiceAccount",
				Name: sa.Name,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: "podadmin",
		},
	}, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
}

func createServiceAccount(ctx context.Context, oc *exutil.CLI, namespace string) *corev1.ServiceAccount {
	framework.Logf("Creating ServiceAccount")
	sa, err := oc.AdminKubeClient().CoreV1().ServiceAccounts(namespace).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{GenerateName: "test-sa-"}}, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Errorf("unexpected error: %v", err))
	}

	framework.Logf("Waiting for ServiceAccount %q to be provisioned...", sa.Name)
	err = exutil.WaitForServiceAccountWithSecret(oc.AdminKubeClient().CoreV1().ServiceAccounts(namespace), sa.Name)
	o.Expect(err).NotTo(o.HaveOccurred())

	return sa
}

func createPodsecuritypolicyselfsubjectreviewsRoleBindingOrDie(ctx context.Context, oc *exutil.CLI, sa *corev1.ServiceAccount) {
	framework.Logf("Creating pspssr role")
	rule := rbacv1helpers.NewRule("create").Groups("security.openshift.io").Resources("podsecuritypolicyselfsubjectreviews").RuleOrDie()
	_, err := oc.AdminKubeClient().RbacV1().Roles(sa.Namespace).Create(
		ctx,
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "pspssr"},
			Rules:      []rbacv1.PolicyRule{rule},
		},
		metav1.CreateOptions{},
	)
	o.Expect(err).NotTo(o.HaveOccurred())

	framework.Logf("Creating pspssr rolebinding")
	_, err = oc.AdminKubeClient().RbacV1().RoleBindings(sa.Namespace).Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    sa.Namespace,
			GenerateName: "podadmin-",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "ServiceAccount",
				Name: sa.Name,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: "pspssr",
		},
	}, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
}

func createClientFromServiceAccount(oc *exutil.CLI, sa *corev1.ServiceAccount) (*kubernetes.Clientset, *securityv1client.SecurityV1Client) {
	// create a new token request for the service account and use it to build a client for it
	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: []string{"https://kubernetes.default.svc"},
		},
	}
	framework.Logf("Creating service account token")
	bootstrapperToken, err := oc.AdminKubeClient().CoreV1().ServiceAccounts(sa.Namespace).CreateToken(context.TODO(), sa.Name, tokenRequest, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	saClientConfig := restclient.AnonymousClientConfig(oc.AdminConfig())
	saClientConfig.BearerToken = bootstrapperToken.Status.Token

	return kubernetes.NewForConfigOrDie(saClientConfig), securityv1client.NewForConfigOrDie(saClientConfig)
}
