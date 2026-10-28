package inventory

import (
	"bytes"
	"cmp"
	"fmt"
	"io"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/yaml"
)

// Source is where an object of a manifest came from: the file and the
// first line of its YAML document. Output of helm template names the
// template in a "# Source:" comment; that template is the file then.
type Source struct {
	File string
	Line int
}

// Manifests builds a snapshot from manifests instead of the cluster, for
// checks before a rollout. Objects without a namespace get namespace.
type Manifests struct {
	Snapshot
	// Sources maps "Kind/namespace/name" of each object to where it is defined.
	Sources map[string]Source
	// Skipped lists kinds that are not checked, e.g. custom resources.
	Skipped []string

	namespace string
}

func NewManifests(namespace string) *Manifests {
	return &Manifests{Sources: map[string]Source{}, namespace: cmp.Or(namespace, "default")}
}

// SourceKey is the key of Sources.
func SourceKey(kind, namespace, name string) string {
	return kind + "/" + namespace + "/" + name
}

// Read adds the objects of a YAML or JSON stream: several documents,
// separated by "---", and kind List are allowed.
func (m *Manifests) Read(r io.Reader, file string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read %s: %w", file, err)
	}
	for _, d := range splitDocs(data) {
		src := Source{file, d.line}
		if tmpl := helmSource(d.text); tmpl != "" {
			src = Source{tmpl, 1}
		}
		js, err := yaml.YAMLToJSON(d.text)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", file, d.line, err)
		}
		if t := bytes.TrimSpace(js); len(t) == 0 || string(t) == "null" {
			continue
		}
		if err := m.add(js, src); err != nil {
			return fmt.Errorf("%s:%d: %w", file, d.line, err)
		}
	}
	return nil
}

type document struct {
	text []byte
	line int // first line, from 1
}

// splitDocs splits YAML at "---" lines.
func splitDocs(data []byte) []document {
	var docs []document
	start, line := 1, 0
	var cur []byte
	for l := range bytes.Lines(data) {
		line++
		if t := bytes.TrimRight(l, " \t\r\n"); bytes.Equal(t, []byte("---")) || bytes.HasPrefix(t, []byte("--- ")) {
			docs = append(docs, document{cur, start})
			cur, start = nil, line+1
			continue
		}
		cur = append(cur, l...)
	}
	return append(docs, document{cur, start})
}

// helmSource returns the template named by "# Source: chart/templates/x.yaml".
func helmSource(doc []byte) string {
	for l := range bytes.Lines(doc) {
		if v, ok := bytes.CutPrefix(bytes.TrimSpace(l), []byte("# Source: ")); ok {
			return string(bytes.TrimSpace(v))
		}
	}
	return ""
}

func (m *Manifests) add(data []byte, src Source) error {
	obj, gvk, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
	if err != nil {
		if runtime.IsNotRegisteredError(err) && gvk != nil {
			m.skip(gvk.Kind)
			return nil
		}
		return err
	}
	if list, ok := obj.(*corev1.List); ok {
		for _, item := range list.Items {
			if err := m.add(item.Raw, src); err != nil {
				return err
			}
		}
		return nil
	}
	m.addObject(obj, src)
	return nil
}

func (m *Manifests) skip(kind string) {
	if !slices.Contains(m.Skipped, kind) {
		m.Skipped = append(m.Skipped, kind)
	}
}

// meta fills the namespace and a stable UID, and records the source.
func (m *Manifests) meta(kind string, om *metav1.ObjectMeta, namespaced bool, src Source) {
	if namespaced {
		om.Namespace = cmp.Or(om.Namespace, m.namespace)
	} else {
		om.Namespace = ""
	}
	key := SourceKey(kind, om.Namespace, om.Name)
	om.UID = types.UID("manifest:" + key)
	m.Sources[key] = src
}

func (m *Manifests) addObject(obj runtime.Object, src Source) {
	switch o := obj.(type) {
	case *corev1.Pod:
		m.meta("Pod", &o.ObjectMeta, true, src)
		m.Pods = append(m.Pods, *o)
	case *appsv1.Deployment:
		m.workload("Deployment", o.ObjectMeta, o.Spec.Template, src)
	case *appsv1.StatefulSet:
		m.workload("StatefulSet", o.ObjectMeta, o.Spec.Template, src)
	case *appsv1.DaemonSet:
		m.workload("DaemonSet", o.ObjectMeta, o.Spec.Template, src)
	case *appsv1.ReplicaSet:
		m.workload("ReplicaSet", o.ObjectMeta, o.Spec.Template, src)
	case *batchv1.Job:
		m.workload("Job", o.ObjectMeta, o.Spec.Template, src)
	case *batchv1.CronJob:
		m.workload("CronJob", o.ObjectMeta, o.Spec.JobTemplate.Spec.Template, src)
	case *corev1.ServiceAccount:
		m.meta("ServiceAccount", &o.ObjectMeta, true, src)
		m.ServiceAccounts = append(m.ServiceAccounts, *o)
	case *corev1.Service:
		m.meta("Service", &o.ObjectMeta, true, src)
		m.Services = append(m.Services, *o)
	case *networkingv1.Ingress:
		m.meta("Ingress", &o.ObjectMeta, true, src)
		m.Ingresses = append(m.Ingresses, *o)
	case *networkingv1.NetworkPolicy:
		m.meta("NetworkPolicy", &o.ObjectMeta, true, src)
		m.NetworkPolicies = append(m.NetworkPolicies, *o)
	case *rbacv1.Role:
		m.meta("Role", &o.ObjectMeta, true, src)
		m.Roles = append(m.Roles, *o)
	case *rbacv1.RoleBinding:
		m.meta("RoleBinding", &o.ObjectMeta, true, src)
		m.RoleBindings = append(m.RoleBindings, *o)
	case *rbacv1.ClusterRole:
		m.meta("ClusterRole", &o.ObjectMeta, false, src)
		m.ClusterRoles = append(m.ClusterRoles, *o)
	case *rbacv1.ClusterRoleBinding:
		m.meta("ClusterRoleBinding", &o.ObjectMeta, false, src)
		m.ClusterRoleBindings = append(m.ClusterRoleBindings, *o)
	case *corev1.Namespace:
		m.Sources[SourceKey("Namespace", "", o.Name)] = src
	case *corev1.ConfigMap, *corev1.Secret, *corev1.PersistentVolumeClaim, *corev1.LimitRange, *corev1.ResourceQuota,
		*policyv1.PodDisruptionBudget, *autoscalingv2.HorizontalPodAutoscaler, *autoscalingv1.HorizontalPodAutoscaler:
		// Not graph nodes and nothing to check: Secrets are derived from pod references.
	default:
		kinds, _, err := scheme.Scheme.ObjectKinds(obj)
		if err == nil && len(kinds) > 0 {
			m.skip(kinds[0].Kind)
		}
	}
}

// workload turns a controller into the pod of its template, owned by the
// controller, so Workload names it as in the cluster.
func (m *Manifests) workload(kind string, om metav1.ObjectMeta, tmpl corev1.PodTemplateSpec, src Source) {
	m.meta(kind, &om, true, src)
	pod := corev1.Pod{ObjectMeta: tmpl.ObjectMeta, Spec: tmpl.Spec}
	pod.Name, pod.Namespace = om.Name, om.Namespace
	pod.UID = types.UID("manifest:pod:" + kind + "/" + om.Namespace + "/" + om.Name)
	controller := true
	pod.OwnerReferences = []metav1.OwnerReference{{Kind: kind, Name: om.Name, UID: om.UID, Controller: &controller}}
	m.Pods = append(m.Pods, pod)
}

// builtinClusterRoles are the roles every cluster has, by name.
var builtinClusterRoles = map[string][]rbacv1.PolicyRule{
	"cluster-admin": {
		{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
		{NonResourceURLs: []string{"*"}, Verbs: []string{"*"}},
	},
}

// Finish adds what every cluster has and manifests do not define: the
// default ServiceAccount of each namespace and the built-in ClusterRoles
// that bindings refer to. exclude drops namespaces as in Collect.
func (m *Manifests) Finish(exclude []string) *Snapshot {
	sas := map[string]bool{}
	for _, sa := range m.ServiceAccounts {
		sas[sa.Namespace+"/"+sa.Name] = true
	}
	for _, pod := range m.Pods {
		name := cmp.Or(pod.Spec.ServiceAccountName, "default")
		if key := pod.Namespace + "/" + name; name == "default" && !sas[key] {
			sas[key] = true
			m.ServiceAccounts = append(m.ServiceAccounts, corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: pod.Namespace, UID: types.UID("manifest:" + SourceKey("ServiceAccount", pod.Namespace, name)),
			}})
		}
	}
	roles := map[string]bool{}
	for _, r := range m.ClusterRoles {
		roles[r.Name] = true
	}
	refs := func(ref rbacv1.RoleRef) {
		rules, ok := builtinClusterRoles[ref.Name]
		if ref.Kind != "ClusterRole" || !ok || roles[ref.Name] {
			return
		}
		roles[ref.Name] = true
		m.ClusterRoles = append(m.ClusterRoles, rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: ref.Name, UID: types.UID("manifest:builtin:" + ref.Name)},
			Rules:      rules,
		})
	}
	for _, b := range m.ClusterRoleBindings {
		refs(b.RoleRef)
	}
	for _, b := range m.RoleBindings {
		refs(b.RoleRef)
	}
	s := m.Snapshot
	s.exclude(exclude)
	return &s
}
