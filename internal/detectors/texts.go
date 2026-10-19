package detectors

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Texts are the parts of a finding meant for people.
type Texts struct {
	Title, Description, Remediation, Recommendation string
	AttackPath                                      []string
}

// Texts of the finding as the detector produced them, in English.
func (f Finding) Texts() Texts {
	return Texts{Title: f.Title, Description: f.Description, Remediation: f.Remediation, Recommendation: f.Recommendation, AttackPath: f.AttackPath}
}

// In returns the finding with its texts in lang.
func (f Finding) In(lang string) Finding {
	t := Localize(lang, f.Detector, f.Texts())
	f.Title, f.Description, f.Remediation, f.Recommendation, f.AttackPath = t.Title, t.Description, t.Remediation, t.Recommendation, t.AttackPath
	return f
}

// Localize translates the English texts of a finding of detector into lang.
// Translation happens on display, so findings stored by earlier scans are
// translated too: values from the cluster are recovered from the English
// text by its format and put into the format of lang as they are. A text
// that does not match its format, e.g. from an older version, stays as is.
func Localize(lang, detector string, t Texts) Texts {
	if lang == "en" || texts[lang] == nil {
		return t
	}
	out := Texts{
		Title:          translate(lang, detector+".title", t.Title),
		Description:    translateDesc(lang, detector, t.Description),
		Remediation:    translate(lang, detector+".fix", t.Remediation),
		Recommendation: translate(lang, detector+".rec", t.Recommendation),
	}
	for _, step := range t.AttackPath {
		for _, key := range pathKeys {
			if s, ok := translateOK(lang, key, step); ok {
				step = s
				break
			}
		}
		out.AttackPath = append(out.AttackPath, step)
	}
	return out
}

// en formats a text of the English catalog; detectors build their texts with it.
func en(key string, args ...any) string {
	return fmtText("en", key, args...)
}

// translateDesc translates a description; a detector may have variants of
// it under the keys with the suffixes "descfix" and "descmany".
func translateDesc(lang, detector, s string) string {
	for _, v := range []string{".descfix", ".descmany"} {
		if out, ok := translateOK(lang, detector+v, s); ok {
			return out
		}
	}
	return translate(lang, detector+".desc", s)
}

func translate(lang, key, s string) string {
	out, _ := translateOK(lang, key, s)
	return out
}

func translateOK(lang, key, s string) (string, bool) {
	p, ok := parsers[key]
	if !ok {
		return s, false
	}
	m := p.re.FindStringSubmatch(s)
	if m == nil {
		return s, false
	}
	args := make([]any, len(p.verbs))
	for i, v := range p.verbs {
		args[i] = m[i+1]
		if v == 'd' {
			n, err := strconv.Atoi(m[i+1])
			if err != nil {
				return s, false
			}
			args[i] = n
		}
	}
	// A value that contains a separator of the format can be split
	// differently; accept only a parse that gives back the same text.
	if en(key, args...) != s {
		return s, false
	}
	return fmtText(lang, key, args...), true
}

func fmtText(lang, key string, args ...any) string {
	return fmt.Sprintf(texts[lang][key], args...)
}

type parser struct {
	re    *regexp.Regexp
	verbs []byte
}

// parsers match the English texts: %s matches any text, %d a number.
var parsers = func() map[string]parser {
	m := map[string]parser{}
	for key, format := range texts["en"] {
		var re strings.Builder
		var verbs []byte
		re.WriteString("^")
		for {
			i := strings.IndexByte(format, '%')
			if i < 0 || i+1 >= len(format) {
				re.WriteString(regexp.QuoteMeta(format))
				break
			}
			re.WriteString(regexp.QuoteMeta(format[:i]))
			switch v := format[i+1]; v {
			case 's':
				re.WriteString("(.*?)")
				verbs = append(verbs, v)
			case 'd':
				re.WriteString(`(-?\d+)`)
				verbs = append(verbs, v)
			default:
				panic(fmt.Sprintf("detector text %s: unsupported verb %%%c", key, v))
			}
			format = format[i+2:]
		}
		re.WriteString("$")
		m[key] = parser{regexp.MustCompile(re.String()), verbs}
	}
	return m
}()

// pathKeys are the attack path steps with words of ours. Steps that are
// names from the cluster or Kubernetes terms ("Service: web") stay as they are.
var pathKeys = []string{"path.internet", "path.node", "path.nodefs", "path.privileged", "path.anypod",
	"path.traffic", "path.registry", "path.hostns", "path.mutable", "path.cves"}

// texts per language. English formats are what detectors produce and what
// earlier scans stored; other languages give the same values, by position
// or as %[n]s, in their own order.
var texts = map[string]map[string]string{
	"en": {
		"cluster-admin-sa.title": "Workload Running with Cluster-Admin ServiceAccount",
		"cluster-admin-sa.desc":  "%s in namespace %s uses ServiceAccount %s bound to %s",
		"cluster-admin-sa.fix":   "Remove cluster-admin from ServiceAccount %s/%s",
		"cluster-admin-sa.rec":   "Bind ServiceAccount to minimal role. Remove ClusterRoleBinding with cluster-admin.",

		"exposed-secret.title": "Secret Mounted in Internet-Exposed Workload",
		"exposed-secret.desc":  "Secret %s mounted in %s/%s exposed via %s",
		"exposed-secret.fix":   "Move secret to external vault or remove internet exposure",
		"exposed-secret.rec":   "Remove Secret mount from internet-exposed pod or apply NetworkPolicy.",

		"exposed-cve.title":   "Internet-Exposed Workload with Known CVE",
		"exposed-cve.desc":    "%s/%s has %d CVEs, top: %s",
		"exposed-cve.descfix": "%s/%s has %d CVEs, top: %s; fixed in %s",
		"exposed-cve.fix":     "Patch the vulnerability or remove internet exposure",
		"exposed-cve.rec":     "Update container image to version with patched CVE. Apply NetworkPolicy.",

		"privileged-container.title": "Privileged Container",
		"privileged-container.desc":  "%s runs privileged containers: %s",
		"privileged-container.fix":   "Remove securityContext.privileged and the SYS_ADMIN capability; grant only the specific capabilities needed",
		"privileged-container.rec":   "Run containers unprivileged: drop privileged and SYS_ADMIN, set allowPrivilegeEscalation: false.",

		"host-namespaces.title": "Pod Shares Host Namespaces",
		"host-namespaces.desc":  "%s uses %s",
		"host-namespaces.fix":   "Remove %s from the pod spec",
		"host-namespaces.rec":   "Do not share the node's network, PID or IPC namespaces with pods.",

		"host-path.title": "hostPath Volume",
		"host-path.desc":  "%s mounts node path %s",
		"host-path.fix":   "Stop mounting %s from the node",
		"host-path.rec":   "Replace hostPath with emptyDir, a PersistentVolume or a ConfigMap.",

		"no-network-policy.title": "Namespace Without NetworkPolicy",
		"no-network-policy.desc":  "Namespace %s: %d workloads (%d pods) are not selected by any NetworkPolicy",
		"no-network-policy.fix":   "Create a default-deny NetworkPolicy in namespace %s",
		"no-network-policy.rec":   "Add a default-deny NetworkPolicy and allow only the traffic each workload needs.",

		"latest-tag.title": "Image Without Pinned Version",
		"latest-tag.desc":  "%s uses unpinned images: %s",
		"latest-tag.fix":   "Reference images by version tag and digest (image:1.2.3@sha256:...)",
		"latest-tag.rec":   "Pin images to a version tag or, better, a digest.",

		"wildcard-rbac.title": "Workload Running with Wildcard RBAC Role",
		"wildcard-rbac.desc":  `%s/%s uses ServiceAccount %s bound to %s %s with "*" in %s (%s scope)`,
		"wildcard-rbac.fix":   `Replace "*" in %s %s with an explicit list of permissions`,
		"wildcard-rbac.rec":   `List the exact verbs, resources and apiGroups the workload needs instead of "*".`,

		"attack-path.title":    "Attack Path from the Internet to %s",
		"attack-path.desc":     "%s/%s leads to %s in %d steps, risk score %d",
		"attack-path.descmany": "%s/%s can read %d Secrets through the rights of %s, risk score %d",
		"attack-path.fix":      "Break the path at any step: close the exposure, remove the token or the right that links the steps",
		"attack-path.rec":      "Remove the exposure or a privilege on the path; each removed step lowers the score.",

		"path.internet":   "Internet",
		"path.node":       "Node",
		"path.nodefs":     "Node filesystem",
		"path.privileged": "Privileged container",
		"path.anypod":     "Any pod in the cluster",
		"path.traffic":    "Unrestricted pod traffic",
		"path.registry":   "Registry",
		"path.hostns":     "Host namespace: %s",
		"path.mutable":    "Mutable tag: %s",
		"path.cves":       "%d CVEs (CRITICAL/HIGH)",
	},
	"ru": {
		"cluster-admin-sa.title": "Рабочая нагрузка с ServiceAccount уровня cluster-admin",
		"cluster-admin-sa.desc":  "%s в namespace %s использует ServiceAccount %s, привязанный к %s",
		"cluster-admin-sa.fix":   "Отзовите cluster-admin у ServiceAccount %s/%s",
		"cluster-admin-sa.rec":   "Привяжите ServiceAccount к роли с минимальными правами. Удалите ClusterRoleBinding на cluster-admin.",

		"exposed-secret.title": "Secret смонтирован в рабочую нагрузку, доступную из интернета",
		"exposed-secret.desc":  "Secret %s смонтирован в %s/%s, доступную через %s",
		"exposed-secret.fix":   "Перенесите секрет во внешнее хранилище или закройте доступ из интернета",
		"exposed-secret.rec":   "Уберите монтирование Secret из пода, доступного из интернета, или ограничьте доступ NetworkPolicy.",

		"exposed-cve.title":   "Доступная из интернета рабочая нагрузка с известными CVE",
		"exposed-cve.desc":    "%s/%s: уязвимостей CVE — %d, наиболее опасные: %s",
		"exposed-cve.descfix": "%s/%s: уязвимостей CVE — %d, наиболее опасные: %s; исправлено в %s",
		"exposed-cve.fix":     "Устраните уязвимость или закройте доступ из интернета",
		"exposed-cve.rec":     "Обновите образ контейнера до версии с исправленными CVE. Ограничьте доступ NetworkPolicy.",

		"privileged-container.title": "Привилегированный контейнер",
		"privileged-container.desc":  "%s запускает привилегированные контейнеры: %s",
		"privileged-container.fix":   "Уберите securityContext.privileged и capability SYS_ADMIN; выдайте только те capabilities, которые действительно нужны",
		"privileged-container.rec":   "Запускайте контейнеры без привилегий: уберите privileged и SYS_ADMIN, задайте allowPrivilegeEscalation: false.",

		"host-namespaces.title": "Под использует пространства имён узла",
		"host-namespaces.desc":  "%s использует %s",
		"host-namespaces.fix":   "Уберите %s из спецификации пода",
		"host-namespaces.rec":   "Не предоставляйте подам сетевое, PID- и IPC-пространства имён узла.",

		"host-path.title": "Том hostPath",
		"host-path.desc":  "%s монтирует путь узла %s",
		"host-path.fix":   "Не монтируйте %s с узла",
		"host-path.rec":   "Замените hostPath на emptyDir, PersistentVolume или ConfigMap.",

		"no-network-policy.title": "Namespace без NetworkPolicy",
		"no-network-policy.desc":  "Namespace %s: рабочих нагрузок без NetworkPolicy — %d (подов — %d)",
		"no-network-policy.fix":   "Создайте NetworkPolicy default-deny в namespace %s",
		"no-network-policy.rec":   "Добавьте NetworkPolicy default-deny и разрешите только трафик, необходимый каждой рабочей нагрузке.",

		"latest-tag.title": "Образ без зафиксированной версии",
		"latest-tag.desc":  "%s использует образы без зафиксированной версии: %s",
		"latest-tag.fix":   "Указывайте образы по тегу версии и digest (image:1.2.3@sha256:...)",
		"latest-tag.rec":   "Фиксируйте образы по тегу версии, а лучше — по digest.",

		"wildcard-rbac.title": "Рабочая нагрузка с ролью RBAC, содержащей «*»",
		"wildcard-rbac.desc":  "%s/%s использует ServiceAccount %s, привязанный к %s %s с «*» в %s (область: %s)",
		"wildcard-rbac.fix":   "Замените «*» в %s %s явным списком прав",
		"wildcard-rbac.rec":   "Перечислите точные verbs, resources и apiGroups, нужные рабочей нагрузке, вместо «*».",

		"attack-path.title":    "Путь атаки из интернета до %s",
		"attack-path.desc":     "%s/%s ведёт к %s, шагов: %d, оценка риска: %d",
		"attack-path.descmany": "%s/%s может читать Secret (%d шт.) через права %s, оценка риска: %d",
		"attack-path.fix":      "Разорвите путь на любом шаге: закройте доступ из интернета, уберите токен или право, связывающее шаги",
		"attack-path.rec":      "Закройте доступ из интернета или уберите привилегию на пути: каждый убранный шаг снижает оценку.",

		"path.internet":   "Интернет",
		"path.node":       "Узел",
		"path.nodefs":     "Файловая система узла",
		"path.privileged": "Привилегированный контейнер",
		"path.anypod":     "Любой под кластера",
		"path.traffic":    "Неограниченный трафик подов",
		"path.registry":   "Реестр образов",
		"path.hostns":     "Пространства имён узла: %s",
		"path.mutable":    "Изменяемый тег: %s",
		"path.cves":       "CVE (CRITICAL/HIGH): %d",
	},
}

// Plain explains a finding of detector in lang to a developer without a
// security background: why it is dangerous and what to do, one sentence
// each. Unknown languages fall back to English, unknown detectors to "".
func Plain(lang, detector string) (why, do string) {
	t, ok := plain[lang]
	if !ok {
		t = plain["en"]
	}
	p := t[detector]
	return p[0], p[1]
}

// plain holds the why and do texts of Plain per language and detector.
var plain = map[string]map[string][2]string{
	"en": {
		"cluster-admin-sa": {
			"Anyone who breaks into this application gets full control of the whole cluster: every application, every secret.",
			"Give the application's ServiceAccount a role with only the rights it uses, and remove its cluster-admin binding.",
		},
		"exposed-secret": {
			"The application is reachable from the Internet and holds passwords or keys: one bug in it hands them to an attacker.",
			"Close the Internet access if it is not needed, or keep the secret out of this application.",
		},
		"exposed-cve": {
			"The application is reachable from the Internet and its image has known vulnerabilities, often with ready-made exploits.",
			"Rebuild the image on the version where the vulnerabilities are fixed and redeploy.",
		},
		"privileged-container": {
			"A privileged container is effectively root on the node: whoever breaks into it controls the node and its other pods.",
			"Remove privileged: true from the container; if it needs one capability, grant only that one.",
		},
		"host-namespaces": {
			"The pod sees the node's network or processes, so a break-in spreads beyond the container to the node.",
			"Remove hostNetwork, hostPID and hostIPC from the pod unless it is a node agent by design.",
		},
		"host-path": {
			"The pod mounts files of the node: through them a break-in reads other pods' data or takes over the node.",
			"Use emptyDir, a PersistentVolume or a ConfigMap instead of the node's directory.",
		},
		"no-network-policy": {
			"Any pod in the cluster can connect to these applications, so one compromised pod reaches all of them.",
			"Add a NetworkPolicy that denies all traffic by default and allows only what the applications need.",
		},
		"latest-tag": {
			"Without a fixed version, a restart may silently run a different or tampered image.",
			"Set an exact image version, ideally with its digest (image:1.2.3@sha256:...).",
		},
		"wildcard-rbac": {
			"A role with \"*\" grants every action, including future ones: a break-in can do far more than the application needs.",
			"List in the role only the actions and resources the application really uses.",
		},
		"attack-path": {
			"There is a chain of settings by which an attacker from the Internet reaches an important target in the cluster.",
			"Break the chain at any step: close the Internet access, remove the token or the right that links the steps.",
		},
	},
	"ru": {
		"cluster-admin-sa": {
			"Взломав это приложение, злоумышленник получит полный контроль над всем кластером: всеми приложениями и секретами.",
			"Дайте ServiceAccount приложения роль только с нужными ему правами и уберите привязку к cluster-admin.",
		},
		"exposed-secret": {
			"Приложение доступно из интернета и хранит пароли или ключи: одна ошибка в нём — и они у злоумышленника.",
			"Закройте доступ из интернета, если он не нужен, или уберите секрет из этого приложения.",
		},
		"exposed-cve": {
			"Приложение доступно из интернета, а в его образе есть известные уязвимости, часто с готовыми эксплойтами.",
			"Пересоберите образ на версии, где уязвимости исправлены, и выкатите заново.",
		},
		"privileged-container": {
			"Привилегированный контейнер — фактически root на узле: взломав его, злоумышленник управляет узлом и соседними подами.",
			"Уберите privileged: true из контейнера; если нужна одна capability, выдайте только её.",
		},
		"host-namespaces": {
			"Под видит сеть или процессы узла, поэтому взлом выходит за пределы контейнера на узел.",
			"Уберите hostNetwork, hostPID и hostIPC из пода, если это не агент узла по устройству.",
		},
		"host-path": {
			"Под монтирует файлы узла: через них взлом читает данные других подов или захватывает узел.",
			"Используйте emptyDir, PersistentVolume или ConfigMap вместо каталога узла.",
		},
		"no-network-policy": {
			"К этим приложениям может подключиться любой под кластера, и один взломанный под достаёт до всех.",
			"Добавьте NetworkPolicy, которая по умолчанию запрещает трафик и разрешает только нужный приложениям.",
		},
		"latest-tag": {
			"Без зафиксированной версии после перезапуска незаметно может запуститься другой или подменённый образ.",
			"Укажите точную версию образа, лучше вместе с digest (image:1.2.3@sha256:...).",
		},
		"wildcard-rbac": {
			"Роль с «*» разрешает любые действия, в том числе будущие: взлом даёт гораздо больше, чем нужно приложению.",
			"Перечислите в роли только те действия и ресурсы, которые приложение действительно использует.",
		},
		"attack-path": {
			"Есть цепочка настроек, по которой злоумышленник из интернета добирается до важной цели в кластере.",
			"Разорвите цепочку на любом шаге: закройте доступ из интернета, уберите токен или право, связывающее шаги.",
		},
	},
}
