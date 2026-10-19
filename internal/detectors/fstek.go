package detectors

import "slices"

// MappingReviewed tells whether a FSTEK expert has confirmed how findings
// map to measures. Until then reports mark the measures table as a draft
// (STRATEGY 2.9); set it to true after the review.
const MappingReviewed = false

// Order is a FSTEK order findings can be mapped to.
type Order struct {
	ID               string // "117" or "17"
	TitleRU, TitleEN string // the document the measures come from
}

// Orders lists the supported orders, the one in force first: it is the default.
var Orders = []Order{
	{"117", "приказ ФСТЭК России от 11.04.2025 № 117; меры — по методическому документу ФСТЭК России «Состав и содержание мероприятий и мер по защите информации, содержащейся в информационных системах» от 12.04.2026",
		"FSTEK Order No. 117 of 11.04.2025; measures as in the FSTEK method document \"Composition and content of activities and measures to protect information in information systems\" of 12.04.2026"},
	{"17", "приказ ФСТЭК России от 11.02.2013 № 17 (утратил силу с 01.03.2026 по приказу № 117)",
		"FSTEK Order No. 17 of 11.02.2013 (repealed from 01.03.2026 by Order No. 117)"},
}

// OrderByID returns the order with the given number.
func OrderByID(id string) (Order, bool) {
	for _, o := range Orders {
		if o.ID == id {
			return o, true
		}
	}
	return Order{}, false
}

// Control is a measure of a FSTEK order under its official designation.
// Designations repeat between orders with other meanings (УПД.2 of order 17
// is not УПД.2 of the 2026 method document), so a measure is identified by
// its order and designation together.
type Control struct {
	Order   string // "17" or "117"
	ID      string // official designation, e.g. "ИАФ.1"
	NameRU  string // name as in the order
	NameEN  string
	Classes string // protection classes of the information system
}

// Controls is the single list of measures: detectors refer to them by
// designation (Finding.FSTEKControls for order 17, Finding.FSTEK117 for
// order 117), the report builds its table from it. Within an order, measures
// follow the sections of the source document.
var Controls = slices.Concat(controls17, controls117)

// Measures of order 17, appendix 2.
var controls17 = []Control{
	{"17", "ИАФ.1", "Идентификация и аутентификация пользователей, являющихся работниками оператора",
		"Identification and authentication of users who are employees of the operator", "К1/К2/К3"},
	{"17", "ИАФ.3", "Управление идентификаторами, в том числе создание, присвоение, уничтожение идентификаторов",
		"Identifier management, including creation, assignment and destruction of identifiers", "К1/К2/К3"},
	{"17", "ИАФ.4", "Управление средствами аутентификации, в том числе хранение, выдача, инициализация, блокирование средств аутентификации и принятие мер в случае утраты и (или) компрометации средств аутентификации",
		"Authenticator management, including storage, issue, initialization and blocking of authenticators and response to their loss or compromise", "К2/К3"},
	{"17", "УПД.2", "Реализация необходимых методов (дискреционный, мандатный, ролевой или иной метод), типов (чтение, запись, выполнение или иной тип) и правил разграничения доступа",
		"Implementation of the required access control methods (discretionary, mandatory, role-based or other), types (read, write, execute or other) and rules", "К1/К2/К3"},
	{"17", "УПД.3", "Управление (фильтрация, маршрутизация, контроль соединений, однонаправленная передача и иные способы управления) информационными потоками между устройствами, сегментами информационной системы, а также между информационными системами",
		"Control of information flows (filtering, routing, connection control, one-way transfer and other means) between devices, segments of the information system and between information systems", "К1/К2/К3"},
	{"17", "УПД.4", "Разделение полномочий (ролей) пользователей, администраторов и лиц, обеспечивающих функционирование информационной системы",
		"Separation of duties (roles) of users, administrators and persons who operate the information system", "К1/К2/К3"},
	{"17", "УПД.5", "Назначение минимально необходимых прав и привилегий пользователям, администраторам и лицам, обеспечивающим функционирование информационной системы",
		"Assignment of the least necessary rights and privileges to users, administrators and persons who operate the information system", "К2/К3"},
	{"17", "ОПС.1", "Управление запуском (обращениями) компонентов программного обеспечения, в том числе определение запускаемых компонентов, настройка параметров запуска компонентов, контроль за запуском компонентов программного обеспечения",
		"Control of software component launch, including defining the components to run, configuring their launch parameters and monitoring launches", "К1/К2/К3"},
	{"17", "ОПС.2", "Управление установкой (инсталляцией) компонентов программного обеспечения, в том числе определение компонентов, подлежащих установке, настройка параметров установки компонентов, контроль за установкой компонентов программного обеспечения",
		"Control of software component installation, including defining the components to install, configuring installation parameters and monitoring installation", "К2/К3"},
	{"17", "АНЗ.1", "Выявление, анализ уязвимостей информационной системы и оперативное устранение вновь выявленных уязвимостей",
		"Detection and analysis of information system vulnerabilities and prompt remediation of newly detected vulnerabilities", "К1/К2/К3"},
	{"17", "АНЗ.2", "Контроль установки обновлений программного обеспечения, включая обновление программного обеспечения средств защиты информации",
		"Control of software update installation, including updates of information security tools", "К2/К3"},
	{"17", "АНЗ.3", "Контроль работоспособности, параметров настройки и правильности функционирования программного обеспечения и средств защиты информации",
		"Control of operability, configuration and correct functioning of software and information security tools", "К2/К3"},
	{"17", "ЗИС.1", "Разделение в информационной системе функций по управлению (администрированию) информационной системой, управлению (администрированию) системой защиты информации, функций по обработке информации и иных функций информационной системы",
		"Separation of information system administration, security system administration, information processing and other functions of the information system", "К1/К2/К3"},
	{"17", "ЗИС.3", "Обеспечение защиты информации от раскрытия, модификации и навязывания (ввода ложной информации) при ее передаче (подготовке к передаче) по каналам связи, имеющим выход за пределы контролируемой зоны, в том числе беспроводным каналам связи",
		"Protection of information against disclosure, modification and injection of false information during transfer over communication channels leaving the controlled area, including wireless channels", "К1/К2/К3"},
	{"17", "ЗИС.17", "Разбиение информационной системы на сегменты (сегментирование информационной системы) и обеспечение защиты периметров сегментов информационной системы",
		"Partitioning of the information system into segments and protection of segment perimeters", "К2/К3"},
}

// Measures of order 117 as given in the FSTEK method document of
// 12.04.2026 (docs/sources/metodika-2026.txt): section IV for names,
// appendix 2 for the base sets. Only measures some detector checks are
// listed: a measure nothing checks would show as met.
var controls117 = []Control{
	{"117", "УПД.2", "Разграничение и контроль прав доступа",
		"Separation and control of access rights", "К1/К2/К3"},
	{"117", "ЗКО.1", "Контроль целостности в контейнерных средах",
		"Integrity control in container environments", "К1/К2/К3"},
	{"117", "ЗКО.3", "Управление доступом в контейнерных средах",
		"Access control in container environments", "К1/К2/К3"},
	{"117", "ЗКО.5", "Изоляция контейнеров в контейнерной среде",
		"Isolation of containers in a container environment", "К1/К2/К3"},
	{"117", "ЗКО.7", "Управление контейнерами и их образами (оркестрация)",
		"Management of containers and their images (orchestration)", "К1/К2/К3"},
	{"117", "ЗКО.8", "Выявление и устранение уязвимостей в контейнерной среде",
		"Detection and remediation of vulnerabilities in a container environment", "К1/К2/К3"},
	{"117", "МСЭ.1", "Сегментация сети",
		"Network segmentation", "К1/К2/К3"},
	{"117", "МСЭ.3", "Контроль сетевого доступа и фильтрация трафика",
		"Network access control and traffic filtering", "К1/К2/К3"},
	{"117", "ЗКС.1", "Защита данных при передаче по каналам связи",
		"Protection of data transferred over communication channels", "К1/К2/К3"},
}

// ControlsOf returns the measures of an order.
func ControlsOf(order string) []Control {
	var out []Control
	for _, c := range Controls {
		if c.Order == order {
			out = append(out, c)
		}
	}
	return out
}

// ControlByID returns the measure of an order with the designation id.
func ControlByID(order, id string) (Control, bool) {
	for _, c := range Controls {
		if c.Order == order && c.ID == id {
			return c, true
		}
	}
	return Control{}, false
}

// detectorControls are the measures each detector maps its findings to, by
// order: the same designations its findings carry (a test keeps them in
// sync). Stored findings keep only their detector, so pages built from the
// triage state map them to measures through it.
var detectorControls = map[string]map[string][]string{
	"cluster-admin-sa":     {"17": {"УПД.2", "УПД.4", "УПД.5", "ОПС.1", "АНЗ.1"}, "117": {"ЗКО.3", "УПД.2"}},
	"exposed-secret":       {"17": {"ИАФ.1", "ИАФ.3", "ИАФ.4", "ЗИС.3", "УПД.3"}, "117": {"ЗКО.3", "УПД.2", "ЗКС.1"}},
	"exposed-cve":          {"17": {"АНЗ.1", "АНЗ.2", "АНЗ.3", "ОПС.2", "ЗИС.1"}, "117": {"ЗКО.8", "ЗКС.1"}},
	"privileged-container": {"17": {"УПД.4", "УПД.5", "ОПС.1", "ЗИС.1"}, "117": {"ЗКО.5", "УПД.2"}},
	"host-namespaces":      {"17": {"УПД.3", "ОПС.1", "ЗИС.1"}, "117": {"ЗКО.5"}},
	"host-path":            {"17": {"УПД.3", "ОПС.1", "ЗИС.1"}, "117": {"ЗКО.5"}},
	"no-network-policy":    {"17": {"УПД.3", "ЗИС.3", "ЗИС.17"}, "117": {"МСЭ.1", "МСЭ.3"}},
	"latest-tag":           {"17": {"ОПС.2", "АНЗ.2", "АНЗ.3"}, "117": {"ЗКО.1", "ЗКО.7"}},
	"wildcard-rbac":        {"17": {"УПД.2", "УПД.4", "УПД.5"}, "117": {"ЗКО.3", "УПД.2"}},
	// Every measure a path can violate; a finding carries those of its steps.
	"attack-path": {"17": {"УПД.3", "УПД.5", "ЗИС.1", "АНЗ.1"}, "117": {"МСЭ.1", "ЗКО.3", "ЗКО.5", "ЗКО.8"}},
}

// DetectorControls returns the designations of the measures of order the
// findings of a detector map to; nil for an unknown detector. A finding of
// attack-path maps to a part of them, by the steps of its path.
func DetectorControls(detector, order string) []string {
	return detectorControls[detector][order]
}
