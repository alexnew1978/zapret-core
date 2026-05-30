package main

import (
	"fmt"
	"strings"
)

// StrategyVector holds all variable parameters for DPI bypass strategies
type StrategyVector struct {
	DesyncMethod    string
	RepeatsTCP      int
	RepeatsUDP      int
	Fooling         string
	SplitPos        string
	TLSMode         string
	TLSFiles        []string
	TLSMod          string
	SeqOvl          int
	SeqOvlPattern   string
	HostFakeMod     string
	Cutoff          string
	BadseqIncrement int
	QuicBin         string
	AnyProtocol     bool
	IPID            string
	AutoTTL         string // Поддержка параметра --dpi-desync-autottl (из Yv06)
}

// SearchSpace defines all possible values for each parameter
var SearchSpace = struct {
	DesyncMethod    []string
	RepeatsTCP      []int
	RepeatsUDP      []int
	Fooling         []string
	SplitPos        []string
	TLSMode         []string
	TLSFiles        [][]string
	TLSMod          []string
	SeqOvl          []int
	SeqOvlPattern   []string
	HostFakeMod     []string
	Cutoff          []string
	BadseqIncrement []int
	QuicBin         []string
	IPID            []string
	AutoTTL         []string
}{
	DesyncMethod: []string{
		// ЧИСТЫЕ МЕТОДЫ И НОВЫЕ РЕЖИМЫ (Из Yv02, Yv04, Yv11, Yv17)
		"multidisorder", "disorder", "split", "multisplit", "disorder,split", 
		"split2", "fakeddisorder", "fake,fakeddisorder",
		
		// Старые методы с фейками
		"fake", "fake,fakedsplit", "fake,multisplit", "fake,hostfakesplit",
		"fake,multidisorder", "syndata,multidisorder", "syndata", "hostfakesplit",
	},
	RepeatsTCP: []int{0, 2, 4, 6, 8, 10, 11, 12, 14}, // Включая repeat=2 и 0 (дефолт)
	RepeatsUDP: []int{4, 6, 10, 11, 12},
	Fooling: []string{
		"", // Без флага fooling (для чистых стратегий)
		"ts", "badseq", "ts,md5sig", "badsum", "md5sig", "ts,badseq", 
		"badsum,badseq", "badseq,badsum", // Комбинации из Yv03, Yv05, Yv15, Yv16
	},
	SplitPos: []string{
		// ТОП ЛУЧШИХ СТРАТЕГИЙ НА ПЕРВЫЕ МЕСТА ТЕСТА
		"1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1", // Ваша рабочая (#Yv26)
		"2,5,105,host+5,sld-1,endsld-5,endsld",                 // Супер-сплит из #Yv11
		"1,midsld,endhost-1",                                   // Позиция из #Yv07
		"7,sld+1",                                              // Позиция из #Yv06
		"2,sld",                                                // Позиция из #Yv03 и #Yv15
		"1,sniext+1",                                           // Позиция из #Yv02 и #Yv16
		"1,midsld",                                             // Позиция из #Yv08, #Yv09, #Yv12
		"10,midsld",                                            // Позиция из #Yv05 и #Yv14
		"1", "2", "1,2", "method+2",                            // Базовые позиции (из Yv10, Yv17)
	},
	TLSMode: []string{"none", "file", "tls-mod"},
	TLSFiles: [][]string{
		{"tls_clienthello_www_google_com.bin"},
		{"stun.bin"}, // Из Yv22, Yv23, Yv24
		{"stun.bin", "tls_clienthello_www_google_com.bin"},
		{"stun.bin", "tls_clienthello_max_ru.bin"},
		{"tls_clienthello_4pda_to.bin"},
		{"tls_clienthello_max_ru.bin"},
	},
	TLSMod: []string{
		"none",
		"rnd,dupsid,sni=://google.com", 
		"rnd,dupsid,sni=ya.ru",
		"rnd,dupsid,sni=://google.com", // Из Yv05, Yv13, Yv14
		"rnd,dupsid,sni=ggpht.com",        // Из Yv03, Yv15
	},
	SeqOvl: []int{0, 1, 4, 336, 568, 620, 654, 664, 679, 681, 2108}, // Размеры наложений из списка
	SeqOvlPattern: []string{
		"tls_clienthello_www_google_com.bin", 
		"tls_clienthello_4pda_to.bin", 
		"tls_clienthello_max_ru.bin",
		"stun.bin", // Из Yv24
		"tls_clienthello_gosuslugi_ru.bin", // Из Yv05
	},
	HostFakeMod: []string{"://google.com", "google.com", "ya.ru", "ozon.ru", "://2gis.com"}, // Из Yv19, Yv25
	Cutoff:          []string{"", "n2", "n3", "n4", "n5"},
	BadseqIncrement: []int{0, 2, 1000, 10000000}, // Из Yv05, Yv16, Yv23, Yv24
	QuicBin:         []string{"quic_initial_www_google_com.bin", "quic_initial_dbankcloud_ru.bin", "quic_initial_yandex_ru.bin"},
	IPID:            []string{"zero", ""},
	AutoTTL:         []string{"", "2:2-12", "2:1-10"}, // Из Yv06
}
func buildTLSArgs(v StrategyVector) []string {
	args := []string{}
	// TLS фейки генерируем только если сам метод использует фейк-пакеты
	if !strings.Contains(v.DesyncMethod, "fake") {
		return args
	}
	if v.TLSMod != "" && v.TLSMod != "none" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-tls-mod=%s", v.TLSMod))
	}
	switch v.TLSMode {
	case "file":
		for _, f := range v.TLSFiles {
			args = append(args, fmt.Sprintf("--dpi-desync-fake-tls=%s", fake(f)))
		}
	}
	return args
}

func buildTCPRule(v StrategyVector) []string {
	// ГЛОБАЛЬНЫЙ СБРОС ДЛЯ ВСЕХ ЧИСТЫХ МЕТОДОВ:
	// Если метод не содержит фейков (fake), принудительно убираем весь мешающий fooling
	// и TLS-модификации, чтобы выдать абсолютно чистую строку без ломающего обход мусора.
	if !strings.Contains(v.DesyncMethod, "fake") {
		v.Fooling = ""
		v.RepeatsTCP = 0
		v.TLSMod = "none"
		v.TLSMode = "none"
		v.AutoTTL = ""
	}

	args := []string{}
	args = append(args, fmt.Sprintf("--dpi-desync=%s", v.DesyncMethod))
	
	if v.RepeatsTCP > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-repeats=%d", v.RepeatsTCP))
	}
	if v.Fooling != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fooling=%s", v.Fooling))
	}
	if v.SplitPos != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-split-pos=%s", v.SplitPos))
	}
	if strings.Contains(v.Fooling, "badseq") && v.BadseqIncrement != 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-badseq-increment=%d", v.BadseqIncrement))
	}
	
	// Поддержка seqovl для multisplit и split2 (из Yv01, Yv04, Yv10 и др.)
	if v.SeqOvl > 0 && (strings.Contains(v.DesyncMethod, "multisplit") || strings.Contains(v.DesyncMethod, "split2")) {
		args = append(args, fmt.Sprintf("--dpi-desync-split-seqovl=%d", v.SeqOvl))
		args = append(args, fmt.Sprintf("--dpi-desync-split-seqovl-pattern=%s", fake(v.SeqOvlPattern)))
	}
	
	// Поддержка autottl против ТСПУ (из Yv06)
	if v.AutoTTL != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-autottl=%s", v.AutoTTL))
	}

	if strings.Contains(v.DesyncMethod, "hostfakesplit") && v.HostFakeMod != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-hostfakesplit-mod=host=%s,altorder=1", v.HostFakeMod))
	}

	args = append(args, buildTLSArgs(v)...)

	// fake-http добавляется ТОЛЬКО для методов с фейками
	if strings.Contains(v.DesyncMethod, "fake") {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-http=%s", fake("tls_clienthello_max_ru.bin")))
	}
	return args
}

func Generate(v StrategyVector) []string {
	args := []string{}
	args = append(args, "--wf-tcp=80,443,2053,2083,2087,2096,8443", "--wf-udp=443,19294-19344,50000-50100")

	// Rule 1: UDP 443 — QUIC fake
	args = append(args, "--filter-udp=443", fmt.Sprintf("--hostlist=%s", lists("list-general.txt")), fmt.Sprintf("--hostlist-exclude=%s", lists("list-exclude.txt")), fmt.Sprintf("--ipset-exclude=%s", lists("ipset-exclude.txt")), "--dpi-desync=fake", fmt.Sprintf("--dpi-desync-repeats=%d", v.RepeatsUDP), fmt.Sprintf("--dpi-desync-fake-quic=%s", fake(v.QuicBin)), "--new")

	// Rule 2: UDP Discord/STUN
	args = append(args, "--filter-udp=19294-19344,50000-50100", "--filter-l7=discord,stun", "--dpi-desync=fake", fmt.Sprintf("--dpi-desync-fake-discord=%s", fake("quic_initial_dbankcloud_ru.bin")), fmt.Sprintf("--dpi-desync-fake-stun=%s", fake("quic_initial_dbankcloud_ru.bin")), fmt.Sprintf("--dpi-desync-repeats=%d", v.RepeatsUDP), "--new")

	// Rule 3: TCP discord.media
	r3 := []string{"--filter-tcp=2053,2083,2087,2096,8443", "--hostlist-domains=discord.media"}
	r3 = append(r3, buildTCPRule(v)...)
	args = append(args, append(r3, "--new")...)

	// Rule 4: TCP 443 — Google
	r4 := []string{"--filter-tcp=443", fmt.Sprintf("--hostlist=%s", lists("list-google.txt"))}
	if v.IPID == "zero" { r4 = append(r4, "--ip-id=zero") }
	r4 = append(r4, buildTCPRule(v)...)
	args = append(args, append(r4, "--new")...)

	// Rule 5: TCP 80,443 — general
	r5 := []string{"--filter-tcp=80,443", fmt.Sprintf("--hostlist=%s", lists("list-general.txt")), fmt.Sprintf("--hostlist-exclude=%s", lists("list-exclude.txt")), fmt.Sprintf("--ipset-exclude=%s", lists("ipset-exclude.txt"))}
	r5 = append(r5, buildTCPRule(v)...)
	args = append(args, append(r5, "--new")...)

	// Rule 6: UDP 443 — ipset-all
	args = append(args, "--filter-udp=443", fmt.Sprintf("--ipset=%s", lists("ipset-all.txt")), fmt.Sprintf("--hostlist-exclude=%s", lists("list-exclude.txt")), fmt.Sprintf("--ipset-exclude=%s", lists("ipset-exclude.txt")), "--dpi-desync=fake", fmt.Sprintf("--dpi-desync-repeats=%d", v.RepeatsUDP), fmt.Sprintf("--dpi-desync-fake-quic=%s", fake(v.QuicBin)), "--new")

	// Rule 7: TCP ipset-all
	r7 := []string{"--filter-tcp=80,443,8443", fmt.Sprintf("--ipset=%s", lists("ipset-all.txt")), fmt.Sprintf("--hostlist-exclude=%s", lists("list-exclude.txt")), fmt.Sprintf("--ipset-exclude=%s", lists("ipset-exclude.txt"))}
	r7 = append(r7, buildTCPRule(v)...)
	args = append(args, append(r7, "--new")...)

	// Rule 8: TCP GameFilter
	r8 := []string{"--filter-tcp=1024-65535", fmt.Sprintf("--ipset=%s", lists("ipset-all.txt")), fmt.Sprintf("--ipset-exclude=%s", lists("ipset-exclude.txt"))}
	if v.AnyProtocol { r8 = append(r8, "--dpi-desync-any-protocol=1") }
	if v.Cutoff != "" { r8 = append(r8, fmt.Sprintf("--dpi-desync-cutoff=%s", v.Cutoff)) }
	r8 = append(r8, buildTCPRule(v)...)
	args = append(args, append(r8, "--new")...)

	// Rule 9: UDP GameFilter
	args = append(args, "--filter-udp=1024-65535", fmt.Sprintf("--ipset=%s", lists("ipset-all.txt")), fmt.Sprintf("--ipset-exclude=%s", lists("ipset-exclude.txt")), "--dpi-desync=fake", fmt.Sprintf("--dpi-desync-repeats=%d", v.RepeatsUDP))
	if v.AnyProtocol { args = append(args, "--dpi-desync-any-protocol=1") }
	if v.Cutoff != "" { args = append(args, fmt.Sprintf("--dpi-desync-cutoff=%s", v.Cutoff)) }
	args = append(args, fmt.Sprintf("--dpi-desync-fake-unknown-udp=%s", fake("quic_initial_dbankcloud_ru.bin")))

	return args
}

func VectorToStrategy(v StrategyVector, id int) *Strategy {
	return &Strategy{
		Name: fmt.Sprintf("auto-%d [%s/%s/%s]", id, v.DesyncMethod, v.Fooling, v.TLSMode),
		Args: Generate(v),
	}
}
