package utils

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	// "strconv"
	"strings"
	"time"

	ps "github.com/mitchellh/go-ps"
)

var bannedProcesses = []string{
	"wireshark",
	"http debugger",
	"burp",
	"httpdebugger",
	"dnspy",
	"fiddler",
	"http debugger pro",
	"httpdebuggerpro",
	"ilspy",
	"justdecompile",
	"just decompile",
	"ollydbg",
	"ida",
	"immunitydebugger",
	"megadumper",
	"mega dumper",
	"processhacker",
	"process hacker",
	"ollydbg",
	"charles",
	"cheat engine",
	"cheatengine",
	"codebrowser",
	"code browser",
	"scylla",
	"burpsuite",
	"nmap",
	"nikto",
	"openvas",
	"angryip",
	"angry ip",
	"qualys",
	"solarwinds",
	"paessler",
	"intruder",
	"acunetix",
	"spiceworks",
}

// var bannedEnvs = []string{"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "https_proxy", "NODE_ENV", "APP_ENV"}
var bannedEnvs = []string{"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "https_proxy", "NODE_ENV"}

const WebhookURL = "webhookurl"

func processCheck() {

	processList, err := ps.Processes()
	if err != nil {
		log.Println("ps.Processes() Failed, are you using windows?")
		return
	}

	for x := range processList {
		// var process ps.Process
		process := processList[x]
		for _, p := range bannedProcesses {
			if strings.Contains(strings.ToLower(process.Executable()), strings.ToLower(p)) {
				sendSecurityWebhook("Process Check", process.Executable())
				os.Exit(2)
				return
			}
		}
	}
}

func envCheck() {
	for _, e := range bannedEnvs {
		env := os.Getenv(e)
		if env != "" {
			sendSecurityWebhook("Env Check", env)
			os.Exit(2)
			return
		}
	}
}

func apiHostCheck() {
	ips, err := net.LookupHost("api.custom.com")
	if err != nil {
		os.Exit(2)
	}
	for _, i := range ips {
		if i == "127.0.0.1" {
			return
		}
	}
	sendSecurityWebhook("API Host Check", "")
	os.Exit(2)
}

var certkey = `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3uVPRb11zAPeoGEAJAGZ
6I2B6rfAKnJMYYwEY75A+6ZWswxooybBtjczhN/KEzuTNhqq/t775omPqUvpKIJ2
aNk0TrQ4Lp/UYTbHGCbP608LhKKIKlMuZhadUJujqOtCI4mKckvMgsTBZswLSRV5
g3ICYV+C+intbci7L+NHF4QlAHvpdAeUVTBal/dY9HppKdl10YIOb3x4N2Trwo/a
fMAvObrOXuIC80tKmWyDlbCLAGdhxiqPhmeawRc7iLe6rhtwid+eK57RwcYJxN/5
PwcuDWqTYcqBKx5Y6ISAVDKo4TXjAxh0+5btZjoxSJ1A6wlsV+lqFMsPsAxYQrKx
2wIDAQAB`

func publicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Println(err.Error())
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

func checkCert() {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", "api.url.com:443", conf)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		log.Println("Error in Dial", err)
		return
	}
	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		spublic := string(publicKeyToBytes(cert.PublicKey.(*rsa.PublicKey)))
		if strings.Contains(cert.Issuer.String(), "Encrypt") && strings.Contains(spublic, certkey) {
			return
		}

	}
	sendSecurityWebhook("Check Cert", "")
	os.Exit(2)
}

var client *http.Client

func LoopSecurityChecks(c *http.Client) {
	client = c
	for {
		go processCheck()
		go envCheck()
		go apiHostCheck()
		//go checkCert()
		time.Sleep(15 * time.Second)
	}
}

func sendSecurityWebhook(typeOfBreach string, extraInfo string) {
	ip := getIP()
	rm := map[string]interface{}{
		"username":   "custom Security",
		"avatar_url": "https://custom.com/img/logo/profile.png",
		"embeds": []map[string]interface{}{
			{
				"title":       "Security Notification",
				"description": "Somebody set off one of the security checks.",
				"fields": []map[string]interface{}{
					{"name": "Type of Breach", "value": typeOfBreach, "inline": true},
					{"name": "IP", "value": ip, "inline": true},
					{"name": "Info", "value": extraInfo, "inline": false},
				},
				"color":     0xff0000,
				"timestamp": time.Now(),
			},
		},
	}
	body, _ := json.Marshal(rm)
	req, _ := http.NewRequest("POST", WebhookURL, bytes.NewBuffer([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err.Error())
	}
	defer resp.Body.Close()
}

func getIP() string {
	url := "https://api.ipify.org?format=text"
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(ip)
}
