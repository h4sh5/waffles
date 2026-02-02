// a WAF proxy that forwards requests and blocks malicious requests

package main

import (
	"bytes"
	"io/ioutil"
	"fmt"
	"io"
	"bufio"
	"net/http"
	"log"
	// "strings"
	"os"
	"regexp"
	"encoding/json"
)

type RuleItem struct {
	Id string `json:"id"`
	Regex string `json:"regex"` // the actual rule content
	Part string `json:"part"` // path | query | body
}

type Rule struct {
	RuleItems []RuleItem `json:"items"`
	Condition string `json:"condition"` // AND | OR 
}

var forwardUrl string
var GlobalRulesData []Rule
var rulesFile string

// implement more blocking functionality here
// return true for blocked, false for allowed
func block_request(r *http.Request, reqBody []byte, rules []Rule) bool {
	// return true or false based on blocking
	// reqBodyStr := string(reqBody)
	for i := 0; i < len(rules); i++ {
		rule := rules[i]
		ruleItems := rule.RuleItems
		reqBodyString := string(reqBody)
		matchedRulesCount := 0

		for j := 0; j < len(ruleItems); j++ {

			if (ruleItems[j].Part == "path") {
				
				matched, _ := regexp.MatchString(ruleItems[j].Regex, r.URL.Path)
				if matched  {
					log.Printf("MATCH regex: %v, url path: %s\n", ruleItems[j].Regex, r.URL.Path)
					matchedRulesCount ++;
					if rule.Condition == "OR" {
						return true
					}
				}
			}
			if (ruleItems[j].Part == "query") {
				
				matched, _ := regexp.MatchString(ruleItems[j].Regex, r.URL.RawQuery)
				if matched {
					log.Printf("MATCH regex: %v, query: %s\n", ruleItems[j].Regex, r.URL.RawQuery)
					matchedRulesCount ++;
					if rule.Condition == "OR" {
						return true
					}
				}
			}
			if (ruleItems[j].Part == "body") {
				
				// log.Printf("regex: %v, body: %s\n", ruleItems[j].Regex, )
				matched, _ := regexp.MatchString(ruleItems[j].Regex, reqBodyString)
				if matched {
					log.Printf("MATCH regex: %v, query: %s\n", ruleItems[j].Regex, r.URL.RawQuery)
					matchedRulesCount ++;
					if rule.Condition == "OR" {
						return true
					}
				}
			}

		}
		if rule.Condition == "AND" && matchedRulesCount == len(ruleItems) {
			log.Printf("BLOCK matchedRulesCount: %v, len(ruleItems): %v\n", matchedRulesCount, len(ruleItems))
			return true
		}
	}

	return false;
}

func getRoot(w http.ResponseWriter, r *http.Request) {
	log.Printf("got / request\n")
	loadRules(rulesFile)

	reqBody, err := ioutil.ReadAll(r.Body)
	log.Printf("reqBody:\n%s", reqBody)

	if err != nil {
		log.Printf("block_request: could not read response body: %s\n", err)	
	}

	if (block_request(r, reqBody, GlobalRulesData)) {
		w.WriteHeader(http.StatusNotAcceptable) // block with 406
		io.WriteString(w, "Blocked by WAF!\n")
		return
	} else {

		requestUrl := fmt.Sprintf("%s%s?%s", forwardUrl, r.URL.Path, r.URL.RawQuery)
		req, err := http.NewRequest(r.Method, requestUrl, bytes.NewBuffer(reqBody))
		if err != nil {
			log.Printf("client: could not create request: %s\n", err)
		}

		// pass thru request headers
		for k, v := range r.Header {
	        req.Header[k] = v
	    }

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("client: error making http request: %s\n", err)
		}

		resBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Printf("client: could not read response body: %s\n", err)
		}

		// pass thru response headers as well
		for k, v := range res.Header {
	        w.Header().Set(k, v[0])
	    }

		w.WriteHeader(res.StatusCode)
		w.Write(resBody)

	}
}

func loadRules(filename string) {
	rulesFile, err := os.Open(filename)
	if err != nil {
	    log.Println("Error opening rules file.")
		return
	}
	reader := bufio.NewReader(rulesFile)
	bytes, err := io.ReadAll(reader)
	rulesFile.Close()
	if (err != nil) {
		log.Println("Error reading rules file.")
		return
	}
	
	err = json.Unmarshal(bytes, &GlobalRulesData)

	if err != nil {
		log.Println("Error unmarshalling rules file.")
		return
	}
	log.Printf("Rules loaded: %#v",GlobalRulesData)
}

func main() {
	forwardUrl = os.Args[1]
	if len(os.Args) > 2 {
		rulesFile = os.Args[2]
	} else{
		rulesFile = "rules.json" // default path
	}
	log.Printf("using rules file: %s\n", rulesFile)
	
	// load rules
	http.HandleFunc("/", getRoot)
	// http.HandleFunc("*", getRoot)
	listenAddr := ":80"
	log.Printf("Listening on %v\n", listenAddr)
	err := http.ListenAndServe(listenAddr, nil)
	if (err != nil) {
		log.Fatalf("Err starting http server: %s", err)
	}
}

