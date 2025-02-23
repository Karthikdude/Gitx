package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Result structure with detailed information
type Result struct {
	URL             string   `json:"url"`
	Exposed         bool     `json:"exposed"`
	LeakedFiles     []string `json:"leaked_files,omitempty"`
	BranchName      string   `json:"branch_name,omitempty"`
	PotentialRisks  []string `json:"potential_risks,omitempty"`
	RecommendedFix  string   `json:"recommended_fix"`
	StatusCodes     map[string]string `json:"status_codes,omitempty"`
	Verification    map[string]bool    `json:"verification,omitempty"`
	ErrorMessages   map[string]string  `json:"error_messages,omitempty"`
}

// List of .git endpoints to check
var paths = []string{
	"/.git/", "/.git/HEAD", "/.git/config", "/.git/index",
	"/.git/logs/HEAD", "/.git/logs/refs/heads/master", "/.git/logs/refs/heads/main",
	"/.git/logs/refs/remotes/origin/HEAD", "/.git/logs/refs/remotes/origin/master", "/.git/logs/refs/remotes/origin/main",
	"/.git/refs/heads/master", "/.git/refs/heads/main",
	"/.git/refs/remotes/origin/HEAD", "/.git/refs/remotes/origin/master", "/.git/refs/remotes/origin/main",
	"/.git/refs/tags/", "/.git/objects/", "/.git/objects/info/packs",
	"/.git/objects/pack/", "/.git/objects/info/", "/.git/objects/00/",
	"/.git/packed-refs", "/.git/info/", "/.git/info/exclude", "/.git/info/refs",
	"/.git/branches/", "/.git/refs/stash", "/.git/refs/notes/",
	"/.git/objects/01/", "/.git/objects/02/", "/.git/objects/03/",
	"/.git/objects/04/", "/.git/objects/05/", "/.git/objects/06/",
	"/.git/objects/07/", "/.git/objects/08/", "/.git/objects/09/",
	"/.git/objects/0a/", "/.git/objects/0b/", "/.git/objects/0c/",
	"/.git/objects/0d/", "/.git/objects/0e/", "/.git/objects/0f/",
	"/.git/hooks/", "/.git/hooks/pre-commit.sample", "/.git/hooks/post-update.sample",
	"/.git/hooks/pre-rebase.sample", "/.git/hooks/pre-applypatch.sample",
	"/.git/hooks/update.sample", "/.git/hooks/pre-push.sample",
	"/.git/hooks/pre-receive.sample", "/.git/hooks/commit-msg.sample",
	"/.git/hooks/applypatch-msg.sample", "/.git/hooks/fsmonitor-watchman.sample",
	"/.git/hooks/pre-merge-commit.sample", "/.git/hooks/sendemail-validate.sample",
}

// Function to check for exposed .git files
func checkGitExposure(url string, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Follow redirects
		},
	}
	result := Result{
		URL:             url,
		Exposed:         false,
		RecommendedFix:  "Restrict access to the .git directory via web server settings.",
		StatusCodes:     make(map[string]string),
		Verification:    make(map[string]bool),
		ErrorMessages:   make(map[string]string),
	}

	// Perform a test request to a non-existent path to detect default responses
	testPath := "/random-nonexistent-check"
	testResp, err := client.Get(url + testPath)
	testResponseLength := 0
	if err == nil {
		defer testResp.Body.Close()
		testBody, _ := ioutil.ReadAll(testResp.Body)
		testResponseLength = len(strings.TrimSpace(string(testBody)))
	}

	errorMessages := []string{
		"not found", "page not found", "requested url was not found",
		"no such file or directory", "does not exist", "invalid request",
		"error", "access denied", "forbidden", "unauthorized", "oops",
		"this page is missing", "resource unavailable", "site can't be reached",
		"something went wrong", "nginx default page", "apache server at",
		"index of /", "403 forbidden", "welcome to nginx", "powered by",
		"directory listing for", "your request could not be processed",
		"this site is under maintenance", "coming soon", "invalid request",
		"site under construction", "temporary error", "account suspended",
		"maintenance mode", "internal server error", "bad request",
		"error 404", "404 not found", "500 internal server error",
		"we are currently experiencing issues", "undergoing maintenance",
		"this service is currently unavailable", "try again later",
		"your request could not be completed", "invalid input",
		"page is missing", "default server page", "403 forbidden",
		"401 unauthorized", "nginx error", "server configuration error",
		"missing resource", "this url is invalid","Sorry","404","sorry",
		"Error 404","The requested URL was rejected","The Page you are looking for can't be found",
		"Illegal host","File or directory not found","The resource you are looking for might have been removed",
		"temporarily unavailable","Your support ID is","Error 404",
		"Page you are looking for is not found!",
	}

	for _, path := range paths {
		resp, err := client.Get(url + path)
		if err != nil {
			result.StatusCodes[path] = "Error: " + err.Error()
			continue
		}
		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)
		bodyString := strings.TrimSpace(string(body))
		statusMessage := http.StatusText(resp.StatusCode)

		result.StatusCodes[path] = fmt.Sprintf("%d %s", resp.StatusCode, statusMessage)

		// Measure response length
		contentLength := len(bodyString)

		// Ignore responses that are too small or match default page size
		if contentLength < 10 || (testResponseLength > 0 && contentLength == testResponseLength) {
			result.Verification[path] = false
			continue
		}

		if resp.StatusCode == 200 {
			if isGitRelated(path, bodyString) {
				result.Exposed = true
				result.LeakedFiles = append(result.LeakedFiles, path)
				result.Verification[path] = true

				// Check for error messages in the response body
				errorCount := 0
				for _, msg := range errorMessages {
					if strings.Contains(strings.ToLower(bodyString), msg) {
						errorCount++
						result.ErrorMessages[path] = fmt.Sprintf("%d Error Messages Found: %s", errorCount, msg)
						break
					}
				}
				if errorCount == 0 {
					result.ErrorMessages[path] = "No Error Messages Found"
				}

				// If it's .git/HEAD, try to extract branch name
				if path == "/.git/HEAD" {
					if strings.HasPrefix(bodyString, "ref: refs/heads/") {
						result.BranchName = strings.TrimPrefix(bodyString, "ref: refs/heads/")
					}
				}
			} else {
				result.Verification[path] = false
			}
		}
	}

	// Add potential risks based on the exposed files
	if result.Exposed {
		result.PotentialRisks = append(result.PotentialRisks, "Attackers can download the entire repository.")

		if contains(result.LeakedFiles, "/.git/config") {
			result.PotentialRisks = append(result.PotentialRisks, "Leaked .git/config may expose repository URLs or sensitive settings.")
		}
		if contains(result.LeakedFiles, "/.git/index") {
			result.PotentialRisks = append(result.PotentialRisks, "Leaked .git/index allows attackers to list all tracked files.")
		}
		if contains(result.LeakedFiles, "/.git/logs/HEAD") {
			result.PotentialRisks = append(result.PotentialRisks, "Leaked .git/logs/HEAD exposes commit history, including possibly sensitive changes.")
		}
		if contains(result.LeakedFiles, "/.git/refs/heads/master") || contains(result.LeakedFiles, "/.git/refs/heads/main") {
			result.PotentialRisks = append(result.PotentialRisks, "Leaked .git/refs/heads/master or main reveals branch names and latest commits.")
		}
		if contains(result.LeakedFiles, "/.git/packed-refs") {
			result.PotentialRisks = append(result.PotentialRisks, "Leaked .git/packed-refs exposes commit hashes, which can help reconstruct history.")
		}
		if contains(result.LeakedFiles, "/.git/objects/") {
			result.PotentialRisks = append(result.PotentialRisks, "Leaked .git/objects/ may allow attackers to reconstruct the repository.")
		}
		if contains(result.LeakedFiles, "/.git/info/refs") {
			result.PotentialRisks = append(result.PotentialRisks, "Leaked .git/info/refs allows enumeration of all references in the repository.")
		}
		if contains(result.LeakedFiles, "/.git/hooks/") {
			result.PotentialRisks = append(result.PotentialRisks, "Leaked .git/hooks/ may contain scripts with security-sensitive logic.")
		}
	}

	results <- result
}

// Helper function to check if a slice contains an element
func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// Function to verify if the response is related to a Git repository
func isGitRelated(path, body string) bool {
	// Check for common patterns in Git files
	if path == "/.git/HEAD" && strings.HasPrefix(body, "ref: refs/heads/") {
		return true
	}
	if path == "/.git/config" && strings.Contains(body, "[core]") && strings.Contains(body, "repositoryformatversion") {
		return true
	}
	if path == "/.git/index" && len(body) > 4 { // Binary data expected
		return true
	}
	if strings.Contains(path, "/.git/logs/") && strings.Contains(body, "commit ") {
		return true
	}
	if strings.Contains(path, "/.git/refs/") && strings.Contains(body, "commit ") {
		return true
	}
	if strings.Contains(path, "/.git/objects/") && len(body) > 20 { // Binary object detection
		return true
	}
	if strings.Contains(path, "/.git/packed-refs") && strings.Contains(body, "^") {
		return true
	}
	if strings.Contains(path, "/.git/info/refs") && strings.Contains(body, "refs/heads/") {
		return true
	}

	// Check for default error pages or placeholders
	if len(body) < 10 || strings.Contains(strings.ToLower(body), "not found") || strings.Contains(strings.ToLower(body), "error") {
		return false
	}

	return false
}

func main() {
	url := flag.String("u", "", "Target URL")
	listFile := flag.String("l", "", "File with list of URLs")
	outputFile := flag.String("o", "", "Save output to file")
	jsonOutput := flag.Bool("json", false, "Output results in JSON format")
	flag.Parse()

	var urls []string
	if *url != "" {
		urls = append(urls, *url)
	} else if *listFile != "" {
		file, err := os.Open(*listFile)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			target := strings.TrimSpace(scanner.Text())
			urls = append(urls, target)
		}
	}

	results := make(chan Result, len(urls))
	var wg sync.WaitGroup

	// Start worker goroutines
	for _, targetURL := range urls {
		wg.Add(1)
		go checkGitExposure(targetURL, results, &wg)
	}

	// Close the channel after all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and display results in real-time
	var finalResults []Result
	for result := range results {
		finalResults = append(finalResults, result)
		if !*jsonOutput {
			fmt.Printf("\n🔍 Scanning: %s\n", result.URL)
			if result.Exposed {
				color.Red("🚨 Git repository is exposed!")
				fmt.Println("📝 Leaked Files:")
				for _, file := range result.LeakedFiles {
					status := result.StatusCodes[file]
					statusColor := determineStatusColor(status)
					verification := "Verified"
					if !result.Verification[file] {
						verification = "Not Verified"
					}
					errorMessage := result.ErrorMessages[file]
					statusColor.Printf("   - %s (Status: %s, %s, %s)\n", file, status, verification, errorMessage)
				}
				if result.BranchName != "" {
					color.Yellow("🔀 Detected Branch: %s", result.BranchName)
				}
				fmt.Println("⚠️ Potential Risks:")
				for _, risk := range result.PotentialRisks {
					color.Yellow("   - %s", risk)
				}
				color.Green("✅ Fix Recommendation: %s", result.RecommendedFix)
			} else {
				color.Green("✅ No Git exposure detected.")
			}
		}
	}

	// Save results to file if specified
	if *outputFile != "" {
		file, _ := os.Create(*outputFile)
		defer file.Close()
		for _, res := range finalResults {
			data, _ := json.MarshalIndent(res, "", "  ")
			file.WriteString(string(data) + "\n")
		}
	}

	// Output all results in JSON format if specified
	if *jsonOutput {
		data, _ := json.MarshalIndent(finalResults, "", "  ")
		fmt.Println(string(data))
	}
}

// Function to determine the color based on the status message
func determineStatusColor(status string) *color.Color {
	status = strings.ToLower(status)
	statusColor := color.New(color.FgWhite) // Default color

	if strings.Contains(status, "403") ||
		strings.Contains(status, "access denied") ||
		strings.Contains(status, "forbidden") ||
		strings.Contains(status, "unauthorized") ||
		strings.Contains(status, "permission denied") ||
		strings.Contains(status, "restricted") ||
		strings.Contains(status, "you don't have permission") ||
		strings.Contains(status, "not allowed") ||
		strings.Contains(status, "request blocked") ||
		strings.Contains(status, "blocked by security policy") ||
		strings.Contains(status, "waf detected") ||
		strings.Contains(status, "cloudflare protected") {
		statusColor = color.New(color.FgRed) // 🔴 Forbidden - Possible WAF or ACL Restrictions
	} else if strings.Contains(status, "401") ||
		strings.Contains(status, "authorization required") ||
		strings.Contains(status, "invalid credentials") ||
		strings.Contains(status, "login required") ||
		strings.Contains(status, "session expired") {
		statusColor = color.New(color.FgRed) // 🔴 Unauthorized - Needs Authentication
	} else if strings.Contains(status, "404") ||
		strings.Contains(status, "not found") ||
		strings.Contains(status, "page not found") ||
		strings.Contains(status, "the requested url was not found") ||
		strings.Contains(status, "no such file or directory") {
		statusColor = color.New(color.FgYellow) // 🟡 Not Found - May Indicate Hidden Files or Directories
	} else if strings.Contains(status, "200") ||
		strings.Contains(status, "ok") ||
		strings.Contains(status, "success") ||
		strings.Contains(status, "everything is fine") ||
		strings.Contains(status, "document follows") {
		statusColor = color.New(color.FgGreen) // 🟢 Success - Resource Accessible
	} else if strings.Contains(status, "201") ||
		strings.Contains(status, "created") {
		statusColor = color.New(color.FgGreen) // 🟢 Created - Resource Successfully Added
	} else if strings.Contains(status, "202") ||
		strings.Contains(status, "accepted") {
		statusColor = color.New(color.FgGreen) // 🟢 Accepted - Request Queued
	} else if strings.Contains(status, "204") ||
		strings.Contains(status, "no content") {
		statusColor = color.New(color.FgGreen) // 🟢 No Content - Action Successful but No Output
	} else if strings.Contains(status, "301") ||
		strings.Contains(status, "302") ||
		strings.Contains(status, "moved permanently") ||
		strings.Contains(status, "found") ||
		strings.Contains(status, "redirect") ||
		strings.Contains(status, "object moved") {
		statusColor = color.New(color.FgCyan) // 🔵 Redirect Detected - Possible Open Redirect or Sensitive Location Exposure
	} else if strings.Contains(status, "307") ||
		strings.Contains(status, "temporary redirect") ||
		strings.Contains(status, "308") ||
		strings.Contains(status, "permanent redirect") {
		statusColor = color.New(color.FgCyan) // 🔵 Redirect Detected - Persistent or Temporary Redirection
	} else if strings.Contains(status, "400") ||
		strings.Contains(status, "bad request") ||
		strings.Contains(status, "invalid request") ||
		strings.Contains(status, "malformed request") ||
		strings.Contains(status, "syntax error") {
		statusColor = color.New(color.FgYellow) // 🟡 Bad Request - May Reveal Internal Debug Messages
	} else if strings.Contains(status, "405") ||
		strings.Contains(status, "method not allowed") ||
		strings.Contains(status, "invalid http method") ||
		strings.Contains(status, "disallowed request") {
		statusColor = color.New(color.FgYellow) // 🟡 Possible Web Application Firewall (WAF) Blocking Certain Methods
	} else if strings.Contains(status, "406") ||
		strings.Contains(status, "not acceptable") ||
		strings.Contains(status, "client not allowed") {
		statusColor = color.New(color.FgYellow) // 🟡 Not Acceptable - May Indicate Input Restrictions
	} else if strings.Contains(status, "408") ||
		strings.Contains(status, "request timeout") ||
		strings.Contains(status, "server took too long to respond") {
		statusColor = color.New(color.FgYellow) // 🟡 Timeout - Possible Slow Server or Rate Limiting
	} else if strings.Contains(status, "409") ||
		strings.Contains(status, "conflict") {
		statusColor = color.New(color.FgYellow) // 🟡 Conflict - May Indicate Versioning Issues or Race Conditions
	} else if strings.Contains(status, "410") ||
		strings.Contains(status, "gone") {
		statusColor = color.New(color.FgYellow) // 🟡 Gone - Previously Existing Resource Removed
	} else if strings.Contains(status, "429") ||
		strings.Contains(status, "too many requests") ||
		strings.Contains(status, "rate limit exceeded") ||
		strings.Contains(status, "try again later") {
		statusColor = color.New(color.FgMagenta) // 🟣 Rate Limiting - Possible Detection of Automated Requests
	} else if strings.Contains(status, "500") ||
		strings.Contains(status, "internal server error") ||
		strings.Contains(status, "server error") ||
		strings.Contains(status, "unexpected error") ||
		strings.Contains(status, "unhandled exception") {
		statusColor = color.New(color.FgRed) // 🔴 Server Error - Possible Code Execution Vulnerability
	} else if strings.Contains(status, "501") ||
		strings.Contains(status, "not implemented") {
		statusColor = color.New(color.FgRed) // 🔴 Not Implemented - May Indicate API Testing Possibilities
	} else if strings.Contains(status, "502") ||
		strings.Contains(status, "bad gateway") ||
		strings.Contains(status, "invalid response from upstream") {
		statusColor = color.New(color.FgRed) // 🔴 Proxy or Server Communication Issue
	} else if strings.Contains(status, "503") ||
		strings.Contains(status, "service unavailable") ||
		strings.Contains(status, "temporarily unavailable") ||
		strings.Contains(status, "server overloaded") {
		statusColor = color.New(color.FgRed) // 🔴 Service Downtime - May Be Under Maintenance
	} else if strings.Contains(status, "504") ||
		strings.Contains(status, "gateway timeout") ||
		strings.Contains(status, "upstream server timeout") {
		statusColor = color.New(color.FgRed) // 🔴 Upstream Server Took Too Long
	} else if strings.Contains(status, "505") ||
		strings.Contains(status, "http version not supported") {
		statusColor = color.New(color.FgYellow) // 🟡 HTTP Version Issues - May Indicate Old Protocol Support
	} else if strings.Contains(status, "511") ||
		strings.Contains(status, "network authentication required") {
		statusColor = color.New(color.FgRed) // 🔴 Network Authentication - May Indicate Captive Portals
	}

	return statusColor
}
