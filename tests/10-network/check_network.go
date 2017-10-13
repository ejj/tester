package main

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/kelda/kelda/api"
	"github.com/kelda/kelda/api/client"
	"github.com/kelda/kelda/api/client/getter"
	"github.com/kelda/kelda/db"
	"github.com/kelda/kelda/join"
)

// anyIPAllowed is used to indicate that any non-error response is okay for an external
// DNS query.
const anyIPAllowed = "0.0.0.0"

var externalHostnames = []string{"google.com", "facebook.com", "en.wikipedia.org"}

type testFailure struct {
	target string
	err    error
}

func (tf testFailure) String() string {
	if tf.err != nil {
		return fmt.Sprintf("%s: %s", tf.target, tf.err)
	}
	return tf.target
}

type testResult struct {
	container        db.Container
	pingUnauthorized []testFailure
	pingUnreachable  []testFailure
	dnsIncorrect     []testFailure
}

func main() {
	clientGetter := getter.New()

	clnt, err := clientGetter.Client(api.DefaultSocket)
	if err != nil {
		log.WithError(err).Fatal("FAILED, couldn't get quiltctl client")
	}
	defer clnt.Close()

	leader, err := clientGetter.LeaderClient(clnt)
	if err != nil {
		log.WithError(err).Fatal("FAILED, couldn't get leader client")
	}

	tester, err := newNetworkTester(leader)
	if err != nil {
		log.WithError(err).Fatal("FAILED, couldn't initialize network tester")
	}

	containers, err := leader.QueryContainers()
	if err != nil {
		log.WithError(err).Fatal("FAILED, couldn't query containers")
	}

	var failed bool
	for _, res := range runTests(tester, containers) {
		fmt.Println(res.container)
		if len(res.pingUnauthorized) != 0 {
			failed = true
			fmt.Println(".. FAILED, could ping unauthorized containers")
			for _, unauthorized := range res.pingUnauthorized {
				fmt.Printf(".... %s\n", unauthorized)
			}
		}
		if len(res.pingUnreachable) != 0 {
			failed = true
			fmt.Println(".. FAILED, couldn't ping authorized containers")
			for _, unreachable := range res.pingUnreachable {
				fmt.Printf(".... %s\n", unreachable)
			}
		}
		if len(res.dnsIncorrect) != 0 {
			failed = true
			fmt.Println(".. FAILED, hostnames resolved incorrectly")
			for _, incorrect := range res.dnsIncorrect {
				fmt.Printf(".... %s\n", incorrect)
			}
		}
	}

	if !failed {
		fmt.Println("PASSED")
	}
}

// Gather test results for each container. For each minion machine, run one test
// at a time.
func runTests(tester networkTester, containers []db.Container) []testResult {
	// Create a separate test executor go routine for each minion machine.
	testChannels := make(map[string]chan db.Container)
	for _, c := range containers {
		testChannels[c.Minion] = make(chan db.Container)
	}

	var wg sync.WaitGroup
	testResultsChan := make(chan testResult, len(containers))
	for _, testChan := range testChannels {
		wg.Add(1)
		go func(testChan chan db.Container) {
			defer wg.Done()
			for c := range testChan {
				testResultsChan <- tester.test(c)
			}
		}(testChan)
	}

	// Feed the worker threads until we've run all the tests.
	for len(containers) != 0 {
		var remainingContainers []db.Container
		for _, c := range containers {
			select {
			case testChannels[c.Minion] <- c:
			default:
				remainingContainers = append(remainingContainers, c)
			}
		}
		containers = remainingContainers
		time.Sleep(1 * time.Second)
	}
	for _, testChan := range testChannels {
		close(testChan)
	}
	wg.Wait()
	close(testResultsChan)

	var testResults []testResult
	for res := range testResultsChan {
		testResults = append(testResults, res)
	}
	return testResults
}

type networkTester struct {
	labelMap      map[string]db.Label
	connectionMap map[string][]string
	hostnameIPMap map[string]string
	allIPs        []string
	allHostnames  []string
}

func newNetworkTester(clnt client.Client) (networkTester, error) {
	labels, err := clnt.QueryLabels()
	if err != nil {
		return networkTester{}, err
	}

	hostnameIPMap := make(map[string]string)
	for _, host := range externalHostnames {
		hostnameIPMap[host] = anyIPAllowed
	}

	allIPsSet := make(map[string]struct{})
	labelMap := make(map[string]db.Label)
	for _, label := range labels {
		labelMap[label.Label] = label

		for _, ip := range append(label.ContainerIPs, label.IP) {
			allIPsSet[ip] = struct{}{}
		}

		hostnameIPMap[label.Label+".q"] = label.IP
		for i, ip := range label.ContainerIPs {
			hostnameIPMap[fmt.Sprintf("%d.%s.q", i+1, label.Label)] = ip
		}
	}

	var allIPs []string
	for ip := range allIPsSet {
		allIPs = append(allIPs, ip)
	}

	connections, err := clnt.QueryConnections()
	if err != nil {
		return networkTester{}, err
	}

	connectionMap := make(map[string][]string)
	for _, conn := range connections {
		connectionMap[conn.From] = append(connectionMap[conn.From], conn.To)
		// Connections are bi-directional.
		connectionMap[conn.To] = append(connectionMap[conn.To], conn.From)
	}

	return networkTester{
		labelMap:      labelMap,
		connectionMap: connectionMap,
		hostnameIPMap: hostnameIPMap,
		allIPs:        allIPs,
	}, nil
}

type pingResult struct {
	target    string
	reachable bool
	err       error
}

// We have to limit our parallelization because each `quilt exec` creates a new SSH login
// session. Doing this quickly in parallel breaks system-logind
// on the remote machine: https://github.com/systemd/systemd/issues/2925.
const concurrencyLimit = 10

func (tester networkTester) pingAll(container db.Container) []pingResult {
	pingResultsChan := make(chan pingResult, len(tester.allIPs))

	// Create worker threads.
	pingRequests := make(chan string, concurrencyLimit)
	var wg sync.WaitGroup
	for i := 0; i < concurrencyLimit; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range pingRequests {
				_, err := ping(container.StitchID, ip)
				pingResultsChan <- pingResult{
					target:    ip,
					reachable: err == nil,
					err:       err,
				}
			}
		}()
	}

	// Feed worker threads.
	for _, ip := range tester.allIPs {
		pingRequests <- ip
	}
	close(pingRequests)
	wg.Wait()
	close(pingResultsChan)

	// Collect results.
	var pingResults []pingResult
	for res := range pingResultsChan {
		pingResults = append(pingResults, res)
	}

	return pingResults
}

type lookupResult struct {
	hostname string
	ip       string
	err      error
}

// Resolve all hostnames on the container with the given StitchID. Parallelize
// over the hostnames.
func (tester networkTester) lookupAll(container db.Container) []lookupResult {
	lookupResultsChan := make(chan lookupResult, len(tester.hostnameIPMap))

	// Create worker threads.
	lookupRequests := make(chan string, concurrencyLimit)
	var wg sync.WaitGroup
	for i := 0; i < concurrencyLimit; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for hostname := range lookupRequests {
				ip, err := lookup(container.StitchID, hostname)
				lookupResultsChan <- lookupResult{hostname, ip, err}
			}
		}()
	}

	// Feed worker threads.
	for hostname := range tester.hostnameIPMap {
		lookupRequests <- hostname
	}
	close(lookupRequests)
	wg.Wait()
	close(lookupResultsChan)

	// Collect results.
	var results []lookupResult
	for res := range lookupResultsChan {
		results = append(results, res)
	}

	return results
}

func (tester networkTester) test(container db.Container) testResult {
	// We should be able to ping ourselves.
	expReachable := map[string]struct{}{
		container.IP: {},
	}
	for _, label := range container.Labels {
		for _, toLabelName := range tester.connectionMap[label] {
			toLabel := tester.labelMap[toLabelName]
			for _, ip := range append(toLabel.ContainerIPs, toLabel.IP) {
				expReachable[ip] = struct{}{}
			}
		}
	}

	var expPings []pingResult
	for _, ip := range tester.allIPs {
		_, reachable := expReachable[ip]
		expPings = append(expPings, pingResult{
			target:    ip,
			reachable: reachable,
		})
	}
	pingResults := tester.pingAll(container)
	_, _, failures := join.HashJoin(pingSlice(expPings), pingSlice(pingResults),
		ignoreErrorField, ignoreErrorField)

	var pingUnreachable, pingUnauthorized []testFailure
	for _, badIntf := range failures {
		bad := badIntf.(pingResult)
		failure := testFailure{bad.target, bad.err}
		if bad.reachable {
			pingUnauthorized = append(pingUnauthorized, failure)
		} else {
			pingUnreachable = append(pingUnreachable, failure)
		}
	}

	lookupResults := tester.lookupAll(container)

	var dnsIncorrect []testFailure
	for _, l := range lookupResults {
		expIP := tester.hostnameIPMap[l.hostname]
		if l.err == nil && (expIP == anyIPAllowed || l.ip == expIP) {
			continue
		}

		err := l.err
		if err == nil {
			err = fmt.Errorf("%s => %s (expected %s)", l.hostname, l.ip, expIP)
		}
		dnsIncorrect = append(dnsIncorrect, testFailure{l.hostname, err})
	}

	return testResult{
		container:        container,
		pingUnreachable:  pingUnreachable,
		pingUnauthorized: pingUnauthorized,
		dnsIncorrect:     dnsIncorrect,
	}
}

func ignoreErrorField(pingResultIntf interface{}) interface{} {
	return pingResult{
		target:    pingResultIntf.(pingResult).target,
		reachable: pingResultIntf.(pingResult).reachable,
	}
}

// ping `target` from within container `id` with 3 packets, with a timeout of
// 1 second for each packet.
func ping(id string, target string) (string, error) {
	return quiltSSH(id, "ping", "-c", "3", "-W", "1", target)
}

func lookup(id string, hostname string) (string, error) {
	stdout, err := quiltSSH(id, "getent", "hosts", hostname)
	if err != nil {
		return "", err
	}

	fields := strings.Fields(stdout)
	if len(fields) < 2 {
		return "", fmt.Errorf("parse error: expected %q to have at "+
			"least 2 fields", fields)
	}

	return fields[0], nil
}

func quiltSSH(id string, cmd ...string) (string, error) {
	execCmd := exec.Command("quilt", append([]string{"ssh", id}, cmd...)...)
	stderrBytes := bytes.NewBuffer(nil)
	execCmd.Stderr = stderrBytes

	stdoutBytes, err := execCmd.Output()
	if err != nil {
		err = errors.New(stderrBytes.String())
	}

	return string(stdoutBytes), err
}

type pingSlice []pingResult

func (ps pingSlice) Get(ii int) interface{} {
	return ps[ii]
}

func (ps pingSlice) Len() int {
	return len(ps)
}
