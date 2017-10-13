package main

import (
	"fmt"
	"os/exec"

	"github.com/kelda/kelda/api"
	"github.com/kelda/kelda/api/client/getter"
	"github.com/kelda/kelda/db"
	"github.com/kelda/kelda/stitch"

	log "github.com/Sirupsen/logrus"
)

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
	defer leader.Close()

	containers, err := leader.QueryContainers()
	if err != nil {
		log.WithError(err).Fatal("FAILED, couldn't query containers")
	}

	connections, err := leader.QueryConnections()
	if err != nil {
		log.WithError(err).Fatal("FAILED, couldn't query connections")
	}

	if test(containers, connections) {
		fmt.Println("PASSED")
	} else {
		fmt.Println("FAILED")
	}
}

var testPort = 80
var testHost = fmt.Sprintf("google.com:%d", testPort)

func test(containers []db.Container, connections []db.Connection) bool {
	connected := map[string]struct{}{}
	for _, conn := range connections {
		if conn.To == stitch.PublicInternetLabel &&
			inRange(testPort, conn.MinPort, conn.MaxPort) {
			connected[conn.From] = struct{}{}
		}
	}

	passed := true
	for _, c := range containers {
		shouldErr := !containsAny(connected, c.Labels)

		fmt.Printf("Fetching %s from container %s\n", testHost, c.StitchID)
		if shouldErr {
			fmt.Println(".. It should fail")
		} else {
			fmt.Println(".. It should not fail")
		}

		out, err := exec.Command("quilt", "ssh", c.StitchID,
			"wget", "-T", "2", "-O", "-", testHost).CombinedOutput()

		errored := err != nil
		if !shouldErr && errored {
			log.WithError(err).Error(
				"Fetch failed when it should have succeeded")
			fmt.Println(string(out))
			passed = false
		} else if shouldErr && !errored {
			log.Error("Fetch succeeded when it should have failed")
			fmt.Println(string(out))
			passed = false
		}
	}

	return passed
}

func inRange(candidate, min, max int) bool {
	return min <= candidate && candidate <= max
}

func containsAny(m map[string]struct{}, keys []string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}
