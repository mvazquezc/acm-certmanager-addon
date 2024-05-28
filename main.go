package main

import (
	customManagers "github.com/mvazquezc/acm-certmanager-addon/pkg/mgr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func main() {
	logf.SetLogger(zap.New())

	log := logf.Log.WithName("acm-certmanager-addon")
	log.Info("Starting acm certmanager addon")
	customManagers.NewHubManager()
}
