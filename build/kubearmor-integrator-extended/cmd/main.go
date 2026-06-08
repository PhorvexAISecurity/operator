/*
 * Copyright (C) 2023 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/kubearmor/kubearmor-client/k8s"
	klog "github.com/r6security/kubearmor-integrator/kubearmorlog"

	amtdv1beta1client "github.com/r6security/kubearmor-integrator/clients"
	seceventclient "github.com/r6security/kubearmor-integrator/clients/securityevent"
	amtdapi "github.com/r6security/phoenix/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

var visitor_number int
var version string
var mux sync.Mutex

type KubeArmorPolicyEvent struct {
	Timestamp     int64  `json:"Timestamp"`
	NamespaceName string `json:"NamespaceName"`
	PodName       string `json:"PodName"`
	Result        string `json:"Result"`
	PolicyName    string `json:"PolicyName"`
	Severity      string `json:"Severity"`
}

func kubeArmorEventHandling(ch <-chan klog.EventInfo) {
	for {
		event := <-ch
		var policyEvent KubeArmorPolicyEvent
		json.Unmarshal(event.Data, &policyEvent)
		secEventName := fmt.Sprintf("kubearmor-%s-%d", policyEvent.PodName, policyEvent.Timestamp)
		secEventNamespace := policyEvent.NamespaceName

		// Phase 7: NORMALIZE KubeArmor's native numeric Severity + PolicyName onto the
		// shared canonical vocabulary, and attach the score-carrier (severity-derived
		// PROXY AnomalyScore + raw signals in Metrics). The `replace =>
		// ../phoenix-extended` was made to build by bumping kustomize/cli-runtime to
		// gnostic-models-aware versions, so the extended SecurityEventSpec is imported
		// here (see canonical.go). Raw PolicyName + Severity are preserved for AUDIT.
		spec := buildKubeArmorSpec(policyEvent)

		fmt.Fprintf(os.Stderr, "New SecEvent         %s:\n", secEventName)
		fmt.Fprintf(os.Stderr, "  Target             %s\n", spec.Targets)
		fmt.Fprintf(os.Stderr, "  Description        %s\n", spec.Description)
		fmt.Fprintf(os.Stderr, "  Rule Type          %s\n", spec.Rule.Type)
		fmt.Fprintf(os.Stderr, "  Rule Threat Level  %s\n", spec.Rule.ThreatLevel)
		fmt.Fprintf(os.Stderr, "  Rule Source        %s\n", spec.Rule.Source)
		if spec.AnomalyScore != nil {
			fmt.Fprintf(os.Stderr, "  Anomaly Score      %s (severity-derived proxy)\n", *spec.AnomalyScore)
		}

		_, error := secEventClient.Create(context.TODO(), &amtdapi.SecurityEvent{
			ObjectMeta: metav1.ObjectMeta{
				Labels:      make(map[string]string),
				Annotations: make(map[string]string),
				Name:        secEventName,
				Namespace:   secEventNamespace,
			},
			Spec: spec,
		})

		if error != nil {
			log.Printf("Error: %v", error)
		} else {
			log.Printf("secevent was successfully created")
		}

	}

}

var secEventClient seceventclient.SecurityEventInterface

func main() {

	log.Print("Loading kubernetes connection configuration")
	cfg := ctrl.GetConfigOrDie()
	client, error := amtdv1beta1client.NewClient(cfg)
	if error != nil {
		log.Panic(error)
	}

	gRPC, ok := os.LookupEnv("KUBEARMOR_SERVICE")
	if !ok {
		log.Fatal("Cannot get gRPC address for kubearmor event relay service. Plese configure the 'KUBEARMOR_SERVICE' env variable to point to a valid gRPC service endpoint")
		return
	}

	secEventClient = client.SecurityEvents()

	eventChan := make(chan klog.EventInfo, 10)

	options := klog.Options{
		GRPC:      gRPC,
		EventChan: eventChan,
	}

	kclient, err := k8s.ConnectK8sClient()
	if err != nil {
		log.Fatalf("Cannot create k8s client: %v", err)
	}

	go kubeArmorEventHandling(eventChan)

	log.Print("Starting to listen to new kubearmor alert messages")
	err = klog.StartObserver(kclient, options)
	if err != nil {
		log.Fatalf("Cannot start the observer: %v", err)
	}
}
