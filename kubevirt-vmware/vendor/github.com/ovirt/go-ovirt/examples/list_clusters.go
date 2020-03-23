//
// Copyright (c) 2017 Joey <majunjiev@gmail.com>.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package examples

import (
	"fmt"
	"time"

	ovirtsdk4 "github.com/ovirt/go-ovirt"
)

func listClusters() {
	inputRawURL := "https://10.1.111.229/ovirt-engine/api"

	conn, err := ovirtsdk4.NewConnectionBuilder().
		URL(inputRawURL).
		Username("admin@internal").
		Password("qwer1234").
		Insecure(true).
		Compress(true).
		Timeout(time.Second * 10).
		Build()
	if err != nil {
		fmt.Printf("Make connection failed, reason: %v\n", err)
		return
	}
	defer conn.Close()

	// To use `Must` methods, you should recover it if panics
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("Panics occurs, try the non-Must methods to find the reason")
		}
	}()

	// Get the reference to the "clusters" service:
	clustersService := conn.SystemService().ClustersService()

	// Use the "list" method of the "clusters" service to list all the clusters of the system:
	clustersResponse, err := clustersService.List().Send()
	if err != nil {
		fmt.Printf("Failed to get cluster list, reason: %v\n", err)
		return
	}

	if clusters, ok := clustersResponse.Clusters(); ok {
		// Print the datacenter names and identifiers:
		for _, cluster := range clusters.Slice() {
			fmt.Printf("Cluster: (")
			if clusterName, ok := cluster.Name(); ok {
				fmt.Printf(" name: %v", clusterName)
			}
			if clusterID, ok := cluster.Id(); ok {
				fmt.Printf(" id: %v", clusterID)
			}
			fmt.Println(")")
		}
	}
}
