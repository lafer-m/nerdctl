/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"context"
	"fmt"

	"github.com/containerd/containerd/api/services/dacscri/v1"
	"github.com/davecgh/go-spew/spew"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

func newTestCommand() *cobra.Command {
	var testCommand = &cobra.Command{
		Use:           "test",
		Short:         "test grpc cmd",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	runCmd := &cobra.Command{
		Use:           "run",
		Short:         "test running containers",
		RunE:          testRunAction,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	runCmd.Flags().String("address", "127.0.0.1:8888", "the containerd tcp grpc address")
	deleteCmd := &cobra.Command{
		Use:   "remove",
		Short: "test remove container",
		RunE:  testRemoveAction,
	}
	deleteCmd.Flags().String("address", "127.0.0.1:8888", "the containerd tcp grpc address")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "test list containers",
		RunE:  testListAction,
	}
	listCmd.Flags().String("address", "127.0.0.1:8888", "the containerd tcp grpc address")

	testCommand.AddCommand(listCmd)
	testCommand.AddCommand(deleteCmd)
	testCommand.AddCommand(runCmd)
	return testCommand
}

func testRemoveAction(cmd *cobra.Command, args []string) error {
	if len(args) <= 0 {
		return fmt.Errorf("at least one arg")
	}
	grpcDialOpts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithInsecure(),
	}

	addr, err := cmd.Flags().GetString("address")
	if err != nil {
		return err
	}
	conn, err := grpc.Dial(addr, grpcDialOpts...)
	if err != nil {
		return err
	}
	cli := dacscri.NewDacsCRIClient(conn)

	for _, cid := range args {
		req := &dacscri.RemoveContainerRequest{
			ID: cid,
		}
		_, err := cli.Remove(context.Background(), req)
		if err != nil {
			return err
		}
	}

	return nil
}

func testListAction(cmd *cobra.Command, args []string) error {
	if len(args) <= 0 {
		return fmt.Errorf("at least one arg")
	}
	grpcDialOpts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithInsecure(),
	}

	addr, err := cmd.Flags().GetString("address")
	if err != nil {
		return err
	}
	conn, err := grpc.Dial(addr, grpcDialOpts...)
	if err != nil {
		return err
	}
	cli := dacscri.NewDacsCRIClient(conn)
	req := &dacscri.ListContainersRequest{}
	resp, err := cli.List(context.Background(), req)
	if err != nil {
		return err
	}

	fmt.Println(spew.Sdump(resp))

	return nil
}

func testRunAction(cmd *cobra.Command, args []string) error {
	// Time to wait after sending a SIGTERM and before sending a SIGKILL.
	// Default is 10 seconds.

	grpcDialOpts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithInsecure(),
	}

	addr, err := cmd.Flags().GetString("address")
	if err != nil {
		return err
	}
	conn, err := grpc.Dial(addr, grpcDialOpts...)
	if err != nil {
		return err
	}
	cli := dacscri.NewDacsCRIClient(conn)

	req := &dacscri.RunContainerRequest{
		Image:   "nginx",
		Token:   "xxxx",
		Publish: []string{"79:80"},
		App: &dacscri.App{
			Type:    "gateway",
			TarType: dacscri.TARTYPE_FILE,
			TarUrl:  "/home/zhouxiaoming/test/test",
		},
	}

	resp, err := cli.Run(context.Background(), req)
	if err != nil {
		return err
	}

	fmt.Println(spew.Sdump(resp))

	return nil
}
