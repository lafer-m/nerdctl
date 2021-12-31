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
	"time"

	"github.com/containerd/containerd/api/services/dacscri/v1"
	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
	runCmd.Flags().String("address", "127.0.0.1:10250", "the containerd tcp grpc address")
	runCmd.Flags().String("cert", "/home/zhouxiaoming/root.crt", "cert ")
	runCmd.Flags().String("image", "", "run image")
	runCmd.Flags().String("service", "gateway", "service type")
	runCmd.Flags().String("tar_type", "FILE", "tar type")
	runCmd.Flags().String("tar_url", "/home/zhouxiaoming/test/test", "tar url")
	runCmd.Flags().Int("port", 80, "service export port")

	deleteCmd := &cobra.Command{
		Use:   "remove",
		Short: "test remove container",
		RunE:  testRemoveAction,
	}
	deleteCmd.Flags().String("address", "127.0.0.1:10250", "the containerd tcp grpc address")
	deleteCmd.Flags().String("cert", "/home/zhouxiaoming/root.crt", "cert ")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "test list containers",
		RunE:  testListAction,
	}
	listCmd.Flags().String("address", "127.0.0.1:10250", "the containerd tcp grpc address")
	listCmd.Flags().String("cert", "/home/zhouxiaoming/root.crt", "cert ")

	testCommand.AddCommand(listCmd)
	testCommand.AddCommand(deleteCmd)
	testCommand.AddCommand(runCmd)
	return testCommand
}

func testRemoveAction(cmd *cobra.Command, args []string) error {
	if len(args) <= 0 {
		return fmt.Errorf("at least one arg")
	}

	addr, err := cmd.Flags().GetString("address")
	if err != nil {
		return err
	}

	cert, _ := cmd.Flags().GetString("cert")
	cli, err := newTcpClient(cert, addr)
	if err != nil {
		return err
	}

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
	// if len(args) <= 0 {
	// 	return fmt.Errorf("at least one arg")
	// }

	cert, _ := cmd.Flags().GetString("cert")
	addr, err := cmd.Flags().GetString("address")
	if err != nil {
		return err
	}
	cli, err := newTcpClient(cert, addr)
	if err != nil {
		return err
	}
	req := &dacscri.ListContainersRequest{}
	resp, err := cli.List(context.Background(), req)
	if err != nil {
		return err
	}

	fmt.Println(spew.Sdump(resp))
	return nil
}

func testRunAction(cmd *cobra.Command, args []string) error {
	cert, _ := cmd.Flags().GetString("cert")
	addr, err := cmd.Flags().GetString("address")
	if err != nil {
		return err
	}
	cli, err := newTcpClient(cert, addr)
	if err != nil {
		return err
	}
	image, err := cmd.Flags().GetString("image")
	if err != nil {
		return err
	}

	service, err := cmd.Flags().GetString("service")
	if err != nil {
		return err
	}

	token, err := signToken(service)
	if err != nil {
		return err
	}

	tar_type, err := cmd.Flags().GetString("tar_type")
	if err != nil {
		return err
	}
	tp := dacscri.TARTYPE_FILE
	if tar_type == "HTTP" {
		tp = dacscri.TARTYPE_HTTP
	}

	tar_url, _ := cmd.Flags().GetString("tar_url")
	port, _ := cmd.Flags().GetInt("port")
	ptstr := fmt.Sprintf("%d:%d", port, port)

	req := &dacscri.RunContainerRequest{
		Image:   image,
		Token:   token,
		Publish: []string{ptstr},
		Restart: dacscri.RESTARTPOLICY_NO,
		App: &dacscri.App{
			Type:    service,
			TarType: tp,
			TarUrl:  tar_url,
		},
	}

	resp, err := cli.Run(context.Background(), req)
	if err != nil {
		return err
	}

	fmt.Println(spew.Sdump(resp))

	return nil
}

func newTcpClient(cert, addr string) (dacscri.DacsCRIClient, error) {
	grpcDialOpts := []grpc.DialOption{}

	if cert == "" {
		grpcDialOpts = append(grpcDialOpts, grpc.WithInsecure())
	} else {
		creds, err := credentials.NewClientTLSFromFile(cert, "dacsd_server")
		if err != nil {
			return nil, err
		}
		grpcDialOpts = append(grpcDialOpts, grpc.WithTransportCredentials(creds))
	}

	conn, err := grpc.Dial(addr, grpcDialOpts...)
	if err != nil {
		return nil, err
	}
	cli := dacscri.NewDacsCRIClient(conn)
	return cli, nil
}

var jwtKey = []byte("my_secret_key")

type PatrickClaims struct {
	jwt.StandardClaims
	Name string `json:"name"`
}

func signToken(name string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, PatrickClaims{
		Name: name,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + 300,
			IssuedAt:  time.Now().Unix() - 100,
			Issuer:    "patrick",
		},
	})
	return token.SignedString(jwtKey)
}
