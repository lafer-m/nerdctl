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
	"encoding/json"
	"fmt"

	"github.com/containerd/nerdctl/pkg/inspecttypes/native"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newVolumeInspectCommand() *cobra.Command {
	volumeInspectCommand := &cobra.Command{
		Use:               "inspect [flags] VOLUME [VOLUME...]",
		Short:             "Display detailed information on one or more volumes",
		Args:              cobra.MinimumNArgs(1),
		RunE:              volumeInspectAction,
		ValidArgsFunction: volumeInspectShellComplete,
		SilenceUsage:      true,
		SilenceErrors:     true,
	}
	return volumeInspectCommand
}

func volumeInspectAction(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return errors.Errorf("requires at least 1 argument")
	}

	volStore, err := getVolumeStore(cmd)
	if err != nil {
		return err
	}
	result := make([]*native.Volume, len(args))
	for i, name := range args {
		vol, err := volStore.Get(name)
		if err != nil {
			return err
		}
		result[i] = vol
	}
	b, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(b))
	return nil
}

func volumeInspectShellComplete(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// show voume names
	return shellCompleteVolumeNames(cmd)
}
